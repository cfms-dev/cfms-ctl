//! Decoupled resolution of CFMS `DEFAULT_GROUP_PERMISSIONS` (`user`, `sysop`, ...).
//!
//! Resolution precedence:
//! 1. Explicit `--defaults-file <JSON>` override.
//! 2. Dependency-free static Python AST inspection (`ruff_python_parser`) of
//!    `<src_dir>/include/domains/access/permissions.py` and
//!    `<src_dir>/include/domains/identity/default_groups.py`.
//! 3. Compiled 0.14.x built-in fallback snapshot when Python source files are absent
//!    (for example, stripped or DB-only workspaces), accompanied by a warning.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use ruff_python_ast::{self as ast, Expr, Operator, Stmt};
use ruff_python_parser::parse_module;
use serde::Serialize;

use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;

const MAX_DEFAULTS_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_IDENTIFIER_LEN: usize = 255;

const PERMISSIONS_REL_PATH: &str = "include/domains/access/permissions.py";
const DEFAULT_GROUPS_REL_PATH: &str = "include/domains/identity/default_groups.py";

/// Built-in default permissions for the `user` group (CFMS 0.14.x baseline).
const BUILTIN_USER_PERMISSIONS: &[&str] = &["configure_auth_methods", "search", "set_username"];

/// Built-in default permissions for the `sysop` group (CFMS 0.14.x baseline).
const BUILTIN_SYSOP_PERMISSIONS: &[&str] = &[
    "move",
    "shutdown",
    "super_create_document",
    "super_create_directory",
    "super_list_directory",
    "create_document",
    "create_directory",
    "delete_document",
    "rename_document",
    "delete_directory",
    "rename_directory",
    "view_settings",
    "manage_settings",
    "diagnostics",
    "view_schedules",
    "manage_schedules",
    "create_user",
    "delete_user",
    "set_nickname",
    "super_set_username",
    "manage_user_status",
    "get_user_info",
    "set_user_permissions",
    "get_group_info",
    "change_user_groups",
    "super_configure_auth_methods",
    "view_access_rules",
    "set_access_rules",
    "view_metadata",
    "set_metadata_tags",
    "list_users",
    "list_groups",
    "create_group",
    "delete_group",
    "rename_group",
    "set_group_permissions",
    "bypass_lockdown",
    "bypass_document_creation_rate_limit",
    "bypass_document_download_rate_limit",
    "bypass_request_rate_limit",
    "apply_lockdown",
    "view_audit_logs",
    "manage_access",
    "view_access_entries",
    "block",
    "unblock",
    "super_set_user_avatar",
    "debugging",
    "super_list_user_auth_methods",
    "list_revisions",
    "view_revision",
    "set_current_revision",
    "delete_revision",
    "manage_keyrings",
    "list_user_blocks",
    "list_banned_subnets",
    "manage_banned_subnets",
    "list_auth_lockouts",
    "unlock_auth_lockouts",
    "purge",
    "restore",
    "list_deleted_items",
    "super_set_nickname",
    "set_user_avatar",
];

/// Provenance of the resolved default group permission table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultsSource {
    JsonOverride,
    StaticAst,
    BuiltinFallback,
}

impl DefaultsSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonOverride => "json_override",
            Self::StaticAst => "static_ast",
            Self::BuiltinFallback => "builtin_fallback",
        }
    }
}

/// Resolved mapping of default group names to ordered, deduplicated permission names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultGroupPermissions {
    pub source: DefaultsSource,
    pub groups: BTreeMap<String, Vec<String>>,
    pub warnings: Vec<String>,
}

impl DefaultGroupPermissions {
    /// Resolve default group permissions from an override file, workspace Python AST, or built-in fallback.
    pub fn resolve(paths: &WorkspacePaths, explicit_file: Option<&Path>) -> Result<Self> {
        if let Some(raw_path) = explicit_file {
            let resolved = paths.resolve_file_override(raw_path);
            return load_defaults_from_json(&resolved);
        }

        let (permissions_path, default_groups_path) = resolve_source_paths(paths);

        match (permissions_path.is_file(), default_groups_path.is_file()) {
            (true, true) => parse_workspace_defaults(&permissions_path, &default_groups_path),
            (false, true) => Err(CfmsError::Config(format!(
                "Found '{}' but '{}' is missing; pass `--defaults-file` or restore both files",
                default_groups_path.display(),
                permissions_path.display()
            ))),
            (true, false) => Err(CfmsError::Config(format!(
                "Found '{}' but '{}' is missing; pass `--defaults-file` or restore both files",
                permissions_path.display(),
                default_groups_path.display()
            ))),
            (false, false) => Ok(Self::builtin_with_warning(paths)),
        }
    }

    /// Return the built-in 0.14.x default group permission snapshot.
    #[must_use]
    pub fn builtin() -> Self {
        let mut groups = BTreeMap::new();
        groups.insert(
            "sysop".to_string(),
            BUILTIN_SYSOP_PERMISSIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        );
        groups.insert(
            "user".to_string(),
            BUILTIN_USER_PERMISSIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        );
        Self {
            source: DefaultsSource::BuiltinFallback,
            groups,
            warnings: Vec::new(),
        }
    }

    #[must_use]
    fn builtin_with_warning(paths: &WorkspacePaths) -> Self {
        let mut resolved = Self::builtin();
        resolved.warnings.push(format!(
            "Workspace Python permission sources were not found under '{}'; using built-in default group permissions snapshot (`user`, `sysop`)",
            paths.server_root.display()
        ));
        resolved
    }

    /// Validate and normalize `--group` arguments into a sorted, deduplicated target list.
    pub fn select_target_groups(&self, requested: &[String]) -> Result<Vec<String>> {
        if requested.is_empty() {
            return Ok(self.groups.keys().cloned().collect());
        }

        let valid_list: Vec<&str> = self.groups.keys().map(String::as_str).collect();
        let mut selected = BTreeSet::new();
        let mut unknown = BTreeSet::new();

        for raw in requested {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(CfmsError::InvalidArgument(format!(
                    "Default group name must not be empty. Choose from: {}",
                    valid_list.join(", ")
                )));
            }
            if self.groups.contains_key(trimmed) {
                selected.insert(trimmed.to_string());
            } else {
                unknown.insert(trimmed.to_string());
            }
        }

        if !unknown.is_empty() {
            let unknown_list: Vec<String> = unknown.into_iter().collect();
            return Err(CfmsError::InvalidArgument(format!(
                "Unknown default group(s): {}. Choose from: {}",
                unknown_list.join(", "),
                valid_list.join(", ")
            )));
        }

        Ok(selected.into_iter().collect())
    }
}

fn resolve_source_paths(paths: &WorkspacePaths) -> (std::path::PathBuf, std::path::PathBuf) {
    let candidates = [
        paths.server_root.clone(),
        paths.server_root.join("src"),
        paths.project_root.join("src"),
    ];
    for root in &candidates {
        let perms = root.join(PERMISSIONS_REL_PATH);
        let groups = root.join(DEFAULT_GROUPS_REL_PATH);
        if perms.is_file() || groups.is_file() {
            return (perms, groups);
        }
    }
    (
        paths.server_root.join(PERMISSIONS_REL_PATH),
        paths.server_root.join(DEFAULT_GROUPS_REL_PATH),
    )
}

fn read_bounded_utf8(path: &Path, label: &str) -> Result<String> {
    let meta = std::fs::metadata(path).map_err(|e| {
        CfmsError::Config(format!("Unable to read {label} '{}': {e}", path.display()))
    })?;
    if !meta.is_file() {
        return Err(CfmsError::Config(format!(
            "{label} is not a regular file: '{}'",
            path.display()
        )));
    }
    if meta.len() > MAX_DEFAULTS_FILE_BYTES {
        return Err(CfmsError::Config(format!(
            "{label} '{}' exceeds the {} MiB limit",
            path.display(),
            MAX_DEFAULTS_FILE_BYTES / (1024 * 1024)
        )));
    }
    std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!("Unable to read {label} '{}': {e}", path.display()))
    })
}

fn validate_identifier(raw: &str, kind: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_IDENTIFIER_LEN {
        return Err(CfmsError::Config(format!(
            "Invalid {kind} name '{raw}': must be 1..={MAX_IDENTIFIER_LEN} characters"
        )));
    }
    if trimmed != raw || raw.chars().any(char::is_whitespace) {
        return Err(CfmsError::Config(format!(
            "Invalid {kind} name '{raw}': whitespace is not permitted"
        )));
    }
    Ok(trimmed.to_string())
}

fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

/// Load default group permissions from `{ "user": [...], "sysop": [...] }` or `{ "groups": { ... } }`.
fn load_defaults_from_json(path: &Path) -> Result<DefaultGroupPermissions> {
    let raw = read_bounded_utf8(path, "Defaults JSON file")?;
    let root: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to parse defaults JSON file '{}': {e}",
            path.display()
        ))
    })?;

    let root_obj = root.as_object().ok_or_else(|| {
        CfmsError::Config(format!(
            "Invalid defaults JSON in '{}': top-level value must be an object",
            path.display()
        ))
    })?;

    let groups_obj = match root_obj.get("groups") {
        Some(serde_json::Value::Object(nested)) => nested,
        Some(_) => {
            return Err(CfmsError::Config(format!(
                "Invalid defaults JSON in '{}': `groups` must be an object",
                path.display()
            )));
        }
        None => root_obj,
    };

    if groups_obj.is_empty() {
        return Err(CfmsError::Config(format!(
            "Invalid defaults JSON in '{}': expected at least one default group",
            path.display()
        )));
    }

    let mut groups = BTreeMap::new();
    for (group_key, perms_val) in groups_obj {
        let group_name = validate_identifier(group_key, "group")?;
        let arr = perms_val.as_array().ok_or_else(|| {
            CfmsError::Config(format!(
                "Invalid defaults JSON in '{}' for group '{group_name}': expected array of permission names",
                path.display()
            ))
        })?;

        let mut perms = Vec::with_capacity(arr.len());
        for entry in arr {
            let raw_perm = entry.as_str().ok_or_else(|| {
                CfmsError::Config(format!(
                    "Invalid defaults JSON in '{}' for group '{group_name}': permission entries must be strings",
                    path.display()
                ))
            })?;
            perms.push(validate_identifier(raw_perm, "permission")?);
        }
        groups.insert(group_name, dedup_preserve_order(perms));
    }

    Ok(DefaultGroupPermissions {
        source: DefaultsSource::JsonOverride,
        groups,
        warnings: Vec::new(),
    })
}

fn parse_workspace_defaults(
    permissions_path: &Path,
    default_groups_path: &Path,
) -> Result<DefaultGroupPermissions> {
    let perms_src = read_bounded_utf8(permissions_path, "permissions module")?;
    let perms_map = extract_permissions_enum(&perms_src, permissions_path)?;

    let groups_src = read_bounded_utf8(default_groups_path, "default_groups module")?;
    let groups = extract_default_group_permissions(&groups_src, default_groups_path, &perms_map)?;

    Ok(DefaultGroupPermissions {
        source: DefaultsSource::StaticAst,
        groups,
        warnings: Vec::new(),
    })
}

fn expr_dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.to_string()),
        Expr::Attribute(a) => {
            let prefix = expr_dotted_name(&a.value)?;
            Some(format!("{prefix}.{}", a.attr))
        }
        _ => None,
    }
}

fn is_enum_base(expr: &Expr) -> bool {
    matches!(
        expr_dotted_name(expr).as_deref(),
        Some("StrEnum" | "enum.StrEnum" | "Enum" | "enum.Enum")
    )
}

fn is_auto_call(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    call.arguments.args.is_empty()
        && call.arguments.keywords.is_empty()
        && matches!(
            expr_dotted_name(&call.func).as_deref(),
            Some("auto" | "enum.auto")
        )
}

fn extract_permissions_enum(source: &str, path: &Path) -> Result<HashMap<String, String>> {
    let parsed = parse_module(source).map_err(|e| {
        CfmsError::Config(format!(
            "Failed to parse '{}' via static Python AST: {e}",
            path.display()
        ))
    })?;

    let mut members = HashMap::new();
    let mut found_class = false;

    for stmt in &parsed.syntax().body {
        let Stmt::ClassDef(cls) = stmt else {
            continue;
        };
        if cls.name.as_str() != "Permissions" {
            continue;
        }
        found_class = true;
        let has_enum_base = cls
            .arguments
            .as_ref()
            .is_some_and(|args| args.args.iter().any(is_enum_base));
        if !has_enum_base {
            return Err(CfmsError::Config(format!(
                "Class `Permissions` in '{}' does not inherit from Enum/StrEnum",
                path.display()
            )));
        }

        for body_stmt in &cls.body {
            let (target_expr, value_expr) = match body_stmt {
                Stmt::Assign(a) if a.targets.len() == 1 => (&a.targets[0], Some(a.value.as_ref())),
                Stmt::AnnAssign(a) => (a.target.as_ref(), a.value.as_deref()),
                Stmt::Expr(e) if matches!(e.value.as_ref(), Expr::StringLiteral(_)) => continue,
                Stmt::Pass(_) | Stmt::FunctionDef(_) => continue,
                _ => continue,
            };

            let Some(Expr::Name(name)) = Some(target_expr) else {
                continue;
            };
            let member = name.id.as_str();
            if member.starts_with("__") {
                continue;
            }
            let Some(val_expr) = value_expr else {
                continue;
            };

            let val_str = match val_expr {
                Expr::StringLiteral(lit) => validate_identifier(lit.value.to_str(), "permission")?,
                expr if is_auto_call(expr) => member.to_ascii_lowercase(),
                _ => {
                    return Err(CfmsError::Config(format!(
                        "Unsupported non-static value for `Permissions.{member}` in '{}'",
                        path.display()
                    )));
                }
            };
            members.insert(member.to_string(), val_str);
        }
    }

    if !found_class || members.is_empty() {
        return Err(CfmsError::Config(format!(
            "Could not find any enum members on `Permissions` in '{}'",
            path.display()
        )));
    }

    Ok(members)
}

fn unwrap_mapping_wrapper(expr: &Expr) -> &Expr {
    if let Expr::Call(call) = expr
        && call.arguments.args.len() == 1
        && call.arguments.keywords.is_empty()
        && matches!(
            expr_dotted_name(&call.func).as_deref(),
            Some("MappingProxyType" | "types.MappingProxyType" | "dict")
        )
    {
        return &call.arguments.args[0];
    }
    expr
}

fn unwrap_sequence_wrapper(expr: &Expr) -> &Expr {
    if let Expr::Call(call) = expr
        && call.arguments.args.len() == 1
        && call.arguments.keywords.is_empty()
        && matches!(
            expr_dotted_name(&call.func).as_deref(),
            Some("tuple" | "list" | "set" | "frozenset")
        )
    {
        return &call.arguments.args[0];
    }
    expr
}

fn eval_single_permission(
    expr: &Expr,
    perms_map: &HashMap<String, String>,
    path: &Path,
) -> Result<String> {
    match expr {
        Expr::StringLiteral(lit) => validate_identifier(lit.value.to_str(), "permission"),
        Expr::Attribute(attr) => {
            if matches!(attr.value.as_ref(), Expr::Name(n) if n.id.as_str() == "Permissions") {
                let member = attr.attr.as_str();
                perms_map.get(member).cloned().ok_or_else(|| {
                    CfmsError::Config(format!(
                        "Unknown permission enum member `Permissions.{member}` referenced in '{}'",
                        path.display()
                    ))
                })
            } else {
                Err(CfmsError::Config(format!(
                    "Unsupported attribute expression in '{}'",
                    path.display()
                )))
            }
        }
        _ => Err(CfmsError::Config(format!(
            "Unsupported permission entry expression in '{}'",
            path.display()
        ))),
    }
}

fn eval_permission_sequence(
    expr: &Expr,
    perms_map: &HashMap<String, String>,
    env: &HashMap<String, Vec<String>>,
    path: &Path,
) -> Result<Vec<String>> {
    let expr = unwrap_sequence_wrapper(expr);
    match expr {
        Expr::Tuple(t) => eval_sequence_elements(&t.elts, perms_map, env, path),
        Expr::List(l) => eval_sequence_elements(&l.elts, perms_map, env, path),
        Expr::Set(s) => eval_sequence_elements(&s.elts, perms_map, env, path),
        Expr::Name(n) => env.get(n.id.as_str()).cloned().ok_or_else(|| {
            CfmsError::Config(format!(
                "Unresolved binding `{}` in '{}'",
                n.id,
                path.display()
            ))
        }),
        Expr::BinOp(bin) if matches!(bin.op, Operator::Add | Operator::BitOr) => {
            let mut left = eval_permission_sequence(&bin.left, perms_map, env, path)?;
            let right = eval_permission_sequence(&bin.right, perms_map, env, path)?;
            left.extend(right);
            Ok(left)
        }
        _ => Err(CfmsError::Config(format!(
            "Unsupported permission collection expression in '{}'",
            path.display()
        ))),
    }
}

fn eval_sequence_elements(
    elts: &[Expr],
    perms_map: &HashMap<String, String>,
    env: &HashMap<String, Vec<String>>,
    path: &Path,
) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(elts.len());
    for el in elts {
        if let Expr::Starred(starred) = el {
            out.extend(eval_permission_sequence(&starred.value, perms_map, env, path)?);
        } else {
            out.push(eval_single_permission(el, perms_map, path)?);
        }
    }
    Ok(out)
}

fn extract_default_group_permissions(
    source: &str,
    path: &Path,
    perms_map: &HashMap<String, String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let parsed = parse_module(source).map_err(|e| {
        CfmsError::Config(format!(
            "Failed to parse '{}' via static Python AST: {e}",
            path.display()
        ))
    })?;

    let mut env: HashMap<String, Vec<String>> = HashMap::new();
    let mut resolved: Option<BTreeMap<String, Vec<String>>> = None;

    for stmt in &parsed.syntax().body {
        let (target_expr, value_expr) = match stmt {
            Stmt::Assign(a) if a.targets.len() == 1 => (&a.targets[0], Some(a.value.as_ref())),
            Stmt::AnnAssign(a) => (a.target.as_ref(), a.value.as_deref()),
            _ => continue,
        };
        let Expr::Name(name) = target_expr else {
            continue;
        };
        let Some(val_expr) = value_expr else {
            continue;
        };

        if name.id.as_str() == "DEFAULT_GROUP_PERMISSIONS" {
            let inner = unwrap_mapping_wrapper(val_expr);
            let Expr::Dict(dict) = inner else {
                return Err(CfmsError::Config(format!(
                    "`DEFAULT_GROUP_PERMISSIONS` in '{}' must evaluate to a dict/MappingProxyType literal",
                    path.display()
                )));
            };

            let mut groups = BTreeMap::new();
            for item in &dict.items {
                let Some(ast::Expr::StringLiteral(key_lit)) = item.key.as_ref() else {
                    return Err(CfmsError::Config(format!(
                        "`DEFAULT_GROUP_PERMISSIONS` in '{}' contains non-string or unpacked key",
                        path.display()
                    )));
                };
                let group_name = validate_identifier(key_lit.value.to_str(), "group")?;
                let perms = eval_permission_sequence(&item.value, perms_map, &env, path)?;
                groups.insert(group_name, dedup_preserve_order(perms));
            }
            if groups.is_empty() {
                return Err(CfmsError::Config(format!(
                    "`DEFAULT_GROUP_PERMISSIONS` in '{}' must not be empty",
                    path.display()
                )));
            }
            resolved = Some(groups);
        } else if let Ok(seq) = eval_permission_sequence(val_expr, perms_map, &env, path) {
            env.insert(name.id.to_string(), dedup_preserve_order(seq));
        }
    }

    resolved.ok_or_else(|| {
        CfmsError::Config(format!(
            "Could not find `DEFAULT_GROUP_PERMISSIONS` in '{}'",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn paths_for(root: &Path) -> WorkspacePaths {
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).expect("create src_dir");
        fs::write(
            src_dir.join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n",
        )
        .expect("write config");
        WorkspacePaths::discover(Some(root), None).expect("discover paths")
    }

    fn write_domain_files(root: &Path, perms_py: &str, defaults_py: &str) {
        let access_dir = root.join("src/include/domains/access");
        let id_dir = root.join("src/include/domains/identity");
        fs::create_dir_all(&access_dir).expect("mkdir access");
        fs::create_dir_all(&id_dir).expect("mkdir identity");
        fs::write(access_dir.join("permissions.py"), perms_py).expect("write permissions.py");
        fs::write(id_dir.join("default_groups.py"), defaults_py).expect("write default_groups.py");
    }

    #[test]
    fn builtin_snapshot_counts_and_uniqueness() {
        let builtin = DefaultGroupPermissions::builtin();
        assert_eq!(builtin.source, DefaultsSource::BuiltinFallback);
        assert_eq!(builtin.groups["user"].len(), 3);
        assert_eq!(builtin.groups["sysop"].len(), 64);

        // No duplicates inside any default group
        for (group, perms) in &builtin.groups {
            let unique: BTreeSet<&String> = perms.iter().collect();
            assert_eq!(unique.len(), perms.len(), "duplicate in {group}");
        }
    }

    #[test]
    fn static_ast_parses_mapping_proxy_bindings_spreads_and_auto() {
        let tmp = TempDir::new().unwrap();
        let perms_py = r#"
from enum import StrEnum, auto

class Permissions(StrEnum):
    """Docstring ignored."""
    SEARCH = "search"
    VIEW_SETTINGS = "view_settings"
    CUSTOM_FLAG = auto()
"#;
        let defaults_py = r#"
from types import MappingProxyType
from include.domains.access.permissions import Permissions

_BASE = (Permissions.SEARCH, "direct_perm")
DEFAULT_GROUP_PERMISSIONS = MappingProxyType({
    "user": (*_BASE, Permissions.SEARCH),
    "sysop": _BASE + (Permissions.VIEW_SETTINGS, Permissions.CUSTOM_FLAG),
})
"#;
        write_domain_files(tmp.path(), perms_py, defaults_py);
        let paths = paths_for(tmp.path());

        let resolved = DefaultGroupPermissions::resolve(&paths, None).expect("resolve AST");
        assert_eq!(resolved.source, DefaultsSource::StaticAst);
        assert!(resolved.warnings.is_empty());
        assert_eq!(
            resolved.groups["user"],
            vec!["search".to_string(), "direct_perm".to_string()]
        );
        assert_eq!(
            resolved.groups["sysop"],
            vec![
                "search".to_string(),
                "direct_perm".to_string(),
                "view_settings".to_string(),
                "custom_flag".to_string(),
            ]
        );
    }

    #[test]
    fn stripped_workspace_falls_back_with_warning_while_corrupt_source_errors() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_for(tmp.path());

        // 1. Missing Python sources -> graceful BuiltinFallback with warning
        let fallback = DefaultGroupPermissions::resolve(&paths, None).expect("fallback");
        assert_eq!(fallback.source, DefaultsSource::BuiltinFallback);
        assert_eq!(fallback.warnings.len(), 1);
        assert_eq!(fallback.groups["user"].len(), 3);

        // 2. Malformed existing Python source -> strict Config error (never silently fall back)
        write_domain_files(
            tmp.path(),
            "class Permissions(StrEnum):\n    SEARCH = 'search'\n",
            "DEFAULT_GROUP_PERMISSIONS = MappingProxyType({'user': (Permissions.MISSING_MEMBER,)})\n",
        );
        let err = DefaultGroupPermissions::resolve(&paths, None).unwrap_err();
        assert!(matches!(err, CfmsError::Config(_)));
        assert!(err.to_string().contains("MISSING_MEMBER"));
    }

    #[test]
    fn defaults_json_override_and_target_selection_validation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_for(tmp.path());
        let json_path = tmp.path().join("custom_defaults.json");
        fs::write(
            &json_path,
            r#"{"groups": {"auditor": ["view_audit_logs", "search", "search"]}}"#,
        )
        .unwrap();

        let resolved = DefaultGroupPermissions::resolve(&paths, Some(&json_path)).expect("json");
        assert_eq!(resolved.source, DefaultsSource::JsonOverride);
        assert_eq!(
            resolved.groups["auditor"],
            vec!["view_audit_logs".to_string(), "search".to_string()]
        );

        assert_eq!(
            resolved
                .select_target_groups(&["auditor".to_string(), "auditor".to_string()])
                .unwrap(),
            vec!["auditor".to_string()]
        );
        let bad_err = resolved.select_target_groups(&["unknown".to_string()]).unwrap_err();
        assert!(matches!(bad_err, CfmsError::InvalidArgument(_)));

        // Project-root config layout still discovers `<project_root>/src/include/...`
        let proj_tmp = TempDir::new().unwrap();
        fs::create_dir_all(proj_tmp.path().join("src")).unwrap();
        fs::write(
            proj_tmp.path().join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n",
        )
        .unwrap();
        write_domain_files(
            proj_tmp.path(),
            "from enum import StrEnum\nclass Permissions(StrEnum):\n    SEARCH = 'search'\n",
            "from include.domains.access.permissions import Permissions\nDEFAULT_GROUP_PERMISSIONS = {'user': (Permissions.SEARCH,)}\n",
        );
        let proj_paths = WorkspacePaths::discover(Some(proj_tmp.path()), None).unwrap();
        let proj_res = DefaultGroupPermissions::resolve(&proj_paths, None).unwrap();
        assert_eq!(proj_res.source, DefaultsSource::StaticAst);
        assert_eq!(proj_res.groups["user"], vec!["search".to_string()]);
    }
}
