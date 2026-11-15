//! Declarative `config.migrations.json` loader and CST-preserving TOML migration engine.

use std::collections::BTreeSet;
use std::path::Path;
use serde::{Deserialize, Serialize};
use toml_edit::{Array, DocumentMut, Item, KeyMut, Table, TableLike, Value};
use crate::core::error::{CfmsError, Result};
use crate::core::schema::{is_valid_policy_regex, load_json_schema_file};

/// Expected `format_version` in `config.migrations.json`.
pub const SUPPORTED_MIGRATIONS_FORMAT_VERSION: u32 = 1;

/// Parsed `config.migrations.json` manifest emitted by the server schema generator.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigMigrationsManifest {
    pub format_version: u32,
    #[serde(default)]
    pub toml_migrations: Vec<TomlMigrationRule>,
    #[serde(default)]
    pub options_migrations: Vec<OptionMigrationGroup>,
    #[serde(default)]
    pub obsolete_paths: Vec<ObsoletePathRule>,
}

/// Ordered rule composed of atomic TOML migration operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TomlMigrationRule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub ops: Vec<MigrationOp>,
}

/// Mapping between a legacy `config.toml` subtree/keys and a database `options` namespace.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OptionMigrationGroup {
    pub toml_path: String,
    pub namespace: String,
    pub owner: String,
    #[serde(default)]
    pub keys: Option<Vec<String>>,
}

/// Obsolete `config.toml` key with no replacement (ignored and removable).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObsoletePathRule {
    pub path: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub warning: Option<String>,
}

/// Atomic declarative operation supported in `config.migrations.json`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MigrationOp {
    RenameOrMove {
        from: String,
        to: String,
        #[serde(default)]
        overwrite: bool,
    },
    MoveTableEntries {
        from_table: String,
        to_table: String,
        #[serde(default)]
        exclude: Vec<String>,
        #[serde(default)]
        overwrite: bool,
    },
    AppendIfTrue {
        from_flag: String,
        to_array: String,
        value: String,
        #[serde(default)]
        warning_if_not_bool: Option<String>,
    },
    CopyPositiveInt {
        from: String,
        to: String,
        #[serde(default)]
        overwrite: bool,
        #[serde(default)]
        warning_if_invalid: Option<String>,
    },
    CopyScaledInt {
        from: String,
        to: String,
        div_ceil: i64,
        #[serde(default)]
        min_from_path: Option<String>,
        #[serde(default = "default_min_floor")]
        default_min: i64,
        #[serde(default)]
        overwrite: bool,
    },
    CharGroupsToRegexList {
        from: String,
        to_rules: String,
        to_count: String,
        #[serde(default)]
        overwrite: bool,
        #[serde(default)]
        warning_if_invalid: Option<String>,
    },
    WrapScalarInTable {
        path: String,
        target_field: String,
        #[serde(default)]
        overwrite: bool,
    },
    UnwrapTableField {
        from_table: String,
        field: String,
        to: String,
        #[serde(default)]
        overwrite: bool,
    },
    SetDefaultIfMissing {
        path: String,
        value: serde_json::Value,
    },
    Remove {
        path: String,
        #[serde(default = "default_true")]
        prune_empty_parents: bool,
        #[serde(default)]
        warning_if_not_table: Option<String>,
        #[serde(default)]
        warning_if_present: Option<String>,
    },
}

const fn default_min_floor() -> i64 {
    1
}

const fn default_true() -> bool {
    true
}

/// Summary produced after applying `toml_migrations` to a `DocumentMut`.
#[derive(Debug, Clone, Default)]
pub struct TomlMigrationOutcome {
    pub changed: bool,
    pub applied_rule_ids: Vec<String>,
    pub removed_paths: Vec<String>,
    pub warnings: Vec<String>,
}

/// Load and validate a `config.migrations.json` file.
pub fn load_config_migrations(path: &Path) -> Result<ConfigMigrationsManifest> {
    let raw = load_json_schema_file(path)?;
    let manifest: ConfigMigrationsManifest = serde_json::from_value(raw).map_err(|e| {
        CfmsError::Config(format!(
            "Invalid config migrations manifest '{}': {e}",
            path.display()
        ))
    })?;
    if manifest.format_version != SUPPORTED_MIGRATIONS_FORMAT_VERSION {
        return Err(CfmsError::Config(format!(
            "Unsupported config.migrations.json format_version {} in '{}' (expected {})",
            manifest.format_version,
            path.display(),
            SUPPORTED_MIGRATIONS_FORMAT_VERSION
        )));
    }
    Ok(manifest)
}

/// Apply all declarative `toml_migrations` rules in-place on `doc`, preserving existing CST decor.
pub fn apply_toml_migrations(
    doc: &mut DocumentMut,
    manifest: &ConfigMigrationsManifest,
    template: Option<&DocumentMut>,
) -> Result<TomlMigrationOutcome> {
    let before_doc = doc.to_string();
    let mut applied_rule_ids = Vec::new();
    let mut removed_paths = Vec::new();
    let mut warnings = Vec::new();

    for rule in &manifest.toml_migrations {
        let before_rule = doc.to_string();
        for op in &rule.ops {
            apply_single_op(doc, template, op, &mut removed_paths, &mut warnings)?;
        }
        if doc.to_string() != before_rule {
            applied_rule_ids.push(rule.id.clone());
        }
    }

    Ok(TomlMigrationOutcome {
        changed: doc.to_string() != before_doc,
        applied_rule_ids,
        removed_paths,
        warnings,
    })
}

fn apply_single_op(
    doc: &mut DocumentMut,
    template: Option<&DocumentMut>,
    op: &MigrationOp,
    removed_paths: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    match op {
        MigrationOp::RenameOrMove {
            from,
            to,
            overwrite,
        } => {
            if let Some(src_item) = get_dotted_item(doc.as_table(), from).cloned()
                && (*overwrite || !has_dotted_path(doc.as_table(), to))
            {
                set_dotted_item(doc.as_table_mut(), to, src_item)?;
            }
        }
        MigrationOp::MoveTableEntries {
            from_table,
            to_table,
            exclude,
            overwrite,
        } => {
            let Some(src_entries) = collect_table_entries(doc.as_table(), from_table, exclude)
            else {
                return Ok(());
            };
            let dst = ensure_table_path(doc.as_table_mut(), to_table)?;
            for (key, key_decor, val_item) in src_entries {
                if *overwrite || !dst.contains_key(&key) {
                    dst.insert(&key, val_item);
                    if let Some(mut k) = dst.key_mut(&key) {
                        *k.leaf_decor_mut() = key_decor.leaf_decor().clone();
                        *k.dotted_decor_mut() = key_decor.dotted_decor().clone();
                    }
                }
            }
        }
        MigrationOp::AppendIfTrue {
            from_flag,
            to_array,
            value,
            warning_if_not_bool,
        } => {
            let Some(flag_item) = get_dotted_item(doc.as_table(), from_flag).cloned() else {
                return Ok(());
            };
            let Some(enabled) = flag_item.as_bool() else {
                if let Some(msg) = warning_if_not_bool {
                    warnings.push(msg.clone());
                }
                return Ok(());
            };
            if enabled {
                append_string_to_array(
                    doc.as_table_mut(),
                    template.map(|t| t.as_table() as &dyn TableLike),
                    to_array,
                    value,
                    warning_if_not_bool.as_deref(),
                    warnings,
                )?;
            }
        }
        MigrationOp::CopyPositiveInt {
            from,
            to,
            overwrite,
            warning_if_invalid,
        } => {
            let Some(item) = get_dotted_item(doc.as_table(), from).cloned() else {
                return Ok(());
            };
            let Some(val) = strict_positive_int(&item) else {
                if let Some(msg) = warning_if_invalid {
                    warnings.push(msg.clone());
                }
                return Ok(());
            };
            if *overwrite || !has_dotted_path(doc.as_table(), to) {
                set_dotted_item(doc.as_table_mut(), to, toml_edit::value(val))?;
            }
        }
        MigrationOp::CopyScaledInt {
            from,
            to,
            div_ceil,
            min_from_path,
            default_min,
            overwrite,
        } => {
            if *div_ceil <= 0 {
                return Err(CfmsError::Config(format!(
                    "Invalid copy_scaled_int div_ceil ({div_ceil}) for '{from}'"
                )));
            }
            let Some(item) = get_dotted_item(doc.as_table(), from).cloned() else {
                return Ok(());
            };
            let Some(val) = strict_positive_int(&item) else {
                return Ok(());
            };
            if *overwrite || !has_dotted_path(doc.as_table(), to) {
                let floor = resolve_min_bound(
                    doc.as_table(),
                    template.map(|t| t.as_table() as &dyn TableLike),
                    min_from_path.as_deref(),
                    *default_min,
                );
                let scaled = ceil_div(val, *div_ceil).max(floor);
                set_dotted_item(doc.as_table_mut(), to, toml_edit::value(scaled))?;
            }
        }
        MigrationOp::CharGroupsToRegexList {
            from,
            to_rules,
            to_count,
            overwrite,
            warning_if_invalid,
        } => {
            let Some(item) = get_dotted_item(doc.as_table(), from).cloned() else {
                return Ok(());
            };
            let Some(rules) = convert_password_char_groups(&item) else {
                if let Some(msg) = warning_if_invalid {
                    warnings.push(msg.clone());
                }
                return Ok(());
            };
            if *overwrite || !has_dotted_path(doc.as_table(), to_rules) {
                let mut arr = Array::new();
                for rule in &rules {
                    arr.push(rule.as_str());
                }
                set_dotted_item(
                    doc.as_table_mut(),
                    to_rules,
                    Item::Value(Value::Array(arr)),
                )?;
            }
            if *overwrite || !has_dotted_path(doc.as_table(), to_count) {
                let count = i64::try_from(rules.len()).map_err(|_| {
                    CfmsError::Config("Password rule count overflow".to_string())
                })?;
                set_dotted_item(doc.as_table_mut(), to_count, toml_edit::value(count))?;
            }
        }
        MigrationOp::WrapScalarInTable {
            path,
            target_field,
            overwrite,
        } => {
            let field_name = target_field
                .strip_prefix(&format!("{path}."))
                .unwrap_or(target_field.as_str());
            if field_name.is_empty() || field_name.contains('.') {
                return Err(CfmsError::Config(format!(
                    "Invalid wrap_scalar_in_table target_field '{target_field}' for '{path}'"
                )));
            }
            let Some(existing) = get_dotted_item(doc.as_table(), path).cloned() else {
                return Ok(());
            };
            if existing.is_none() {
                return Ok(());
            }
            if let Some(tbl) = existing.as_table_like() {
                if *overwrite && tbl.is_empty() {
                    // Already a table; idempotent no-op when non-empty.
                }
                return Ok(());
            }
            let mut wrapped = Table::new();
            wrapped.insert(field_name, existing);
            set_dotted_item(doc.as_table_mut(), path, Item::Table(wrapped))?;
        }
        MigrationOp::UnwrapTableField {
            from_table,
            field,
            to,
            overwrite,
        } => {
            let extracted = get_dotted_item(doc.as_table(), from_table)
                .and_then(|item| item.as_table_like())
                .and_then(|tbl| tbl.get(field))
                .filter(|item| !item.is_none())
                .cloned();
            let Some(val_item) = extracted else {
                return Ok(());
            };
            if to == from_table {
                set_dotted_item(doc.as_table_mut(), to, val_item)?;
            } else if *overwrite || !has_dotted_path(doc.as_table(), to) {
                set_dotted_item(doc.as_table_mut(), to, val_item)?;
                remove_dotted_and_prune(doc.as_table_mut(), &format!("{from_table}.{field}"), true);
            }
        }
        MigrationOp::SetDefaultIfMissing { path, value } => {
            if !has_dotted_path(doc.as_table(), path) {
                let toml_item = json_value_to_toml_item(value)?;
                set_dotted_item(doc.as_table_mut(), path, toml_item)?;
            }
        }
        MigrationOp::Remove {
            path,
            prune_empty_parents,
            warning_if_not_table,
            warning_if_present,
        } => {
            let Some(existing) = get_dotted_item(doc.as_table(), path) else {
                return Ok(());
            };
            if existing.is_none() {
                return Ok(());
            }
            if let Some(msg) = warning_if_not_table
                && !existing.is_table_like()
            {
                warnings.push(msg.clone());
            }
            if let Some(msg) = warning_if_present {
                warnings.push(msg.clone());
            }
            if remove_dotted_and_prune(doc.as_table_mut(), path, *prune_empty_parents) {
                removed_paths.push(path.clone());
            }
        }
    }
    Ok(())
}

/// Collect dotted paths from `options_migrations` currently present in `table`.
#[must_use]
pub fn find_present_option_migration_paths(
    table: &dyn TableLike,
    manifest: &ConfigMigrationsManifest,
) -> Vec<String> {
    let mut found = BTreeSet::new();
    for group in &manifest.options_migrations {
        let Some(item) = get_dotted_item(table, &group.toml_path) else {
            continue;
        };
        if item.is_none() {
            continue;
        }
        match &group.keys {
            Some(keys) => {
                if let Some(sub) = item.as_table_like() {
                    for key in keys {
                        if let Some(val) = sub.get(key)
                            && !val.is_none()
                        {
                            found.insert(format!("{}.{key}", group.toml_path));
                        }
                    }
                } else {
                    found.insert(group.toml_path.clone());
                }
            }
            None => {
                found.insert(group.toml_path.clone());
            }
        }
    }
    found.into_iter().collect()
}

/// Collect dotted paths from `obsolete_paths` currently present in `table`.
#[must_use]
pub fn find_present_obsolete_paths(
    table: &dyn TableLike,
    manifest: &ConfigMigrationsManifest,
) -> Vec<String> {
    manifest
        .obsolete_paths
        .iter()
        .filter(|rule| has_dotted_path(table, &rule.path))
        .map(|rule| rule.path.clone())
        .collect()
}

/// Remove a dotted path and optionally prune any empty parent tables left behind.
pub(crate) fn remove_dotted_and_prune(
    root: &mut dyn TableLike,
    dotted_path: &str,
    prune_empty_parents: bool,
) -> bool {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    remove_parts_and_prune(root, &parts, prune_empty_parents)
}

fn remove_parts_and_prune(
    current: &mut dyn TableLike,
    parts: &[&str],
    prune_empty_parents: bool,
) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return false;
    };
    if rest.is_empty() {
        return current.remove(first).is_some();
    }
    let mut removed = false;
    let mut should_prune = false;
    if let Some(child_item) = current.get_mut(first)
        && let Some(child_table) = child_item.as_table_like_mut()
    {
        removed = remove_parts_and_prune(child_table, rest, prune_empty_parents);
        if removed && prune_empty_parents && child_table.is_empty() {
            should_prune = true;
        }
    }
    if should_prune {
        current.remove(first);
    }
    removed
}

/// Resolve a dotted path inside a `TableLike`.
pub(crate) fn get_dotted_item<'a>(root: &'a dyn TableLike, dotted_path: &str) -> Option<&'a Item> {
    let mut parts = dotted_path.split('.');
    let first = parts.next()?;
    if first.is_empty() {
        return None;
    }
    let mut current = root.get(first)?;
    if current.is_none() {
        return None;
    }
    for part in parts {
        if part.is_empty() {
            return None;
        }
        current = current.as_table_like()?.get(part)?;
        if current.is_none() {
            return None;
        }
    }
    Some(current)
}

/// Return true if `dotted_path` exists and is not `Item::None`.
pub(crate) fn has_dotted_path(root: &dyn TableLike, dotted_path: &str) -> bool {
    get_dotted_item(root, dotted_path).is_some()
}

/// Set or replace `dotted_path` inside `root`, creating intermediate tables as needed.
pub(crate) fn set_dotted_item(
    root: &mut dyn TableLike,
    dotted_path: &str,
    item: Item,
) -> Result<()> {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    let Some((leaf, parents)) = parts.split_last() else {
        return Err(CfmsError::Config("Empty configuration path".to_string()));
    };
    if leaf.is_empty() || parents.iter().any(|p| p.is_empty()) {
        return Err(CfmsError::Config(format!(
            "Invalid configuration path '{dotted_path}'"
        )));
    }
    let parent_table = if parents.is_empty() {
        root
    } else {
        ensure_table_parts(root, parents, dotted_path, true)?
    };
    if let Some(existing) = parent_table.get_mut(leaf) {
        if let (Some(existing_val), Some(new_val)) = (existing.as_value_mut(), item.as_value()) {
            let decor = existing_val.decor().clone();
            let mut replacement = new_val.clone();
            *replacement.decor_mut() = decor;
            *existing_val = replacement;
        } else {
            *existing = item;
        }
    } else {
        parent_table.insert(leaf, item);
    }
    Ok(())
}

fn ensure_table_path<'a>(root: &'a mut dyn TableLike, dotted_path: &str) -> Result<&'a mut dyn TableLike> {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(CfmsError::Config(format!(
            "Invalid table path '{dotted_path}'"
        )));
    }
    ensure_table_parts(root, &parts, dotted_path, false)
}

fn ensure_table_parts<'a>(
    mut current: &'a mut dyn TableLike,
    parts: &[&str],
    full_path: &str,
    mark_last_implicit: bool,
) -> Result<&'a mut dyn TableLike> {
    for (idx, part) in parts.iter().enumerate() {
        if !current.contains_key(part) {
            let mut tbl = Table::new();
            let is_intermediate = idx + 1 < parts.len() || mark_last_implicit;
            tbl.set_implicit(is_intermediate);
            current.insert(part, Item::Table(tbl));
        }
        let child = current.get_mut(part).ok_or_else(|| {
            CfmsError::Config(format!("Failed to access table segment '{part}' in '{full_path}'"))
        })?;
        current = child.as_table_like_mut().ok_or_else(|| {
            CfmsError::Config(format!(
                "Configuration path '{part}' inside '{full_path}' is not a table"
            ))
        })?;
    }
    Ok(current)
}

fn collect_table_entries(
    root: &dyn TableLike,
    from_table: &str,
    exclude: &[String],
) -> Option<Vec<(String, toml_edit::Key, Item)>> {
    let tbl = get_dotted_item(root, from_table)?.as_table_like()?;
    let excluded: BTreeSet<&str> = exclude.iter().map(String::as_str).collect();
    let mut entries = Vec::new();
    for (k, v) in tbl.iter() {
        if excluded.contains(k) || v.is_none() {
            continue;
        }
        let key_obj = tbl
            .key(k)
            .cloned()
            .unwrap_or_else(|| toml_edit::Key::new(k));
        entries.push((k.to_string(), key_obj, v.clone()));
    }
    Some(entries)
}

fn append_string_to_array(
    root: &mut dyn TableLike,
    template: Option<&dyn TableLike>,
    to_array: &str,
    value: &str,
    warning_if_invalid: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut arr = if let Some(existing) = get_dotted_item(root, to_array) {
        let Some(existing_arr) = existing.as_array() else {
            if let Some(msg) = warning_if_invalid {
                warnings.push(msg.to_string());
            }
            return Ok(());
        };
        existing_arr.clone()
    } else if let Some(tmpl_arr) = template
        .and_then(|t| get_dotted_item(t, to_array))
        .and_then(|i| i.as_array())
    {
        tmpl_arr.clone()
    } else {
        Array::new()
    };

    let already_present = arr
        .iter()
        .filter_map(Value::as_str)
        .any(|item| item == value);
    if !already_present {
        arr.push(value);
        set_dotted_item(root, to_array, Item::Value(Value::Array(arr)))?;
    }
    Ok(())
}

fn strict_positive_int(item: &Item) -> Option<i64> {
    let raw = item.as_integer()?;
    (raw > 0).then_some(raw)
}

fn resolve_min_bound(
    doc: &dyn TableLike,
    template: Option<&dyn TableLike>,
    min_from_path: Option<&str>,
    default_min: i64,
) -> i64 {
    let from_doc = min_from_path.and_then(|p| get_dotted_item(doc, p)).and_then(Item::as_integer);
    let from_tmpl = min_from_path
        .and_then(|p| template.and_then(|t| get_dotted_item(t, p)))
        .and_then(Item::as_integer);
    from_doc.or(from_tmpl).unwrap_or(default_min)
}

fn ceil_div(numerator: i64, denominator: i64) -> i64 {
    let rem = numerator % denominator;
    let q = numerator / denominator;
    if rem > 0 { q.saturating_add(1) } else { q }
}

/// Convert legacy `security.passwd_must_contain` character groups into validated regex rules.
pub(crate) fn convert_password_char_groups(item: &Item) -> Option<Vec<String>> {
    let arr = item.as_array()?;
    let mut rules = Vec::with_capacity(arr.len());

    for group in arr.iter() {
        let mut unique_chars: Vec<char> = Vec::new();
        match group {
            Value::String(s) => {
                for ch in s.value().chars() {
                    if !unique_chars.contains(&ch) {
                        unique_chars.push(ch);
                    }
                }
            }
            Value::Array(sub) => {
                for elem in sub.iter() {
                    let Value::String(s) = elem else {
                        return None;
                    };
                    let mut chars = s.value().chars();
                    let ch = chars.next()?;
                    if chars.next().is_some() {
                        return None;
                    }
                    if !unique_chars.contains(&ch) {
                        unique_chars.push(ch);
                    }
                }
            }
            _ => return None,
        }

        if unique_chars.is_empty() {
            return None;
        }

        let alts: String = unique_chars
            .iter()
            .map(|ch| python_regex_escape_char(*ch))
            .collect::<Vec<_>>()
            .join("|");
        let pattern = format!("(?:{alts})");
        if !is_valid_policy_regex(&pattern) {
            return None;
        }
        rules.push(pattern);
    }

    Some(rules)
}

fn python_regex_escape_char(ch: char) -> String {
    // Match Python's `re.escape` special ASCII characters so regexes match Python & Rust identically.
    const SPECIAL: &str = "()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c";
    if SPECIAL.contains(ch) {
        format!("\\{ch}")
    } else {
        ch.to_string()
    }
}

/// Convert a JSON value into a `toml_edit::Item` for `set_default_if_missing`.
pub fn json_value_to_toml_item(val: &serde_json::Value) -> Result<Item> {
    Ok(Item::Value(json_value_to_toml_value(val)?))
}

fn json_value_to_toml_value(val: &serde_json::Value) -> Result<Value> {
    match val {
        serde_json::Value::Bool(b) => Ok(Value::from(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::from(i))
            } else if let Some(u) = n.as_u64() {
                let i = i64::try_from(u).map_err(|_| {
                    CfmsError::Config(format!("Integer literal '{u}' exceeds TOML i64 range"))
                })?;
                Ok(Value::from(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::from(f))
            } else {
                Err(CfmsError::Config(format!("Unsupported JSON number: {n}")))
            }
        }
        serde_json::Value::String(s) => Ok(Value::from(s.as_str())),
        serde_json::Value::Array(items) => {
            let mut arr = Array::new();
            for item in items {
                arr.push(json_value_to_toml_value(item)?);
            }
            Ok(Value::Array(arr))
        }
        serde_json::Value::Object(map) => {
            let mut tbl = toml_edit::InlineTable::new();
            for (k, v) in map {
                tbl.insert(k, json_value_to_toml_value(v)?);
            }
            Ok(Value::InlineTable(tbl))
        }
        serde_json::Value::Null => Err(CfmsError::Config(
            "TOML values cannot be null in set_default_if_missing".to_string(),
        )),
    }
}

/// Keep key formatting metadata helper usable cleanly without dead code.
#[allow(dead_code)]
fn _touch_key(_k: &KeyMut<'_>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin_v013_manifest() -> ConfigMigrationsManifest {
        serde_json::from_value(serde_json::json!({
            "format_version": 1,
            "toml_migrations": [
                {
                    "id": "database_db_name_to_name",
                    "description": "database.db_name -> database.name",
                    "ops": [
                        { "op": "rename_or_move", "from": "database.db_name", "to": "database.name", "overwrite": false },
                        { "op": "remove", "path": "database.db_name", "prune_empty_parents": true }
                    ]
                },
                {
                    "id": "sso_oidc_to_extensions",
                    "description": "sso.oidc -> extensions.oidc_sso + extensions.enabled",
                    "ops": [
                        { "op": "move_table_entries", "from_table": "sso.oidc", "to_table": "extensions.oidc_sso", "exclude": ["enabled"], "overwrite": false },
                        { "op": "append_if_true", "from_flag": "sso.oidc.enabled", "to_array": "extensions.enabled", "value": "oidc_sso", "warning_if_not_bool": "sso.oidc.enabled invalid" },
                        { "op": "remove", "path": "sso.oidc", "prune_empty_parents": true, "warning_if_not_table": "sso.oidc not table" }
                    ]
                },
                {
                    "id": "document_upload_creation_rate_to_risk_control",
                    "ops": [
                        { "op": "copy_positive_int", "from": "document.upload.creation_rate_window_seconds", "to": "document.upload.creation_risk_control.refill_period_seconds", "warning_if_invalid": "bad window" },
                        { "op": "copy_positive_int", "from": "document.upload.creation_rate_per_user", "to": "document.upload.creation_risk_control.account_refill_tokens" },
                        { "op": "copy_scaled_int", "from": "document.upload.creation_rate_per_user", "to": "document.upload.creation_risk_control.account_capacity", "div_ceil": 5, "min_from_path": "document.upload.creation_risk_control.high_cost", "default_min": 10 },
                        { "op": "remove", "path": "document.upload.creation_rate_window_seconds" },
                        { "op": "remove", "path": "document.upload.creation_rate_per_user" }
                    ]
                },
                {
                    "id": "security_passwd_must_contain_to_rules",
                    "ops": [
                        { "op": "char_groups_to_regex_list", "from": "security.passwd_must_contain", "to_rules": "security.passwd_rules", "to_count": "security.passwd_min_passed_count", "warning_if_invalid": "bad groups" },
                        { "op": "remove", "path": "security.passwd_must_contain" }
                    ]
                },
                {
                    "id": "remove_obsolete_document_allow_name_duplicate",
                    "ops": [
                        { "op": "remove", "path": "document.allow_name_duplicate", "warning_if_present": "allow_name_duplicate obsolete" }
                    ]
                }
            ],
            "options_migrations": [
                { "toml_path": "security", "namespace": "security.password", "owner": "core", "keys": ["passwd_rules", "passwd_min_passed_count"] },
                { "toml_path": "document.upload.creation_risk_control", "namespace": "document.upload.creation_risk_control", "owner": "core", "keys": null }
            ],
            "obsolete_paths": [
                { "path": "security.require_passwd_enforcement_changes", "action": "remove_obsolete", "warning": "obsolete" }
            ]
        })).expect("valid manifest")
    }

    #[test]
    fn test_apply_v013_toml_migrations_preserves_comments_and_is_idempotent() {
        let mut doc: DocumentMut = r#"# Top comment
[database]
type = "sqlite"
db_name = "legacy.db" # operator db note

[extensions]
enabled = []

[sso.oidc]
enabled = true
issuer = "https://idp.example.com"
client_id = "cfms"

[document]
allow_name_duplicate = true

[document.upload]
creation_rate_window_seconds = 120
creation_rate_per_user = 25

[security]
passwd_must_contain = ["AB", ["0", "1"], "!@$"]
require_passwd_enforcement_changes = false
"#
        .parse()
        .expect("parse v0.13 toml");

        let manifest = builtin_v013_manifest();
        let outcome = apply_toml_migrations(&mut doc, &manifest, None).expect("apply migrations");
        assert!(outcome.changed);
        assert_eq!(outcome.warnings, vec!["allow_name_duplicate obsolete"]);
        assert_eq!(
            outcome.applied_rule_ids,
            vec![
                "database_db_name_to_name",
                "sso_oidc_to_extensions",
                "document_upload_creation_rate_to_risk_control",
                "security_passwd_must_contain_to_rules",
                "remove_obsolete_document_allow_name_duplicate",
            ]
        );

        let rendered = doc.to_string();
        assert!(rendered.contains("# Top comment"));
        assert!(rendered.contains("# operator db note"));
        assert_eq!(doc["database"]["name"].as_str(), Some("legacy.db"));
        assert!(doc["database"].get("db_name").is_none());
        assert!(doc.get("sso").is_none());
        assert_eq!(
            doc["extensions"]["oidc_sso"]["issuer"].as_str(),
            Some("https://idp.example.com")
        );
        let enabled: Vec<&str> = doc["extensions"]["enabled"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(enabled, vec!["oidc_sso"]);

        let rc = doc["document"]["upload"]["creation_risk_control"]
            .as_table_like()
            .unwrap();
        assert_eq!(rc.get("refill_period_seconds").and_then(Item::as_integer), Some(120));
        assert_eq!(rc.get("account_refill_tokens").and_then(Item::as_integer), Some(25));
        assert_eq!(rc.get("account_capacity").and_then(Item::as_integer), Some(10));

        let rules: Vec<&str> = doc["security"]["passwd_rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(rules, vec![r"(?:A|B)", r"(?:0|1)", r"(?:!|@|\$)"]);
        assert_eq!(
            doc["security"]["passwd_min_passed_count"].as_integer(),
            Some(3)
        );
        assert!(doc["security"].get("passwd_must_contain").is_none());

        // Second pass must be a clean no-op
        let second = apply_toml_migrations(&mut doc, &manifest, None).expect("second pass");
        assert!(!second.changed);
        assert!(second.applied_rule_ids.is_empty());
        assert!(second.warnings.is_empty());

        let pending_opts = find_present_option_migration_paths(doc.as_table(), &manifest);
        assert_eq!(
            pending_opts,
            vec![
                "document.upload.creation_risk_control",
                "security.passwd_min_passed_count",
                "security.passwd_rules",
            ]
        );
        let pending_obsolete = find_present_obsolete_paths(doc.as_table(), &manifest);
        assert_eq!(pending_obsolete, vec!["security.require_passwd_enforcement_changes"]);
    }

    #[test]
    fn test_wrap_scalar_and_unwrap_table_shape_flips() {
        let mut doc: DocumentMut = "[database]\npool = 16\n\n[legacy_box]\nvalue = \"abc\"\n"
            .parse()
            .expect("parse");
        let manifest: ConfigMigrationsManifest = serde_json::from_value(serde_json::json!({
            "format_version": 1,
            "toml_migrations": [
                {
                    "id": "shape_flips",
                    "ops": [
                        { "op": "wrap_scalar_in_table", "path": "database.pool", "target_field": "database.pool.size" },
                        { "op": "unwrap_table_field", "from_table": "legacy_box", "field": "value", "to": "legacy_box" }
                    ]
                }
            ]
        }))
        .expect("manifest");

        let first = apply_toml_migrations(&mut doc, &manifest, None).expect("apply");
        assert!(first.changed);
        assert_eq!(doc["database"]["pool"]["size"].as_integer(), Some(16));
        assert_eq!(doc["legacy_box"].as_str(), Some("abc"));

        let second = apply_toml_migrations(&mut doc, &manifest, None).expect("idempotent");
        assert!(!second.changed);
    }

    #[test]
    fn test_overwrite_false_preserves_existing_target_values() {
        let mut doc: DocumentMut = "[database]\nname = \"new.db\"\ndb_name = \"old.db\"\n"
            .parse()
            .expect("parse");
        let manifest = builtin_v013_manifest();
        apply_toml_migrations(&mut doc, &manifest, None).expect("apply");
        assert_eq!(doc["database"]["name"].as_str(), Some("new.db"));
        assert!(doc["database"].get("db_name").is_none());
    }
}
