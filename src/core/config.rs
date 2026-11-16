//! Lossless and forward-compatible `config.toml` reader/editor.
//!
//! Uses `toml_edit::DocumentMut` so unknown sections added by newer CFMS
//! server versions are preserved verbatim without failing validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use toml_edit::{Array, DocumentMut, Item, Key, Table, TableLike, Value};
use crate::core::atomic::write_with_timestamped_backup;
use crate::core::contract::CoreConfigContract;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::DatabaseKind;

const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

/// Minimal typed `[database]` section extracted from `config.toml`.
/// Unknown fields in `[database]` are tolerated and ignored during extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSectionConfig {
    #[serde(rename = "type")]
    pub kind: DatabaseKind,
    #[serde(default = "default_sqlite_file")]
    pub file: String,
    #[serde(default = "default_db_host")]
    pub host: String,
    #[serde(default = "default_db_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_db_name")]
    pub name: String,
    #[serde(default = "default_charset")]
    pub charset: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

fn default_sqlite_file() -> String {
    "app.db".to_string()
}
fn default_db_host() -> String {
    "localhost".to_string()
}
const fn default_db_port() -> u16 {
    3306
}
fn default_db_name() -> String {
    "app_db".to_string()
}
fn default_charset() -> String {
    "utf8mb4".to_string()
}

impl DatabaseSectionConfig {
    /// Validate that this `[database]` configuration contains complete, non-memory settings
    /// suitable as a `database migrate` target, using the raw TOML table to verify required keys.
    pub fn validate_as_migration_target(&self, raw_table: &dyn TableLike) -> Result<()> {
        match self.kind {
            DatabaseKind::Sqlite => {
                let raw_file = raw_table.get("file").and_then(|v| v.as_str());
                let Some(file) = raw_file else {
                    return Err(CfmsError::Config(
                        "Target SQLite configuration requires database.file".to_string(),
                    ));
                };
                if file.trim().is_empty() {
                    return Err(CfmsError::Config(
                        "Target SQLite configuration requires a non-empty database.file".to_string(),
                    ));
                }
                if file == ":memory:" {
                    return Err(CfmsError::Config(
                        "An in-memory SQLite database cannot be used as a migration target"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            DatabaseKind::Mysql | DatabaseKind::Postgresql => {
                let label = match self.kind {
                    DatabaseKind::Mysql => "MySQL",
                    DatabaseKind::Postgresql => "PostgreSQL",
                    DatabaseKind::Sqlite => unreachable!(),
                };
                for field in ["host", "username", "name"] {
                    let val = raw_table.get(field).and_then(|v| v.as_str());
                    if val.is_none_or(|s| s.trim().is_empty()) {
                        return Err(CfmsError::Config(format!(
                            "Target {label} configuration requires database.{field}"
                        )));
                    }
                }
                if raw_table.get("password").and_then(|v| v.as_str()).is_none() {
                    return Err(CfmsError::Config(format!(
                        "Target {label} configuration requires string database.password"
                    )));
                }
                let port_valid = raw_table
                    .get("port")
                    .and_then(|v| v.as_integer())
                    .is_some_and(|p| (1..=65535).contains(&p));
                if !port_valid {
                    return Err(CfmsError::Config(format!(
                        "Target {label} database.port must be an integer from 1 to 65535"
                    )));
                }
                if self.kind == DatabaseKind::Mysql && self.charset != "utf8mb4" {
                    return Err(CfmsError::Config(
                        "Target MySQL database.charset must be 'utf8mb4'".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Ensure source and target do not resolve to the exact same physical database.
    pub fn ensure_distinct_from(
        &self,
        target: &Self,
        paths: &WorkspacePaths,
    ) -> Result<()> {
        if self.kind != target.kind {
            return Ok(());
        }
        match self.kind {
            DatabaseKind::Sqlite => {
                let src_path = normalize_target_path(&paths.resolve_sqlite_path(&self.file));
                let dst_path = normalize_target_path(&paths.resolve_sqlite_path(&target.file));
                if src_path == dst_path {
                    return Err(CfmsError::Config(format!(
                        "Source and target SQLite databases resolve to the same file: '{}'",
                        dst_path.display()
                    )));
                }
            }
            DatabaseKind::Mysql | DatabaseKind::Postgresql => {
                let same_host = self.host.trim().eq_ignore_ascii_case(target.host.trim());
                let same_port = self.port == target.port;
                let same_db = self.name.trim() == target.name.trim();
                if same_host && same_port && same_db {
                    return Err(CfmsError::Config(format!(
                        "Source and target {} databases resolve to the same endpoint '{}:{}/{}'",
                        self.kind, target.host, target.port, target.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// Human-readable display endpoint without credentials.
    #[must_use]
    pub fn display_endpoint(&self, paths: &WorkspacePaths) -> String {
        match self.kind {
            DatabaseKind::Sqlite => paths.resolve_sqlite_path(&self.file).display().to_string(),
            DatabaseKind::Mysql | DatabaseKind::Postgresql => {
                format!("{}:{}/{}", self.host, self.port, self.name)
            }
        }
    }
}

fn normalize_target_path(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) {
        let base = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(canon_parent) = std::fs::canonicalize(base) {
            return canon_parent.join(file_name);
        }
    }
    path.to_path_buf()
}

/// High-level summary of `config.toml` for diagnostics and operations.
#[derive(Debug, Clone, Serialize)]
pub struct ServerConfigSummary {
    pub debug: bool,
    pub host: String,
    pub port: u16,
    pub has_secret_key: bool,
    pub has_pepper: bool,
    pub enabled_extensions: Vec<String>,
    pub database: DatabaseSectionConfig,
}

/// Core TOML path renamed cleanly via `x-renamed-from` in `core_config_contract`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenamedPathRecord {
    pub from: String,
    pub to: String,
}

/// Result of synchronizing a `ConfigDocument` with a template `ConfigDocument`.
#[derive(Debug, Clone, Serialize)]
pub struct TemplateSyncPlan {
    pub config_path: PathBuf,
    pub template_path: PathBuf,
    pub changed: bool,
    pub renamed_paths: Vec<RenamedPathRecord>,
    pub added_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub preserved_unknown_core_paths: Vec<String>,
    pub warnings: Vec<String>,
}

/// Wrapper around a raw UTF-8 string and its parsed `toml_edit::DocumentMut`.
#[derive(Debug, Clone)]
pub struct ConfigDocument {
    path: PathBuf,
    raw_source: String,
    doc: DocumentMut,
}

impl ConfigDocument {
    /// Load a TOML configuration file from disk with size bounds and UTF-8 validation.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path).map_err(|e| {
            CfmsError::Config(format!("Unable to stat configuration file '{}': {e}", path.display()))
        })?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(CfmsError::Config(format!(
                "Configuration file '{}' exceeds the 16 MiB limit",
                path.display()
            )));
        }
        let raw_source = std::fs::read_to_string(path).map_err(|e| {
            CfmsError::Config(format!("Unable to read configuration file '{}': {e}", path.display()))
        })?;
        let doc = raw_source.parse::<DocumentMut>().map_err(|e| {
            CfmsError::Config(format!("Invalid TOML syntax in '{}': {e}", path.display()))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            raw_source,
            doc,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn raw_source(&self) -> &str {
        &self.raw_source
    }

    #[must_use]
    pub const fn document(&self) -> &DocumentMut {
        &self.doc
    }

    pub const fn document_mut(&mut self) -> &mut DocumentMut {
        &mut self.doc
    }

    /// Extract the `[database]` section without validating unrelated sections.
    pub fn database_config(&self) -> Result<DatabaseSectionConfig> {
        let Some(db_item) = self.doc.get("database") else {
            return Err(CfmsError::Config(
                "Configuration is missing required [database] table".to_string(),
            ));
        };
        let db_toml_str = db_item.to_string();
        toml::from_str::<DatabaseSectionConfig>(&db_toml_str).map_err(|e| {
            CfmsError::Config(format!("Invalid [database] configuration in '{}': {e}", self.path.display()))
        })
    }

    /// Extract a diagnostic summary from `config.toml` using open-world parsing.
    pub fn summary(&self) -> Result<ServerConfigSummary> {
        let database = self.database_config()?;
        let debug = self
            .doc
            .get("debug")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let server_table = self.doc.get("server").and_then(|v| v.as_table_like());
        let host = server_table
            .and_then(|t| t.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("localhost")
            .to_string();
        let port = server_table
            .and_then(|t| t.get("port"))
            .and_then(|v| v.as_integer())
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(5104);
        let has_secret_key = server_table
            .and_then(|t| t.get("secret_key"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty());

        let has_pepper = self
            .doc
            .get("security")
            .and_then(|v| v.as_table_like())
            .and_then(|t| t.get("pepper"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty());

        let enabled_extensions = self
            .doc
            .get("extensions")
            .and_then(|v| v.as_table_like())
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Ok(ServerConfigSummary {
            debug,
            host,
            port,
            has_secret_key,
            has_pepper,
            enabled_extensions,
            database,
        })
    }

    /// Persist changes atomically and create a timestamped backup of the previous file.
    pub fn save_with_backup(&self) -> Result<PathBuf> {
        let rendered = self.doc.to_string();
        write_with_timestamped_backup(&self.path, &self.raw_source, rendered.as_bytes())
    }

    /// Replace this document's `[database]` section with the `[database]` section from `target`,
    /// validating the resulting document (including optional core contract) before mutating `self`.
    pub fn replace_database_section(
        &mut self,
        target: &Self,
        contract: Option<&CoreConfigContract>,
    ) -> Result<()> {
        if paths_refer_to_same_file(&self.path, &target.path) {
            return Err(CfmsError::Config(
                "Target database configuration must be different from config.toml".to_string(),
            ));
        }
        let Some(target_db_item) = target.doc.get("database") else {
            return Err(CfmsError::Config(
                "Target configuration must contain a [database] table".to_string(),
            ));
        };
        if !target_db_item.is_table_like() {
            return Err(CfmsError::Config(
                "Target configuration [database] entry must be a table".to_string(),
            ));
        }

        let mut cloned_db = target_db_item.clone();
        clear_table_positions(&mut cloned_db);

        let mut candidate = self.doc.clone();
        candidate["database"] = cloned_db;

        let candidate_wrapper = Self {
            path: self.path.clone(),
            raw_source: self.raw_source.clone(),
            doc: candidate,
        };
        candidate_wrapper.validate_with_contract(contract)?;
        self.doc = candidate_wrapper.doc;
        Ok(())
    }

    /// Read `[extensions].enabled` strictly without coercing invalid types to empty.
    ///
    /// Returns `Ok(None)` when `[extensions]` or `extensions.enabled` is absent.
    pub fn extensions_enabled_raw(&self) -> Result<Option<Vec<String>>> {
        let Some(ext_item) = self.doc.get("extensions") else {
            return Ok(None);
        };
        let Some(ext_table) = ext_item.as_table_like() else {
            return Err(CfmsError::Config(format!(
                "Configuration section 'extensions' in '{}' must be a table",
                self.path.display()
            )));
        };
        let Some(enabled_item) = ext_table.get("enabled") else {
            return Ok(None);
        };
        let Some(array) = enabled_item.as_array() else {
            return Err(CfmsError::Config(format!(
                "Configuration value 'extensions.enabled' in '{}' must be an array of strings",
                self.path.display()
            )));
        };

        let mut values = Vec::with_capacity(array.len());
        for item in array.iter() {
            let Some(text) = item.as_str() else {
                return Err(CfmsError::Config(format!(
                    "All entries in 'extensions.enabled' in '{}' must be strings",
                    self.path.display()
                )));
            };
            values.push(text.to_string());
        }
        Ok(Some(values))
    }

    /// Losslessly update `[extensions].enabled` in memory, preserving comments and formatting.
    ///
    /// Creates the `[extensions]` table if absent, validates against `contract` when supplied,
    /// and commits the candidate `DocumentMut` only if validation succeeds.
    pub fn set_extensions_enabled(
        &mut self,
        enabled: &[String],
        contract: Option<&CoreConfigContract>,
    ) -> Result<Vec<String>> {
        let mut candidate = self.doc.clone();
        if !candidate.contains_key("extensions") {
            candidate["extensions"] = Item::Table(Table::new());
        }
        let Some(ext_item) = candidate.get_mut("extensions") else {
            unreachable!("inserted extensions table if missing");
        };
        let Some(ext_table) = ext_item.as_table_like_mut() else {
            return Err(CfmsError::Config(format!(
                "Configuration section 'extensions' in '{}' must be a table",
                self.path.display()
            )));
        };

        let mut new_array = Array::new();
        for identifier in enabled {
            new_array.push(identifier.as_str());
        }

        if let Some(existing_item) = ext_table.get_mut("enabled") {
            match existing_item {
                Item::Value(existing_val) if existing_val.is_array() => {
                    let decor = existing_val.decor().clone();
                    let mut replacement = Value::Array(new_array);
                    *replacement.decor_mut() = decor;
                    *existing_val = replacement;
                }
                _ => {
                    return Err(CfmsError::Config(format!(
                        "Configuration value 'extensions.enabled' in '{}' must be an array of strings",
                        self.path.display()
                    )));
                }
            }
        } else {
            ext_table.insert("enabled", Item::Value(Value::Array(new_array)));
        }

        let candidate_wrapper = Self {
            path: self.path.clone(),
            raw_source: self.raw_source.clone(),
            doc: candidate,
        };
        let warnings = if contract.is_some() {
            candidate_wrapper.validate_with_contract(contract)?
        } else {
            Vec::new()
        };
        self.doc = candidate_wrapper.doc;
        Ok(warnings)
    }

    /// Synchronize this configuration document in-place with `template` using `toml_edit` CST merging.
    pub fn sync_with_template(
        &mut self,
        template: &Self,
        remove_paths: &[String],
        prune: bool,
    ) -> Result<TemplateSyncPlan> {
        self.sync_with_contract(template, remove_paths, prune, None)
    }

    /// Synchronize this configuration document in-place with `template` using `toml_edit` CST merging
    /// and an optional [`CoreConfigContract`].
    ///
    /// When `contract` is provided:
    /// - Core fields declaring `x-renamed-from` (e.g. `database.db_name -> database.name`) are moved
    ///   before missing template defaults are merged.
    /// - Unmanaged `[extensions.<id>]` subtables (`x-unmanaged-subtables: true`) are preserved verbatim.
    /// - Removed/unknown core fields are preserved with warnings unless `--prune` removes them.
    pub fn sync_with_contract(
        &mut self,
        template: &Self,
        remove_paths: &[String],
        prune: bool,
        contract: Option<&CoreConfigContract>,
    ) -> Result<TemplateSyncPlan> {
        if paths_refer_to_same_file(&self.path, &template.path) {
            return Err(CfmsError::Config(
                "The configuration template must be different from config.toml".to_string(),
            ));
        }

        let mut candidate = self.doc.clone();
        let mut warnings = Vec::new();
        let mut renamed_paths = Vec::new();

        let mut unknown_roots = Vec::new();
        find_unknown_roots(
            candidate.as_table(),
            template.doc.as_table(),
            &[],
            &mut unknown_roots,
        )?;

        let requested_removals: BTreeSet<String> = remove_paths.iter().cloned().collect();
        let mut invalid_removals = Vec::new();
        for req in &requested_removals {
            let exists_in_current = has_dotted_path(candidate.as_table(), req);
            let is_template_external = !has_dotted_path(template.doc.as_table(), req)
                && (unknown_roots
                    .iter()
                    .any(|u| req == u || req.starts_with(&format!("{u}.")))
                    || is_unmanaged_extension_path(req));
            if !exists_in_current || !is_template_external {
                invalid_removals.push(req.clone());
            }
        }
        if !invalid_removals.is_empty() {
            return Err(CfmsError::Config(format!(
                "Unknown --remove path(s): {}",
                invalid_removals.join(", ")
            )));
        }

        let selected_removals: Vec<String> = if prune {
            unknown_roots.clone()
        } else {
            requested_removals.into_iter().collect()
        };

        for path in &selected_removals {
            remove_dotted_path(candidate.as_table_mut(), template.doc.as_table(), path);
        }

        if let Some(c) = contract {
            apply_contract_renames(&mut candidate, c, &mut renamed_paths, &mut warnings);
        }

        let mut added_paths = Vec::new();
        merge_missing_from_template(
            candidate.as_table_mut(),
            template.doc.as_table(),
            &[],
            &mut added_paths,
        );

        let mut preserved_paths = Vec::new();
        find_unknown_roots(
            candidate.as_table(),
            template.doc.as_table(),
            &[],
            &mut preserved_paths,
        )?;

        let candidate_wrapper = Self {
            path: self.path.clone(),
            raw_source: self.raw_source.clone(),
            doc: candidate,
        };

        let mut preserved_unknown_core_paths = Vec::new();
        if let Some(c) = contract {
            let config_json = candidate_wrapper.to_json_value()?;
            let unknown_core = c.collect_unknown_core_toml_paths(&config_json);
            if !prune {
                for p in &unknown_core {
                    warnings.push(format!(
                        "Preserved removed/unknown core configuration path '{p}' (not present in core_config_contract.toml)"
                    ));
                }
                preserved_unknown_core_paths = unknown_core.clone();
            }
            // Validate active core schema + invariants + `[extensions]`, ignoring any preserved unknown core paths.
            candidate_wrapper.validate_structural_baseline()?;
            warnings.extend(c.validate_toml(&config_json, &preserved_unknown_core_paths)?);
        } else {
            candidate_wrapper.validate_structural_baseline()?;
        }

        added_paths.sort();
        let mut removed_paths = selected_removals;
        removed_paths.sort();
        preserved_paths.sort();

        let changed =
            !renamed_paths.is_empty() || !added_paths.is_empty() || !removed_paths.is_empty();
        if changed {
            self.doc = candidate_wrapper.doc;
        }

        Ok(TemplateSyncPlan {
            config_path: self.path.clone(),
            template_path: template.path.clone(),
            changed,
            renamed_paths,
            added_paths,
            removed_paths,
            preserved_paths,
            preserved_unknown_core_paths,
            warnings,
        })
    }

    fn validate_structural_baseline(&self) -> Result<()> {
        if let Some(sec_item) = self.doc.get("security")
            && !sec_item.is_table_like()
        {
            return Err(CfmsError::Config(
                "Configuration section 'security' must be a table".to_string(),
            ));
        }

        // Verify that the minimal [database] connection table required by cfms-ctl is well-formed.
        let _ = self.database_config()?;
        Ok(())
    }

    fn to_json_value(&self) -> Result<serde_json::Value> {
        toml::from_str(&self.doc.to_string()).map_err(|e| {
            CfmsError::Config(format!(
                "Unable to convert '{}' for contract validation: {e}",
                self.path.display()
            ))
        })
    }

    /// Validate structural invariants and strictly evaluate an optional [`CoreConfigContract`]
    /// (`Draft 2020-12` JSON Schema, `x-normalize`, `x-invariants`, and `[extensions]` rules).
    pub fn validate_with_contract(
        &self,
        contract: Option<&CoreConfigContract>,
    ) -> Result<Vec<String>> {
        self.validate_structural_baseline()?;

        let Some(c) = contract else {
            return Ok(Vec::new());
        };

        let config_json = self.to_json_value()?;
        c.validate_toml(&config_json, &[])
    }

    /// Extract normalized `[extensions.oidc_sso].issuer` if configured (trailing `/` stripped).
    #[must_use]
    pub fn oidc_sso_issuer(&self) -> Option<String> {
        let issuer = self
            .doc
            .get("extensions")
            .and_then(|v| v.as_table_like())
            .and_then(|ext| ext.get("oidc_sso"))
            .and_then(|v| v.as_table_like())
            .and_then(|oidc| oidc.get("issuer"))
            .and_then(|v| v.as_str())?
            .trim()
            .trim_end_matches('/');
        if issuer.is_empty() {
            None
        } else {
            Some(issuer.to_string())
        }
    }
}

fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    if let (Ok(ca), Ok(cb)) = (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        ca == cb
    } else {
        false
    }
}

fn find_unknown_roots(
    current: &dyn TableLike,
    template: &dyn TableLike,
    prefix: &[String],
    out: &mut Vec<String>,
) -> Result<()> {
    for (key, current_item) in current.iter() {
        if current_item.is_none() {
            continue;
        }
        // Unmanaged `[extensions.<id>]` subtables are never flagged for pruning.
        if prefix.len() == 1 && prefix[0] == "extensions" && key != "enabled" {
            continue;
        }
        let mut path = prefix.to_vec();
        path.push(key.to_string());
        let dotted = path.join(".");
        let current_is_table = current_item.is_table_like();

        let Some(template_item) = template.get(key) else {
            out.push(dotted);
            continue;
        };
        let template_is_table = template_item.is_table_like();
        if current_is_table != template_is_table {
            return Err(CfmsError::Config(format!(
                "Configuration shape differs from the template at '{dotted}'"
            )));
        }
        if let (Some(curr_sub), Some(tmpl_sub)) =
            (current_item.as_table_like(), template_item.as_table_like())
        {
            find_unknown_roots(curr_sub, tmpl_sub, &path, out)?;
        }
    }
    Ok(())
}

fn has_dotted_path(root: &dyn TableLike, dotted_path: &str) -> bool {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    let Some((first, rest)) = parts.split_first() else {
        return false;
    };
    let Some(mut item) = root.get(first) else {
        return false;
    };
    if item.is_none() {
        return false;
    }
    for part in rest {
        let Some(table) = item.as_table_like() else {
            return false;
        };
        let Some(next) = table.get(part) else {
            return false;
        };
        if next.is_none() {
            return false;
        }
        item = next;
    }
    true
}

fn is_unmanaged_extension_path(dotted_path: &str) -> bool {
    let mut parts = dotted_path.split('.');
    matches!((parts.next(), parts.next()), (Some("extensions"), Some(sub)) if sub != "enabled")
}

fn can_set_dotted_item(root: &dyn TableLike, dotted_path: &str) -> bool {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    if parts.is_empty() {
        return false;
    }
    let mut current = root;
    for part in &parts[..parts.len() - 1] {
        match current.get(part) {
            Some(item) if !item.is_none() => {
                let Some(next) = item.as_table_like() else {
                    return false;
                };
                current = next;
            }
            _ => return true,
        }
    }
    true
}

fn take_dotted_item(current: &mut dyn TableLike, dotted_path: &str) -> Option<Item> {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    take_parts_recursive(current, &parts)
}

fn take_parts_recursive(current: &mut dyn TableLike, parts: &[&str]) -> Option<Item> {
    let (first, rest) = parts.split_first()?;
    if rest.is_empty() {
        let removed = current.remove(first)?;
        return if removed.is_none() { None } else { Some(removed) };
    }
    let (taken, became_empty) = if let Some(child_item) = current.get_mut(first)
        && let Some(child_table) = child_item.as_table_like_mut()
    {
        let item = take_parts_recursive(child_table, rest);
        (item, child_table.is_empty())
    } else {
        return None;
    };
    if taken.is_some() && became_empty {
        current.remove(first);
    }
    taken
}

fn set_dotted_item(current: &mut dyn TableLike, dotted_path: &str, item: Item) {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    set_parts_recursive(current, &parts, item);
}

fn set_parts_recursive(current: &mut dyn TableLike, parts: &[&str], item: Item) {
    let Some((first, rest)) = parts.split_first() else {
        return;
    };
    if rest.is_empty() {
        current.insert(first, item);
        return;
    }
    if !current.contains_key(first) || current.get(first).is_some_and(Item::is_none) {
        let mut table = Table::new();
        table.set_implicit(true);
        current.insert(first, Item::Table(table));
    }
    if let Some(child) = current.get_mut(first).and_then(|i| i.as_table_like_mut()) {
        set_parts_recursive(child, rest, item);
    }
}

fn apply_contract_renames(
    candidate: &mut DocumentMut,
    contract: &CoreConfigContract,
    renamed: &mut Vec<RenamedPathRecord>,
    warnings: &mut Vec<String>,
) {
    for spec in contract.collect_toml_leaf_specs() {
        if spec.renamed_from.is_empty() {
            continue;
        }
        for old_path in &spec.renamed_from {
            if !has_dotted_path(candidate.as_table(), old_path) {
                continue;
            }
            if has_dotted_path(candidate.as_table(), &spec.dotted_path) {
                warnings.push(format!(
                    "Both legacy path '{old_path}' and new path '{}' exist; kept '{}'",
                    spec.dotted_path, spec.dotted_path
                ));
                break;
            }
            if !can_set_dotted_item(candidate.as_table(), &spec.dotted_path) {
                warnings.push(format!(
                    "Could not rename '{old_path}' to '{}' because parent path is not a table; kept '{old_path}'",
                    spec.dotted_path
                ));
                continue;
            }
            if let Some(mut moved_item) = take_dotted_item(candidate.as_table_mut(), old_path) {
                clear_table_positions(&mut moved_item);
                set_dotted_item(candidate.as_table_mut(), &spec.dotted_path, moved_item);
                renamed.push(RenamedPathRecord {
                    from: old_path.clone(),
                    to: spec.dotted_path.clone(),
                });
                break;
            }
        }
    }
}

fn remove_dotted_path(
    current: &mut dyn TableLike,
    template: &dyn TableLike,
    dotted_path: &str,
) {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    remove_parts_recursive(current, Some(template), &parts);
}

fn remove_parts_recursive(
    current: &mut dyn TableLike,
    template: Option<&dyn TableLike>,
    parts: &[&str],
) {
    let Some((first, rest)) = parts.split_first() else {
        return;
    };
    if rest.is_empty() {
        current.remove(first);
        return;
    }
    let child_template = template
        .and_then(|t| t.get(first))
        .and_then(|item| item.as_table_like());
    let should_prune_child = if let Some(child_item) = current.get_mut(first)
        && let Some(child_table) = child_item.as_table_like_mut()
    {
        remove_parts_recursive(child_table, child_template, rest);
        child_table.is_empty() && child_template.is_none()
    } else {
        false
    };
    if should_prune_child {
        current.remove(first);
    }
}

fn merge_missing_from_template(
    current: &mut dyn TableLike,
    template: &dyn TableLike,
    prefix: &[String],
    added_paths: &mut Vec<String>,
) {
    let template_keys: Vec<String> = template.iter().map(|(k, _)| k.to_string()).collect();
    for key_str in template_keys {
        let Some((template_key, template_item)) = template.get_key_value(&key_str) else {
            continue;
        };
        if template_item.is_none() {
            continue;
        }
        let mut path = prefix.to_vec();
        path.push(key_str.clone());

        if !current.contains_key(&key_str) {
            collect_leaf_paths(template_item, &path, added_paths);
            let mut cloned_item = template_item.clone();
            clear_table_positions(&mut cloned_item);
            insert_formatted_into_table_like(current, template_key, cloned_item);
        } else if let (Some(curr_item), Some(tmpl_sub)) =
            (current.get_mut(&key_str), template_item.as_table_like())
            && let Some(curr_sub) = curr_item.as_table_like_mut()
        {
            merge_missing_from_template(curr_sub, tmpl_sub, &path, added_paths);
        }
    }
}

fn insert_formatted_into_table_like(target: &mut dyn TableLike, key: &Key, item: Item) {
    target.insert(key.get(), item);
    if let Some(mut key_mut) = target.key_mut(key.get()) {
        *key_mut.leaf_decor_mut() = key.leaf_decor().clone();
        *key_mut.dotted_decor_mut() = key.dotted_decor().clone();
    }
}

fn clear_table_positions(item: &mut Item) {
    match item {
        Item::Table(table) => {
            table.set_position(None);
            for (_, child) in table.iter_mut() {
                clear_table_positions(child);
            }
        }
        Item::ArrayOfTables(arr) => {
            for table in arr.iter_mut() {
                table.set_position(None);
            }
        }
        Item::Value(Value::InlineTable(_)) | Item::Value(_) | Item::None => {}
    }
}

fn collect_leaf_paths(item: &Item, prefix: &[String], out: &mut Vec<String>) {
    if let Some(table) = item.as_table_like() {
        if table.is_empty() {
            out.push(prefix.join("."));
            return;
        }
        for (k, child) in table.iter() {
            let mut next = prefix.to_vec();
            next.push(k.to_string());
            collect_leaf_paths(child, &next, out);
        }
    } else {
        out.push(prefix.join("."));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tolerant_config_parsing_with_unknown_future_sections() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        let content = r#"
# Comment preserved
debug = false

[server]
host = "0.0.0.0"
port = 5104
secret_key = "supersecret"
future_server_flag = "new_in_v0_16"

[security]
pepper = "0123456789abcdef"

[database]
type = "postgresql"
host = "db.internal"
port = 5432
username = "cfms"
password = "secret"
name = "cfms_prod"
future_pool_strategy = "adaptive"

[future_section_v2]
experimental = true
"#;
        std::fs::write(temp.path(), content).expect("write config");
        let doc = ConfigDocument::load(temp.path()).expect("load config");
        let summary = doc.summary().expect("summary");
        assert_eq!(summary.database.kind, DatabaseKind::Postgresql);
        assert_eq!(summary.database.port, 5432);
        assert!(summary.has_pepper);
        assert!(summary.has_secret_key);
        assert!(summary.database.extra.contains_key("future_pool_strategy"));
    }

    #[test]
    fn test_sync_template_adds_missing_keys_and_tables_preserving_operator_comments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let template_path = dir.path().join("config.toml.sample");

        let config_content = r#"# Operator header comment
[server]
host = "127.0.0.1" # operator choice
port = 9999
secret_key = "custom-secret"

[security]
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[database]
type = "sqlite"
sqlite_path = "./data.db"
"#;
        let template_content = r#"# Default template header
[server]
host = "0.0.0.0"
port = 5104
secret_key = ""
# Max concurrent workers
workers = 4

[server.admission_control]
# Maximum inflight requests
max_inflight_requests = 12

[security]
pepper = ""

[database]
type = "sqlite"
sqlite_path = "./cfms.db"

[database.pool]
size = 5
max_overflow = 10
"#;
        std::fs::write(&config_path, config_content).expect("write config");
        std::fs::write(&template_path, template_content).expect("write template");

        let mut doc = ConfigDocument::load(&config_path).expect("load config");
        let template_doc = ConfigDocument::load(&template_path).expect("load template");
        let plan = doc
            .sync_with_template(&template_doc, &[], false)
            .expect("sync template");

        assert!(plan.changed);
        assert_eq!(
            plan.added_paths,
            vec![
                "database.pool.max_overflow".to_string(),
                "database.pool.size".to_string(),
                "server.admission_control.max_inflight_requests".to_string(),
                "server.workers".to_string(),
            ]
        );
        assert!(plan.removed_paths.is_empty());
        assert!(plan.preserved_paths.is_empty());

        let backup = doc.save_with_backup().expect("save with backup");
        assert!(backup.exists());

        let rendered = std::fs::read_to_string(&config_path).expect("read synced config");
        assert!(rendered.contains("# Operator header comment"));
        assert!(rendered.contains("host = \"127.0.0.1\" # operator choice"));
        assert!(rendered.contains("port = 9999"));
        assert!(rendered.contains("workers = 4"));
        assert!(rendered.contains("# Max concurrent workers"));
        assert!(rendered.contains("[server.admission_control]"));
        assert!(rendered.contains("max_inflight_requests = 12"));
        assert!(rendered.contains("[database.pool]"));
        assert!(rendered.contains("size = 5"));
    }

    #[test]
    fn test_sync_template_idempotent_when_already_synced_with_extra_operator_comments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let template_path = dir.path().join("config.toml.sample");

        let config_content = r#"# Operator note at top of file
[server]
# Custom inline note
host = "127.0.0.1" # keep loopback
port = 5104
secret_key = "non-empty"

[security]
pepper = "non-empty-pepper"

[database]
type = "sqlite"
sqlite_path = "./data.db"
"#;
        let template_content = r#"[server]
host = "0.0.0.0"
port = 5104
secret_key = ""

[security]
pepper = ""

[database]
type = "sqlite"
sqlite_path = "./cfms.db"
"#;
        std::fs::write(&config_path, config_content).expect("write config");
        std::fs::write(&template_path, template_content).expect("write template");

        let mut doc = ConfigDocument::load(&config_path).expect("load config");
        let template_doc = ConfigDocument::load(&template_path).expect("load template");
        let plan = doc
            .sync_with_template(&template_doc, &[], false)
            .expect("sync template");
        assert!(!plan.changed);
        assert!(plan.added_paths.is_empty());
        assert!(plan.removed_paths.is_empty());
        assert!(plan.preserved_paths.is_empty());
        assert_eq!(doc.document().to_string(), config_content);
    }

    #[test]
    fn test_sync_template_remove_specific_paths_and_prune_unknown_roots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let template_path = dir.path().join("config.toml.sample");

        let config_content = r#"[server]
host = "127.0.0.1"
port = 5104
secret_key = "secret"
deprecated_flag = true

[security]
pepper = "pepper"

[database]
type = "sqlite"
sqlite_path = "./data.db"

[legacy_section]
old_key = "value"
other_old = 123
"#;
        let template_content = r#"[server]
host = "0.0.0.0"
port = 5104
secret_key = ""

[security]
pepper = ""

[database]
type = "sqlite"
sqlite_path = "./cfms.db"
"#;
        std::fs::write(&config_path, config_content).expect("write config");
        std::fs::write(&template_path, template_content).expect("write template");

        let template_doc = ConfigDocument::load(&template_path).expect("load template");

        // 1. Remove only `legacy_section.old_key`; `legacy_section` and `server.deprecated_flag` remain as preserved roots.
        let mut doc = ConfigDocument::load(&config_path).expect("load config");
        let plan = doc
            .sync_with_template(
                &template_doc,
                &["legacy_section.old_key".to_string()],
                false,
            )
            .expect("partial remove");
        assert!(plan.changed);
        assert_eq!(plan.removed_paths, vec!["legacy_section.old_key"]);
        assert_eq!(
            plan.preserved_paths,
            vec!["legacy_section", "server.deprecated_flag"]
        );

        // 2. Prune all unknown roots.
        let mut doc2 = ConfigDocument::load(&config_path).expect("load config");
        let plan2 = doc2
            .sync_with_template(&template_doc, &[], true)
            .expect("prune all");
        assert!(plan2.changed);
        assert_eq!(
            plan2.removed_paths,
            vec!["legacy_section", "server.deprecated_flag"]
        );
        assert!(plan2.preserved_paths.is_empty());
        assert!(!doc2.document().to_string().contains("legacy_section"));
        assert!(!doc2.document().to_string().contains("deprecated_flag"));
    }

    #[test]
    fn test_sync_template_rejects_invalid_remove_paths_and_shape_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let template_path = dir.path().join("config.toml.sample");

        let config_content = r#"[server]
host = "127.0.0.1"
port = 5104
secret_key = "secret"

[security]
pepper = "pepper"

[database]
type = "sqlite"
sqlite_path = "./data.db"
"#;
        std::fs::write(&config_path, config_content).expect("write config");
        std::fs::write(&template_path, config_content).expect("write template");

        let template_doc = ConfigDocument::load(&template_path).expect("load template");

        // Reject removing a path still defined in template
        let mut doc = ConfigDocument::load(&config_path).expect("load config");
        let err = doc
            .sync_with_template(&template_doc, &["server.host".to_string()], false)
            .expect_err("cannot remove template path");
        assert!(err.to_string().contains("Unknown --remove path(s): server.host"));

        // Reject removing a path not present in config
        let err = doc
            .sync_with_template(&template_doc, &["nonexistent.key".to_string()], false)
            .expect_err("cannot remove missing path");
        assert!(
            err.to_string()
                .contains("Unknown --remove path(s): nonexistent.key")
        );

        // Reject shape mismatch where `server` is scalar in config but table in template
        std::fs::write(&config_path, "server = \"bad\"\n").expect("write malformed config");
        let mut bad_doc = ConfigDocument::load(&config_path).expect("load bad config");
        let err = bad_doc
            .sync_with_template(&template_doc, &[], false)
            .expect_err("shape mismatch");
        assert!(
            err.to_string()
                .contains("Configuration shape differs from the template at 'server'")
        );
    }

    #[test]
    fn test_sync_with_contract_renames_preserves_extensions_and_enforces_invariants() {
        use crate::core::contract::{CORE_CONFIG_CONTRACT_VERSION, DRAFT_2020_12_DIALECT};
        use serde_json::json;

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let template_path = dir.path().join("config.toml.sample");

        let template_content = r#"[server]
host = "0.0.0.0"
port = 5104
secret_key = ""
file_chunk_size = 1048576

[server.admission_control]
max_connections = 64
max_connections_per_ip = 16
max_inflight_requests = 12

[security]
pepper = ""

[database]
type = "sqlite"
name = "app_db"

[database.pool]
size = 5
max_overflow = 10

[extensions]
enabled = []
"#;
        let contract = CoreConfigContract {
            contract_version: CORE_CONFIG_CONTRACT_VERSION.to_string(),
            core_version: "0.14.0".to_string(),
            schema_dialect: DRAFT_2020_12_DIALECT.to_string(),
            toml: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "required": ["server", "security", "database", "extensions"],
                "properties": {
                    "server": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["file_chunk_size"],
                        "properties": {
                            "host": { "type": "string", "minLength": 1, "x-normalize": "trim" },
                            "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                            "secret_key": { "type": "string" },
                            "file_chunk_size": { "type": "integer", "exclusiveMinimum": 0 },
                            "admission_control": {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "max_connections": { "type": "integer", "minimum": 1 },
                                    "max_connections_per_ip": { "type": "integer", "minimum": 1 },
                                    "max_inflight_requests": { "type": "integer", "minimum": 1 }
                                }
                            }
                        }
                    },
                    "security": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "pepper": { "type": "string" }
                        }
                    },
                    "database": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["type"],
                        "properties": {
                            "type": { "type": "string", "enum": ["sqlite", "mysql", "postgresql"] },
                            "name": {
                                "type": "string",
                                "default": "app_db",
                                "x-renamed-from": ["database.db_name"]
                            },
                            "pool": {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "size": { "type": "integer", "minimum": 1 },
                                    "max_overflow": { "type": "integer", "minimum": 0 }
                                }
                            }
                        }
                    },
                    "extensions": {
                        "type": "object",
                        "additionalProperties": { "type": "object" },
                        "required": ["enabled"],
                        "x-unmanaged-subtables": true,
                        "properties": {
                            "enabled": {
                                "type": "array",
                                "uniqueItems": true,
                                "items": {
                                    "type": "string",
                                    "pattern": "^[a-z][a-z0-9_]*$",
                                    "not": { "enum": ["builtin", "scheduling"] }
                                }
                            }
                        }
                    }
                },
                "x-invariants": [
                    {
                        "rule": "order",
                        "lower": "server.admission_control.max_connections_per_ip",
                        "upper": "server.admission_control.max_connections",
                        "allow_equal": true,
                        "message": "server.admission_control.max_connections_per_ip must not exceed max_connections"
                    },
                    {
                        "rule": "order",
                        "lower": "server.admission_control.max_inflight_requests",
                        "upper": ["database.pool.size", "database.pool.max_overflow"],
                        "allow_equal": true,
                        "severity": "warning",
                        "message": "`server.admission_control.max_inflight_requests` exceeds `database.pool.size + database.pool.max_overflow`."
                    },
                    {
                        "rule": "non_empty",
                        "path": "security.pepper",
                        "severity": "warning",
                        "message": "Setting `security.pepper` to empty can lead to password storage security risks; run `cfms-ctl config fill-pepper`."
                    }
                ]
            }),
            options: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            }),
        };
        std::fs::write(&template_path, template_content).expect("write template");

        // 1. Legacy database.db_name renames cleanly, removed core field is preserved with warning,
        // unmanaged extension subtable is left untouched, and non-blocking invariant warnings surface.
        let valid_config = r#"[server]
host = "  127.0.0.1  "
port = 5104
secret_key = "secret"
removed_core_flag = true

[server.admission_control]
max_inflight_requests = 20

[security]
pepper = ""

[database]
type = "sqlite"
db_name = "custom_legacy_db"

[extensions]
enabled = ["oidc_sso"]

[extensions.oidc_sso]
issuer = "https://idp.example.com"
client_id = "cfms-web"
"#;
        std::fs::write(&config_path, valid_config).expect("write config");
        let mut doc = ConfigDocument::load(&config_path).expect("load config");
        let template_doc = ConfigDocument::load(&template_path).expect("load template");
        let plan = doc
            .sync_with_contract(&template_doc, &[], false, Some(&contract))
            .expect("sync with contract");
        assert_eq!(
            plan.renamed_paths,
            vec![RenamedPathRecord {
                from: "database.db_name".to_string(),
                to: "database.name".to_string(),
            }]
        );
        assert_eq!(
            plan.preserved_unknown_core_paths,
            vec!["server.removed_core_flag"]
        );
        assert!(plan.warnings.len() >= 3);
        let rendered = doc.document().to_string();
        assert!(rendered.contains("name = \"custom_legacy_db\""));
        assert!(!rendered.contains("db_name"));
        assert!(rendered.contains("removed_core_flag = true"));
        assert!(rendered.contains("[extensions.oidc_sso]"));
        assert!(rendered.contains("issuer = \"https://idp.example.com\""));

        // Strict validate still fails on preserved unknown core field
        assert!(doc.validate_with_contract(Some(&contract)).is_err());

        // Prune removes removed core key while keeping [extensions.oidc_sso] untouched
        let prune_plan = doc
            .sync_with_contract(&template_doc, &[], true, Some(&contract))
            .expect("prune with contract");
        assert_eq!(prune_plan.removed_paths, vec!["server.removed_core_flag"]);
        assert!(doc.document().to_string().contains("[extensions.oidc_sso]"));
        doc.validate_with_contract(Some(&contract))
            .expect("valid after prune");

        // 2. Config violating blocking order invariant fails
        let bad_config = r#"[server]
host = "127.0.0.1"
port = 5104
file_chunk_size = 1024

[server.admission_control]
max_connections = 32
max_connections_per_ip = 64

[security]
pepper = "abc"

[database]
type = "sqlite"

[extensions]
enabled = []
"#;
        std::fs::write(&config_path, bad_config).expect("write bad config");
        let mut bad_doc = ConfigDocument::load(&config_path).expect("load bad config");
        let err = bad_doc
            .sync_with_contract(&template_doc, &[], false, Some(&contract))
            .expect_err("blocking invariant violation");
        assert!(
            err.to_string()
                .contains("max_connections_per_ip must not exceed max_connections")
        );
    }

    #[test]
    fn migration_target_validation_and_distinct_checks_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).expect("src dir");
        std::fs::write(src_dir.join("main.py"), "# cfms").expect("main.py");
        let cfg_path = src_dir.join("config.toml");
        std::fs::write(
            &cfg_path,
            "# keep operator comment\n[server]\nhost = \"127.0.0.1\"\nport = 5104\n\n[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n",
        )
        .expect("write config");
        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let mut source_doc = ConfigDocument::load(&cfg_path).expect("load source");
        let source_cfg = source_doc.database_config().expect("source db");

        // Same SQLite file via relative vs explicit path rejected
        let same_target = dir.path().join("same.toml");
        std::fs::write(
            &same_target,
            "[database]\ntype = \"sqlite\"\nfile = \"./app.db\"\n",
        )
        .expect("same toml");
        let same_doc = ConfigDocument::load(&same_target).expect("load same");
        let same_cfg = same_doc.database_config().expect("same db");
        same_cfg
            .validate_as_migration_target(same_doc.document()["database"].as_table_like().unwrap())
            .expect("valid target shape");
        let err = source_cfg
            .ensure_distinct_from(&same_cfg, &paths)
            .expect_err("same sqlite file rejected");
        assert!(err.to_string().contains("same file"));

        // Incomplete PostgreSQL target missing host/password rejected
        let incomplete_pg = dir.path().join("bad_pg.toml");
        std::fs::write(
            &incomplete_pg,
            "[database]\ntype = \"postgresql\"\nname = \"cfms\"\n",
        )
        .expect("bad pg");
        let bad_pg_doc = ConfigDocument::load(&incomplete_pg).expect("load bad pg");
        let bad_pg_cfg = bad_pg_doc.database_config().expect("bad pg cfg");
        let err = bad_pg_cfg
            .validate_as_migration_target(bad_pg_doc.document()["database"].as_table_like().unwrap())
            .expect_err("incomplete pg rejected");
        assert!(err.to_string().contains("PostgreSQL"));

        // Valid PostgreSQL activation replaces [database] cleanly preserving comments & backing up
        let good_pg = dir.path().join("good_pg.toml");
        std::fs::write(
            &good_pg,
            "[database]\ntype = \"postgresql\"\nhost = \"127.0.0.1\"\nport = 5432\nusername = \"cfms\"\npassword = \"secret\"\nname = \"cfms_prod\"\n\n[database.pool]\nsize = 10\n",
        )
        .expect("good pg");
        let pg_doc = ConfigDocument::load(&good_pg).expect("load good pg");
        let pg_cfg = pg_doc.database_config().expect("pg cfg");
        pg_cfg
            .validate_as_migration_target(pg_doc.document()["database"].as_table_like().unwrap())
            .expect("valid pg");
        source_cfg
            .ensure_distinct_from(&pg_cfg, &paths)
            .expect("distinct dialect");

        source_doc
            .replace_database_section(&pg_doc, None)
            .expect("replace database section");
        let backup_path = source_doc.save_with_backup().expect("save with backup");
        assert!(backup_path.is_file());
        let saved = std::fs::read_to_string(&cfg_path).expect("read updated config");
        assert!(saved.contains("# keep operator comment"));
        assert!(saved.contains("name = \"cfms_prod\""));
        assert!(saved.contains("[database.pool]"));
    }

    #[test]
    fn test_set_extensions_enabled_preserves_comments_and_creates_missing_table() {
        let dir = tempfile::tempdir().expect("tempdir");

        // 1. Existing [extensions] table preserves key & inline comments and other sections
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            "# Global comment\n\n[extensions]\n# Keep extension comment\nenabled = [] # inline note\n\n[extensions.http_api]\nport = 5105\n",
        )
        .expect("write config");
        let mut doc = ConfigDocument::load(&cfg_path).expect("load");
        assert_eq!(doc.extensions_enabled_raw().expect("read"), Some(vec![]));
        doc.set_extensions_enabled(&["http_api".to_string(), "oidc_sso".to_string()], None)
            .expect("update enabled");
        let rendered = doc.document().to_string();
        assert!(rendered.contains("# Keep extension comment"));
        assert!(rendered.contains("] # inline note"));
        assert!(rendered.contains("[extensions.http_api]"));
        assert_eq!(
            doc.extensions_enabled_raw().expect("re-read"),
            Some(vec!["http_api".to_string(), "oidc_sso".to_string()])
        );

        // 2. Missing [extensions] table is created cleanly
        let minimal_path = dir.path().join("minimal.toml");
        std::fs::write(&minimal_path, "debug = true\n").expect("write minimal");
        let mut minimal = ConfigDocument::load(&minimal_path).expect("load minimal");
        assert_eq!(minimal.extensions_enabled_raw().expect("absent"), None);
        minimal
            .set_extensions_enabled(&["oidc_sso".to_string()], None)
            .expect("create extensions section");
        assert_eq!(
            minimal.extensions_enabled_raw().expect("created"),
            Some(vec!["oidc_sso".to_string()])
        );

        // 3. Invalid non-array extensions.enabled fails strictly
        let bad_path = dir.path().join("bad.toml");
        std::fs::write(&bad_path, "[extensions]\nenabled = \"http_api\"\n").expect("write bad");
        let bad = ConfigDocument::load(&bad_path).expect("load bad");
        assert!(bad.extensions_enabled_raw().is_err());
    }

    #[test]
    fn oidc_sso_issuer_normalizes_trailing_slash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[extensions.oidc_sso]\nissuer = \"https://idp.example.com///\"\n",
        )
        .expect("write");
        let doc = ConfigDocument::load(&path).expect("load");
        assert_eq!(
            doc.oidc_sso_issuer().as_deref(),
            Some("https://idp.example.com")
        );

        let empty_path = dir.path().join("empty.toml");
        std::fs::write(&empty_path, "[extensions.oidc_sso]\nissuer = \"   \"\n").expect("write");
        let empty = ConfigDocument::load(&empty_path).expect("load empty");
        assert_eq!(empty.oidc_sso_issuer(), None);
    }
}
