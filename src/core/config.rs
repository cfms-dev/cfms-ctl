//! Lossless and forward-compatible `config.toml` reader/editor.
//!
//! Uses `toml_edit::DocumentMut` so unknown sections added by newer CFMS
//! server versions are preserved verbatim without failing validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, Item, Key, TableLike, Value};
use crate::core::atomic::write_with_timestamped_backup;
use crate::core::error::{CfmsError, Result};
use crate::core::schema::{
    evaluate_schema_invariants, load_json_schema_file, validate_instance_against_schema,
};
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

/// Result of synchronizing a `ConfigDocument` with a template `ConfigDocument`.
#[derive(Debug, Clone, Serialize)]
pub struct TemplateSyncPlan {
    pub config_path: PathBuf,
    pub template_path: PathBuf,
    pub changed: bool,
    pub added_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub preserved_paths: Vec<String>,
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

    /// Synchronize this configuration document in-place with `template` using `toml_edit` CST merging.
    pub fn sync_with_template(
        &mut self,
        template: &Self,
        remove_paths: &[String],
        prune: bool,
    ) -> Result<TemplateSyncPlan> {
        self.sync_with_template_and_schema(template, remove_paths, prune, None)
    }

    /// Synchronize this configuration document in-place with `template` using `toml_edit` CST merging,
    /// and optionally validate the resulting configuration against an external JSON Schema file.
    ///
    /// - Existing operator values, inline comments, section headers, and key ordering are preserved.
    /// - Missing keys and sections from `template` are inserted with their template comments (`Decor`).
    /// - Template-external paths in `self` are preserved in `preserved_paths` unless removed via
    ///   `remove_paths` or `prune`.
    /// - When `schema_path` is provided, the merged document is validated against the JSON Schema
    ///   and its declarative `x-invariants` rules.
    pub fn sync_with_template_and_schema(
        &mut self,
        template: &Self,
        remove_paths: &[String],
        prune: bool,
        schema_path: Option<&Path>,
    ) -> Result<TemplateSyncPlan> {
        if paths_refer_to_same_file(&self.path, &template.path) {
            return Err(CfmsError::Config(
                "The configuration template must be different from config.toml".to_string(),
            ));
        }

        let mut candidate = self.doc.clone();
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
            let is_template_external = unknown_roots
                .iter()
                .any(|u| req == u || req.starts_with(&format!("{u}.")));
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
        let warnings = candidate_wrapper.validate_with_schema(schema_path)?;

        added_paths.sort();
        let mut removed_paths = selected_removals;
        removed_paths.sort();
        preserved_paths.sort();

        let changed = !added_paths.is_empty() || !removed_paths.is_empty();
        if changed {
            self.doc = candidate_wrapper.doc;
        }

        Ok(TemplateSyncPlan {
            config_path: self.path.clone(),
            template_path: template.path.clone(),
            changed,
            added_paths,
            removed_paths,
            preserved_paths,
            warnings,
        })
    }

    /// Validate structural invariants and optionally evaluate an external `config.schema.json`
    /// (including standard JSON Schema keywords and declarative `x-invariants`).
    pub fn validate_with_schema(&self, schema_path: Option<&Path>) -> Result<Vec<String>> {
        if let Some(sec_item) = self.doc.get("security")
            && !sec_item.is_table_like()
        {
            return Err(CfmsError::Config(
                "Configuration section 'security' must be a table".to_string(),
            ));
        }

        // Verify that the minimal [database] connection table required by cfms-ctl is well-formed.
        let _ = self.database_config()?;

        let Some(path) = schema_path else {
            return Ok(Vec::new());
        };

        let schema_json = load_json_schema_file(path)?;
        let config_json: serde_json::Value = toml::from_str(&self.doc.to_string()).map_err(|e| {
            CfmsError::Config(format!(
                "Unable to convert '{}' for schema validation: {e}",
                self.path.display()
            ))
        })?;

        validate_instance_against_schema(&schema_json, &config_json, "config.toml")?;
        evaluate_schema_invariants(&schema_json, &config_json)
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
    if parts.is_empty() {
        return false;
    }
    let mut current = root;
    for (idx, part) in parts.iter().enumerate() {
        let Some(item) = current.get(part) else {
            return false;
        };
        if item.is_none() {
            return false;
        }
        if idx + 1 == parts.len() {
            return true;
        }
        let Some(next_table) = item.as_table_like() else {
            return false;
        };
        current = next_table;
    }
    false
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
    fn test_sync_template_with_external_json_schema_and_invariants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let template_path = dir.path().join("config.toml.sample");
        let schema_path = dir.path().join("config.schema.json");

        let template_content = r#"[server]
host = "0.0.0.0"
port = 5104
secret_key = ""

[server.admission_control]
max_connections = 64
max_connections_per_ip = 16
max_inflight_requests = 12

[security]
pepper = ""

[database]
type = "sqlite"
file = "app.db"

[database.pool]
size = 5
max_overflow = 10
"#;
        let schema_content = r#"{
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "server": {
                    "type": "object",
                    "properties": {
                        "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
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
        }"#;
        std::fs::write(&template_path, template_content).expect("write template");
        std::fs::write(&schema_path, schema_content).expect("write schema");

        // 1. Valid config with inflight > pool sum and empty pepper produces non-blocking warnings from schema
        let valid_config = r#"[server]
host = "127.0.0.1"
port = 5104
secret_key = "secret"

[server.admission_control]
max_inflight_requests = 20

[security]
pepper = ""

[database]
type = "sqlite"
file = "app.db"
"#;
        std::fs::write(&config_path, valid_config).expect("write config");
        let mut doc = ConfigDocument::load(&config_path).expect("load config");
        let template_doc = ConfigDocument::load(&template_path).expect("load template");
        let plan = doc
            .sync_with_template_and_schema(&template_doc, &[], false, Some(&schema_path))
            .expect("sync with schema");
        assert_eq!(plan.warnings.len(), 2);

        // 2. Config violating blocking order invariant fails
        let bad_config = r#"[server]
host = "127.0.0.1"
port = 5104

[server.admission_control]
max_connections = 32
max_connections_per_ip = 64

[database]
type = "sqlite"
file = "app.db"
"#;
        std::fs::write(&config_path, bad_config).expect("write bad config");
        let mut bad_doc = ConfigDocument::load(&config_path).expect("load bad config");
        let err = bad_doc
            .sync_with_template_and_schema(&template_doc, &[], false, Some(&schema_path))
            .expect_err("blocking invariant violation");
        assert!(
            err.to_string()
                .contains("max_connections_per_ip must not exceed max_connections")
        );
    }
}
