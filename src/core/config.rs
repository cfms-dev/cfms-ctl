//! Lossless and forward-compatible `config.toml` reader/editor.
//!
//! Uses `toml_edit::DocumentMut` so unknown sections added by newer CFMS
//! server versions are preserved verbatim without failing validation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use toml_edit::DocumentMut;
use crate::core::atomic::write_with_timestamped_backup;
use crate::core::error::{CfmsError, Result};
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
}
