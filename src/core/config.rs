//! Lossless and forward-compatible `config.toml` reader/editor.
//!
//! Uses `toml_edit::DocumentMut` so unknown sections added by newer CFMS
//! server versions are preserved verbatim without failing validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use toml_edit::{Array, DocumentMut, Item, Key, Table, TableLike, Value};
use zeroize::Zeroizing;
use crate::core::atomic::write_with_timestamped_backup;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::DatabaseKind;

const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_S3_MAX_POOL_CONNECTIONS: usize = 64;

/// Zeroizing secret wrapper whose [`fmt::Debug`] and [`fmt::Display`] implementations never leak
/// credential material.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedSecret(Zeroizing<String>);

impl RedactedSecret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for RedactedSecret {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("\"[empty]\"")
        } else {
            f.write_str("\"[REDACTED]\"")
        }
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Active storage backend configured under `[provider].storage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageProviderKind {
    #[default]
    Local,
    S3,
}

impl StorageProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S3 => "s3",
        }
    }
}

impl fmt::Display for StorageProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// S3 bucket addressing mode matching `botocore` & CFMS server `[s3].addressing_style`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum S3AddressingStyle {
    #[default]
    Auto,
    Virtual,
    Path,
}

impl S3AddressingStyle {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Virtual => "virtual",
            Self::Path => "path",
        }
    }
}

impl fmt::Display for S3AddressingStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated runtime `[s3]` configuration extracted from `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3SectionConfig {
    pub bucket: String,
    pub endpoint_url: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<RedactedSecret>,
    pub session_token: Option<RedactedSecret>,
    pub region_name: Option<String>,
    pub addressing_style: S3AddressingStyle,
    pub max_pool_connections: usize,
}

impl S3SectionConfig {
    /// Non-sensitive summary safe for JSON serialization and terminal diagnostics.
    #[must_use]
    pub fn summary(&self) -> S3SectionSummary {
        S3SectionSummary {
            bucket: self.bucket.clone(),
            endpoint_url: self.endpoint_url.clone(),
            region_name: self.region_name.clone(),
            addressing_style: self.addressing_style,
            max_pool_connections: self.max_pool_connections,
            has_explicit_credentials: self.access_key_id.is_some(),
            has_session_token: self.session_token.is_some(),
        }
    }
}

/// Redacted `[s3]` configuration metadata safe to embed in diagnostic JSON/human reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct S3SectionSummary {
    pub bucket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_name: Option<String>,
    pub addressing_style: S3AddressingStyle,
    pub max_pool_connections: usize,
    pub has_explicit_credentials: bool,
    pub has_session_token: bool,
}

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
    pub storage_provider: StorageProviderKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3SectionSummary>,
}

/// Kind of 3-way merge conflict encountered while synchronizing `config.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigMergeConflictKind {
    /// Both local `config.toml` and the new template modified this key differently (kept local value).
    BothModified,
    /// Both local `config.toml` and the new template added this key with different values (kept local value).
    BothAdded,
    /// The new template removed this key, but local `config.toml` customized it (kept local value).
    ModifyDelete,
    /// Local `config.toml` removed this key, while the new template modified it (kept deleted).
    DeleteModify,
    /// Local `config.toml` and the new template disagree on table vs scalar shape (kept local value).
    ShapeMismatch,
}

impl fmt::Display for ConfigMergeConflictKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BothModified => "both_modified",
            Self::BothAdded => "both_added",
            Self::ModifyDelete => "modify_delete",
            Self::DeleteModify => "delete_modify",
            Self::ShapeMismatch => "shape_mismatch",
        })
    }
}

/// Non-destructive 3-way merge conflict resolved by keeping local `config.toml` (`ours`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigMergeConflict {
    pub path: String,
    pub kind: ConfigMergeConflictKind,
    pub detail: String,
}

/// Result of synchronizing a `ConfigDocument` with a template (2-way or 3-way merge).
#[derive(Debug, Clone, Serialize)]
pub struct TemplateSyncPlan {
    pub config_path: PathBuf,
    pub template_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_template_path: Option<PathBuf>,
    pub changed: bool,
    pub added_paths: Vec<String>,
    pub updated_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub conflicts: Vec<ConfigMergeConflict>,
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

    /// Extract the active `[provider].storage` kind (defaults to `local` when omitted).
    pub fn storage_provider(&self) -> Result<StorageProviderKind> {
        let Some(provider_item) = self.doc.get("provider") else {
            return Ok(StorageProviderKind::Local);
        };
        let Some(provider_tbl) = provider_item.as_table_like() else {
            return Err(CfmsError::Config(
                "Configuration section 'provider' must be a table".to_string(),
            ));
        };
        let Some(storage_item) = provider_tbl.get("storage") else {
            return Ok(StorageProviderKind::Local);
        };
        let Some(storage_kind) = storage_item.as_str() else {
            return Err(CfmsError::Config(
                "Configuration key 'provider.storage' must be a string".to_string(),
            ));
        };
        match storage_kind {
            "local" => Ok(StorageProviderKind::Local),
            "s3" => Ok(StorageProviderKind::S3),
            other => Err(CfmsError::Config(format!(
                "Unsupported storage provider '{other}' in 'provider.storage' (expected 'local' or 's3')"
            ))),
        }
    }

    /// Extract and validate `[s3]` if the section is present in `config.toml`.
    /// Allows empty `s3.bucket` when `[provider].storage` is `local` (matching `config.toml.sample`),
    /// while strictly validating types, endpoint URL syntax, addressing style, pool size, and
    /// credential pairing.
    pub fn s3_config_optional(&self) -> Result<Option<S3SectionConfig>> {
        let Some(s3_item) = self.doc.get("s3") else {
            return Ok(None);
        };
        let Some(s3_tbl) = s3_item.as_table_like() else {
            return Err(CfmsError::Config(
                "Configuration section 's3' must be a table".to_string(),
            ));
        };

        let bucket = optional_table_string(s3_tbl, "s3", "bucket")?
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let endpoint_url = match optional_table_string(s3_tbl, "s3", "endpoint_url")? {
            Some(raw) if !raw.trim().is_empty() => {
                let trimmed = raw.trim().to_string();
                validate_s3_endpoint_url(&trimmed)?;
                Some(trimmed)
            }
            _ => None,
        };

        let access_key_id = optional_table_string(s3_tbl, "s3", "access_key_id")?
            .filter(|s| !s.is_empty());
        let secret_access_key = optional_table_string(s3_tbl, "s3", "secret_access_key")?
            .filter(|s| !s.is_empty())
            .map(RedactedSecret::new);
        let session_token = optional_table_string(s3_tbl, "s3", "session_token")?
            .filter(|s| !s.is_empty())
            .map(RedactedSecret::new);

        if access_key_id.is_some() != secret_access_key.is_some() {
            return Err(CfmsError::Config(
                "s3.access_key_id and s3.secret_access_key must be configured together"
                    .to_string(),
            ));
        }
        if session_token.is_some() && access_key_id.is_none() {
            return Err(CfmsError::Config(
                "s3.session_token requires explicit access key credentials".to_string(),
            ));
        }

        let region_name = optional_table_string(s3_tbl, "s3", "region_name")?
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let addressing_style = match optional_table_string(s3_tbl, "s3", "addressing_style")? {
            None => S3AddressingStyle::Auto,
            Some(raw) => match raw.as_str() {
                "auto" => S3AddressingStyle::Auto,
                "virtual" => S3AddressingStyle::Virtual,
                "path" => S3AddressingStyle::Path,
                other => {
                    return Err(CfmsError::Config(format!(
                        "Unsupported s3.addressing_style '{other}' (expected 'auto', 'virtual', or 'path')"
                    )));
                }
            },
        };

        let max_pool_connections = match s3_tbl.get("max_pool_connections") {
            Some(item) => {
                let Some(val) = item.as_integer() else {
                    return Err(CfmsError::Config(
                        "Configuration key 's3.max_pool_connections' must be a positive integer"
                            .to_string(),
                    ));
                };
                if val < 1 {
                    return Err(CfmsError::Config(
                        "Configuration key 's3.max_pool_connections' must be >= 1".to_string(),
                    ));
                }
                usize::try_from(val).map_err(|_| {
                    CfmsError::Config(
                        "Configuration key 's3.max_pool_connections' exceeds platform range"
                            .to_string(),
                    )
                })?
            }
            None => self.default_s3_pool_connections(),
        };

        Ok(Some(S3SectionConfig {
            bucket,
            endpoint_url,
            access_key_id,
            secret_access_key,
            session_token,
            region_name,
            addressing_style,
            max_pool_connections,
        }))
    }

    fn default_s3_pool_connections(&self) -> usize {
        self.doc
            .get("server")
            .and_then(|v| v.as_table_like())
            .and_then(|srv| srv.get("admission_control"))
            .and_then(|v| v.as_table_like())
            .and_then(|ac| ac.get("max_connections"))
            .and_then(|v| v.as_integer())
            .and_then(|n| if n > 0 { usize::try_from(n).ok() } else { None })
            .unwrap_or(DEFAULT_S3_MAX_POOL_CONNECTIONS)
    }

    /// Extract and strictly validate `[s3]` settings required when `[provider].storage = "s3"`.
    pub fn s3_config(&self) -> Result<S3SectionConfig> {
        let Some(cfg) = self.s3_config_optional()? else {
            return Err(CfmsError::Config(
                "Configuration is missing required [s3] table when provider.storage = 's3'"
                    .to_string(),
            ));
        };
        if cfg.bucket.trim().is_empty() {
            return Err(CfmsError::Config(
                "Configuration key 's3.bucket' must not be empty when provider.storage = 's3'"
                    .to_string(),
            ));
        }
        Ok(cfg)
    }

    /// Extract a diagnostic summary from `config.toml` using open-world parsing.
    pub fn summary(&self) -> Result<ServerConfigSummary> {
        let database = self.database_config()?;
        let storage_provider = self.storage_provider()?;
        let s3 = match storage_provider {
            StorageProviderKind::S3 => Some(self.s3_config()?.summary()),
            StorageProviderKind::Local => self.s3_config_optional()?.map(|c| c.summary()),
        };
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
            storage_provider,
            s3,
        })
    }

    /// Persist changes atomically and create a timestamped backup of the previous file.
    pub fn save_with_backup(&self) -> Result<PathBuf> {
        let rendered = self.doc.to_string();
        write_with_timestamped_backup(&self.path, &self.raw_source, rendered.as_bytes())
    }

    /// Replace this document's `[database]` section with the `[database]` section from `target`,
    /// validating baseline structural invariants before mutating `self`.
    pub fn replace_database_section(&mut self, target: &Self) -> Result<()> {
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
        candidate_wrapper.validate_structural_baseline()?;
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
    /// Creates the `[extensions]` table if absent and commits the candidate `DocumentMut`.
    pub fn set_extensions_enabled(&mut self, enabled: &[String]) -> Result<()> {
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

        self.doc = candidate;
        Ok(())
    }

    /// Synchronize this configuration document in-place with `template` using 2-way `toml_edit` CST merging.
    pub fn sync_with_template(
        &mut self,
        template: &Self,
        remove_paths: &[String],
        prune: bool,
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
        candidate_wrapper.validate_structural_baseline()?;

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
            base_template_path: None,
            changed,
            added_paths,
            updated_paths: Vec::new(),
            removed_paths,
            preserved_paths,
            conflicts: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Perform a lossless semantic 3-way TOML merge of `self` (`ours`) against `base` (previous
    /// template) and `template` (`theirs`, new template) using `toml_edit` CST manipulation.
    ///
    /// Merge semantics:
    /// - Keys added in `template` (absent from `base` and `ours`) are inserted verbatim with template comments.
    /// - Keys modified in `template` (`base != template`) whose local value is unchanged (`ours == base`)
    ///   are updated automatically while preserving inline `ours` decor/comments.
    /// - Keys removed in `template` (`base` had them, `template` dropped them) whose local value is
    ///   unchanged (`ours == base`) are removed cleanly (along with emptied parent tables).
    /// - Unmanaged `[extensions.<id>]` subtables and operator custom keys are preserved verbatim.
    /// - On any 3-way conflict, local `ours` always wins non-destructively and a structured conflict
    ///   record plus human-readable warning are emitted.
    pub fn merge_three_way(
        &mut self,
        base: &Self,
        template: &Self,
        remove_paths: &[String],
        prune: bool,
    ) -> Result<TemplateSyncPlan> {
        if paths_refer_to_same_file(&self.path, &template.path) {
            return Err(CfmsError::Config(
                "The configuration template must be different from config.toml".to_string(),
            ));
        }
        if paths_refer_to_same_file(&self.path, &base.path) {
            return Err(CfmsError::Config(
                "The base configuration template must be different from config.toml".to_string(),
            ));
        }

        let mut candidate = self.doc.clone();
        let mut added_paths = Vec::new();
        let mut updated_paths = Vec::new();
        let mut removed_paths = Vec::new();
        let mut conflicts = Vec::new();
        let mut warnings = Vec::new();

        // Validate explicit `--remove` requests up front before mutating.
        let requested_removals: BTreeSet<String> = remove_paths.iter().cloned().collect();
        if !requested_removals.is_empty() {
            let mut invalid_removals = Vec::new();
            for req in &requested_removals {
                let exists_in_current = has_dotted_path(candidate.as_table(), req);
                let exists_in_template = has_dotted_path(template.doc.as_table(), req);
                if !exists_in_current || exists_in_template {
                    invalid_removals.push(req.clone());
                }
            }
            if !invalid_removals.is_empty() {
                return Err(CfmsError::Config(format!(
                    "Unknown --remove path(s): {}",
                    invalid_removals.join(", ")
                )));
            }
            for path in &requested_removals {
                remove_dotted_path(candidate.as_table_mut(), template.doc.as_table(), path);
                removed_paths.push(path.clone());
            }
        }

        merge_three_way_table(
            Some(base.doc.as_table()),
            candidate.as_table_mut(),
            template.doc.as_table(),
            &[],
            &mut ThreeWayAccum {
                added: &mut added_paths,
                updated: &mut updated_paths,
                removed: &mut removed_paths,
                conflicts: &mut conflicts,
                warnings: &mut warnings,
            },
        );

        if prune {
            let mut remaining_unknown = Vec::new();
            find_unknown_roots_tolerant(
                candidate.as_table(),
                template.doc.as_table(),
                &[],
                &mut remaining_unknown,
            );
            for path in &remaining_unknown {
                remove_dotted_path(candidate.as_table_mut(), template.doc.as_table(), path);
                removed_paths.push(path.clone());
            }
            let pruned_set: BTreeSet<&str> = remaining_unknown.iter().map(String::as_str).collect();
            if !pruned_set.is_empty() {
                conflicts.retain(|c| {
                    !(c.kind == ConfigMergeConflictKind::ModifyDelete
                        && pruned_set.iter().any(|p| {
                            c.path == *p || c.path.starts_with(&format!("{p}."))
                        }))
                });
                warnings = conflicts
                    .iter()
                    .map(|c| format!("Config merge conflict at '{}' ({}): {}", c.path, c.kind, c.detail))
                    .collect();
            }
        }

        let mut preserved_paths = Vec::new();
        find_unknown_roots_tolerant(
            candidate.as_table(),
            template.doc.as_table(),
            &[],
            &mut preserved_paths,
        );

        let candidate_wrapper = Self {
            path: self.path.clone(),
            raw_source: self.raw_source.clone(),
            doc: candidate,
        };
        candidate_wrapper.validate_structural_baseline()?;

        added_paths.sort();
        added_paths.dedup();
        updated_paths.sort();
        updated_paths.dedup();
        removed_paths.sort();
        removed_paths.dedup();
        preserved_paths.sort();
        preserved_paths.dedup();
        conflicts.sort_by(|a, b| a.path.cmp(&b.path));

        let changed =
            !added_paths.is_empty() || !updated_paths.is_empty() || !removed_paths.is_empty();
        if changed {
            self.doc = candidate_wrapper.doc;
        }

        Ok(TemplateSyncPlan {
            config_path: self.path.clone(),
            template_path: template.path.clone(),
            base_template_path: Some(base.path.clone()),
            changed,
            added_paths,
            updated_paths,
            removed_paths,
            preserved_paths,
            conflicts,
            warnings,
        })
    }

    /// Validate minimal structural invariants required by `cfms-ctl` (`[security]`, `[database]`, `[provider]`/`[s3]`).
    pub fn validate_structural_baseline(&self) -> Result<()> {
        if let Some(sec_item) = self.doc.get("security")
            && !sec_item.is_table_like()
        {
            return Err(CfmsError::Config(
                "Configuration section 'security' must be a table".to_string(),
            ));
        }

        // Verify that the minimal [database] connection table required by cfms-ctl is well-formed.
        let _ = self.database_config()?;

        // Align [provider] / [s3] structural invariants with server deployment rules.
        match self.storage_provider()? {
            StorageProviderKind::S3 => {
                let _ = self.s3_config()?;
            }
            StorageProviderKind::Local => {
                let _ = self.s3_config_optional()?;
            }
        }
        Ok(())
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

fn optional_table_string(
    table: &dyn TableLike,
    section: &str,
    key: &str,
) -> Result<Option<String>> {
    let Some(item) = table.get(key) else {
        return Ok(None);
    };
    let Some(value) = item.as_str() else {
        return Err(CfmsError::Config(format!(
            "Configuration key '{section}.{key}' must be a string"
        )));
    };
    Ok(Some(value.to_string()))
}

fn validate_s3_endpoint_url(endpoint: &str) -> Result<()> {
    let parsed = url::Url::parse(endpoint).map_err(|e| {
        CfmsError::Config(format!("Invalid s3.endpoint_url '{endpoint}': {e}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(CfmsError::Config(format!(
            "Invalid s3.endpoint_url '{endpoint}': scheme must be http or https"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(CfmsError::Config(format!(
            "Invalid s3.endpoint_url '{endpoint}': URL must include a host"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CfmsError::Config(
            "s3.endpoint_url must not embed credentials; configure s3.access_key_id and s3.secret_access_key instead"
                .to_string(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(CfmsError::Config(format!(
            "Invalid s3.endpoint_url '{endpoint}': query parameters and fragments are not supported"
        )));
    }
    Ok(())
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

fn find_unknown_roots_tolerant(
    current: &dyn TableLike,
    template: &dyn TableLike,
    prefix: &[String],
    out: &mut Vec<String>,
) {
    for (key, current_item) in current.iter() {
        if current_item.is_none() {
            continue;
        }
        if is_unmanaged_extension_key(prefix, key) {
            continue;
        }
        let mut path = prefix.to_vec();
        path.push(key.to_string());
        let dotted = path.join(".");

        let Some(template_item) = template.get(key).filter(|i| !i.is_none()) else {
            out.push(dotted);
            continue;
        };
        if let (Some(curr_sub), Some(tmpl_sub)) =
            (current_item.as_table_like(), template_item.as_table_like())
        {
            find_unknown_roots_tolerant(curr_sub, tmpl_sub, &path, out);
        }
    }
}

fn is_unmanaged_extension_key(prefix: &[String], key: &str) -> bool {
    prefix.len() == 1 && prefix[0] == "extensions" && key != "enabled"
}

fn is_unmanaged_extension_path(dotted_path: &str) -> bool {
    let mut parts = dotted_path.split('.');
    matches!((parts.next(), parts.next()), (Some("extensions"), Some(sub)) if sub != "enabled")
}

struct ThreeWayAccum<'a> {
    added: &'a mut Vec<String>,
    updated: &'a mut Vec<String>,
    removed: &'a mut Vec<String>,
    conflicts: &'a mut Vec<ConfigMergeConflict>,
    warnings: &'a mut Vec<String>,
}

impl ThreeWayAccum<'_> {
    fn push_conflict(&mut self, path: String, kind: ConfigMergeConflictKind, detail: String) {
        self.warnings
            .push(format!("Config merge conflict at '{path}' ({kind}): {detail}"));
        self.conflicts.push(ConfigMergeConflict { path, kind, detail });
    }
}

fn active_table_item<'a>(table: &'a dyn TableLike, key: &str) -> Option<&'a Item> {
    table.get(key).filter(|i| !i.is_none())
}

fn merge_three_way_table(
    base: Option<&dyn TableLike>,
    ours: &mut dyn TableLike,
    theirs: &dyn TableLike,
    prefix: &[String],
    acc: &mut ThreeWayAccum<'_>,
) {
    // Collect deterministic key order: theirs keys first (preserving template order for inserts),
    // then any remaining keys from base or ours.
    let mut ordered_keys: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (k, item) in theirs.iter() {
        if !item.is_none() && seen.insert(k.to_string()) {
            ordered_keys.push(k.to_string());
        }
    }
    if let Some(b_tbl) = base {
        for (k, item) in b_tbl.iter() {
            if !item.is_none() && seen.insert(k.to_string()) {
                ordered_keys.push(k.to_string());
            }
        }
    }
    let ours_keys: Vec<String> = ours
        .iter()
        .filter(|(_, item)| !item.is_none())
        .map(|(k, _)| k.to_string())
        .collect();
    for k in ours_keys {
        if seen.insert(k.clone()) {
            ordered_keys.push(k);
        }
    }

    for key in ordered_keys {
        if is_unmanaged_extension_key(prefix, &key) {
            continue;
        }
        let mut path = prefix.to_vec();
        path.push(key.clone());
        let dotted = path.join(".");

        let base_item = base.and_then(|b| active_table_item(b, &key));
        let theirs_kv = theirs
            .get_key_value(&key)
            .filter(|(_, item)| !item.is_none());
        let has_ours = active_table_item(ours, &key).is_some();

        match (base_item, has_ours, theirs_kv) {
            // 1. Added in theirs only
            (None, false, Some((t_key, t_item))) => {
                collect_leaf_paths(t_item, &path, acc.added);
                let mut cloned = t_item.clone();
                clear_table_positions(&mut cloned);
                insert_formatted_into_table_like(ours, t_key, cloned);
            }
            // 2. Added in both ours and theirs
            (None, true, Some((_, t_item))) => {
                let ours_is_tbl = active_table_item(ours, &key).is_some_and(Item::is_table_like);
                let theirs_is_tbl = t_item.is_table_like();
                if ours_is_tbl && theirs_is_tbl {
                    if let (Some(o_sub), Some(t_sub)) = (
                        ours.get_mut(&key).and_then(|i| i.as_table_like_mut()),
                        t_item.as_table_like(),
                    ) {
                        merge_three_way_table(None, o_sub, t_sub, &path, acc);
                    }
                } else if ours_is_tbl != theirs_is_tbl {
                    acc.push_conflict(
                        dotted,
                        ConfigMergeConflictKind::ShapeMismatch,
                        "local config and new template disagree on table vs scalar shape; kept local value"
                            .to_string(),
                    );
                } else if let Some(o_item) = active_table_item(ours, &key)
                    && !items_semantically_equal(o_item, t_item)
                {
                    acc.push_conflict(
                        dotted,
                        ConfigMergeConflictKind::BothAdded,
                        "added in both local config and new template with different values; kept local value"
                            .to_string(),
                    );
                }
            }
            // 3. Only in ours (operator custom key/table) -> preserve verbatim
            (None, true, None) => {}
            // 4. Absent from both ours and theirs -> no-op
            (_, false, None) => {}
            // 5. Present in base and theirs, deleted in ours
            (Some(b_item), false, Some((_, t_item))) => {
                if !items_semantically_equal(b_item, t_item) {
                    acc.push_conflict(
                        dotted,
                        ConfigMergeConflictKind::DeleteModify,
                        "key was removed in local config while modified in new template; kept removed"
                            .to_string(),
                    );
                }
            }
            // 6. Present in base and ours, removed in theirs
            (Some(b_item), true, None) => {
                let unchanged = active_table_item(ours, &key)
                    .is_some_and(|o_item| items_semantically_equal(o_item, b_item));
                if unchanged {
                    if let Some(removed_item) = ours.remove(&key) {
                        collect_leaf_paths(&removed_item, &path, acc.removed);
                    }
                } else {
                    acc.push_conflict(
                        dotted,
                        ConfigMergeConflictKind::ModifyDelete,
                        "key was removed in new template but customized locally; kept local value"
                            .to_string(),
                    );
                }
            }
            // 7. Present in base, ours, and theirs
            (Some(b_item), true, Some((_, t_item))) => {
                let b_is_tbl = b_item.is_table_like();
                let o_is_tbl = active_table_item(ours, &key).is_some_and(Item::is_table_like);
                let t_is_tbl = t_item.is_table_like();

                if b_is_tbl && o_is_tbl && t_is_tbl {
                    if let (Some(b_sub), Some(o_sub), Some(t_sub)) = (
                        b_item.as_table_like(),
                        ours.get_mut(&key).and_then(|i| i.as_table_like_mut()),
                        t_item.as_table_like(),
                    ) {
                        merge_three_way_table(Some(b_sub), o_sub, t_sub, &path, acc);
                    }
                } else if !b_is_tbl && o_is_tbl && t_is_tbl {
                    // Both ours and theirs converted scalar -> table; merge subkeys with empty base.
                    if let (Some(o_sub), Some(t_sub)) = (
                        ours.get_mut(&key).and_then(|i| i.as_table_like_mut()),
                        t_item.as_table_like(),
                    ) {
                        merge_three_way_table(None, o_sub, t_sub, &path, acc);
                    }
                } else if items_semantically_equal(b_item, t_item) {
                    // Unchanged in template -> keep ours untouched.
                } else if active_table_item(ours, &key)
                    .is_some_and(|o_item| items_semantically_equal(o_item, b_item))
                {
                    // Unchanged in ours, modified in theirs -> update cleanly.
                    replace_item_preserving_decor(ours, &key, t_item);
                    collect_leaf_paths(t_item, &path, acc.updated);
                } else if active_table_item(ours, &key)
                    .is_some_and(|o_item| items_semantically_equal(o_item, t_item))
                {
                    // Both ours and theirs converged to the same semantic value -> no-op.
                } else if o_is_tbl != t_is_tbl {
                    acc.push_conflict(
                        dotted,
                        ConfigMergeConflictKind::ShapeMismatch,
                        "local config and new template disagree on table vs scalar shape; kept local value"
                            .to_string(),
                    );
                } else {
                    acc.push_conflict(
                        dotted,
                        ConfigMergeConflictKind::BothModified,
                        "modified in both local config and new template; kept local value"
                            .to_string(),
                    );
                }
            }
        }
    }
}

fn replace_item_preserving_decor(target: &mut dyn TableLike, key: &str, new_item: &Item) {
    if let (Some(Item::Value(existing_val)), Item::Value(new_val)) = (target.get_mut(key), new_item)
        && !existing_val.is_inline_table()
        && !new_val.is_inline_table()
    {
        let decor = existing_val.decor().clone();
        let mut replacement = new_val.clone();
        *replacement.decor_mut() = decor;
        *existing_val = replacement;
        return;
    }

    let mut cloned = new_item.clone();
    clear_table_positions(&mut cloned);
    target.insert(key, cloned);
}

fn items_semantically_equal(a: &Item, b: &Item) -> bool {
    if a.is_none() && b.is_none() {
        return true;
    }
    if let (Some(ta), Some(tb)) = (a.as_table_like(), b.as_table_like()) {
        return table_likes_semantically_equal(ta, tb);
    }
    match (a, b) {
        (Item::Value(va), Item::Value(vb)) => values_semantically_equal(va, vb),
        (Item::ArrayOfTables(aa), Item::ArrayOfTables(ab)) => {
            aa.len() == ab.len()
                && aa
                    .iter()
                    .zip(ab.iter())
                    .all(|(ta, tb)| table_likes_semantically_equal(ta, tb))
        }
        _ => false,
    }
}

fn table_likes_semantically_equal(a: &dyn TableLike, b: &dyn TableLike) -> bool {
    let count_a = a.iter().filter(|(_, item)| !item.is_none()).count();
    let count_b = b.iter().filter(|(_, item)| !item.is_none()).count();
    if count_a != count_b {
        return false;
    }
    for (k, va) in a.iter() {
        if va.is_none() {
            continue;
        }
        let Some(vb) = b.get(k).filter(|item| !item.is_none()) else {
            return false;
        };
        if !items_semantically_equal(va, vb) {
            return false;
        }
    }
    true
}

fn values_semantically_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(sa), Value::String(sb)) => sa.value() == sb.value(),
        (Value::Integer(ia), Value::Integer(ib)) => ia.value() == ib.value(),
        (Value::Float(fa), Value::Float(fb)) => {
            let x = *fa.value();
            let y = *fb.value();
            x == y || (x.is_nan() && y.is_nan())
        }
        (Value::Boolean(ba), Value::Boolean(bb)) => ba.value() == bb.value(),
        (Value::Datetime(da), Value::Datetime(db)) => da.value() == db.value(),
        (Value::Array(aa), Value::Array(ab)) => {
            aa.len() == ab.len()
                && aa
                    .iter()
                    .zip(ab.iter())
                    .all(|(xa, xb)| values_semantically_equal(xa, xb))
        }
        (Value::InlineTable(ta), Value::InlineTable(tb)) => table_likes_semantically_equal(ta, tb),
        _ => false,
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
    fn test_merge_three_way_updates_adds_removes_preserves_extensions_and_reports_conflicts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_path = dir.path().join("base.toml.sample");
        let config_path = dir.path().join("config.toml");
        let new_tpl_path = dir.path().join("new.toml.sample");

        let base_content = r#"[server]
host = "0.0.0.0"
port = 5104
secret_key = ""
workers = 4
old_unmodified_flag = false
old_customized_flag = false
deleted_by_operator = "v1"
shape_key = "scalar_v1"

[legacy_unmodified]
k = 1

[security]
pepper = ""

[database]
type = "sqlite"
file = "app.db"

[database.pool]
size = 5
max_overflow = 10

[extensions]
enabled = []
"#;
        let ours_content = r#"# Operator header comment
[server]
host = "127.0.0.1" # custom bind
port = 5104 # unchanged default with inline note
secret_key = "operator-secret-key"
workers = 16 # customized by operator
old_unmodified_flag = false
old_customized_flag = true
both_added = "ours_val"
shape_key = "custom_scalar"

[legacy_unmodified]
k = 1

[security]
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[database]
type = "sqlite"
file = "prod.db"
pool = { size = 5, max_overflow = 20 }

[extensions]
enabled = ["oidc_sso"]

[extensions.oidc_sso]
issuer = "https://idp.example.com"
client_id = "cfms-web"

[operator_custom]
note = "keep-me"
"#;
        let new_tpl_content = r#"[server]
host = "0.0.0.0"
port = 5105
secret_key = ""
workers = 8
# Newly introduced timeout setting
request_timeout = 30
deleted_by_operator = "v2"
both_added = "theirs_val"

[server.shape_key]
mode = "structured"

[security]
pepper = ""

[database]
type = "sqlite"
file = "app.db"

[database.pool]
size = 10
max_overflow = 10

[extensions]
enabled = []
"#;
        std::fs::write(&base_path, base_content).unwrap();
        std::fs::write(&config_path, ours_content).unwrap();
        std::fs::write(&new_tpl_path, new_tpl_content).unwrap();

        let base_doc = ConfigDocument::load(&base_path).unwrap();
        let mut ours_doc = ConfigDocument::load(&config_path).unwrap();
        let new_tpl_doc = ConfigDocument::load(&new_tpl_path).unwrap();

        let plan = ours_doc
            .merge_three_way(&base_doc, &new_tpl_doc, &[], false)
            .expect("3-way merge succeeds non-destructively");

        assert!(plan.changed);
        assert_eq!(plan.base_template_path.as_deref(), Some(base_path.as_path()));
        assert_eq!(plan.added_paths, vec!["server.request_timeout".to_string()]);
        assert_eq!(
            plan.updated_paths,
            vec!["database.pool.size".to_string(), "server.port".to_string()]
        );
        assert_eq!(
            plan.removed_paths,
            vec![
                "legacy_unmodified.k".to_string(),
                "server.old_unmodified_flag".to_string(),
            ]
        );
        assert_eq!(
            plan.preserved_paths,
            vec![
                "operator_custom".to_string(),
                "server.old_customized_flag".to_string(),
            ]
        );

        // Verify all 5 conflict kinds were recorded non-destructively (ours wins)
        let by_path: BTreeMap<&str, ConfigMergeConflictKind> = plan
            .conflicts
            .iter()
            .map(|c| (c.path.as_str(), c.kind))
            .collect();
        assert_eq!(
            by_path.get("server.workers"),
            Some(&ConfigMergeConflictKind::BothModified)
        );
        assert_eq!(
            by_path.get("server.both_added"),
            Some(&ConfigMergeConflictKind::BothAdded)
        );
        assert_eq!(
            by_path.get("server.old_customized_flag"),
            Some(&ConfigMergeConflictKind::ModifyDelete)
        );
        assert_eq!(
            by_path.get("server.deleted_by_operator"),
            Some(&ConfigMergeConflictKind::DeleteModify)
        );
        assert_eq!(
            by_path.get("server.shape_key"),
            Some(&ConfigMergeConflictKind::ShapeMismatch)
        );
        assert_eq!(plan.warnings.len(), 5);

        let rendered = ours_doc.document().to_string();
        assert!(rendered.contains("# Operator header comment"));
        assert!(rendered.contains("port = 5105 # unchanged default with inline note"));
        assert!(rendered.contains("workers = 16 # customized by operator"));
        assert!(rendered.contains("# Newly introduced timeout setting"));
        assert!(rendered.contains("request_timeout = 30"));
        assert!(!rendered.contains("old_unmodified_flag"));
        assert!(!rendered.contains("[legacy_unmodified]"));
        assert!(rendered.contains("old_customized_flag = true"));
        assert!(rendered.contains("both_added = \"ours_val\""));
        assert!(rendered.contains("shape_key = \"custom_scalar\""));
        assert!(!rendered.contains("deleted_by_operator"));
        assert!(rendered.contains("size = 10"));
        assert!(rendered.contains("max_overflow = 20"));
        assert!(rendered.contains("secret_key = \"operator-secret-key\""));
        assert!(rendered.contains("[extensions.oidc_sso]"));
        assert!(rendered.contains("issuer = \"https://idp.example.com\""));
        assert!(rendered.contains("[operator_custom]"));

        // Running 3-way merge with base == template is idempotent and makes zero changes.
        let mut idempotent_doc = ConfigDocument::load(&config_path).unwrap();
        let noop_plan = idempotent_doc
            .merge_three_way(&base_doc, &base_doc, &[], false)
            .expect("base == template no-op");
        assert!(!noop_plan.changed);
        assert!(noop_plan.conflicts.is_empty());
        assert_eq!(idempotent_doc.document().to_string(), ours_content);
    }

    #[test]
    fn test_merge_three_way_with_prune_clears_modify_delete_and_preserves_extensions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_path = dir.path().join("base.toml.sample");
        let config_path = dir.path().join("config.toml");
        let new_tpl_path = dir.path().join("new.toml.sample");

        let base = "[database]\ntype = \"sqlite\"\nfile = \"a.db\"\n[server]\nobsolete = false\n[extensions]\nenabled = []\n";
        let ours = "[database]\ntype = \"sqlite\"\nfile = \"a.db\"\n[server]\nobsolete = true\n[extensions]\nenabled = [\"oidc_sso\"]\n[extensions.oidc_sso]\nissuer = \"https://idp.example.com\"\n";
        let theirs = "[database]\ntype = \"sqlite\"\nfile = \"a.db\"\n[server]\n[extensions]\nenabled = []\n";
        std::fs::write(&base_path, base).unwrap();
        std::fs::write(&config_path, ours).unwrap();
        std::fs::write(&new_tpl_path, theirs).unwrap();

        let base_doc = ConfigDocument::load(&base_path).unwrap();
        let mut ours_doc = ConfigDocument::load(&config_path).unwrap();
        let new_tpl_doc = ConfigDocument::load(&new_tpl_path).unwrap();

        let plan = ours_doc
            .merge_three_way(&base_doc, &new_tpl_doc, &[], true)
            .expect("prune with 3-way merge");
        assert!(plan.changed);
        assert_eq!(plan.removed_paths, vec!["server.obsolete".to_string()]);
        assert!(plan.conflicts.is_empty());
        assert!(ours_doc.document().to_string().contains("[extensions.oidc_sso]"));
        assert!(!ours_doc.document().to_string().contains("obsolete"));
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
            .replace_database_section(&pg_doc)
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
        doc.set_extensions_enabled(&["http_api".to_string(), "oidc_sso".to_string()])
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
            .set_extensions_enabled(&["oidc_sso".to_string()])
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

    #[test]
    fn s3_config_parsing_redaction_and_validation_parity() {
        let dir = tempfile::tempdir().expect("tempdir");

        // 1. Valid S3 config with inherited max_pool_connections from server.admission_control
        let valid_path = dir.path().join("valid_s3.toml");
        std::fs::write(
            &valid_path,
            r#"
[server.admission_control]
max_connections = 96

[database]
type = "sqlite"
file = "app.db"

[provider]
storage = "s3"

[s3]
bucket = "cfms-assets"
endpoint_url = "https://acct.r2.cloudflarestorage.com"
access_key_id = "AKIA_TEST"
secret_access_key = "TOP_SECRET_VALUE"
session_token = "SESSION_SECRET"
region_name = ""
addressing_style = "auto"
"#,
        )
        .unwrap();
        let doc = ConfigDocument::load(&valid_path).unwrap();
        assert_eq!(doc.storage_provider().unwrap(), StorageProviderKind::S3);
        let cfg = doc.s3_config().unwrap();
        assert_eq!(cfg.bucket, "cfms-assets");
        assert_eq!(
            cfg.endpoint_url.as_deref(),
            Some("https://acct.r2.cloudflarestorage.com")
        );
        assert_eq!(cfg.region_name, None);
        assert_eq!(cfg.addressing_style, S3AddressingStyle::Auto);
        assert_eq!(cfg.max_pool_connections, 96);

        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("TOP_SECRET_VALUE"));
        assert!(!dbg.contains("SESSION_SECRET"));
        assert!(dbg.contains("[REDACTED]"));

        let summary = doc.summary().unwrap();
        assert_eq!(summary.storage_provider, StorageProviderKind::S3);
        let s3_sum = summary.s3.unwrap();
        assert!(s3_sum.has_explicit_credentials);
        assert!(s3_sum.has_session_token);
        let summary_json = serde_json::to_string(&s3_sum).unwrap();
        assert!(!summary_json.contains("TOP_SECRET_VALUE"));
        assert!(!summary_json.contains("SESSION_SECRET"));

        // 2. local storage allows empty s3.bucket (matching config.toml.sample)
        let local_sample = dir.path().join("local_sample.toml");
        std::fs::write(
            &local_sample,
            r#"
[database]
type = "sqlite"
file = "app.db"

[provider]
storage = "local"

[s3]
bucket = ""
addressing_style = "path"
"#,
        )
        .unwrap();
        let local_doc = ConfigDocument::load(&local_sample).unwrap();
        assert!(local_doc.validate_structural_baseline().is_ok());

        // 3. s3 storage without bucket fails
        let missing_bucket = dir.path().join("missing_bucket.toml");
        std::fs::write(
            &missing_bucket,
            "[database]\ntype=\"sqlite\"\nfile=\"a.db\"\n[provider]\nstorage=\"s3\"\n[s3]\nbucket=\"  \"\n",
        )
        .unwrap();
        assert!(ConfigDocument::load(&missing_bucket).unwrap().s3_config().is_err());

        // 4. Unpaired credentials or session_token without access keys fail
        let unpaired = dir.path().join("unpaired.toml");
        std::fs::write(
            &unpaired,
            "[database]\ntype=\"sqlite\"\nfile=\"a.db\"\n[provider]\nstorage=\"s3\"\n[s3]\nbucket=\"b\"\naccess_key_id=\"k\"\n",
        )
        .unwrap();
        assert!(ConfigDocument::load(&unpaired).unwrap().s3_config().is_err());

        let token_only = dir.path().join("token_only.toml");
        std::fs::write(
            &token_only,
            "[database]\ntype=\"sqlite\"\nfile=\"a.db\"\n[provider]\nstorage=\"s3\"\n[s3]\nbucket=\"b\"\nsession_token=\"tok\"\n",
        )
        .unwrap();
        assert!(ConfigDocument::load(&token_only).unwrap().s3_config().is_err());

        // 5. Invalid endpoint_url or addressing_style or pool count fail
        let bad_endpoint = dir.path().join("bad_endpoint.toml");
        std::fs::write(
            &bad_endpoint,
            "[database]\ntype=\"sqlite\"\nfile=\"a.db\"\n[provider]\nstorage=\"s3\"\n[s3]\nbucket=\"b\"\nendpoint_url=\"ftp://s3.local\"\n",
        )
        .unwrap();
        assert!(ConfigDocument::load(&bad_endpoint).unwrap().s3_config().is_err());

        let bad_style = dir.path().join("bad_style.toml");
        std::fs::write(
            &bad_style,
            "[database]\ntype=\"sqlite\"\nfile=\"a.db\"\n[provider]\nstorage=\"s3\"\n[s3]\nbucket=\"b\"\naddressing_style=\"dns\"\n",
        )
        .unwrap();
        assert!(ConfigDocument::load(&bad_style).unwrap().s3_config().is_err());

        let zero_pool = dir.path().join("zero_pool.toml");
        std::fs::write(
            &zero_pool,
            "[database]\ntype=\"sqlite\"\nfile=\"a.db\"\n[provider]\nstorage=\"s3\"\n[s3]\nbucket=\"b\"\nmax_pool_connections=0\n",
        )
        .unwrap();
        assert!(ConfigDocument::load(&zero_pool).unwrap().s3_config().is_err());
    }
}
