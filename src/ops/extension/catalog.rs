//! Safe extension discovery, manifest validation, and `config.toml` extension-list accessors.
//!
//! All discovery and manifest checks are purely declarative: target `_extension.py`
//! modules are never imported or executed during maintenance.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use pep440_rs::Version as Pep440Version;
use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::core::{CfmsError, ConfigDocument, Result, WorkspacePaths};
use crate::ops::extension::version::{
    CfmsServerVersion, DependencyConstraint, parse_pep440_version,
};

pub const BUILTIN_EXTENSION_ID: &str = "builtin";
pub const RESERVED_EXTENSION_IDS: &[&str] = &["core"];
pub const RETIRED_EXTENSION_IDS: &[&str] = &["scheduling"];
pub const MANIFEST_FILENAME: &str = "manifest.toml";
pub const ENTRYPOINT_FILENAME: &str = "_extension.py";
pub const RELEASE_MANIFEST_FILENAME: &str = "release-manifest.json";
pub const MAX_EXTENSION_IDENTIFIER_LEN: usize = 255;
pub const MAX_EXTENSION_SCAN_ENTRIES: usize = 1024;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

pub(crate) const TRANSACTION_PREFIXES: &[&str] =
    &[".cfms-extension-stage-", ".cfms-extension-rollback-"];

/// Open-world representation of `[extension]` inside `manifest.toml`.
/// Unknown fields introduced by newer CFMS versions are captured in `extra`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionMeta {
    #[serde(default)]
    pub identifier: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Open-world representation of `[compatibility]` inside `manifest.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionCompatibility {
    #[serde(default)]
    pub minimum_server_version: Option<String>,
    #[serde(default)]
    pub maximum_server_version: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Open-world representation of `[dependencies]` inside `manifest.toml` (Manifest v3+).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionDependencies {
    #[serde(default)]
    pub extensions: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Open-world representation of an extension's `manifest.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawExtensionManifest {
    #[serde(default)]
    pub manifest_version: Option<u32>,
    #[serde(default)]
    pub extension: ExtensionMeta,
    #[serde(default)]
    pub compatibility: ExtensionCompatibility,
    #[serde(default)]
    pub dependencies: ExtensionDependencies,
    #[serde(flatten)]
    pub extra_sections: BTreeMap<String, toml::Value>,
}

/// Parsed dependency entry declared under `[dependencies.extensions]`.
#[derive(Debug, Clone)]
pub struct ParsedDependency {
    pub raw_requirement: String,
    pub constraint: DependencyConstraint,
}

/// Validated extension discovered on disk under `include/extensions/`.
#[derive(Debug, Clone)]
pub struct InstalledExtension {
    pub raw: RawExtensionManifest,
    pub identifier: String,
    pub display_name: String,
    pub manifest_version: u32,
    pub pep440_version: Option<Pep440Version>,
    pub minimum_server_version: Option<CfmsServerVersion>,
    pub maximum_server_version: Option<CfmsServerVersion>,
    pub dependencies: BTreeMap<String, ParsedDependency>,
    pub directory: PathBuf,
    pub entrypoint: PathBuf,
    pub builtin: bool,
}

/// Per-directory discovery error captured without blinding unrelated extensions.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogDiagnostic {
    pub directory: PathBuf,
    pub identifier_hint: Option<String>,
    pub message: String,
}

/// Interrupted staging or rollback directory discovered inside `extensions_root`.
#[derive(Debug, Clone, Serialize)]
pub struct StagingMarker {
    pub name: String,
    pub path: PathBuf,
    pub target_identifier: Option<String>,
}

/// Resolved uninstall candidate on disk under `extensions_root`.
#[derive(Debug, Clone)]
pub enum UninstallTarget<'a> {
    Installed(&'a InstalledExtension),
    Broken(&'a CatalogDiagnostic),
}

/// Complete extension catalog discovered under `<server_root>/include/extensions`.
#[derive(Debug, Clone)]
pub struct ExtensionCatalog {
    pub extensions_root: PathBuf,
    pub root_exists: bool,
    pub root_entry_count: usize,
    pub root_entry_names_lower: BTreeMap<String, PathBuf>,
    pub extensions: BTreeMap<String, InstalledExtension>,
    pub conflicted_identifiers: BTreeMap<String, Vec<PathBuf>>,
    pub diagnostics: Vec<CatalogDiagnostic>,
    pub staging_markers: Vec<StagingMarker>,
}

impl ExtensionCatalog {
    #[must_use]
    pub fn diagnostic_for(&self, identifier: &str) -> Option<&CatalogDiagnostic> {
        self.diagnostics.iter().find(|d| {
            d.identifier_hint.as_deref() == Some(identifier)
                || d.directory.file_name().and_then(|n| n.to_str()) == Some(identifier)
        })
    }

    /// Resolve a target extension for uninstall, permitting broken diagnostic directories.
    pub fn resolve_uninstall_target(&self, identifier: &str) -> Result<UninstallTarget<'_>> {
        if let Some(dirs) = self.conflicted_identifiers.get(identifier) {
            let joined = dirs
                .iter()
                .map(|p| format!("'{}'", p.display()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CfmsError::Extension(format!(
                "Duplicate extension identifier '{identifier}' found in {joined}"
            )));
        }
        if let Some(ext) = self.extensions.get(identifier) {
            return Ok(UninstallTarget::Installed(ext));
        }
        let matching_diags: Vec<&CatalogDiagnostic> = self
            .diagnostics
            .iter()
            .filter(|d| {
                d.identifier_hint.as_deref() == Some(identifier)
                    || d.directory
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|name| name.eq_ignore_ascii_case(identifier))
            })
            .collect();
        match matching_diags.as_slice() {
            [diag] => Ok(UninstallTarget::Broken(diag)),
            [] => Err(CfmsError::Extension(format!(
                "Extension '{identifier}' is not installed under '{}'",
                self.extensions_root.display()
            ))),
            many => {
                let joined = many
                    .iter()
                    .map(|d| format!("'{}'", d.directory.display()))
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(CfmsError::Extension(format!(
                    "Multiple broken extension directories match '{identifier}': {joined}"
                )))
            }
        }
    }
}

/// Return true if filesystem metadata describes a symlink or Windows reparse point (junction/mount).
pub(crate) use crate::core::is_symlink_or_reparse_point;

/// Read managed extension identifiers from `release-manifest.json` (plus `builtin`).
pub fn read_managed_extensions(paths: &WorkspacePaths) -> Result<BTreeSet<String>> {
    let mut managed = BTreeSet::new();
    managed.insert(BUILTIN_EXTENSION_ID.to_string());

    let manifest_path = &paths.release_manifest_path;
    let Some(meta) = symlink_stat_if_present(manifest_path)? else {
        return Ok(managed);
    };
    if !meta.is_file() {
        return Err(CfmsError::Extension(format!(
            "Release manifest '{}' must be a regular file",
            manifest_path.display()
        )));
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(CfmsError::Extension(format!(
            "Release manifest '{}' exceeds the 1 MiB safety limit",
            manifest_path.display()
        )));
    }

    let raw = std::fs::read_to_string(manifest_path)?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        CfmsError::Extension(format!(
            "Invalid JSON in release manifest '{}': {e}",
            manifest_path.display()
        ))
    })?;
    let Some(obj) = parsed.as_object() else {
        return Err(CfmsError::Extension(format!(
            "Release manifest '{}' must decode to a JSON object",
            manifest_path.display()
        )));
    };

    if let Some(entries_val) = obj.get("managed_extensions") {
        let Some(entries) = entries_val.as_array() else {
            return Err(CfmsError::Extension(format!(
                "Release manifest '{}' field 'managed_extensions' must be a JSON array of strings",
                manifest_path.display()
            )));
        };
        for item in entries {
            let Some(id) = item.as_str() else {
                return Err(CfmsError::Extension(format!(
                    "Release manifest '{}' field 'managed_extensions' must contain only strings",
                    manifest_path.display()
                )));
            };
            validate_extension_identifier(id)?;
            managed.insert(id.to_string());
        }
    }

    Ok(managed)
}

/// Extract optional `[data].module` string declared inside an extension manifest.
#[must_use]
pub(crate) fn declared_data_module(raw: &RawExtensionManifest) -> Option<&str> {
    raw.extra_sections
        .get("data")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("module"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Extract optional top-level `option_namespaces` list declared inside an extension manifest.
#[must_use]
pub(crate) fn declared_option_namespaces(raw: &RawExtensionManifest) -> Vec<String> {
    raw.extra_sections
        .get("option_namespaces")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Validated view of `[extensions].enabled` in `config.toml`.
#[derive(Debug, Clone)]
pub struct EnabledConfigState {
    pub has_section_or_key: bool,
    pub entries: Vec<String>,
}

/// Validate extension identifier syntax and reserved names.
pub fn validate_extension_identifier(identifier: &str) -> Result<()> {
    if identifier.is_empty() || identifier.len() > MAX_EXTENSION_IDENTIFIER_LEN {
        return Err(CfmsError::Extension(format!(
            "Invalid extension identifier '{identifier}': must be 1..={MAX_EXTENSION_IDENTIFIER_LEN} characters"
        )));
    }
    if !identifier_regex().is_match(identifier) {
        return Err(CfmsError::Extension(format!(
            "Invalid extension identifier '{identifier}': must match ^[a-z][a-z0-9_]*$"
        )));
    }
    if RESERVED_EXTENSION_IDS.contains(&identifier) {
        return Err(CfmsError::Extension(format!(
            "Extension identifier '{identifier}' is reserved"
        )));
    }
    Ok(())
}

/// Reject retired identifiers such as `"scheduling"`.
pub fn ensure_not_retired(identifier: &str) -> Result<()> {
    if RETIRED_EXTENSION_IDS.contains(&identifier) {
        return Err(CfmsError::Extension(format!(
            "Extension '{identifier}' has been retired and is no longer supported"
        )));
    }
    Ok(())
}

/// Read `[extensions].enabled` from `ConfigDocument` with strict CFMS contract validation.
///
/// When `allow_retired_entries` is true (used by `disable` cleanup paths), retired
/// identifiers such as `"scheduling"` present in an existing config are returned so
/// operators can remove them cleanly.
pub fn read_enabled_config(
    doc: &ConfigDocument,
    allow_retired_entries: bool,
) -> Result<EnabledConfigState> {
    let Some(entries) = doc.extensions_enabled_raw()? else {
        return Ok(EnabledConfigState {
            has_section_or_key: false,
            entries: Vec::new(),
        });
    };

    let mut seen = BTreeSet::new();
    for entry in &entries {
        validate_extension_identifier(entry)?;
        if entry == BUILTIN_EXTENSION_ID {
            return Err(CfmsError::Config(
                "extensions.enabled must not contain 'builtin'; it is always enabled".to_string(),
            ));
        }
        if !allow_retired_entries && RETIRED_EXTENSION_IDS.contains(&entry.as_str()) {
            return Err(CfmsError::Config(format!(
                "extensions.enabled must not contain retired identifier '{entry}'; run `cfms-ctl extension disable {entry}` to clean config.toml"
            )));
        }
        if !seen.insert(entry.clone()) {
            return Err(CfmsError::Config(format!(
                "extensions.enabled contains duplicate identifier '{entry}'"
            )));
        }
    }

    Ok(EnabledConfigState {
        has_section_or_key: true,
        entries,
    })
}

/// Discover and validate installed extensions under `extensions_root` without executing Python.
///
/// Traversal/symlink security violations and excessive directory sizes fail immediately;
/// individual broken extension directories are captured in `ExtensionCatalog::diagnostics`
/// so healthy extensions remain inspectable and `disable` stays unblocked for cleanup.
pub fn discover_catalog(extensions_root: &Path) -> Result<ExtensionCatalog> {
    let mut catalog = ExtensionCatalog {
        extensions_root: extensions_root.to_path_buf(),
        root_exists: false,
        root_entry_count: 0,
        root_entry_names_lower: BTreeMap::new(),
        extensions: BTreeMap::new(),
        conflicted_identifiers: BTreeMap::new(),
        diagnostics: Vec::new(),
        staging_markers: Vec::new(),
    };

    let root_meta = match std::fs::symlink_metadata(extensions_root) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(catalog),
        Err(err) => return Err(CfmsError::Io(err)),
    };
    if is_symlink_or_reparse_point(&root_meta) {
        return Err(CfmsError::Extension(format!(
            "Extension directory '{}' cannot be a symlink or junction",
            extensions_root.display()
        )));
    }
    if !root_meta.is_dir() {
        return Err(CfmsError::Extension(format!(
            "Extension path '{}' exists but is not a directory",
            extensions_root.display()
        )));
    }
    catalog.root_exists = true;

    let mut entries = Vec::new();
    for (idx, entry_res) in std::fs::read_dir(extensions_root)?.enumerate() {
        if idx >= MAX_EXTENSION_SCAN_ENTRIES {
            return Err(CfmsError::Extension(format!(
                "Extension directory '{}' exceeds the {MAX_EXTENSION_SCAN_ENTRIES}-entry safety limit",
                extensions_root.display()
            )));
        }
        let entry = entry_res?;
        entries.push(entry.path());
    }
    catalog.root_entry_count = entries.len();
    entries.sort();

    let mut seen_dirs: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();

    for entry_path in entries {
        let name = entry_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        let entry_meta = std::fs::symlink_metadata(&entry_path)?;
        if is_symlink_or_reparse_point(&entry_meta) {
            return Err(CfmsError::Extension(format!(
                "Extension directory cannot contain symlinks or junctions: '{}'",
                entry_path.display()
            )));
        }

        if is_transaction_marker(name) {
            let target_identifier = peek_staging_identifier(&entry_path);
            catalog.staging_markers.push(StagingMarker {
                name: name.to_string(),
                path: entry_path,
                target_identifier,
            });
            continue;
        }

        if !name.is_empty() {
            catalog
                .root_entry_names_lower
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| entry_path.clone());
        }

        if name.starts_with('_') || name.starts_with('.') || !entry_meta.is_dir() {
            continue;
        }

        let manifest_path = entry_path.join(MANIFEST_FILENAME);
        let entrypoint_path = entry_path.join(ENTRYPOINT_FILENAME);
        let manifest_meta = symlink_stat_if_present(&manifest_path)?;
        let entrypoint_meta = symlink_stat_if_present(&entrypoint_path)?;

        let has_manifest = manifest_meta.as_ref().is_some_and(|m| m.is_file());
        let has_entrypoint = entrypoint_meta.as_ref().is_some_and(|m| m.is_file());

        if !has_manifest && !has_entrypoint {
            if manifest_meta.is_none() && entrypoint_meta.is_none() {
                continue;
            }
            catalog.diagnostics.push(CatalogDiagnostic {
                directory: entry_path,
                identifier_hint: None,
                message: format!(
                    "Extension candidate has non-file {MANIFEST_FILENAME} or {ENTRYPOINT_FILENAME}"
                ),
            });
            continue;
        }

        if !has_manifest {
            catalog.diagnostics.push(CatalogDiagnostic {
                directory: entry_path,
                identifier_hint: None,
                message: format!("Extension directory is missing {MANIFEST_FILENAME}"),
            });
            continue;
        }

        if !has_entrypoint {
            let hint = peek_manifest_identifier(&manifest_path);
            catalog.diagnostics.push(CatalogDiagnostic {
                directory: entry_path,
                identifier_hint: hint,
                message: format!("Extension directory is missing {ENTRYPOINT_FILENAME}"),
            });
            continue;
        }

        match parse_installed_extension(&entry_path, &manifest_path, &entrypoint_path) {
            Ok(ext) => {
                let id = ext.identifier.clone();
                seen_dirs.entry(id.clone()).or_default().push(entry_path);
                catalog.extensions.insert(id, ext);
            }
            Err(err) => {
                let hint = peek_manifest_identifier(&manifest_path);
                catalog.diagnostics.push(CatalogDiagnostic {
                    directory: entry_path,
                    identifier_hint: hint,
                    message: err.to_string(),
                });
            }
        }
    }

    for (id, dirs) in seen_dirs {
        if dirs.len() > 1 {
            catalog.extensions.remove(&id);
            let joined = dirs
                .iter()
                .map(|p| format!("'{}'", p.display()))
                .collect::<Vec<_>>()
                .join(", ");
            catalog.diagnostics.push(CatalogDiagnostic {
                directory: dirs[0].clone(),
                identifier_hint: Some(id.clone()),
                message: format!("Duplicate extension identifier '{id}' found in {joined}"),
            });
            catalog.conflicted_identifiers.insert(id, dirs);
        }
    }

    Ok(catalog)
}

pub(crate) fn symlink_stat_if_present(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse_point(&meta) {
                return Err(CfmsError::Extension(format!(
                    "Extension path cannot be a symlink or junction: '{}'",
                    path.display()
                )));
            }
            Ok(Some(meta))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CfmsError::Io(err)),
    }
}

fn parse_installed_extension(
    dir_path: &Path,
    manifest_path: &Path,
    entrypoint_path: &Path,
) -> Result<InstalledExtension> {
    let meta = std::fs::metadata(manifest_path)?;
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(CfmsError::Extension(format!(
            "Manifest '{}' exceeds the 1 MiB safety limit",
            manifest_path.display()
        )));
    }

    let raw_str = std::fs::read_to_string(manifest_path)?;
    parse_extension_manifest_str(&raw_str, manifest_path, dir_path, entrypoint_path)
}

/// Validate raw `manifest.toml` text into a parsed [`InstalledExtension`].
pub(crate) fn parse_extension_manifest_str(
    raw_str: &str,
    manifest_path: &Path,
    dir_path: &Path,
    entrypoint_path: &Path,
) -> Result<InstalledExtension> {
    if raw_str.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(CfmsError::Extension(format!(
            "Manifest '{}' exceeds the 1 MiB safety limit",
            manifest_path.display()
        )));
    }
    let raw_table: toml::Table = toml::from_str(raw_str).map_err(|e| {
        CfmsError::Extension(format!(
            "Invalid TOML in manifest '{}': {e}",
            manifest_path.display()
        ))
    })?;
    let parsed: RawExtensionManifest = toml::from_str(raw_str).map_err(|e| {
        CfmsError::Extension(format!(
            "Invalid manifest schema in '{}': {e}",
            manifest_path.display()
        ))
    })?;

    let manifest_version = match parsed.manifest_version {
        Some(v @ (2 | 3)) => v,
        Some(other) => {
            return Err(CfmsError::Extension(format!(
                "Unsupported manifest_version {other} in '{}'; expected 2 or 3",
                manifest_path.display()
            )));
        }
        None => {
            return Err(CfmsError::Extension(format!(
                "Manifest '{}' is missing required manifest_version",
                manifest_path.display()
            )));
        }
    };

    if manifest_version == 2 && raw_table.contains_key("dependencies") {
        return Err(CfmsError::Extension(format!(
            "Manifest '{}' uses manifest_version = 2 and must not declare [dependencies]",
            manifest_path.display()
        )));
    }

    let identifier = require_trimmed_non_empty(
        &parsed.extension.identifier,
        "extension.identifier",
        manifest_path,
    )?
    .to_string();
    validate_extension_identifier(&identifier)?;
    ensure_not_retired(&identifier)?;

    let display_name =
        require_trimmed_non_empty(&parsed.extension.name, "extension.name", manifest_path)?
            .to_string();
    let version = require_trimmed_non_empty(
        &parsed.extension.version,
        "extension.version",
        manifest_path,
    )?;
    require_trimmed_non_empty(&parsed.extension.license, "extension.license", manifest_path)?;

    if parsed.extension.authors.is_empty()
        || parsed
            .extension
            .authors
            .iter()
            .any(|a| a.trim().is_empty() || a.trim() != a)
    {
        return Err(CfmsError::Extension(format!(
            "Manifest '{}' must declare at least one non-empty trimmed author in extension.authors",
            manifest_path.display()
        )));
    }

    let pep440_version = if manifest_version == 3 {
        Some(parse_pep440_version(version)?)
    } else {
        parse_pep440_version(version).ok()
    };

    let minimum_server_version = parsed
        .compatibility
        .minimum_server_version
        .as_deref()
        .map(CfmsServerVersion::parse)
        .transpose()?;
    let maximum_server_version = parsed
        .compatibility
        .maximum_server_version
        .as_deref()
        .map(CfmsServerVersion::parse)
        .transpose()?;

    if let (Some(min), Some(max)) = (&minimum_server_version, &maximum_server_version)
        && min > max
    {
        return Err(CfmsError::Extension(format!(
            "Manifest '{}' has minimum_server_version ({min}) greater than maximum_server_version ({max})",
            manifest_path.display()
        )));
    }

    let mut dependencies = BTreeMap::new();
    for (dep_id, dep_req) in &parsed.dependencies.extensions {
        validate_extension_identifier(dep_id)?;
        ensure_not_retired(dep_id)?;
        if dep_id == &identifier {
            return Err(CfmsError::Extension(format!(
                "Extension '{identifier}' declares a self-dependency in '{}'",
                manifest_path.display()
            )));
        }
        let constraint = DependencyConstraint::parse(dep_req)?;
        dependencies.insert(
            dep_id.clone(),
            ParsedDependency {
                raw_requirement: dep_req.clone(),
                constraint,
            },
        );
    }

    Ok(InstalledExtension {
        builtin: identifier == BUILTIN_EXTENSION_ID,
        raw: parsed,
        identifier,
        display_name,
        manifest_version,
        pep440_version,
        minimum_server_version,
        maximum_server_version,
        dependencies,
        directory: dir_path.to_path_buf(),
        entrypoint: entrypoint_path.to_path_buf(),
    })
}

fn require_trimmed_non_empty<'a>(
    value: &'a str,
    field: &str,
    manifest_path: &Path,
) -> Result<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(CfmsError::Extension(format!(
            "Manifest '{}' has empty or untrimmed field '{field}'",
            manifest_path.display()
        )));
    }
    Ok(value)
}

fn peek_manifest_identifier(manifest_path: &Path) -> Option<String> {
    if symlink_stat_if_present(manifest_path)
        .ok()
        .flatten()
        .is_none_or(|m| !m.is_file() || m.len() > MAX_MANIFEST_BYTES)
    {
        return None;
    }
    let raw = std::fs::read_to_string(manifest_path).ok()?;
    let parsed: RawExtensionManifest = toml::from_str(&raw).ok()?;
    let id = parsed.extension.identifier.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

fn peek_staging_identifier(marker_dir: &Path) -> Option<String> {
    if !marker_dir.is_dir() {
        return None;
    }
    peek_manifest_identifier(&marker_dir.join(MANIFEST_FILENAME))
}

fn is_transaction_marker(name: &str) -> bool {
    TRANSACTION_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn identifier_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_]*$").expect("valid identifier regex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_extension(
        root: &Path,
        dir_name: &str,
        manifest: Option<&str>,
        with_entrypoint: bool,
    ) -> PathBuf {
        let dir = root.join(dir_name);
        std::fs::create_dir_all(&dir).expect("create ext dir");
        if let Some(m) = manifest {
            std::fs::write(dir.join(MANIFEST_FILENAME), m).expect("write manifest");
        }
        if with_entrypoint {
            std::fs::write(dir.join(ENTRYPOINT_FILENAME), "# entrypoint").expect("write entry");
        }
        dir
    }

    #[test]
    fn catalog_skips_ignored_dirs_and_records_diagnostics_without_aborting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        write_extension(root, "__pycache__", None, false);
        write_extension(root, ".hidden_helper", None, false);
        write_extension(
            root,
            ".cfms-extension-stage-1234",
            Some(
                "manifest_version = 2\n[extension]\nidentifier = \"pending_ext\"\nname = \"Pending\"\nversion = \"1.0.0\"\nauthors = [\"Dev\"]\nlicense = \"MIT\"\n",
            ),
            true,
        );
        write_extension(
            root,
            "builtin",
            Some(
                "manifest_version = 2\n[extension]\nidentifier = \"builtin\"\nname = \"Built-in\"\nversion = \"0.14.0\"\nauthors = [\"CFMS\"]\nlicense = \"GPL\"\nextra_flag = true\n",
            ),
            true,
        );
        // Broken directory missing _extension.py
        write_extension(
            root,
            "broken_ext",
            Some(
                "manifest_version = 2\n[extension]\nidentifier = \"broken_ext\"\nname = \"Broken\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            ),
            false,
        );

        let catalog = discover_catalog(root).expect("catalog");
        assert_eq!(catalog.extensions.len(), 1);
        assert!(catalog.extensions.contains_key("builtin"));
        assert_eq!(catalog.diagnostics.len(), 1);
        assert_eq!(
            catalog.diagnostics[0].identifier_hint.as_deref(),
            Some("broken_ext")
        );
        assert_eq!(catalog.staging_markers.len(), 1);
        assert_eq!(
            catalog.staging_markers[0].target_identifier.as_deref(),
            Some("pending_ext")
        );
    }

    #[test]
    fn rejects_manifest_v2_with_dependencies_and_duplicate_identifiers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        write_extension(
            root,
            "v2_with_deps",
            Some(
                "manifest_version = 2\n[extension]\nidentifier = \"v2_with_deps\"\nname = \"V2\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies]\n",
            ),
            true,
        );
        write_extension(
            root,
            "dup_a",
            Some(
                "manifest_version = 2\n[extension]\nidentifier = \"dup\"\nname = \"Dup A\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            ),
            true,
        );
        write_extension(
            root,
            "dup_b",
            Some(
                "manifest_version = 2\n[extension]\nidentifier = \"dup\"\nname = \"Dup B\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            ),
            true,
        );

        let catalog = discover_catalog(root).expect("catalog");
        assert!(catalog.extensions.is_empty());
        assert!(catalog.conflicted_identifiers.contains_key("dup"));
        assert_eq!(catalog.diagnostics.len(), 2);
    }
}
