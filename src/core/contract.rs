//! Core configuration contract loading, discovery, and schema-walking helpers.
//!
//! Aligns `cfms-ctl` with CFMS server's `include.config.contract` (`contract_version = "1.0"`):
//! - Loaded from `release-manifest.json` (`core_config_contract`), an explicit `--contract` file,
//!   or Python reflection (`python -m include.config.contract --compact`) on source checkouts.
//! - Treats `extensions.<id>` TOML subtables as unmanaged (`"x-unmanaged-subtables": true`).
//! - Covers core database option namespaces only (`"x-owner": "core"`).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::atomic::is_symlink_or_reparse_point;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::core::schema::{InvariantRule, validate_config_against_schema};
use crate::db::schema::probe::discover_python_candidates;

/// Supported `core_config_contract.contract_version`.
pub const CORE_CONFIG_CONTRACT_VERSION: &str = "1.0";

/// Supported JSON Schema dialect (`core_config_contract.schema_dialect`).
pub const DRAFT_2020_12_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

const MAX_CONTRACT_BYTES: u64 = 16 * 1024 * 1024;

/// Core configuration contract emitted by CFMS (`include.config.contract`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoreConfigContract {
    pub contract_version: String,
    pub core_version: String,
    pub schema_dialect: String,
    pub toml: Value,
    pub options: Value,
}

/// Flattened specification of a core leaf field inside `contract.toml`.
#[derive(Debug, Clone, PartialEq)]
pub struct TomlLeafSpec {
    pub dotted_path: String,
    pub default: Option<Value>,
    pub required: bool,
    pub renamed_from: Vec<String>,
}

impl CoreConfigContract {
    /// Validate contract metadata, Draft 2020-12 schemas, and declarative `x-*` rules.
    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CORE_CONFIG_CONTRACT_VERSION {
            return Err(CfmsError::Config(format!(
                "Unsupported core_config_contract version '{}' (expected '{CORE_CONFIG_CONTRACT_VERSION}')",
                self.contract_version
            )));
        }
        if self.schema_dialect != DRAFT_2020_12_DIALECT {
            return Err(CfmsError::Config(format!(
                "Unsupported core_config_contract schema dialect '{}' (expected '{DRAFT_2020_12_DIALECT}')",
                self.schema_dialect
            )));
        }
        let Some(toml_obj) = self.toml.as_object() else {
            return Err(CfmsError::Config(
                "Invalid core_config_contract: 'toml' must be a JSON object schema".to_string(),
            ));
        };
        jsonschema::validator_for(&self.toml).map_err(|e| {
            CfmsError::Config(format!(
                "Invalid JSON Schema in core_config_contract.toml: {e}"
            ))
        })?;
        if let Some(inv_val) = toml_obj.get("x-invariants") {
            let _: Vec<InvariantRule> = serde_json::from_value(inv_val.clone()).map_err(|e| {
                CfmsError::Config(format!(
                    "Invalid 'x-invariants' in core_config_contract.toml: {e}"
                ))
            })?;
        }

        let Some(opt_obj) = self.options.as_object() else {
            return Err(CfmsError::Config(
                "Invalid core_config_contract: 'options' must be a JSON object schema".to_string(),
            ));
        };
        jsonschema::validator_for(&self.options).map_err(|e| {
            CfmsError::Config(format!(
                "Invalid JSON Schema in core_config_contract.options: {e}"
            ))
        })?;
        let Some(ns_props) = opt_obj.get("properties").and_then(Value::as_object) else {
            return Err(CfmsError::Config(
                "Invalid core_config_contract.options: missing top-level 'properties' namespace map"
                    .to_string(),
            ));
        };

        for (ns, ns_schema) in ns_props {
            let Some(ns_obj) = ns_schema.as_object() else {
                return Err(CfmsError::Config(format!(
                    "Invalid core_config_contract.options namespace '{ns}': must be an object"
                )));
            };
            if let Some(owner) = ns_obj.get("x-owner").and_then(Value::as_str)
                && owner != "core"
            {
                return Err(CfmsError::Config(format!(
                    "Invalid core_config_contract.options namespace '{ns}': expected x-owner='core', got '{owner}'"
                )));
            }
            if let Some(inv_val) = ns_obj.get("x-invariants") {
                let _: Vec<InvariantRule> =
                    serde_json::from_value(inv_val.clone()).map_err(|e| {
                        CfmsError::Config(format!(
                            "Invalid 'x-invariants' in core_config_contract.options namespace '{ns}': {e}"
                        ))
                    })?;
            }
            let Some(keys_props) = ns_obj.get("properties").and_then(Value::as_object) else {
                return Err(CfmsError::Config(format!(
                    "Invalid core_config_contract.options namespace '{ns}': missing 'properties'"
                )));
            };
            for (key, key_schema) in keys_props {
                jsonschema::validator_for(key_schema).map_err(|e| {
                    CfmsError::Config(format!(
                        "Invalid JSON Schema in core_config_contract.options for '{ns}/{key}': {e}"
                    ))
                })?;
            }
        }

        Ok(())
    }

    /// Parse a [`CoreConfigContract`] from a JSON value representing either the contract itself
    /// or a `release-manifest.json` wrapper containing `"core_config_contract"`.
    pub fn from_json_value(value: &Value, source_desc: &str) -> Result<Self> {
        let obj = value.as_object().ok_or_else(|| {
            CfmsError::Config(format!(
                "Contract file '{source_desc}' must contain a JSON object"
            ))
        })?;

        let contract: Self = if let Some(inner) = obj.get("core_config_contract") {
            if inner.is_null() {
                return Err(CfmsError::Config(format!(
                    "Release manifest '{source_desc}' has null 'core_config_contract'"
                )));
            }
            serde_json::from_value(inner.clone()).map_err(|e| {
                CfmsError::Config(format!(
                    "Invalid 'core_config_contract' in '{source_desc}': {e}"
                ))
            })?
        } else if obj.contains_key("contract_version") {
            serde_json::from_value(value.clone()).map_err(|e| {
                CfmsError::Config(format!(
                    "Invalid core configuration contract in '{source_desc}': {e}"
                ))
            })?
        } else if obj.contains_key("format_version") && obj.contains_key("files") {
            return Err(CfmsError::Config(format!(
                "Release manifest '{source_desc}' does not include 'core_config_contract'"
            )));
        } else {
            return Err(CfmsError::Config(format!(
                "File '{source_desc}' is neither a core configuration contract nor a release-manifest.json with 'core_config_contract'"
            )));
        };

        contract.validate()?;
        Ok(contract)
    }

    /// Safely load and validate a [`CoreConfigContract`] from disk (accepting contract JSON or
    /// `release-manifest.json`).
    pub fn from_json_file(path: &Path) -> Result<Self> {
        let raw = read_bounded_json_file(path, "Contract")?;
        Self::from_json_value(&raw, &path.display().to_string())
    }

    /// Discover and load the workspace [`CoreConfigContract`] and its source description.
    ///
    /// Resolution order:
    /// 1. Explicit `--contract <FILE>` override (errors if missing or invalid).
    /// 2. Workspace `release-manifest.json` `"core_config_contract"` field.
    /// 3. Source-checkout reflection via `python -m include.config.contract --compact` when
    ///    `<server_root>/include/config/contract.py` exists.
    /// 4. `Ok(None)` when neither manifest contract nor source contract module exists.
    pub fn from_workspace(
        paths: &WorkspacePaths,
        explicit_contract: Option<&Path>,
    ) -> Result<Option<(Self, String)>> {
        if let Some(explicit) = explicit_contract {
            let resolved = paths.resolve_file_override(explicit);
            if !resolved.is_file() {
                return Err(CfmsError::Config(format!(
                    "Core configuration contract file not found: '{}'",
                    resolved.display()
                )));
            }
            let contract = Self::from_json_file(&resolved)?;
            return Ok(Some((contract, resolved.display().to_string())));
        }

        if fs::symlink_metadata(&paths.release_manifest_path)
            .is_ok_and(|m| m.is_file() && !is_symlink_or_reparse_point(&m))
        {
            let manifest_json = read_bounded_json_file(&paths.release_manifest_path, "Release manifest")?;
            if let Some(raw_contract) = manifest_json.get("core_config_contract")
                && !raw_contract.is_null()
            {
                let contract: Self = serde_json::from_value(raw_contract.clone()).map_err(|e| {
                    CfmsError::Config(format!(
                        "Invalid 'core_config_contract' in '{}': {e}",
                        paths.release_manifest_path.display()
                    ))
                })?;
                contract.validate()?;
                return Ok(Some((
                    contract,
                    format!("release-manifest ({})", paths.release_manifest_path.display()),
                )));
            }
        }

        let contract_py = paths
            .server_root
            .join("include")
            .join("config")
            .join("contract.py");
        if contract_py.is_file() {
            let (contract, desc) = extract_contract_via_python(paths)?;
            return Ok(Some((contract, desc)));
        }

        Ok(None)
    }

    /// Collect flattened leaf field specifications from `contract.toml`.
    ///
    /// Traverses core `properties` recursively (including explicit core properties such as
    /// `extensions.enabled` inside `extensions`), without enumerating unmanaged
    /// `additionalProperties` subtables (`extensions.<id>`).
    #[must_use]
    pub fn collect_toml_leaf_specs(&self) -> Vec<TomlLeafSpec> {
        let mut out = Vec::new();
        collect_leaf_specs_recursive(&self.toml, "", false, &mut out);
        out
    }

    /// Collect dotted paths present in `instance` that are not permitted by `contract.toml`.
    ///
    /// Subtrees under an object marked `"x-unmanaged-subtables": true` (`extensions.<id>`) are
    /// treated as unmanaged and never reported as unknown core fields.
    #[must_use]
    pub fn collect_unknown_core_toml_paths(&self, instance: &Value) -> Vec<String> {
        let mut out = Vec::new();
        collect_unknown_paths_recursive(instance, &self.toml, "", &mut out);
        out
    }

    /// Validate a JSON representation of `config.toml` against `contract.toml`.
    ///
    /// Any dotted paths in `ignored_core_paths` (used in preserve-and-warn mode during template
    /// synchronization / upgrades) are stripped from a cloned validation copy so that active core
    /// constraints, `x-normalize`, `x-invariants`, and `[extensions]` rules still enforce cleanly.
    pub fn validate_toml(&self, instance: &Value, ignored_core_paths: &[String]) -> Result<Vec<String>> {
        if ignored_core_paths.is_empty() {
            return validate_config_against_schema(&self.toml, instance);
        }
        let mut filtered = instance.clone();
        for dotted in ignored_core_paths {
            remove_json_dotted_path(&mut filtered, dotted);
        }
        validate_config_against_schema(&self.toml, &filtered)
    }
}

fn read_bounded_json_file(path: &Path, label: &str) -> Result<Value> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to stat {label} file '{}': {e}",
            path.display()
        ))
    })?;
    if is_symlink_or_reparse_point(&metadata) {
        return Err(CfmsError::Config(format!(
            "Refusing symlink/reparse point for {label} file '{}'",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(CfmsError::Config(format!(
            "{label} path '{}' is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_CONTRACT_BYTES {
        return Err(CfmsError::Config(format!(
            "{label} file '{}' exceeds the 16 MiB limit",
            path.display()
        )));
    }
    let raw = fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to read {label} file '{}': {e}",
            path.display()
        ))
    })?;
    serde_json::from_str::<Value>(&raw).map_err(|e| {
        CfmsError::Config(format!(
            "Invalid JSON syntax in {label} file '{}': {e}",
            path.display()
        ))
    })
}

fn extract_contract_via_python(paths: &WorkspacePaths) -> Result<(CoreConfigContract, String)> {
    let candidates = discover_python_candidates(paths);
    if candidates.is_empty() {
        return Err(CfmsError::Config(
            "No Python interpreter candidate found to reflect core_config_contract; pass --contract or set CFMS_PYTHON"
                .to_string(),
        ));
    }

    let mut errors = Vec::new();
    for candidate in candidates {
        let mut cmd = Command::new(&candidate.program);
        cmd.args(&candidate.prefix_args)
            .args(["-m", "include.config.contract", "--compact"])
            .current_dir(&paths.project_root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONUTF8", "1")
            .env("PYTHONPATH", &paths.server_root);

        match cmd.output() {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                match serde_json::from_str::<CoreConfigContract>(stdout.trim()) {
                    Ok(contract) => {
                        contract.validate()?;
                        return Ok((
                            contract,
                            format!("python include.config.contract ({})", candidate.description),
                        ));
                    }
                    Err(e) => errors.push(format!(
                        "{}: invalid contract JSON output ({e})",
                        candidate.description
                    )),
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let snippet = stderr.lines().take(3).collect::<Vec<_>>().join(" | ");
                errors.push(format!(
                    "{}: exit {:?} ({})",
                    candidate.description,
                    out.status.code(),
                    snippet
                ));
            }
            Err(e) => {
                errors.push(format!("{}: {e}", candidate.description));
            }
        }
    }

    Err(CfmsError::Config(format!(
        "Failed to reflect core_config_contract via `python -m include.config.contract` across all Python candidates (pass --contract or set CFMS_PYTHON): {}",
        errors.join("; ")
    )))
}

fn collect_leaf_specs_recursive(
    schema: &Value,
    prefix: &str,
    required: bool,
    out: &mut Vec<TomlLeafSpec>,
) {
    let Some(obj) = schema.as_object() else {
        return;
    };
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        let required_set: BTreeSet<&str> = obj
            .get("required")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        for (key, child) in props {
            let child_path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            collect_leaf_specs_recursive(
                child,
                &child_path,
                required_set.contains(key.as_str()),
                out,
            );
        }
        return;
    }

    if prefix.is_empty() {
        return;
    }

    let renamed_from = obj
        .get("x-renamed-from")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    out.push(TomlLeafSpec {
        dotted_path: prefix.to_string(),
        default: obj.get("default").cloned(),
        required,
        renamed_from,
    });
}

fn collect_unknown_paths_recursive(
    instance: &Value,
    schema: &Value,
    prefix: &str,
    out: &mut Vec<String>,
) {
    let (Some(inst_obj), Some(schema_obj)) = (instance.as_object(), schema.as_object()) else {
        return;
    };
    let unmanaged = schema_obj
        .get("x-unmanaged-subtables")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let props = schema_obj.get("properties").and_then(Value::as_object);

    let keys: BTreeSet<&str> = inst_obj.keys().map(String::as_str).collect();
    for key in keys {
        let path = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };
        if let Some(child_schema) = props.and_then(|p| p.get(key)) {
            let child_val = &inst_obj[key];
            if child_val.is_object()
                && child_schema
                    .as_object()
                    .is_some_and(|s| s.contains_key("properties") || s.contains_key("x-unmanaged-subtables"))
            {
                collect_unknown_paths_recursive(child_val, child_schema, &path, out);
            }
        } else if unmanaged {
            // Extensions subtables (`[extensions.<id>]`) are intentionally unmanaged by cfms-ctl.
            continue;
        } else {
            out.push(path);
        }
    }
}

fn remove_json_dotted_path(root: &mut Value, dotted: &str) {
    let parts: Vec<&str> = dotted.split('.').collect();
    if parts.is_empty() {
        return;
    }
    let Some(map) = root.as_object_mut() else {
        return;
    };
    remove_json_parts(map, &parts);
}

fn remove_json_parts(map: &mut Map<String, Value>, parts: &[&str]) {
    let Some((first, rest)) = parts.split_first() else {
        return;
    };
    if rest.is_empty() {
        map.remove(*first);
        return;
    }
    if let Some(Value::Object(child)) = map.get_mut(*first) {
        remove_json_parts(child, rest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn sample_test_contract() -> CoreConfigContract {
        CoreConfigContract {
            contract_version: CORE_CONFIG_CONTRACT_VERSION.to_string(),
            core_version: "0.14.0".to_string(),
            schema_dialect: DRAFT_2020_12_DIALECT.to_string(),
            toml: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "required": ["server", "database", "extensions"],
                "properties": {
                    "server": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["file_chunk_size"],
                        "properties": {
                            "host": {
                                "type": "string",
                                "minLength": 1,
                                "default": "localhost",
                                "x-normalize": "trim"
                            },
                            "port": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 65535,
                                "default": 5104
                            },
                            "file_chunk_size": {
                                "type": "integer",
                                "exclusiveMinimum": 0
                            }
                        }
                    },
                    "database": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["type"],
                        "properties": {
                            "type": {
                                "type": "string",
                                "enum": ["sqlite", "mysql", "postgresql"]
                            },
                            "name": {
                                "type": "string",
                                "default": "app_db",
                                "x-renamed-from": ["database.db_name"]
                            }
                        }
                    },
                    "extensions": {
                        "type": "object",
                        "additionalProperties": {"type": "object"},
                        "required": ["enabled"],
                        "x-unmanaged-subtables": true,
                        "properties": {
                            "enabled": {
                                "type": "array",
                                "uniqueItems": true,
                                "items": {
                                    "type": "string",
                                    "pattern": "^[a-z][a-z0-9_]*$",
                                    "not": {"enum": ["builtin", "scheduling"]}
                                }
                            }
                        }
                    }
                }
            }),
            options: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "server": {
                        "type": "object",
                        "additionalProperties": false,
                        "x-owner": "core",
                        "properties": {
                            "name": {
                                "type": "string",
                                "default": "CFMS Server",
                                "x-schema-version": 1
                            }
                        }
                    },
                    "security.password": {
                        "type": "object",
                        "additionalProperties": false,
                        "x-owner": "core",
                        "x-invariants": [{
                            "rule": "order",
                            "lower": "passwd_min_length",
                            "upper": "passwd_max_length",
                            "allow_equal": true,
                            "severity": "error",
                            "message": "Minimum password length exceeds maximum"
                        }],
                        "properties": {
                            "passwd_min_length": {
                                "type": "integer",
                                "minimum": 1,
                                "default": 8,
                                "x-schema-version": 1
                            },
                            "passwd_max_length": {
                                "type": "integer",
                                "minimum": 1,
                                "default": 128,
                                "x-schema-version": 1
                            }
                        }
                    }
                }
            }),
        }
    }

    #[test]
    fn leaf_specs_and_unknown_core_paths_respect_unmanaged_extensions() {
        let contract = sample_test_contract();
        contract.validate().expect("valid contract");

        let specs = contract.collect_toml_leaf_specs();
        let db_name = specs
            .iter()
            .find(|s| s.dotted_path == "database.name")
            .expect("database.name leaf spec");
        assert_eq!(db_name.renamed_from, vec!["database.db_name".to_string()]);
        assert!(specs.iter().any(|s| s.dotted_path == "extensions.enabled"));

        let instance = json!({
            "server": {
                "host": "localhost",
                "file_chunk_size": 1024,
                "legacy_flag": true
            },
            "database": {
                "type": "sqlite",
                "name": "app_db"
            },
            "extensions": {
                "enabled": ["oidc_sso"],
                "oidc_sso": {
                    "issuer": "https://idp.example.com",
                    "arbitrary_nested": {"k": 1}
                }
            },
            "obsolete_section": {
                "k": "v"
            }
        });

        let unknown = contract.collect_unknown_core_toml_paths(&instance);
        assert_eq!(unknown, vec!["obsolete_section", "server.legacy_flag"]);

        // Strict validation rejects unknown core fields
        assert!(contract.validate_toml(&instance, &[]).is_err());
        // Preserve-and-warn validation skips listed unknown core paths while validating extensions & active core fields
        contract
            .validate_toml(&instance, &unknown)
            .expect("valid once unknown core paths ignored");
    }

    #[test]
    fn loads_contract_from_release_manifest_in_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("main.py"), "# cfms").unwrap();
        fs::write(src.join("config.toml"), "[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n")
            .unwrap();

        let contract = sample_test_contract();
        let manifest_json = json!({
            "format_version": 1,
            "product": "cfms-server",
            "version": "0.14.0",
            "requires_python": ">=3.12",
            "managed_extensions": ["oidc_sso"],
            "files": {},
            "core_config_contract": contract
        });
        fs::write(
            temp.path().join("release-manifest.json"),
            serde_json::to_string_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let paths = WorkspacePaths::discover(Some(temp.path()), None).unwrap();
        let (loaded, source) = CoreConfigContract::from_workspace(&paths, None)
            .unwrap()
            .expect("manifest contract");
        assert_eq!(loaded, sample_test_contract());
        assert!(source.contains("release-manifest.json"));
    }
}
