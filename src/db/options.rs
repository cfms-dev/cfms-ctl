//! Database-backed `options` CRUD with two-level optimistic concurrency (`options.revision`
//! and `system_states` namespace write-skew guard), canonical tagged scalar/JSON encoding,
//! external JSON Schema + `x-invariants` validation, and transactional `audit_entries` logging.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{MySql, Postgres, Row, Sqlite, Transaction};
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::core::schema::{
    evaluate_schema_invariants, format_canonical_float, is_canonical_int_str,
    load_json_schema_file, normalize_and_precheck_value, validate_instance_against_schema,
};
use crate::db::backend::DbPool;

const OPTIONS_REVISION_PREFIX: &str = "options_revision.";

static NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$").expect("valid namespace regex")
});
static OWNER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*$").expect("valid owner regex"));
static KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_.-]*$").expect("valid key regex"));

/// Canonical storage tag stored in `options.value_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OptionValueType {
    Str,
    Int,
    Float,
    Bool,
    Null,
    Json,
}

impl OptionValueType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Str => "str",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Null => "null",
            Self::Json => "json",
        }
    }

    pub fn parse_tag(tag: &str) -> Result<Self> {
        match tag {
            "str" => Ok(Self::Str),
            "int" => Ok(Self::Int),
            "float" => Ok(Self::Float),
            "bool" => Ok(Self::Bool),
            "null" => Ok(Self::Null),
            "json" => Ok(Self::Json),
            _ => Err(CfmsError::Config(format!(
                "Invalid stored option value for type '{tag}'"
            ))),
        }
    }
}

/// Resolved snapshot of a database-backed or schema-default option.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedOptionRecord {
    pub namespace: String,
    pub owner: String,
    pub option_key: String,
    pub schema_version: i32,
    pub revision: u64,
    pub value: Value,
    pub updated_at: Option<f64>,
}

/// Input entry for updating an option with optimistic concurrency.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionUpdateInput {
    pub value: Value,
    pub expected_revision: u64,
}

/// Validate a namespace string against CFMS `OptionNamespace` constraints (`1..=111` chars).
pub fn validate_option_namespace(namespace: &str) -> Result<()> {
    let char_len = namespace.chars().count();
    if !(1..=111).contains(&char_len) || !NAMESPACE_RE.is_match(namespace) {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid option namespace '{namespace}'"
        )));
    }
    Ok(())
}

/// Validate an owner identifier against CFMS `OptionOwner` constraints (`1..=255` chars).
pub fn validate_option_owner(owner: &str) -> Result<()> {
    let char_len = owner.chars().count();
    if !(1..=255).contains(&char_len) || !OWNER_RE.is_match(owner) {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid option owner '{owner}'"
        )));
    }
    Ok(())
}

/// Validate an option key against CFMS `OptionKey` constraints (`1..=128` chars).
pub fn validate_option_key(option_key: &str) -> Result<()> {
    let char_len = option_key.chars().count();
    if !(1..=128).contains(&char_len) || !KEY_RE.is_match(option_key) {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid option key '{option_key}'"
        )));
    }
    Ok(())
}

fn validate_json_tree_numbers(value: &Value) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => {
            let raw = n.to_string();
            if is_canonical_int_str(&raw) {
                return Ok(());
            }
            let parsed = raw.parse::<f64>().map_err(|_| {
                CfmsError::Config("Option value contains an invalid number".to_string())
            })?;
            if !parsed.is_finite() {
                return Err(CfmsError::Config(
                    "Option value must not contain NaN or infinite numbers".to_string(),
                ));
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                validate_json_tree_numbers(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for val in map.values() {
                validate_json_tree_numbers(val)?;
            }
            Ok(())
        }
    }
}

/// Encode a JSON value into CFMS's canonical `(OptionValueType, option_value)` pair.
///
/// Strings are stored verbatim; booleans as `"1"`/`"0"`; integers as canonical base-10;
/// floats as canonical finite representations; null as `""`; and objects/arrays as compact JSON.
pub fn encode_option_value(value: &Value) -> Result<(OptionValueType, String)> {
    validate_json_tree_numbers(value)?;
    match value {
        Value::String(s) => Ok((OptionValueType::Str, s.clone())),
        Value::Bool(b) => Ok((
            OptionValueType::Bool,
            if *b { "1".to_string() } else { "0".to_string() },
        )),
        Value::Null => Ok((OptionValueType::Null, String::new())),
        Value::Number(n) => {
            let raw = n.to_string();
            if is_canonical_int_str(&raw) {
                Ok((OptionValueType::Int, raw))
            } else {
                let parsed = raw
                    .parse::<f64>()
                    .map_err(|_| CfmsError::Config("Invalid float option value".to_string()))?;
                Ok((OptionValueType::Float, format_canonical_float(parsed)?))
            }
        }
        Value::Array(_) | Value::Object(_) => {
            let compact = serde_json::to_string(value).map_err(|_| {
                CfmsError::Config("Unable to serialize structured option value".to_string())
            })?;
            Ok((OptionValueType::Json, compact))
        }
    }
}

/// Decode a stored `(value_type, option_value)` pair without exposing raw invalid content in errors.
pub fn decode_option_value(value_type: &str, option_value: &str) -> Result<Value> {
    let err = || {
        CfmsError::Config(format!(
            "Invalid stored option value for type '{value_type}'"
        ))
    };
    let kind = OptionValueType::parse_tag(value_type)?;
    match kind {
        OptionValueType::Str => Ok(Value::String(option_value.to_string())),
        OptionValueType::Bool => match option_value {
            "1" => Ok(Value::Bool(true)),
            "0" => Ok(Value::Bool(false)),
            _ => Err(err()),
        },
        OptionValueType::Null => {
            if option_value.is_empty() {
                Ok(Value::Null)
            } else {
                Err(err())
            }
        }
        OptionValueType::Int => {
            if !is_canonical_int_str(option_value) {
                return Err(err());
            }
            let val: Value = serde_json::from_str(option_value).map_err(|_| err())?;
            if !val.is_number() {
                return Err(err());
            }
            Ok(val)
        }
        OptionValueType::Float => {
            if option_value.trim() != option_value
                || (!option_value.contains('.')
                    && !option_value.contains('e')
                    && !option_value.contains('E'))
            {
                return Err(err());
            }
            let parsed = option_value.parse::<f64>().map_err(|_| err())?;
            if !parsed.is_finite() {
                return Err(err());
            }
            let canonical = format_canonical_float(parsed).map_err(|_| err())?;
            if canonical != option_value {
                return Err(err());
            }
            serde_json::from_str(&canonical).map_err(|_| err())
        }
        OptionValueType::Json => {
            let parsed: Value = serde_json::from_str(option_value).map_err(|_| err())?;
            if !matches!(parsed, Value::Array(_) | Value::Object(_)) {
                return Err(err());
            }
            validate_json_tree_numbers(&parsed).map_err(|_| err())?;
            Ok(parsed)
        }
    }
}

/// Property-level metadata extracted from a namespace's JSON Schema.
#[derive(Debug, Clone)]
pub struct OptionPropertySpec {
    pub option_key: String,
    pub schema_version: i32,
    pub default_value: Option<Value>,
    pub raw_property_schema: Value,
}

/// Namespace-level schema specification loaded from an external JSON Schema or extension manifest.
#[derive(Debug, Clone)]
pub struct NamespaceSchemaSpec {
    pub namespace: String,
    pub owner: String,
    pub is_core: bool,
    pub has_detailed_schema: bool,
    pub raw_schema: Value,
    pub properties: BTreeMap<String, OptionPropertySpec>,
}

/// Dynamically loaded registry of option namespace schemas discovered from the target workspace.
#[derive(Debug, Clone, Default)]
pub struct OptionsSchemaRegistry {
    has_core_schema: bool,
    namespaces: BTreeMap<String, NamespaceSchemaSpec>,
}

#[derive(Debug, Deserialize)]
struct ExtensionManifestOptions {
    #[serde(default)]
    option_namespaces: Vec<String>,
    #[serde(default)]
    options_schema: Option<toml::Value>,
    #[serde(default)]
    extension: ManifestExtId,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestExtId {
    #[serde(default)]
    identifier: String,
}

impl OptionsSchemaRegistry {
    /// Create an empty schema registry (schema-less fallback mode).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Discover and load core and extension option schemas from `WorkspacePaths`.
    pub fn from_workspace(
        paths: &WorkspacePaths,
        explicit_schema: Option<&Path>,
    ) -> Result<Self> {
        let core_schema = paths.discover_options_schema_path(explicit_schema)?;
        Self::load(core_schema.as_deref(), Some(&paths.extensions_root))
    }

    /// Load an `OptionsSchemaRegistry` from an optional core JSON Schema path and extensions directory.
    pub fn load(
        core_schema_path: Option<&Path>,
        extensions_root: Option<&Path>,
    ) -> Result<Self> {
        let mut registry = Self::empty();

        if let Some(path) = core_schema_path {
            let root_json = load_json_schema_file(path)?;
            registry.has_core_schema = true;
            registry.ingest_schema_document(&root_json, "core", true)?;
        }

        if let Some(ext_root) = extensions_root
            && ext_root.is_dir()
        {
            registry.ingest_extensions_dir(ext_root)?;
        }

        Ok(registry)
    }

    /// Whether a core `options.schema.json` file was loaded.
    #[must_use]
    pub const fn has_core_schema(&self) -> bool {
        self.has_core_schema
    }

    /// Look up a namespace schema specification by name.
    #[must_use]
    pub fn get_namespace(&self, namespace: &str) -> Option<&NamespaceSchemaSpec> {
        self.namespaces.get(namespace)
    }

    /// Iterate over all loaded namespace specifications.
    pub fn namespaces(&self) -> impl Iterator<Item = (&String, &NamespaceSchemaSpec)> {
        self.namespaces.iter()
    }

    /// Ingest a JSON Schema document (either a multi-namespace catalog or a single-namespace schema).
    pub fn ingest_schema_document(
        &mut self,
        doc: &Value,
        default_owner: &str,
        default_is_core: bool,
    ) -> Result<()> {
        let Some(root_obj) = doc.as_object() else {
            return Err(CfmsError::Config(
                "Options JSON Schema root must be a JSON object".to_string(),
            ));
        };

        // Case 1: Single-namespace JSON Schema with `"x-namespace": "<ns>"`
        if let Some(ns_name) = root_obj.get("x-namespace").and_then(Value::as_str) {
            let spec = parse_namespace_schema_object(
                ns_name,
                root_obj,
                default_owner,
                default_is_core,
            )?;
            self.register_namespace_spec(spec)?;
            return Ok(());
        }

        // Case 2: Multi-namespace catalog under `"namespaces"`, `"properties"`, `"$defs"`,
        // or a direct top-level mapping `{ "<namespace>": { "properties": ... } }` (e.g. inline `[options_schema."<ns>"]` in `manifest.toml`).
        let catalog_map = if let Some(ns_map) = root_obj
            .get("namespaces")
            .and_then(Value::as_object)
            .or_else(|| root_obj.get("properties").and_then(Value::as_object))
            .or_else(|| root_obj.get("$defs").and_then(Value::as_object))
        {
            ns_map
        } else if !root_obj.is_empty()
            && root_obj
                .iter()
                .filter(|(k, _)| !k.starts_with('$'))
                .all(|(k, v)| v.is_object() && validate_option_namespace(k).is_ok())
        {
            root_obj
        } else {
            return Err(CfmsError::Config(
                "Options JSON Schema must contain 'properties', 'namespaces', or 'x-namespace'"
                    .to_string(),
            ));
        };

        for (ns_name, ns_val) in catalog_map {
            if ns_name.starts_with('$') {
                continue;
            }
            let Some(ns_obj) = ns_val.as_object() else {
                return Err(CfmsError::Config(format!(
                    "Namespace schema for '{ns_name}' must be a JSON object"
                )));
            };
            let spec =
                parse_namespace_schema_object(ns_name, ns_obj, default_owner, default_is_core)?;
            self.register_namespace_spec(spec)?;
        }

        Ok(())
    }

    fn ingest_extensions_dir(&mut self, extensions_root: &Path) -> Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(extensions_root)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in entries {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let manifest_path = dir.join("manifest.toml");
            let mut ext_owner = entry.file_name().to_string_lossy().to_string();
            let mut declared_namespaces = Vec::new();
            let mut inline_or_linked_loaded = false;

            if manifest_path.is_file() {
                let raw = std::fs::read_to_string(&manifest_path)?;
                let parsed: ExtensionManifestOptions = toml::from_str(&raw).map_err(|e| {
                    CfmsError::Extension(format!(
                        "Invalid extension manifest '{}': {e}",
                        manifest_path.display()
                    ))
                })?;
                if !parsed.extension.identifier.is_empty() {
                    ext_owner = parsed.extension.identifier;
                }
                validate_option_owner(&ext_owner)?;
                declared_namespaces = parsed.option_namespaces;

                if let Some(opt_schema_toml) = parsed.options_schema {
                    match opt_schema_toml {
                        toml::Value::String(rel_file) => {
                            let schema_file = dir.join(rel_file);
                            let json_doc = load_json_schema_file(&schema_file)?;
                            self.ingest_schema_document(&json_doc, &ext_owner, false)?;
                            inline_or_linked_loaded = true;
                        }
                        toml::Value::Table(_) => {
                            let json_doc: Value =
                                serde_json::to_value(opt_schema_toml).map_err(|e| {
                                    CfmsError::Extension(format!(
                                        "Invalid inline options_schema in '{}': {e}",
                                        manifest_path.display()
                                    ))
                                })?;
                            self.ingest_schema_document(&json_doc, &ext_owner, false)?;
                            inline_or_linked_loaded = true;
                        }
                        _ => {
                            return Err(CfmsError::Extension(format!(
                                "Invalid 'options_schema' in '{}': must be a file path string or table",
                                manifest_path.display()
                            )));
                        }
                    }
                }
            }

            let standalone_schema_path = dir.join("options.schema.json");
            if !inline_or_linked_loaded && standalone_schema_path.is_file() {
                validate_option_owner(&ext_owner)?;
                let json_doc = load_json_schema_file(&standalone_schema_path)?;
                self.ingest_schema_document(&json_doc, &ext_owner, false)?;
            }

            for ns in declared_namespaces {
                validate_option_namespace(&ns)?;
                if let Some(existing) = self.namespaces.get(&ns) {
                    if existing.owner != ext_owner {
                        return Err(CfmsError::Config(format!(
                            "Multiple owners declare option namespace '{ns}': {}, {ext_owner}",
                            existing.owner
                        )));
                    }
                } else {
                    self.namespaces.insert(
                        ns.clone(),
                        NamespaceSchemaSpec {
                            namespace: ns,
                            owner: ext_owner.clone(),
                            is_core: false,
                            has_detailed_schema: false,
                            raw_schema: json!({"type": "object"}),
                            properties: BTreeMap::new(),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn register_namespace_spec(&mut self, spec: NamespaceSchemaSpec) -> Result<()> {
        if let Some(existing) = self.namespaces.get(&spec.namespace)
            && existing.owner != spec.owner
        {
            return Err(CfmsError::Config(format!(
                "Multiple owners declare option namespace '{}': {}, {}",
                spec.namespace, existing.owner, spec.owner
            )));
        }
        self.namespaces.insert(spec.namespace.clone(), spec);
        Ok(())
    }
}

fn parse_namespace_schema_object(
    namespace: &str,
    ns_obj: &Map<String, Value>,
    default_owner: &str,
    default_is_core: bool,
) -> Result<NamespaceSchemaSpec> {
    validate_option_namespace(namespace)?;
    let owner = ns_obj
        .get("x-owner")
        .and_then(Value::as_str)
        .unwrap_or(default_owner)
        .to_string();
    validate_option_owner(&owner)?;

    let is_core = ns_obj
        .get("x-core")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| default_is_core && owner == "core");

    let mut properties = BTreeMap::new();
    if let Some(props_obj) = ns_obj.get("properties").and_then(Value::as_object) {
        for (opt_key, prop_val) in props_obj {
            validate_option_key(opt_key)?;
            let Some(prop_obj) = prop_val.as_object() else {
                return Err(CfmsError::Config(format!(
                    "Option schema for '{namespace}/{opt_key}' must be a JSON object"
                )));
            };
            let schema_version = prop_obj
                .get("x-schema-version")
                .and_then(Value::as_i64)
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(1);
            if schema_version <= 0 {
                return Err(CfmsError::Config(format!(
                    "Invalid x-schema-version {schema_version} for '{namespace}/{opt_key}'"
                )));
            }
            let default_value = prop_obj.get("default").cloned();
            if let Some(ref def_val) = default_value {
                let _ = encode_option_value(def_val)?;
            }
            properties.insert(
                opt_key.clone(),
                OptionPropertySpec {
                    option_key: opt_key.clone(),
                    schema_version,
                    default_value,
                    raw_property_schema: prop_val.clone(),
                },
            );
        }
    }

    let mut raw_schema_map = ns_obj.clone();
    raw_schema_map
        .entry("type".to_string())
        .or_insert_with(|| Value::String("object".to_string()));
    raw_schema_map
        .entry("additionalProperties".to_string())
        .or_insert_with(|| Value::Bool(false));

    Ok(NamespaceSchemaSpec {
        namespace: namespace.to_string(),
        owner,
        is_core,
        has_detailed_schema: true,
        raw_schema: Value::Object(raw_schema_map),
        properties,
    })
}

/// Validate all individual fields and aggregate cross-field `x-invariants` rules for a schema-backed namespace.
pub fn validate_namespace_values_with_schema(
    spec: &NamespaceSchemaSpec,
    candidate_values: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let allow_additional = spec
        .raw_schema
        .get("additionalProperties")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if !allow_additional {
        for key in candidate_values.keys() {
            if !spec.properties.contains_key(key) {
                return Err(CfmsError::Config(format!(
                    "No option definition for {}/{key}",
                    spec.namespace
                )));
            }
        }
    }

    let mut normalized_obj = Map::new();
    for (key, prop_spec) in &spec.properties {
        if let Some(raw_val) = candidate_values
            .get(key)
            .or(prop_spec.default_value.as_ref())
        {
            let norm_val =
                normalize_and_precheck_value(key, &prop_spec.raw_property_schema, raw_val)?;
            let _ = encode_option_value(&norm_val)?;
            normalized_obj.insert(key.clone(), norm_val);
        }
    }

    if allow_additional {
        for (key, val) in candidate_values {
            if !normalized_obj.contains_key(key) {
                let _ = encode_option_value(val)?;
                normalized_obj.insert(key.clone(), val.clone());
            }
        }
    }

    let instance = Value::Object(normalized_obj.clone());
    validate_instance_against_schema(&spec.raw_schema, &instance, &spec.namespace)?;
    let _warnings = evaluate_schema_invariants(&spec.raw_schema, &instance)?;

    Ok(normalized_obj.into_iter().collect())
}

#[derive(Debug, Clone)]
struct RawOptionRow {
    namespace: String,
    owner: String,
    option_key: String,
    schema_version: i32,
    revision: i64,
    value_type: String,
    option_value: String,
    updated_at: f64,
}

impl RawOptionRow {
    fn into_resolved(self) -> Result<ResolvedOptionRecord> {
        validate_option_namespace(&self.namespace)?;
        validate_option_owner(&self.owner)?;
        validate_option_key(&self.option_key)?;
        if self.schema_version <= 0 {
            return Err(CfmsError::Config(format!(
                "Invalid stored schema_version {} for {}/{}",
                self.schema_version, self.namespace, self.option_key
            )));
        }
        let revision = u64::try_from(self.revision).map_err(|_| {
            CfmsError::Config(format!(
                "Invalid stored revision {} for {}/{}",
                self.revision, self.namespace, self.option_key
            ))
        })?;
        if revision == 0 {
            return Err(CfmsError::Config(format!(
                "Stored option {}/{} must have positive revision",
                self.namespace, self.option_key
            )));
        }
        let value = decode_option_value(&self.value_type, &self.option_value)?;
        Ok(ResolvedOptionRecord {
            namespace: self.namespace,
            owner: self.owner,
            option_key: self.option_key,
            schema_version: self.schema_version,
            revision,
            value,
            updated_at: Some(self.updated_at),
        })
    }
}

/// List stored database options merged with any defaults declared in the external `OptionsSchemaRegistry`.
pub async fn list_options(
    pool: &DbPool,
    registry: &OptionsSchemaRegistry,
    namespace: Option<&str>,
) -> Result<Vec<ResolvedOptionRecord>> {
    if let Some(ns) = namespace {
        validate_option_namespace(ns)?;
    }

    let raw_rows = fetch_option_rows(pool, namespace).await?;
    let mut records = Vec::with_capacity(raw_rows.len());
    let mut stored_keys = BTreeSet::new();

    for row in raw_rows {
        stored_keys.insert((row.namespace.clone(), row.option_key.clone()));
        records.push(row.into_resolved()?);
    }

    for (ns_name, spec) in registry.namespaces() {
        if !spec.has_detailed_schema {
            continue;
        }
        if let Some(filter) = namespace {
            if filter != ns_name {
                continue;
            }
        } else if !spec.is_core {
            continue;
        }

        for prop in spec.properties.values() {
            if let Some(ref def_val) = prop.default_value
                && !stored_keys.contains(&(ns_name.clone(), prop.option_key.clone()))
            {
                records.push(ResolvedOptionRecord {
                    namespace: ns_name.clone(),
                    owner: spec.owner.clone(),
                    option_key: prop.option_key.clone(),
                    schema_version: prop.schema_version,
                    revision: 0,
                    value: def_val.clone(),
                    updated_at: None,
                });
            }
        }
    }

    records.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.option_key.cmp(&b.option_key))
    });
    Ok(records)
}

/// Read a single option by `(namespace, option_key)` using database state and optional external schema defaults.
pub async fn get_option(
    pool: &DbPool,
    registry: &OptionsSchemaRegistry,
    namespace: &str,
    option_key: &str,
) -> Result<ResolvedOptionRecord> {
    validate_option_namespace(namespace)?;
    validate_option_key(option_key)?;

    if let Some(row) = fetch_single_option_row(pool, namespace, option_key).await? {
        return row.into_resolved();
    }

    if let Some(spec) = registry.get_namespace(namespace)
        && spec.has_detailed_schema
    {
        if let Some(prop) = spec.properties.get(option_key)
            && let Some(ref def_val) = prop.default_value
        {
            return Ok(ResolvedOptionRecord {
                namespace: namespace.to_string(),
                owner: spec.owner.clone(),
                option_key: option_key.to_string(),
                schema_version: prop.schema_version,
                revision: 0,
                value: def_val.clone(),
                updated_at: None,
            });
        }
        return Err(CfmsError::Config(format!(
            "No option definition for {namespace}/{option_key}"
        )));
    }

    Err(CfmsError::Config(format!(
        "No stored option {namespace}/{option_key}"
    )))
}

/// Reset a single option in `namespace` to its external schema default using optimistic concurrency.
pub async fn reset_option(
    pool: &DbPool,
    registry: &OptionsSchemaRegistry,
    namespace: &str,
    option_key: &str,
    expected_revision: u64,
) -> Result<ResolvedOptionRecord> {
    validate_option_namespace(namespace)?;
    validate_option_key(option_key)?;

    let Some(spec) = registry.get_namespace(namespace) else {
        return Err(CfmsError::Config(format!(
            "No schema default definition for {namespace}/{option_key}"
        )));
    };
    if !spec.has_detailed_schema {
        return Err(CfmsError::Config(format!(
            "No schema default definition for {namespace}/{option_key}"
        )));
    }
    let Some(prop) = spec.properties.get(option_key) else {
        return Err(CfmsError::Config(format!(
            "No option definition for {namespace}/{option_key}"
        )));
    };
    let Some(ref def_val) = prop.default_value else {
        return Err(CfmsError::Config(format!(
            "Option schema for {namespace}/{option_key} does not define a default value"
        )));
    };

    let mut updates = BTreeMap::new();
    updates.insert(
        option_key.to_string(),
        OptionUpdateInput {
            value: def_val.clone(),
            expected_revision,
        },
    );

    let mut updated = write_options_batch(pool, registry, namespace, updates).await?;
    updated.remove(option_key).ok_or_else(|| {
        CfmsError::Database(format!(
            "Failed to read back reset option {namespace}/{option_key}"
        ))
    })
}

/// Fetch only persisted rows from the `options` table keyed by `(namespace, option_key)`.
pub async fn fetch_stored_options(
    pool: &DbPool,
    namespace: Option<&str>,
) -> Result<BTreeMap<(String, String), ResolvedOptionRecord>> {
    if let Some(ns) = namespace {
        validate_option_namespace(ns)?;
    }
    let raw_rows = fetch_option_rows(pool, namespace).await?;
    let mut map = BTreeMap::new();
    for row in raw_rows {
        let resolved = row.into_resolved()?;
        map.insert(
            (resolved.namespace.clone(), resolved.option_key.clone()),
            resolved,
        );
    }
    Ok(map)
}

fn validate_batch_target<'a>(
    registry: &'a OptionsSchemaRegistry,
    namespace: &str,
    updates: &BTreeMap<String, OptionUpdateInput>,
) -> Result<Option<&'a NamespaceSchemaSpec>> {
    validate_option_namespace(namespace)?;
    if updates.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "Options update batch must contain at least one setting".to_string(),
        ));
    }
    for key in updates.keys() {
        validate_option_key(key)?;
    }

    let ns_spec = registry.get_namespace(namespace);
    if ns_spec.is_none() && registry.has_core_schema() {
        return Err(CfmsError::Config(format!(
            "Cannot resolve option declarations for '{namespace}'"
        )));
    }

    if let Some(spec) = ns_spec
        && spec.has_detailed_schema
    {
        let allow_additional = spec
            .raw_schema
            .get("additionalProperties")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !allow_additional {
            for key in updates.keys() {
                if !spec.properties.contains_key(key) {
                    return Err(CfmsError::Config(format!(
                        "No option definition for {namespace}/{key}"
                    )));
                }
            }
        }
    }

    Ok(ns_spec)
}

/// Atomically validate and write one or more options in `namespace` with optimistic concurrency
/// (`options.revision` CAS + `system_states` namespace guard + `audit_entries` record).
pub async fn write_options_batch(
    pool: &DbPool,
    registry: &OptionsSchemaRegistry,
    namespace: &str,
    updates: BTreeMap<String, OptionUpdateInput>,
) -> Result<BTreeMap<String, ResolvedOptionRecord>> {
    let ns_spec = validate_batch_target(registry, namespace, &updates)?;

    match pool {
        DbPool::Sqlite(sqlite_pool) => {
            let mut tx = sqlite_pool.begin().await?;
            let result = execute_write_tx_sqlite(
                &mut tx,
                namespace,
                ns_spec,
                &updates,
                "maintenance_cli",
            )
            .await?;
            tx.commit().await?;
            Ok(result)
        }
        DbPool::Mysql(mysql_pool) => {
            let mut tx = mysql_pool.begin().await?;
            let result = execute_write_tx_mysql(
                &mut tx,
                namespace,
                ns_spec,
                &updates,
                "maintenance_cli",
            )
            .await?;
            tx.commit().await?;
            Ok(result)
        }
        DbPool::Postgres(pg_pool) => {
            let mut tx = pg_pool.begin().await?;
            let result = execute_write_tx_postgres(
                &mut tx,
                namespace,
                ns_spec,
                &updates,
                "maintenance_cli",
            )
            .await?;
            tx.commit().await?;
            Ok(result)
        }
    }
}

/// Atomically validate and commit option batches across multiple namespaces in one SQL transaction.
pub async fn write_options_batches(
    pool: &DbPool,
    registry: &OptionsSchemaRegistry,
    batches: &[(String, BTreeMap<String, OptionUpdateInput>)],
    audit_source: &str,
) -> Result<Vec<(String, BTreeMap<String, ResolvedOptionRecord>)>> {
    if batches.is_empty() {
        return Ok(Vec::new());
    }

    let mut prepared = Vec::with_capacity(batches.len());
    for (namespace, updates) in batches {
        let ns_spec = validate_batch_target(registry, namespace, updates)?;
        prepared.push((namespace.as_str(), ns_spec, updates));
    }

    match pool {
        DbPool::Sqlite(sqlite_pool) => {
            let mut tx = sqlite_pool.begin().await?;
            let mut results = Vec::with_capacity(prepared.len());
            for (namespace, ns_spec, updates) in prepared {
                let res = execute_write_tx_sqlite(
                    &mut tx,
                    namespace,
                    ns_spec,
                    updates,
                    audit_source,
                )
                .await?;
                results.push((namespace.to_string(), res));
            }
            tx.commit().await?;
            Ok(results)
        }
        DbPool::Mysql(mysql_pool) => {
            let mut tx = mysql_pool.begin().await?;
            let mut results = Vec::with_capacity(prepared.len());
            for (namespace, ns_spec, updates) in prepared {
                let res = execute_write_tx_mysql(
                    &mut tx,
                    namespace,
                    ns_spec,
                    updates,
                    audit_source,
                )
                .await?;
                results.push((namespace.to_string(), res));
            }
            tx.commit().await?;
            Ok(results)
        }
        DbPool::Postgres(pg_pool) => {
            let mut tx = pg_pool.begin().await?;
            let mut results = Vec::with_capacity(prepared.len());
            for (namespace, ns_spec, updates) in prepared {
                let res = execute_write_tx_postgres(
                    &mut tx,
                    namespace,
                    ns_spec,
                    updates,
                    audit_source,
                )
                .await?;
                results.push((namespace.to_string(), res));
            }
            tx.commit().await?;
            Ok(results)
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedNamespaceMutation {
    guard_revision: u64,
    rows_to_write: Vec<PreparedRowWrite>,
    changed_keys: Vec<String>,
    previous_revisions: BTreeMap<String, u64>,
    new_revisions: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct PreparedRowWrite {
    option_key: String,
    owner: String,
    schema_version: i32,
    expected_revision: u64,
    new_revision: u64,
    value_type: OptionValueType,
    option_value: String,
    normalized_value: Value,
}

fn prepare_namespace_mutation(
    namespace: &str,
    ns_spec: Option<&NamespaceSchemaSpec>,
    guard_revision: u64,
    stored_rows: Vec<RawOptionRow>,
    updates: &BTreeMap<String, OptionUpdateInput>,
) -> Result<PreparedNamespaceMutation> {
    let mut stored_map: BTreeMap<String, ResolvedOptionRecord> = BTreeMap::new();
    for raw in stored_rows {
        let resolved = raw.into_resolved()?;
        stored_map.insert(resolved.option_key.clone(), resolved);
    }

    let resolved_owner = if let Some(spec) = ns_spec {
        spec.owner.clone()
    } else if let Some(first_stored) = stored_map.values().next() {
        first_stored.owner.clone()
    } else {
        "core".to_string()
    };

    let mut previous_resolved: BTreeMap<String, ResolvedOptionRecord> = BTreeMap::new();
    if let Some(spec) = ns_spec
        && spec.has_detailed_schema
    {
        for prop in spec.properties.values() {
            if let Some(stored) = stored_map.get(&prop.option_key) {
                if stored.schema_version != prop.schema_version {
                    return Err(CfmsError::Config(format!(
                        "Unsupported option schema for {namespace}/{}: {}; expected {}",
                        prop.option_key, stored.schema_version, prop.schema_version
                    )));
                }
                let validated_stored = normalize_and_precheck_value(
                    &prop.option_key,
                    &prop.raw_property_schema,
                    &stored.value,
                )?;
                previous_resolved.insert(
                    prop.option_key.clone(),
                    ResolvedOptionRecord {
                        value: validated_stored,
                        ..stored.clone()
                    },
                );
            } else if let Some(ref def_val) = prop.default_value {
                previous_resolved.insert(
                    prop.option_key.clone(),
                    ResolvedOptionRecord {
                        namespace: namespace.to_string(),
                        owner: spec.owner.clone(),
                        option_key: prop.option_key.clone(),
                        schema_version: prop.schema_version,
                        revision: 0,
                        value: def_val.clone(),
                        updated_at: None,
                    },
                );
            }
        }
        for (k, v) in &stored_map {
            previous_resolved.entry(k.clone()).or_insert_with(|| v.clone());
        }
    } else {
        for (k, v) in &stored_map {
            previous_resolved.insert(k.clone(), v.clone());
        }
        for k in updates.keys() {
            previous_resolved
                .entry(k.clone())
                .or_insert_with(|| ResolvedOptionRecord {
                    namespace: namespace.to_string(),
                    owner: resolved_owner.clone(),
                    option_key: k.clone(),
                    schema_version: 1,
                    revision: 0,
                    value: Value::Null,
                    updated_at: None,
                });
        }
    }

    // Check expected revisions for all target keys before validating/writing
    for (key, update) in updates {
        let current_rev = previous_resolved.get(key).map_or(0, |r| r.revision);
        if current_rev != update.expected_revision {
            return Err(CfmsError::OptionConflict(format!(
                "Option revision conflict for {namespace}/{key} (expected {}, actual {current_rev})",
                update.expected_revision
            )));
        }
    }

    let mut merged_values: BTreeMap<String, Value> = previous_resolved
        .iter()
        .map(|(k, r)| (k.clone(), r.value.clone()))
        .collect();
    for (key, update) in updates {
        merged_values.insert(key.clone(), update.value.clone());
    }

    let normalized_map = if let Some(spec) = ns_spec
        && spec.has_detailed_schema
    {
        validate_namespace_values_with_schema(spec, &merged_values)?
    } else {
        for val in merged_values.values() {
            let _ = encode_option_value(val)?;
        }
        merged_values
    };

    let mut rows_to_write = Vec::with_capacity(updates.len());
    let mut changed_keys = Vec::new();
    let mut previous_revisions = BTreeMap::new();
    let mut new_revisions = BTreeMap::new();

    for (key, update) in updates {
        let prev = previous_resolved.get(key);
        let schema_version = prev
            .map(|p| p.schema_version)
            .or_else(|| {
                ns_spec
                    .and_then(|s| s.properties.get(key))
                    .map(|p| p.schema_version)
            })
            .unwrap_or(1);
        let norm_val = normalized_map[key].clone();
        let (value_type, option_value) = encode_option_value(&norm_val)?;
        if let Some(p) = prev {
            let prev_encoded = encode_option_value(&p.value)?;
            if prev_encoded != (value_type, option_value.clone()) {
                changed_keys.push(key.clone());
            }
        } else {
            changed_keys.push(key.clone());
        }

        let new_rev = update.expected_revision.checked_add(1).ok_or_else(|| {
            CfmsError::Config(format!("Revision overflow for {namespace}/{key}"))
        })?;
        previous_revisions.insert(key.clone(), update.expected_revision);
        new_revisions.insert(key.clone(), new_rev);

        rows_to_write.push(PreparedRowWrite {
            option_key: key.clone(),
            owner: resolved_owner.clone(),
            schema_version,
            expected_revision: update.expected_revision,
            new_revision: new_rev,
            value_type,
            option_value,
            normalized_value: norm_val,
        });
    }

    changed_keys.sort();

    Ok(PreparedNamespaceMutation {
        guard_revision,
        rows_to_write,
        changed_keys,
        previous_revisions,
        new_revisions,
    })
}

fn unix_timestamp_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn generate_audit_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn validate_guard_row(
    namespace: &str,
    schema_version: i32,
    revision: i64,
    payload_str: &str,
) -> Result<u64> {
    if schema_version != 1 {
        return Err(CfmsError::Config(format!(
            "Unsupported options revision schema for {namespace}"
        )));
    }
    let payload: Value = serde_json::from_str(payload_str).map_err(|_| {
        CfmsError::Config(format!(
            "Unsupported options revision schema for {namespace}"
        ))
    })?;
    if payload.as_object().is_none_or(|m| !m.is_empty()) {
        return Err(CfmsError::Config(format!(
            "Unsupported options revision schema for {namespace}"
        )));
    }
    let rev = u64::try_from(revision).map_err(|_| {
        CfmsError::Config(format!(
            "Unsupported options revision schema for {namespace}"
        ))
    })?;
    if rev == 0 {
        return Err(CfmsError::Config(format!(
            "Unsupported options revision schema for {namespace}"
        )));
    }
    Ok(rev)
}

async fn execute_write_tx_sqlite(
    tx: &mut Transaction<'_, Sqlite>,
    namespace: &str,
    ns_spec: Option<&NamespaceSchemaSpec>,
    updates: &BTreeMap<String, OptionUpdateInput>,
    audit_source: &str,
) -> Result<BTreeMap<String, ResolvedOptionRecord>> {
    let state_key = format!("{OPTIONS_REVISION_PREFIX}{namespace}");
    let guard_row = sqlx::query(
        "SELECT schema_version, revision, CAST(payload AS TEXT) FROM system_states WHERE owner = 'core' AND state_key = ?",
    )
    .bind(&state_key)
    .fetch_optional(&mut **tx)
    .await?;

    let guard_revision = if let Some(row) = guard_row {
        validate_guard_row(
            namespace,
            row.get::<i32, _>(0),
            row.get::<i64, _>(1),
            &row.get::<String, _>(2),
        )?
    } else {
        0
    };

    let existing_rows = sqlx::query(
        "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = ? ORDER BY option_key",
    )
    .bind(namespace)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|r| RawOptionRow {
        namespace: r.get(0),
        owner: r.get(1),
        option_key: r.get(2),
        schema_version: r.get(3),
        revision: r.get(4),
        value_type: r.get(5),
        option_value: r.get(6),
        updated_at: r.get(7),
    })
    .collect::<Vec<_>>();

    let plan = prepare_namespace_mutation(namespace, ns_spec, guard_revision, existing_rows, updates)?;

    let now = unix_timestamp_secs();
    let guard_affected = if plan.guard_revision == 0 {
        sqlx::query(
            "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES ('core', ?, 1, 1, '{}', ?) ON CONFLICT (owner, state_key) DO NOTHING",
        )
        .bind(&state_key)
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    } else {
        let prev_i64 = i64::try_from(plan.guard_revision).unwrap_or(i64::MAX);
        let next_i64 = prev_i64.saturating_add(1);
        sqlx::query(
            "UPDATE system_states SET schema_version = 1, revision = ?, payload = '{}', updated_at = ? WHERE owner = 'core' AND state_key = ? AND revision = ?",
        )
        .bind(next_i64)
        .bind(now)
        .bind(&state_key)
        .bind(prev_i64)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    };

    if guard_affected != 1 {
        return Err(CfmsError::OptionConflict(format!(
            "Concurrent option update for {namespace}"
        )));
    }

    let mut out = BTreeMap::new();
    for item in &plan.rows_to_write {
        let row_now = unix_timestamp_secs();
        let affected = if item.expected_revision == 0 {
            sqlx::query(
                "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?) ON CONFLICT (namespace, option_key) DO NOTHING",
            )
            .bind(namespace)
            .bind(&item.owner)
            .bind(&item.option_key)
            .bind(item.schema_version)
            .bind(item.value_type.as_str())
            .bind(&item.option_value)
            .bind(row_now)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        } else {
            let exp_i64 = i64::try_from(item.expected_revision).unwrap_or(i64::MAX);
            let new_i64 = i64::try_from(item.new_revision).unwrap_or(i64::MAX);
            sqlx::query(
                "UPDATE options SET schema_version = ?, revision = ?, value_type = ?, option_value = ?, updated_at = ? WHERE namespace = ? AND option_key = ? AND revision = ?",
            )
            .bind(item.schema_version)
            .bind(new_i64)
            .bind(item.value_type.as_str())
            .bind(&item.option_value)
            .bind(row_now)
            .bind(namespace)
            .bind(&item.option_key)
            .bind(exp_i64)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        };

        if affected != 1 {
            return Err(CfmsError::OptionConflict(format!(
                "Option revision conflict for {namespace}/{}",
                item.option_key
            )));
        }

        out.insert(
            item.option_key.clone(),
            ResolvedOptionRecord {
                namespace: namespace.to_string(),
                owner: item.owner.clone(),
                option_key: item.option_key.clone(),
                schema_version: item.schema_version,
                revision: item.new_revision,
                value: item.normalized_value.clone(),
                updated_at: Some(row_now),
            },
        );
    }

    let audit_data = serde_json::to_string(&json!({
        "source": audit_source,
        "namespace": namespace,
        "previous_revisions": plan.previous_revisions,
        "revisions": plan.new_revisions,
        "changed_keys": plan.changed_keys,
    }))
    .unwrap_or_else(|_| "{}".to_string());

    sqlx::query(
        "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'update_options', NULL, ?, ?, 0, NULL, ?)",
    )
    .bind(generate_audit_id())
    .bind(namespace)
    .bind(audit_data)
    .bind(unix_timestamp_secs())
    .execute(&mut **tx)
    .await?;

    Ok(out)
}

async fn execute_write_tx_mysql(
    tx: &mut Transaction<'_, MySql>,
    namespace: &str,
    ns_spec: Option<&NamespaceSchemaSpec>,
    updates: &BTreeMap<String, OptionUpdateInput>,
    audit_source: &str,
) -> Result<BTreeMap<String, ResolvedOptionRecord>> {
    let state_key = format!("{OPTIONS_REVISION_PREFIX}{namespace}");
    let guard_row = sqlx::query(
        "SELECT schema_version, revision, CAST(payload AS CHAR) FROM system_states WHERE owner = 'core' AND state_key = ?",
    )
    .bind(&state_key)
    .fetch_optional(&mut **tx)
    .await?;

    let guard_revision = if let Some(row) = guard_row {
        validate_guard_row(
            namespace,
            row.get::<i32, _>(0),
            row.get::<i64, _>(1),
            &row.get::<String, _>(2),
        )?
    } else {
        0
    };

    let existing_rows = sqlx::query(
        "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = ? ORDER BY option_key",
    )
    .bind(namespace)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|r| RawOptionRow {
        namespace: r.get(0),
        owner: r.get(1),
        option_key: r.get(2),
        schema_version: r.get(3),
        revision: r.get(4),
        value_type: r.get(5),
        option_value: r.get(6),
        updated_at: r.get(7),
    })
    .collect::<Vec<_>>();

    let plan = prepare_namespace_mutation(namespace, ns_spec, guard_revision, existing_rows, updates)?;

    let now = unix_timestamp_secs();
    let guard_affected = if plan.guard_revision == 0 {
        sqlx::query(
            "INSERT IGNORE INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES ('core', ?, 1, 1, '{}', ?)",
        )
        .bind(&state_key)
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    } else {
        let prev_i64 = i64::try_from(plan.guard_revision).unwrap_or(i64::MAX);
        let next_i64 = prev_i64.saturating_add(1);
        sqlx::query(
            "UPDATE system_states SET schema_version = 1, revision = ?, payload = '{}', updated_at = ? WHERE owner = 'core' AND state_key = ? AND revision = ?",
        )
        .bind(next_i64)
        .bind(now)
        .bind(&state_key)
        .bind(prev_i64)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    };

    if guard_affected != 1 {
        return Err(CfmsError::OptionConflict(format!(
            "Concurrent option update for {namespace}"
        )));
    }

    let mut out = BTreeMap::new();
    for item in &plan.rows_to_write {
        let row_now = unix_timestamp_secs();
        let affected = if item.expected_revision == 0 {
            sqlx::query(
                "INSERT IGNORE INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            )
            .bind(namespace)
            .bind(&item.owner)
            .bind(&item.option_key)
            .bind(item.schema_version)
            .bind(item.value_type.as_str())
            .bind(&item.option_value)
            .bind(row_now)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        } else {
            let exp_i64 = i64::try_from(item.expected_revision).unwrap_or(i64::MAX);
            let new_i64 = i64::try_from(item.new_revision).unwrap_or(i64::MAX);
            sqlx::query(
                "UPDATE options SET schema_version = ?, revision = ?, value_type = ?, option_value = ?, updated_at = ? WHERE namespace = ? AND option_key = ? AND revision = ?",
            )
            .bind(item.schema_version)
            .bind(new_i64)
            .bind(item.value_type.as_str())
            .bind(&item.option_value)
            .bind(row_now)
            .bind(namespace)
            .bind(&item.option_key)
            .bind(exp_i64)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        };

        if affected != 1 {
            return Err(CfmsError::OptionConflict(format!(
                "Option revision conflict for {namespace}/{}",
                item.option_key
            )));
        }

        out.insert(
            item.option_key.clone(),
            ResolvedOptionRecord {
                namespace: namespace.to_string(),
                owner: item.owner.clone(),
                option_key: item.option_key.clone(),
                schema_version: item.schema_version,
                revision: item.new_revision,
                value: item.normalized_value.clone(),
                updated_at: Some(row_now),
            },
        );
    }

    let audit_data = serde_json::to_string(&json!({
        "source": audit_source,
        "namespace": namespace,
        "previous_revisions": plan.previous_revisions,
        "revisions": plan.new_revisions,
        "changed_keys": plan.changed_keys,
    }))
    .unwrap_or_else(|_| "{}".to_string());

    sqlx::query(
        "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'update_options', NULL, ?, ?, 0, NULL, ?)",
    )
    .bind(generate_audit_id())
    .bind(namespace)
    .bind(audit_data)
    .bind(unix_timestamp_secs())
    .execute(&mut **tx)
    .await?;

    Ok(out)
}

async fn execute_write_tx_postgres(
    tx: &mut Transaction<'_, Postgres>,
    namespace: &str,
    ns_spec: Option<&NamespaceSchemaSpec>,
    updates: &BTreeMap<String, OptionUpdateInput>,
    audit_source: &str,
) -> Result<BTreeMap<String, ResolvedOptionRecord>> {
    let state_key = format!("{OPTIONS_REVISION_PREFIX}{namespace}");
    let guard_row = sqlx::query(
        "SELECT schema_version, revision, payload::text FROM system_states WHERE owner = 'core' AND state_key = $1",
    )
    .bind(&state_key)
    .fetch_optional(&mut **tx)
    .await?;

    let guard_revision = if let Some(row) = guard_row {
        validate_guard_row(
            namespace,
            row.get::<i32, _>(0),
            row.get::<i64, _>(1),
            &row.get::<String, _>(2),
        )?
    } else {
        0
    };

    let existing_rows = sqlx::query(
        "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = $1 ORDER BY option_key",
    )
    .bind(namespace)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|r| RawOptionRow {
        namespace: r.get(0),
        owner: r.get(1),
        option_key: r.get(2),
        schema_version: r.get(3),
        revision: r.get(4),
        value_type: r.get(5),
        option_value: r.get(6),
        updated_at: r.get(7),
    })
    .collect::<Vec<_>>();

    let plan = prepare_namespace_mutation(namespace, ns_spec, guard_revision, existing_rows, updates)?;

    let now = unix_timestamp_secs();
    let guard_affected = if plan.guard_revision == 0 {
        sqlx::query(
            "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES ('core', $1, 1, 1, '{}'::json, $2) ON CONFLICT (owner, state_key) DO NOTHING",
        )
        .bind(&state_key)
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    } else {
        let prev_i64 = i64::try_from(plan.guard_revision).unwrap_or(i64::MAX);
        let next_i64 = prev_i64.saturating_add(1);
        sqlx::query(
            "UPDATE system_states SET schema_version = 1, revision = $1, payload = '{}'::json, updated_at = $2 WHERE owner = 'core' AND state_key = $3 AND revision = $4",
        )
        .bind(next_i64)
        .bind(now)
        .bind(&state_key)
        .bind(prev_i64)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    };

    if guard_affected != 1 {
        return Err(CfmsError::OptionConflict(format!(
            "Concurrent option update for {namespace}"
        )));
    }

    let mut out = BTreeMap::new();
    for item in &plan.rows_to_write {
        let row_now = unix_timestamp_secs();
        let affected = if item.expected_revision == 0 {
            sqlx::query(
                "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ($1, $2, $3, $4, 1, $5, $6, $7) ON CONFLICT (namespace, option_key) DO NOTHING",
            )
            .bind(namespace)
            .bind(&item.owner)
            .bind(&item.option_key)
            .bind(item.schema_version)
            .bind(item.value_type.as_str())
            .bind(&item.option_value)
            .bind(row_now)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        } else {
            let exp_i64 = i64::try_from(item.expected_revision).unwrap_or(i64::MAX);
            let new_i64 = i64::try_from(item.new_revision).unwrap_or(i64::MAX);
            sqlx::query(
                "UPDATE options SET schema_version = $1, revision = $2, value_type = $3, option_value = $4, updated_at = $5 WHERE namespace = $6 AND option_key = $7 AND revision = $8",
            )
            .bind(item.schema_version)
            .bind(new_i64)
            .bind(item.value_type.as_str())
            .bind(&item.option_value)
            .bind(row_now)
            .bind(namespace)
            .bind(&item.option_key)
            .bind(exp_i64)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        };

        if affected != 1 {
            return Err(CfmsError::OptionConflict(format!(
                "Option revision conflict for {namespace}/{}",
                item.option_key
            )));
        }

        out.insert(
            item.option_key.clone(),
            ResolvedOptionRecord {
                namespace: namespace.to_string(),
                owner: item.owner.clone(),
                option_key: item.option_key.clone(),
                schema_version: item.schema_version,
                revision: item.new_revision,
                value: item.normalized_value.clone(),
                updated_at: Some(row_now),
            },
        );
    }

    let audit_data = serde_json::to_string(&json!({
        "source": audit_source,
        "namespace": namespace,
        "previous_revisions": plan.previous_revisions,
        "revisions": plan.new_revisions,
        "changed_keys": plan.changed_keys,
    }))
    .unwrap_or_else(|_| "{}".to_string());

    sqlx::query(
        "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES ($1, 'update_options', NULL, $2, $3::json, 0, NULL, $4)",
    )
    .bind(generate_audit_id())
    .bind(namespace)
    .bind(audit_data)
    .bind(unix_timestamp_secs())
    .execute(&mut **tx)
    .await?;

    Ok(out)
}

async fn fetch_option_rows(
    pool: &DbPool,
    namespace: Option<&str>,
) -> Result<Vec<RawOptionRow>> {
    match (pool, namespace) {
        (DbPool::Sqlite(p), None) => {
            let rows = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options ORDER BY namespace, option_key",
            )
            .fetch_all(p)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| RawOptionRow {
                    namespace: r.get(0),
                    owner: r.get(1),
                    option_key: r.get(2),
                    schema_version: r.get(3),
                    revision: r.get(4),
                    value_type: r.get(5),
                    option_value: r.get(6),
                    updated_at: r.get(7),
                })
                .collect())
        }
        (DbPool::Sqlite(p), Some(ns)) => {
            let rows = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = ? ORDER BY namespace, option_key",
            )
            .bind(ns)
            .fetch_all(p)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| RawOptionRow {
                    namespace: r.get(0),
                    owner: r.get(1),
                    option_key: r.get(2),
                    schema_version: r.get(3),
                    revision: r.get(4),
                    value_type: r.get(5),
                    option_value: r.get(6),
                    updated_at: r.get(7),
                })
                .collect())
        }
        (DbPool::Mysql(p), None) => {
            let rows = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options ORDER BY namespace, option_key",
            )
            .fetch_all(p)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| RawOptionRow {
                    namespace: r.get(0),
                    owner: r.get(1),
                    option_key: r.get(2),
                    schema_version: r.get(3),
                    revision: r.get(4),
                    value_type: r.get(5),
                    option_value: r.get(6),
                    updated_at: r.get(7),
                })
                .collect())
        }
        (DbPool::Mysql(p), Some(ns)) => {
            let rows = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = ? ORDER BY namespace, option_key",
            )
            .bind(ns)
            .fetch_all(p)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| RawOptionRow {
                    namespace: r.get(0),
                    owner: r.get(1),
                    option_key: r.get(2),
                    schema_version: r.get(3),
                    revision: r.get(4),
                    value_type: r.get(5),
                    option_value: r.get(6),
                    updated_at: r.get(7),
                })
                .collect())
        }
        (DbPool::Postgres(p), None) => {
            let rows = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options ORDER BY namespace, option_key",
            )
            .fetch_all(p)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| RawOptionRow {
                    namespace: r.get(0),
                    owner: r.get(1),
                    option_key: r.get(2),
                    schema_version: r.get(3),
                    revision: r.get(4),
                    value_type: r.get(5),
                    option_value: r.get(6),
                    updated_at: r.get(7),
                })
                .collect())
        }
        (DbPool::Postgres(p), Some(ns)) => {
            let rows = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = $1 ORDER BY namespace, option_key",
            )
            .bind(ns)
            .fetch_all(p)
            .await?;
            Ok(rows
                .into_iter()
                .map(|r| RawOptionRow {
                    namespace: r.get(0),
                    owner: r.get(1),
                    option_key: r.get(2),
                    schema_version: r.get(3),
                    revision: r.get(4),
                    value_type: r.get(5),
                    option_value: r.get(6),
                    updated_at: r.get(7),
                })
                .collect())
        }
    }
}

async fn fetch_single_option_row(
    pool: &DbPool,
    namespace: &str,
    option_key: &str,
) -> Result<Option<RawOptionRow>> {
    match pool {
        DbPool::Sqlite(p) => {
            let row = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = ? AND option_key = ?",
            )
            .bind(namespace)
            .bind(option_key)
            .fetch_optional(p)
            .await?;
            Ok(row.map(|r| RawOptionRow {
                namespace: r.get(0),
                owner: r.get(1),
                option_key: r.get(2),
                schema_version: r.get(3),
                revision: r.get(4),
                value_type: r.get(5),
                option_value: r.get(6),
                updated_at: r.get(7),
            }))
        }
        DbPool::Mysql(p) => {
            let row = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = ? AND option_key = ?",
            )
            .bind(namespace)
            .bind(option_key)
            .fetch_optional(p)
            .await?;
            Ok(row.map(|r| RawOptionRow {
                namespace: r.get(0),
                owner: r.get(1),
                option_key: r.get(2),
                schema_version: r.get(3),
                revision: r.get(4),
                value_type: r.get(5),
                option_value: r.get(6),
                updated_at: r.get(7),
            }))
        }
        DbPool::Postgres(p) => {
            let row = sqlx::query(
                "SELECT namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at FROM options WHERE namespace = $1 AND option_key = $2",
            )
            .bind(namespace)
            .bind(option_key)
            .fetch_optional(p)
            .await?;
            Ok(row.map(|r| RawOptionRow {
                namespace: r.get(0),
                owner: r.get(1),
                option_key: r.get(2),
                schema_version: r.get(3),
                revision: r.get(4),
                value_type: r.get(5),
                option_value: r.get(6),
                updated_at: r.get(7),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_sqlite_pool() -> DbPool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite");
        sqlx::query(
            r#"
            CREATE TABLE options (
                namespace VARCHAR(111) NOT NULL,
                owner VARCHAR(255) NOT NULL,
                option_key VARCHAR(128) NOT NULL,
                schema_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                value_type VARCHAR(16) NOT NULL,
                option_value TEXT NOT NULL,
                updated_at FLOAT NOT NULL,
                PRIMARY KEY (namespace, option_key)
            );
            "#,
        )
        .execute(&pool)
        .await
        .expect("create options table");
        sqlx::query(
            r#"
            CREATE TABLE system_states (
                owner VARCHAR(255) NOT NULL,
                state_key VARCHAR(128) NOT NULL,
                schema_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                updated_at FLOAT NOT NULL,
                PRIMARY KEY (owner, state_key)
            );
            "#,
        )
        .execute(&pool)
        .await
        .expect("create system_states table");
        sqlx::query(
            r#"
            CREATE TABLE audit_entries (
                id VARCHAR(64) NOT NULL PRIMARY KEY,
                action VARCHAR(64) NOT NULL,
                user_id VARCHAR(255),
                target VARCHAR(255),
                data TEXT,
                result INTEGER NOT NULL,
                remote_address VARCHAR(64),
                logged_time FLOAT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await
        .expect("create audit_entries table");
        DbPool::Sqlite(pool)
    }

    fn write_sample_schemas(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let core_schema_path = root.join("options.schema.json");
        let ext_root = root.join("extensions");
        std::fs::create_dir_all(&ext_root).expect("create extensions root");

        let core_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "security.password": {
                    "type": "object",
                    "x-owner": "core",
                    "x-core": true,
                    "additionalProperties": false,
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
                            "default": 32,
                            "x-schema-version": 1
                        },
                        "passwd_rules": {
                            "type": "array",
                            "items": { "type": "string", "x-format": "regex" },
                            "default": ["[A-Z]", "[a-z]", "[0-9]"],
                            "x-schema-version": 1
                        }
                    },
                    "x-invariants": [
                        {
                            "rule": "order",
                            "lower": "passwd_min_length",
                            "upper": "passwd_max_length",
                            "allow_equal": true,
                            "message": "Invalid options for security.password: Minimum password length exceeds maximum"
                        }
                    ]
                }
            }
        });
        std::fs::write(
            &core_schema_path,
            serde_json::to_string_pretty(&core_schema).expect("serialize core schema"),
        )
        .expect("write core options.schema.json");

        // Extension 1: `brute_force_lockdown` with its own `options.schema.json`
        let bf_dir = ext_root.join("brute_force_lockdown");
        std::fs::create_dir_all(&bf_dir).expect("create bf_dir");
        std::fs::write(
            bf_dir.join("manifest.toml"),
            r#"
option_namespaces = ["security.brute_force_lockdown"]

[extension]
identifier = "brute_force_lockdown"
"#,
        )
        .expect("write bf manifest");
        let bf_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "x-namespace": "security.brute_force_lockdown",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "failure_threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 50,
                    "x-schema-version": 1
                },
                "distinct_account_threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 10,
                    "x-schema-version": 1
                },
                "reason": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1024,
                    "x-normalize": "trim",
                    "default": "Automatic security lockdown",
                    "x-schema-version": 1
                }
            },
            "x-invariants": [
                {
                    "rule": "order",
                    "lower": "distinct_account_threshold",
                    "upper": "failure_threshold",
                    "allow_equal": true,
                    "message": "Invalid options for security.brute_force_lockdown: distinct_account_threshold must not exceed failure_threshold"
                }
            ]
        });
        std::fs::write(
            bf_dir.join("options.schema.json"),
            serde_json::to_string_pretty(&bf_schema).expect("serialize bf schema"),
        )
        .expect("write bf options.schema.json");

        // Extension 2: `oidc_sso` with inline `[options_schema]` inside `manifest.toml`
        let oidc_dir = ext_root.join("oidc_sso");
        std::fs::create_dir_all(&oidc_dir).expect("create oidc_dir");
        std::fs::write(
            oidc_dir.join("manifest.toml"),
            r#"
[extension]
identifier = "oidc_sso"

[options_schema."identity.oidc"]
type = "object"
additionalProperties = false

[options_schema."identity.oidc".properties.default_groups]
type = "array"
default = ["user"]
items = { type = "string", minLength = 1 }
"#,
        )
        .expect("write oidc manifest");

        // Extension 3: `acme_sso` declaring only `option_namespaces` (schema-less extension)
        let acme_dir = ext_root.join("acme_sso");
        std::fs::create_dir_all(&acme_dir).expect("create acme_dir");
        std::fs::write(
            acme_dir.join("manifest.toml"),
            r#"
option_namespaces = ["identity.acme_sso"]

[extension]
identifier = "acme_sso"
"#,
        )
        .expect("write acme manifest");

        (core_schema_path, ext_root)
    }

    #[test]
    fn test_option_value_codec_roundtrip_and_strict_rejection() {
        // 1. Scalars and arbitrary-precision integers (2^80 + 1)
        let big_int: Value =
            serde_json::from_str("1208925819614629174706177").expect("parse big int");
        let (vtype, encoded) = encode_option_value(&big_int).expect("encode big int");
        assert_eq!(vtype, OptionValueType::Int);
        assert_eq!(encoded, "1208925819614629174706177");
        let decoded = decode_option_value(vtype.as_str(), &encoded).expect("decode big int");
        assert_eq!(decoded, big_int);

        // 2. Float canonical representation
        let float_val: Value = serde_json::from_str("1.500").expect("parse float");
        let (ft, fe) = encode_option_value(&float_val).expect("encode float");
        assert_eq!(ft, OptionValueType::Float);
        assert_eq!(fe, "1.5");
        let fd = decode_option_value(ft.as_str(), &fe).expect("decode float");
        assert_eq!(fd.as_f64(), Some(1.5));

        let whole_float: Value = serde_json::from_str("2.0").expect("parse 2.0");
        let (wft, wfe) = encode_option_value(&whole_float).expect("encode 2.0");
        assert_eq!(wft, OptionValueType::Float);
        assert_eq!(wfe, "2.0");

        // 3. Bool and null
        assert_eq!(
            encode_option_value(&json!(true)).expect("bool true"),
            (OptionValueType::Bool, "1".to_string())
        );
        assert_eq!(
            encode_option_value(&json!(false)).expect("bool false"),
            (OptionValueType::Bool, "0".to_string())
        );
        assert_eq!(
            encode_option_value(&Value::Null).expect("null"),
            (OptionValueType::Null, String::new())
        );

        // 4. JSON objects/arrays and scalar rejection in "json" type
        let obj = json!({"b": 1, "a": [true, null]});
        let (jt, je) = encode_option_value(&obj).expect("encode json");
        assert_eq!(jt, OptionValueType::Json);
        assert_eq!(je, r#"{"a":[true,null],"b":1}"#);
        assert_eq!(
            decode_option_value(jt.as_str(), &je).expect("decode json"),
            obj
        );

        let err = decode_option_value("json", "\"scalar-secret\"").expect_err("reject scalar json");
        assert!(!err.to_string().contains("scalar-secret"));

        // 5. Ensure invalid stored values never echo back secret strings
        let err = decode_option_value("int", "super-secret-token-123").expect_err("bad int");
        assert!(!err.to_string().contains("super-secret-token-123"));
        let err = decode_option_value("bool", "secret-bool").expect_err("bad bool");
        assert!(!err.to_string().contains("secret-bool"));
    }

    #[tokio::test]
    async fn test_options_list_and_get_defaults_from_external_schema_without_db_writes() {
        let pool = setup_sqlite_pool().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (core_schema_path, ext_root) = write_sample_schemas(dir.path());
        let registry = OptionsSchemaRegistry::load(Some(&core_schema_path), Some(&ext_root))
            .expect("load registry");

        let all = list_options(&pool, &registry, None)
            .await
            .expect("list all options");
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|r| r.revision == 0 && r.updated_at.is_none()));

        let min_len = get_option(&pool, &registry, "security.password", "passwd_min_length")
            .await
            .expect("get passwd_min_length");
        assert_eq!(min_len.owner, "core");
        assert_eq!(min_len.schema_version, 1);
        assert_eq!(min_len.revision, 0);
        assert_eq!(min_len.value, json!(8));

        // Verify extension defaults can also be queried directly via `get_option`!
        let bf_default = get_option(
            &pool,
            &registry,
            "security.brute_force_lockdown",
            "failure_threshold",
        )
        .await
        .expect("get extension default");
        assert_eq!(bf_default.owner, "brute_force_lockdown");
        assert_eq!(bf_default.revision, 0);
        assert_eq!(bf_default.value, json!(50));

        // Verify no rows were written to `options`
        let DbPool::Sqlite(ref sqlite) = pool else {
            unreachable!()
        };
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM options")
            .fetch_one(sqlite)
            .await
            .expect("count options");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_options_set_set_many_reset_optimistic_concurrency_and_audit() {
        let pool = setup_sqlite_pool().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (core_schema_path, ext_root) = write_sample_schemas(dir.path());
        let registry = OptionsSchemaRegistry::load(Some(&core_schema_path), Some(&ext_root))
            .expect("load registry");

        // 1. Set single option (revision 0 -> 1)
        let mut updates = BTreeMap::new();
        updates.insert(
            "passwd_min_length".to_string(),
            OptionUpdateInput {
                value: json!(12),
                expected_revision: 0,
            },
        );
        let written = write_options_batch(&pool, &registry, "security.password", updates.clone())
            .await
            .expect("write passwd_min_length");
        let rec = written
            .get("passwd_min_length")
            .expect("passwd_min_length record");
        assert_eq!(rec.revision, 1);
        assert_eq!(rec.value, json!(12));
        assert!(rec.updated_at.is_some());

        // 2. Stale expected_revision = 0 must fail with OptionConflict
        let conflict_err = write_options_batch(&pool, &registry, "security.password", updates)
            .await
            .expect_err("must fail with conflict");
        assert!(matches!(conflict_err, CfmsError::OptionConflict(_)));

        // 3. Batch update in extension `security.brute_force_lockdown`
        let mut bf_updates = BTreeMap::new();
        bf_updates.insert(
            "failure_threshold".to_string(),
            OptionUpdateInput {
                value: json!(80),
                expected_revision: 0,
            },
        );
        bf_updates.insert(
            "reason".to_string(),
            OptionUpdateInput {
                value: json!("  Lockdown triggered by policy  "),
                expected_revision: 0,
            },
        );
        let bf_written = write_options_batch(
            &pool,
            &registry,
            "security.brute_force_lockdown",
            bf_updates,
        )
        .await
        .expect("write brute_force_lockdown");

        // Verify `x-normalize: "trim"` normalization from extension schema
        assert_eq!(
            bf_written["reason"].value,
            json!("Lockdown triggered by policy")
        );

        // 4. Verify `system_states` namespace revision guard was incremented
        let DbPool::Sqlite(ref sqlite) = pool else {
            unreachable!()
        };
        let state_rev: i64 = sqlx::query_scalar(
            "SELECT revision FROM system_states WHERE owner = 'core' AND state_key = 'options_revision.security.password'",
        )
        .fetch_one(sqlite)
        .await
        .expect("fetch system_states revision");
        assert_eq!(state_rev, 1);

        // 5. Reset `security.password.passwd_min_length` with expected_revision = 1 -> writes default with revision = 2
        let reset_rec = reset_option(
            &pool,
            &registry,
            "security.password",
            "passwd_min_length",
            1,
        )
        .await
        .expect("reset passwd_min_length");
        assert_eq!(reset_rec.revision, 2);
        assert_eq!(reset_rec.value, json!(8));
        assert!(reset_rec.updated_at.is_some());

        // 6. Verify audit_entries were recorded without leaking option values
        let audit_rows: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT action, result, data FROM audit_entries ORDER BY logged_time ASC",
        )
        .fetch_all(sqlite)
        .await
        .expect("fetch audit entries");
        assert_eq!(audit_rows.len(), 3);
        for (action, result, data_str) in &audit_rows {
            assert_eq!(action, "update_options");
            assert_eq!(*result, 0);
            assert!(!data_str.contains("Lockdown triggered by policy"));
            let data: Value = serde_json::from_str(data_str).expect("parse audit json");
            assert_eq!(data["source"], json!("maintenance_cli"));
            assert!(data.get("changed_keys").is_some());
            assert!(data.get("previous_revisions").is_some());
            assert!(data.get("revisions").is_some());
        }
    }

    #[tokio::test]
    async fn test_external_json_schema_validation_and_schemaless_fallback() {
        let pool = setup_sqlite_pool().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (core_schema_path, ext_root) = write_sample_schemas(dir.path());
        let registry = OptionsSchemaRegistry::load(Some(&core_schema_path), Some(&ext_root))
            .expect("load registry");

        // 1. Strict type check: integer field rejects string `"12"` and float `12.0`
        for bad_val in [json!("12"), json!(12.0), json!(true)] {
            let mut updates = BTreeMap::new();
            updates.insert(
                "passwd_min_length".to_string(),
                OptionUpdateInput {
                    value: bad_val,
                    expected_revision: 0,
                },
            );
            assert!(
                write_options_batch(&pool, &registry, "security.password", updates)
                    .await
                    .is_err()
            );
        }

        // 2. Cross-field validation via `x-invariants`: `distinct_account_threshold <= failure_threshold`
        let mut bad_bf = BTreeMap::new();
        bad_bf.insert(
            "failure_threshold".to_string(),
            OptionUpdateInput {
                value: json!(10),
                expected_revision: 0,
            },
        );
        bad_bf.insert(
            "distinct_account_threshold".to_string(),
            OptionUpdateInput {
                value: json!(25),
                expected_revision: 0,
            },
        );
        let err = write_options_batch(
            &pool,
            &registry,
            "security.brute_force_lockdown",
            bad_bf,
        )
        .await
        .expect_err("cross-field failure");
        assert!(
            err.to_string()
                .contains("distinct_account_threshold must not exceed failure_threshold")
        );

        // 3. Inline manifest.toml `[options_schema]` validation: default_groups requires non-empty strings
        let mut bad_oidc = BTreeMap::new();
        bad_oidc.insert(
            "default_groups".to_string(),
            OptionUpdateInput {
                value: json!([""]),
                expected_revision: 0,
            },
        );
        let oidc_err = write_options_batch(&pool, &registry, "identity.oidc", bad_oidc)
            .await
            .expect_err("oidc default_groups rejects empty string");
        assert!(oidc_err.to_string().contains("default_groups"));

        // 4. Schema-less extension fallback (`acme_sso/manifest.toml` with only `option_namespaces`)
        let mut ext_updates = BTreeMap::new();
        ext_updates.insert(
            "tenant_id".to_string(),
            OptionUpdateInput {
                value: json!("acme-prod"),
                expected_revision: 0,
            },
        );
        let ext_written =
            write_options_batch(&pool, &registry, "identity.acme_sso", ext_updates)
                .await
                .expect("write manifest-discovered extension option");
        assert_eq!(ext_written["tenant_id"].owner, "acme_sso");
        assert_eq!(ext_written["tenant_id"].revision, 1);

        // 5. Pure schema-less workspace (OptionsSchemaRegistry::empty()) allows basic CRUD without any schema file
        let empty_registry = OptionsSchemaRegistry::empty();
        let mut custom_updates = BTreeMap::new();
        custom_updates.insert(
            "custom_flag".to_string(),
            OptionUpdateInput {
                value: json!(true),
                expected_revision: 0,
            },
        );
        let custom_written =
            write_options_batch(&pool, &empty_registry, "custom.feature", custom_updates)
                .await
                .expect("write in pure schema-less mode");
        assert_eq!(custom_written["custom_flag"].value, json!(true));
        assert_eq!(custom_written["custom_flag"].revision, 1);
    }
}
