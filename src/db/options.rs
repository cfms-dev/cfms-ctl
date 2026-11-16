//! Database-backed `options` CRUD with two-level optimistic concurrency (`options.revision`
//! and `system_states` namespace write-skew guard), canonical tagged scalar/JSON encoding,
//! `core_config_contract.options` (`Draft 2020-12` + `x-invariants`) validation, and transactional
//! `audit_entries` logging.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{MySql, Postgres, Row, Sqlite, Transaction};
use crate::core::contract::CoreConfigContract;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::core::schema::{
    evaluate_schema_invariants, format_canonical_float, is_canonical_int_str,
    normalize_and_precheck_value, validate_instance_against_schema,
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

/// Property-level metadata extracted from `core_config_contract.options`.
#[derive(Debug, Clone)]
pub struct OptionPropertySpec {
    pub option_key: String,
    pub schema_version: i32,
    pub default_value: Option<Value>,
    pub renamed_from: Vec<String>,
    pub raw_property_schema: Value,
}

/// Core namespace specification loaded from `core_config_contract.options`.
#[derive(Debug, Clone)]
pub struct NamespaceSchemaSpec {
    pub namespace: String,
    pub owner: String,
    pub raw_schema: Value,
    pub properties: BTreeMap<String, OptionPropertySpec>,
}

/// Registry of core database option schemas loaded from `core_config_contract.options`.
///
/// Extension options are intentionally excluded; reads (`list` / `get`) return stored database
/// rows across all owners while validated writes (`set` / `set-many` / `reset`) are restricted to
/// declared core namespaces when a contract is active.
#[derive(Debug, Clone, Default)]
pub struct OptionsSchemaRegistry {
    has_core_contract: bool,
    namespaces: BTreeMap<String, NamespaceSchemaSpec>,
}

impl OptionsSchemaRegistry {
    /// Create an empty registry (schema-less fallback mode for pre-contract workspaces).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a registry directly from a [`CoreConfigContract`].
    pub fn from_contract(contract: &CoreConfigContract) -> Result<Self> {
        let mut registry = Self {
            has_core_contract: true,
            namespaces: BTreeMap::new(),
        };
        let Some(ns_map) = contract
            .options
            .as_object()
            .and_then(|o| o.get("properties"))
            .and_then(Value::as_object)
        else {
            return Err(CfmsError::Config(
                "Invalid core_config_contract.options: missing top-level 'properties' object"
                    .to_string(),
            ));
        };

        for (ns_name, ns_val) in ns_map {
            let Some(ns_obj) = ns_val.as_object() else {
                return Err(CfmsError::Config(format!(
                    "Namespace schema for '{ns_name}' in core_config_contract.options must be a JSON object"
                )));
            };
            let spec = parse_namespace_schema_object(ns_name, ns_obj)?;
            registry.namespaces.insert(spec.namespace.clone(), spec);
        }

        Ok(registry)
    }

    /// Discover and load core option schemas from the workspace `core_config_contract`
    /// (explicit `--contract` override, `release-manifest.json`, or source Python reflection).
    pub fn from_workspace(
        paths: &WorkspacePaths,
        explicit_contract: Option<&Path>,
    ) -> Result<Self> {
        let Some((contract, _source)) =
            CoreConfigContract::from_workspace(paths, explicit_contract)?
        else {
            return Ok(Self::empty());
        };
        Self::from_contract(&contract)
    }

    /// Whether an active `core_config_contract` was loaded.
    #[must_use]
    pub const fn has_core_contract(&self) -> bool {
        self.has_core_contract
    }

    /// Look up a core namespace schema specification by name.
    #[must_use]
    pub fn get_namespace(&self, namespace: &str) -> Option<&NamespaceSchemaSpec> {
        self.namespaces.get(namespace)
    }

    /// Iterate over all loaded core namespace specifications.
    pub fn namespaces(&self) -> impl Iterator<Item = (&String, &NamespaceSchemaSpec)> {
        self.namespaces.iter()
    }
}

fn parse_namespace_schema_object(
    namespace: &str,
    ns_obj: &Map<String, Value>,
) -> Result<NamespaceSchemaSpec> {
    validate_option_namespace(namespace)?;
    let owner = ns_obj
        .get("x-owner")
        .and_then(Value::as_str)
        .unwrap_or("core")
        .to_string();
    validate_option_owner(&owner)?;
    if owner != "core" {
        return Err(CfmsError::Config(format!(
            "Namespace '{namespace}' in core_config_contract.options has non-core owner '{owner}'"
        )));
    }

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
            let renamed_from = prop_obj
                .get("x-renamed-from")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            properties.insert(
                opt_key.clone(),
                OptionPropertySpec {
                    option_key: opt_key.clone(),
                    schema_version,
                    default_value,
                    renamed_from,
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
        if let Some(filter) = namespace
            && filter != ns_name
        {
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

/// Read a single option by `(namespace, option_key)` using database state and optional core contract defaults.
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

    if let Some(spec) = registry.get_namespace(namespace) {
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

/// Reset a single core option in `namespace` to its contract default using optimistic concurrency.
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
        if registry.has_core_contract() {
            return Err(CfmsError::Config(format!(
                "Option namespace '{namespace}' is not part of core_config_contract; extension/custom options must be managed via the CFMS server or Python maintenance CLI"
            )));
        }
        return Err(CfmsError::Config(format!(
            "No schema default definition for {namespace}/{option_key}"
        )));
    };
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

/// Specification for renaming a core database option row (`WHERE owner = 'core'`).
#[derive(Debug, Clone)]
pub struct CoreOptionRename {
    pub old_namespace: String,
    pub old_key: String,
    pub new_namespace: String,
    pub new_key: String,
    pub schema_version: i32,
}

/// Rename core database option keys in a single SQL transaction (`WHERE owner = 'core'`).
pub async fn rename_core_option_keys(
    pool: &DbPool,
    renames: &[CoreOptionRename],
) -> Result<u64> {
    if renames.is_empty() {
        return Ok(0);
    }
    let mut moved = 0u64;
    match pool {
        DbPool::Sqlite(sqlite_pool) => {
            let mut tx = sqlite_pool.begin().await?;
            for r in renames {
                let res = sqlx::query(
                    "UPDATE options SET namespace = ?, option_key = ?, schema_version = ? WHERE owner = 'core' AND namespace = ? AND option_key = ?",
                )
                .bind(&r.new_namespace)
                .bind(&r.new_key)
                .bind(r.schema_version)
                .bind(&r.old_namespace)
                .bind(&r.old_key)
                .execute(&mut *tx)
                .await?;
                moved += res.rows_affected();
            }
            tx.commit().await?;
        }
        DbPool::Mysql(mysql_pool) => {
            let mut tx = mysql_pool.begin().await?;
            for r in renames {
                let res = sqlx::query(
                    "UPDATE options SET namespace = ?, option_key = ?, schema_version = ? WHERE owner = 'core' AND namespace = ? AND option_key = ?",
                )
                .bind(&r.new_namespace)
                .bind(&r.new_key)
                .bind(r.schema_version)
                .bind(&r.old_namespace)
                .bind(&r.old_key)
                .execute(&mut *tx)
                .await?;
                moved += res.rows_affected();
            }
            tx.commit().await?;
        }
        DbPool::Postgres(pg_pool) => {
            let mut tx = pg_pool.begin().await?;
            for r in renames {
                let res = sqlx::query(
                    "UPDATE options SET namespace = $1, option_key = $2, schema_version = $3 WHERE owner = 'core' AND namespace = $4 AND option_key = $5",
                )
                .bind(&r.new_namespace)
                .bind(&r.new_key)
                .bind(r.schema_version)
                .bind(&r.old_namespace)
                .bind(&r.old_key)
                .execute(&mut *tx)
                .await?;
                moved += res.rows_affected();
            }
            tx.commit().await?;
        }
    }
    Ok(moved)
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
    if ns_spec.is_none() && registry.has_core_contract() {
        return Err(CfmsError::Config(format!(
            "Option namespace '{namespace}' is not part of core_config_contract; extension/custom option writes must be managed via the CFMS server or Python maintenance CLI"
        )));
    }

    if let Some(spec) = ns_spec {
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
    if let Some(spec) = ns_spec {
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

    let normalized_map = if let Some(spec) = ns_spec {
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
    use crate::core::contract::{CORE_CONFIG_CONTRACT_VERSION, DRAFT_2020_12_DIALECT};
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

    fn sample_contract() -> CoreConfigContract {
        CoreConfigContract {
            contract_version: CORE_CONFIG_CONTRACT_VERSION.to_string(),
            core_version: "0.14.0".to_string(),
            schema_dialect: DRAFT_2020_12_DIALECT.to_string(),
            toml: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            }),
            options: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "security.password": {
                        "type": "object",
                        "x-owner": "core",
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
                    },
                    "security.request_rate_control": {
                        "type": "object",
                        "x-owner": "core",
                        "additionalProperties": false,
                        "properties": {
                            "account_capacity": {
                                "type": "integer",
                                "minimum": 1,
                                "default": 100,
                                "x-schema-version": 1
                            },
                            "action_costs": {
                                "type": "object",
                                "additionalProperties": { "type": "integer", "minimum": 1 },
                                "propertyNames": { "minLength": 1 },
                                "x-normalize-keys": "trim",
                                "default": { "download": 5 },
                                "x-schema-version": 1
                            }
                        },
                        "x-invariants": [
                            {
                                "rule": "map_values_lte",
                                "map": "action_costs",
                                "uppers": ["account_capacity"],
                                "message": "action_costs exceed account_capacity"
                            }
                        ]
                    },
                    "server": {
                        "type": "object",
                        "x-owner": "core",
                        "additionalProperties": false,
                        "properties": {
                            "name": {
                                "type": "string",
                                "default": "CFMS Server",
                                "x-schema-version": 1,
                                "x-renamed-from": ["server/display_name"]
                            }
                        }
                    }
                }
            }),
        }
    }

    #[test]
    fn test_option_value_codec_roundtrip_and_strict_rejection() {
        let big_int: Value =
            serde_json::from_str("1208925819614629174706177").expect("parse big int");
        let (vtype, encoded) = encode_option_value(&big_int).expect("encode big int");
        assert_eq!(vtype, OptionValueType::Int);
        assert_eq!(encoded, "1208925819614629174706177");
        let decoded = decode_option_value(vtype.as_str(), &encoded).expect("decode big int");
        assert_eq!(decoded, big_int);

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
        let err = decode_option_value("int", "super-secret-token-123").expect_err("bad int");
        assert!(!err.to_string().contains("super-secret-token-123"));
        let err = decode_option_value("bool", "secret-bool").expect_err("bad bool");
        assert!(!err.to_string().contains("secret-bool"));
    }

    #[tokio::test]
    async fn test_options_list_and_get_core_defaults_plus_stored_extension_rows() {
        let pool = setup_sqlite_pool().await;
        let registry =
            OptionsSchemaRegistry::from_contract(&sample_contract()).expect("load contract");

        // Pre-populate one stored extension row owned by `oidc_sso`
        let DbPool::Sqlite(ref sqlite) = pool else {
            unreachable!()
        };
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('identity.oidc', 'oidc_sso', 'issuer', 1, 1, 'str', 'https://idp.example.com', 100.0)",
        )
        .execute(sqlite)
        .await
        .expect("insert extension row");

        let all = list_options(&pool, &registry, None)
            .await
            .expect("list all options");
        // 6 core defaults + 1 stored extension row
        assert_eq!(all.len(), 7);
        assert!(all.iter().any(|r| {
            r.namespace == "identity.oidc"
                && r.owner == "oidc_sso"
                && r.option_key == "issuer"
                && r.value == json!("https://idp.example.com")
        }));

        let filtered_ext = list_options(&pool, &registry, Some("identity.oidc"))
            .await
            .expect("list extension namespace");
        assert_eq!(filtered_ext.len(), 1);
        assert_eq!(filtered_ext[0].owner, "oidc_sso");

        let ext_item = get_option(&pool, &registry, "identity.oidc", "issuer")
            .await
            .expect("get stored extension option");
        assert_eq!(ext_item.owner, "oidc_sso");

        let min_len = get_option(&pool, &registry, "security.password", "passwd_min_length")
            .await
            .expect("get passwd_min_length");
        assert_eq!(min_len.owner, "core");
        assert_eq!(min_len.schema_version, 1);
        assert_eq!(min_len.revision, 0);
        assert_eq!(min_len.value, json!(8));

        let renamed_spec = registry
            .get_namespace("server")
            .and_then(|s| s.properties.get("name"))
            .expect("server/name spec");
        assert_eq!(renamed_spec.renamed_from, vec!["server/display_name"]);
    }

    #[tokio::test]
    async fn test_options_set_reset_concurrency_audit_and_rejects_non_core_writes() {
        let pool = setup_sqlite_pool().await;
        let registry =
            OptionsSchemaRegistry::from_contract(&sample_contract()).expect("load contract");

        // 1. Set single core option (revision 0 -> 1)
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

        // 3. Writes/resets to non-core/extension namespaces are rejected when contract is active
        let mut ext_updates = BTreeMap::new();
        ext_updates.insert(
            "issuer".to_string(),
            OptionUpdateInput {
                value: json!("https://idp.example.com"),
                expected_revision: 0,
            },
        );
        let ext_err = write_options_batch(&pool, &registry, "identity.oidc", ext_updates)
            .await
            .expect_err("non-core namespace rejected on write");
        assert!(ext_err.to_string().contains("core_config_contract"));

        let reset_ext_err = reset_option(&pool, &registry, "identity.oidc", "issuer", 0)
            .await
            .expect_err("non-core namespace rejected on reset");
        assert!(reset_ext_err.to_string().contains("core_config_contract"));

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
        assert_eq!(audit_rows.len(), 2);
        for (action, result, data_str) in &audit_rows {
            assert_eq!(action, "update_options");
            assert_eq!(*result, 0);
            let data: Value = serde_json::from_str(data_str).expect("parse audit json");
            assert_eq!(data["source"], json!("maintenance_cli"));
            assert!(data.get("changed_keys").is_some());
            assert!(data.get("previous_revisions").is_some());
            assert!(data.get("revisions").is_some());
        }
    }

    #[tokio::test]
    async fn test_core_contract_validation_and_schemaless_fallback() {
        let pool = setup_sqlite_pool().await;
        let registry =
            OptionsSchemaRegistry::from_contract(&sample_contract()).expect("load contract");

        // 1. Strict type check: integer field rejects string `"12"`, float `12.0`, and bool
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

        // 2. Cross-field validation via `x-invariants` + `x-normalize-keys: "trim"`
        let mut rate_updates = BTreeMap::new();
        rate_updates.insert(
            "action_costs".to_string(),
            OptionUpdateInput {
                value: json!({ "  upload  ": 20 }),
                expected_revision: 0,
            },
        );
        let rate_written =
            write_options_batch(&pool, &registry, "security.request_rate_control", rate_updates)
                .await
                .expect("write normalized action_costs");
        assert_eq!(rate_written["action_costs"].value, json!({ "upload": 20 }));

        let mut bad_rate = BTreeMap::new();
        bad_rate.insert(
            "action_costs".to_string(),
            OptionUpdateInput {
                value: json!({ "upload": 250 }),
                expected_revision: 1,
            },
        );
        let rate_err =
            write_options_batch(&pool, &registry, "security.request_rate_control", bad_rate)
                .await
                .expect_err("map_values_lte invariant failure");
        assert!(
            rate_err
                .to_string()
                .contains("action_costs exceed account_capacity")
        );

        // 3. Pure schema-less workspace (OptionsSchemaRegistry::empty()) allows basic CRUD without any contract
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
