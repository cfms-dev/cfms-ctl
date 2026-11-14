//! Database-backed `options` CRUD with two-level optimistic concurrency (`options.revision`
//! and `system_states` namespace write-skew guard), canonical tagged scalar/JSON encoding,
//! declarative CFMS 0.14+ policy validation, and transactional `audit_entries` logging.

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

/// Resolved snapshot of a database-backed or default option.
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

/// Check whether a raw token string is a canonical base-10 integer (supports arbitrary precision).
#[must_use]
pub fn is_canonical_int_str(raw: &str) -> bool {
    if raw == "0" {
        return true;
    }
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    let mut chars = digits.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !('1'..='9').contains(&first) {
        return false;
    }
    chars.all(|c| c.is_ascii_digit())
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

fn format_canonical_float(f: f64) -> Result<String> {
    if !f.is_finite() {
        return Err(CfmsError::Config(
            "Option float value must be finite".to_string(),
        ));
    }
    if f == 0.0 {
        return Ok(if f.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        });
    }
    let abs = f.abs();
    if (1e-4..1e16).contains(&abs) {
        let mut s = f.to_string();
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        Ok(s)
    } else {
        // Match Python's repr(float) exponent formatting (e.g. 1e+16, 1e-05)
        let sci = format!("{f:e}");
        let Some((mantissa, exp_str)) = sci.split_once('e') else {
            return Ok(sci);
        };
        let exp: i32 = exp_str.parse().unwrap_or(0);
        if exp >= 0 {
            Ok(format!("{mantissa}e+{exp:02}"))
        } else {
            let abs_exp = exp.unsigned_abs();
            Ok(format!("{mantissa}e-{abs_exp:02}"))
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
                let parsed = raw.parse::<f64>().map_err(|_| {
                    CfmsError::Config("Invalid float option value".to_string())
                })?;
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

/// Type specification for a single registered CFMS option.
#[derive(Debug, Clone)]
pub enum OptionTypeSpec {
    Str,
    NonEmptyStr,
    TrimmedLockdownReason,
    Bool,
    PositiveInt,
    NonNegativeInt,
    UnitRatio,
    Literal(&'static [&'static str]),
    RegexStringArray,
    NonEmptyStringArray,
    ActionCostsMap,
}

impl OptionTypeSpec {
    /// Validate and normalize a single option value in strict mode, never leaking raw input values.
    pub fn validate(&self, option_key: &str, value: &Value) -> Result<Value> {
        let invalid = |msg: &str| {
            CfmsError::Config(format!("Invalid option '{option_key}': {msg}"))
        };
        match self {
            Self::Str => match value {
                Value::String(s) => Ok(Value::String(s.clone())),
                _ => Err(invalid("Input should be a valid string")),
            },
            Self::NonEmptyStr => match value {
                Value::String(s) if !s.is_empty() => Ok(Value::String(s.clone())),
                Value::String(_) => Err(invalid("String should have at least 1 character")),
                _ => Err(invalid("Input should be a valid string")),
            },
            Self::TrimmedLockdownReason => match value {
                Value::String(s) => {
                    let char_len = s.chars().count();
                    if !(1..=1024).contains(&char_len) {
                        return Err(invalid(
                            "String should have between 1 and 1024 characters",
                        ));
                    }
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        return Err(invalid("Lockdown reason must not be blank"));
                    }
                    Ok(Value::String(trimmed.to_string()))
                }
                _ => Err(invalid("Input should be a valid string")),
            },
            Self::Bool => match value {
                Value::Bool(b) => Ok(Value::Bool(*b)),
                _ => Err(invalid("Input should be a valid boolean")),
            },
            Self::PositiveInt => match value {
                Value::Number(n) => {
                    let raw = n.to_string();
                    if !is_canonical_int_str(&raw) || raw == "0" || raw.starts_with('-') {
                        return Err(invalid("Input should be a positive integer (> 0)"));
                    }
                    Ok(Value::Number(n.clone()))
                }
                _ => Err(invalid("Input should be a valid integer")),
            },
            Self::NonNegativeInt => match value {
                Value::Number(n) => {
                    let raw = n.to_string();
                    if !is_canonical_int_str(&raw) || raw.starts_with('-') {
                        return Err(invalid("Input should be a non-negative integer (>= 0)"));
                    }
                    Ok(Value::Number(n.clone()))
                }
                _ => Err(invalid("Input should be a valid integer")),
            },
            Self::UnitRatio => match value {
                Value::Number(n) => {
                    let parsed = n
                        .to_string()
                        .parse::<f64>()
                        .map_err(|_| invalid("Input should be a valid number"))?;
                    if !parsed.is_finite() || parsed <= 0.0 || parsed > 1.0 {
                        return Err(invalid("Input should be in (0.0, 1.0]"));
                    }
                    let canonical = format_canonical_float(parsed)
                        .map_err(|_| invalid("Input should be a valid number"))?;
                    serde_json::from_str(&canonical)
                        .map_err(|_| invalid("Input should be a valid number"))
                }
                _ => Err(invalid("Input should be a valid number")),
            },
            Self::Literal(allowed) => match value {
                Value::String(s) if allowed.contains(&s.as_str()) => {
                    Ok(Value::String(s.clone()))
                }
                Value::String(_) => Err(invalid(&format!(
                    "Input should be one of: {}",
                    allowed.join(", ")
                ))),
                _ => Err(invalid("Input should be a valid string")),
            },
            Self::RegexStringArray => match value {
                Value::Array(items) => {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let Some(s) = item.as_str() else {
                            return Err(invalid("Array elements must be strings"));
                        };
                        if !is_valid_password_regex(s) {
                            return Err(invalid("Invalid password rule regular expression"));
                        }
                        out.push(Value::String(s.to_string()));
                    }
                    Ok(Value::Array(out))
                }
                _ => Err(invalid("Input should be a valid array of strings")),
            },
            Self::NonEmptyStringArray => match value {
                Value::Array(items) => {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let Some(s) = item.as_str() else {
                            return Err(invalid("Array elements must be strings"));
                        };
                        if s.is_empty() {
                            return Err(invalid("String should have at least 1 character"));
                        }
                        out.push(Value::String(s.to_string()));
                    }
                    Ok(Value::Array(out))
                }
                _ => Err(invalid("Input should be a valid array of non-empty strings")),
            },
            Self::ActionCostsMap => match value {
                Value::Object(map) => {
                    let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
                    for (k, v) in map {
                        let trimmed = k.trim();
                        if trimmed.is_empty() {
                            return Err(invalid(
                                "action_costs keys must be non-empty strings",
                            ));
                        }
                        let validated_cost = Self::PositiveInt.validate(option_key, v)?;
                        sorted.insert(trimmed.to_string(), validated_cost);
                    }
                    let mut out = Map::new();
                    for (k, v) in sorted {
                        out.insert(k, v);
                    }
                    Ok(Value::Object(out))
                }
                _ => Err(invalid("Input should be a JSON object mapping actions to positive integer costs")),
            },
        }
    }
}

fn is_valid_password_regex(pattern: &str) -> bool {
    if Regex::new(pattern).is_ok() {
        return true;
    }
    // Tolerate Python lookarounds (e.g. (?=...\d)) by checking balanced parentheses and escapes
    if (pattern.contains("(?=") || pattern.contains("(?!")) && has_balanced_regex_delimiters(pattern)
    {
        return true;
    }
    false
}

fn has_balanced_regex_delimiters(pattern: &str) -> bool {
    let mut depth = 0_i32;
    let mut in_char_class = false;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_char_class => in_char_class = true,
            ']' if in_char_class => in_char_class = false,
            '(' if !in_char_class => depth += 1,
            ')' if !in_char_class => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    !escaped && !in_char_class && depth == 0
}

/// Declarative definition for a single option inside a namespace.
#[derive(Debug, Clone)]
pub struct OptionDefinitionSpec {
    pub option_key: &'static str,
    pub schema_version: i32,
    pub type_spec: OptionTypeSpec,
    pub default_value: Value,
}

/// Declarative definition for a namespace (core or bundled extension).
#[derive(Debug, Clone)]
pub struct NamespaceSpec {
    pub namespace: &'static str,
    pub owner: &'static str,
    pub is_core: bool,
    pub options: Vec<OptionDefinitionSpec>,
}

#[allow(clippy::too_many_lines)]
fn build_builtin_registry() -> BTreeMap<&'static str, NamespaceSpec> {
    let mut reg = BTreeMap::new();

    reg.insert(
        "server",
        NamespaceSpec {
            namespace: "server",
            owner: "core",
            is_core: true,
            options: vec![OptionDefinitionSpec {
                option_key: "name",
                schema_version: 1,
                type_spec: OptionTypeSpec::Str,
                default_value: json!("CFMS WebSocket Server"),
            }],
        },
    );

    reg.insert(
        "access",
        NamespaceSpec {
            namespace: "access",
            owner: "core",
            is_core: true,
            options: vec![OptionDefinitionSpec {
                option_key: "enable_access_recursive_check",
                schema_version: 1,
                type_spec: OptionTypeSpec::Bool,
                default_value: json!(true),
            }],
        },
    );

    reg.insert(
        "security.password",
        NamespaceSpec {
            namespace: "security.password",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "passwd_min_length",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(8),
                },
                OptionDefinitionSpec {
                    option_key: "passwd_max_length",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(32),
                },
                OptionDefinitionSpec {
                    option_key: "passwd_rules",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::RegexStringArray,
                    default_value: json!(["[A-Z]", "[a-z]", "[0-9]", "[!@#$%^&*()]"]),
                },
                OptionDefinitionSpec {
                    option_key: "passwd_min_passed_count",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::NonNegativeInt,
                    default_value: json!(2),
                },
                OptionDefinitionSpec {
                    option_key: "enable_passwd_force_expiration",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::Bool,
                    default_value: json!(true),
                },
                OptionDefinitionSpec {
                    option_key: "passwd_expire_after_days",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(365),
                },
            ],
        },
    );

    reg.insert(
        "security.auth_throttle",
        NamespaceSpec {
            namespace: "security.auth_throttle",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "enabled",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::Bool,
                    default_value: json!(true),
                },
                OptionDefinitionSpec {
                    option_key: "account_failure_threshold",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(5),
                },
                OptionDefinitionSpec {
                    option_key: "account_base_delay_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(30),
                },
                OptionDefinitionSpec {
                    option_key: "account_max_delay_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3600),
                },
                OptionDefinitionSpec {
                    option_key: "account_reset_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(86400),
                },
                OptionDefinitionSpec {
                    option_key: "account_ip_failure_threshold",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(5),
                },
                OptionDefinitionSpec {
                    option_key: "account_ip_window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(900),
                },
                OptionDefinitionSpec {
                    option_key: "account_ip_block_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(900),
                },
                OptionDefinitionSpec {
                    option_key: "ip_failure_threshold",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "ip_window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "ip_block_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(900),
                },
                OptionDefinitionSpec {
                    option_key: "record_retention_days",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(7),
                },
            ],
        },
    );

    reg.insert(
        "maintenance.audit_retention",
        NamespaceSpec {
            namespace: "maintenance.audit_retention",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "retention_days",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(365),
                },
                OptionDefinitionSpec {
                    option_key: "batch_size",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(500),
                },
            ],
        },
    );

    reg.insert(
        "identity.permission_retention",
        NamespaceSpec {
            namespace: "identity.permission_retention",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "retention_days",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(30),
                },
                OptionDefinitionSpec {
                    option_key: "cleanup_interval_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3600),
                },
                OptionDefinitionSpec {
                    option_key: "batch_size",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(500),
                },
            ],
        },
    );

    reg.insert(
        "security.request_rate_control",
        NamespaceSpec {
            namespace: "security.request_rate_control",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "mode",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::Literal(&["disabled", "observe", "enforce"]),
                    default_value: json!("observe"),
                },
                OptionDefinitionSpec {
                    option_key: "connection_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(20),
                },
                OptionDefinitionSpec {
                    option_key: "connection_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "connection_refill_period_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "request_refill_period_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "account_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(120),
                },
                OptionDefinitionSpec {
                    option_key: "account_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(120),
                },
                OptionDefinitionSpec {
                    option_key: "ip_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "ip_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "state_retention_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "action_costs",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::ActionCostsMap,
                    default_value: json!({}),
                },
            ],
        },
    );

    reg.insert(
        "document.upload",
        NamespaceSpec {
            namespace: "document.upload",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "start_timeout_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3600),
                },
                OptionDefinitionSpec {
                    option_key: "max_duration_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(86400),
                },
                OptionDefinitionSpec {
                    option_key: "idle_timeout_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(300),
                },
                OptionDefinitionSpec {
                    option_key: "cleanup_interval_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "max_pending_documents_per_creator",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(16),
                },
            ],
        },
    );

    reg.insert(
        "document.upload.creation_risk_control",
        NamespaceSpec {
            namespace: "document.upload.creation_risk_control",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "mode",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::Literal(&["observe", "enforce"]),
                    default_value: json!("enforce"),
                },
                OptionDefinitionSpec {
                    option_key: "refill_period_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "account_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "account_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(300),
                },
                OptionDefinitionSpec {
                    option_key: "ip_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(200),
                },
                OptionDefinitionSpec {
                    option_key: "ip_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(1000),
                },
                OptionDefinitionSpec {
                    option_key: "new_account_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(604_800),
                },
                OptionDefinitionSpec {
                    option_key: "pending_elevated_ratio",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::UnitRatio,
                    default_value: serde_json::from_str("0.5").expect("0.5"),
                },
                OptionDefinitionSpec {
                    option_key: "pending_high_ratio",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::UnitRatio,
                    default_value: serde_json::from_str("0.75").expect("0.75"),
                },
                OptionDefinitionSpec {
                    option_key: "ip_account_window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "ip_accounts_elevated",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(4),
                },
                OptionDefinitionSpec {
                    option_key: "ip_accounts_high",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "denial_window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "denials_elevated",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(1),
                },
                OptionDefinitionSpec {
                    option_key: "denials_high",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3),
                },
                OptionDefinitionSpec {
                    option_key: "elevated_cost",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3),
                },
                OptionDefinitionSpec {
                    option_key: "high_cost",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "state_retention_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(86400),
                },
            ],
        },
    );

    reg.insert(
        "document.download.risk_control",
        NamespaceSpec {
            namespace: "document.download.risk_control",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "mode",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::Literal(&["observe", "enforce"]),
                    default_value: json!("observe"),
                },
                OptionDefinitionSpec {
                    option_key: "refill_period_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "issue_account_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "issue_account_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(300),
                },
                OptionDefinitionSpec {
                    option_key: "issue_ip_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(200),
                },
                OptionDefinitionSpec {
                    option_key: "issue_ip_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(1000),
                },
                OptionDefinitionSpec {
                    option_key: "transfer_account_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(60),
                },
                OptionDefinitionSpec {
                    option_key: "transfer_account_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(300),
                },
                OptionDefinitionSpec {
                    option_key: "transfer_ip_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(200),
                },
                OptionDefinitionSpec {
                    option_key: "transfer_ip_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(1000),
                },
                OptionDefinitionSpec {
                    option_key: "task_capacity",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(5),
                },
                OptionDefinitionSpec {
                    option_key: "task_refill_tokens",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "task_refill_period_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3600),
                },
                OptionDefinitionSpec {
                    option_key: "new_account_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(604_800),
                },
                OptionDefinitionSpec {
                    option_key: "ip_account_window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "ip_accounts_elevated",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(4),
                },
                OptionDefinitionSpec {
                    option_key: "ip_accounts_high",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "denial_window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "denials_elevated",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(1),
                },
                OptionDefinitionSpec {
                    option_key: "denials_high",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3),
                },
                OptionDefinitionSpec {
                    option_key: "elevated_cost",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(3),
                },
                OptionDefinitionSpec {
                    option_key: "high_cost",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "state_retention_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(86400),
                },
            ],
        },
    );

    reg.insert(
        "scheduling",
        NamespaceSpec {
            namespace: "scheduling",
            owner: "core",
            is_core: true,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "misfire_grace_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(300),
                },
                OptionDefinitionSpec {
                    option_key: "history_retention_days",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(90),
                },
            ],
        },
    );

    reg.insert(
        "security.brute_force_lockdown",
        NamespaceSpec {
            namespace: "security.brute_force_lockdown",
            owner: "brute_force_lockdown",
            is_core: false,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "window_seconds",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(600),
                },
                OptionDefinitionSpec {
                    option_key: "failure_threshold",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(50),
                },
                OptionDefinitionSpec {
                    option_key: "distinct_account_threshold",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "distinct_ip_threshold",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::PositiveInt,
                    default_value: json!(10),
                },
                OptionDefinitionSpec {
                    option_key: "reason",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::TrimmedLockdownReason,
                    default_value: json!(
                        "Automatic security lockdown: suspected credential-guessing attack detected."
                    ),
                },
            ],
        },
    );

    reg.insert(
        "identity.oidc",
        NamespaceSpec {
            namespace: "identity.oidc",
            owner: "oidc_sso",
            is_core: false,
            options: vec![
                OptionDefinitionSpec {
                    option_key: "username_claim",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::NonEmptyStr,
                    default_value: json!("preferred_username"),
                },
                OptionDefinitionSpec {
                    option_key: "auto_provision",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::Bool,
                    default_value: json!(false),
                },
                OptionDefinitionSpec {
                    option_key: "default_groups",
                    schema_version: 1,
                    type_spec: OptionTypeSpec::NonEmptyStringArray,
                    default_value: json!(["user"]),
                },
            ],
        },
    );

    reg
}

static BUILTIN_REGISTRY: LazyLock<BTreeMap<&'static str, NamespaceSpec>> =
    LazyLock::new(build_builtin_registry);

/// Retrieve a built-in namespace specification (core or bundled official extension).
#[must_use]
pub fn get_builtin_namespace(namespace: &str) -> Option<&'static NamespaceSpec> {
    BUILTIN_REGISTRY.get(namespace)
}

/// Compare two validated canonical integer `Value::Number` instances of arbitrary precision.
fn cmp_canonical_positive_int(a: &Value, b: &Value) -> std::cmp::Ordering {
    let sa = a.to_string();
    let sb = b.to_string();
    sa.len().cmp(&sb.len()).then_with(|| sa.cmp(&sb))
}

fn require_field_order(
    values: &BTreeMap<String, Value>,
    lower_key: &str,
    upper_key: &str,
    allow_equal: bool,
    message: &str,
) -> Result<()> {
    let lower = &values[lower_key];
    let upper = &values[upper_key];
    let ord = cmp_canonical_positive_int(lower, upper);
    let valid = if allow_equal {
        ord != std::cmp::Ordering::Greater
    } else {
        ord == std::cmp::Ordering::Less
    };
    if !valid {
        return Err(CfmsError::Config(message.to_string()));
    }
    Ok(())
}

fn require_minimum_capacity(
    values: &BTreeMap<String, Value>,
    capacity_fields: &[&str],
    minimum_field: &str,
    message: &str,
) -> Result<()> {
    let min_val = &values[minimum_field];
    for cap_field in capacity_fields {
        if cmp_canonical_positive_int(&values[*cap_field], min_val) == std::cmp::Ordering::Less {
            return Err(CfmsError::Config(message.to_string()));
        }
    }
    Ok(())
}

fn require_window_coverage(
    values: &BTreeMap<String, Value>,
    retention_field: &str,
    window_fields: &[&str],
    message: &str,
) -> Result<()> {
    let retention = &values[retention_field];
    for win_field in window_fields {
        if cmp_canonical_positive_int(retention, &values[*win_field]) == std::cmp::Ordering::Less {
            return Err(CfmsError::Config(message.to_string()));
        }
    }
    Ok(())
}

/// Validate all individual fields and aggregate cross-field rules for a built-in namespace.
pub fn validate_builtin_namespace_values(
    spec: &NamespaceSpec,
    candidate_values: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let def_map: BTreeMap<&str, &OptionDefinitionSpec> = spec
        .options
        .iter()
        .map(|d| (d.option_key, d))
        .collect();

    for key in candidate_values.keys() {
        if !def_map.contains_key(key.as_str()) {
            return Err(CfmsError::Config(format!(
                "No option definition for {}/{key}",
                spec.namespace
            )));
        }
    }

    let mut normalized = BTreeMap::new();
    for def in &spec.options {
        let raw_val = candidate_values
            .get(def.option_key)
            .unwrap_or(&def.default_value);
        let norm_val = def.type_spec.validate(def.option_key, raw_val)?;
        normalized.insert(def.option_key.to_string(), norm_val);
    }

    match spec.namespace {
        "security.password" => {
            require_field_order(
                &normalized,
                "passwd_min_length",
                "passwd_max_length",
                true,
                "Invalid options for security.password: Minimum password length exceeds maximum",
            )?;
        }
        "security.auth_throttle" => {
            require_field_order(
                &normalized,
                "account_base_delay_seconds",
                "account_max_delay_seconds",
                true,
                "security.auth_throttle.account_base_delay_seconds must not exceed security.auth_throttle.account_max_delay_seconds",
            )?;
        }
        "security.request_rate_control" => {
            let acc_cap = &normalized["account_capacity"];
            let ip_cap = &normalized["ip_capacity"];
            if let Some(costs_obj) = normalized["action_costs"].as_object() {
                for cost in costs_obj.values() {
                    if cmp_canonical_positive_int(cost, acc_cap) == std::cmp::Ordering::Greater
                        || cmp_canonical_positive_int(cost, ip_cap) == std::cmp::Ordering::Greater
                    {
                        return Err(CfmsError::Config(
                            "security.request_rate_control action costs must not exceed account_capacity or ip_capacity"
                                .to_string(),
                        ));
                    }
                }
            }
            require_window_coverage(
                &normalized,
                "state_retention_seconds",
                &[
                    "connection_refill_period_seconds",
                    "request_refill_period_seconds",
                ],
                "security.request_rate_control.state_retention_seconds must cover every refill period",
            )?;
        }
        "document.upload" => {
            require_field_order(
                &normalized,
                "idle_timeout_seconds",
                "max_duration_seconds",
                true,
                "document.upload.idle_timeout_seconds must not exceed document.upload.max_duration_seconds",
            )?;
            require_field_order(
                &normalized,
                "start_timeout_seconds",
                "max_duration_seconds",
                false,
                "document.upload.start_timeout_seconds must be less than document.upload.max_duration_seconds",
            )?;
        }
        "document.upload.creation_risk_control" => {
            let elevated_ratio = normalized["pending_elevated_ratio"]
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.5);
            let high_ratio = normalized["pending_high_ratio"]
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.75);
            if elevated_ratio >= high_ratio {
                return Err(CfmsError::Config(
                    "document.upload.creation_risk_control.pending_elevated_ratio must be less than pending_high_ratio"
                        .to_string(),
                ));
            }
            require_field_order(
                &normalized,
                "ip_accounts_elevated",
                "ip_accounts_high",
                false,
                "document.upload.creation_risk_control.ip_accounts_elevated must be less than ip_accounts_high",
            )?;
            require_field_order(
                &normalized,
                "denials_elevated",
                "denials_high",
                false,
                "document.upload.creation_risk_control.denials_elevated must be less than denials_high",
            )?;
            require_minimum_capacity(
                &normalized,
                &["account_capacity", "ip_capacity"],
                "high_cost",
                "document.upload.creation_risk_control bucket capacities must be at least high_cost",
            )?;
            require_window_coverage(
                &normalized,
                "state_retention_seconds",
                &[
                    "refill_period_seconds",
                    "ip_account_window_seconds",
                    "denial_window_seconds",
                ],
                "document.upload.creation_risk_control.state_retention_seconds must cover every risk-control window",
            )?;
        }
        "document.download.risk_control" => {
            require_field_order(
                &normalized,
                "ip_accounts_elevated",
                "ip_accounts_high",
                false,
                "document.download.risk_control.ip_accounts_elevated must be less than ip_accounts_high",
            )?;
            require_field_order(
                &normalized,
                "denials_elevated",
                "denials_high",
                false,
                "document.download.risk_control.denials_elevated must be less than denials_high",
            )?;
            require_minimum_capacity(
                &normalized,
                &[
                    "issue_account_capacity",
                    "issue_ip_capacity",
                    "transfer_account_capacity",
                    "transfer_ip_capacity",
                ],
                "high_cost",
                "document.download.risk_control account and IP bucket capacities must be at least high_cost",
            )?;
            require_window_coverage(
                &normalized,
                "state_retention_seconds",
                &[
                    "refill_period_seconds",
                    "task_refill_period_seconds",
                    "ip_account_window_seconds",
                    "denial_window_seconds",
                ],
                "document.download.risk_control.state_retention_seconds must cover every risk-control window",
            )?;
        }
        "security.brute_force_lockdown" => {
            require_field_order(
                &normalized,
                "distinct_account_threshold",
                "failure_threshold",
                true,
                "Invalid options for security.brute_force_lockdown: distinct_account_threshold must not exceed failure_threshold",
            )?;
            require_field_order(
                &normalized,
                "distinct_ip_threshold",
                "failure_threshold",
                true,
                "Invalid options for security.brute_force_lockdown: distinct_ip_threshold must not exceed failure_threshold",
            )?;
        }
        _ => {}
    }

    Ok(normalized)
}

#[derive(Debug, Deserialize)]
struct ManifestOptionNamespaces {
    #[serde(default)]
    option_namespaces: Vec<String>,
    #[serde(default)]
    extension: ManifestExtId,
}

#[derive(Debug, Default, Deserialize)]
struct ManifestExtId {
    #[serde(default)]
    identifier: String,
}

/// Resolve the declaring extension owner for a namespace from `src/include/extensions/*/manifest.toml`.
pub fn discover_extension_namespace_owner(
    extensions_root: &Path,
    namespace: &str,
) -> Result<Option<String>> {
    if !extensions_root.is_dir() {
        return Ok(None);
    }
    let mut owners = Vec::new();
    for entry in std::fs::read_dir(extensions_root)? {
        let entry = entry?;
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let manifest_path = dir.join("manifest.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&manifest_path)?;
        let parsed: ManifestOptionNamespaces = toml::from_str(&raw).map_err(|e| {
            CfmsError::Extension(format!(
                "Invalid extension manifest '{}': {e}",
                manifest_path.display()
            ))
        })?;
        if parsed.option_namespaces.iter().any(|ns| ns == namespace) {
            let id = if parsed.extension.identifier.is_empty() {
                entry.file_name().to_string_lossy().to_string()
            } else {
                parsed.extension.identifier
            };
            validate_option_owner(&id)?;
            owners.push(id);
        }
    }
    owners.sort();
    owners.dedup();
    if owners.len() > 1 {
        return Err(CfmsError::Config(format!(
            "Multiple extensions declare option namespace '{namespace}': {}",
            owners.join(", ")
        )));
    }
    Ok(owners.into_iter().next())
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

/// List stored database options (including uninstalled extension rows) merged with missing core defaults.
pub async fn list_options(
    pool: &DbPool,
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

    for (&ns_name, spec) in BUILTIN_REGISTRY.iter() {
        if !spec.is_core {
            continue;
        }
        if namespace.is_some_and(|filter| filter != ns_name) {
            continue;
        }
        for def in &spec.options {
            if !stored_keys.contains(&(ns_name.to_string(), def.option_key.to_string())) {
                records.push(ResolvedOptionRecord {
                    namespace: ns_name.to_string(),
                    owner: spec.owner.to_string(),
                    option_key: def.option_key.to_string(),
                    schema_version: def.schema_version,
                    revision: 0,
                    value: def.default_value.clone(),
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

/// Read a single option by `(namespace, option_key)` without executing extension code.
pub async fn get_option(
    pool: &DbPool,
    namespace: &str,
    option_key: &str,
) -> Result<ResolvedOptionRecord> {
    validate_option_namespace(namespace)?;
    validate_option_key(option_key)?;

    if let Some(row) = fetch_single_option_row(pool, namespace, option_key).await? {
        return row.into_resolved();
    }

    if let Some(spec) = get_builtin_namespace(namespace)
        && spec.is_core
    {
        if let Some(def) = spec.options.iter().find(|d| d.option_key == option_key) {
            return Ok(ResolvedOptionRecord {
                namespace: namespace.to_string(),
                owner: spec.owner.to_string(),
                option_key: option_key.to_string(),
                schema_version: def.schema_version,
                revision: 0,
                value: def.default_value.clone(),
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

/// Reset a single option in `namespace` to its code default using optimistic concurrency.
pub async fn reset_option(
    pool: &DbPool,
    extensions_root: &Path,
    namespace: &str,
    option_key: &str,
    expected_revision: u64,
) -> Result<ResolvedOptionRecord> {
    validate_option_namespace(namespace)?;
    validate_option_key(option_key)?;

    let Some(spec) = get_builtin_namespace(namespace) else {
        return Err(CfmsError::Config(format!(
            "No built-in default definition for {namespace}/{option_key}"
        )));
    };
    let Some(def) = spec.options.iter().find(|d| d.option_key == option_key) else {
        return Err(CfmsError::Config(format!(
            "No option definition for {namespace}/{option_key}"
        )));
    };

    let mut updates = BTreeMap::new();
    updates.insert(
        option_key.to_string(),
        OptionUpdateInput {
            value: def.default_value.clone(),
            expected_revision,
        },
    );

    let mut updated = write_options_batch(pool, extensions_root, namespace, updates).await?;
    updated.remove(option_key).ok_or_else(|| {
        CfmsError::Database(format!(
            "Failed to read back reset option {namespace}/{option_key}"
        ))
    })
}

/// Atomically validate and write one or more options in `namespace` with optimistic concurrency
/// (`options.revision` CAS + `system_states` namespace guard + `audit_entries` record).
pub async fn write_options_batch(
    pool: &DbPool,
    extensions_root: &Path,
    namespace: &str,
    updates: BTreeMap<String, OptionUpdateInput>,
) -> Result<BTreeMap<String, ResolvedOptionRecord>> {
    validate_option_namespace(namespace)?;
    if updates.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "Options update batch must contain at least one setting".to_string(),
        ));
    }
    for key in updates.keys() {
        validate_option_key(key)?;
    }

    let builtin_spec = get_builtin_namespace(namespace);
    let resolved_owner = if let Some(spec) = builtin_spec {
        if !spec.is_core
            && let Some(manifest_owner) =
                discover_extension_namespace_owner(extensions_root, namespace)?
            && manifest_owner != spec.owner
        {
            return Err(CfmsError::Config(format!(
                "Extension owner mismatch for '{namespace}': expected '{}', found '{manifest_owner}'",
                spec.owner
            )));
        }
        spec.owner.to_string()
    } else if let Some(ext_owner) =
        discover_extension_namespace_owner(extensions_root, namespace)?
    {
        ext_owner
    } else {
        return Err(CfmsError::Config(format!(
            "Cannot resolve option declarations for '{namespace}'"
        )));
    };

    if let Some(spec) = builtin_spec {
        for key in updates.keys() {
            if !spec.options.iter().any(|d| d.option_key == key) {
                return Err(CfmsError::Config(format!(
                    "No option definition for {namespace}/{key}"
                )));
            }
        }
    }

    match pool {
        DbPool::Sqlite(sqlite_pool) => {
            let mut tx = sqlite_pool.begin().await?;
            let result = execute_write_tx_sqlite(
                &mut tx,
                namespace,
                &resolved_owner,
                builtin_spec,
                &updates,
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
                &resolved_owner,
                builtin_spec,
                &updates,
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
                &resolved_owner,
                builtin_spec,
                &updates,
            )
            .await?;
            tx.commit().await?;
            Ok(result)
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
    resolved_owner: &str,
    builtin_spec: Option<&NamespaceSpec>,
    guard_revision: u64,
    stored_rows: Vec<RawOptionRow>,
    updates: &BTreeMap<String, OptionUpdateInput>,
) -> Result<PreparedNamespaceMutation> {
    let mut stored_map: BTreeMap<String, ResolvedOptionRecord> = BTreeMap::new();
    for raw in stored_rows {
        let resolved = raw.into_resolved()?;
        stored_map.insert(resolved.option_key.clone(), resolved);
    }

    let mut previous_resolved: BTreeMap<String, ResolvedOptionRecord> = BTreeMap::new();
    if let Some(spec) = builtin_spec {
        for def in &spec.options {
            if let Some(stored) = stored_map.get(def.option_key) {
                if stored.schema_version != def.schema_version {
                    return Err(CfmsError::Config(format!(
                        "Unsupported option schema for {namespace}/{}: {}; expected {}",
                        def.option_key, stored.schema_version, def.schema_version
                    )));
                }
                let validated_stored = def.type_spec.validate(def.option_key, &stored.value)?;
                previous_resolved.insert(
                    def.option_key.to_string(),
                    ResolvedOptionRecord {
                        value: validated_stored,
                        ..stored.clone()
                    },
                );
            } else {
                previous_resolved.insert(
                    def.option_key.to_string(),
                    ResolvedOptionRecord {
                        namespace: namespace.to_string(),
                        owner: spec.owner.to_string(),
                        option_key: def.option_key.to_string(),
                        schema_version: def.schema_version,
                        revision: 0,
                        value: def.default_value.clone(),
                        updated_at: None,
                    },
                );
            }
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
                    owner: resolved_owner.to_string(),
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

    let normalized_map = if let Some(spec) = builtin_spec {
        validate_builtin_namespace_values(spec, &merged_values)?
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
        let prev = &previous_resolved[key];
        let norm_val = normalized_map[key].clone();
        let (value_type, option_value) = encode_option_value(&norm_val)?;
        let prev_encoded = encode_option_value(&prev.value)?;
        if prev.revision == 0 || prev_encoded != (value_type, option_value.clone()) {
            // Note: in CFMS `changed_keys` compares `encode_option_value(previous[key].value) != encode_option_value(normalized[key])`
            if prev_encoded != (value_type, option_value.clone()) {
                changed_keys.push(key.clone());
            }
        }
        let new_rev = update.expected_revision.checked_add(1).ok_or_else(|| {
            CfmsError::Config(format!("Revision overflow for {namespace}/{key}"))
        })?;
        previous_revisions.insert(key.clone(), update.expected_revision);
        new_revisions.insert(key.clone(), new_rev);

        rows_to_write.push(PreparedRowWrite {
            option_key: key.clone(),
            owner: resolved_owner.to_string(),
            schema_version: prev.schema_version,
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
    resolved_owner: &str,
    builtin_spec: Option<&NamespaceSpec>,
    updates: &BTreeMap<String, OptionUpdateInput>,
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

    let plan = prepare_namespace_mutation(
        namespace,
        resolved_owner,
        builtin_spec,
        guard_revision,
        existing_rows,
        updates,
    )?;

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
        "source": "maintenance_cli",
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
    resolved_owner: &str,
    builtin_spec: Option<&NamespaceSpec>,
    updates: &BTreeMap<String, OptionUpdateInput>,
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

    let plan = prepare_namespace_mutation(
        namespace,
        resolved_owner,
        builtin_spec,
        guard_revision,
        existing_rows,
        updates,
    )?;

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
        "source": "maintenance_cli",
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
    resolved_owner: &str,
    builtin_spec: Option<&NamespaceSpec>,
    updates: &BTreeMap<String, OptionUpdateInput>,
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

    let plan = prepare_namespace_mutation(
        namespace,
        resolved_owner,
        builtin_spec,
        guard_revision,
        existing_rows,
        updates,
    )?;

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
        "source": "maintenance_cli",
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
    async fn test_options_list_and_get_defaults_without_db_writes() {
        let pool = setup_sqlite_pool().await;

        let all = list_options(&pool, None)
            .await
            .expect("list all options");
        assert!(!all.is_empty());
        assert!(all.iter().all(|r| r.revision == 0 && r.updated_at.is_none()));

        let min_len = get_option(&pool, "security.password", "passwd_min_length")
            .await
            .expect("get passwd_min_length");
        assert_eq!(min_len.owner, "core");
        assert_eq!(min_len.schema_version, 1);
        assert_eq!(min_len.revision, 0);
        assert_eq!(min_len.value, json!(8));

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

        // 1. Set single option (revision 0 -> 1)
        let mut updates = BTreeMap::new();
        updates.insert(
            "passwd_min_length".to_string(),
            OptionUpdateInput {
                value: json!(12),
                expected_revision: 0,
            },
        );
        let written = write_options_batch(&pool, dir.path(), "security.password", updates.clone())
            .await
            .expect("write passwd_min_length");
        let rec = written
            .get("passwd_min_length")
            .expect("passwd_min_length record");
        assert_eq!(rec.revision, 1);
        assert_eq!(rec.value, json!(12));
        assert!(rec.updated_at.is_some());

        // 2. Stale expected_revision = 0 must fail with OptionConflict
        let conflict_err = write_options_batch(&pool, dir.path(), "security.password", updates)
            .await
            .expect_err("must fail with conflict");
        assert!(matches!(conflict_err, CfmsError::OptionConflict(_)));

        // 3. Batch update in `security.brute_force_lockdown`
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
            dir.path(),
            "security.brute_force_lockdown",
            bf_updates,
        )
        .await
        .expect("write brute_force_lockdown");
        // Verify trimmed lockdown reason normalization
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
        let reset_rec =
            reset_option(&pool, dir.path(), "security.password", "passwd_min_length", 1)
                .await
                .expect("reset passwd_min_length");
        assert_eq!(reset_rec.revision, 2);
        assert_eq!(reset_rec.value, json!(8));
        assert!(reset_rec.updated_at.is_some());

        let state_rev_after_reset: i64 = sqlx::query_scalar(
            "SELECT revision FROM system_states WHERE owner = 'core' AND state_key = 'options_revision.security.password'",
        )
        .fetch_one(sqlite)
        .await
        .expect("fetch system_states revision after reset");
        assert_eq!(state_rev_after_reset, 2);

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
    async fn test_options_declarative_policy_validation_and_extension_fallback() {
        let pool = setup_sqlite_pool().await;
        let dir = tempfile::tempdir().expect("tempdir");

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
                write_options_batch(&pool, dir.path(), "security.password", updates)
                    .await
                    .is_err()
            );
        }

        // 2. Cross-field validation: `distinct_account_threshold <= failure_threshold`
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
            dir.path(),
            "security.brute_force_lockdown",
            bad_bf,
        )
        .await
        .expect_err("cross-field failure");
        assert!(
            err.to_string()
                .contains("distinct_account_threshold must not exceed failure_threshold")
        );

        // 3. OIDC validation: default_groups requires non-empty strings
        let mut bad_oidc = BTreeMap::new();
        bad_oidc.insert(
            "default_groups".to_string(),
            OptionUpdateInput {
                value: json!([""]),
                expected_revision: 0,
            },
        );
        let oidc_err = write_options_batch(&pool, dir.path(), "identity.oidc", bad_oidc)
            .await
            .expect_err("oidc default_groups rejects empty string");
        assert!(oidc_err.to_string().contains("default_groups"));

        // 4. Extension manifest fallback discovery (`acme_sso/manifest.toml`)
        let ext_dir = dir.path().join("acme_sso");
        std::fs::create_dir_all(&ext_dir).expect("create extension dir");
        std::fs::write(
            ext_dir.join("manifest.toml"),
            r#"
option_namespaces = ["identity.acme_sso"]

[extension]
identifier = "acme_sso"
"#,
        )
        .expect("write manifest.toml");

        let mut ext_updates = BTreeMap::new();
        ext_updates.insert(
            "tenant_id".to_string(),
            OptionUpdateInput {
                value: json!("acme-prod"),
                expected_revision: 0,
            },
        );
        let ext_written =
            write_options_batch(&pool, dir.path(), "identity.acme_sso", ext_updates)
                .await
                .expect("write manifest-discovered extension option");
        assert_eq!(ext_written["tenant_id"].owner, "acme_sso");
        assert_eq!(ext_written["tenant_id"].revision, 1);
    }
}
