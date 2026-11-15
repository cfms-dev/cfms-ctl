//! Generic JSON Schema (Draft 2020-12) validation, declarative normalization (`x-normalize`),
//! and cross-field invariant evaluation (`x-invariants`) for `config.toml` and database `options`.
//!
//! Designed so CFMS server releases and extensions can ship standard JSON Schema files
//! without hardcoding business configuration definitions into the `cfms-ctl` binary.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use crate::core::error::{CfmsError, Result};

const MAX_SCHEMA_BYTES: u64 = 16 * 1024 * 1024;

/// Severity level for a declarative `x-invariants` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvariantSeverity {
    #[default]
    Error,
    Warning,
}

/// A single dotted field path or a list of dotted field paths whose numeric values are summed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathOrSum {
    Single(String),
    Sum(Vec<String>),
}

const fn default_true() -> bool {
    true
}

/// Declarative cross-field invariant rule embedded under `"x-invariants"` in a JSON Schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum InvariantRule {
    /// Require `lower <= upper` (when `allow_equal = true`) or `lower < upper` (`allow_equal = false`).
    Order {
        lower: PathOrSum,
        upper: PathOrSum,
        #[serde(default = "default_true")]
        allow_equal: bool,
        #[serde(default)]
        severity: InvariantSeverity,
        message: String,
    },
    /// Require every numeric field in `uppers` to be `>=` every numeric field in `lowers`.
    AllGte {
        uppers: Vec<String>,
        lowers: Vec<String>,
        #[serde(default)]
        severity: InvariantSeverity,
        message: String,
    },
    /// Require every numeric entry value inside the object at `map` to be `<=` every field in `uppers`.
    MapValuesLte {
        map: String,
        uppers: Vec<String>,
        #[serde(default)]
        severity: InvariantSeverity,
        message: String,
    },
    /// Require the value at `path` to be present and non-empty (non-blank string, non-empty array/object).
    NonEmpty {
        path: String,
        #[serde(default)]
        severity: InvariantSeverity,
        message: String,
    },
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

/// Format a finite `f64` into CFMS's canonical float representation.
pub fn format_canonical_float(f: f64) -> Result<String> {
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

/// Compare two JSON numeric values, preserving exact ordering for arbitrary-precision canonical integers.
pub fn cmp_numeric_values(a: &Value, b: &Value) -> Option<Ordering> {
    let (Value::Number(na), Value::Number(nb)) = (a, b) else {
        return None;
    };
    let sa = na.to_string();
    let sb = nb.to_string();
    if is_canonical_int_str(&sa) && is_canonical_int_str(&sb) {
        let a_neg = sa.starts_with('-');
        let b_neg = sb.starts_with('-');
        return Some(match (a_neg, b_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => sa.len().cmp(&sb.len()).then_with(|| sa.cmp(&sb)),
            (true, true) => {
                let da = &sa[1..];
                let db = &sb[1..];
                db.len().cmp(&da.len()).then_with(|| db.cmp(da))
            }
        });
    }
    let fa = sa.parse::<f64>().ok()?;
    let fb = sb.parse::<f64>().ok()?;
    fa.partial_cmp(&fb)
}

/// Check whether a regular expression pattern is valid (including balanced Python lookarounds).
#[must_use]
pub fn is_valid_policy_regex(pattern: &str) -> bool {
    if Regex::new(pattern).is_ok() {
        return true;
    }
    if (pattern.contains("(?=") || pattern.contains("(?!"))
        && has_balanced_regex_delimiters(pattern)
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

/// Load and parse a JSON Schema file from disk with size bounds check.
pub fn load_json_schema_file(path: &Path) -> Result<Value> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to stat schema file '{}': {e}",
            path.display()
        ))
    })?;
    if metadata.len() > MAX_SCHEMA_BYTES {
        return Err(CfmsError::Config(format!(
            "Schema file '{}' exceeds the 16 MiB limit",
            path.display()
        )));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to read schema file '{}': {e}",
            path.display()
        ))
    })?;
    serde_json::from_str::<Value>(&raw).map_err(|e| {
        CfmsError::Config(format!(
            "Invalid JSON syntax in schema file '{}': {e}",
            path.display()
        ))
    })
}

/// Apply declarative normalizations (`x-normalize`, `x-normalize-keys`) and strict scalar/format
/// checks (`type = "integer"` token check, `x-format = "regex"`) defined in a property schema.
pub fn normalize_and_precheck_value(
    field_name: &str,
    prop_schema: &Value,
    raw_value: &Value,
) -> Result<Value> {
    let invalid = |msg: &str| CfmsError::Config(format!("Invalid option '{field_name}': {msg}"));
    let Some(schema_obj) = prop_schema.as_object() else {
        return Ok(raw_value.clone());
    };

    let mut value = raw_value.clone();

    // 1. `x-normalize`: "trim" on strings
    if has_extension_flag(schema_obj.get("x-normalize"), "trim")
        && let Value::String(s) = &value
    {
        value = Value::String(s.trim().to_string());
    }

    // 2. `x-normalize-keys`: "trim" on object maps
    if has_extension_flag(schema_obj.get("x-normalize-keys"), "trim")
        && let Value::Object(map) = &value
    {
        let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
        for (k, v) in map {
            let trimmed = k.trim();
            if trimmed.is_empty() {
                return Err(invalid("Object keys must be non-empty strings"));
            }
            let item_val = if let Some(add_schema) = schema_obj.get("additionalProperties")
                && add_schema.is_object()
            {
                normalize_and_precheck_value(field_name, add_schema, v)?
            } else {
                v.clone()
            };
            sorted.insert(trimmed.to_string(), item_val);
        }
        let mut out = Map::new();
        for (k, v) in sorted {
            out.insert(k, v);
        }
        value = Value::Object(out);
    }

    // 3. Strict integer / float token verification
    if let Some(expected_type) = schema_obj.get("type").and_then(Value::as_str) {
        match expected_type {
            "integer" => {
                let Value::Number(n) = &value else {
                    return Err(invalid("Input should be a valid integer"));
                };
                let raw = n.to_string();
                if !is_canonical_int_str(&raw) {
                    return Err(invalid("Input should be a valid integer"));
                }
            }
            "number" => {
                let Value::Number(n) = &value else {
                    return Err(invalid("Input should be a valid number"));
                };
                let parsed = n
                    .to_string()
                    .parse::<f64>()
                    .map_err(|_| invalid("Input should be a valid number"))?;
                let canonical = format_canonical_float(parsed)
                    .map_err(|_| invalid("Input should be a valid number"))?;
                value = serde_json::from_str(&canonical)
                    .map_err(|_| invalid("Input should be a valid number"))?;
            }
            "array" => {
                if let Value::Array(items) = &value
                    && let Some(item_schema) = schema_obj.get("items")
                {
                    let mut normalized_items = Vec::with_capacity(items.len());
                    for item in items {
                        normalized_items.push(normalize_and_precheck_value(
                            field_name,
                            item_schema,
                            item,
                        )?);
                    }
                    value = Value::Array(normalized_items);
                }
            }
            "object" => {
                if let Value::Object(map) = &value
                    && !has_extension_flag(schema_obj.get("x-normalize-keys"), "trim")
                {
                    if let Some(props) = schema_obj.get("properties").and_then(Value::as_object) {
                        let mut out = map.clone();
                        for (k, prop_s) in props {
                            if let Some(existing_v) = map.get(k) {
                                let child_path = format!("{field_name}.{k}");
                                out.insert(
                                    k.clone(),
                                    normalize_and_precheck_value(&child_path, prop_s, existing_v)?,
                                );
                            }
                        }
                        value = Value::Object(out);
                    } else if let Some(add_schema) = schema_obj.get("additionalProperties")
                        && add_schema.is_object()
                    {
                        let mut out = Map::new();
                        for (k, v) in map {
                            out.insert(
                                k.clone(),
                                normalize_and_precheck_value(field_name, add_schema, v)?,
                            );
                        }
                        value = Value::Object(out);
                    }
                }
            }
            _ => {}
        }
    }

    // 4. `x-format`: "regex"
    if schema_obj
        .get("x-format")
        .and_then(Value::as_str)
        .is_some_and(|f| f == "regex")
        && let Value::String(s) = &value
        && !is_valid_policy_regex(s)
    {
        return Err(invalid("Invalid regular expression pattern"));
    }

    Ok(value)
}

fn has_extension_flag(ext_val: Option<&Value>, flag: &str) -> bool {
    match ext_val {
        Some(Value::String(s)) => s == flag,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(flag)),
        _ => false,
    }
}

/// Validate a JSON instance against a standard JSON Schema without leaking raw instance values in errors.
pub fn validate_instance_against_schema(
    schema_json: &Value,
    instance: &Value,
    context_label: &str,
) -> Result<()> {
    let validator = jsonschema::validator_for(schema_json).map_err(|e| {
        CfmsError::Config(format!("Invalid JSON Schema for '{context_label}': {e}"))
    })?;

    let mut err_iter = validator.iter_errors(instance);
    if let Some(first_err) = err_iter.next() {
        let loc = first_err.instance_path().to_string();
        let field_display = if loc.is_empty() {
            context_label.to_string()
        } else {
            loc.trim_start_matches('/').replace('/', ".")
        };
        let schema_loc = first_err.schema_path().to_string();
        let reason = sanitize_schema_error_reason(&schema_loc);
        return Err(CfmsError::Config(format!(
            "Schema validation failed at '{field_display}': {reason}"
        )));
    }
    Ok(())
}

/// Describe the failed schema constraint solely from `schema_path` so raw user secrets are never echoed.
fn sanitize_schema_error_reason(schema_path: &str) -> String {
    let keyword = schema_path.rsplit('/').next().unwrap_or("constraint");
    match keyword {
        "type" => "Value does not match expected type".to_string(),
        "minimum" | "exclusiveMinimum" => "Number is below the minimum allowed value".to_string(),
        "maximum" | "exclusiveMaximum" => "Number exceeds the maximum allowed value".to_string(),
        "minLength" => "String is shorter than the minimum allowed length".to_string(),
        "maxLength" => "String exceeds the maximum allowed length".to_string(),
        "pattern" => "String does not match the required pattern".to_string(),
        "enum" | "const" => "Value is not one of the allowed choices".to_string(),
        "required" => "Required field is missing".to_string(),
        "additionalProperties" => "Unknown or extra field is not permitted".to_string(),
        "propertyNames" => "Object key name violates naming constraints".to_string(),
        "minItems" => "Array has fewer items than required".to_string(),
        "maxItems" => "Array has more items than permitted".to_string(),
        "uniqueItems" => "Array items must be unique".to_string(),
        other => format!("Violated schema constraint '{other}'"),
    }
}

/// Extract and evaluate `"x-invariants"` from a JSON Schema object against `instance`.
///
/// Returns non-blocking warnings (`severity == "warning"`), or fails with `CfmsError::Config`
/// on the first blocking invariant failure (`severity == "error"`).
pub fn evaluate_schema_invariants(schema_json: &Value, instance: &Value) -> Result<Vec<String>> {
    let Some(invariants_val) = schema_json.get("x-invariants") else {
        return Ok(Vec::new());
    };
    let rules: Vec<InvariantRule> =
        serde_json::from_value(invariants_val.clone()).map_err(|e| {
            CfmsError::Config(format!(
                "Invalid 'x-invariants' definition in JSON Schema: {e}"
            ))
        })?;
    evaluate_invariants(&rules, instance)
}

/// Evaluate a slice of declarative `InvariantRule` items against a JSON object tree.
pub fn evaluate_invariants(rules: &[InvariantRule], instance: &Value) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    for rule in rules {
        match rule {
            InvariantRule::Order {
                lower,
                upper,
                allow_equal,
                severity,
                message,
            } => {
                let Some(ord) = compare_path_or_sum(instance, lower, upper) else {
                    continue;
                };
                let ok = if *allow_equal {
                    ord != Ordering::Greater
                } else {
                    ord == Ordering::Less
                };
                if !ok {
                    handle_violation(*severity, message, &mut warnings)?;
                }
            }
            InvariantRule::AllGte {
                uppers,
                lowers,
                severity,
                message,
            } => {
                for up_path in uppers {
                    let Some(up_val) = resolve_dotted_value(instance, up_path) else {
                        continue;
                    };
                    for low_path in lowers {
                        let Some(low_val) = resolve_dotted_value(instance, low_path) else {
                            continue;
                        };
                        if cmp_numeric_values(up_val, low_val) == Some(Ordering::Less) {
                            handle_violation(*severity, message, &mut warnings)?;
                        }
                    }
                }
            }
            InvariantRule::MapValuesLte {
                map,
                uppers,
                severity,
                message,
            } => {
                let Some(Value::Object(map_obj)) = resolve_dotted_value(instance, map) else {
                    continue;
                };
                for entry_val in map_obj.values() {
                    for up_path in uppers {
                        let Some(up_val) = resolve_dotted_value(instance, up_path) else {
                            continue;
                        };
                        if cmp_numeric_values(entry_val, up_val) == Some(Ordering::Greater) {
                            handle_violation(*severity, message, &mut warnings)?;
                        }
                    }
                }
            }
            InvariantRule::NonEmpty {
                path,
                severity,
                message,
            } => {
                let is_non_empty = match resolve_dotted_value(instance, path) {
                    Some(Value::String(s)) => !s.trim().is_empty(),
                    Some(Value::Array(a)) => !a.is_empty(),
                    Some(Value::Object(o)) => !o.is_empty(),
                    Some(Value::Null) | None => false,
                    Some(_) => true,
                };
                if !is_non_empty {
                    handle_violation(*severity, message, &mut warnings)?;
                }
            }
        }
    }

    Ok(warnings)
}

fn handle_violation(
    severity: InvariantSeverity,
    message: &str,
    warnings: &mut Vec<String>,
) -> Result<()> {
    match severity {
        InvariantSeverity::Error => Err(CfmsError::Config(message.to_string())),
        InvariantSeverity::Warning => {
            warnings.push(message.to_string());
            Ok(())
        }
    }
}

fn compare_path_or_sum(
    instance: &Value,
    lower: &PathOrSum,
    upper: &PathOrSum,
) -> Option<Ordering> {
    if let (PathOrSum::Single(l_path), PathOrSum::Single(u_path)) = (lower, upper) {
        let l_val = resolve_dotted_value(instance, l_path)?;
        let u_val = resolve_dotted_value(instance, u_path)?;
        return cmp_numeric_values(l_val, u_val);
    }
    let l_sum = eval_numeric_sum(instance, lower)?;
    let u_sum = eval_numeric_sum(instance, upper)?;
    l_sum.partial_cmp(&u_sum)
}

fn eval_numeric_sum(instance: &Value, expr: &PathOrSum) -> Option<f64> {
    match expr {
        PathOrSum::Single(path) => {
            let v = resolve_dotted_value(instance, path)?;
            v.to_string().parse::<f64>().ok()
        }
        PathOrSum::Sum(paths) => {
            let mut total = 0.0_f64;
            for path in paths {
                let v = resolve_dotted_value(instance, path)?;
                total += v.to_string().parse::<f64>().ok()?;
            }
            Some(total)
        }
    }
}

/// Resolve a value inside a nested JSON object using a dotted path (or exact key if present at top level).
#[must_use]
pub fn resolve_dotted_value<'a>(root: &'a Value, dotted_path: &str) -> Option<&'a Value> {
    if let Some(obj) = root.as_object()
        && let Some(direct) = obj.get(dotted_path)
    {
        return Some(direct);
    }
    let mut current = root;
    for part in dotted_path.split('.') {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

/// Normalize declarative fields, enforce strict integer/regex formats, validate against
/// Draft 2020-12 JSON Schema, and evaluate `x-invariants` on `config.toml`.
pub fn validate_config_against_schema(
    schema_json: &Value,
    raw_instance: &Value,
) -> Result<Vec<String>> {
    let normalized = normalize_and_precheck_value("config", schema_json, raw_instance)?;
    validate_instance_against_schema(schema_json, &normalized, "config.toml")?;
    evaluate_schema_invariants(schema_json, &normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_schema_validation_never_leaks_secret_values() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "api_secret": {
                    "type": "string",
                    "minLength": 32
                }
            },
            "required": ["api_secret"]
        });
        let instance = json!({
            "api_secret": "my-short-secret-value-123"
        });
        let err = validate_instance_against_schema(&schema, &instance, "security")
            .expect_err("should fail minLength");
        assert!(!err.to_string().contains("my-short-secret-value-123"));
        assert!(err.to_string().contains("api_secret"));
    }

    #[test]
    fn test_invariants_order_all_gte_map_values_and_non_empty() {
        let rules: Vec<InvariantRule> = serde_json::from_value(json!([
            {
                "rule": "order",
                "lower": "min_len",
                "upper": "max_len",
                "allow_equal": true,
                "message": "min_len exceeds max_len"
            },
            {
                "rule": "all_gte",
                "uppers": ["account_capacity", "ip_capacity"],
                "lowers": ["high_cost"],
                "message": "capacities must be at least high_cost"
            },
            {
                "rule": "map_values_lte",
                "map": "action_costs",
                "uppers": ["account_capacity"],
                "message": "action_costs exceed account_capacity"
            },
            {
                "rule": "non_empty",
                "path": "security.pepper",
                "severity": "warning",
                "message": "security.pepper is empty"
            }
        ]))
        .expect("parse rules");

        let valid_doc = json!({
            "min_len": 8,
            "max_len": 32,
            "account_capacity": 20,
            "ip_capacity": 50,
            "high_cost": 10,
            "action_costs": { "upload": 15 },
            "security": { "pepper": "" }
        });
        let warnings = evaluate_invariants(&rules, &valid_doc).expect("valid invariants");
        assert_eq!(warnings, vec!["security.pepper is empty"]);

        let bad_order = json!({
            "min_len": 40,
            "max_len": 32
        });
        let err = evaluate_invariants(&rules, &bad_order).expect_err("order violation");
        assert!(err.to_string().contains("min_len exceeds max_len"));
    }
}
