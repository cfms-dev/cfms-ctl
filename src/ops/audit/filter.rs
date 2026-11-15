//! Timestamp parsing and filter normalization for `cfms-ctl audit`.

use std::collections::HashSet;
use std::hash::Hash;
use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use serde::Serialize;
use uuid::Uuid;
use crate::cli::audit::AuditFilterArgs;
use crate::core::error::{CfmsError, Result};
use crate::ops::audit::policy::AuditRetentionPolicy;

/// How the upper time cutoff (`--before`) was determined for an audit command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoffMode {
    ExplicitBefore,
    RetentionPolicy,
    AllTime,
}

impl CutoffMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitBefore => "explicit_before",
            Self::RetentionPolicy => "retention_policy",
            Self::AllTime => "all_time",
        }
    }
}

/// Validated, deduplicated filter parameters ready for database username resolution and SQL binding.
#[derive(Debug, Clone)]
pub struct ResolvedAuditFilter {
    pub before_unix: Option<f64>,
    pub before_utc: Option<String>,
    pub after_unix: Option<f64>,
    pub after_utc: Option<String>,
    pub cutoff_mode: CutoffMode,
    pub retention_days_applied: Option<u64>,
    pub actions: Vec<String>,
    pub exclude_actions: Vec<String>,
    pub usernames: Vec<String>,
    pub user_ids: Vec<Uuid>,
    pub targets: Vec<String>,
    pub results: Vec<i32>,
    pub remote_addresses: Vec<String>,
}

impl ResolvedAuditFilter {
    /// Normalize CLI filter arguments and resolve the time window once upfront.
    pub fn from_args(
        args: &AuditFilterArgs,
        all_history: bool,
        policy: Option<AuditRetentionPolicy>,
        now_unix: f64,
    ) -> Result<Self> {
        let after = args
            .after
            .as_deref()
            .map(|raw| parse_iso8601_timestamp(raw, "--after"))
            .transpose()?;

        let (before_unix, before_utc, cutoff_mode, retention_days_applied) = if all_history {
            (None, None, CutoffMode::AllTime, None)
        } else if let Some(raw) = &args.before {
            let (ts, utc) = parse_iso8601_timestamp(raw, "--before")?;
            (Some(ts), Some(utc), CutoffMode::ExplicitBefore, None)
        } else {
            let p = policy.ok_or_else(|| {
                CfmsError::Config(
                    "Audit retention policy is required when `--before` and `--all` are omitted"
                        .to_string(),
                )
            })?;
            let cutoff = p.cutoff_unix_seconds(now_unix);
            let utc = format_unix_utc(cutoff);
            (
                Some(cutoff),
                Some(utc),
                CutoffMode::RetentionPolicy,
                Some(p.retention_days),
            )
        };

        if let (Some((after_ts, _)), Some(before_ts)) = (&after, before_unix)
            && *after_ts >= before_ts
        {
            return Err(CfmsError::InvalidArgument(
                "`--after` must be strictly earlier than `--before` cutoff".to_string(),
            ));
        }

        let actions = dedup_non_empty("--action", &args.actions)?;
        let exclude_actions = dedup_non_empty("--exclude-action", &args.exclude_actions)?;
        let usernames = dedup_non_empty("--username", &args.usernames)?;
        let user_ids = parse_and_dedup_uuids("--user-id", &args.user_ids)?;
        let targets = dedup_non_empty("--target", &args.targets)?;
        let results = dedup_preserve(&args.results);
        let remote_addresses = dedup_non_empty("--remote-address", &args.remote_addresses)?;

        Ok(Self {
            before_unix,
            before_utc,
            after_unix: after.as_ref().map(|(ts, _)| *ts),
            after_utc: after.map(|(_, utc)| utc),
            cutoff_mode,
            retention_days_applied,
            actions,
            exclude_actions,
            usernames,
            user_ids,
            targets,
            results,
            remote_addresses,
        })
    }
}

/// Validate CLI filter syntax (`--before`, `--after`, UUIDs, non-empty strings) before opening DB or locks.
pub fn validate_filter_syntax(args: &AuditFilterArgs) -> Result<()> {
    let after = args
        .after
        .as_deref()
        .map(|raw| parse_iso8601_timestamp(raw, "--after"))
        .transpose()?;
    let before = args
        .before
        .as_deref()
        .map(|raw| parse_iso8601_timestamp(raw, "--before"))
        .transpose()?;
    if let (Some((a, _)), Some((b, _))) = (&after, &before)
        && *a >= *b
    {
        return Err(CfmsError::InvalidArgument(
            "`--after` must be strictly earlier than `--before` cutoff".to_string(),
        ));
    }

    let _ = dedup_non_empty("--action", &args.actions)?;
    let _ = dedup_non_empty("--exclude-action", &args.exclude_actions)?;
    let _ = dedup_non_empty("--username", &args.usernames)?;
    let _ = parse_and_dedup_uuids("--user-id", &args.user_ids)?;
    let _ = dedup_non_empty("--target", &args.targets)?;
    let _ = dedup_non_empty("--remote-address", &args.remote_addresses)?;
    Ok(())
}

/// Parse an ISO 8601 timestamp requiring an explicit timezone offset (`Z` or `±HH:MM`/`±HHMM`/`±HH`).
pub fn parse_iso8601_timestamp(raw: &str, flag_name: &str) -> Result<(f64, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CfmsError::InvalidArgument(format!(
            "`{flag_name}` timestamp cannot be empty"
        )));
    }

    let dt = if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        parsed
    } else if let Some(normalized) = normalize_iso8601_with_offset(trimmed)
        && let Ok(parsed) = DateTime::parse_from_rfc3339(&normalized)
    {
        parsed
    } else {
        if looks_like_naive_datetime(trimmed) {
            return Err(CfmsError::InvalidArgument(format!(
                "Invalid `{flag_name}` timestamp '{raw}': timezone offset is required (use 'Z' or '±HH:MM', e.g. '2026-01-01T00:00:00Z')"
            )));
        }
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid `{flag_name}` timestamp '{raw}': expected ISO 8601 datetime with timezone offset (e.g. '2026-01-01T00:00:00+08:00' or '2026-01-01T00:00:00Z')"
        )));
    };

    let secs = dt.timestamp() as f64;
    let subsec = f64::from(dt.timestamp_subsec_nanos()) / 1_000_000_000.0;
    let unix = secs + subsec;
    if !unix.is_finite() {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid `{flag_name}` timestamp '{raw}': timestamp out of finite range"
        )));
    }

    let utc = dt
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::AutoSi, true);
    Ok((unix, utc))
}

/// Format a finite Unix timestamp (seconds) as a compact UTC RFC 3339 string.
#[must_use]
pub fn format_unix_utc(unix_seconds: f64) -> String {
    if !unix_seconds.is_finite() {
        return unix_seconds.to_string();
    }
    let whole_secs = unix_seconds.floor();
    let frac_nanos = ((unix_seconds - whole_secs) * 1_000_000_000.0).round();
    let (secs_i64, nanos_u32) = if frac_nanos >= 1_000_000_000.0 {
        ((whole_secs as i64).saturating_add(1), 0)
    } else if frac_nanos <= 0.0 {
        (whole_secs as i64, 0)
    } else {
        (whole_secs as i64, frac_nanos as u32)
    };

    DateTime::<Utc>::from_timestamp(secs_i64, nanos_u32)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .unwrap_or_else(|| format!("{unix_seconds}"))
}

fn normalize_iso8601_with_offset(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let valid_date = bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit);
    if !valid_date || !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    let valid_hms = bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit);
    if !valid_hms {
        return None;
    }

    let mut idx = 19;
    let frac = if idx < bytes.len() && bytes[idx] == b'.' {
        let start = idx;
        idx += 1;
        let digits_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == digits_start {
            return None;
        }
        &input[start..idx]
    } else {
        ""
    };

    let tz = &input[idx..];
    let normalized_tz = if tz.eq_ignore_ascii_case("z") {
        "Z".to_string()
    } else {
        let tb = tz.as_bytes();
        if tb.is_empty() || !matches!(tb[0], b'+' | b'-') {
            return None;
        }
        match tb.len() {
            6 if tb[3] == b':' && tb[1..3].iter().all(u8::is_ascii_digit) && tb[4..6].iter().all(u8::is_ascii_digit) => {
                tz.to_string()
            }
            5 if tb[1..5].iter().all(u8::is_ascii_digit) => {
                format!("{}:{}", &tz[..3], &tz[3..])
            }
            3 if tb[1..3].iter().all(u8::is_ascii_digit) => {
                format!("{tz}:00")
            }
            _ => return None,
        }
    };

    Some(format!("{}T{}{}{}", &input[0..10], &input[11..19], frac, normalized_tz))
}

fn looks_like_naive_datetime(input: &str) -> bool {
    NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S%.f").is_ok()
        || NaiveDateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S%.f").is_ok()
        || NaiveDate::parse_from_str(input, "%Y-%m-%d").is_ok()
}

fn dedup_non_empty(flag_name: &str, values: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::with_capacity(values.len());
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        if v.is_empty() {
            return Err(CfmsError::InvalidArgument(format!(
                "`{flag_name}` value cannot be empty"
            )));
        }
        if seen.insert(v.clone()) {
            out.push(v.clone());
        }
    }
    Ok(out)
}

fn parse_and_dedup_uuids(flag_name: &str, values: &[String]) -> Result<Vec<Uuid>> {
    let mut seen = HashSet::with_capacity(values.len());
    let mut out = Vec::with_capacity(values.len());
    for raw in values {
        let trimmed = raw.trim();
        let parsed = Uuid::parse_str(trimmed).map_err(|_| {
            CfmsError::InvalidArgument(format!(
                "Invalid `{flag_name}` UUID '{raw}': expected RFC 4122 UUID"
            ))
        })?;
        if seen.insert(parsed) {
            out.push(parsed);
        }
    }
    Ok(out)
}

fn dedup_preserve<T: Clone + Eq + Hash>(values: &[T]) -> Vec<T> {
    let mut seen = HashSet::with_capacity(values.len());
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        if seen.insert(v.clone()) {
            out.push(v.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_and_iso8601_offsets_and_rejects_naive() {
        let (ts_z, utc_z) = parse_iso8601_timestamp("2026-11-15T04:00:00Z", "--before").unwrap();
        let (ts_plus, utc_plus) =
            parse_iso8601_timestamp("2026-11-15 12:00:00+0800", "--before").unwrap();
        let (ts_short, _) =
            parse_iso8601_timestamp("2026-11-15t12:00:00.000+08", "--before").unwrap();
        assert!((ts_z - ts_plus).abs() < 1e-9);
        assert!((ts_z - ts_short).abs() < 1e-9);
        assert_eq!(utc_z, "2026-11-15T04:00:00Z");
        assert_eq!(utc_plus, "2026-11-15T04:00:00Z");

        let (ts_frac, _) =
            parse_iso8601_timestamp("2026-11-15T04:00:00.25z", "--before").unwrap();
        assert!((ts_frac - ts_z - 0.25).abs() < 1e-9);

        assert!(matches!(
            parse_iso8601_timestamp("2026-11-15T04:00:00", "--before").unwrap_err(),
            CfmsError::InvalidArgument(_)
        ));
        assert!(matches!(
            parse_iso8601_timestamp("2026-11-15", "--before").unwrap_err(),
            CfmsError::InvalidArgument(_)
        ));
        assert!(matches!(
            parse_iso8601_timestamp("", "--before").unwrap_err(),
            CfmsError::InvalidArgument(_)
        ));
    }

    #[test]
    fn resolves_retention_and_rejects_inverted_window() {
        let args = AuditFilterArgs {
            before: Some("2026-11-15T00:00:00Z".to_string()),
            after: Some("2026-11-15T00:00:00Z".to_string()),
            actions: vec![],
            exclude_actions: vec![],
            usernames: vec![],
            user_ids: vec![],
            targets: vec![],
            results: vec![],
            remote_addresses: vec![],
        };
        let err = ResolvedAuditFilter::from_args(
            &args,
            false,
            Some(AuditRetentionPolicy::default()),
            2_000_000_000.0,
        )
        .unwrap_err();
        assert!(matches!(err, CfmsError::InvalidArgument(_)));

        let all_args = AuditFilterArgs {
            before: None,
            after: None,
            actions: vec!["a".to_string(), "a".to_string()],
            exclude_actions: vec![],
            usernames: vec![],
            user_ids: vec!["12345678-1234-4234-9234-123456789ABC".to_string()],
            targets: vec![],
            results: vec![200, 200],
            remote_addresses: vec![],
        };
        let resolved = ResolvedAuditFilter::from_args(&all_args, true, None, 2_000_000_000.0)
            .expect("resolve --all");
        assert_eq!(resolved.cutoff_mode, CutoffMode::AllTime);
        assert!(resolved.before_unix.is_none());
        assert_eq!(resolved.actions, vec!["a"]);
        assert_eq!(resolved.results, vec![200]);
        assert_eq!(resolved.user_ids.len(), 1);
    }
}
