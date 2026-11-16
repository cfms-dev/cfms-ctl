//! Retention policy loading, CLI override resolution, and authoritative database UTC clock
//! for `cfms-ctl permission purge-expired`.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::cli::permission::PermissionPurgeExpiredArgs;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::backend::DbPool;
use crate::db::options::{OptionsSchemaRegistry, list_options};
use crate::ops::audit::filter::{format_unix_utc, parse_iso8601_timestamp};
use crate::ops::audit::policy::SECONDS_PER_DAY;

pub const PERMISSION_RETENTION_NAMESPACE: &str = "identity.permission_retention";
pub const DEFAULT_RETENTION_DAYS: u64 = 30;
pub const DEFAULT_BATCH_SIZE: usize = 500;
pub const MAX_RETENTION_DAYS: u64 = 36_500;
pub const MAX_BATCH_SIZE: usize = 100_000;

/// Retention policy values stored in `options` under `identity.permission_retention`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PermissionRetentionPolicy {
    pub retention_days: u64,
    pub batch_size: usize,
}

impl Default for PermissionRetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

/// Source describing how the effective purge cutoff was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoffSource {
    DbPolicy,
    CliRetentionDays,
    CliBefore,
}

impl CutoffSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DbPolicy => "db_policy",
            Self::CliRetentionDays => "cli_retention_days",
            Self::CliBefore => "cli_before",
        }
    }
}

/// Resolved purge execution parameters derived from CLI overrides, DB options, and DB clock.
#[derive(Debug, Clone)]
pub struct ResolvedPurgeConfig {
    pub db_now: f64,
    pub cutoff_timestamp: f64,
    pub cutoff_utc: String,
    pub cutoff_source: CutoffSource,
    pub retention_days: Option<u64>,
    pub batch_size: usize,
}

/// Validate CLI purge flags before opening a database connection.
pub fn validate_purge_args(args: &PermissionPurgeExpiredArgs) -> Result<Option<(f64, String)>> {
    if let Some(days) = args.retention_days
        && days > MAX_RETENTION_DAYS
    {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid --retention-days: {days} exceeds maximum {MAX_RETENTION_DAYS}"
        )));
    }

    if let Some(batch) = args.batch_size
        && (batch == 0 || batch > MAX_BATCH_SIZE)
    {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid --batch-size: {batch} must be between 1 and {MAX_BATCH_SIZE}"
        )));
    }

    match args.before.as_deref() {
        Some(raw) => parse_iso8601_timestamp(raw, "--before").map(Some),
        None => Ok(None),
    }
}

/// Query the database server's current UTC timestamp in Unix epoch seconds (`f64`).
///
/// Mirrors `include/database/clock.py` while eliminating MySQL session-timezone/DST fold
/// ambiguity and casting PostgreSQL 14+ `NUMERIC` `EXTRACT(EPOCH)` results to `double precision`.
pub async fn database_now(pool: &DbPool) -> Result<f64> {
    let now: f64 = match pool {
        DbPool::Sqlite(p) => {
            sqlx::query_scalar("SELECT (julianday('now') - 2440587.5) * 86400.0")
                .fetch_one(p)
                .await?
        }
        DbPool::Mysql(p) => {
            sqlx::query_scalar(
                "SELECT CAST(TIMESTAMPDIFF(MICROSECOND, '1970-01-01 00:00:00', UTC_TIMESTAMP(6)) / 1000000.0 AS DOUBLE)",
            )
            .fetch_one(p)
            .await?
        }
        DbPool::Postgres(p) => {
            sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM clock_timestamp())::double precision")
                .fetch_one(p)
                .await?
        }
    };

    if !now.is_finite() {
        return Err(CfmsError::Database(format!(
            "Database clock returned non-finite timestamp: {now}"
        )));
    }
    Ok(now)
}

/// Resolve effective cutoff and batch size from CLI arguments overlaid on DB `options`.
pub async fn resolve_purge_config(
    pool: &DbPool,
    paths: Option<&WorkspacePaths>,
    args: &PermissionPurgeExpiredArgs,
) -> Result<ResolvedPurgeConfig> {
    let explicit_before = validate_purge_args(args)?;
    let need_db_retention = explicit_before.is_none() && args.retention_days.is_none();
    let need_db_batch = args.batch_size.is_none();

    let db_policy = if need_db_retention || need_db_batch {
        load_db_policy(
            pool,
            paths,
            args.contract.as_deref(),
            need_db_retention,
            need_db_batch,
        )
        .await?
    } else {
        PermissionRetentionPolicy::default()
    };

    let db_now = database_now(pool).await?;
    let batch_size = args.batch_size.unwrap_or(db_policy.batch_size);

    let (cutoff_timestamp, cutoff_utc, cutoff_source, retention_days) = match explicit_before {
        Some((ts, utc)) => {
            if ts > db_now {
                return Err(CfmsError::InvalidArgument(format!(
                    "--before cutoff ({utc}) is later than the current database UTC time ({}); refusing to purge active or future permissions",
                    format_unix_utc(db_now)
                )));
            }
            (ts, utc, CutoffSource::CliBefore, None)
        }
        None => {
            let (days, source) = match args.retention_days {
                Some(override_days) => (override_days, CutoffSource::CliRetentionDays),
                None => (db_policy.retention_days, CutoffSource::DbPolicy),
            };
            let cutoff = db_now - (days as f64) * SECONDS_PER_DAY;
            if !cutoff.is_finite() {
                return Err(CfmsError::InvalidArgument(
                    "Computed purge cutoff timestamp is outside finite range".to_string(),
                ));
            }
            (cutoff, format_unix_utc(cutoff), source, Some(days))
        }
    };

    Ok(ResolvedPurgeConfig {
        db_now,
        cutoff_timestamp,
        cutoff_utc,
        cutoff_source,
        retention_days,
        batch_size,
    })
}

async fn load_db_policy(
    pool: &DbPool,
    paths: Option<&WorkspacePaths>,
    explicit_contract: Option<&Path>,
    validate_retention: bool,
    validate_batch: bool,
) -> Result<PermissionRetentionPolicy> {
    let registry = match paths {
        Some(p) => OptionsSchemaRegistry::from_workspace(p, explicit_contract)?,
        None => OptionsSchemaRegistry::empty(),
    };
    let records = list_options(pool, &registry, Some(PERMISSION_RETENTION_NAMESPACE)).await?;
    let mut policy = PermissionRetentionPolicy::default();

    for rec in records {
        match rec.option_key.as_str() {
            "retention_days" if validate_retention => {
                let days = parse_positive_u64_option("retention_days", &rec.value)?;
                if days > MAX_RETENTION_DAYS {
                    return Err(CfmsError::Config(format!(
                        "Invalid {PERMISSION_RETENTION_NAMESPACE}.retention_days: {days} exceeds maximum {MAX_RETENTION_DAYS}"
                    )));
                }
                policy.retention_days = days;
            }
            "batch_size" if validate_batch => {
                let batch = parse_positive_u64_option("batch_size", &rec.value)?;
                let batch_usize = usize::try_from(batch).map_err(|_| {
                    CfmsError::Config(format!(
                        "Invalid {PERMISSION_RETENTION_NAMESPACE}.batch_size: value {batch} out of range"
                    ))
                })?;
                if batch_usize > MAX_BATCH_SIZE {
                    return Err(CfmsError::Config(format!(
                        "Invalid {PERMISSION_RETENTION_NAMESPACE}.batch_size: {batch_usize} exceeds maximum {MAX_BATCH_SIZE}"
                    )));
                }
                policy.batch_size = batch_usize;
            }
            _ => {}
        }
    }

    Ok(policy)
}

fn parse_positive_u64_option(key: &str, value: &Value) -> Result<u64> {
    let parsed = match value {
        Value::Number(num) => num.as_u64(),
        _ => None,
    }
    .ok_or_else(|| {
        CfmsError::Config(format!(
            "Invalid {PERMISSION_RETENTION_NAMESPACE}.{key}: expected positive integer, got {value}"
        ))
    })?;

    if parsed == 0 || i64::try_from(parsed).is_err() {
        return Err(CfmsError::Config(format!(
            "Invalid {PERMISSION_RETENTION_NAMESPACE}.{key}: must be a positive integer >= 1 (got {parsed})"
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::permission::PermissionScope;
    use crate::db::options::{OptionUpdateInput, write_options_batch};
    use crate::db::schema::create_head_schema;
    use serde_json::json;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    async fn setup_memory_db() -> DbPool {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .create_if_missing(true);
        let pool = DbPool::Sqlite(SqlitePool::connect_with(opts).await.unwrap());
        create_head_schema(&pool, false).await.unwrap();
        pool
    }

    fn base_args() -> PermissionPurgeExpiredArgs {
        PermissionPurgeExpiredArgs {
            before: None,
            retention_days: None,
            scope: PermissionScope::All,
            batch_size: None,
            contract: None,
            dry_run: true,
        }
    }

    #[tokio::test]
    async fn database_now_and_policy_defaults_and_overrides() {
        let pool = setup_memory_db().await;
        let now = database_now(&pool).await.unwrap();
        assert!(now > 1_700_000_000.0);

        let default_cfg = resolve_purge_config(&pool, None, &base_args()).await.unwrap();
        assert_eq!(default_cfg.cutoff_source, CutoffSource::DbPolicy);
        assert_eq!(default_cfg.retention_days, Some(30));
        assert_eq!(default_cfg.batch_size, 500);
        assert!(
            (default_cfg.cutoff_timestamp - (default_cfg.db_now - 30.0 * SECONDS_PER_DAY)).abs()
                < 1e-3
        );

        let registry = OptionsSchemaRegistry::empty();
        let mut updates = BTreeMap::new();
        updates.insert(
            "retention_days".to_string(),
            OptionUpdateInput {
                value: json!(7),
                expected_revision: 0,
            },
        );
        updates.insert(
            "batch_size".to_string(),
            OptionUpdateInput {
                value: json!(120),
                expected_revision: 0,
            },
        );
        write_options_batch(&pool, &registry, PERMISSION_RETENTION_NAMESPACE, updates)
            .await
            .unwrap();

        let db_cfg = resolve_purge_config(&pool, None, &base_args()).await.unwrap();
        assert_eq!(db_cfg.retention_days, Some(7));
        assert_eq!(db_cfg.batch_size, 120);

        let mut cli_args = base_args();
        cli_args.retention_days = Some(0);
        cli_args.batch_size = Some(42);
        let cli_cfg = resolve_purge_config(&pool, None, &cli_args).await.unwrap();
        assert_eq!(cli_cfg.cutoff_source, CutoffSource::CliRetentionDays);
        assert_eq!(cli_cfg.retention_days, Some(0));
        assert_eq!(cli_cfg.batch_size, 42);
    }

    #[tokio::test]
    async fn future_before_and_invalid_db_options_are_rejected_unless_overridden() {
        let pool = setup_memory_db().await;

        let mut future_args = base_args();
        future_args.before = Some("2099-01-01T00:00:00Z".to_string());
        let future_err = resolve_purge_config(&pool, None, &future_args).await.unwrap_err();
        assert!(matches!(future_err, CfmsError::InvalidArgument(_)));

        let DbPool::Sqlite(ref sq) = pool else { unreachable!() };
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('identity.permission_retention', 'core', 'retention_days', 1, 1, 'int', '0', 100.0)",
        )
        .execute(sq)
        .await
        .unwrap();

        let bad_db_err = resolve_purge_config(&pool, None, &base_args()).await.unwrap_err();
        assert!(matches!(bad_db_err, CfmsError::Config(_)));

        // Explicit CLI --before bypasses broken stored DB retention_days
        let mut rescue_args = base_args();
        rescue_args.before = Some("2025-01-01T00:00:00Z".to_string());
        let rescued = resolve_purge_config(&pool, None, &rescue_args).await.unwrap();
        assert_eq!(rescued.cutoff_source, CutoffSource::CliBefore);
    }

    #[test]
    fn validate_purge_args_rejects_out_of_range_or_naive_inputs() {
        let mut too_many_days = base_args();
        too_many_days.retention_days = Some(MAX_RETENTION_DAYS + 1);
        assert!(matches!(
            validate_purge_args(&too_many_days),
            Err(CfmsError::InvalidArgument(_))
        ));

        let mut zero_batch = base_args();
        zero_batch.batch_size = Some(0);
        assert!(matches!(
            validate_purge_args(&zero_batch),
            Err(CfmsError::InvalidArgument(_))
        ));

        let mut huge_batch = base_args();
        huge_batch.batch_size = Some(MAX_BATCH_SIZE + 1);
        assert!(matches!(
            validate_purge_args(&huge_batch),
            Err(CfmsError::InvalidArgument(_))
        ));

        let mut naive_before = base_args();
        naive_before.before = Some("2025-01-01T00:00:00".to_string());
        assert!(matches!(
            validate_purge_args(&naive_before),
            Err(CfmsError::InvalidArgument(_))
        ));
    }
}
