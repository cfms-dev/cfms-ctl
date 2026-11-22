//! Database-backed audit log retention policy (`maintenance.audit_retention`).

use serde::Serialize;
use serde_json::Value;
use crate::core::error::{CfmsError, Result};
use crate::db::backend::DbPool;
use crate::db::options::list_options;

pub const AUDIT_RETENTION_NAMESPACE: &str = "maintenance.audit_retention";
pub const DEFAULT_RETENTION_DAYS: u64 = 365;
pub const DEFAULT_BATCH_SIZE: u64 = 500;
pub const SECONDS_PER_DAY: f64 = 86_400.0;
const MAX_RETENTION_DAYS: u64 = 3_650_000;

/// Retention policy resolved from `options` (`maintenance.audit_retention`) overlaid onto defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuditRetentionPolicy {
    pub retention_days: u64,
    pub batch_size: u64,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl AuditRetentionPolicy {
    /// Load and validate `maintenance.audit_retention` from the `options` table.
    pub async fn load(pool: &DbPool) -> Result<Self> {
        let records = list_options(pool, Some(AUDIT_RETENTION_NAMESPACE)).await?;
        let mut policy = Self::default();

        for rec in records {
            match rec.option_key.as_str() {
                "retention_days" => {
                    let days = parse_positive_u64_option("retention_days", &rec.value)?;
                    if days > MAX_RETENTION_DAYS {
                        return Err(CfmsError::Config(format!(
                            "Invalid {AUDIT_RETENTION_NAMESPACE}.retention_days: {days} exceeds maximum {MAX_RETENTION_DAYS}"
                        )));
                    }
                    policy.retention_days = days;
                }
                "batch_size" => {
                    let batch = parse_positive_u64_option("batch_size", &rec.value)?;
                    if usize::try_from(batch).is_err() {
                        return Err(CfmsError::Config(format!(
                            "Invalid {AUDIT_RETENTION_NAMESPACE}.batch_size: value {batch} out of range"
                        )));
                    }
                    policy.batch_size = batch;
                }
                _ => {}
            }
        }

        Ok(policy)
    }

    /// Compute the Unix timestamp cutoff (`now - retention_days * 86400`) for `logged_time < cutoff`.
    #[must_use]
    pub fn cutoff_unix_seconds(&self, now_unix: f64) -> f64 {
        now_unix - (self.retention_days as f64) * SECONDS_PER_DAY
    }
}

fn parse_positive_u64_option(key: &str, value: &Value) -> Result<u64> {
    let parsed = match value {
        // With `arbitrary_precision`, integer literals parse cleanly via `as_u64()`,
        // while floats like `"10.0"` or negative values return `None`.
        Value::Number(num) => num.as_u64(),
        _ => None,
    }
    .ok_or_else(|| {
        CfmsError::Config(format!(
            "Invalid {AUDIT_RETENTION_NAMESPACE}.{key}: expected positive integer, got {value}"
        ))
    })?;

    if parsed == 0 || i64::try_from(parsed).is_err() {
        return Err(CfmsError::Config(format!(
            "Invalid {AUDIT_RETENTION_NAMESPACE}.{key}: must be a positive integer >= 1 (got {parsed})"
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn retention_policy_defaults_and_db_overrides() {
        let pool = setup_memory_db().await;
        let defaults = AuditRetentionPolicy::load(&pool).await.unwrap();
        assert_eq!(defaults, AuditRetentionPolicy::default());

        let mut updates = BTreeMap::new();
        updates.insert(
            "retention_days".to_string(),
            OptionUpdateInput {
                value: json!(90),
                expected_revision: 0,
            },
        );
        updates.insert(
            "batch_size".to_string(),
            OptionUpdateInput {
                value: json!(250),
                expected_revision: 0,
            },
        );
        write_options_batch(&pool, AUDIT_RETENTION_NAMESPACE, updates)
            .await
            .unwrap();

        let loaded = AuditRetentionPolicy::load(&pool).await.unwrap();
        assert_eq!(loaded.retention_days, 90);
        assert_eq!(loaded.batch_size, 250);
    }

    #[tokio::test]
    async fn retention_policy_rejects_non_positive_or_wrong_type() {
        let pool = setup_memory_db().await;
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('maintenance.audit_retention', 'core', 'retention_days', 1, 1, 'int', '0', 100.0)",
        )
        .execute(match &pool {
            DbPool::Sqlite(p) => p,
            _ => unreachable!(),
        })
        .await
        .unwrap();

        let err = AuditRetentionPolicy::load(&pool).await.unwrap_err();
        assert!(matches!(err, CfmsError::Config(_)));

        sqlx::query(
            "UPDATE options SET value_type = 'str', option_value = 'bad' WHERE namespace = 'maintenance.audit_retention' AND option_key = 'retention_days'",
        )
        .execute(match &pool {
            DbPool::Sqlite(p) => p,
            _ => unreachable!(),
        })
        .await
        .unwrap();

        let err2 = AuditRetentionPolicy::load(&pool).await.unwrap_err();
        assert!(matches!(err2, CfmsError::Config(_)));
    }
}
