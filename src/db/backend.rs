//! Multi-backend connection pool and query helpers for SQLite, MySQL, and PostgreSQL.

use std::str::FromStr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{MySqlPool, PgPool, Row, SqlitePool};
use crate::core::config::DatabaseSectionConfig;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;

/// Supported database engines in CFMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseKind {
    Sqlite,
    Mysql,
    #[serde(alias = "postgres")]
    Postgresql,
}

impl DatabaseKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Mysql => "mysql",
            Self::Postgresql => "postgresql",
        }
    }
}

impl std::fmt::Display for DatabaseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unified database connection pool across SQLite, MySQL, and PostgreSQL.
#[derive(Debug, Clone)]
pub enum DbPool {
    Sqlite(SqlitePool),
    Mysql(MySqlPool),
    Postgres(PgPool),
}

impl DbPool {
    /// Connect to the configured database backend with CFMS-standard pool and session settings.
    pub async fn connect(
        config: &DatabaseSectionConfig,
        paths: &WorkspacePaths,
    ) -> Result<Self> {
        match config.kind {
            DatabaseKind::Sqlite => {
                let db_path = paths.resolve_sqlite_path(&config.file);
                let options = if config.file == ":memory:" {
                    SqliteConnectOptions::from_str("sqlite::memory:")
                        .map_err(|e| CfmsError::Database(e.to_string()))?
                } else {
                    SqliteConnectOptions::new()
                        .filename(&db_path)
                        .create_if_missing(true)
                        .foreign_keys(true)
                        .busy_timeout(Duration::from_secs(30))
                        .journal_mode(SqliteJournalMode::Wal)
                        .synchronous(SqliteSynchronous::Normal)
                };

                let pool = SqlitePoolOptions::new()
                    .max_connections(5)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect_with(options)
                    .await?;
                Ok(Self::Sqlite(pool))
            }
            DatabaseKind::Mysql => {
                if config.charset != "utf8mb4" {
                    return Err(CfmsError::Config(format!(
                        "MySQL database.charset must be 'utf8mb4', got '{}'",
                        config.charset
                    )));
                }
                let options = MySqlConnectOptions::new()
                    .host(&config.host)
                    .port(config.port)
                    .username(&config.username)
                    .password(&config.password)
                    .database(&config.name)
                    .charset(&config.charset);

                let pool = MySqlPoolOptions::new()
                    .max_connections(5)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect_with(options)
                    .await?;
                Ok(Self::Mysql(pool))
            }
            DatabaseKind::Postgresql => {
                let options = PgConnectOptions::new()
                    .host(&config.host)
                    .port(config.port)
                    .username(&config.username)
                    .password(&config.password)
                    .database(&config.name);

                let pool = PgPoolOptions::new()
                    .max_connections(5)
                    .acquire_timeout(Duration::from_secs(30))
                    .connect_with(options)
                    .await?;
                Ok(Self::Postgres(pool))
            }
        }
    }

    #[must_use]
    pub const fn kind(&self) -> DatabaseKind {
        match self {
            Self::Sqlite(_) => DatabaseKind::Sqlite,
            Self::Mysql(_) => DatabaseKind::Mysql,
            Self::Postgres(_) => DatabaseKind::Postgresql,
        }
    }

    /// Ping the database to verify connectivity.
    pub async fn ping(&self) -> Result<()> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::Mysql(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        }
        Ok(())
    }

    /// Close pooled connections cleanly (checkpointing SQLite WAL if applicable).
    pub async fn close(&self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
            Self::Mysql(pool) => pool.close().await,
            Self::Postgres(pool) => pool.close().await,
        }
    }

    /// Read all table names present in the current database schema.
    pub async fn list_tables(&self) -> Result<Vec<String>> {
        let mut tables = match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|r| r.get::<String, _>(0))
                    .collect::<Vec<_>>()
            }
            Self::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name",
                )
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|r| r.get::<String, _>(0))
                    .collect::<Vec<_>>()
            }
            Self::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' ORDER BY tablename",
                )
                .fetch_all(pool)
                .await?;
                rows.into_iter()
                    .map(|r| r.get::<String, _>(0))
                    .collect::<Vec<_>>()
            }
        };
        tables.sort();
        Ok(tables)
    }

    /// Query the current schema revision recorded in `alembic_version` (if present).
    pub async fn current_revision(&self) -> Result<Option<String>> {
        let tables = self.list_tables().await?;
        if !tables.iter().any(|t| t == "alembic_version") {
            return Ok(None);
        }

        let heads: Vec<String> = match self {
            Self::Sqlite(pool) => {
                let rows = sqlx::query("SELECT version_num FROM alembic_version")
                    .fetch_all(pool)
                    .await?;
                rows.into_iter().map(|r| r.get::<String, _>(0)).collect()
            }
            Self::Mysql(pool) => {
                let rows = sqlx::query("SELECT version_num FROM alembic_version")
                    .fetch_all(pool)
                    .await?;
                rows.into_iter().map(|r| r.get::<String, _>(0)).collect()
            }
            Self::Postgres(pool) => {
                let rows = sqlx::query("SELECT version_num FROM alembic_version")
                    .fetch_all(pool)
                    .await?;
                rows.into_iter().map(|r| r.get::<String, _>(0)).collect()
            }
        };

        if heads.len() > 1 {
            return Err(CfmsError::SchemaDrift(format!(
                "Database has multiple Alembic heads: {}",
                heads.join(", ")
            )));
        }

        Ok(heads.into_iter().next())
    }

    /// List column names for `table` on the active backend.
    pub async fn list_table_columns(&self, table: &str) -> Result<Vec<String>> {
        let cols = match self {
            Self::Sqlite(pool) => {
                let escaped = table.replace('"', "\"\"");
                let sql = format!("PRAGMA table_xinfo(\"{escaped}\")");
                let rows = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch_all(pool).await?;
                rows.into_iter().map(|r| r.get::<String, _>("name")).collect()
            }
            Self::Mysql(pool) => {
                let rows = sqlx::query(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position",
                )
                .bind(table)
                .fetch_all(pool)
                .await?;
                rows.into_iter().map(|r| r.get::<String, _>(0)).collect()
            }
            Self::Postgres(pool) => {
                let rows = sqlx::query(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
                )
                .bind(table)
                .fetch_all(pool)
                .await?;
                rows.into_iter().map(|r| r.get::<String, _>(0)).collect()
            }
        };
        Ok(cols)
    }

    /// Verify that the connected database server version supports all CFMS schema features
    /// (generated `STORED` columns and functional expression indexes) and emit advisory warnings
    /// for non-LTS MySQL releases.
    pub async fn validate_server_compatibility(&self) -> Result<ServerCompatibility> {
        match self {
            Self::Sqlite(_) => Ok(ServerCompatibility::default()),
            Self::Mysql(pool) => {
                let raw: String = sqlx::query_scalar("SELECT VERSION()")
                    .fetch_one(pool)
                    .await?;
                check_mysql_version_string(&raw)
            }
            Self::Postgres(pool) => {
                let raw: String = sqlx::query_scalar("SELECT current_setting('server_version_num')")
                    .fetch_one(pool)
                    .await?;
                let num: u32 = raw.trim().parse().map_err(|_| {
                    CfmsError::Database(format!(
                        "Unable to parse PostgreSQL server_version_num: '{raw}'"
                    ))
                })?;
                if num < 120_000 {
                    return Err(CfmsError::Database(format!(
                        "CFMS requires PostgreSQL 12 or newer (for STORED generated columns); connected server_version_num is {num}"
                    )));
                }
                Ok(ServerCompatibility::default())
            }
        }
    }
}

/// Engine compatibility check output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerCompatibility {
    pub warnings: Vec<String>,
}

/// Parse a MySQL `SELECT VERSION()` string and enforce MySQL 8.0.13+ (non-MariaDB) compatibility,
/// warning when running outside the CFMS-recommended `8.4.x` / `9.7.x` LTS series.
pub fn check_mysql_version_string(raw: &str) -> Result<ServerCompatibility> {
    let trimmed = raw.trim();
    if trimmed.to_ascii_lowercase().contains("mariadb") {
        return Err(CfmsError::Database(format!(
            "MariaDB is not supported (functional expression index syntax differs from MySQL); connected to '{trimmed}'"
        )));
    }

    let numeric_part = trimmed
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or("");
    let mut parts = numeric_part.split('.').filter(|s| !s.is_empty());
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| CfmsError::Database(format!("Unable to parse MySQL version '{trimmed}'")))?;
    let minor: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| CfmsError::Database(format!("Unable to parse MySQL version '{trimmed}'")))?;
    let patch: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    if (major, minor, patch) < (8, 0, 13) {
        return Err(CfmsError::Database(format!(
            "CFMS requires MySQL 8.0.13 or newer (for expression indexes and STORED generated columns); connected to {major}.{minor}.{patch}"
        )));
    }

    let mut warnings = Vec::new();
    if !matches!((major, minor), (8, 4) | (9, 7)) {
        warnings.push(format!(
            "Connected to MySQL {major}.{minor}.{patch}; cfms_on_websocket recommends MySQL 8.4.x or 9.7.x LTS."
        ));
    }

    Ok(ServerCompatibility { warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_version_validation_matches_policy() {
        assert!(
            check_mysql_version_string("8.4.3")
                .expect("8.4.3 ok")
                .warnings
                .is_empty()
        );
        assert!(
            check_mysql_version_string("9.7.0-log")
                .expect("9.7.0 ok")
                .warnings
                .is_empty()
        );

        let non_lts = check_mysql_version_string("8.0.39-0ubuntu0.24.04.1").expect("8.0.39 allowed");
        assert_eq!(non_lts.warnings.len(), 1);
        assert!(non_lts.warnings[0].contains("8.0.39"));

        assert!(check_mysql_version_string("8.0.12").is_err());
        assert!(check_mysql_version_string("5.7.44").is_err());
        assert!(check_mysql_version_string("11.4.2-MariaDB-ubu2404").is_err());
    }
}
