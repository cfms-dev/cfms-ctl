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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}
