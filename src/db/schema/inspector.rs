//! Live database schema inspection and drift detection across SQLite, MySQL, and PostgreSQL.

use std::collections::BTreeSet;
use serde::Serialize;
use crate::core::error::Result;
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::registry::{APPLICATION_TABLE_NAMES, LATEST_SCHEMA_REVISION};

/// Report comparing a live database schema against the expected CFMS schema contract.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaDriftReport {
    pub dialect: DatabaseKind,
    pub current_revision: Option<String>,
    pub expected_revision: String,
    pub revision_matches: bool,
    pub present_core_tables: usize,
    pub expected_core_tables: usize,
    pub missing_tables: Vec<String>,
    pub extra_tables: Vec<String>,
    pub is_empty_database: bool,
    pub healthy: bool,
}

/// Inspects live database tables and detects schema drift before migrations or upgrades.
pub struct SchemaInspector;

impl SchemaInspector {
    /// Inspect the connected database and produce a [`SchemaDriftReport`].
    pub async fn inspect(pool: &DbPool) -> Result<SchemaDriftReport> {
        let live_tables = pool.list_tables().await?;
        let current_revision = pool.current_revision().await?;

        let live_set: BTreeSet<String> = live_tables
            .into_iter()
            .filter(|t| t != "alembic_version")
            .collect();
        let expected_set: BTreeSet<String> = APPLICATION_TABLE_NAMES
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let missing_tables: Vec<String> = expected_set.difference(&live_set).cloned().collect();
        let extra_tables: Vec<String> = live_set.difference(&expected_set).cloned().collect();
        let present_core_tables = expected_set.intersection(&live_set).count();
        let is_empty_database = live_set.is_empty() && current_revision.is_none();
        let revision_matches = current_revision.as_deref() == Some(LATEST_SCHEMA_REVISION);
        let healthy = revision_matches && missing_tables.is_empty();

        Ok(SchemaDriftReport {
            dialect: pool.kind(),
            current_revision,
            expected_revision: LATEST_SCHEMA_REVISION.to_string(),
            revision_matches,
            present_core_tables,
            expected_core_tables: APPLICATION_TABLE_NAMES.len(),
            missing_tables,
            extra_tables,
            is_empty_database,
            healthy,
        })
    }
}
