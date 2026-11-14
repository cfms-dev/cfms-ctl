//! Live database schema inspection and drift detection across SQLite, MySQL, and PostgreSQL.

use std::collections::{BTreeMap, BTreeSet};
use serde::Serialize;
use crate::core::error::Result;
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::ddl::builtin_schema_ir;
use crate::db::schema::diff::{DiffOptions, SchemaOp, diff_schemas};
use crate::db::schema::ir::{SchemaIr, TableOwnership};
use crate::db::schema::live_ir::introspect_live_schema_ir;
use crate::db::schema::registry::{KNOWN_EXTENSION_TABLES, LATEST_SCHEMA_REVISION};

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_extension_tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub column_mismatches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraint_mismatches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index_mismatches: Vec<String>,
}

impl SchemaDriftReport {
    /// Split `extra_tables` into recognized extension tables and unknown tables.
    #[must_use]
    pub fn partition_extra_tables(&self) -> (Vec<String>, Vec<String>) {
        let mut known_ext = Vec::new();
        let mut unknown = Vec::new();
        for name in &self.extra_tables {
            if KNOWN_EXTENSION_TABLES.contains(&name.as_str())
                || self.known_extension_tables.iter().any(|k| k == name)
            {
                known_ext.push(name.clone());
            } else {
                unknown.push(name.clone());
            }
        }
        (known_ext, unknown)
    }
}

/// Inspects live database tables and detects schema drift before migrations or upgrades.
pub struct SchemaInspector;

impl SchemaInspector {
    /// Inspect the connected database against the built-in CFMS schema contract.
    pub async fn inspect(pool: &DbPool) -> Result<SchemaDriftReport> {
        let expected = builtin_schema_ir(false);
        Self::inspect_against_ir(pool, &expected).await
    }

    /// Inspect the connected database against an explicit target [`SchemaIr`],
    /// checking table inventory, column types/nullability/defaults, constraints, and indexes.
    pub async fn inspect_against_ir(
        pool: &DbPool,
        expected: &SchemaIr,
    ) -> Result<SchemaDriftReport> {
        let live_tables = pool.list_tables().await?;
        let current_revision = pool.current_revision().await?;

        let live_set: BTreeSet<String> = live_tables
            .into_iter()
            .filter(|t| t != "alembic_version")
            .collect();

        let expected_core_set: BTreeSet<String> = expected
            .tables
            .iter()
            .filter(|(_, t)| t.ownership == TableOwnership::Core)
            .map(|(name, _)| name.clone())
            .collect();

        let mut known_ext_set: BTreeSet<String> = KNOWN_EXTENSION_TABLES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        known_ext_set.extend(expected.extension_table_names());

        let missing_tables: Vec<String> = expected_core_set.difference(&live_set).cloned().collect();
        let extra_tables: Vec<String> = live_set.difference(&expected_core_set).cloned().collect();
        let present_core_tables = expected_core_set.intersection(&live_set).count();
        let is_empty_database = live_set.is_empty() && current_revision.is_none();

        let expected_revision = expected
            .schema_revision
            .clone()
            .unwrap_or_else(|| LATEST_SCHEMA_REVISION.to_string());
        let revision_matches = current_revision.as_deref() == Some(expected_revision.as_str());

        let mut column_mismatches = Vec::new();
        let mut constraint_mismatches = Vec::new();
        let mut index_mismatches = Vec::new();

        if !is_empty_database {
            let ownership_hints: BTreeMap<String, TableOwnership> = expected
                .tables
                .iter()
                .map(|(k, t)| (k.clone(), t.ownership.clone()))
                .collect();
            let live_ir = introspect_live_schema_ir(pool, true, Some(&ownership_hints)).await?;
            let mut shared_live = SchemaIr::new(live_ir.source, live_ir.schema_revision.clone());
            let mut shared_expected = SchemaIr::new(expected.source, expected.schema_revision.clone());
            for (name, live_tbl) in &live_ir.tables {
                if let Some(exp_tbl) = expected.tables.get(name) {
                    shared_live.tables.insert(name.clone(), live_tbl.clone());
                    shared_expected.tables.insert(name.clone(), exp_tbl.clone());
                }
            }

            let plan = diff_schemas(
                &shared_live,
                &shared_expected,
                &DiffOptions {
                    dialect: Some(pool.kind()),
                    coalesce_sqlite_rebuilds: false,
                    include_extensions: true,
                    compare_comments: false,
                    ..DiffOptions::default()
                },
            );

            for op in &plan.operations {
                record_drift_op(
                    op,
                    &mut column_mismatches,
                    &mut constraint_mismatches,
                    &mut index_mismatches,
                );
            }
        }

        let healthy = revision_matches && missing_tables.is_empty() && column_mismatches.is_empty();

        Ok(SchemaDriftReport {
            dialect: pool.kind(),
            current_revision,
            expected_revision,
            revision_matches,
            present_core_tables,
            expected_core_tables: expected_core_set.len(),
            missing_tables,
            extra_tables,
            is_empty_database,
            healthy,
            known_extension_tables: known_ext_set.into_iter().collect(),
            column_mismatches,
            constraint_mismatches,
            index_mismatches,
        })
    }
}

fn record_drift_op(
    op: &SchemaOp,
    column_mismatches: &mut Vec<String>,
    constraint_mismatches: &mut Vec<String>,
    index_mismatches: &mut Vec<String>,
) {
    match op {
        SchemaOp::AddColumn { table, column } => {
            column_mismatches.push(format!("{table}.{}: missing in live database", column.name));
        }
        SchemaOp::DropColumn { table, column } => {
            column_mismatches.push(format!(
                "{table}.{}: unexpected extra column in live database",
                column.name
            ));
        }
        SchemaOp::RenameColumn {
            table,
            old_column,
            new_column,
            ..
        } => {
            column_mismatches.push(format!(
                "{table}.{}: expected column '{}'",
                old_column.name, new_column.name
            ));
        }
        SchemaOp::AlterColumn {
            table,
            old_column,
            new_column,
            type_changed,
            nullable_changed,
            default_changed,
            computed_changed,
            ..
        } => {
            let mut diffs = Vec::new();
            if *type_changed {
                diffs.push(format!(
                    "type {:?} != {:?}",
                    old_column.canonical_type, new_column.canonical_type
                ));
            }
            if *nullable_changed {
                diffs.push(format!(
                    "nullable {} != {}",
                    old_column.nullable, new_column.nullable
                ));
            }
            if *default_changed {
                diffs.push(format!(
                    "default {:?} != {:?}",
                    old_column.server_default, new_column.server_default
                ));
            }
            if *computed_changed {
                diffs.push("generated expression mismatch".to_string());
            }
            if !diffs.is_empty() {
                column_mismatches.push(format!("{table}.{}: {}", new_column.name, diffs.join("; ")));
            }
        }
        SchemaOp::AddForeignKey { table, fk, .. } => {
            constraint_mismatches.push(format!(
                "{table}: missing FK ({}) -> {}({})",
                fk.columns.join(", "),
                fk.ref_table,
                fk.ref_columns.join(", ")
            ));
        }
        SchemaOp::DropForeignKey { table, fk } => {
            constraint_mismatches.push(format!(
                "{table}: unexpected FK ({}) -> {}({})",
                fk.columns.join(", "),
                fk.ref_table,
                fk.ref_columns.join(", ")
            ));
        }
        SchemaOp::AddUnique { table, unique } => {
            constraint_mismatches.push(format!(
                "{table}: missing UNIQUE ({})",
                unique.columns.join(", ")
            ));
        }
        SchemaOp::DropUnique { table, unique } => {
            constraint_mismatches.push(format!(
                "{table}: unexpected UNIQUE ({})",
                unique.columns.join(", ")
            ));
        }
        SchemaOp::AddCheck { table, check } => {
            constraint_mismatches.push(format!("{table}: missing CHECK ({})", check.expression));
        }
        SchemaOp::DropCheck { table, check } => {
            constraint_mismatches.push(format!("{table}: unexpected CHECK ({})", check.expression));
        }
        SchemaOp::CreateIndex { table, index } => {
            index_mismatches.push(format!("{table}: missing INDEX '{}'", index.name));
        }
        SchemaOp::DropIndex { table, index } => {
            index_mismatches.push(format!("{table}: unexpected INDEX '{}'", index.name));
        }
        SchemaOp::SqliteRebuildTable { folded_ops, .. } => {
            for inner in folded_ops {
                record_drift_op(inner, column_mismatches, constraint_mismatches, index_mismatches);
            }
        }
        SchemaOp::CreateTable { .. }
        | SchemaOp::DropTable { .. }
        | SchemaOp::SetColumnCommentPg { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ddl::set_alembic_version;
    use crate::db::schema::ir::{
        CanonicalType, ColumnIr, ConfidenceLevel, ExtractionSource, PrimaryKeyIr, SchemaIr,
        TableIr, TableOwnership,
    };
    use sqlx::sqlite::SqlitePoolOptions;
    use tempfile::tempdir;

    fn expected_items_ir() -> SchemaIr {
        let mut ir = SchemaIr::new(ExtractionSource::BuiltinFallback, Some("rev_items_1".to_string()));
        ir.tables.insert(
            "items".to_string(),
            TableIr {
                name: "items".to_string(),
                ownership: TableOwnership::Core,
                columns: vec![
                    ColumnIr {
                        name: "id".to_string(),
                        ordinal: 0,
                        canonical_type: CanonicalType::Integer,
                        dialect_types: BTreeMap::new(),
                        nullable: false,
                        autoincrement: true,
                        server_default: None,
                        computed: None,
                        comment: None,
                        confidence: ConfidenceLevel::High,
                    },
                    ColumnIr {
                        name: "title".to_string(),
                        ordinal: 1,
                        canonical_type: CanonicalType::Varchar { length: Some(64) },
                        dialect_types: BTreeMap::new(),
                        nullable: false,
                        autoincrement: false,
                        server_default: None,
                        computed: None,
                        comment: None,
                        confidence: ConfidenceLevel::High,
                    },
                ],
                primary_key: PrimaryKeyIr {
                    name: Some("pk_items".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["id".to_string()],
                },
                foreign_keys: Vec::new(),
                uniques: Vec::new(),
                checks: Vec::new(),
                indexes: Vec::new(),
                comment: None,
                confidence: ConfidenceLevel::High,
            },
        );
        ir
    }

    #[tokio::test]
    async fn inspect_against_ir_detects_column_type_missing_and_extra_drift() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("drift.db");
        let pool = DbPool::Sqlite(
            SqlitePoolOptions::new()
                .max_connections(2)
                .connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
                .await
                .unwrap(),
        );
        let DbPool::Sqlite(ref p) = pool else {
            unreachable!()
        };

        sqlx::query(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, title TEXT NULL, legacy_col INTEGER)",
        )
        .execute(p)
        .await
        .unwrap();
        set_alembic_version(&pool, "rev_items_1").await.unwrap();

        let expected = expected_items_ir();
        let report = SchemaInspector::inspect_against_ir(&pool, &expected)
            .await
            .unwrap();
        assert!(!report.healthy);
        assert!(report.revision_matches);
        assert!(
            report
                .column_mismatches
                .iter()
                .any(|m| m.contains("items.title")),
            "expected items.title drift, got: {:?}",
            report.column_mismatches
        );
        assert!(
            report
                .column_mismatches
                .iter()
                .any(|m| m.contains("items.legacy_col")),
            "expected items.legacy_col extra column drift, got: {:?}",
            report.column_mismatches
        );

        pool.close().await;
    }
}
