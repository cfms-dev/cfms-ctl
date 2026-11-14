//! Cross-database streaming table transfer, node tree topological copy, and
//! canonical SHA-256 verification across SQLite, MySQL, and PostgreSQL.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::Instant;

use futures_util::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Postgres, Row, Sqlite, Transaction, mysql::MySqlRow, postgres::PgRow, sqlite::SqliteRow};
use uuid::Uuid;

use crate::core::error::{CfmsError, Result};
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::ddl::{
    ColumnDef, ColumnType, builtin_schema_ir, execute_ddl_statements,
};
use crate::db::schema::graph::infer_transfer_metadata;
use crate::db::schema::ir::{CanonicalType, ColumnIr, SchemaIr, TableIr, TableOwnership};
use crate::db::schema::registry::LATEST_SCHEMA_REVISION;
use crate::db::schema::render::compile_full_schema_ddl;
use crate::db::schema::{
    SchemaInspector, create_head_schema, drop_all_cfms_tables, set_alembic_version,
};

const MAX_INSERT_ROWS_PER_BATCH: usize = 500;
const MAX_BIND_PARAMS_PER_BATCH: usize = 9_500;
pub(crate) const NODE_BATCH_SIZE: usize = 200;
pub(crate) const DEFERRED_UPDATE_BATCH_SIZE: usize = 200;

/// Per-table verification summary during cross-backend or distinct-target cloning (`database migrate`).
#[derive(Debug, Clone, Serialize)]
pub struct TableTransferSummary {
    pub table_name: String,
    pub row_count: u64,
    pub sha256_digest: String,
}

/// Summary of a cross-backend or distinct-target database migration (`SQLite <-> MySQL <-> PostgreSQL`).
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseTransferSummary {
    pub source_dialect: DatabaseKind,
    pub target_dialect: DatabaseKind,
    pub table_count: usize,
    pub total_rows: u64,
    pub elapsed_ms: u128,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extension_tables: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub tables: Vec<TableTransferSummary>,
}

/// Progress update emitted during database migration stages.
#[derive(Debug, Clone)]
pub struct MigrationProgress<'a> {
    pub stage: &'a str,
    pub current: usize,
    pub total: usize,
}

/// Validated preflight migration plan before schema creation or confirmation prompt.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub source_dialect: DatabaseKind,
    pub target_dialect: DatabaseKind,
    pub source_revision: String,
    pub extension_tables: Vec<String>,
    pub warnings: Vec<String>,
    pub table_count: usize,
}

/// Canonical dialect-neutral SQL value representation for lossless transfer and SHA-256 verification.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SqlValue {
    Null,
    Bool(bool),
    I64(i64),
    F64(f64),
    Str(String),
    Uuid([u8; 16]),
    Bytes(Vec<u8>),
    Json(serde_json::Value),
}

#[derive(Debug, Clone)]
pub(crate) struct TransferColumn {
    pub(crate) name: String,
    pub(crate) col_type: ColumnType,
    pub(crate) is_generated: bool,
}

impl TransferColumn {
    #[allow(dead_code)]
    pub(crate) fn from_def(col: &ColumnDef) -> Self {
        Self {
            name: col.name.to_string(),
            col_type: col.col_type,
            is_generated: col.generated_expr.is_some(),
        }
    }

    pub(crate) fn from_ir(col: &ColumnIr) -> Self {
        Self {
            name: col.name.clone(),
            col_type: canonical_to_transfer_type(&col.canonical_type),
            is_generated: col.computed.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransferTable {
    pub(crate) name: String,
    pub(crate) columns: Vec<TransferColumn>,
    pub(crate) pk_columns: Vec<String>,
}

impl TransferTable {
    pub(crate) fn from_ir(table: &TableIr) -> Self {
        Self {
            name: table.name.clone(),
            columns: table.columns.iter().map(TransferColumn::from_ir).collect(),
            pk_columns: table.primary_key.columns.clone(),
        }
    }

    pub(crate) fn data_columns(&self) -> impl Iterator<Item = &TransferColumn> {
        self.columns.iter().filter(|c| !c.is_generated)
    }
}

pub(crate) fn canonical_to_transfer_type(ct: &CanonicalType) -> ColumnType {
    match ct {
        CanonicalType::Varchar { length } => {
            ColumnType::Varchar(length.unwrap_or(255).min(u32::from(u16::MAX)) as u16)
        }
        CanonicalType::Char { .. }
        | CanonicalType::Text
        | CanonicalType::MediumText
        | CanonicalType::Enum { .. }
        | CanonicalType::DateTime { .. }
        | CanonicalType::Date
        | CanonicalType::Time { .. }
        | CanonicalType::Custom { .. } => ColumnType::Text,
        CanonicalType::LongText => ColumnType::LongText,
        CanonicalType::SmallInt => ColumnType::SmallInt,
        CanonicalType::Integer => ColumnType::Integer,
        CanonicalType::BigInt => ColumnType::BigInt,
        CanonicalType::SqliteIntElseBigInt => ColumnType::SqliteIntElseBigInt,
        CanonicalType::Serial => ColumnType::Serial,
        CanonicalType::BigSerial => ColumnType::BigSerial,
        CanonicalType::Float | CanonicalType::Double | CanonicalType::Numeric { .. } => {
            ColumnType::Double
        }
        CanonicalType::Boolean => ColumnType::Boolean,
        CanonicalType::Uuid => ColumnType::Uuid,
        CanonicalType::Json | CanonicalType::Jsonb => ColumnType::Json,
        CanonicalType::FixedBinary { length: Some(32) } => ColumnType::FixedBinary32,
        CanonicalType::Blob | CanonicalType::FixedBinary { .. } | CanonicalType::VarBinary { .. } => {
            ColumnType::Blob
        }
    }
}

pub(crate) fn active_schema_subset(base: &SchemaIr, active_extensions: &[String]) -> SchemaIr {
    let ext_set: BTreeSet<&str> = active_extensions.iter().map(String::as_str).collect();
    let mut sub = SchemaIr::new(base.source, base.schema_revision.clone());
    for (name, table) in &base.tables {
        let include = match &table.ownership {
            TableOwnership::Core => true,
            TableOwnership::Extension(_) => ext_set.contains(name.as_str()),
        };
        if include {
            sub.tables.insert(name.clone(), table.clone());
        }
    }
    sub
}

/// Inspect and validate source & target readiness before mutating anything on the target database.
pub async fn inspect_migration_readiness(
    source: &DbPool,
    target: &DbPool,
) -> Result<MigrationPlan> {
    inspect_migration_readiness_with_ir(source, target, None).await
}

/// Inspect and validate source & target readiness against an explicit or built-in [`SchemaIr`].
pub async fn inspect_migration_readiness_with_ir(
    source: &DbPool,
    target: &DbPool,
    schema_ir: Option<&SchemaIr>,
) -> Result<MigrationPlan> {
    let mut warnings = Vec::new();
    let src_compat = source.validate_server_compatibility().await?;
    warnings.extend(src_compat.warnings);
    let dst_compat = target.validate_server_compatibility().await?;
    warnings.extend(dst_compat.warnings);

    let effective_ir = match schema_ir {
        Some(ir) => ir.clone(),
        None => builtin_schema_ir(true),
    };
    let expected_revision = effective_ir
        .schema_revision
        .as_deref()
        .unwrap_or(LATEST_SCHEMA_REVISION);

    let report = SchemaInspector::inspect_against_ir(source, &effective_ir).await?;
    let source_revision = match report.current_revision.as_deref() {
        Some(rev) if rev == expected_revision => rev.to_string(),
        Some(rev) => {
            return Err(CfmsError::SchemaDrift(format!(
                "Source database revision is '{rev}', expected HEAD '{expected_revision}'. Run `cfms-ctl database upgrade` first."
            )));
        }
        None => {
            return Err(CfmsError::SchemaDrift(
                "Source database has no Alembic revision stamped. Run `cfms-ctl database upgrade` first."
                    .to_string(),
            ));
        }
    };

    if !report.missing_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database is missing required CFMS tables: {}",
            report.missing_tables.join(", ")
        )));
    }
    if !report.column_mismatches.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database has column drift against expected schema: {}",
            report.column_mismatches.join("; ")
        )));
    }

    let (known_extensions, unknown_extra) = report.partition_extra_tables();
    if !unknown_extra.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database contains unsupported extra tables: {}",
            unknown_extra.join(", ")
        )));
    }

    if known_extensions.iter().any(|t| t == "user_oidc_credentials") {
        validate_oidc_table(source).await?;
    }

    let target_tables = target.list_tables().await?;
    if !target_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Target database is not empty; found existing tables: {}",
            target_tables.join(", ")
        )));
    }

    let active_ir = active_schema_subset(&effective_ir, &known_extensions);
    let (_, _, ordered_names) = infer_transfer_metadata(&active_ir, target.kind());

    Ok(MigrationPlan {
        source_dialect: source.kind(),
        target_dialect: target.kind(),
        source_revision,
        extension_tables: known_extensions,
        warnings,
        table_count: ordered_names.len(),
    })
}

/// Migrate full CFMS database schema and contents from `source` to an empty `target`,
/// returning per-table canonical SHA-256 verification digests.
pub async fn migrate_database_contents<F>(
    source: &DbPool,
    target: &DbPool,
    on_progress: F,
) -> Result<DatabaseTransferSummary>
where
    F: FnMut(MigrationProgress<'_>),
{
    migrate_database_contents_with_ir(source, target, None, on_progress).await
}

/// Migrate full CFMS database schema and contents using an explicit or built-in [`SchemaIr`].
pub async fn migrate_database_contents_with_ir<F>(
    source: &DbPool,
    target: &DbPool,
    schema_ir: Option<&SchemaIr>,
    mut on_progress: F,
) -> Result<DatabaseTransferSummary>
where
    F: FnMut(MigrationProgress<'_>),
{
    let started = Instant::now();
    let plan = inspect_migration_readiness_with_ir(source, target, schema_ir).await?;
    let base_ir = match schema_ir {
        Some(ir) => ir.clone(),
        None => builtin_schema_ir(true),
    };
    let active_ir = active_schema_subset(&base_ir, &plan.extension_tables);
    let (serial_cols, mut deferred_cols, ordered_names) =
        infer_transfer_metadata(&active_ir, target.kind());

    let use_node_hierarchy_copy = active_ir.tables.contains_key("nodes")
        && active_ir.tables.contains_key("folders")
        && active_ir.tables.contains_key("documents")
        && active_ir
            .tables
            .get("nodes")
            .is_some_and(|n| n.column("parent_id").is_some());
    if use_node_hierarchy_copy
        && let Some(node_deferred) = deferred_cols.get_mut("nodes")
    {
        // Depth-ordered CTE insertion guarantees every parent folder already exists;
        // nulling `nodes.parent_id` would violate `ck_nodes_root_parent`.
        node_deferred.retain(|col| col != "parent_id");
    }

    let tables: Vec<TransferTable> = ordered_names
        .iter()
        .filter_map(|name| active_ir.tables.get(name).map(TransferTable::from_ir))
        .collect();
    let include_oidc = plan
        .extension_tables
        .iter()
        .any(|t| t == "user_oidc_credentials");

    // Progress phases: 1 schema creation + N table transfers + 1 deferred FK restore + N verifications.
    let total_steps = 1 + tables.len() + 1 + tables.len();
    let mut step = 0usize;

    let mut report_progress = |stage: &str| {
        step += 1;
        on_progress(MigrationProgress {
            stage,
            current: step.min(total_steps),
            total: total_steps,
        });
    };

    report_progress("Creating target head schema");
    let create_res = if schema_ir.is_some() {
        let stmts = compile_full_schema_ddl(&active_ir, target.kind());
        execute_ddl_statements(target, &stmts).await
    } else {
        create_head_schema(target, include_oidc).await
    };
    if let Err(err) = create_res {
        let _ = cleanup_target_schema(target).await;
        return Err(err);
    }

    let copy_and_verify: Result<Vec<TableTransferSummary>> = async {
        // Transfer all data rows & deferred columns within a single target write transaction
        // (for atomic/fast bulk ingestion), then verify committed target rows.
        copy_all_tables(source, target, &tables, &deferred_cols, &mut report_progress).await?;
        set_alembic_version(target, &plan.source_revision).await?;
        sync_target_sequences(target, &serial_cols).await?;

        let mut summaries = Vec::with_capacity(tables.len());
        for table in &tables {
            report_progress(&format!("Verifying {}", table.name));
            let summary = verify_table_parity(source, target, table).await?;
            summaries.push(summary);
        }
        Ok(summaries)
    }
    .await;

    match copy_and_verify {
        Ok(tables_summary) => {
            let total_rows = tables_summary.iter().map(|t| t.row_count).sum();
            Ok(DatabaseTransferSummary {
                source_dialect: plan.source_dialect,
                target_dialect: plan.target_dialect,
                table_count: tables_summary.len(),
                total_rows,
                elapsed_ms: started.elapsed().as_millis(),
                extension_tables: plan.extension_tables,
                warnings: plan.warnings,
                tables: tables_summary,
            })
        }
        Err(err) => {
            let _ = cleanup_target_schema(target).await;
            Err(err)
        }
    }
}

async fn cleanup_target_schema(target: &DbPool) -> Result<()> {
    let existing = target.list_tables().await.unwrap_or_default();
    if existing.is_empty() {
        return Ok(());
    }
    drop_all_cfms_tables(target, &existing).await
}

pub(crate) async fn validate_oidc_table(source: &DbPool) -> Result<()> {
    let sql = "SELECT id, issuer, subject, identity_digest FROM user_oidc_credentials";
    const VALIDATE_COLS: &[ColumnDef] = &[
        ColumnDef {
            name: "id",
            col_type: ColumnType::Varchar(32),
            nullable: false,
            default: crate::db::schema::ddl::DefaultClause::None,
            generated_expr: None,
            comment: None,
        },
        ColumnDef {
            name: "issuer",
            col_type: ColumnType::Varchar(512),
            nullable: false,
            default: crate::db::schema::ddl::DefaultClause::None,
            generated_expr: None,
            comment: None,
        },
        ColumnDef {
            name: "subject",
            col_type: ColumnType::Varchar(255),
            nullable: false,
            default: crate::db::schema::ddl::DefaultClause::None,
            generated_expr: None,
            comment: None,
        },
        ColumnDef {
            name: "identity_digest",
            col_type: ColumnType::FixedBinary32,
            nullable: false,
            default: crate::db::schema::ddl::DefaultClause::None,
            generated_expr: None,
            comment: None,
        },
    ];
    let validate_cols: Vec<TransferColumn> = VALIDATE_COLS
        .iter()
        .map(TransferColumn::from_def)
        .collect();
    let mut rows = stream_query(source, sql, &validate_cols).await?;
    while let Some(res) = rows.next().await {
        let row = res?;
        let cred_id = match &row[0] {
            SqlValue::Str(s) => s.as_str(),
            _ => "",
        };
        let issuer = match &row[1] {
            SqlValue::Str(s) => s.as_str(),
            _ => {
                return Err(CfmsError::Extension(format!(
                    "Invalid OIDC credential '{cred_id}': missing issuer"
                )));
            }
        };
        let subject = match &row[2] {
            SqlValue::Str(s) => s.as_str(),
            _ => {
                return Err(CfmsError::Extension(format!(
                    "Invalid OIDC credential '{cred_id}': missing subject"
                )));
            }
        };
        let digest = match &row[3] {
            SqlValue::Bytes(b) => b.as_slice(),
            _ => {
                return Err(CfmsError::Extension(format!(
                    "Invalid OIDC credential '{cred_id}': missing identity_digest"
                )));
            }
        };
        validate_oidc_binding(cred_id, issuer, subject, digest)?;
    }
    Ok(())
}

/// Validate a single OIDC credential binding row against CFMS `oidc_sso` invariants.
pub(crate) fn validate_oidc_binding(
    cred_id: &str,
    issuer: &str,
    subject: &str,
    identity_digest: &[u8],
) -> Result<()> {
    if issuer.is_empty() {
        return Err(CfmsError::Extension(format!(
            "Invalid OIDC credential '{cred_id}': issuer must not be empty"
        )));
    }
    if subject.is_empty() || subject.chars().count() > 255 {
        return Err(CfmsError::Extension(format!(
            "Invalid OIDC credential '{cred_id}': subject must be 1..=255 characters"
        )));
    }
    if identity_digest.len() != 32 {
        return Err(CfmsError::Extension(format!(
            "Invalid OIDC credential '{cred_id}': identity_digest must be 32 bytes, found {}",
            identity_digest.len()
        )));
    }
    let payload = serde_json::to_vec(&[issuer, subject])
        .map_err(|e| CfmsError::Extension(format!("Failed to serialize OIDC identity pair: {e}")))?;
    let expected = Sha256::digest(&payload);
    if identity_digest != expected.as_slice() {
        return Err(CfmsError::Extension(format!(
            "Invalid OIDC credential '{cred_id}': identity_digest mismatch for issuer/subject"
        )));
    }
    Ok(())
}

pub(crate) enum TargetTx<'c> {
    Sqlite(Transaction<'c, Sqlite>),
    Mysql(Transaction<'c, MySql>),
    Postgres(Transaction<'c, Postgres>),
}

impl TargetTx<'_> {
    pub(crate) async fn begin(pool: &DbPool) -> Result<Self> {
        match pool {
            DbPool::Sqlite(p) => Ok(Self::Sqlite(p.begin().await?)),
            DbPool::Mysql(p) => Ok(Self::Mysql(p.begin().await?)),
            DbPool::Postgres(p) => Ok(Self::Postgres(p.begin().await?)),
        }
    }

    pub(crate) async fn commit(self) -> Result<()> {
        match self {
            Self::Sqlite(tx) => tx.commit().await?,
            Self::Mysql(tx) => tx.commit().await?,
            Self::Postgres(tx) => tx.commit().await?,
        }
        Ok(())
    }
}

async fn copy_all_tables<F>(
    source: &DbPool,
    target: &DbPool,
    tables: &[TransferTable],
    deferred_cols: &BTreeMap<String, Vec<String>>,
    report_progress: &mut F,
) -> Result<()>
where
    F: FnMut(&str),
{
    let mut tx = TargetTx::begin(target).await?;
    let nodes_tbl = tables.iter().find(|t| t.name == "nodes");
    let folders_tbl = tables.iter().find(|t| t.name == "folders");
    let documents_tbl = tables.iter().find(|t| t.name == "documents");
    let use_node_hierarchy_copy = nodes_tbl.is_some()
        && folders_tbl.is_some()
        && documents_tbl.is_some()
        && nodes_tbl.is_some_and(|n| n.columns.iter().any(|c| c.name == "parent_id"));

    for table in tables {
        match table.name.as_str() {
            "nodes" if use_node_hierarchy_copy => {
                report_progress("Copying nodes, folders, documents");
                copy_node_tables(
                    source,
                    &mut tx,
                    nodes_tbl.unwrap(),
                    folders_tbl.unwrap(),
                    documents_tbl.unwrap(),
                    deferred_cols,
                )
                .await?;
                report_progress("Copied folders");
                report_progress("Copied documents");
            }
            "folders" | "documents" if use_node_hierarchy_copy => {
                // Already copied depth-by-depth together with `nodes`.
            }
            _ => {
                report_progress(&format!("Copying {}", table.name));
                let deferred = deferred_cols
                    .get(&table.name)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                copy_regular_table(source, &mut tx, table, deferred).await?;
            }
        }
    }

    report_progress("Restoring deferred foreign keys");
    restore_deferred_columns(source, &mut tx, tables, deferred_cols).await?;

    tx.commit().await?;
    Ok(())
}

async fn copy_regular_table(
    source: &DbPool,
    tx: &mut TargetTx<'_>,
    table: &TransferTable,
    deferred: &[String],
) -> Result<()> {
    let data_cols: Vec<TransferColumn> = table.data_columns().cloned().collect();
    let select_sql = build_select_sql(source.kind(), table, &data_cols, false);
    let deferred_indices: Vec<usize> = data_cols
        .iter()
        .enumerate()
        .filter(|(_, c)| deferred.iter().any(|d| d == &c.name))
        .map(|(i, _)| i)
        .collect();

    let batch_size = insert_batch_size(data_cols.len());
    let mut batch: Vec<Vec<SqlValue>> = Vec::with_capacity(batch_size);

    let mut rows = stream_query(source, &select_sql, &data_cols).await?;
    while let Some(res) = rows.next().await {
        let mut row = res?;
        for &idx in &deferred_indices {
            row[idx] = SqlValue::Null;
        }
        batch.push(row);
        if batch.len() >= batch_size {
            insert_batch(tx, &table.name, &data_cols, &batch).await?;
            batch.clear();
        }
    }

    if !batch.is_empty() {
        insert_batch(tx, &table.name, &data_cols, &batch).await?;
    }
    Ok(())
}

async fn copy_node_tables(
    source: &DbPool,
    tx: &mut TargetTx<'_>,
    nodes_def: &TransferTable,
    folders_def: &TransferTable,
    documents_def: &TransferTable,
    deferred_cols: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    let node_cols: Vec<TransferColumn> = nodes_def.data_columns().cloned().collect();
    let folder_cols: Vec<TransferColumn> = folders_def.data_columns().cloned().collect();
    let doc_cols: Vec<TransferColumn> = documents_def.data_columns().cloned().collect();

    let total_source_nodes = count_table_rows(source, "nodes").await?;
    if total_source_nodes == 0 {
        return Ok(());
    }

    let node_deferred = deferred_cols.get("nodes").map(Vec::as_slice).unwrap_or(&[]);
    let folder_deferred = deferred_cols.get("folders").map(Vec::as_slice).unwrap_or(&[]);
    let doc_deferred = deferred_cols.get("documents").map(Vec::as_slice).unwrap_or(&[]);

    // Note `full_row` prepends synthetic `migration_depth` at index 0, so deferred indices shift +1!
    let node_deferred_indices: Vec<usize> = node_cols
        .iter()
        .enumerate()
        .filter(|(_, c)| node_deferred.iter().any(|d| d == &c.name) || c.name == "access_rule_set_id")
        .map(|(i, _)| i + 1)
        .collect();
    let node_id_idx = node_cols
        .iter()
        .position(|c| c.name == "id")
        .ok_or_else(|| CfmsError::Database("Missing nodes.id column".to_string()))?
        + 1;
    let folder_deferred_indices: Vec<usize> = folder_cols
        .iter()
        .enumerate()
        .filter(|(_, c)| folder_deferred.iter().any(|d| d == &c.name))
        .map(|(i, _)| i)
        .collect();
    let doc_deferred_indices: Vec<usize> = doc_cols
        .iter()
        .enumerate()
        .filter(|(_, c)| doc_deferred.iter().any(|d| d == &c.name) || c.name == "current_revision_id")
        .map(|(i, _)| i)
        .collect();

    let (cte_cols, cte_sql) = build_node_hierarchy_cte_sql(source.kind(), &node_cols);

    let batch_limit = NODE_BATCH_SIZE.min(insert_batch_size(node_cols.len()));
    let mut current_depth: Option<i64> = None;
    let mut pending_nodes: Vec<Vec<SqlValue>> = Vec::with_capacity(batch_limit);
    let mut pending_ids: Vec<String> = Vec::with_capacity(batch_limit);
    let mut copied_nodes: u64 = 0;

    let mut rows = stream_query(source, &cte_sql, &cte_cols).await?;
    while let Some(res) = rows.next().await {
        let mut full_row = res?;
        let depth = match &full_row[0] {
            SqlValue::I64(d) => *d,
            other => {
                return Err(CfmsError::Database(format!(
                    "Unexpected CTE migration_depth value: {other:?}"
                )));
            }
        };

        let should_flush = match current_depth {
            Some(prev) if prev != depth => true,
            _ => pending_nodes.len() >= batch_limit,
        };
        if should_flush && !pending_nodes.is_empty() {
            copied_nodes += flush_node_batch(
                source,
                tx,
                &pending_nodes,
                &pending_ids,
                &node_cols,
                &folder_cols,
                &doc_cols,
                &folder_deferred_indices,
                &doc_deferred_indices,
            )
            .await?;
            pending_nodes.clear();
            pending_ids.clear();
        }
        current_depth = Some(depth);

        for &idx in &node_deferred_indices {
            full_row[idx] = SqlValue::Null;
        }
        let node_id = match &full_row[node_id_idx] {
            SqlValue::Str(s) => s.clone(),
            other => {
                return Err(CfmsError::Database(format!(
                    "Unexpected nodes.id value: {other:?}"
                )));
            }
        };
        pending_ids.push(node_id);
        pending_nodes.push(full_row[1..].to_vec());
    }

    if !pending_nodes.is_empty() {
        copied_nodes += flush_node_batch(
            source,
            tx,
            &pending_nodes,
            &pending_ids,
            &node_cols,
            &folder_cols,
            &doc_cols,
            &folder_deferred_indices,
            &doc_deferred_indices,
        )
        .await?;
    }

    if copied_nodes != total_source_nodes {
        return Err(CfmsError::SchemaDrift(format!(
            "Node hierarchy copy mismatch: source has {total_source_nodes} nodes, but recursive tree copied {copied_nodes} (possible disconnected or cyclic parent_id)"
        )));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn flush_node_batch(
    source: &DbPool,
    tx: &mut TargetTx<'_>,
    node_rows: &[Vec<SqlValue>],
    node_ids: &[String],
    node_cols: &[TransferColumn],
    folder_cols: &[TransferColumn],
    doc_cols: &[TransferColumn],
    folder_deferred_indices: &[usize],
    doc_deferred_indices: &[usize],
) -> Result<u64> {
    let mut folder_rows = fetch_rows_by_str_ids(source, "folders", folder_cols, node_ids).await?;
    for &idx in folder_deferred_indices {
        for row in &mut folder_rows {
            row[idx] = SqlValue::Null;
        }
    }
    let mut doc_rows = fetch_rows_by_str_ids(source, "documents", doc_cols, node_ids).await?;
    for &idx in doc_deferred_indices {
        for row in &mut doc_rows {
            row[idx] = SqlValue::Null;
        }
    }

    if folder_rows.len() + doc_rows.len() != node_rows.len() {
        return Err(CfmsError::SchemaDrift(format!(
            "Node subtype integrity violation: {} nodes vs {} folders + {} documents in batch",
            node_rows.len(),
            folder_rows.len(),
            doc_rows.len()
        )));
    }

    insert_batch(tx, "nodes", node_cols, node_rows).await?;
    if !folder_rows.is_empty() {
        insert_batch(tx, "folders", folder_cols, &folder_rows).await?;
    }
    if !doc_rows.is_empty() {
        insert_batch(tx, "documents", doc_cols, &doc_rows).await?;
    }

    Ok(node_rows.len() as u64)
}

async fn restore_deferred_columns(
    source: &DbPool,
    tx: &mut TargetTx<'_>,
    tables: &[TransferTable],
    deferred_cols: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    for (table_name, cols) in deferred_cols {
        if cols.is_empty() {
            continue;
        }
        let table = tables
            .iter()
            .find(|t| t.name == *table_name)
            .ok_or_else(|| CfmsError::Database(format!("Unknown table '{table_name}'")))?;
        let pk_col_name = table.pk_columns.first().ok_or_else(|| {
            CfmsError::Database(format!(
                "Deferred table '{table_name}' has no primary key for deferred FK restoration"
            ))
        })?;
        let pk_def = table
            .columns
            .iter()
            .find(|c| c.name == *pk_col_name)
            .cloned()
            .ok_or_else(|| {
                CfmsError::Database(format!("Missing PK column '{table_name}.{pk_col_name}'"))
            })?;

        for deferred_col_name in cols {
            let val_def = table
                .columns
                .iter()
                .find(|c| c.name == *deferred_col_name)
                .cloned()
                .ok_or_else(|| {
                    CfmsError::Database(format!(
                        "Missing deferred column '{table_name}.{deferred_col_name}'"
                    ))
                })?;
            let pair_cols = [pk_def.clone(), val_def.clone()];
            let sql = format!(
                "SELECT {}, {} FROM {} WHERE {} IS NOT NULL",
                quote_ident(source.kind(), &pk_def.name),
                quote_ident(source.kind(), &val_def.name),
                quote_ident(source.kind(), table_name),
                quote_ident(source.kind(), &val_def.name),
            );

            let mut pairs: Vec<(SqlValue, SqlValue)> =
                Vec::with_capacity(DEFERRED_UPDATE_BATCH_SIZE);
            let mut rows = stream_query(source, &sql, &pair_cols).await?;
            while let Some(res) = rows.next().await {
                let mut row = res?;
                let val = row.pop().expect("pair val");
                let pk = row.pop().expect("pair pk");
                pairs.push((pk, val));
                if pairs.len() >= DEFERRED_UPDATE_BATCH_SIZE {
                    apply_deferred_update_batch(tx, table_name, &pk_def, &val_def, &pairs).await?;
                    pairs.clear();
                }
            }
            if !pairs.is_empty() {
                apply_deferred_update_batch(tx, table_name, &pk_def, &val_def, &pairs).await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn sync_target_sequences(target: &DbPool, serial_cols: &[(String, String)]) -> Result<()> {
    let DbPool::Postgres(pg) = target else {
        return Ok(());
    };
    for (table, col) in serial_cols {
        let sql = format!(
            "SELECT setval(pg_get_serial_sequence('{table}', '{col}'), \
             COALESCE((SELECT MAX({col}) FROM {table}), 1), \
             EXISTS(SELECT 1 FROM {table}))"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql)).execute(pg).await?;
    }
    Ok(())
}

async fn verify_table_parity(
    source: &DbPool,
    target: &DbPool,
    table: &TransferTable,
) -> Result<TableTransferSummary> {
    let src_sql = build_select_sql(source.kind(), table, &table.columns, true);
    let dst_sql = build_select_sql(target.kind(), table, &table.columns, true);

    let (src_res, dst_res) = tokio::join!(
        compute_table_digest(source, &src_sql, &table.columns),
        compute_table_digest(target, &dst_sql, &table.columns),
    );
    let (src_count, src_digest) = src_res?;
    let (dst_count, dst_digest) = dst_res?;

    if src_count != dst_count {
        return Err(CfmsError::Database(format!(
            "Verification failed for table '{}': source row count ({src_count}) != target row count ({dst_count})",
            table.name
        )));
    }
    if src_digest != dst_digest {
        return Err(CfmsError::Database(format!(
            "Verification failed for table '{}': canonical SHA-256 mismatch (source={src_digest}, target={dst_digest})",
            table.name
        )));
    }

    Ok(TableTransferSummary {
        table_name: table.name.to_string(),
        row_count: dst_count,
        sha256_digest: dst_digest,
    })
}

async fn compute_table_digest(
    pool: &DbPool,
    sql: &str,
    columns: &[TransferColumn],
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut rows = stream_query(pool, sql, columns).await?;
    while let Some(res) = rows.next().await {
        let row = res?;
        count += 1;
        hash_canonical_row(&mut hasher, &row)?;
    }
    Ok((count, hex::encode(hasher.finalize())))
}

pub(crate) fn hash_canonical_row(hasher: &mut Sha256, values: &[SqlValue]) -> Result<()> {
    for val in values {
        match val {
            SqlValue::Null => hasher.update([0x00]),
            SqlValue::Bool(b) => {
                hasher.update([0x01, u8::from(*b)]);
            }
            SqlValue::I64(n) => {
                hasher.update([0x02]);
                hasher.update(n.to_be_bytes());
            }
            SqlValue::F64(f) => {
                if !f.is_finite() {
                    return Err(CfmsError::Database(
                        "Cannot hash non-finite float value during migration verification"
                            .to_string(),
                    ));
                }
                let normalized = if *f == 0.0 { 0.0_f64 } else { *f };
                hasher.update([0x03]);
                hasher.update(normalized.to_be_bytes());
            }
            SqlValue::Str(s) => {
                hasher.update([0x04]);
                hasher.update((s.len() as u64).to_be_bytes());
                hasher.update(s.as_bytes());
            }
            SqlValue::Uuid(bytes) => {
                hasher.update([0x05]);
                hasher.update(bytes);
            }
            SqlValue::Bytes(bytes) => {
                hasher.update([0x06]);
                hasher.update((bytes.len() as u64).to_be_bytes());
                hasher.update(bytes);
            }
            SqlValue::Json(v) => {
                let mut canonical = String::new();
                write_canonical_json(v, &mut canonical)?;
                hasher.update([0x07]);
                hasher.update((canonical.len() as u64).to_be_bytes());
                hasher.update(canonical.as_bytes());
            }
        }
    }
    Ok(())
}

pub(crate) fn write_canonical_json(val: &serde_json::Value, out: &mut String) -> Result<()> {
    match val {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                let _ = write!(out, "{i}");
            } else if let Some(u) = num.as_u64() {
                let _ = write!(out, "{u}");
            } else if let Some(f) = num.as_f64() {
                if !f.is_finite() {
                    return Err(CfmsError::Database(
                        "Non-finite float inside JSON column".to_string(),
                    ));
                }
                let norm = if f == 0.0 { 0.0_f64 } else { f };
                let s = serde_json::to_string(&norm).map_err(|e| {
                    CfmsError::Database(format!("Failed to format JSON float: {e}"))
                })?;
                out.push_str(&s);
            } else {
                out.push_str(&num.to_string());
            }
        }
        serde_json::Value::String(s) => {
            let encoded = serde_json::to_string(s)
                .map_err(|e| CfmsError::Database(format!("Failed to encode JSON string: {e}")))?;
            out.push_str(&encoded);
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&str, &serde_json::Value> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let encoded_key = serde_json::to_string(k).map_err(|e| {
                    CfmsError::Database(format!("Failed to encode JSON object key: {e}"))
                })?;
                out.push_str(&encoded_key);
                out.push(':');
                write_canonical_json(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub(crate) fn build_node_hierarchy_cte_sql(
    kind: DatabaseKind,
    node_cols: &[TransferColumn],
) -> (Vec<TransferColumn>, String) {
    let mut cte_cols = Vec::with_capacity(1 + node_cols.len());
    cte_cols.push(TransferColumn {
        name: "migration_depth".to_string(),
        col_type: ColumnType::BigInt,
        is_generated: false,
    });
    cte_cols.extend(node_cols.iter().cloned());

    let qualified_node_cols = node_cols
        .iter()
        .map(|c| format!("child.{}", quote_ident(kind, &c.name)))
        .collect::<Vec<_>>()
        .join(", ");
    let order_id_col = text_order_expr(kind, "child.id");

    let cte_sql = format!(
        "WITH RECURSIVE migration_node_hierarchy (id, migration_depth) AS (\n\
            SELECT id, 0 AS migration_depth FROM nodes WHERE parent_id IS NULL\n\
            UNION ALL\n\
            SELECT child.id, parent.migration_depth + 1 AS migration_depth \
            FROM nodes child \
            JOIN migration_node_hierarchy parent ON child.parent_id = parent.id\n\
        )\n\
        SELECT h.migration_depth, {qualified_node_cols} \
        FROM migration_node_hierarchy h \
        JOIN nodes child ON child.id = h.id \
        ORDER BY h.migration_depth ASC, {order_id_col} ASC"
    );
    (cte_cols, cte_sql)
}

pub(crate) fn insert_batch_size(col_count: usize) -> usize {
    MAX_INSERT_ROWS_PER_BATCH.min((MAX_BIND_PARAMS_PER_BATCH / col_count.max(1)).max(1))
}

pub(crate) fn quote_ident(kind: DatabaseKind, ident: &str) -> String {
    match kind {
        DatabaseKind::Mysql => format!("`{}`", ident.replace('`', "``")),
        DatabaseKind::Sqlite | DatabaseKind::Postgresql => {
            format!("\"{}\"", ident.replace('"', "\"\""))
        }
    }
}

pub(crate) fn placeholder(kind: DatabaseKind, idx_1_based: usize) -> String {
    match kind {
        DatabaseKind::Postgresql => format!("${idx_1_based}"),
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "?".to_string(),
    }
}

pub(crate) fn text_order_expr(kind: DatabaseKind, col_expr: &str) -> String {
    match kind {
        DatabaseKind::Sqlite => format!("{col_expr} COLLATE BINARY"),
        DatabaseKind::Mysql => format!("{col_expr} COLLATE utf8mb4_bin"),
        DatabaseKind::Postgresql => format!("{col_expr} COLLATE \"C\""),
    }
}

pub(crate) fn build_select_sql(
    kind: DatabaseKind,
    table: &TransferTable,
    columns: &[TransferColumn],
    order_by_pk: bool,
) -> String {
    build_filtered_select_sql(kind, table, columns, None, order_by_pk)
}

pub(crate) fn build_filtered_select_sql(
    kind: DatabaseKind,
    table: &TransferTable,
    columns: &[TransferColumn],
    where_clause: Option<&str>,
    order_by_pk: bool,
) -> String {
    let col_list = columns
        .iter()
        .map(|c| quote_ident(kind, &c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let mut sql = format!("SELECT {col_list} FROM {}", quote_ident(kind, &table.name));
    if let Some(clause) = where_clause {
        sql.push_str(" WHERE ");
        sql.push_str(clause);
    }
    if order_by_pk && !table.pk_columns.is_empty() {
        let mut order_terms = Vec::with_capacity(table.pk_columns.len());
        for pk_name in &table.pk_columns {
            let quoted = quote_ident(kind, pk_name);
            let is_text = table
                .columns
                .iter()
                .find(|c| c.name == *pk_name)
                .is_some_and(|c| {
                    matches!(
                        c.col_type,
                        ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText
                    )
                });
            if is_text {
                order_terms.push(format!("{} ASC", text_order_expr(kind, &quoted)));
            } else {
                order_terms.push(format!("{quoted} ASC"));
            }
        }
        sql.push_str(" ORDER BY ");
        sql.push_str(&order_terms.join(", "));
    }
    sql
}

pub(crate) async fn count_table_rows(pool: &DbPool, table_name: &str) -> Result<u64> {
    let sql = format!("SELECT COUNT(*) FROM {}", quote_ident(pool.kind(), table_name));
    let cnt: i64 = match pool {
        DbPool::Sqlite(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(p).await?,
        DbPool::Mysql(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(p).await?,
        DbPool::Postgres(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(p).await?,
    };
    u64::try_from(cnt).map_err(|_| CfmsError::Database(format!("Negative row count: {cnt}")))
}

pub(crate) async fn fetch_rows_by_str_ids(
    pool: &DbPool,
    table_name: &str,
    columns: &[TransferColumn],
    ids: &[String],
) -> Result<Vec<Vec<SqlValue>>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let kind = pool.kind();
    let col_list = columns
        .iter()
        .map(|c| quote_ident(kind, &c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (1..=ids.len())
        .map(|i| placeholder(kind, i))
        .collect::<Vec<_>>()
        .join(", ");
    let id_col = quote_ident(kind, "id");
    let order_id = text_order_expr(kind, &id_col);
    let sql = format!(
        "SELECT {col_list} FROM {} WHERE {id_col} IN ({placeholders}) ORDER BY {order_id} ASC",
        quote_ident(kind, table_name),
    );

    let out = match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for id in ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            rows.into_iter()
                .map(|r| decode_sqlite_row(&r, columns))
                .collect::<Result<Vec<_>>>()?
        }
        DbPool::Mysql(p) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for id in ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            rows.into_iter()
                .map(|r| decode_mysql_row(&r, columns))
                .collect::<Result<Vec<_>>>()?
        }
        DbPool::Postgres(p) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for id in ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            rows.into_iter()
                .map(|r| decode_postgres_row(&r, columns))
                .collect::<Result<Vec<_>>>()?
        }
    };
    Ok(out)
}

pub(crate) async fn stream_query<'a>(
    pool: &'a DbPool,
    sql: &str,
    columns: &'a [TransferColumn],
) -> Result<futures_util::stream::BoxStream<'a, Result<Vec<SqlValue>>>> {
    let sql_owned = sql.to_string();
    let stream: futures_util::stream::BoxStream<'a, Result<Vec<SqlValue>>> = match pool {
        DbPool::Sqlite(p) => Box::pin(
            sqlx::query(sqlx::AssertSqlSafe(sql_owned))
                .fetch(p)
                .map(move |res| match res {
                    Ok(row) => decode_sqlite_row(&row, columns),
                    Err(e) => Err(CfmsError::from(e)),
                }),
        ),
        DbPool::Mysql(p) => Box::pin(
            sqlx::query(sqlx::AssertSqlSafe(sql_owned))
                .fetch(p)
                .map(move |res| match res {
                    Ok(row) => decode_mysql_row(&row, columns),
                    Err(e) => Err(CfmsError::from(e)),
                }),
        ),
        DbPool::Postgres(p) => Box::pin(
            sqlx::query(sqlx::AssertSqlSafe(sql_owned))
                .fetch(p)
                .map(move |res| match res {
                    Ok(row) => decode_postgres_row(&row, columns),
                    Err(e) => Err(CfmsError::from(e)),
                }),
        ),
    };
    Ok(stream)
}

fn decode_sqlite_row(row: &SqliteRow, columns: &[TransferColumn]) -> Result<Vec<SqlValue>> {
    let mut out = Vec::with_capacity(columns.len());
    for (idx, col) in columns.iter().enumerate() {
        let val = match col.col_type {
            ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText => row
                .try_get::<Option<String>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Str),
            ColumnType::SmallInt
            | ColumnType::Integer
            | ColumnType::BigInt
            | ColumnType::SqliteIntElseBigInt
            | ColumnType::Serial
            | ColumnType::BigSerial => row
                .try_get::<Option<i64>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::I64),
            ColumnType::Double => decode_opt_f64(&col.name, row.try_get::<Option<f64>, _>(idx)?)?,
            ColumnType::Boolean => row
                .try_get::<Option<bool>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Bool),
            ColumnType::Uuid => decode_opt_uuid_str(&col.name, row.try_get::<Option<String>, _>(idx)?)?,
            ColumnType::Blob | ColumnType::FixedBinary32 => row
                .try_get::<Option<Vec<u8>>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Bytes),
            ColumnType::Json => row
                .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>(idx)?
                .map_or(SqlValue::Null, |j| SqlValue::Json(j.0)),
        };
        out.push(val);
    }
    Ok(out)
}

fn decode_mysql_row(row: &MySqlRow, columns: &[TransferColumn]) -> Result<Vec<SqlValue>> {
    let mut out = Vec::with_capacity(columns.len());
    for (idx, col) in columns.iter().enumerate() {
        let val = match col.col_type {
            ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText => row
                .try_get::<Option<String>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Str),
            ColumnType::SmallInt => row
                .try_get::<Option<i16>, _>(idx)?
                .map_or(SqlValue::Null, |v| SqlValue::I64(i64::from(v))),
            ColumnType::Integer | ColumnType::Serial => row
                .try_get::<Option<i32>, _>(idx)?
                .map_or(SqlValue::Null, |v| SqlValue::I64(i64::from(v))),
            ColumnType::BigInt | ColumnType::SqliteIntElseBigInt | ColumnType::BigSerial => row
                .try_get::<Option<i64>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::I64),
            ColumnType::Double => decode_opt_f64(&col.name, row.try_get::<Option<f64>, _>(idx)?)?,
            ColumnType::Boolean => row
                .try_get::<Option<bool>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Bool),
            ColumnType::Uuid => decode_opt_uuid_str(&col.name, row.try_get::<Option<String>, _>(idx)?)?,
            ColumnType::Blob | ColumnType::FixedBinary32 => row
                .try_get::<Option<Vec<u8>>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Bytes),
            ColumnType::Json => row
                .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>(idx)?
                .map_or(SqlValue::Null, |j| SqlValue::Json(j.0)),
        };
        out.push(val);
    }
    Ok(out)
}

fn decode_postgres_row(row: &PgRow, columns: &[TransferColumn]) -> Result<Vec<SqlValue>> {
    let mut out = Vec::with_capacity(columns.len());
    for (idx, col) in columns.iter().enumerate() {
        let val = match col.col_type {
            ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText => row
                .try_get::<Option<String>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Str),
            ColumnType::SmallInt => row
                .try_get::<Option<i16>, _>(idx)?
                .map_or(SqlValue::Null, |v| SqlValue::I64(i64::from(v))),
            ColumnType::Integer | ColumnType::Serial => row
                .try_get::<Option<i32>, _>(idx)?
                .map_or(SqlValue::Null, |v| SqlValue::I64(i64::from(v))),
            ColumnType::BigInt | ColumnType::SqliteIntElseBigInt | ColumnType::BigSerial => row
                .try_get::<Option<i64>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::I64),
            ColumnType::Double => decode_opt_f64(&col.name, row.try_get::<Option<f64>, _>(idx)?)?,
            ColumnType::Boolean => row
                .try_get::<Option<bool>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Bool),
            ColumnType::Uuid => row
                .try_get::<Option<Uuid>, _>(idx)?
                .map_or(SqlValue::Null, |u| SqlValue::Uuid(*u.as_bytes())),
            ColumnType::Blob | ColumnType::FixedBinary32 => row
                .try_get::<Option<Vec<u8>>, _>(idx)?
                .map_or(SqlValue::Null, SqlValue::Bytes),
            ColumnType::Json => row
                .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>(idx)?
                .map_or(SqlValue::Null, |j| SqlValue::Json(j.0)),
        };
        out.push(val);
    }
    Ok(out)
}

fn decode_opt_f64(col_name: &str, opt: Option<f64>) -> Result<SqlValue> {
    let Some(v) = opt else {
        return Ok(SqlValue::Null);
    };
    if !v.is_finite() {
        return Err(CfmsError::Database(format!(
            "Non-finite floating point value in column '{col_name}'"
        )));
    }
    Ok(SqlValue::F64(if v == 0.0 { 0.0_f64 } else { v }))
}

fn decode_opt_uuid_str(col_name: &str, opt: Option<String>) -> Result<SqlValue> {
    let Some(s) = opt else {
        return Ok(SqlValue::Null);
    };
    let u = Uuid::parse_str(s.trim()).map_err(|e| {
        CfmsError::Database(format!("Invalid UUID string '{s}' in column '{col_name}': {e}"))
    })?;
    Ok(SqlValue::Uuid(*u.as_bytes()))
}

pub(crate) async fn insert_batch(
    tx: &mut TargetTx<'_>,
    table_name: &str,
    columns: &[TransferColumn],
    rows: &[Vec<SqlValue>],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let kind = match tx {
        TargetTx::Sqlite(_) => DatabaseKind::Sqlite,
        TargetTx::Mysql(_) => DatabaseKind::Mysql,
        TargetTx::Postgres(_) => DatabaseKind::Postgresql,
    };

    let col_list = columns
        .iter()
        .map(|c| quote_ident(kind, &c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let mut param_idx = 0usize;
    let mut row_tuples = Vec::with_capacity(rows.len());
    for _ in rows {
        let mut phs = Vec::with_capacity(columns.len());
        for _ in columns {
            param_idx += 1;
            phs.push(placeholder(kind, param_idx));
        }
        row_tuples.push(format!("({})", phs.join(", ")));
    }

    let sql = format!(
        "INSERT INTO {} ({col_list}) VALUES {}",
        quote_ident(kind, table_name),
        row_tuples.join(", ")
    );

    match tx {
        TargetTx::Sqlite(inner) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for row in rows {
                for (col, val) in columns.iter().zip(row.iter()) {
                    q = bind_sqlite(q, col, val)?;
                }
            }
            q.execute(&mut **inner).await?;
        }
        TargetTx::Mysql(inner) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for row in rows {
                for (col, val) in columns.iter().zip(row.iter()) {
                    q = bind_mysql(q, col, val)?;
                }
            }
            q.execute(&mut **inner).await?;
        }
        TargetTx::Postgres(inner) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for row in rows {
                for (col, val) in columns.iter().zip(row.iter()) {
                    q = bind_postgres(q, col, val)?;
                }
            }
            q.execute(&mut **inner).await?;
        }
    }

    Ok(())
}

pub(crate) async fn apply_deferred_update_batch(
    tx: &mut TargetTx<'_>,
    table_name: &str,
    pk_col: &TransferColumn,
    val_col: &TransferColumn,
    pairs: &[(SqlValue, SqlValue)],
) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let kind = match tx {
        TargetTx::Sqlite(_) => DatabaseKind::Sqlite,
        TargetTx::Mysql(_) => DatabaseKind::Mysql,
        TargetTx::Postgres(_) => DatabaseKind::Postgresql,
    };

    let tq = quote_ident(kind, table_name);
    let pkq = quote_ident(kind, &pk_col.name);
    let vq = quote_ident(kind, &val_col.name);

    let mut idx = 0usize;
    let mut when_clauses = Vec::with_capacity(pairs.len());
    for _ in pairs {
        idx += 1;
        let p_when = placeholder(kind, idx);
        idx += 1;
        let p_then = placeholder(kind, idx);
        when_clauses.push(format!("WHEN {pkq} = {p_when} THEN {p_then}"));
    }
    let mut in_clauses = Vec::with_capacity(pairs.len());
    for _ in pairs {
        idx += 1;
        in_clauses.push(placeholder(kind, idx));
    }

    let sql = format!(
        "UPDATE {tq} SET {vq} = CASE {} END WHERE {pkq} IN ({})",
        when_clauses.join(" "),
        in_clauses.join(", ")
    );

    match tx {
        TargetTx::Sqlite(inner) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for (pk, val) in pairs {
                q = bind_sqlite(q, pk_col, pk)?;
                q = bind_sqlite(q, val_col, val)?;
            }
            for (pk, _) in pairs {
                q = bind_sqlite(q, pk_col, pk)?;
            }
            q.execute(&mut **inner).await?;
        }
        TargetTx::Mysql(inner) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for (pk, val) in pairs {
                q = bind_mysql(q, pk_col, pk)?;
                q = bind_mysql(q, val_col, val)?;
            }
            for (pk, _) in pairs {
                q = bind_mysql(q, pk_col, pk)?;
            }
            q.execute(&mut **inner).await?;
        }
        TargetTx::Postgres(inner) => {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for (pk, val) in pairs {
                q = bind_postgres(q, pk_col, pk)?;
                q = bind_postgres(q, val_col, val)?;
            }
            for (pk, _) in pairs {
                q = bind_postgres(q, pk_col, pk)?;
            }
            q.execute(&mut **inner).await?;
        }
    }

    Ok(())
}

fn bind_sqlite<'q>(
    q: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments>,
    col: &TransferColumn,
    val: &'q SqlValue,
) -> Result<sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments>> {
    let q = match (col.col_type, val) {
        (_, SqlValue::Null) => match col.col_type {
            ColumnType::Varchar(_)
            | ColumnType::Text
            | ColumnType::LongText
            | ColumnType::Uuid
            | ColumnType::Json => q.bind(Option::<String>::None),
            ColumnType::SmallInt
            | ColumnType::Integer
            | ColumnType::BigInt
            | ColumnType::SqliteIntElseBigInt
            | ColumnType::Serial
            | ColumnType::BigSerial => q.bind(Option::<i64>::None),
            ColumnType::Double => q.bind(Option::<f64>::None),
            ColumnType::Boolean => q.bind(Option::<bool>::None),
            ColumnType::Blob | ColumnType::FixedBinary32 => q.bind(Option::<Vec<u8>>::None),
        },
        (ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText, SqlValue::Str(s)) => {
            q.bind(s.as_str())
        }
        (
            ColumnType::SmallInt
            | ColumnType::Integer
            | ColumnType::BigInt
            | ColumnType::SqliteIntElseBigInt
            | ColumnType::Serial
            | ColumnType::BigSerial,
            SqlValue::I64(n),
        ) => q.bind(*n),
        (ColumnType::Double, SqlValue::F64(f)) => q.bind(*f),
        (ColumnType::Boolean, SqlValue::Bool(b)) => q.bind(*b),
        (ColumnType::Uuid, SqlValue::Uuid(bytes)) => {
            q.bind(Uuid::from_bytes(*bytes).simple().to_string())
        }
        (ColumnType::Blob | ColumnType::FixedBinary32, SqlValue::Bytes(b)) => q.bind(b.as_slice()),
        (ColumnType::Json, SqlValue::Json(v)) => q.bind(sqlx::types::Json(v)),
        (_, other) => {
            return Err(CfmsError::Database(format!(
                "Type mismatch binding SQLite column '{}': {:?} vs {other:?}",
                col.name, col.col_type
            )));
        }
    };
    Ok(q)
}

fn bind_mysql<'q>(
    q: sqlx::query::Query<'q, MySql, sqlx::mysql::MySqlArguments>,
    col: &TransferColumn,
    val: &'q SqlValue,
) -> Result<sqlx::query::Query<'q, MySql, sqlx::mysql::MySqlArguments>> {
    let q = match (col.col_type, val) {
        (_, SqlValue::Null) => match col.col_type {
            ColumnType::Varchar(_)
            | ColumnType::Text
            | ColumnType::LongText
            | ColumnType::Uuid => q.bind(Option::<String>::None),
            ColumnType::SmallInt => q.bind(Option::<i16>::None),
            ColumnType::Integer | ColumnType::Serial => q.bind(Option::<i32>::None),
            ColumnType::BigInt | ColumnType::SqliteIntElseBigInt | ColumnType::BigSerial => {
                q.bind(Option::<i64>::None)
            }
            ColumnType::Double => q.bind(Option::<f64>::None),
            ColumnType::Boolean => q.bind(Option::<bool>::None),
            ColumnType::Blob | ColumnType::FixedBinary32 => q.bind(Option::<Vec<u8>>::None),
            ColumnType::Json => q.bind(Option::<sqlx::types::Json<serde_json::Value>>::None),
        },
        (ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText, SqlValue::Str(s)) => {
            q.bind(s.as_str())
        }
        (ColumnType::SmallInt, SqlValue::I64(n)) => {
            let v = i16::try_from(*n).map_err(|_| {
                CfmsError::Database(format!("SMALLINT overflow for column '{}': {n}", col.name))
            })?;
            q.bind(v)
        }
        (ColumnType::Integer | ColumnType::Serial, SqlValue::I64(n)) => {
            let v = i32::try_from(*n).map_err(|_| {
                CfmsError::Database(format!("INTEGER overflow for column '{}': {n}", col.name))
            })?;
            q.bind(v)
        }
        (
            ColumnType::BigInt | ColumnType::SqliteIntElseBigInt | ColumnType::BigSerial,
            SqlValue::I64(n),
        ) => q.bind(*n),
        (ColumnType::Double, SqlValue::F64(f)) => q.bind(*f),
        (ColumnType::Boolean, SqlValue::Bool(b)) => q.bind(*b),
        (ColumnType::Uuid, SqlValue::Uuid(bytes)) => {
            q.bind(Uuid::from_bytes(*bytes).simple().to_string())
        }
        (ColumnType::Blob | ColumnType::FixedBinary32, SqlValue::Bytes(b)) => q.bind(b.as_slice()),
        (ColumnType::Json, SqlValue::Json(v)) => q.bind(sqlx::types::Json(v)),
        (_, other) => {
            return Err(CfmsError::Database(format!(
                "Type mismatch binding MySQL column '{}': {:?} vs {other:?}",
                col.name, col.col_type
            )));
        }
    };
    Ok(q)
}

fn bind_postgres<'q>(
    q: sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>,
    col: &TransferColumn,
    val: &'q SqlValue,
) -> Result<sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>> {
    let q = match (col.col_type, val) {
        (_, SqlValue::Null) => match col.col_type {
            ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText => {
                q.bind(Option::<String>::None)
            }
            ColumnType::SmallInt => q.bind(Option::<i16>::None),
            ColumnType::Integer | ColumnType::Serial => q.bind(Option::<i32>::None),
            ColumnType::BigInt | ColumnType::SqliteIntElseBigInt | ColumnType::BigSerial => {
                q.bind(Option::<i64>::None)
            }
            ColumnType::Double => q.bind(Option::<f64>::None),
            ColumnType::Boolean => q.bind(Option::<bool>::None),
            ColumnType::Uuid => q.bind(Option::<Uuid>::None),
            ColumnType::Blob | ColumnType::FixedBinary32 => q.bind(Option::<Vec<u8>>::None),
            ColumnType::Json => q.bind(Option::<sqlx::types::Json<serde_json::Value>>::None),
        },
        (ColumnType::Varchar(_) | ColumnType::Text | ColumnType::LongText, SqlValue::Str(s)) => {
            q.bind(s.as_str())
        }
        (ColumnType::SmallInt, SqlValue::I64(n)) => {
            let v = i16::try_from(*n).map_err(|_| {
                CfmsError::Database(format!("SMALLINT overflow for column '{}': {n}", col.name))
            })?;
            q.bind(v)
        }
        (ColumnType::Integer | ColumnType::Serial, SqlValue::I64(n)) => {
            let v = i32::try_from(*n).map_err(|_| {
                CfmsError::Database(format!("INTEGER overflow for column '{}': {n}", col.name))
            })?;
            q.bind(v)
        }
        (
            ColumnType::BigInt | ColumnType::SqliteIntElseBigInt | ColumnType::BigSerial,
            SqlValue::I64(n),
        ) => q.bind(*n),
        (ColumnType::Double, SqlValue::F64(f)) => q.bind(*f),
        (ColumnType::Boolean, SqlValue::Bool(b)) => q.bind(*b),
        (ColumnType::Uuid, SqlValue::Uuid(bytes)) => q.bind(Uuid::from_bytes(*bytes)),
        (ColumnType::Blob | ColumnType::FixedBinary32, SqlValue::Bytes(b)) => q.bind(b.as_slice()),
        (ColumnType::Json, SqlValue::Json(v)) => q.bind(sqlx::types::Json(v)),
        (_, other) => {
            return Err(CfmsError::Database(format!(
                "Type mismatch binding PostgreSQL column '{}': {:?} vs {other:?}",
                col.name, col.col_type
            )));
        }
    };
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use tempfile::tempdir;

    async fn open_sqlite_file(path: &std::path::Path) -> DbPool {
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("sqlite connect");
        DbPool::Sqlite(pool)
    }

    #[test]
    fn canonical_json_hash_normalizes_key_order_numbers_and_distinguishes_nulls() {
        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();
        let v1: serde_json::Value = serde_json::from_str(r#"{"b": 2, "a": {"z": 1, "m": 1e2}}"#)
            .expect("parse json 1");
        let v2: serde_json::Value = serde_json::from_str(r#"{"a":{"m":100.0,"z":1},"b":2}"#)
            .expect("parse json 2");

        hash_canonical_row(&mut h1, &[SqlValue::Json(v1)]).unwrap();
        hash_canonical_row(&mut h2, &[SqlValue::Json(v2)]).unwrap();
        assert_eq!(h1.finalize(), h2.finalize());

        // SQL NULL != JSON null
        let mut h_sql_null = Sha256::new();
        let mut h_json_null = Sha256::new();
        hash_canonical_row(&mut h_sql_null, &[SqlValue::Null]).unwrap();
        hash_canonical_row(&mut h_json_null, &[SqlValue::Json(serde_json::Value::Null)]).unwrap();
        assert_ne!(h_sql_null.finalize(), h_json_null.finalize());
    }

    #[test]
    fn float_negative_zero_and_uuid_bytes_hash_canonically() {
        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();
        let mut f1 = -0.0_f64;
        if f1 == 0.0 {
            f1 = 0.0;
        }
        hash_canonical_row(&mut h1, &[SqlValue::F64(f1)]).unwrap();
        hash_canonical_row(&mut h2, &[SqlValue::F64(-0.0_f64)]).unwrap();
        assert_eq!(h1.finalize(), h2.finalize());

        let u_hex = Uuid::parse_str("00112233445566778899aabbccddeeff").unwrap();
        let u_hy = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let mut u1 = Sha256::new();
        let mut u2 = Sha256::new();
        hash_canonical_row(&mut u1, &[SqlValue::Uuid(*u_hex.as_bytes())]).unwrap();
        hash_canonical_row(&mut u2, &[SqlValue::Uuid(*u_hy.as_bytes())]).unwrap();
        assert_eq!(u1.finalize(), u2.finalize());
    }

    #[test]
    fn oidc_binding_validation_enforces_rules() {
        let payload = serde_json::to_vec(&["https://accounts.example.com", "sub-123"]).unwrap();
        let digest = Sha256::digest(&payload);
        assert!(validate_oidc_binding(
            "cred-1",
            "https://accounts.example.com",
            "sub-123",
            &digest
        )
        .is_ok());

        let mut bad_digest = digest.to_vec();
        bad_digest[0] ^= 0xff;
        assert!(validate_oidc_binding(
            "cred-1",
            "https://accounts.example.com",
            "sub-123",
            &bad_digest
        )
        .is_err());

        assert!(validate_oidc_binding("cred-2", "", "sub", &digest).is_err());
        assert!(validate_oidc_binding("cred-3", "https://iss", "", &digest).is_err());
        assert!(
            validate_oidc_binding("cred-4", "https://iss", &"a".repeat(256), &digest).is_err()
        );
    }

    #[tokio::test]
    async fn end_to_end_sqlite_to_sqlite_migration_handles_cycles_trees_and_oidc() {
        let dir = tempdir().unwrap();
        let src_path = dir.path().join("source.db");
        let dst_path = dir.path().join("target.db");

        let source = open_sqlite_file(&src_path).await;
        let target = open_sqlite_file(&dst_path).await;

        create_head_schema(&source, true).await.unwrap();
        set_alembic_version(&source, LATEST_SCHEMA_REVISION)
            .await
            .unwrap();

        let DbPool::Sqlite(src_p) = &source else {
            unreachable!();
        };

        let uid = Uuid::new_v4();
        let uid_hex = uid.simple().to_string();

        // Populate complex cyclic FKs, nested folder/document hierarchy, mixed-case PKs, JSON, floats, and OIDC.
        sqlx::query("INSERT INTO files (id, sha256, path, size, created_time, active) VALUES (?, ?, ?, ?, ?, ?)")
            .bind("file-1")
            .bind("abc")
            .bind("/objects/file-1")
            .bind(128i64)
            .bind(1.0_f64)
            .bind(true)
            .execute(src_p)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO users (id, username, nickname, created_time, status, secret_key, preference_dek_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&uid_hex)
        .bind("alice")
        .bind("Alice")
        .bind(1.0_f64)
        .bind(0i64)
        .bind("a".repeat(64))
        .bind(Option::<String>::None)
        .execute(src_p)
        .await
        .unwrap();

        sqlx::query("INSERT INTO keyrings (id, user_id, content, label, created_time) VALUES (?, ?, ?, ?, ?)")
            .bind("dek-1")
            .bind(&uid_hex)
            .bind("{\"encrypted\":true}")
            .bind("primary")
            .bind(123.5_f64)
            .execute(src_p)
            .await
            .unwrap();

        sqlx::query("UPDATE users SET preference_dek_id = ? WHERE id = ?")
            .bind("dek-1")
            .bind(&uid_hex)
            .execute(src_p)
            .await
            .unwrap();

        let oidc_digest = Sha256::digest(
            serde_json::to_vec(&["https://idp.example.com", "alice-sub"]).unwrap(),
        );
        sqlx::query(
            "INSERT INTO user_oidc_credentials (id, user_id, issuer, subject, identity_digest) VALUES (?, ?, ?, ?, ?)",
        )
        .bind("oidc-1")
        .bind(&uid_hex)
        .bind("https://idp.example.com")
        .bind("alice-sub")
        .bind(oidc_digest.as_slice())
        .execute(src_p)
        .await
        .unwrap();

        // Deep folder hierarchy: / -> /docs (Aa & aA mixed-case ordering check) -> /docs/spec.txt
        sqlx::query("INSERT INTO nodes (id, type, name, parent_id, inherit, status, status_operation_id, access_rule_set_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind("/")
            .bind("directory")
            .bind("/")
            .bind(Option::<String>::None)
            .bind(true)
            .bind(0i64)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .execute(src_p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO folders (id, created_time) VALUES ('/', 1.0)")
            .execute(src_p)
            .await
            .unwrap();

        for (fid, name) in [("/Aa", "Aa"), ("/aA", "aA"), ("/docs", "docs")] {
            sqlx::query("INSERT INTO nodes (id, type, name, parent_id, inherit, status) VALUES (?, 'directory', ?, '/', 1, 0)")
                .bind(fid)
                .bind(name)
                .execute(src_p)
                .await
                .unwrap();
            sqlx::query("INSERT INTO folders (id, created_time) VALUES (?, 2.0)")
                .bind(fid)
                .execute(src_p)
                .await
                .unwrap();
        }

        sqlx::query("INSERT INTO nodes (id, type, name, parent_id, inherit, status) VALUES ('/docs/readme', 'file', 'readme', '/docs', 1, 0)")
            .execute(src_p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO documents (id, created_time, current_revision_id) VALUES ('/docs/readme', 3.0, NULL)")
            .execute(src_p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO document_revisions (id, document_id, file_id, created_time, parent_revision_id, status) VALUES ('rev-1', '/docs/readme', 'file-1', 3.0, NULL, 0)")
            .execute(src_p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO document_revisions (id, document_id, file_id, created_time, parent_revision_id, status) VALUES ('rev-2', '/docs/readme', 'file-1', 4.0, 'rev-1', 0)")
            .execute(src_p)
            .await
            .unwrap();
        sqlx::query("UPDATE documents SET current_revision_id = 'rev-2' WHERE id = '/docs/readme'")
            .execute(src_p)
            .await
            .unwrap();

        sqlx::query("INSERT INTO compiled_access_rule_sets (id, node_id, created_at) VALUES ('ars-1', '/docs/readme', 5.0)")
            .execute(src_p)
            .await
            .unwrap();
        sqlx::query("UPDATE nodes SET access_rule_set_id = 'ars-1' WHERE id = '/docs/readme'")
            .execute(src_p)
            .await
            .unwrap();

        // JSON column with arbitrary key order & -0.0 float edge case
        sqlx::query("INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind("aud-1")
            .bind("login")
            .bind(&uid_hex)
            .bind("user:alice")
            .bind(r#"{"z":1,"a":[true,null,-0.0]}"#)
            .bind(0i64)
            .bind("127.0.0.1")
            .bind(-0.0_f64)
            .execute(src_p)
            .await
            .unwrap();

        let mut progress_events = 0usize;
        let summary = migrate_database_contents(&source, &target, |_| {
            progress_events += 1;
        })
        .await
        .expect("sqlite->sqlite migration");

        assert!(progress_events >= 10);
        assert_eq!(summary.table_count, 41);
        assert_eq!(summary.extension_tables, vec!["user_oidc_credentials"]);
        assert_eq!(
            target.current_revision().await.unwrap().as_deref(),
            Some(LATEST_SCHEMA_REVISION)
        );
        let dst_inspector = SchemaInspector::inspect(&target).await.unwrap();
        assert!(dst_inspector.healthy);
        assert_eq!(dst_inspector.extra_tables, vec!["user_oidc_credentials"]);

        let DbPool::Sqlite(dst_p) = &target else {
            unreachable!();
        };
        let active_name: Option<String> =
            sqlx::query_scalar("SELECT active_name FROM nodes WHERE id = '/docs/readme'")
                .fetch_one(dst_p)
                .await
                .unwrap();
        assert_eq!(active_name.as_deref(), Some("readme"));
        let pref_dek: Option<String> =
            sqlx::query_scalar("SELECT preference_dek_id FROM users WHERE username = 'alice'")
                .fetch_one(dst_p)
                .await
                .unwrap();
        assert_eq!(pref_dek.as_deref(), Some("dek-1"));

        // Non-empty target must be rejected cleanly before mutating anything
        let err = migrate_database_contents(&source, &target, |_| {})
            .await
            .expect_err("non-empty target should fail");
        assert!(err.to_string().contains("not empty"));

        // Unknown extra table on source must be rejected
        sqlx::query("CREATE TABLE mystery_custom_table (id INTEGER PRIMARY KEY)")
            .execute(src_p)
            .await
            .unwrap();
        let third_target = open_sqlite_file(&dir.path().join("target2.db")).await;
        let err2 = migrate_database_contents(&source, &third_target, |_| {})
            .await
            .expect_err("unknown extra table must fail");
        assert!(err2.to_string().contains("mystery_custom_table"));
        assert!(third_target.list_tables().await.unwrap().is_empty());
    }
}
