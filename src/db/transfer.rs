//! Cross-database streaming table transfer and canonical SHA-256 verification scaffold.

use serde::Serialize;
use crate::db::backend::DatabaseKind;

/// Per-table verification summary during cross-backend database cloning (`database migrate`).
#[derive(Debug, Clone, Serialize)]
pub struct TableTransferSummary {
    pub table_name: String,
    pub row_count: u64,
    pub sha256_digest: String,
}

/// Summary of a cross-backend database migration (`SQLite <-> MySQL <-> PostgreSQL`).
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseTransferSummary {
    pub source_dialect: DatabaseKind,
    pub target_dialect: DatabaseKind,
    pub table_count: usize,
    pub total_rows: u64,
    pub elapsed_ms: u128,
    pub tables: Vec<TableTransferSummary>,
}
