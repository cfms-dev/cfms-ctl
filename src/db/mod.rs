//! Multi-database backend abstraction (SQLite, MySQL, PostgreSQL), native schema
//! registry, live schema introspection, and cross-dialect data transfer.

pub mod backend;
pub mod schema;
pub mod transfer;

pub use backend::{DatabaseKind, DbPool};
pub use schema::{
    APPLICATION_TABLE_NAMES, DEFERRED_COLUMNS, LATEST_SCHEMA_REVISION, SchemaDriftReport,
    SchemaInspector,
};
