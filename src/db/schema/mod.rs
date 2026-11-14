//! Native schema contract registry, dialect DDL, live database schema inspector,
//! and multi-backend native upgrade engine.

pub mod ddl;
pub mod inspector;
pub mod migrations;
pub mod registry;

pub use ddl::{create_head_schema, drop_all_cfms_tables, set_alembic_version, table_def};
pub use inspector::{SchemaDriftReport, SchemaInspector};
pub use migrations::{SchemaUpgradeOutcome, inspect_upgrade_plan, upgrade_database_schema};
pub use registry::{
    APPLICATION_TABLE_NAMES, DEFERRED_COLUMNS, DEFERRED_UPDATE_ORDER, KNOWN_EXTENSION_TABLES,
    LATEST_SCHEMA_REVISION, SCHEMA_REVISIONS, SERIAL_IDENTITY_COLUMNS,
};
