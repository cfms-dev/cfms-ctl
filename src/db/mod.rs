//! Multi-database backend abstraction (SQLite, MySQL, PostgreSQL), native schema
//! registry, live schema introspection, and cross-dialect data transfer.

pub mod backend;
pub mod options;
pub mod schema;
pub mod transfer;

pub use backend::{DatabaseKind, DbPool};
pub use options::{
    OptionUpdateInput, OptionValueType, ResolvedOptionRecord, decode_option_value,
    encode_option_value, format_canonical_float, get_option, is_canonical_int_str, list_options,
    validate_option_key, validate_option_namespace, validate_option_owner, write_options_batch,
};
pub use schema::{
    APPLICATION_TABLE_NAMES, DEFERRED_COLUMNS, KNOWN_EXTENSION_TABLES, LATEST_SCHEMA_REVISION,
    SCHEMA_REVISIONS, SchemaDriftReport, SchemaInspector, SchemaIr, SchemaUpgradeOutcome,
    StampOutcome, inspect_upgrade_plan, stamp_database_revision, upgrade_database_schema,
};
pub use transfer::{
    DatabaseTransferSummary, MigrationPlan, MigrationProgress, TableTransferSummary,
    inspect_migration_readiness, inspect_migration_readiness_with_ir, migrate_database_contents,
    migrate_database_contents_with_ir,
};
