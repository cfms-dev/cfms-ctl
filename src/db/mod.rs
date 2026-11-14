//! Multi-database backend abstraction (SQLite, MySQL, PostgreSQL), native schema
//! registry, live schema introspection, and cross-dialect data transfer.

pub mod backend;
pub mod options;
pub mod schema;
pub mod transfer;

pub use backend::{DatabaseKind, DbPool};
pub use options::{
    OptionUpdateInput, OptionValueType, ResolvedOptionRecord, decode_option_value,
    encode_option_value, get_option, list_options, reset_option, validate_option_key,
    validate_option_namespace, validate_option_owner, write_options_batch,
};
pub use schema::{
    APPLICATION_TABLE_NAMES, DEFERRED_COLUMNS, LATEST_SCHEMA_REVISION, SchemaDriftReport,
    SchemaInspector,
};
