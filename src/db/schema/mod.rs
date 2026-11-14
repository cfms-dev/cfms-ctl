//! Native schema contract registry and live database schema inspector.

pub mod inspector;
pub mod registry;

pub use inspector::{SchemaDriftReport, SchemaInspector};
pub use registry::{
    APPLICATION_TABLE_NAMES, DEFERRED_COLUMNS, DEFERRED_UPDATE_ORDER, LATEST_SCHEMA_REVISION,
};
