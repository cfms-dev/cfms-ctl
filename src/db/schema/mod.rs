//! Native schema contract registry, dialect DDL, live database schema inspector,
//! and multi-backend native upgrade engine.

pub mod ddl;
pub mod diff;
pub mod graph;
pub mod inspector;
pub mod ir;
pub mod live_ir;
pub mod migrations;
pub mod probe;
pub mod registry;
pub mod rename;
pub mod render;
pub mod risk;
pub mod static_ast;

pub use ddl::{
    builtin_schema_ir, create_head_schema, drop_all_cfms_tables, set_alembic_version, table_def,
};
pub use diff::{DiffOptions, ExecutionPhase, SchemaDiffPlan, SchemaOp, diff_schemas};
pub use graph::{SchemaGraphPlan, infer_transfer_metadata, plan_schema_graph, plan_table_subset};
pub use inspector::{SchemaDriftReport, SchemaInspector};
pub use ir::{
    CanonicalType, CheckIr, ColumnIr, ComputedColumnIr, ConfidenceLevel, ExtractionSource,
    ForeignKeyIr, IndexIr, PrimaryKeyIr, ReferentialAction, SCHEMA_IR_VERSION, SchemaIr,
    ServerDefaultIr, TableIr, TableOwnership, UniqueIr,
};
pub use live_ir::introspect_live_schema_ir;
pub use probe::{ExtractorMode, extract_code_schema_ir, load_schema_ir_file, run_python_probe};
pub use rename::{RenameConfig, RenameScoreBreakdown};
pub use render::{
    AlembicRenderOptions, SqlRenderOptions, compile_full_schema_ddl, compile_op_to_sql_statements,
    render_alembic_migration_script, render_native_ddl_sql,
};
pub use risk::{RiskAuditReport, RiskFinding, RiskLevel, audit_diff_plan, run_live_preflight_checks};
pub use static_ast::{
    AlembicDirectoryAnalysis, PendingAlembicAnalysis, analyze_alembic_directory,
    extract_static_schema_ir, parse_python_syntax_check,
};
pub use migrations::{
    HybridUpgradeOptions, HybridUpgradeOutcome, HybridUpgradePlan, SchemaUpgradeOutcome,
    StampOutcome, UpgradeStrategy, execute_hybrid_upgrade, inspect_upgrade_plan,
    plan_hybrid_upgrade, run_alembic_upgrade_head, stamp_database_revision,
    upgrade_database_schema,
};
pub use registry::{
    APPLICATION_TABLE_NAMES, DEFERRED_COLUMNS, DEFERRED_UPDATE_ORDER, KNOWN_EXTENSION_TABLES,
    LATEST_SCHEMA_REVISION, SCHEMA_REVISIONS, SERIAL_IDENTITY_COLUMNS,
};
