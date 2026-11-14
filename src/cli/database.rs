//! CLI arguments for `cfms-ctl database`.

use std::path::PathBuf;
use clap::{Args, Subcommand, ValueEnum};
use crate::db::schema::ExtractorMode;

#[derive(Debug, Clone, Subcommand)]
pub enum DatabaseCommand {
    /// Inspect database backend connectivity, current revision, and table inventory.
    Status,

    /// Validate live database schema against extracted codebase or built-in CFMS schema contract.
    Check(DatabaseCheckArgs),

    /// Intelligently analyze, audit, render, or execute database upgrades using the hybrid Python+Rust engine.
    Upgrade(DatabaseUpgradeArgs),

    /// Compute a structural diff, rename map, FK DAG order, and risk audit between two schemas or directories.
    Diff(DatabaseDiffArgs),

    /// Export a canonical `schema.ir.json` intermediate representation from codebase or live DB.
    ExportIr(DatabaseExportIrArgs),

    /// Clone the stopped server database into an empty target database engine (SQLite/MySQL/PostgreSQL).
    Migrate(DatabaseMigrateArgs),

    /// Explicitly stamp the `alembic_version` revision table after manual recovery.
    Stamp(DatabaseStampArgs),
}

/// Shared schema IR resolution arguments across database commands.
#[derive(Debug, Clone, Default, Args)]
pub struct SchemaSourceArgs {
    /// Schema extraction source (`auto`, `python`, `static`, `json`, or `builtin`).
    #[arg(long = "extractor", value_enum, default_value_t = ExtractorMode::Auto)]
    pub extractor: ExtractorMode,

    /// Explicit path to a pre-exported `schema.ir.json` artifact.
    #[arg(long = "ir", value_name = "FILE")]
    pub ir_file: Option<PathBuf>,

    /// Python `<module>:<attr>` SQLAlchemy declarative target (default `include.database.session:Base`).
    #[arg(long = "models-target", value_name = "MODULE:ATTR")]
    pub models_target: Option<String>,

    /// Include optional extension tables declared in metadata/registry when planning schemas.
    #[arg(long = "include-extensions")]
    pub include_extensions: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DatabaseCheckArgs {
    #[command(flatten)]
    pub schema: SchemaSourceArgs,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DatabaseUpgradeArgs {
    #[command(flatten)]
    pub schema: SchemaSourceArgs,

    /// Preview planned operations, risk audit, and SQL counts without mutating the database.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Render a risk-annotated Alembic Python migration script to FILE without mutating the database.
    #[arg(long = "emit-alembic", value_name = "FILE")]
    pub emit_alembic: Option<PathBuf>,

    /// Render a risk-annotated native DDL SQL script to FILE without mutating the database.
    #[arg(long = "emit-sql", value_name = "FILE")]
    pub emit_sql: Option<PathBuf>,

    /// Explicitly permit destructive, narrowing, or ambiguous migration operations.
    #[arg(long = "allow-destructive")]
    pub allow_destructive: bool,

    /// Disambiguate column renames explicitly (`table.old_col=new_col`); repeatable.
    #[arg(long = "rename", value_name = "TABLE.OLD=NEW")]
    pub rename: Vec<String>,

    /// Execute schema DDL only without running pending Alembic data DML scripts.
    #[arg(long = "schema-only")]
    pub schema_only: bool,

    /// Do not delegate pending DML migrations to Python `alembic upgrade head`.
    #[arg(long = "no-alembic-delegate")]
    pub no_alembic_delegate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliSqlDialect {
    Sqlite,
    Mysql,
    Postgresql,
}

#[derive(Debug, Clone, Args)]
pub struct DatabaseDiffArgs {
    /// Old schema source (`live`, `builtin`, `.ir.json` file, `.db` SQLite file, or code directory).
    #[arg(long = "from", default_value = "live", value_name = "SOURCE")]
    pub from: String,

    /// New schema target (`code`, `live`, `builtin`, `.ir.json` file, `.db` SQLite file, or code directory).
    #[arg(long = "to", default_value = "code", value_name = "TARGET")]
    pub to: String,

    /// Target SQL dialect for SQL rendering (`sqlite`, `mysql`, `postgresql`). Inferred if omitted.
    #[arg(long = "dialect", value_enum)]
    pub dialect: Option<CliSqlDialect>,

    #[command(flatten)]
    pub schema: SchemaSourceArgs,

    /// Explicit column rename disambiguation (`table.old_col=new_col`); repeatable.
    #[arg(long = "rename", value_name = "TABLE.OLD=NEW")]
    pub rename: Vec<String>,

    /// Render the resulting risk-annotated native DDL SQL script to FILE.
    #[arg(long = "emit-sql", value_name = "FILE")]
    pub emit_sql: Option<PathBuf>,

    /// Render the resulting risk-annotated Alembic Python migration script to FILE.
    #[arg(long = "emit-alembic", value_name = "FILE")]
    pub emit_alembic: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DatabaseExportIrArgs {
    #[command(flatten)]
    pub schema: SchemaSourceArgs,

    /// Introspect the live database configured in `config.toml` instead of the codebase.
    #[arg(long = "from-live")]
    pub from_live: bool,

    /// Write formatted `schema.ir.json` to FILE (or emit inline report / stdout if omitted).
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct DatabaseMigrateArgs {
    /// TOML file containing the target `[database]` configuration.
    #[arg(long = "target-config", value_name = "FILE")]
    pub target_config: PathBuf,

    /// Back up `config.toml` and switch `[database]` to the verified target after migration.
    #[arg(long = "activate")]
    pub activate: bool,

    #[command(flatten)]
    pub schema: SchemaSourceArgs,
}

#[derive(Debug, Clone, Args)]
pub struct DatabaseStampArgs {
    /// Target schema revision identifier (or `head`).
    #[arg(value_name = "REVISION", default_value = "head")]
    pub revision: String,

    /// Bypass workspace Alembic DAG / historical revision validation.
    #[arg(long = "force")]
    pub force: bool,
}
