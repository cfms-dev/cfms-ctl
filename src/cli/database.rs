//! CLI arguments for `cfms-ctl database`.

use std::path::PathBuf;
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum DatabaseCommand {
    /// Inspect database backend connectivity, current revision, and table inventory.
    Status,

    /// Validate live database schema against the expected CFMS schema contract (drift preflight).
    Check,

    /// Natively upgrade or bootstrap the configured database schema to the latest head.
    Upgrade,

    /// Clone the stopped server database into an empty target database engine (SQLite/MySQL/PostgreSQL).
    Migrate(DatabaseMigrateArgs),

    /// Explicitly stamp the `alembic_version` revision table after manual recovery.
    Stamp(DatabaseStampArgs),
}

#[derive(Debug, Clone, Args)]
pub struct DatabaseMigrateArgs {
    /// TOML file containing the target `[database]` configuration.
    #[arg(long = "target-config", value_name = "FILE")]
    pub target_config: PathBuf,

    /// Back up `config.toml` and switch `[database]` to the verified target after migration.
    #[arg(long = "activate")]
    pub activate: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DatabaseStampArgs {
    /// Target schema revision identifier (or `head`).
    #[arg(value_name = "REVISION", default_value = "head")]
    pub revision: String,
}
