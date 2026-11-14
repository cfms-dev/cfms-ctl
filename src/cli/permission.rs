//! CLI arguments for `cfms-ctl permission`.

use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum PermissionCommand {
    /// Purge permission records older than the configured retention period.
    PurgeExpired(PermissionPurgeExpiredArgs),

    /// Restore missing default group permission records (`user`, `sysop`).
    SyncDefaults(PermissionSyncDefaultsArgs),
}

#[derive(Debug, Clone, Args)]
pub struct PermissionPurgeExpiredArgs {
    /// Show eligible expired permission entries without deleting them.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct PermissionSyncDefaultsArgs {
    /// Target default group name(s) (`user`, `sysop`); defaults to all default groups.
    #[arg(long = "group", value_name = "GROUP")]
    pub groups: Vec<String>,

    /// Show missing permission records without inserting them.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}
