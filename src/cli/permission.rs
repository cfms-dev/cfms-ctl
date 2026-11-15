//! CLI arguments for `cfms-ctl permission`.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Clone, Subcommand)]
pub enum PermissionCommand {
    /// Purge permission records older than the configured retention period.
    PurgeExpired(PermissionPurgeExpiredArgs),

    /// Restore missing default group permission records (`user`, `sysop`).
    SyncDefaults(PermissionSyncDefaultsArgs),
}

/// Target table scope for `cfms-ctl permission purge-expired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum PermissionScope {
    /// Purge expired rows from both `user_permissions` and `group_permissions`.
    #[default]
    All,
    /// Purge expired rows only from `user_permissions`.
    User,
    /// Purge expired rows only from `group_permissions`.
    Group,
}

impl PermissionScope {
    /// Canonical lowercase label used in reports and audit entries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::User => "user",
            Self::Group => "group",
        }
    }

    #[must_use]
    pub const fn includes_user(self) -> bool {
        matches!(self, Self::All | Self::User)
    }

    #[must_use]
    pub const fn includes_group(self) -> bool {
        matches!(self, Self::All | Self::Group)
    }
}

#[derive(Debug, Clone, Args)]
pub struct PermissionPurgeExpiredArgs {
    /// Override cutoff with an explicit ISO 8601 UTC/offset timestamp (for example, 2026-01-01T00:00:00Z).
    #[arg(long = "before", value_name = "ISO8601_TIMESTAMP", conflicts_with = "retention_days")]
    pub before: Option<String>,

    /// Override configured retention days before expiration cutoff (0 purges all already-expired entries).
    #[arg(long = "retention-days", value_name = "DAYS", conflicts_with = "before")]
    pub retention_days: Option<u64>,

    /// Restrict cleanup to user permissions, group permissions, or both.
    #[arg(long = "scope", value_enum, default_value_t = PermissionScope::All)]
    pub scope: PermissionScope,

    /// Override maximum expired permission entries deleted per transaction batch.
    #[arg(long = "batch-size", value_name = "COUNT")]
    pub batch_size: Option<usize>,

    /// Optional explicit path to `options.schema.json`.
    #[arg(long = "schema", value_name = "FILE")]
    pub schema: Option<PathBuf>,

    /// Show eligible expired permission entries without deleting them.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct PermissionSyncDefaultsArgs {
    /// Target default group name(s) (`user`, `sysop`); defaults to all default groups.
    #[arg(long = "group", value_name = "GROUP")]
    pub groups: Vec<String>,

    /// Optional JSON file overriding default group permission definitions.
    #[arg(long = "defaults-file", value_name = "FILE")]
    pub defaults_file: Option<PathBuf>,

    /// Show missing permission records without inserting them.
    #[arg(long = "dry-run", conflicts_with = "check")]
    pub dry_run: bool,

    /// Verify default group permissions are complete without modifying the database; fail if out of sync.
    #[arg(long = "check", conflicts_with = "dry_run")]
    pub check: bool,
}
