//! CLI arguments for `cfms-ctl audit`.

use std::path::PathBuf;
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum AuditCommand {
    /// Inspect counts of eligible audit entries by action and result without writing or deleting.
    Inspect(AuditFilterArgs),

    /// Export selected audit entries as readable JSONL.
    Export(AuditExportArgs),

    /// Archive selected expired audit entries to JSONL and then purge them from the database.
    Purge(AuditPurgeArgs),
}

/// Common filter options for selecting audit log entries.
#[derive(Debug, Clone, Args)]
pub struct AuditFilterArgs {
    /// Only include entries before this ISO 8601 timestamp with timezone offset (defaults to retention policy).
    #[arg(long = "before", value_name = "ISO8601_TIMESTAMP")]
    pub before: Option<String>,

    /// Filter by action name (may be repeated).
    #[arg(long = "action", value_name = "ACTION")]
    pub actions: Vec<String>,

    /// Filter by username (may be repeated).
    #[arg(long = "username", value_name = "USERNAME")]
    pub usernames: Vec<String>,

    /// Filter by target identifier (may be repeated).
    #[arg(long = "target", value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Filter by exact result code (may be repeated).
    #[arg(long = "result", value_name = "CODE")]
    pub results: Vec<i32>,

    /// Filter by remote IP address (may be repeated).
    #[arg(long = "remote-address", value_name = "IP")]
    pub remote_addresses: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct AuditExportArgs {
    /// Destination path for the JSONL audit export.
    #[arg(value_name = "OUTPUT_PATH")]
    pub output_path: PathBuf,

    #[command(flatten)]
    pub filter: AuditFilterArgs,
}

#[derive(Debug, Clone, Args)]
pub struct AuditPurgeArgs {
    /// JSONL archive path that must be written and verified before deleting database rows.
    #[arg(long = "archive", value_name = "FILE", required_unless_present = "dry_run")]
    pub archive: Option<PathBuf>,

    /// Preview eligible audit entries without writing an archive or deleting rows.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    #[command(flatten)]
    pub filter: AuditFilterArgs,
}
