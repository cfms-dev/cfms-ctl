//! CLI arguments for `cfms-ctl audit`.

use std::path::PathBuf;
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum AuditCommand {
    /// Inspect counts of eligible audit entries by action and result without writing or deleting.
    Inspect(AuditInspectArgs),

    /// Export selected audit entries as canonical sorted JSONL (or Zstd-compressed JSONL).
    Export(AuditExportArgs),

    /// Archive selected expired audit entries to JSONL and then purge them from the database.
    Purge(AuditPurgeArgs),

    /// Verify an exported audit archive's readability, JSONL schema, ordering, and SHA-256 checksum.
    Verify(AuditVerifyArgs),
}

/// Common filter options for selecting audit log entries.
#[derive(Debug, Clone, Args)]
pub struct AuditFilterArgs {
    /// Only include entries strictly before this ISO 8601 timestamp with timezone offset (defaults to retention policy).
    #[arg(long = "before", value_name = "ISO8601_TIMESTAMP")]
    pub before: Option<String>,

    /// Only include entries at or after this ISO 8601 timestamp with timezone offset.
    #[arg(long = "after", value_name = "ISO8601_TIMESTAMP")]
    pub after: Option<String>,

    /// Filter by action name (may be repeated).
    #[arg(long = "action", value_name = "ACTION")]
    pub actions: Vec<String>,

    /// Exclude entries with the given action name (may be repeated).
    #[arg(long = "exclude-action", value_name = "ACTION")]
    pub exclude_actions: Vec<String>,

    /// Filter by username resolved through `users` (may be repeated).
    #[arg(long = "username", value_name = "USERNAME")]
    pub usernames: Vec<String>,

    /// Filter directly by actor user UUID (may be repeated; supports deleted users).
    #[arg(long = "user-id", value_name = "UUID")]
    pub user_ids: Vec<String>,

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
pub struct AuditInspectArgs {
    /// Include all entries without applying the retention-policy `--before` cutoff.
    #[arg(long = "all", conflicts_with = "before")]
    pub all: bool,

    #[command(flatten)]
    pub filter: AuditFilterArgs,
}

#[derive(Debug, Clone, Args)]
pub struct AuditExportArgs {
    /// Destination path for the JSONL audit export.
    #[arg(value_name = "OUTPUT_PATH")]
    pub output_path: PathBuf,

    /// Include all entries without applying the retention-policy `--before` cutoff.
    #[arg(long = "all", conflicts_with = "before")]
    pub all: bool,

    /// Compress the exported JSONL stream with Zstd.
    #[arg(long = "compress")]
    pub compress: bool,

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

    /// Compress the purge archive stream with Zstd.
    #[arg(long = "compress", requires = "archive")]
    pub compress: bool,

    #[command(flatten)]
    pub filter: AuditFilterArgs,
}

#[derive(Debug, Clone, Args)]
pub struct AuditVerifyArgs {
    /// Path to an exported `.jsonl` or Zstd-compressed `.jsonl.zst` audit archive.
    #[arg(value_name = "ARCHIVE_PATH")]
    pub archive_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use crate::cli::{Cli, Commands};
    use super::*;

    #[test]
    fn audit_cli_parses_all_subcommands_and_filters() {
        let inspect = Cli::try_parse_from([
            "cfms-ctl",
            "audit",
            "inspect",
            "--all",
            "--after",
            "2026-01-01T00:00:00Z",
            "--action",
            "core.auth.login",
            "--exclude-action",
            "core.file.download",
            "--username",
            "alice",
            "--user-id",
            "12345678-1234-4234-9234-123456789abc",
            "--result",
            "200",
            "--result",
            "403",
        ])
        .expect("parse audit inspect");
        match inspect.command {
            Commands::Audit(AuditCommand::Inspect(args)) => {
                assert!(args.all);
                assert_eq!(args.filter.after.as_deref(), Some("2026-01-01T00:00:00Z"));
                assert_eq!(args.filter.actions, vec!["core.auth.login"]);
                assert_eq!(args.filter.exclude_actions, vec!["core.file.download"]);
                assert_eq!(args.filter.usernames, vec!["alice"]);
                assert_eq!(
                    args.filter.user_ids,
                    vec!["12345678-1234-4234-9234-123456789abc"]
                );
                assert_eq!(args.filter.results, vec![200, 403]);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let export = Cli::try_parse_from([
            "cfms-ctl",
            "audit",
            "export",
            "audit.jsonl.zst",
            "--compress",
            "--before",
            "2026-11-01T00:00:00+08:00",
        ])
        .expect("parse audit export");
        match export.command {
            Commands::Audit(AuditCommand::Export(args)) => {
                assert_eq!(args.output_path, PathBuf::from("audit.jsonl.zst"));
                assert!(args.compress);
                assert!(!args.all);
                assert_eq!(
                    args.filter.before.as_deref(),
                    Some("2026-11-01T00:00:00+08:00")
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let purge = Cli::try_parse_from(["cfms-ctl", "audit", "purge", "--dry-run"])
            .expect("parse audit purge dry-run");
        match purge.command {
            Commands::Audit(AuditCommand::Purge(args)) => {
                assert!(args.dry_run);
                assert!(args.archive.is_none());
                assert!(!args.compress);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let verify = Cli::try_parse_from(["cfms-ctl", "audit", "verify", "archive.jsonl"])
            .expect("parse audit verify");
        match verify.command {
            Commands::Audit(AuditCommand::Verify(args)) => {
                assert_eq!(args.archive_path, PathBuf::from("archive.jsonl"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn audit_cli_rejects_conflicting_flags() {
        assert!(
            Cli::try_parse_from([
                "cfms-ctl",
                "audit",
                "inspect",
                "--all",
                "--before",
                "2026-01-01T00:00:00Z"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "cfms-ctl",
                "audit",
                "export",
                "out.jsonl",
                "--all",
                "--before",
                "2026-01-01T00:00:00Z"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["cfms-ctl", "audit", "purge"]).is_err());
        assert!(
            Cli::try_parse_from(["cfms-ctl", "audit", "purge", "--dry-run", "--compress"]).is_err()
        );
    }
}
