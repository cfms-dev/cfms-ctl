//! CLI arguments for `cfms-ctl backup`.

use std::path::PathBuf;
use clap::{Args, Subcommand, ValueEnum};

/// Logical backup components supported by `cfms-ctl backup export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum)]
pub enum BackupComponentArg {
    /// Users, credentials, groups, permissions, keyrings, schedules, and account extensions.
    Accounts,
    /// Nodes, folders, documents, revisions, metadata, and DACL rules.
    Documents,
    /// Audit log entries (`audit_entries`).
    Audit,
    /// IP/subnet bans (`banned_subnets`) and linked reason comments.
    #[value(name = "banned_subnets", alias = "banned-subnets")]
    BannedSubnets,
    /// Database `options` and security secrets (`security.pepper`, `server.secret_key`).
    Configuration,
}

#[derive(Debug, Clone, Subcommand)]
pub enum BackupCommand {
    /// Export an encrypted CFMS logical backup archive (.confbak).
    Export(BackupExportArgs),

    /// Import an encrypted CFMS logical backup into an empty or blank database.
    Import(BackupImportArgs),

    /// Read and display unencrypted header metadata from a backup file.
    Info(BackupInfoArgs),

    /// Decrypt and verify archive manifest, table digests, and file SHA-256 digests without touching DB or storage.
    Verify(BackupVerifyArgs),
}

#[derive(Debug, Clone, Args)]
pub struct BackupExportArgs {
    /// Destination path for the encrypted `.confbak` archive.
    #[arg(value_name = "OUTPUT_PATH", required_unless_present = "interactive")]
    pub output_path: Option<PathBuf>,

    /// File to receive the generated decryption key.
    #[arg(long = "key-out", value_name = "FILE")]
    pub key_out: Option<PathBuf>,

    /// Components to include (comma-separated; dependencies added automatically). Defaults to all.
    #[arg(
        long = "components",
        value_enum,
        value_delimiter = ',',
        value_name = "LIST",
        conflicts_with = "interactive"
    )]
    pub components: Vec<BackupComponentArg>,

    /// Run the interactive backup component and key export wizard.
    #[arg(long = "interactive", short = 'i', conflicts_with_all = ["output_path", "key_out", "components"])]
    pub interactive: bool,
}

#[derive(Debug, Clone, Args)]
pub struct BackupImportArgs {
    /// Path to the `.confbak` backup archive to restore.
    #[arg(value_name = "BACKUP_PATH")]
    pub backup_path: PathBuf,

    /// Decryption key (human-readable grouped key or base64url key).
    #[arg(long = "key", conflicts_with = "key_file", required_unless_present = "key_file")]
    pub key: Option<String>,

    /// Path to a file containing the decryption key.
    #[arg(long = "key-file", value_name = "FILE", conflicts_with = "key", required_unless_present = "key")]
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct BackupInfoArgs {
    /// Path to the `.confbak` backup archive to inspect.
    #[arg(value_name = "BACKUP_PATH")]
    pub backup_path: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct BackupVerifyArgs {
    /// Path to the `.confbak` backup archive to verify.
    #[arg(value_name = "BACKUP_PATH")]
    pub backup_path: PathBuf,

    /// Decryption key (human-readable grouped key or base64url key).
    #[arg(long = "key", conflicts_with = "key_file", required_unless_present = "key_file")]
    pub key: Option<String>,

    /// Path to a file containing the decryption key.
    #[arg(long = "key-file", value_name = "FILE", conflicts_with = "key", required_unless_present = "key")]
    pub key_file: Option<PathBuf>,
}
