//! Command-line interface definitions powered by `clap` derive.

pub mod audit;
pub mod backup;
pub mod config;
pub mod database;
pub mod deployment;
pub mod doctor;
pub mod extension;
pub mod permission;
pub mod user;

use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};
use crate::ui::OutputFormat;

/// Standalone, high-performance maintenance CLI for CFMS servers.
#[derive(Debug, Parser)]
#[command(
    name = "cfms-ctl",
    version,
    about = "Standalone multi-database operations and maintenance CLI for CFMS servers.",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Commands,
}

/// Global options shared by all `cfms-ctl` commands.
#[derive(Debug, Clone, Args)]
pub struct GlobalOpts {
    /// Path to the CFMS deployment or server root directory (auto-discovered if omitted).
    #[arg(long = "root", global = true, env = "CFMS_ROOT", value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Override path to `config.toml`.
    #[arg(long = "config", global = true, env = "CFMS_CONFIG", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Output format (`human` tables or structured `json`).
    #[arg(
        long = "output",
        short = 'o',
        global = true,
        value_enum,
        default_value_t = OutputFormat::Human
    )]
    pub output: OutputFormat,

    /// Automatically confirm high-risk or mutating prompts.
    #[arg(long = "yes", short = 'y', global = true)]
    pub yes: bool,

    /// Enable verbose diagnostic logging on stderr.
    #[arg(long = "verbose", short = 'v', global = true)]
    pub verbose: bool,
}

/// Top-level command domains.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run comprehensive health, configuration, lock, and database schema diagnostics.
    Doctor(doctor::DoctorArgs),

    /// Check, upgrade, update, downgrade, resume, and prune packaged CFMS deployments.
    #[command(subcommand)]
    Deployment(deployment::DeploymentCommand),

    /// Inspect, validate, upgrade, stamp, and cross-engine migrate CFMS databases.
    #[command(subcommand)]
    Database(database::DatabaseCommand),

    /// Export, import, inspect, and verify encrypted CFMS logical backups (Format v2).
    #[command(subcommand)]
    Backup(backup::BackupCommand),

    /// Synchronize `config.toml` templates, manage secrets, and edit database-backed options.
    #[command(subcommand)]
    Config(config::ConfigCommand),

    /// Inspect, install, upgrade, enable, disable, uninstall, and purge server extensions.
    #[command(subcommand)]
    Extension(extension::ExtensionCommand),

    /// Reset user passwords, rotate token signing secrets, and clear TOTP states.
    #[command(subcommand)]
    User(user::UserCommand),

    /// Synchronize default group permissions and purge expired permission records.
    #[command(subcommand)]
    Permission(permission::PermissionCommand),

    /// Inspect, export, and archive-then-purge expired audit log entries.
    #[command(subcommand)]
    Audit(audit::AuditCommand),
}
