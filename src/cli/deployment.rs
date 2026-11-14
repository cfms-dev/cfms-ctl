//! CLI arguments for `cfms-ctl deployment`.

use std::path::PathBuf;
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum DeploymentCommand {
    /// Show the active release and stored historical releases without mutating state.
    Status,

    /// Check the latest official GitHub release against the active deployment.
    Check,

    /// Stage, migrate, and atomically activate a newer local release archive (.zip or .tar.gz).
    Upgrade(DeploymentUpgradeArgs),

    /// Download, verify, and activate the latest official GitHub release when newer.
    Update(DeploymentUpdateArgs),

    /// Downgrade the database and restore a previously stored release by ID or prefix.
    Downgrade(DeploymentDowngradeArgs),

    /// Finish or roll back an interrupted deployment transaction (`transaction.json`).
    Resume,

    /// Permanently remove all inactive stored releases under `.maintenance/versions`.
    Prune(DeploymentPruneArgs),
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentUpgradeArgs {
    /// Path to the local CFMS release archive (.zip or .tar.gz).
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Expected 64-hex-digit SHA-256 digest of the package.
    #[arg(long = "sha256", conflicts_with = "checksums")]
    pub sha256: Option<String>,

    /// Path to a SHA256SUMS.txt file containing the package digest.
    #[arg(long = "checksums", value_name = "FILE", conflicts_with = "sha256")]
    pub checksums: Option<PathBuf>,

    /// Optional core dependency extras to pass to `uv sync --extra`.
    #[arg(long = "extra", value_name = "EXTRA")]
    pub extras: Vec<String>,

    /// Hash-locked `requirements.lock` for third-party extensions.
    #[arg(long = "requirements-lock", value_name = "FILE")]
    pub requirements_lock: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentUpdateArgs {
    /// Optional core dependency extras to pass to `uv sync --extra`.
    #[arg(long = "extra", value_name = "EXTRA")]
    pub extras: Vec<String>,

    /// Hash-locked `requirements.lock` for third-party extensions.
    #[arg(long = "requirements-lock", value_name = "FILE")]
    pub requirements_lock: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentDowngradeArgs {
    /// Stored release SHA-256 ID or unambiguous prefix.
    #[arg(value_name = "RELEASE_ID")]
    pub release_id: String,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentPruneArgs {
    /// Preview inactive releases eligible for pruning without deleting them.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}
