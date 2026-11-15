//! CLI arguments for `cfms-ctl deployment`.

use std::path::PathBuf;
use clap::{Args, Subcommand, ValueEnum};

/// Preferred release archive format when querying or downloading GitHub releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ReleaseArchiveFormat {
    /// Prefer `.zip` on Windows and `.tar.gz` on POSIX when both exist, falling back automatically.
    #[default]
    Auto,
    /// Require a `.zip` release bundle.
    Zip,
    /// Require a `.tar.gz` / `.tgz` release bundle.
    #[value(name = "tar.gz", alias = "tgz")]
    TarGz,
}

#[derive(Debug, Clone, Subcommand)]
pub enum DeploymentCommand {
    /// Show the active release, lock/transaction state, database revision, and stored releases.
    Status(DeploymentStatusArgs),

    /// Deep-verify cryptographic SHA-256 digests of the active deployment and/or stored snapshots.
    Verify(DeploymentVerifyArgs),

    /// Check official GitHub releases against the active deployment.
    #[command(disable_version_flag = true)]
    Check(DeploymentCheckArgs),

    /// Stage, verify, migrate, and atomically activate a local release archive (.zip or .tar.gz).
    Upgrade(DeploymentUpgradeArgs),

    /// Download, verify, and activate an official GitHub release when newer or pinned.
    #[command(disable_version_flag = true)]
    Update(DeploymentUpdateArgs),

    /// Safely downgrade the database and restore a stored historical release.
    #[command(disable_version_flag = true)]
    Downgrade(DeploymentDowngradeArgs),

    /// Inspect and finish or roll back an interrupted deployment transaction (`transaction.json`).
    Resume(DeploymentResumeArgs),

    /// Remove inactive historical snapshots under `src/.maintenance/versions`.
    Prune(DeploymentPruneArgs),

    /// Perform a cold-start installation from a local archive or GitHub release into a target directory.
    #[command(disable_version_flag = true)]
    Install(DeploymentInstallArgs),

    /// Adopt an existing unmanaged non-git deployment by verifying it against a release manifest.
    #[command(disable_version_flag = true)]
    Adopt(DeploymentAdoptArgs),
}

/// Optional checksum verification inputs for local package archives.
#[derive(Debug, Clone, Default, Args)]
pub struct LocalChecksumArgs {
    /// Expected 64-hex-digit SHA-256 digest of the local package archive.
    #[arg(long = "sha256", value_name = "HEX", conflicts_with = "checksums")]
    pub sha256: Option<String>,

    /// Path to a checksum file (`SHA256SUMS.txt` or `<archive>.sha256`) containing the digest.
    #[arg(long = "checksums", value_name = "FILE", conflicts_with = "sha256")]
    pub checksums: Option<PathBuf>,
}

/// Environment sync options shared across install, upgrade, and update operations.
#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentEnvArgs {
    /// Optional core dependency extras passed to `uv sync --extra` (replaces previously saved extras).
    #[arg(long = "extra", value_name = "EXTRA", conflicts_with = "clear_extras")]
    pub extras: Vec<String>,

    /// Clear any previously persisted extras (`settings.json`) and sync base runtime dependencies only.
    #[arg(long = "clear-extras", conflicts_with = "extras")]
    pub clear_extras: bool,

    /// Hash-locked `requirements.lock` for third-party extension dependencies.
    #[arg(
        long = "requirements-lock",
        value_name = "FILE",
        conflicts_with = "clear_requirements_lock"
    )]
    pub requirements_lock: Option<PathBuf>,

    /// Remove any previously persisted `requirements.lock` from `src/.maintenance/`.
    #[arg(long = "clear-requirements-lock", conflicts_with = "requirements_lock")]
    pub clear_requirements_lock: bool,

    /// Skip `uv sync` / `uv pip install` execution (useful in pre-built or airgapped containers).
    #[arg(long = "skip-env")]
    pub skip_env: bool,
}

/// GitHub Releases source coordinates and asset selection options.
#[derive(Debug, Clone, Default, Args)]
pub struct OnlineReleaseArgs {
    /// Query or target a specific release version or tag (e.g. `0.15.0` or `v0.15.0`).
    #[arg(long = "version", visible_alias = "tag", value_name = "VERSION")]
    pub version: Option<String>,

    /// Preferred release archive format (`auto`, `zip`, or `tar.gz`).
    #[arg(long = "format", value_enum, default_value_t = ReleaseArchiveFormat::Auto)]
    pub format: ReleaseArchiveFormat,

    /// Include prerelease GitHub releases when resolving target releases.
    #[arg(long = "include-prerelease")]
    pub include_prerelease: bool,

    /// Override the GitHub repository (`OWNER/NAME`, default `cfms-dev/cfms_on_websocket`).
    #[arg(long = "repo", value_name = "OWNER/NAME")]
    pub repo: Option<String>,
}

/// Optional encrypted pre-mutation safety backup export options.
#[derive(Debug, Clone, Default, Args)]
pub struct SafetyBackupArgs {
    /// Create an encrypted `.confbak` logical backup before mutating files or database schema.
    #[arg(long = "backup", value_name = "FILE")]
    pub backup: Option<PathBuf>,

    /// Destination file for the generated `.confbak` decryption key (used with `--backup`).
    #[arg(long = "backup-key-out", value_name = "FILE", requires = "backup")]
    pub backup_key_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentStatusArgs {
    /// Perform full SHA-256 verification of active and stored release files (slower on large trees).
    #[arg(long = "verify")]
    pub verify: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentVerifyArgs {
    /// Verify a specific stored release ID, unambiguous prefix, or version instead of all snapshots.
    #[arg(long = "release", value_name = "ID_OR_VERSION", conflicts_with = "active_only")]
    pub release: Option<String>,

    /// Only verify the active deployment files and skip stored historical snapshots.
    #[arg(long = "active-only", conflicts_with = "release")]
    pub active_only: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentCheckArgs {
    #[command(flatten)]
    pub online: OnlineReleaseArgs,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentUpgradeArgs {
    /// Path to the local CFMS release archive (`.zip`, `.tar.gz`, or `.tgz`).
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    #[command(flatten)]
    pub checksum: LocalChecksumArgs,

    #[command(flatten)]
    pub env: DeploymentEnvArgs,

    #[command(flatten)]
    pub backup: SafetyBackupArgs,

    /// Allow destructive/narrowing schema migrations when advancing the database.
    #[arg(long = "allow-destructive")]
    pub allow_destructive: bool,

    /// Stage, verify, and preview file/config/database changes without mutating the workspace or DB.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentUpdateArgs {
    #[command(flatten)]
    pub online: OnlineReleaseArgs,

    #[command(flatten)]
    pub env: DeploymentEnvArgs,

    #[command(flatten)]
    pub backup: SafetyBackupArgs,

    /// Require the GitHub API asset `digest` field to be present instead of relying on `SHA256SUMS.txt` alone when `digest` is null.
    #[arg(long = "require-github-digest")]
    pub require_github_digest: bool,

    /// Allow destructive/narrowing schema migrations when advancing the database.
    #[arg(long = "allow-destructive")]
    pub allow_destructive: bool,

    /// Query, download, verify, and preview upgrade plan without mutating the workspace or DB.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentDowngradeArgs {
    /// Stored release SHA-256 ID or unambiguous hex prefix.
    #[arg(value_name = "RELEASE_ID", required_unless_present = "version")]
    pub release_id: Option<String>,

    /// Look up the stored historical release by version (e.g. `0.14.0`) instead of release ID.
    #[arg(long = "version", value_name = "VERSION", conflicts_with = "release_id")]
    pub version: Option<String>,

    /// Replace `src/config.toml` byte-for-byte with the stored snapshot instead of template-syncing live config.
    #[arg(long = "restore-snapshot-config")]
    pub restore_snapshot_config: bool,

    /// Move incompatible or post-upgrade third-party extensions into `src/.maintenance/quarantine/` instead of leaving them in place.
    #[arg(long = "quarantine-extensions")]
    pub quarantine_extensions: bool,

    /// Skip `uv sync` / `uv pip install` execution during downgrade.
    #[arg(long = "skip-env")]
    pub skip_env: bool,

    #[command(flatten)]
    pub backup: SafetyBackupArgs,

    /// Preflight Alembic downgrade, config delta, and extension impacts without mutating disk or DB.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentResumeArgs {
    /// Roll back to the recorded source release where safely possible instead of continuing forward.
    #[arg(long = "rollback", conflicts_with_all = ["continue_forward", "abort_clear"])]
    pub rollback: bool,

    /// Continue moving forward toward the recorded target release revision and state.
    #[arg(long = "continue-forward", conflicts_with_all = ["rollback", "abort_clear"])]
    pub continue_forward: bool,

    /// Clear `transaction.json` only after explicit confirmation that manual recovery is complete.
    #[arg(long = "abort-clear", conflicts_with_all = ["rollback", "continue_forward"])]
    pub abort_clear: bool,

    /// Skip `uv sync` / `uv pip install` when finishing or rolling back activation state.
    #[arg(long = "skip-env")]
    pub skip_env: bool,

    /// Permit destructive schema operations if resuming a database upgrade step.
    #[arg(long = "allow-destructive")]
    pub allow_destructive: bool,

    /// Inspect `transaction.json`, live database revision, and schema drift without modifying state.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Args)]
pub struct DeploymentPruneArgs {
    /// Retain the `N` newest healthy inactive snapshots under `src/.maintenance/versions`.
    #[arg(long = "keep", value_name = "N", conflicts_with_all = ["release", "corrupt", "all"])]
    pub keep: Option<usize>,

    /// Remove specific stored release ID(s) or unambiguous prefixes (repeatable).
    #[arg(long = "release", value_name = "ID", conflicts_with_all = ["keep", "corrupt", "all"])]
    pub release: Vec<String>,

    /// Remove only damaged or incomplete historical snapshots.
    #[arg(long = "corrupt", conflicts_with_all = ["keep", "release", "all"])]
    pub corrupt: bool,

    /// Explicitly remove all inactive historical snapshots.
    #[arg(long = "all", conflicts_with_all = ["keep", "release", "corrupt"])]
    pub all: bool,

    /// Preview candidate snapshots to remove without deleting any files.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentInstallArgs {
    /// Local CFMS release archive (`.zip`, `.tar.gz`, or `.tgz`) to install.
    #[arg(value_name = "PACKAGE", required_unless_present = "from_github")]
    pub package: Option<PathBuf>,

    /// Fetch the release archive directly from GitHub Releases instead of a local file.
    #[arg(long = "from-github", conflicts_with = "package")]
    pub from_github: bool,

    /// Target installation directory (defaults to `--root` or current directory).
    #[arg(long = "target", value_name = "DIR")]
    pub target: Option<PathBuf>,

    #[command(flatten)]
    pub online: OnlineReleaseArgs,

    /// Require non-null GitHub asset `digest` when installing with `--from-github`.
    #[arg(long = "require-github-digest", requires = "from_github")]
    pub require_github_digest: bool,

    #[command(flatten)]
    pub checksum: LocalChecksumArgs,

    #[command(flatten)]
    pub env: DeploymentEnvArgs,

    /// Generate `src/config.toml` and unpack files without running initial database schema bootstrap.
    #[arg(long = "skip-db-init")]
    pub skip_db_init: bool,

    /// Verify package and preview target layout without writing files or creating databases.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeploymentAdoptArgs {
    /// Local CFMS release archive matching the installed files.
    #[arg(value_name = "PACKAGE", required_unless_present = "from_github")]
    pub package: Option<PathBuf>,

    /// Fetch the matching reference release archive from GitHub Releases.
    #[arg(long = "from-github", conflicts_with = "package")]
    pub from_github: bool,

    #[command(flatten)]
    pub online: OnlineReleaseArgs,

    /// Require non-null GitHub asset `digest` when adopting with `--from-github`.
    #[arg(long = "require-github-digest", requires = "from_github")]
    pub require_github_digest: bool,

    #[command(flatten)]
    pub checksum: LocalChecksumArgs,

    /// Optional persisted extras metadata to record in `src/.maintenance/settings.json`.
    #[arg(long = "extra", value_name = "EXTRA")]
    pub extras: Vec<String>,

    /// Hash-locked `requirements.lock` to record in `src/.maintenance/`.
    #[arg(long = "requirements-lock", value_name = "FILE")]
    pub requirements_lock: Option<PathBuf>,

    /// Verify unpacked workspace against reference manifest without writing `release-manifest.json` or snapshots.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use crate::cli::{Cli, Commands};
    use super::*;

    #[test]
    fn cli_command_tree_passes_clap_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_status_default_and_verify() {
        let cli = Cli::try_parse_from(["cfms-ctl", "deployment", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Status(DeploymentStatusArgs { verify: false }))
        ));

        let cli = Cli::try_parse_from(["cfms-ctl", "deployment", "status", "--verify"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Status(DeploymentStatusArgs { verify: true }))
        ));
    }

    #[test]
    fn parses_upgrade_update_downgrade_prune_and_install() {
        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "deployment",
            "upgrade",
            "bundle.tar.gz",
            "--extra",
            "postgres",
            "--backup",
            "pre.confbak",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Commands::Deployment(DeploymentCommand::Upgrade(args)) => {
                assert_eq!(args.package, PathBuf::from("bundle.tar.gz"));
                assert_eq!(args.env.extras, vec!["postgres"]);
                assert_eq!(args.backup.backup, Some(PathBuf::from("pre.confbak")));
                assert!(args.dry_run);
            }
            other => panic!("unexpected parsed command: {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "deployment",
            "downgrade",
            "--version",
            "0.14.0",
            "--restore-snapshot-config",
        ])
        .unwrap();
        match cli.command {
            Commands::Deployment(DeploymentCommand::Downgrade(args)) => {
                assert!(args.release_id.is_none());
                assert_eq!(args.version.as_deref(), Some("0.14.0"));
                assert!(args.restore_snapshot_config);
            }
            other => panic!("unexpected parsed command: {other:?}"),
        }

        let cli = Cli::try_parse_from(["cfms-ctl", "deployment", "prune", "--keep", "2"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Prune(DeploymentPruneArgs {
                keep: Some(2),
                ..
            }))
        ));

        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "deployment",
            "install",
            "--from-github",
            "--version",
            "0.15.0",
            "--format",
            "tar.gz",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Install(DeploymentInstallArgs {
                from_github: true,
                ..
            }))
        ));

        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "deployment",
            "check",
            "--version",
            "v0.15.0",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Check(DeploymentCheckArgs {
                online: OnlineReleaseArgs {
                    version: Some(_),
                    ..
                },
            }))
        ));

        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "deployment",
            "update",
            "--version",
            "0.15.0",
            "--require-github-digest",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Update(DeploymentUpdateArgs {
                require_github_digest: true,
                ..
            }))
        ));

        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "deployment",
            "adopt",
            "--from-github",
            "--version",
            "0.14.0",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Deployment(DeploymentCommand::Adopt(DeploymentAdoptArgs {
                from_github: true,
                ..
            }))
        ));
    }

    #[test]
    fn rejects_conflicting_flags() {
        assert!(
            Cli::try_parse_from([
                "cfms-ctl",
                "deployment",
                "resume",
                "--rollback",
                "--continue-forward",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "cfms-ctl",
                "deployment",
                "prune",
                "--keep",
                "2",
                "--corrupt",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["cfms-ctl", "deployment", "install"]).is_err()
        );
    }
}
