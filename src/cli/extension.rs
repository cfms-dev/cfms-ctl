//! CLI arguments for `cfms-ctl extension`.

use std::path::PathBuf;
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum ExtensionCommand {
    /// List installed extensions, dependencies, compatibility, and activation health.
    List,

    /// Show manifest details and state of a single installed extension.
    Info(ExtensionIdentifierArgs),

    /// Install a local extension ZIP package without enabling it.
    Install(ExtensionPackageArgs),

    /// Replace an installed third-party extension with a strictly newer version.
    Upgrade(ExtensionPackageArgs),

    /// Enable one or more installed extensions and their transitive dependencies in `config.toml`.
    Enable(ExtensionEnableArgs),

    /// Disable one or more extensions and any enabled dependents in `config.toml`.
    Disable(ExtensionDisableArgs),

    /// Uninstall a third-party extension's code (and optionally purge its database data).
    Uninstall(ExtensionUninstallArgs),

    /// Purge a disabled extension's persistent database options, system states, and declared data tables.
    PurgeData(ExtensionPurgeDataArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionIdentifierArgs {
    /// Extension identifier (`^[a-z][a-z0-9_]*$`).
    #[arg(value_name = "IDENTIFIER")]
    pub identifier: String,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionEnableArgs {
    /// One or more installed extension identifiers (`^[a-z][a-z0-9_]*$`).
    #[arg(value_name = "IDENTIFIER", required = true, num_args = 1..)]
    pub identifiers: Vec<String>,

    /// Preview dependency resolution and `config.toml` changes without writing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionDisableArgs {
    /// One or more extension identifiers (`^[a-z][a-z0-9_]*$`) to disable.
    #[arg(value_name = "IDENTIFIER", required = true, num_args = 1..)]
    pub identifiers: Vec<String>,

    /// Preview reverse-dependent closure and `config.toml` changes without writing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionPackageArgs {
    /// Path to the local extension ZIP package.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Expected 64-hex-digit SHA-256 digest of the extension package.
    #[arg(long = "sha256")]
    pub sha256: Option<String>,

    /// Preview package inspection, resolved metadata, and planned changes without writing to disk.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionUninstallArgs {
    /// Installed extension identifier.
    #[arg(value_name = "IDENTIFIER")]
    pub identifier: String,

    /// Also purge database options and system states owned by this extension (requires stopped server).
    #[arg(long = "purge-data")]
    pub purge_data: bool,

    /// Preview configuration updates, directory removal, and optional data purge summary without modifying state.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionPurgeDataArgs {
    /// Disabled extension identifier (or orphaned identifier when `--options-only` is set).
    #[arg(value_name = "IDENTIFIER")]
    pub identifier: String,

    /// Delete only `options` and `system_states` rows owned by this extension without importing extension code or purging `[data]` tables.
    #[arg(long = "options-only")]
    pub options_only: bool,

    /// Preview affected options, system states, declared `[data]` tables, and purge hooks without modifying the database.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use crate::cli::{Cli, Commands, extension::ExtensionCommand};

    #[test]
    fn parses_extension_enable_with_multiple_ids_and_flags() {
        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "extension",
            "enable",
            "http_api",
            "oidc_sso",
            "--dry-run",
        ])
        .expect("valid extension enable args");

        match cli.command {
            Commands::Extension(ExtensionCommand::Enable(args)) => {
                assert_eq!(args.identifiers, vec!["http_api", "oidc_sso"]);
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let err = Cli::try_parse_from([
            "cfms-ctl",
            "extension",
            "enable",
            "http_api",
            "--server-version",
            "0.14.0",
        ])
        .expect_err("removed --server-version flag must be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn parses_extension_disable_with_single_id() {
        let cli = Cli::try_parse_from(["cfms-ctl", "extension", "disable", "oidc_sso", "--dry-run"])
            .expect("valid extension disable args");

        match cli.command {
            Commands::Extension(ExtensionCommand::Disable(args)) => {
                assert_eq!(args.identifiers, vec!["oidc_sso"]);
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rejects_extension_enable_without_identifiers() {
        assert!(Cli::try_parse_from(["cfms-ctl", "extension", "enable"]).is_err());
        assert!(Cli::try_parse_from(["cfms-ctl", "extension", "disable"]).is_err());
    }

    #[test]
    fn parses_extension_install_upgrade_uninstall_flags() {
        let install = Cli::try_parse_from([
            "cfms-ctl",
            "extension",
            "install",
            "pkg.zip",
            "--sha256",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--dry-run",
        ])
        .expect("parse install");
        match install.command {
            Commands::Extension(ExtensionCommand::Install(args)) => {
                assert_eq!(args.package, std::path::PathBuf::from("pkg.zip"));
                assert!(args.sha256.is_some());
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let upgrade =
            Cli::try_parse_from(["cfms-ctl", "extension", "upgrade", "pkg_v2.zip", "--dry-run"])
                .expect("parse upgrade");
        match upgrade.command {
            Commands::Extension(ExtensionCommand::Upgrade(args)) => {
                assert_eq!(args.package, std::path::PathBuf::from("pkg_v2.zip"));
                assert!(args.sha256.is_none());
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let uninstall = Cli::try_parse_from([
            "cfms-ctl",
            "extension",
            "uninstall",
            "sample_ext",
            "--purge-data",
            "--dry-run",
        ])
        .expect("parse uninstall");
        match uninstall.command {
            Commands::Extension(ExtensionCommand::Uninstall(args)) => {
                assert_eq!(args.identifier, "sample_ext");
                assert!(args.purge_data);
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_extension_purge_data_flags() {
        let bare = Cli::try_parse_from(["cfms-ctl", "extension", "purge-data", "oidc_sso"])
            .expect("parse bare purge-data");
        match bare.command {
            Commands::Extension(ExtensionCommand::PurgeData(args)) => {
                assert_eq!(args.identifier, "oidc_sso");
                assert!(!args.options_only);
                assert!(!args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let flagged = Cli::try_parse_from([
            "cfms-ctl",
            "extension",
            "purge-data",
            "sample_ext",
            "--options-only",
            "--dry-run",
        ])
        .expect("parse flagged purge-data");
        match flagged.command {
            Commands::Extension(ExtensionCommand::PurgeData(args)) => {
                assert_eq!(args.identifier, "sample_ext");
                assert!(args.options_only);
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
