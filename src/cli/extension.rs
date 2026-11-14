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

    /// Purge a disabled extension's persistent database options and system states.
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

    /// Override the detected CFMS server version for `[compatibility]` checks.
    #[arg(long = "server-version", value_name = "VERSION")]
    pub server_version: Option<String>,

    /// Optional JSON Schema file (`config.schema.json`) used to validate `config.toml` before write.
    #[arg(long = "schema", value_name = "FILE")]
    pub schema: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionDisableArgs {
    /// One or more extension identifiers (`^[a-z][a-z0-9_]*$`) to disable.
    #[arg(value_name = "IDENTIFIER", required = true, num_args = 1..)]
    pub identifiers: Vec<String>,

    /// Preview reverse-dependent closure and `config.toml` changes without writing.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Optional JSON Schema file (`config.schema.json`) used to validate `config.toml` before write.
    #[arg(long = "schema", value_name = "FILE")]
    pub schema: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionPackageArgs {
    /// Path to the local extension ZIP package.
    #[arg(value_name = "PACKAGE")]
    pub package: PathBuf,

    /// Expected 64-hex-digit SHA-256 digest of the extension package.
    #[arg(long = "sha256")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionUninstallArgs {
    /// Installed extension identifier.
    #[arg(value_name = "IDENTIFIER")]
    pub identifier: String,

    /// Also purge database options and system states owned by this extension (requires stopped server).
    #[arg(long = "purge-data")]
    pub purge_data: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ExtensionPurgeDataArgs {
    /// Disabled extension identifier.
    #[arg(value_name = "IDENTIFIER")]
    pub identifier: String,

    /// Delete only `options` and `system_states` rows owned by this extension.
    #[arg(long = "options-only")]
    pub options_only: bool,
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
            "--server-version",
            "0.14.0",
            "--schema",
            "config.schema.json",
        ])
        .expect("valid extension enable args");

        match cli.command {
            Commands::Extension(ExtensionCommand::Enable(args)) => {
                assert_eq!(args.identifiers, vec!["http_api", "oidc_sso"]);
                assert!(args.dry_run);
                assert_eq!(args.server_version.as_deref(), Some("0.14.0"));
                assert_eq!(
                    args.schema.as_deref(),
                    Some(std::path::Path::new("config.schema.json"))
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_extension_disable_with_single_id() {
        let cli = Cli::try_parse_from(["cfms-ctl", "extension", "disable", "oidc_sso", "--dry-run"])
            .expect("valid extension disable args");

        match cli.command {
            Commands::Extension(ExtensionCommand::Disable(args)) => {
                assert_eq!(args.identifiers, vec!["oidc_sso"]);
                assert!(args.dry_run);
                assert!(args.schema.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rejects_extension_enable_without_identifiers() {
        assert!(Cli::try_parse_from(["cfms-ctl", "extension", "enable"]).is_err());
        assert!(Cli::try_parse_from(["cfms-ctl", "extension", "disable"]).is_err());
    }
}
