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

    /// Enable an installed extension and its transitive dependencies in `config.toml`.
    Enable(ExtensionIdentifierArgs),

    /// Disable an extension and any enabled dependents in `config.toml`.
    Disable(ExtensionIdentifierArgs),

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
