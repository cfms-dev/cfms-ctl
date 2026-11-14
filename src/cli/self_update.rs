//! `cfms-ctl self-update` command arguments.

use clap::Args;

#[derive(Debug, Clone, Args)]
#[command(disable_version_flag = true)]
pub struct SelfUpdateArgs {
    /// Only check whether a newer release is available on GitHub without downloading or installing
    #[arg(short = 'c', long)]
    pub check: bool,

    /// Update to a specific version or release tag (e.g. `0.2.0` or `v0.2.0`) instead of the latest release
    #[arg(long = "version", visible_alias = "target-version", value_name = "VERSION")]
    pub version: Option<String>,
}
