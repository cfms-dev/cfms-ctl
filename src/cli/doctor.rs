//! CLI arguments for `cfms-ctl doctor`.

use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Skip live database connection and schema drift inspection.
    #[arg(long = "skip-db")]
    pub skip_db: bool,

    /// Skip storage backend preflight checks (e.g. S3 HeadBucket probe).
    #[arg(long = "skip-storage")]
    pub skip_storage: bool,
}
