//! `cfms-ctl deployment`: Packaged release inspection, GitHub update checks,
//! staged upgrades, interrupted-upgrade recovery, cold installs, adoption, and snapshot pruning.

pub mod archive;
pub mod database;
pub mod environment;
pub mod lifecycle;
pub mod manifest;
pub mod models;
pub mod online;
pub mod repository;

pub use models::{
    DeploymentCheckReport, DeploymentMutationReport, DeploymentPruneReport, DeploymentSettings,
    DeploymentStatusReport, DeploymentTransaction, DeploymentVerifyReport, ReleaseManifest,
    ReleaseManifestSummary, StoredReleaseSummary, TransactionOperation, TransactionPhase,
};

use crate::cli::deployment::DeploymentCommand;
use crate::core::Result;
use crate::ops::AppContext;

pub async fn handle(ctx: &AppContext, cmd: DeploymentCommand) -> Result<()> {
    match cmd {
        DeploymentCommand::Status(args) => lifecycle::handle_status(ctx, args).await,
        DeploymentCommand::Verify(args) => lifecycle::handle_verify(ctx, args).await,
        DeploymentCommand::Check(args) => lifecycle::handle_check(ctx, args).await,
        DeploymentCommand::Upgrade(args) => lifecycle::handle_upgrade(ctx, args).await,
        DeploymentCommand::Update(args) => lifecycle::handle_update(ctx, args).await,
        DeploymentCommand::Resume(args) => lifecycle::handle_resume(ctx, args).await,
        DeploymentCommand::Prune(args) => lifecycle::handle_prune(ctx, args).await,
        DeploymentCommand::Install(args) => lifecycle::handle_install(ctx, args).await,
        DeploymentCommand::Adopt(args) => lifecycle::handle_adopt(ctx, args).await,
    }
}
