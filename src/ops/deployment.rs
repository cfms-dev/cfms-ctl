//! `cfms-ctl deployment`: Packaged release inspection, GitHub update checks,
//! staged upgrades, rollbacks, transaction resumption, and version pruning.

use serde::{Deserialize, Serialize};
use crate::cli::deployment::{
    DeploymentCommand, DeploymentDowngradeArgs, DeploymentPruneArgs, DeploymentUpdateArgs,
    DeploymentUpgradeArgs,
};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Release manifest metadata stored in packaged CFMS deployments (`release-manifest.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifestSummary {
    #[serde(default)]
    pub release_id: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub schema_revision: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Report returned by `cfms-ctl deployment status`.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentStatusReport {
    pub project_root: String,
    pub mode: String,
    pub detected_version: Option<String>,
    pub active_release: Option<ReleaseManifestSummary>,
    pub unfinished_transaction: bool,
    pub stored_releases: Vec<String>,
}

impl CommandReport for DeploymentStatusReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("Deployment Status");
        table
            .row("Project Root", self.project_root.clone())
            .row("Installation Mode", self.mode.clone())
            .row(
                "Detected Version",
                self.detected_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
            .row(
                "Active Release ID",
                self.active_release
                    .as_ref()
                    .and_then(|r| r.release_id.clone())
                    .unwrap_or_else(|| "(git / unpacked workspace)".to_string()),
            )
            .row(
                "Unfinished Transaction",
                self.unfinished_transaction.to_string(),
            )
            .row(
                "Stored Historical Releases",
                if self.stored_releases.is_empty() {
                    "0".to_string()
                } else {
                    format!("{} ({})", self.stored_releases.len(), self.stored_releases.join(", "))
                },
            );
        table.print();
    }
}

pub async fn handle(ctx: &AppContext, cmd: DeploymentCommand) -> Result<()> {
    match cmd {
        DeploymentCommand::Status => handle_status(ctx),
        DeploymentCommand::Check => Err(CfmsError::NotImplementedYet("deployment check")),
        DeploymentCommand::Upgrade(_args) => {
            Err(CfmsError::NotImplementedYet("deployment upgrade"))
        }
        DeploymentCommand::Update(_args) => Err(CfmsError::NotImplementedYet("deployment update")),
        DeploymentCommand::Downgrade(_args) => {
            Err(CfmsError::NotImplementedYet("deployment downgrade"))
        }
        DeploymentCommand::Resume => Err(CfmsError::NotImplementedYet("deployment resume")),
        DeploymentCommand::Prune(_args) => Err(CfmsError::NotImplementedYet("deployment prune")),
    }
}

fn handle_status(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let active_release = if paths.release_manifest_path.is_file() {
        let raw = std::fs::read_to_string(&paths.release_manifest_path)?;
        serde_json::from_str::<ReleaseManifestSummary>(&raw).ok()
    } else {
        None
    };

    let pyproject_path = paths.project_root.join("pyproject.toml");
    let detected_version = active_release
        .as_ref()
        .and_then(|r| r.version.clone())
        .or_else(|| {
            let content = std::fs::read_to_string(pyproject_path).ok()?;
            let doc = content.parse::<toml_edit::DocumentMut>().ok()?;
            doc.get("project")?
                .get("version")?
                .as_str()
                .map(ToString::to_string)
        });

    let versions_dir = paths.maintenance_root.join("versions");
    let mut stored_releases = Vec::new();
    if versions_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&versions_dir)
    {
        for entry in entries.flatten() {
            if entry.path().is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                stored_releases.push(name.to_string());
            }
        }
    }
    stored_releases.sort();

    let mode = if active_release.is_some() {
        "packaged-release".to_string()
    } else {
        "source-tree".to_string()
    };

    let report = DeploymentStatusReport {
        project_root: paths.project_root.display().to_string(),
        mode,
        detected_version,
        active_release,
        unfinished_transaction: paths.transaction_path().is_file(),
        stored_releases,
    };
    ctx.ui.render(&report);
    Ok(())
}

#[allow(dead_code)]
type _UnusedArgs = (
    DeploymentUpgradeArgs,
    DeploymentUpdateArgs,
    DeploymentDowngradeArgs,
    DeploymentPruneArgs,
);
