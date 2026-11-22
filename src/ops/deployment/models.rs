//! Data models, constants, transaction journal records, and dual-mode UI reports
//! for `cfms-ctl deployment`.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

pub const RELEASE_MANIFEST_FORMAT_VERSION: u32 = 1;
pub const RELEASE_PRODUCT_NAME: &str = "cfms-on-websocket";
pub const SETTINGS_FORMAT_VERSION: u32 = 1;
pub const TRANSACTION_FORMAT_VERSION: u32 = 2;

pub const RELEASE_MANIFEST_FILENAME: &str = "release-manifest.json";
pub const SETTINGS_FILENAME: &str = "settings.json";
pub const REQUIREMENTS_LOCK_FILENAME: &str = "requirements.lock";
pub const TRANSACTION_FILENAME: &str = "transaction.json";
pub const VERSIONS_DIRNAME: &str = "versions";
pub const STAGING_DIRNAME: &str = "staging";
pub const TX_JOURNAL_DIRNAME: &str = "tx";
pub const STATE_DIRNAME: &str = "state";
pub const RELEASE_SUBDIR: &str = "release";

pub const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ARCHIVE_MEMBERS: usize = 4096;
pub const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_STATE_BYTES: u64 = 1024 * 1024;
pub const MAX_STORED_RELEASES: usize = 1024;

pub const REQUIRED_RELEASE_FILES: &[&str] = &[
    "pyproject.toml",
    "uv.lock",
    "src/alembic.ini",
    "src/config.toml.sample",
    "src/main.py",
];

pub const OPERATOR_OWNED_PREFIXES: &[&str] = &[
    "src/.maintenance/",
    "src/content/files/",
    "src/content/logs/",
];

pub const PRESERVED_WORKSPACE_PREFIXES: &[&str] = &[
    "src/.maintenance/",
    "src/content/",
    "src/logs/",
    ".venv/",
];

/// Lightweight summary of `release-manifest.json` reused across maintenance domains (e.g. `backup export`).
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

/// Full release manifest stored in `release-manifest.json` (`format_version == 1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseManifest {
    pub format_version: u32,
    pub product: String,
    pub version: String,
    pub requires_python: String,
    #[serde(default)]
    pub managed_extensions: Vec<String>,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

/// Validated manifest paired with its exact canonical byte SHA-256 (`release_id`) and raw bytes.
#[derive(Debug, Clone)]
pub struct ValidatedManifest {
    pub release_id: String,
    pub raw_bytes: Vec<u8>,
    pub manifest: ReleaseManifest,
}

/// Persisted deployment environment preferences at `src/.maintenance/settings.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentSettings {
    pub format_version: u32,
    #[serde(default)]
    pub extras: Vec<String>,
}

impl Default for DeploymentSettings {
    fn default() -> Self {
        Self {
            format_version: SETTINGS_FORMAT_VERSION,
            extras: Vec::new(),
        }
    }
}

/// Lifecycle operation recorded in `src/.maintenance/transaction.json`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionOperation {
    Upgrade,
    Install,
}

impl std::fmt::Display for TransactionOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Upgrade => "upgrade",
            Self::Install => "install",
        })
    }
}

/// Recovery phase recorded in `src/.maintenance/transaction.json`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionPhase {
    Activation,
    DatabaseMigration,
    DatabaseRecoveryRequired,
}

impl std::fmt::Display for TransactionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Activation => "activation",
            Self::DatabaseMigration => "database-migration",
            Self::DatabaseRecoveryRequired => "database-recovery-required",
        })
    }
}

const fn default_tx_version() -> u32 {
    1
}

/// Persistent transaction state written to `src/.maintenance/transaction.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentTransaction {
    #[serde(default = "default_tx_version")]
    pub format_version: u32,
    pub transaction_id: String,
    pub operation: TransactionOperation,
    pub phase: TransactionPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    pub source_release_id: String,
    pub target_release_id: String,
    pub source_version: String,
    pub target_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_checkpoint_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_checkpoint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_db_revision: Option<String>,
    #[serde(default)]
    pub step_history: Vec<String>,
}

/// Health and metadata summary for a single snapshot stored under `src/.maintenance/versions/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredReleaseSummary {
    pub release_id: String,
    pub version: Option<String>,
    pub requires_python: Option<String>,
    pub file_count: usize,
    pub total_bytes: u64,
    pub has_saved_state: bool,
    pub active: bool,
    pub healthy: bool,
    pub verified_hashes: bool,
    pub created_epoch_secs: Option<u64>,
    #[serde(default)]
    pub issues: Vec<String>,
}

/// File verification mismatch discovered during active or stored release inspection.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrityMismatch {
    pub path: String,
    pub kind: String,
    pub detail: String,
}

/// Per-target verification result returned by `deployment verify` and `deployment status --verify`.
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseIntegrityReport {
    pub target: String,
    pub release_id: Option<String>,
    pub version: Option<String>,
    pub healthy: bool,
    pub checked_files: usize,
    pub verified_hashes: bool,
    pub mismatches: Vec<IntegrityMismatch>,
}

/// Archive checksum source description included in plans, confirmations, and reports.
#[derive(Debug, Clone, Serialize)]
pub struct ChecksumVerificationInfo {
    pub package_sha256: String,
    pub package_bytes: u64,
    pub source: String,
    pub verified_against_external: bool,
}

/// GitHub asset summary inspected during `check`, `update`, `install`, or `adopt`.
#[derive(Debug, Clone, Serialize)]
pub struct GitHubAssetSummary {
    pub name: String,
    pub format: String,
    pub size: u64,
    pub download_url: String,
    pub digest_sha256: Option<String>,
    pub sha256sums_sha256: String,
}

/// Report returned by `cfms-ctl deployment status`.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentStatusReport {
    pub project_root: String,
    pub mode: String,
    pub detected_version: Option<String>,
    pub active_release: Option<ReleaseManifestSummary>,
    pub active_release_healthy: bool,
    pub active_issues: Vec<String>,
    pub verified_hashes: bool,
    pub extras: Vec<String>,
    pub has_requirements_lock: bool,
    pub runtime_lock_holder_pid: Option<u32>,
    pub unfinished_transaction: bool,
    pub transaction: Option<DeploymentTransaction>,
    pub database_backend: Option<String>,
    pub database_revision: Option<String>,
    pub alembic_head: Option<String>,
    pub stored_releases: Vec<StoredReleaseSummary>,
    pub warnings: Vec<String>,
}

impl CommandReport for DeploymentStatusReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new("Deployment Status");
        table
            .row("Project Root", self.project_root.clone())
            .row("Installation Mode", self.mode.clone())
            .row(
                "Active Version",
                self.detected_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
            .row(
                "Active Release ID",
                self.active_release
                    .as_ref()
                    .and_then(|r| r.release_id.clone())
                    .unwrap_or_else(|| "(unmanaged / no release-manifest.json)".to_string()),
            )
            .row(
                "Active Tree Health",
                if self.active_release_healthy {
                    if self.verified_hashes {
                        "OK (SHA-256 verified)".to_string()
                    } else {
                        "OK (fast structural check)".to_string()
                    }
                } else {
                    format!("ISSUES ({})", self.active_issues.len())
                },
            )
            .row(
                "Configured Extras",
                if self.extras.is_empty() {
                    "(none)".to_string()
                } else {
                    self.extras.join(", ")
                },
            )
            .row("Requirements Lock", self.has_requirements_lock.to_string())
            .row(
                "Runtime Lock",
                self.runtime_lock_holder_pid.map_or_else(
                    || "free".to_string(),
                    |pid| format!("LOCKED (pid {pid})"),
                ),
            )
            .row(
                "Pending Transaction",
                match &self.transaction {
                    Some(tx) => format!("{} ({})", tx.operation, tx.phase),
                    None => "none".to_string(),
                },
            )
            .row(
                "Database",
                match (&self.database_backend, &self.database_revision, &self.alembic_head) {
                    (Some(backend), Some(rev), Some(head)) => {
                        format!("{backend} (live={rev}, head={head})")
                    }
                    (Some(backend), None, head) => format!(
                        "{backend} (uninitialized/unreadable, head={})",
                        head.as_deref().unwrap_or("unknown")
                    ),
                    _ => "unavailable".to_string(),
                },
            )
            .row("Stored Snapshots", self.stored_releases.len().to_string());
        table.print();

        if !self.stored_releases.is_empty() {
            println!();
            println!("Stored Releases:");
            for rel in &self.stored_releases {
                let short_id = &rel.release_id[..12.min(rel.release_id.len())];
                let ver = rel.version.as_deref().unwrap_or("unknown");
                let marker = if rel.active { "*" } else { " " };
                let health = if rel.healthy { "healthy" } else { "corrupt" };
                println!(
                    "  {marker} {short_id}  v{ver:<16}  {health:<8}  {} files",
                    rel.file_count
                );
                for issue in &rel.issues {
                    ui.print_warning(&format!("    [{short_id}] {issue}"));
                }
            }
        }

        for issue in &self.active_issues {
            ui.print_warning(issue);
        }
        for warning in &self.warnings {
            ui.print_warning(warning);
        }
    }
}

/// Report returned by `cfms-ctl deployment verify`.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentVerifyReport {
    pub overall_healthy: bool,
    pub reports: Vec<ReleaseIntegrityReport>,
}

impl CommandReport for DeploymentVerifyReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new("Deployment Integrity Verification");
        table
            .row("Overall Status", if self.overall_healthy { "PASS" } else { "FAILED" })
            .row("Targets Checked", self.reports.len().to_string());
        table.print();

        for item in &self.reports {
            println!();
            let ver = item.version.as_deref().unwrap_or("unknown");
            let id = item
                .release_id
                .as_deref()
                .map(|s| &s[..12.min(s.len())])
                .unwrap_or("n/a");
            let status = if item.healthy { "OK" } else { "FAILED" };
            println!(
                "  [{status}] {} (id={id}, v{ver}, {} files)",
                item.target, item.checked_files
            );
            for mismatch in &item.mismatches {
                ui.print_error(&format!(
                    "    - {} ({}): {}",
                    mismatch.path, mismatch.kind, mismatch.detail
                ));
            }
        }
        println!();
        if self.overall_healthy {
            ui.print_success("All inspected deployment release trees passed SHA-256 verification.");
        } else {
            ui.print_error("One or more release trees failed SHA-256 verification.");
        }
    }
}

/// Report returned by `cfms-ctl deployment check`.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentCheckReport {
    pub repository: String,
    pub current_version: Option<String>,
    pub target_version: String,
    pub tag_name: String,
    pub prerelease: bool,
    pub update_available: bool,
    pub asset: GitHubAssetSummary,
    pub release_url: String,
    pub published_at: Option<String>,
    pub warnings: Vec<String>,
}

impl CommandReport for DeploymentCheckReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new(format!("Deployment Release Check ({})", self.repository));
        table
            .row(
                "Current Version",
                self.current_version
                    .clone()
                    .unwrap_or_else(|| "(unknown)".to_string()),
            )
            .row("Target Release", format!("v{} ({})", self.target_version, self.tag_name))
            .row("Update Available", self.update_available.to_string())
            .row("Archive Asset", format!("{} ({} bytes)", self.asset.name, self.asset.size))
            .row("SHA256SUMS Digest", self.asset.sha256sums_sha256.clone())
            .row(
                "GitHub Asset Digest",
                self.asset
                    .digest_sha256
                    .clone()
                    .unwrap_or_else(|| "null (not reported by GitHub API)".to_string()),
            )
            .row("Release Page", self.release_url.clone());
        table.print();
        for warning in &self.warnings {
            ui.print_warning(warning);
        }
        println!();
        if self.update_available {
            ui.print_success(&format!(
                "Update available: {} -> {}",
                self.current_version.as_deref().unwrap_or("uninstalled"),
                self.target_version
            ));
        } else {
            ui.print_success(&format!(
                "Active deployment is up to date with release {}.",
                self.target_version
            ));
        }
    }
}

/// Unified structured report for `upgrade`, `update`, `resume`, `install`, and `adopt`.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentMutationReport {
    pub operation: String,
    pub dry_run: bool,
    pub outcome: String,
    pub source_release_id: Option<String>,
    pub source_version: Option<String>,
    pub target_release_id: Option<String>,
    pub target_version: Option<String>,
    pub checksum: Option<ChecksumVerificationInfo>,
    pub files_added: usize,
    pub files_updated: usize,
    pub files_removed: usize,
    pub extras: Vec<String>,
    pub config_changed: bool,
    pub config_backup_path: Option<String>,
    pub db_revision_before: Option<String>,
    pub db_revision_after: Option<String>,
    pub backup_archive_path: Option<String>,
    pub backup_generated_key: Option<String>,
    pub warnings: Vec<String>,
    pub next_steps: Vec<String>,
}

impl CommandReport for DeploymentMutationReport {
    fn render_human(&self, ui: &UiConsole) {
        let heading = if self.dry_run {
            format!("Deployment {} Preview (Dry Run)", self.operation)
        } else {
            format!("Deployment {} Summary", self.operation)
        };
        let mut table = KeyValueTable::new(heading);
        table
            .row("Outcome", self.outcome.clone())
            .row(
                "Source",
                match (&self.source_version, &self.source_release_id) {
                    (Some(v), Some(id)) => format!("v{v} ({})", &id[..12.min(id.len())]),
                    (Some(v), None) => format!("v{v}"),
                    (None, _) => "(none)".to_string(),
                },
            )
            .row(
                "Target",
                match (&self.target_version, &self.target_release_id) {
                    (Some(v), Some(id)) => format!("v{v} ({})", &id[..12.min(id.len())]),
                    (Some(v), None) => format!("v{v}"),
                    (None, _) => "(none)".to_string(),
                },
            );
        if let Some(ref csum) = self.checksum {
            table
                .row("Package SHA-256", csum.package_sha256.clone())
                .row("Checksum Source", csum.source.clone());
        }
        table
            .row(
                "File Changes",
                format!(
                    "+{} added / ~{} updated / -{} removed",
                    self.files_added, self.files_updated, self.files_removed
                ),
            )
            .row(
                "Extras",
                if self.extras.is_empty() {
                    "(none)".to_string()
                } else {
                    self.extras.join(", ")
                },
            )
            .row(
                "Config Synced",
                match &self.config_backup_path {
                    Some(bak) => format!("{} (backup: {bak})", self.config_changed),
                    None => self.config_changed.to_string(),
                },
            )
            .row(
                "Database Revision",
                format!(
                    "{} -> {}",
                    self.db_revision_before.as_deref().unwrap_or("none"),
                    self.db_revision_after.as_deref().unwrap_or("unchanged")
                ),
            );
        if let Some(ref bak) = self.backup_archive_path {
            table.row("Safety Backup", bak.clone());
        }
        table.print();

        if let Some(ref key) = self.backup_generated_key {
            println!();
            ui.print_warning(
                "Store this pre-operation `.confbak` decryption key safely; it will not be shown again:",
            );
            println!("  {key}");
        }

        for warning in &self.warnings {
            ui.print_warning(warning);
        }
        if !self.next_steps.is_empty() {
            println!();
            println!("Next steps:");
            for step in &self.next_steps {
                println!("  - {step}");
            }
        }
        println!();
        if self.dry_run {
            ui.print_success("Dry-run completed; no workspace files or database state were changed.");
        } else {
            ui.print_success(&format!("Deployment {} finished: {}.", self.operation, self.outcome));
        }
    }
}

/// Report returned by `cfms-ctl deployment prune`.
#[derive(Debug, Clone, Serialize)]
pub struct DeploymentPruneReport {
    pub dry_run: bool,
    pub active_release_id: String,
    pub kept_release_ids: Vec<String>,
    pub removed_release_ids: Vec<String>,
    pub freed_bytes: u64,
    pub warnings: Vec<String>,
}

impl CommandReport for DeploymentPruneReport {
    fn render_human(&self, ui: &UiConsole) {
        let title = if self.dry_run {
            "Deployment Prune Preview (Dry Run)"
        } else {
            "Deployment Prune Summary"
        };
        let mut table = KeyValueTable::new(title);
        table
            .row("Active Release", self.active_release_id.clone())
            .row("Retained Snapshots", self.kept_release_ids.len().to_string())
            .row(
                if self.dry_run {
                    "Eligible to Remove"
                } else {
                    "Removed Snapshots"
                },
                self.removed_release_ids.len().to_string(),
            )
            .row("Disk Space Freed (bytes)", self.freed_bytes.to_string());
        table.print();

        if !self.removed_release_ids.is_empty() {
            println!();
            println!(
                "{}:",
                if self.dry_run { "Would remove" } else { "Removed" }
            );
            for id in &self.removed_release_ids {
                println!("  - {id}");
            }
        }
        for w in &self.warnings {
            ui.print_warning(w);
        }
    }
}
