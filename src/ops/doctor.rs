//! `cfms-ctl doctor`: Non-destructive comprehensive diagnostics across workspace paths,
//! runtime lock state, configuration health, storage reachability, and live database schema drift.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::Serialize;
use tokio::sync::Notify;
use crate::cli::doctor::DoctorArgs;
use crate::core::{
    ConfigDocument, Result, RuntimeLock, ServerConfigSummary, StorageProviderKind, WorkspacePaths,
};
use crate::db::DbPool;
use crate::db::schema::{
    ExtractorMode, SchemaDriftReport, SchemaInspector, builtin_schema_ir, extract_code_schema_ir,
};
use crate::ops::AppContext;
use crate::storage::{S3Storage, resolve_storage};
use crate::ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole};

const DOCTOR_SPINNER_REVEAL_DELAY: Duration = Duration::from_millis(250);
const DOCTOR_SPINNER_TICK_INTERVAL: Duration = Duration::from_millis(120);

/// Storage backend reachability report included in [`DoctorReport`].
#[derive(Debug, Clone, Serialize)]
pub struct StorageHealthReport {
    pub provider: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_path_style: Option<bool>,
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Comprehensive diagnostic report returned by `cfms-ctl doctor`.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub paths: WorkspacePaths,
    pub server_locked: bool,
    pub unfinished_transaction: bool,
    pub config_exists: bool,
    pub config_template_exists: bool,
    pub config_summary: Option<ServerConfigSummary>,
    pub config_error: Option<String>,
    pub storage_health: Option<StorageHealthReport>,
    pub database_schema: Option<SchemaDriftReport>,
    pub database_error: Option<String>,
    pub healthy: bool,
}

impl CommandReport for DoctorReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut ws_table = KeyValueTable::new("Workspace & Runtime State");
        ws_table
            .row("Project Root", self.paths.project_root.display().to_string())
            .row("Server Root", self.paths.server_root.display().to_string())
            .row("Config File", self.paths.config_path.display().to_string())
            .row(
                "Server Lock (.maintenance/server.lock)",
                if self.server_locked {
                    "LOCKED (server or maintenance active)"
                } else {
                    "FREE (server stopped)"
                },
            )
            .row(
                "Deployment Transaction",
                if self.unfinished_transaction {
                    "UNFINISHED (run `cfms-ctl deployment resume`)"
                } else {
                    "Clean"
                },
            );
        ws_table.print();

        let mut cfg_table = KeyValueTable::new("Configuration Summary (Tolerant Parser)");
        cfg_table
            .row("config.toml Present", self.config_exists.to_string())
            .row(
                "config.toml.sample Present",
                self.config_template_exists.to_string(),
            );

        if let Some(summary) = &self.config_summary {
            cfg_table
                .row("Bind Endpoint", format!("{}:{}", summary.host, summary.port))
                .row("Debug Mode", summary.debug.to_string())
                .row(
                    "server.secret_key Configured",
                    summary.has_secret_key.to_string(),
                )
                .row("security.pepper Configured", summary.has_pepper.to_string())
                .row("Database Backend", summary.database.kind.to_string())
                .row("Storage Backend", summary.storage_provider.to_string());
            if let Some(ref s3) = summary.s3 {
                cfg_table
                    .row(
                        "S3 Bucket",
                        if s3.bucket.is_empty() {
                            "(empty)".to_string()
                        } else {
                            s3.bucket.clone()
                        },
                    )
                    .row(
                        "S3 Endpoint",
                        s3.endpoint_url
                            .clone()
                            .unwrap_or_else(|| "(AWS default)".to_string()),
                    )
                    .row("S3 Addressing Style", s3.addressing_style.to_string())
                    .row(
                        "S3 Pool Connections",
                        s3.max_pool_connections.to_string(),
                    );
            }
            cfg_table.row(
                "Enabled Extensions",
                if summary.enabled_extensions.is_empty() {
                    "(none)".to_string()
                } else {
                    summary.enabled_extensions.join(", ")
                },
            );
        } else if let Some(err) = &self.config_error {
            cfg_table.row("Configuration Error", err.clone());
        }
        cfg_table.print();

        if let Some(storage) = &self.storage_health {
            let mut st_table = KeyValueTable::new("Storage Backend Preflight");
            st_table
                .row("Provider", storage.provider.clone())
                .row("Target", storage.target.clone());
            if let Some(ref region) = storage.resolved_region {
                st_table.row("Effective Region", region.clone());
            }
            if let Some(path_style) = storage.force_path_style {
                st_table.row("Force Path Style", path_style.to_string());
            }
            st_table.row(
                "Connectivity",
                if storage.healthy {
                    "OK".to_string()
                } else {
                    "FAILED".to_string()
                },
            );
            st_table.print();
            if let Some(ref err) = storage.error {
                ui.print_warning(&format!("Storage preflight failed: {err}"));
            }
        }

        if let Some(schema) = &self.database_schema {
            let mut db_table = KeyValueTable::new("Database & Schema Preflight");
            db_table
                .row("Dialect", schema.dialect.to_string())
                .row(
                    "Current Revision",
                    schema
                        .current_revision
                        .clone()
                        .unwrap_or_else(|| "(unversioned)".to_string()),
                )
                .row("Expected Head Revision", schema.expected_revision.clone())
                .row("Revision Matches Head", schema.revision_matches.to_string())
                .row(
                    "Core Tables Present",
                    format!(
                        "{}/{}",
                        schema.present_core_tables, schema.expected_core_tables
                    ),
                )
                .row(
                    "Missing Core Tables",
                    if schema.missing_tables.is_empty() {
                        "0 (none)".to_string()
                    } else {
                        schema.missing_tables.join(", ")
                    },
                );
            if !schema.column_mismatches.is_empty() {
                db_table.row("Column Drift", schema.column_mismatches.join("; "));
            }
            if !schema.constraint_mismatches.is_empty() {
                db_table.row(
                    "Constraint Drift",
                    format!("{} difference(s)", schema.constraint_mismatches.len()),
                );
            }
            if !schema.index_mismatches.is_empty() {
                db_table.row(
                    "Index Drift",
                    format!("{} difference(s)", schema.index_mismatches.len()),
                );
            }
            db_table.print();
        } else if let Some(err) = &self.database_error {
            ui.print_warning(&format!("Database inspection failed: {err}"));
        }

        println!();
        if self.healthy {
            ui.print_success("All inspected CFMS workspace, storage, and schema checks passed.");
        } else {
            ui.print_warning("One or more diagnostic checks reported warnings or errors.");
        }
    }
}

/// Delayed spinner that stays hidden during sub-250ms local diagnostics and reveals smoothly on
/// `stderr` whenever I/O-bound checks take noticeable wall-clock time.
struct DelayedDoctorProgress {
    bar: ProgressBar,
    done: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl DelayedDoctorProgress {
    fn start(format: OutputFormat, initial_msg: &str) -> Self {
        let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::hidden());
        if let Ok(style) = ProgressStyle::with_template(
            "{spinner:.cyan} [{elapsed_precise}] Checking workspace: {msg}",
        ) {
            bar.set_style(style);
        }
        bar.set_message(initial_msg.to_string());

        let done = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());

        if format == OutputFormat::Human {
            let bar_bg = bar.clone();
            let done_bg = Arc::clone(&done);
            let notify_bg = Arc::clone(&notify);
            tokio::spawn(async move {
                tokio::select! {
                    () = tokio::time::sleep(DOCTOR_SPINNER_REVEAL_DELAY) => {
                        if !done_bg.load(Ordering::Acquire) {
                            bar_bg.set_draw_target(ProgressDrawTarget::stderr());
                            bar_bg.enable_steady_tick(DOCTOR_SPINNER_TICK_INTERVAL);
                        }
                    }
                    () = notify_bg.notified() => {}
                }
            });
        }

        Self { bar, done, notify }
    }

    fn set_stage(&self, msg: impl Into<String>) {
        self.bar.set_message(msg.into());
    }

    fn finish(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
            self.bar.finish_and_clear();
        }
    }
}

impl Drop for DelayedDoctorProgress {
    fn drop(&mut self) {
        self.finish();
    }
}

async fn check_storage_health(
    paths: &WorkspacePaths,
    doc: &ConfigDocument,
    summary: &ServerConfigSummary,
    progress: &DelayedDoctorProgress,
) -> StorageHealthReport {
    let provider_kind = summary.storage_provider;
    if provider_kind == StorageProviderKind::S3 {
        let s3_cfg = match doc.s3_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                return StorageHealthReport {
                    provider: provider_kind.to_string(),
                    target: "(unconfigured S3 bucket)".to_string(),
                    resolved_region: None,
                    force_path_style: None,
                    healthy: false,
                    error: Some(e.to_string()),
                };
            }
        };

        progress.set_stage("Resolving S3 client and probing bucket (HeadBucket)...");
        match S3Storage::from_config(&s3_cfg).await {
            Ok(s3) => {
                let target = crate::storage::StorageBackend::target_description(&s3);
                let resolved_region = Some(s3.region().to_string());
                let force_path_style = Some(s3.force_path_style());
                match crate::storage::StorageBackend::preflight(&s3).await {
                    Ok(()) => StorageHealthReport {
                        provider: provider_kind.to_string(),
                        target,
                        resolved_region,
                        force_path_style,
                        healthy: true,
                        error: None,
                    },
                    Err(e) => StorageHealthReport {
                        provider: provider_kind.to_string(),
                        target,
                        resolved_region,
                        force_path_style,
                        healthy: false,
                        error: Some(e.to_string()),
                    },
                }
            }
            Err(e) => StorageHealthReport {
                provider: provider_kind.to_string(),
                target: format!("s3://{}", s3_cfg.bucket),
                resolved_region: s3_cfg.region_name.clone(),
                force_path_style: None,
                healthy: false,
                error: Some(e.to_string()),
            },
        }
    } else {
        progress.set_stage("Checking local storage root...");
        match resolve_storage(paths, doc).await {
            Ok(storage) => {
                let target = storage.target_description();
                match storage.preflight().await {
                    Ok(()) => StorageHealthReport {
                        provider: provider_kind.to_string(),
                        target,
                        resolved_region: None,
                        force_path_style: None,
                        healthy: true,
                        error: None,
                    },
                    Err(e) => StorageHealthReport {
                        provider: provider_kind.to_string(),
                        target,
                        resolved_region: None,
                        force_path_style: None,
                        healthy: false,
                        error: Some(e.to_string()),
                    },
                }
            }
            Err(e) => StorageHealthReport {
                provider: provider_kind.to_string(),
                target: paths.server_root.display().to_string(),
                resolved_region: None,
                force_path_style: None,
                healthy: false,
                error: Some(e.to_string()),
            },
        }
    }
}

pub async fn handle(ctx: &AppContext, args: DoctorArgs) -> Result<()> {
    let report = diagnose(ctx, &args).await?;
    ctx.ui.render(&report);
    Ok(())
}

/// Run diagnostics and return the structured [`DoctorReport`] without printing.
pub async fn diagnose(ctx: &AppContext, args: &DoctorArgs) -> Result<DoctorReport> {
    let progress = DelayedDoctorProgress::start(ctx.ui.format(), "Discovering workspace paths...");
    let paths = ctx.resolve_paths()?;
    let server_locked = RuntimeLock::is_locked(&paths);
    let unfinished_transaction = paths.transaction_path().is_file();
    let config_exists = paths.config_path.is_file();
    let config_template_exists = paths.config_template_path.is_file();

    let mut config_summary = None;
    let mut config_error = None;
    let mut storage_health = None;
    let mut database_schema = None;
    let mut database_error = None;

    if config_exists {
        progress.set_stage("Parsing and validating config.toml...");
        match ConfigDocument::load(&paths.config_path) {
            Ok(doc) => match doc.summary() {
                Ok(summary) => {
                    if !args.skip_storage {
                        storage_health =
                            Some(check_storage_health(&paths, &doc, &summary, &progress).await);
                    }
                    if !args.skip_db {
                        progress.set_stage("Extracting target schema contract...");
                        let target_ir = extract_code_schema_ir(
                            &paths,
                            ExtractorMode::Auto,
                            None,
                            None,
                            false,
                            true,
                        )
                        .await
                        .unwrap_or_else(|_| builtin_schema_ir(false));

                        progress.set_stage("Connecting to database and inspecting schema drift...");
                        match DbPool::connect(&summary.database, &paths).await {
                            Ok(pool) => {
                                match SchemaInspector::inspect_against_ir(&pool, &target_ir).await {
                                    Ok(report) => database_schema = Some(report),
                                    Err(e) => database_error = Some(e.to_string()),
                                }
                                pool.close().await;
                            }
                            Err(e) => database_error = Some(e.to_string()),
                        }
                    }
                    config_summary = Some(summary);
                }
                Err(e) => config_error = Some(e.to_string()),
            },
            Err(e) => config_error = Some(e.to_string()),
        }
    } else {
        config_error = Some(format!(
            "Configuration file '{}' does not exist",
            paths.config_path.display()
        ));
    }

    progress.finish();

    let config_healthy = config_summary
        .as_ref()
        .is_some_and(|s| s.has_pepper && s.has_secret_key);
    let storage_healthy = if args.skip_storage {
        true
    } else {
        storage_health.as_ref().is_some_and(|s| s.healthy)
    };
    let db_healthy = if args.skip_db {
        true
    } else {
        database_schema.as_ref().is_some_and(|d| d.healthy)
    };
    let healthy = !unfinished_transaction && config_healthy && storage_healthy && db_healthy;

    Ok(DoctorReport {
        paths,
        server_locked,
        unfinished_transaction,
        config_exists,
        config_template_exists,
        config_summary,
        config_error,
        storage_health,
        database_schema,
        database_error,
        healthy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delayed_doctor_progress_handles_fast_and_slow_runs_cleanly() {
        // Fast completion before 250ms reveal threshold
        let fast = DelayedDoctorProgress::start(OutputFormat::Human, "Fast check...");
        fast.set_stage("Done fast");
        fast.finish();

        // Slow completion exceeding reveal threshold
        let slow = DelayedDoctorProgress::start(OutputFormat::Human, "Slow check...");
        tokio::time::sleep(Duration::from_millis(300)).await;
        slow.set_stage("Completed slow check");
        slow.finish();

        // JSON mode remains silent cleanly
        let json = DelayedDoctorProgress::start(OutputFormat::Json, "Hidden");
        json.finish();
    }
}
