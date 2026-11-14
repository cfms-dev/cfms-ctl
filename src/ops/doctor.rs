//! `cfms-ctl doctor`: Non-destructive comprehensive diagnostics across workspace paths,
//! runtime lock state, configuration health, and live database schema drift.

use serde::Serialize;
use crate::cli::doctor::DoctorArgs;
use crate::core::{ConfigDocument, Result, RuntimeLock, ServerConfigSummary, WorkspacePaths};
use crate::db::DbPool;
use crate::db::schema::{SchemaDriftReport, SchemaInspector};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

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
            .row("config.toml.sample Present", self.config_template_exists.to_string());

        if let Some(summary) = &self.config_summary {
            cfg_table
                .row("Bind Endpoint", format!("{}:{}", summary.host, summary.port))
                .row("Debug Mode", summary.debug.to_string())
                .row("server.secret_key Configured", summary.has_secret_key.to_string())
                .row("security.pepper Configured", summary.has_pepper.to_string())
                .row("Database Backend", summary.database.kind.to_string())
                .row(
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
                    format!("{}/{}", schema.present_core_tables, schema.expected_core_tables),
                )
                .row(
                    "Missing Core Tables",
                    if schema.missing_tables.is_empty() {
                        "0 (none)".to_string()
                    } else {
                        schema.missing_tables.join(", ")
                    },
                );
            db_table.print();
        } else if let Some(err) = &self.database_error {
            ui.print_warning(&format!("Database inspection failed: {err}"));
        }

        println!();
        if self.healthy {
            ui.print_success("All inspected CFMS workspace and schema checks passed.");
        } else {
            ui.print_warning("One or more diagnostic checks reported warnings or drift.");
        }
    }
}

pub async fn handle(ctx: &AppContext, args: DoctorArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let server_locked = RuntimeLock::is_locked(&paths);
    let unfinished_transaction = paths.transaction_path().is_file();
    let config_exists = paths.config_path.is_file();
    let config_template_exists = paths.config_template_path.is_file();

    let mut config_summary = None;
    let mut config_error = None;
    let mut database_schema = None;
    let mut database_error = None;

    if config_exists {
        match ConfigDocument::load(&paths.config_path).and_then(|doc| doc.summary()) {
            Ok(summary) => {
                if !args.skip_db {
                    match DbPool::connect(&summary.database, &paths).await {
                        Ok(pool) => match SchemaInspector::inspect(&pool).await {
                            Ok(report) => database_schema = Some(report),
                            Err(e) => database_error = Some(e.to_string()),
                        },
                        Err(e) => database_error = Some(e.to_string()),
                    }
                }
                config_summary = Some(summary);
            }
            Err(e) => config_error = Some(e.to_string()),
        }
    } else {
        config_error = Some(format!(
            "Configuration file '{}' does not exist",
            paths.config_path.display()
        ));
    }

    let config_healthy = config_summary
        .as_ref()
        .is_some_and(|s| s.has_pepper && s.has_secret_key);
    let db_healthy = if args.skip_db {
        true
    } else {
        database_schema.as_ref().is_some_and(|d| d.healthy)
    };
    let healthy = !unfinished_transaction && config_healthy && db_healthy;

    let report = DoctorReport {
        paths,
        server_locked,
        unfinished_transaction,
        config_exists,
        config_template_exists,
        config_summary,
        config_error,
        database_schema,
        database_error,
        healthy,
    };

    ctx.ui.render(&report);
    Ok(())
}
