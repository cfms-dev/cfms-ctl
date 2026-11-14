//! `cfms-ctl database`: Multi-backend database status, live schema drift checking,
//! native schema upgrades, cross-engine migration, and revision stamping.

use serde::Serialize;
use crate::cli::database::{DatabaseCommand, DatabaseMigrateArgs, DatabaseStampArgs};
use crate::core::{CfmsError, Result};
use crate::db::DatabaseKind;
use crate::db::schema::{SchemaDriftReport, SchemaInspector};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Report for `cfms-ctl database status`.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseStatusReport {
    pub dialect: DatabaseKind,
    pub endpoint: String,
    pub current_revision: Option<String>,
    pub expected_revision: String,
    pub table_count: usize,
    pub tables: Vec<String>,
}

impl CommandReport for DatabaseStatusReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("Database Backend Status");
        table
            .row("Dialect", self.dialect.to_string())
            .row("Target", self.endpoint.clone())
            .row(
                "Current Revision",
                self.current_revision
                    .clone()
                    .unwrap_or_else(|| "(none)".to_string()),
            )
            .row("Expected Head Revision", self.expected_revision.clone())
            .row("Total Tables", self.table_count.to_string());
        table.print();
    }
}

impl CommandReport for SchemaDriftReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new("Database Schema Drift Preflight");
        table
            .row("Dialect", self.dialect.to_string())
            .row(
                "Current Revision",
                self.current_revision
                    .clone()
                    .unwrap_or_else(|| "(unversioned)".to_string()),
            )
            .row("Expected Head Revision", self.expected_revision.clone())
            .row("Revision Matches Head", self.revision_matches.to_string())
            .row(
                "Core Application Tables",
                format!("{}/{}", self.present_core_tables, self.expected_core_tables),
            )
            .row(
                "Missing Core Tables",
                if self.missing_tables.is_empty() {
                    "None".to_string()
                } else {
                    self.missing_tables.join(", ")
                },
            )
            .row(
                "Extra Tables",
                if self.extra_tables.is_empty() {
                    "None".to_string()
                } else {
                    self.extra_tables.join(", ")
                },
            );
        table.print();

        if self.healthy {
            ui.print_success("Database schema matches the expected CFMS contract.");
        } else {
            ui.print_warning("Schema drift or revision mismatch detected.");
        }
    }
}

pub async fn handle(ctx: &AppContext, cmd: DatabaseCommand) -> Result<()> {
    match cmd {
        DatabaseCommand::Status => handle_status(ctx).await,
        DatabaseCommand::Check => handle_check(ctx).await,
        DatabaseCommand::Upgrade => handle_upgrade(ctx).await,
        DatabaseCommand::Migrate(args) => handle_migrate(ctx, args).await,
        DatabaseCommand::Stamp(args) => handle_stamp(ctx, args).await,
    }
}

async fn handle_status(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let doc = ctx.load_config(&paths)?;
    let db_cfg = doc.database_config()?;
    let endpoint = match db_cfg.kind {
        DatabaseKind::Sqlite => paths.resolve_sqlite_path(&db_cfg.file).display().to_string(),
        DatabaseKind::Mysql | DatabaseKind::Postgresql => {
            format!("{}:{}/{}", db_cfg.host, db_cfg.port, db_cfg.name)
        }
    };

    let pool = ctx.connect_db(&paths).await?;
    pool.ping().await?;
    let tables = pool.list_tables().await?;
    let current_revision = pool.current_revision().await?;

    let report = DatabaseStatusReport {
        dialect: pool.kind(),
        endpoint,
        current_revision,
        expected_revision: crate::db::schema::LATEST_SCHEMA_REVISION.to_string(),
        table_count: tables.len(),
        tables,
    };
    ctx.ui.render(&report);
    Ok(())
}

async fn handle_check(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let pool = ctx.connect_db(&paths).await?;
    let report = SchemaInspector::inspect(&pool).await?;
    ctx.ui.render(&report);

    if !report.healthy {
        return Err(CfmsError::SchemaDrift(format!(
            "Database schema check failed (current_revision={:?}, missing_tables={})",
            report.current_revision,
            report.missing_tables.len()
        )));
    }
    Ok(())
}

async fn handle_upgrade(_ctx: &AppContext) -> Result<()> {
    Err(CfmsError::NotImplementedYet("database upgrade"))
}

async fn handle_migrate(_ctx: &AppContext, _args: DatabaseMigrateArgs) -> Result<()> {
    Err(CfmsError::NotImplementedYet("database migrate"))
}

async fn handle_stamp(_ctx: &AppContext, _args: DatabaseStampArgs) -> Result<()> {
    Err(CfmsError::NotImplementedYet("database stamp"))
}
