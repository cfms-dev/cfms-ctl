//! `cfms-ctl database`: Multi-backend database status, live schema drift checking,
//! hybrid Python+Rust schema upgrades, structural diffs, IR export, cross-engine migration,
//! and revision stamping.

use std::path::{Path, PathBuf};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::cli::database::{
    CliSqlDialect, DatabaseCheckArgs, DatabaseCommand, DatabaseDiffArgs, DatabaseExportIrArgs,
    DatabaseMigrateArgs, DatabaseStampArgs, DatabaseUpgradeArgs, SchemaSourceArgs,
};
use crate::core::atomic::atomic_write;
use crate::core::{CfmsError, ConfigDocument, Result, WorkspacePaths};
use crate::db::schema::{
    AlembicRenderOptions, DiffOptions, ExtractionSource, ExtractorMode, HybridUpgradeOptions,
    HybridUpgradeOutcome, LATEST_SCHEMA_REVISION, RenameConfig, RiskAuditReport,
    SchemaDiffPlan, SchemaDriftReport, SchemaInspector, SchemaIr, SchemaOp, SqlRenderOptions,
    StampOutcome, UpgradeStrategy, audit_diff_plan, builtin_schema_ir, diff_schemas,
    execute_hybrid_upgrade, extract_code_schema_ir, introspect_live_schema_ir,
    load_schema_ir_file, plan_hybrid_upgrade, render_alembic_migration_script,
    render_native_ddl_sql, run_alembic_upgrade_head, run_live_preflight_checks,
    stamp_database_revision,
};
use crate::db::transfer::{
    DatabaseTransferSummary, inspect_migration_readiness_with_ir,
    migrate_database_contents_with_ir,
};
use crate::db::{DatabaseKind, DbPool};
use crate::ops::AppContext;
use crate::ui::{
    CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort, styled_table,
};

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

/// Report for `cfms-ctl database upgrade`.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseUpgradeReport {
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_sql_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_alembic_path: Option<String>,
    #[serde(flatten)]
    pub outcome: HybridUpgradeOutcome,
}

/// Report for `cfms-ctl database diff`.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseDiffReport {
    pub from_source: String,
    pub to_target: String,
    pub dialect: DatabaseKind,
    pub operation_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_sql_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_alembic_path: Option<String>,
    pub plan: SchemaDiffPlan,
    pub risk_audit: RiskAuditReport,
}

/// Report for `cfms-ctl database export-ir`.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseExportIrReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written_path: Option<String>,
    pub source: ExtractionSource,
    pub schema_revision: Option<String>,
    pub table_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Report for `cfms-ctl database migrate`.
#[derive(Debug, Clone, Serialize)]
pub struct DatabaseMigrateReport {
    pub source_endpoint: String,
    pub target_endpoint: String,
    pub activated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_backup_path: Option<String>,
    #[serde(flatten)]
    pub summary: DatabaseTransferSummary,
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
        if !self.column_mismatches.is_empty() {
            table.row("Column Drift", self.column_mismatches.join("; "));
        }
        if !self.constraint_mismatches.is_empty() {
            table.row(
                "Constraint Drift",
                format!(
                    "{} difference(s): {}",
                    self.constraint_mismatches.len(),
                    self.constraint_mismatches
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            );
        }
        if !self.index_mismatches.is_empty() {
            table.row(
                "Index Drift",
                format!(
                    "{} difference(s): {}",
                    self.index_mismatches.len(),
                    self.index_mismatches
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            );
        }
        table.print();

        if self.healthy {
            ui.print_success("Database schema matches the expected CFMS contract.");
        } else {
            ui.print_warning("Schema drift or revision mismatch detected.");
        }
    }
}

impl CommandReport for DatabaseUpgradeReport {
    fn render_human(&self, ui: &UiConsole) {
        for warning in &self.outcome.warnings {
            ui.print_warning(warning);
        }

        let mode = if self.outcome.dry_run {
            "Dry run preview (no database mutations)"
        } else if self.outcome.bootstrapped {
            "Bootstrapped empty database to HEAD"
        } else if self.outcome.delegated_to_alembic {
            "Delegated upgrade to Python `alembic upgrade head`"
        } else if self.outcome.applied_revisions.is_empty() && self.outcome.executed_sql_count == 0
        {
            "Already at HEAD (no changes)"
        } else {
            "Upgraded schema to target revision"
        };

        let mut table = KeyValueTable::new("Database Schema Upgrade");
        table
            .row("Dialect", self.outcome.dialect.to_string())
            .row("Target", self.endpoint.clone())
            .row("Strategy", self.outcome.strategy.to_string())
            .row("Action", mode)
            .row(
                "Previous Revision",
                self.outcome
                    .previous_revision
                    .clone()
                    .unwrap_or_else(|| "(empty)".to_string()),
            )
            .row("Target / Current Revision", self.outcome.current_revision.clone())
            .row(
                "Max Audit Risk Level",
                self.outcome.risk_audit.max_level.label(),
            )
            .row(
                "Applied Revisions",
                if self.outcome.applied_revisions.is_empty() {
                    "None".to_string()
                } else {
                    self.outcome.applied_revisions.join(" -> ")
                },
            );
        if self.outcome.executed_sql_count > 0 {
            table.row(
                "SQL Statements Planned/Executed",
                self.outcome.executed_sql_count.to_string(),
            );
        }
        if let Some(ref p) = self.emitted_sql_path {
            table.row("Rendered Native SQL", p.clone());
        }
        if let Some(ref p) = self.emitted_alembic_path {
            table.row("Rendered Alembic Script", p.clone());
        }
        table.print();

        render_risk_findings_human(ui, &self.outcome.risk_audit);

        if self.outcome.dry_run {
            ui.print_success("Dry run / script rendering completed without database changes.");
        } else if self.outcome.applied_revisions.is_empty()
            && !self.outcome.bootstrapped
            && self.outcome.executed_sql_count == 0
        {
            ui.print_success("Database schema is already up to date.");
        } else {
            ui.print_success(&format!(
                "Database schema is now at '{}'.",
                self.outcome.current_revision
            ));
        }
    }
}

impl CommandReport for DatabaseDiffReport {
    fn render_human(&self, ui: &UiConsole) {
        for warning in &self.plan.warnings {
            ui.print_warning(warning);
        }

        let mut table = KeyValueTable::new("Database Schema Diff Summary");
        table
            .row("From Source", self.from_source.clone())
            .row("To Target", self.to_target.clone())
            .row("Dialect", self.dialect.to_string())
            .row(
                "Revisions",
                format!(
                    "{} -> {}",
                    self.plan.from_revision.as_deref().unwrap_or("<unknown>"),
                    self.plan.to_revision.as_deref().unwrap_or("<unknown>")
                ),
            )
            .row("Planned Operations", self.operation_count.to_string())
            .row(
                "Ambiguous Renames",
                self.plan.ambiguous_renames.len().to_string(),
            )
            .row("Max Risk Level", self.risk_audit.max_level.label())
            .row(
                "Blocking Risk Gate",
                self.risk_audit.has_blocking_risks.to_string(),
            );
        if let Some(ref p) = self.emitted_sql_path {
            table.row("Rendered Native SQL", p.clone());
        }
        if let Some(ref p) = self.emitted_alembic_path {
            table.row("Rendered Alembic Script", p.clone());
        }
        table.print();

        if !self.plan.operations.is_empty() {
            ui.print_section("Planned Operations (Topological Phase Order)");
            let mut grid = styled_table(&["#", "Phase", "Table", "Operation"]);
            for (idx, op) in self.plan.operations.iter().enumerate() {
                grid.add_row(vec![
                    (idx + 1).to_string(),
                    format!("{:?}", op.phase()),
                    op.table_name().to_string(),
                    summarize_schema_op(op),
                ]);
            }
            println!("{grid}");
        }

        if !self.plan.ambiguous_renames.is_empty() {
            ui.print_section("Ambiguous Column Renames (Require `--rename table.old=new`)");
            let mut grid = styled_table(&["Table", "Dropped", "Added", "Score", "Reason"]);
            for (table_name, items) in &self.plan.ambiguous_renames {
                for item in items {
                    grid.add_row(vec![
                        table_name.as_str(),
                        item.old_column.as_str(),
                        item.new_column.as_str(),
                        &format!("{:.3}", item.score.total),
                        item.reason.as_str(),
                    ]);
                }
            }
            println!("{grid}");
        }

        render_risk_findings_human(ui, &self.risk_audit);

        if self.plan.is_empty() {
            ui.print_success("No structural differences detected between source and target.");
        }
    }
}

impl CommandReport for DatabaseExportIrReport {
    fn render_human(&self, ui: &UiConsole) {
        for w in &self.warnings {
            ui.print_warning(w);
        }
        let mut table = KeyValueTable::new("Schema IR Export");
        table
            .row("Extraction Source", self.source.to_string())
            .row(
                "Schema Revision",
                self.schema_revision
                    .clone()
                    .unwrap_or_else(|| "(unknown)".to_string()),
            )
            .row("Extracted Tables", self.table_count.to_string());
        if let Some(ref path) = self.written_path {
            table.row("Written Artifact", path.clone());
        }
        table.print();
        if let Some(ref path) = self.written_path {
            ui.print_success(&format!("Exported Schema IR v1 to '{path}'."));
        } else {
            ui.print_success("Extracted Schema IR v1 (pass `--out schema.ir.json` or `--output json` to write JSON).");
        }
    }
}

impl CommandReport for StampOutcome {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new("Database Revision Stamp");
        table
            .row("Dialect", self.dialect.to_string())
            .row(
                "Previous Revision",
                self.previous_revision
                    .clone()
                    .unwrap_or_else(|| "(unversioned)".to_string()),
            )
            .row("Stamped Revision", self.stamped_revision.clone())
            .row("Validated Against", self.validated_against.clone())
            .row("Forced", self.forced.to_string());
        table.print();
        ui.print_success(&format!(
            "Stamped `alembic_version` to '{}'.",
            self.stamped_revision
        ));
    }
}

fn render_risk_findings_human(ui: &UiConsole, audit: &RiskAuditReport) {
    if audit.findings.is_empty() {
        return;
    }
    ui.print_section("Risk Audit Findings");
    let mut grid = styled_table(&["Code", "Level", "Blocking", "Target", "Summary"]);
    for f in &audit.findings {
        let target = match (&f.table, &f.column) {
            (Some(t), Some(c)) => format!("{t}.{c}"),
            (Some(t), None) => t.clone(),
            _ => "-".to_string(),
        };
        grid.add_row(vec![
            f.code.as_str(),
            f.level.label(),
            if f.blocking { "YES" } else { "no" },
            target.as_str(),
            f.summary.as_str(),
        ]);
    }
    println!("{grid}");
}

fn summarize_schema_op(op: &SchemaOp) -> String {
    match op {
        SchemaOp::DropForeignKey { fk, .. } => {
            format!("DROP FK ({}) -> {}", fk.columns.join(", "), fk.ref_table)
        }
        SchemaOp::DropIndex { index, .. } => format!("DROP INDEX {}", index.name),
        SchemaOp::DropUnique { unique, .. } => {
            format!("DROP UNIQUE ({})", unique.columns.join(", "))
        }
        SchemaOp::DropCheck { check, .. } => format!("DROP CHECK ({})", check.expression),
        SchemaOp::DropTable { table, .. } => format!("DROP TABLE {}", table.name),
        SchemaOp::CreateTable { table, deferred_fk_names } => format!(
            "CREATE TABLE {} ({} cols, {} deferred FK)",
            table.name,
            table.columns.len(),
            deferred_fk_names.len()
        ),
        SchemaOp::RenameColumn { old_column, new_column, score, .. } => format!(
            "RENAME COLUMN {} -> {} (score={:.2})",
            old_column.name, new_column.name, score.total
        ),
        SchemaOp::AddColumn { column, .. } => format!("ADD COLUMN {}", column.name),
        SchemaOp::AlterColumn {
            old_column,
            new_column,
            type_changed,
            nullable_changed,
            default_changed,
            ..
        } => format!(
            "ALTER COLUMN {} (type={type_changed}, null={nullable_changed}, dflt={default_changed}; {:?} -> {:?})",
            new_column.name, old_column.canonical_type, new_column.canonical_type
        ),
        SchemaOp::DropColumn { column, .. } => format!("DROP COLUMN {}", column.name),
        SchemaOp::SqliteRebuildTable { new_table, folded_ops, .. } => {
            format!("SQLITE REBUILD {} ({} folded op(s))", new_table.name, folded_ops.len())
        }
        SchemaOp::AddUnique { unique, .. } => {
            format!("ADD UNIQUE ({})", unique.columns.join(", "))
        }
        SchemaOp::AddCheck { check, .. } => format!("ADD CHECK ({})", check.expression),
        SchemaOp::AddForeignKey { fk, .. } => {
            format!("ADD FK ({}) -> {}", fk.columns.join(", "), fk.ref_table)
        }
        SchemaOp::CreateIndex { index, .. } => format!("CREATE INDEX {}", index.name),
        SchemaOp::SetColumnCommentPg { column, .. } => format!("COMMENT COLUMN {column}"),
    }
}

impl CommandReport for DatabaseMigrateReport {
    fn render_human(&self, ui: &UiConsole) {
        for warning in &self.summary.warnings {
            ui.print_warning(warning);
        }

        let mut table = KeyValueTable::new("Database Migration Summary");
        table
            .row(
                "Source",
                format!("{} ({})", self.source_endpoint, self.summary.source_dialect),
            )
            .row(
                "Target",
                format!("{} ({})", self.target_endpoint, self.summary.target_dialect),
            )
            .row("Tables Cloned & Verified", self.summary.table_count.to_string())
            .row(
                "Extension Tables",
                if self.summary.extension_tables.is_empty() {
                    "None".to_string()
                } else {
                    self.summary.extension_tables.join(", ")
                },
            )
            .row("Total Rows Copied", self.summary.total_rows.to_string())
            .row("Elapsed", format!("{} ms", self.summary.elapsed_ms))
            .row(
                "Activated in config.toml",
                if self.activated { "yes" } else { "no" },
            );
        if let Some(ref backup) = self.config_backup_path {
            table.row("Config Backup", backup.clone());
        }
        table.print();

        ui.print_section("Per-Table Canonical SHA-256 Verification");
        let mut grid = styled_table(&["Table", "Rows", "SHA-256 Digest"]);
        for t in &self.summary.tables {
            grid.add_row(vec![
                t.table_name.as_str(),
                &t.row_count.to_string(),
                t.sha256_digest.as_str(),
            ]);
        }
        println!("{grid}");

        ui.print_success(
            "Database migration completed and verified across all tables with matching SHA-256 digests.",
        );
    }
}

pub async fn handle(ctx: &AppContext, cmd: DatabaseCommand) -> Result<()> {
    match cmd {
        DatabaseCommand::Status => handle_status(ctx).await,
        DatabaseCommand::Check(args) => handle_check(ctx, args).await,
        DatabaseCommand::Upgrade(args) => handle_upgrade(ctx, args).await,
        DatabaseCommand::Diff(args) => handle_diff(ctx, args).await,
        DatabaseCommand::ExportIr(args) => handle_export_ir(ctx, args).await,
        DatabaseCommand::Migrate(args) => handle_migrate(ctx, args).await,
        DatabaseCommand::Stamp(args) => handle_stamp(ctx, args).await,
    }
}

async fn resolve_workspace_schema_ir(
    paths: &WorkspacePaths,
    schema: &SchemaSourceArgs,
    fallback_to_builtin_when_empty: bool,
) -> Result<SchemaIr> {
    let ir_override = schema
        .ir_file
        .as_deref()
        .map(|p| resolve_input_path(paths, p));
    extract_code_schema_ir(
        paths,
        schema.extractor,
        ir_override.as_deref(),
        schema.models_target.as_deref(),
        schema.include_extensions,
        fallback_to_builtin_when_empty,
    )
    .await
}

fn resolve_input_path(paths: &WorkspacePaths, explicit: &Path) -> PathBuf {
    if explicit.exists() {
        explicit.to_path_buf()
    } else {
        paths.resolve_file_override(explicit)
    }
}

fn write_rendered_output(path: &Path, content: &str) -> Result<String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write(path, content.as_bytes())?;
    Ok(path.display().to_string())
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

    let expected_revision = extract_code_schema_ir(
        &paths,
        ExtractorMode::Auto,
        None,
        None,
        false,
        true,
    )
    .await
    .ok()
    .and_then(|ir| ir.schema_revision)
    .unwrap_or_else(|| LATEST_SCHEMA_REVISION.to_string());

    let pool = ctx.connect_db(&paths).await?;
    pool.ping().await?;
    let tables = pool.list_tables().await?;
    let current_revision = pool.current_revision().await?;

    let report = DatabaseStatusReport {
        dialect: pool.kind(),
        endpoint,
        current_revision,
        expected_revision,
        table_count: tables.len(),
        tables,
    };
    ctx.ui.render(&report);
    Ok(())
}

async fn handle_check(ctx: &AppContext, args: DatabaseCheckArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let target_ir = resolve_workspace_schema_ir(&paths, &args.schema, true).await?;
    for w in &target_ir.warnings {
        ctx.ui.print_warning(w);
    }

    let pool = ctx.connect_db(&paths).await?;
    let report = SchemaInspector::inspect_against_ir(&pool, &target_ir).await?;
    ctx.ui.render(&report);

    if !report.healthy {
        return Err(CfmsError::SchemaDrift(format!(
            "Database schema check failed (current_revision={:?}, expected_revision={}, missing_tables={}, column_mismatches={})",
            report.current_revision,
            report.expected_revision,
            report.missing_tables.len(),
            report.column_mismatches.len(),
        )));
    }
    Ok(())
}

async fn handle_upgrade(ctx: &AppContext, args: DatabaseUpgradeArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let doc = ctx.load_config(&paths)?;
    let db_cfg = doc.database_config()?;
    let endpoint = db_cfg.display_endpoint(&paths);

    let is_preview_only =
        args.dry_run || args.emit_alembic.is_some() || args.emit_sql.is_some();
    let _lock = if is_preview_only {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let target_ir = resolve_workspace_schema_ir(&paths, &args.schema, true).await?;
    let hybrid_opts = HybridUpgradeOptions {
        dry_run: is_preview_only,
        allow_destructive: args.allow_destructive,
        rename_overrides: args.rename.clone(),
        schema_only: args.schema_only,
        no_alembic_delegate: args.no_alembic_delegate,
        include_extensions: args.schema.include_extensions,
    };

    let pool = DbPool::connect(&db_cfg, &paths).await?;
    let plan = plan_hybrid_upgrade(&pool, Some(&paths), &target_ir, &hybrid_opts).await?;
    for warning in &plan.compatibility.warnings {
        ctx.ui.print_warning(warning);
    }

    // Handle `--emit-sql` / `--emit-alembic` (never mutates DB).
    if args.emit_sql.is_some() || args.emit_alembic.is_some() {
        let render_plan = match &plan.diff_plan {
            Some(p) => p.clone(),
            None => diff_schemas(
                &SchemaIr::new(ExtractionSource::LiveDatabase, plan.drift.current_revision.clone()),
                &plan.effective_target_ir,
                &DiffOptions {
                    dialect: Some(pool.kind()),
                    coalesce_sqlite_rebuilds: true,
                    include_extensions: true,
                    compare_comments: pool.kind() == DatabaseKind::Postgresql,
                    ..DiffOptions::default()
                },
            ),
        };
        let render_audit = if plan.diff_plan.is_some() {
            plan.risk_audit.clone()
        } else {
            audit_diff_plan(
                &render_plan,
                Some(&plan.effective_target_ir),
                plan.pending_alembic.as_ref(),
            )
        };

        let mut emitted_sql_path = None;
        if let Some(ref sql_path) = args.emit_sql {
            let rendered = render_native_ddl_sql(
                &render_plan,
                &render_audit,
                &SqlRenderOptions::new(pool.kind()),
            )?;
            emitted_sql_path = Some(write_rendered_output(sql_path, &rendered)?);
        }

        let mut emitted_alembic_path = None;
        if let Some(ref py_path) = args.emit_alembic {
            let rendered = render_alembic_migration_script(
                &render_plan,
                &render_audit,
                &AlembicRenderOptions {
                    revision: plan.target_revision.clone(),
                    down_revision: plan.drift.current_revision.clone(),
                    summary_title: format!(
                        "CFMS hybrid schema diff ({} -> {})",
                        plan.drift.current_revision.as_deref().unwrap_or("empty"),
                        plan.target_revision
                    ),
                },
            )?;
            emitted_alembic_path = Some(write_rendered_output(py_path, &rendered)?);
        }

        let outcome = execute_hybrid_upgrade(&pool, Some(&paths), &target_ir, &hybrid_opts).await?;
        pool.close().await;
        ctx.ui.render(&DatabaseUpgradeReport {
            endpoint,
            emitted_sql_path,
            emitted_alembic_path,
            outcome,
        });
        return Ok(());
    }

    if args.dry_run {
        let outcome = execute_hybrid_upgrade(&pool, Some(&paths), &target_ir, &hybrid_opts).await?;
        pool.close().await;
        ctx.ui.render(&DatabaseUpgradeReport {
            endpoint,
            emitted_sql_path: None,
            emitted_alembic_path: None,
            outcome,
        });
        return Ok(());
    }

    if plan.strategy == UpgradeStrategy::AlreadyAtTarget {
        let outcome = execute_hybrid_upgrade(&pool, Some(&paths), &target_ir, &hybrid_opts).await?;
        pool.close().await;
        ctx.ui.render(&DatabaseUpgradeReport {
            endpoint,
            emitted_sql_path: None,
            emitted_alembic_path: None,
            outcome,
        });
        return Ok(());
    }

    if plan.risk_audit.has_blocking_risks && !args.allow_destructive {
        if ctx.ui.format() == OutputFormat::Human {
            render_risk_findings_human(&ctx.ui, &plan.risk_audit);
        }
        let blocking_summaries: Vec<String> = plan
            .risk_audit
            .findings
            .iter()
            .filter(|f| f.blocking)
            .map(|f| format!("[{}] {}", f.code, f.summary))
            .collect();
        pool.close().await;
        return Err(CfmsError::DestructiveMigrationBlocked(format!(
            "{} blocking migration risk(s) detected: {}. Re-run with `--allow-destructive` or resolve `--rename table.old=new` first",
            blocking_summaries.len(),
            blocking_summaries.join("; ")
        )));
    }

    if ctx.ui.format() == OutputFormat::Human && !ctx.global.yes {
        let ops_count = plan.diff_plan.as_ref().map_or(plan.historical_steps.len(), |p| {
            plan.historical_steps.len() + p.operations.len()
        });
        let mut preview = KeyValueTable::new("Database Upgrade Plan");
        preview
            .row("Dialect", pool.kind().to_string())
            .row("Target", endpoint.clone())
            .row("Strategy", plan.strategy.to_string())
            .row(
                "Current Revision",
                plan.drift
                    .current_revision
                    .clone()
                    .unwrap_or_else(|| "(empty)".to_string()),
            )
            .row("Target Revision", plan.target_revision.clone())
            .row("Max Risk Level", plan.risk_audit.max_level.label())
            .row("Planned Steps / Ops", ops_count.to_string());
        if !plan.dml_revisions.is_empty() {
            let revs: Vec<&str> = plan.dml_revisions.iter().map(|(r, _)| r.as_str()).collect();
            preview.row("DML Revisions", revs.join(", "));
        }
        preview.print();
        render_risk_findings_human(&ctx.ui, &plan.risk_audit);
    }

    let prompt = match plan.strategy {
        UpgradeStrategy::BootstrapTarget => format!(
            "Bootstrap empty {} database '{}' to revision '{}'?",
            pool.kind(),
            endpoint,
            plan.target_revision
        ),
        UpgradeStrategy::DelegateAlembic => {
            let dml_revs: Vec<&str> = plan.dml_revisions.iter().map(|(r, _)| r.as_str()).collect();
            format!(
                "Pending Alembic revision(s) [{}] contain data DML. Run `alembic upgrade head` against {} database '{}'?",
                dml_revs.join(", "),
                pool.kind(),
                endpoint
            )
        }
        UpgradeStrategy::AlreadyAtTarget => unreachable!(),
        UpgradeStrategy::HistoricalNative
        | UpgradeStrategy::HistoricalThenHybridDdl
        | UpgradeStrategy::HybridNativeDdl => format!(
            "Upgrade {} database '{}' to revision '{}' (strategy: {}, max risk: {})?",
            pool.kind(),
            endpoint,
            plan.target_revision,
            plan.strategy,
            plan.risk_audit.max_level.label()
        ),
    };
    confirm_or_abort(&prompt, ctx.global.yes)?;

    if plan.strategy == UpgradeStrategy::DelegateAlembic {
        let alembic_paths = paths.discover_alembic_paths().ok_or_else(|| {
            CfmsError::Config(
                "Unable to locate workspace alembic.ini and alembic/versions for Alembic delegation"
                    .to_string(),
            )
        })?;
        // Close pooled Rust connections cleanly before spawning Python Alembic so SQLite
        // has zero cross-process file lock contention on Windows.
        pool.close().await;
        run_alembic_upgrade_head(&paths, &alembic_paths).await?;

        let verify_pool = DbPool::connect(&db_cfg, &paths).await?;
        let post_rev = verify_pool
            .current_revision()
            .await?
            .unwrap_or_else(|| plan.target_revision.clone());
        let final_report =
            SchemaInspector::inspect_against_ir(&verify_pool, &plan.effective_target_ir).await?;
        verify_pool.close().await;

        let mut warnings = plan.warnings;
        if !final_report.healthy {
            warnings.push(format!(
                "Post-Alembic schema check reported residual differences (missing: {:?}, column_mismatches: {:?})",
                final_report.missing_tables, final_report.column_mismatches
            ));
        }

        let outcome = HybridUpgradeOutcome {
            dialect: plan.dialect,
            strategy: UpgradeStrategy::DelegateAlembic,
            dry_run: false,
            previous_revision: plan.drift.current_revision,
            current_revision: post_rev,
            bootstrapped: false,
            delegated_to_alembic: true,
            applied_revisions: plan
                .pending_alembic
                .map(|p| p.pending_revisions)
                .unwrap_or_default(),
            executed_sql_count: 0,
            risk_audit: plan.risk_audit,
            dml_scripts: plan.dml_revisions.into_iter().map(|(r, _)| r).collect(),
            warnings,
        };
        ctx.ui.render(&DatabaseUpgradeReport {
            endpoint,
            emitted_sql_path: None,
            emitted_alembic_path: None,
            outcome,
        });
        return Ok(());
    }

    let outcome = execute_hybrid_upgrade(&pool, Some(&paths), &target_ir, &hybrid_opts).await?;
    pool.close().await;

    ctx.ui.render(&DatabaseUpgradeReport {
        endpoint,
        emitted_sql_path: None,
        emitted_alembic_path: None,
        outcome,
    });
    Ok(())
}

async fn resolve_diff_endpoint(
    ctx: &AppContext,
    ws_paths: Option<&WorkspacePaths>,
    spec: &str,
    schema: &SchemaSourceArgs,
) -> Result<(SchemaIr, Option<DatabaseKind>)> {
    let trimmed = spec.trim();
    if trimmed.eq_ignore_ascii_case("builtin") {
        return Ok((builtin_schema_ir(schema.include_extensions), None));
    }

    if trimmed.eq_ignore_ascii_case("live") {
        let paths = match ws_paths {
            Some(p) => p.clone(),
            None => ctx.resolve_paths()?,
        };
        let pool = ctx.connect_db(&paths).await?;
        let dialect = pool.kind();
        let ir = introspect_live_schema_ir(&pool, schema.include_extensions, None).await?;
        pool.close().await;
        return Ok((ir, Some(dialect)));
    }

    if trimmed.eq_ignore_ascii_case("code") {
        let paths = match ws_paths {
            Some(p) => p.clone(),
            None => ctx.resolve_paths()?,
        };
        let ir = resolve_workspace_schema_ir(&paths, schema, true).await?;
        return Ok((ir, None));
    }

    let raw_path = Path::new(trimmed);
    let resolved_path = if raw_path.exists() {
        raw_path.to_path_buf()
    } else if let Some(paths) = ws_paths {
        paths.resolve_file_override(raw_path)
    } else {
        raw_path.to_path_buf()
    };

    if resolved_path.is_file() {
        let ext = resolved_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "json" {
            let ir = load_schema_ir_file(&resolved_path, schema.include_extensions)?;
            return Ok((ir, None));
        }
        if matches!(ext.as_str(), "db" | "sqlite" | "sqlite3") {
            let opts = SqliteConnectOptions::new()
                .filename(&resolved_path)
                .read_only(true);
            let pool = DbPool::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(opts)
                    .await?,
            );
            let ir = introspect_live_schema_ir(&pool, schema.include_extensions, None).await?;
            pool.close().await;
            return Ok((ir, Some(DatabaseKind::Sqlite)));
        }
        return Err(CfmsError::InvalidArgument(format!(
            "Unsupported file endpoint '{}'; pass `.ir.json`, `.db`/`.sqlite`, a directory, `live`, `code`, or `builtin`",
            resolved_path.display()
        )));
    }

    if resolved_path.is_dir() {
        let dir_paths = WorkspacePaths::from_code_dir(&resolved_path)?;
        let ir = extract_code_schema_ir(
            &dir_paths,
            schema.extractor,
            None,
            schema.models_target.as_deref(),
            schema.include_extensions,
            false,
        )
        .await?;
        return Ok((ir, None));
    }

    Err(CfmsError::InvalidArgument(format!(
        "Unable to resolve diff source/target '{spec}' (not `live`, `code`, `builtin`, an existing file, or directory)"
    )))
}

async fn handle_diff(ctx: &AppContext, args: DatabaseDiffArgs) -> Result<()> {
    let ws_paths = ctx.resolve_paths().ok();
    let (from_ir, from_dialect) =
        resolve_diff_endpoint(ctx, ws_paths.as_ref(), &args.from, &args.schema).await?;
    let (to_ir, to_dialect) =
        resolve_diff_endpoint(ctx, ws_paths.as_ref(), &args.to, &args.schema).await?;

    let dialect = match args.dialect {
        Some(CliSqlDialect::Sqlite) => DatabaseKind::Sqlite,
        Some(CliSqlDialect::Mysql) => DatabaseKind::Mysql,
        Some(CliSqlDialect::Postgresql) => DatabaseKind::Postgresql,
        None => {
            if let Some(d) = from_dialect.or(to_dialect) {
                d
            } else if let Some(ref paths) = ws_paths
                && let Ok(doc) = ctx.load_config(paths)
                && let Ok(cfg) = doc.database_config()
            {
                cfg.kind
            } else {
                DatabaseKind::Sqlite
            }
        }
    };

    let mut rename_cfg = RenameConfig::default();
    for spec in &args.rename {
        rename_cfg
            .insert_override_spec(spec)
            .map_err(|e| CfmsError::InvalidArgument(format!("Invalid --rename '{spec}': {e}")))?;
    }

    let plan = diff_schemas(
        &from_ir,
        &to_ir,
        &DiffOptions {
            dialect: Some(dialect),
            rename: rename_cfg,
            coalesce_sqlite_rebuilds: true,
            include_extensions: args.schema.include_extensions,
            compare_comments: dialect == DatabaseKind::Postgresql,
        },
    );

    let pending_alembic = ws_paths
        .as_ref()
        .and_then(|p| p.discover_alembic_paths())
        .and_then(|ap| crate::db::schema::analyze_alembic_directory(&ap.versions_dir).ok())
        .map(|dag| dag.pending_since(from_ir.schema_revision.as_deref()));

    let mut risk_audit = audit_diff_plan(&plan, Some(&to_ir), pending_alembic.as_ref());
    if args.from.eq_ignore_ascii_case("live")
        && let Some(ref paths) = ws_paths
        && let Ok(pool) = ctx.connect_db(paths).await
    {
        run_live_preflight_checks(&pool, &plan, &mut risk_audit).await;
        pool.close().await;
    }

    let mut emitted_sql_path = None;
    if let Some(ref sql_path) = args.emit_sql {
        let rendered = render_native_ddl_sql(
            &plan,
            &risk_audit,
            &SqlRenderOptions::new(dialect),
        )?;
        emitted_sql_path = Some(write_rendered_output(sql_path, &rendered)?);
    }

    let mut emitted_alembic_path = None;
    if let Some(ref py_path) = args.emit_alembic {
        let rendered = render_alembic_migration_script(
            &plan,
            &risk_audit,
            &AlembicRenderOptions {
                revision: to_ir
                    .schema_revision
                    .clone()
                    .unwrap_or_else(|| "auto_generated_head".to_string()),
                down_revision: from_ir.schema_revision.clone(),
                summary_title: format!("CFMS schema diff ({} -> {})", args.from, args.to),
            },
        )?;
        emitted_alembic_path = Some(write_rendered_output(py_path, &rendered)?);
    }

    let report = DatabaseDiffReport {
        from_source: args.from,
        to_target: args.to,
        dialect,
        operation_count: plan.operations.len(),
        emitted_sql_path,
        emitted_alembic_path,
        plan,
        risk_audit,
    };
    ctx.ui.render(&report);
    Ok(())
}

async fn handle_export_ir(ctx: &AppContext, args: DatabaseExportIrArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let ir = if args.from_live {
        let pool = ctx.connect_db(&paths).await?;
        let res = introspect_live_schema_ir(&pool, args.schema.include_extensions, None).await?;
        pool.close().await;
        res
    } else {
        resolve_workspace_schema_ir(&paths, &args.schema, false).await?
    };

    if let Some(ref out_path) = args.out {
        let json = ir.to_pretty_json()?;
        let written = write_rendered_output(out_path, &json)?;
        ctx.ui.render(&DatabaseExportIrReport {
            written_path: Some(written),
            source: ir.source,
            schema_revision: ir.schema_revision,
            table_count: ir.tables.len(),
            warnings: ir.warnings,
        });
        return Ok(());
    }

    if ctx.ui.format() == OutputFormat::Json {
        println!("{}", ir.to_pretty_json()?);
    } else {
        ctx.ui.render(&DatabaseExportIrReport {
            written_path: None,
            source: ir.source,
            schema_revision: ir.schema_revision,
            table_count: ir.tables.len(),
            warnings: ir.warnings,
        });
    }
    Ok(())
}

async fn handle_migrate(ctx: &AppContext, args: DatabaseMigrateArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let mut source_doc = ctx.load_config(&paths)?;
    let source_cfg = source_doc.database_config()?;
    let source_endpoint = source_cfg.display_endpoint(&paths);

    let _lock = ctx.acquire_server_lock(&paths, false)?;

    let target_config_path = paths.resolve_file_override(&args.target_config);
    let target_doc = ConfigDocument::load(&target_config_path)?;
    let raw_target_table = target_doc
        .document()
        .get("database")
        .and_then(|item| item.as_table_like())
        .ok_or_else(|| {
            CfmsError::Config(format!(
                "Target configuration '{}' must contain a [database] table",
                target_config_path.display()
            ))
        })?;
    let target_cfg = target_doc.database_config()?;
    target_cfg.validate_as_migration_target(raw_target_table)?;
    source_cfg.ensure_distinct_from(&target_cfg, &paths)?;
    let target_endpoint = target_cfg.display_endpoint(&paths);

    if args.activate {
        let schema_path = paths.discover_config_schema_path(None)?;
        source_doc.replace_database_section(&target_doc, schema_path.as_deref())?;
    }

    let mut transfer_schema_args = args.schema.clone();
    transfer_schema_args.include_extensions = true;
    let extracted_ir = resolve_workspace_schema_ir(&paths, &transfer_schema_args, true).await?;
    let expected_ir = if extracted_ir.source == ExtractionSource::BuiltinFallback
        && args.schema.extractor == ExtractorMode::Auto
        && args.schema.ir_file.is_none()
    {
        None
    } else {
        Some(extracted_ir)
    };
    let inspect_ir = expected_ir
        .clone()
        .unwrap_or_else(|| builtin_schema_ir(true));
    let expected_rev = inspect_ir
        .schema_revision
        .as_deref()
        .unwrap_or(LATEST_SCHEMA_REVISION);

    let source = DbPool::connect(&source_cfg, &paths).await?;
    // Validate source readiness before opening/creating the target SQLite file.
    let _ = source.validate_server_compatibility().await?;
    let source_drift = SchemaInspector::inspect_against_ir(&source, &inspect_ir).await?;
    if source_drift.current_revision.as_deref() != Some(expected_rev) {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database revision is {:?}, expected HEAD '{expected_rev}'. Run `cfms-ctl database upgrade` first.",
            source_drift.current_revision
        )));
    }
    if !source_drift.missing_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database is missing required CFMS tables: {}",
            source_drift.missing_tables.join(", ")
        )));
    }
    if !source_drift.column_mismatches.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database has column drift against expected schema: {}",
            source_drift.column_mismatches.join("; ")
        )));
    }
    let (_, unknown_extra) = source_drift.partition_extra_tables();
    if !unknown_extra.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database contains unsupported extra tables: {}",
            unknown_extra.join(", ")
        )));
    }

    if target_cfg.kind == DatabaseKind::Sqlite {
        let sqlite_target = paths.resolve_sqlite_path(&target_cfg.file);
        if let Some(parent) = sqlite_target.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
    }

    let target = DbPool::connect(&target_cfg, &paths).await?;
    let plan =
        inspect_migration_readiness_with_ir(&source, &target, expected_ir.as_ref()).await?;

    for warning in &plan.warnings {
        ctx.ui.print_warning(warning);
    }

    if ctx.ui.format() == OutputFormat::Human && !ctx.global.yes {
        let mut preview = KeyValueTable::new("Database Migration Plan");
        preview
            .row("Source", format!("{} ({})", source_endpoint, plan.source_dialect))
            .row("Target", format!("{} ({})", target_endpoint, plan.target_dialect))
            .row("Tables to Clone", plan.table_count.to_string())
            .row(
                "Extension Tables",
                if plan.extension_tables.is_empty() {
                    "None".to_string()
                } else {
                    plan.extension_tables.join(", ")
                },
            )
            .row(
                "Activate Target Config",
                if args.activate { "yes" } else { "no" },
            );
        preview.print();
    }

    confirm_or_abort(
        &format!(
            "Clone {} ({}) into empty target {} ({})?",
            source_endpoint, plan.source_dialect, target_endpoint, plan.target_dialect
        ),
        ctx.global.yes,
    )?;

    let total_steps = (plan.table_count * 2 + 2) as u64;
    let pb = match ctx.ui.format() {
        OutputFormat::Human => {
            let bar = ProgressBar::with_draw_target(Some(total_steps), ProgressDrawTarget::stderr());
            let style = ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:32.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("##-");
            bar.set_style(style);
            bar
        }
        OutputFormat::Json => ProgressBar::hidden(),
    };

    let res = migrate_database_contents_with_ir(&source, &target, expected_ir.as_ref(), |ev| {
        pb.set_length(ev.total as u64);
        pb.set_position(ev.current as u64);
        pb.set_message(ev.stage.to_string());
    })
    .await;
    pb.finish_and_clear();

    let summary = res?;
    source.close().await;
    target.close().await;

    let config_backup_path = if args.activate {
        let backup = source_doc.save_with_backup()?;
        Some(backup.display().to_string())
    } else {
        None
    };

    let report = DatabaseMigrateReport {
        source_endpoint,
        target_endpoint,
        activated: args.activate,
        config_backup_path,
        summary,
    };
    ctx.ui.render(&report);
    Ok(())
}

async fn handle_stamp(ctx: &AppContext, args: DatabaseStampArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let doc = ctx.load_config(&paths)?;
    let db_cfg = doc.database_config()?;
    let endpoint = db_cfg.display_endpoint(&paths);

    let _lock = ctx.acquire_server_lock(&paths, false)?;
    let versions_dir = paths.discover_alembic_paths().map(|p| p.versions_dir);

    confirm_or_abort(
        &format!(
            "Stamp `alembic_version` on {} database '{}' to '{}'{}?",
            db_cfg.kind,
            endpoint,
            args.revision,
            if args.force { " (FORCED)" } else { "" }
        ),
        ctx.global.yes,
    )?;

    let pool = DbPool::connect(&db_cfg, &paths).await?;
    let outcome =
        stamp_database_revision(&pool, versions_dir.as_deref(), &args.revision, args.force)
            .await?;
    pool.close().await;

    ctx.ui.render(&outcome);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalOpts;
    use crate::db::{migrate_database_contents, upgrade_database_schema};
    use sqlx::Row;
    use tempfile::tempdir;

    fn make_test_ctx(root: &std::path::Path) -> AppContext {
        AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output: OutputFormat::Json,
                yes: true,
                verbose: false,
            },
            UiConsole::new(OutputFormat::Json),
        )
    }

    #[tokio::test]
    async fn handle_upgrade_and_migrate_activate_roundtrip_on_workspace() {
        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("main.py"), "# cfms").unwrap();

        let cfg_path = src_dir.join("config.toml");
        std::fs::write(
            &cfg_path,
            "# operator header\n[server]\nhost = \"127.0.0.1\"\nport = 5104\n\n[database]\ntype = \"sqlite\"\nfile = \"source.db\"\n",
        )
        .unwrap();

        let ctx = make_test_ctx(dir.path());

        // 1. Upgrade empty workspace DB to HEAD
        handle(&ctx, DatabaseCommand::Upgrade(DatabaseUpgradeArgs::default()))
            .await
            .expect("upgrade empty DB via command handler");

        // Insert representative user row to verify data survives migrate --activate
        let paths = ctx.resolve_paths().unwrap();
        let pool = ctx.connect_db(&paths).await.unwrap();
        if let DbPool::Sqlite(ref p) = pool {
            sqlx::query(
                "INSERT INTO users (id, username, nickname, created_time, status, secret_key) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind("00112233445566778899aabbccddeeff")
            .bind("bob")
            .bind("Bob")
            .bind(1.0_f64)
            .bind(0i64)
            .bind("b".repeat(64))
            .execute(p)
            .await
            .unwrap();
        }
        pool.close().await;

        // 2. Migrate to target SQLite config with --activate
        let target_toml = dir.path().join("target_sqlite.toml");
        std::fs::write(
            &target_toml,
            "[database]\ntype = \"sqlite\"\nfile = \"nested/migrated.db\"\n",
        )
        .unwrap();

        handle(
            &ctx,
            DatabaseCommand::Migrate(DatabaseMigrateArgs {
                target_config: target_toml,
                activate: true,
                schema: SchemaSourceArgs::default(),
            }),
        )
        .await
        .expect("migrate --activate via command handler");

        // Verify config.toml switched to nested/migrated.db, comment preserved, backup exists
        let updated_cfg = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(updated_cfg.contains("# operator header"));
        assert!(updated_cfg.contains("file = \"nested/migrated.db\""));
        let has_backup = std::fs::read_dir(&src_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("config.toml.backup-")
            });
        assert!(has_backup);

        // Connect using newly activated config.toml and verify Bob exists
        let migrated_pool = ctx.connect_db(&paths).await.unwrap();
        let inspector = SchemaInspector::inspect(&migrated_pool).await.unwrap();
        assert!(inspector.healthy);
        if let DbPool::Sqlite(ref p) = migrated_pool {
            let row = sqlx::query("SELECT username, nickname FROM users")
                .fetch_one(p)
                .await
                .unwrap();
            assert_eq!(row.get::<String, _>("username"), "bob");
            assert_eq!(row.get::<String, _>("nickname"), "Bob");
        }
        migrated_pool.close().await;
    }

    #[tokio::test]
    #[ignore = "Requires live MySQL/PostgreSQL instances via CFMS_TEST_MYSQL_URL and/or CFMS_TEST_POSTGRES_URL"]
    async fn live_multi_engine_upgrade_and_cross_dialect_migration_matrix() {
        let mysql_url = std::env::var("CFMS_TEST_MYSQL_URL").ok();
        let pg_url = std::env::var("CFMS_TEST_POSTGRES_URL").ok();
        assert!(
            mysql_url.is_some() || pg_url.is_some(),
            "Set CFMS_TEST_MYSQL_URL and/or CFMS_TEST_POSTGRES_URL before running ignored live DB tests"
        );

        let dir = tempdir().unwrap();
        let sqlite_pool = {
            let url = format!("sqlite://{}?mode=rwc", dir.path().join("src.db").display());
            DbPool::Sqlite(
                sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(4)
                    .connect(&url)
                    .await
                    .unwrap(),
            )
        };
        upgrade_database_schema(&sqlite_pool).await.unwrap();

        if let Some(url) = mysql_url {
            let mysql_pool = DbPool::Mysql(
                sqlx::mysql::MySqlPoolOptions::new()
                    .max_connections(4)
                    .connect(&url)
                    .await
                    .unwrap(),
            );
            let existing = mysql_pool.list_tables().await.unwrap();
            if !existing.is_empty() {
                crate::db::schema::drop_all_cfms_tables(&mysql_pool, &existing)
                    .await
                    .unwrap();
            }
            let summary = migrate_database_contents(&sqlite_pool, &mysql_pool, |_| {})
                .await
                .expect("sqlite -> mysql migration");
            assert_eq!(summary.table_count, 40);
            mysql_pool.close().await;
        }

        if let Some(url) = pg_url {
            let pg_pool = DbPool::Postgres(
                sqlx::postgres::PgPoolOptions::new()
                    .max_connections(4)
                    .connect(&url)
                    .await
                    .unwrap(),
            );
            let existing = pg_pool.list_tables().await.unwrap();
            if !existing.is_empty() {
                crate::db::schema::drop_all_cfms_tables(&pg_pool, &existing)
                    .await
                    .unwrap();
            }
            let summary = migrate_database_contents(&sqlite_pool, &pg_pool, |_| {})
                .await
                .expect("sqlite -> postgres migration");
            assert_eq!(summary.table_count, 40);
            pg_pool.close().await;
        }

        sqlite_pool.close().await;
    }

    #[tokio::test]
    async fn handle_diff_export_ir_upgrade_dry_run_emit_and_stamp_cli_flows() {
        use crate::db::schema::ir::{CanonicalType, ColumnIr, ConfidenceLevel};
        use std::collections::BTreeMap;

        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("main.py"), "# cfms").unwrap();
        std::fs::write(
            src_dir.join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"cli.db\"\n",
        )
        .unwrap();

        let ctx = make_test_ctx(dir.path());
        let paths = ctx.resolve_paths().unwrap();

        // 1. Bootstrap built-in DB at `e952c02c1454`.
        let pool = ctx.connect_db(&paths).await.unwrap();
        upgrade_database_schema(&pool).await.unwrap();
        pool.close().await;

        // 2. Write a target `schema.ir.json` evolving `users` with an additive nullable `bio` column.
        let mut target_ir = builtin_schema_ir(false);
        target_ir.schema_revision = Some("e952c02c1455".to_string());
        let users = target_ir.tables.get_mut("users").unwrap();
        let next_ordinal = users.columns.len();
        users.columns.push(ColumnIr {
            name: "bio".to_string(),
            ordinal: next_ordinal,
            canonical_type: CanonicalType::Text,
            dialect_types: BTreeMap::new(),
            nullable: true,
            autoincrement: false,
            server_default: None,
            computed: None,
            comment: None,
            confidence: ConfidenceLevel::High,
        });
        let ir_json_path = src_dir.join("schema.ir.json");
        std::fs::write(&ir_json_path, target_ir.to_pretty_json().unwrap()).unwrap();

        // 3. `database export-ir` (from `live`) writes reloadable JSON.
        let exported_live_path = dir.path().join("exported_live.ir.json");
        handle(
            &ctx,
            DatabaseCommand::ExportIr(DatabaseExportIrArgs {
                schema: SchemaSourceArgs {
                    extractor: ExtractorMode::Auto,
                    ir_file: None,
                    models_target: None,
                    include_extensions: false,
                },
                from_live: true,
                out: Some(exported_live_path.clone()),
            }),
        )
        .await
        .unwrap();
        let reloaded_live = load_schema_ir_file(&exported_live_path, false).unwrap();
        assert_eq!(reloaded_live.tables.len(), 40);

        // 4. `database diff live code --emit-sql ... --emit-alembic ...`
        let diff_sql_path = dir.path().join("diff_upgrade.sql");
        let diff_py_path = dir.path().join("diff_upgrade.py");
        handle(
            &ctx,
            DatabaseCommand::Diff(DatabaseDiffArgs {
                from: "live".to_string(),
                to: "code".to_string(),
                dialect: Some(CliSqlDialect::Sqlite),
                rename: Vec::new(),
                emit_sql: Some(diff_sql_path.clone()),
                emit_alembic: Some(diff_py_path.clone()),
                schema: SchemaSourceArgs {
                    extractor: ExtractorMode::Auto,
                    ir_file: None,
                    models_target: None,
                    include_extensions: false,
                },
            }),
        )
        .await
        .unwrap();
        let diff_sql = std::fs::read_to_string(&diff_sql_path).unwrap();
        let diff_py = std::fs::read_to_string(&diff_py_path).unwrap();
        assert!(diff_sql.contains("ADD COLUMN") && diff_sql.contains("bio"));
        assert!(diff_py.contains("def upgrade() -> None:") && diff_py.contains("\"bio\""));

        // 5. `database upgrade --dry-run`, `--emit-sql`, and `--emit-alembic` do not mutate `alembic_version`.
        let default_upgrade_args = || DatabaseUpgradeArgs {
            schema: SchemaSourceArgs {
                extractor: ExtractorMode::Auto,
                ir_file: None,
                models_target: None,
                include_extensions: false,
            },
            dry_run: false,
            allow_destructive: false,
            rename: Vec::new(),
            emit_alembic: None,
            emit_sql: None,
            schema_only: false,
            no_alembic_delegate: false,
        };
        let upg_sql_path = dir.path().join("upg_preview.sql");
        let upg_py_path = dir.path().join("upg_preview.py");
        handle(
            &ctx,
            DatabaseCommand::Upgrade(DatabaseUpgradeArgs {
                emit_sql: Some(upg_sql_path.clone()),
                emit_alembic: Some(upg_py_path.clone()),
                ..default_upgrade_args()
            }),
        )
        .await
        .unwrap();
        assert!(std::fs::read_to_string(&upg_sql_path).unwrap().contains("bio"));
        assert!(std::fs::read_to_string(&upg_py_path).unwrap().contains("bio"));
        handle(
            &ctx,
            DatabaseCommand::Upgrade(DatabaseUpgradeArgs {
                dry_run: true,
                ..default_upgrade_args()
            }),
        )
        .await
        .unwrap();
        let pool_check = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(
            pool_check.current_revision().await.unwrap().as_deref(),
            Some(LATEST_SCHEMA_REVISION)
        );
        pool_check.close().await;

        // 6. Real `database upgrade` executes additive hybrid DDL and updates revision + check passes.
        handle(&ctx, DatabaseCommand::Upgrade(default_upgrade_args()))
            .await
            .unwrap();
        handle(
            &ctx,
            DatabaseCommand::Check(DatabaseCheckArgs {
                schema: SchemaSourceArgs {
                    extractor: ExtractorMode::Auto,
                    ir_file: None,
                    models_target: None,
                    include_extensions: false,
                },
            }),
        )
        .await
        .unwrap();

        // 7. `database stamp` with `--force` updates `alembic_version`.
        handle(
            &ctx,
            DatabaseCommand::Stamp(DatabaseStampArgs {
                revision: "custom_stamp_99".to_string(),
                force: true,
            }),
        )
        .await
        .unwrap();
        let pool_final = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(
            pool_final.current_revision().await.unwrap().as_deref(),
            Some("custom_stamp_99")
        );
        pool_final.close().await;
    }
}
