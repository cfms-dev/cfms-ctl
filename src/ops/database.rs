//! `cfms-ctl database`: Multi-backend database status, live schema drift checking,
//! native schema upgrades, cross-engine migration, and revision stamping.

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::Serialize;

use crate::cli::database::{DatabaseCommand, DatabaseMigrateArgs, DatabaseStampArgs};
use crate::core::{CfmsError, ConfigDocument, Result};
use crate::db::schema::{
    LATEST_SCHEMA_REVISION, SchemaDriftReport, SchemaInspector, SchemaUpgradeOutcome,
    inspect_upgrade_plan, upgrade_database_schema,
};
use crate::db::transfer::{
    DatabaseTransferSummary, inspect_migration_readiness, migrate_database_contents,
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
    #[serde(flatten)]
    pub outcome: SchemaUpgradeOutcome,
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

        let mode = if self.outcome.bootstrapped {
            "Bootstrapped empty database to HEAD"
        } else if self.outcome.applied_revisions.is_empty() {
            "Already at HEAD (no changes)"
        } else {
            "Upgraded schema to HEAD"
        };

        let mut table = KeyValueTable::new("Database Schema Upgrade");
        table
            .row("Dialect", self.outcome.dialect.to_string())
            .row("Target", self.endpoint.clone())
            .row("Action", mode)
            .row(
                "Previous Revision",
                self.outcome
                    .previous_revision
                    .clone()
                    .unwrap_or_else(|| "(empty)".to_string()),
            )
            .row("Current Revision", self.outcome.current_revision.clone())
            .row(
                "Applied Revisions",
                if self.outcome.applied_revisions.is_empty() {
                    "None".to_string()
                } else {
                    self.outcome.applied_revisions.join(" -> ")
                },
            );
        table.print();

        if self.outcome.applied_revisions.is_empty() && !self.outcome.bootstrapped {
            ui.print_success("Database schema is already up to date.");
        } else {
            ui.print_success(&format!(
                "Database schema is now at HEAD '{}'.",
                self.outcome.current_revision
            ));
        }
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

async fn handle_upgrade(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let doc = ctx.load_config(&paths)?;
    let db_cfg = doc.database_config()?;
    let endpoint = db_cfg.display_endpoint(&paths);

    let _lock = ctx.acquire_server_lock(&paths, false)?;
    let pool = DbPool::connect(&db_cfg, &paths).await?;

    let (drift, compat, pending) = inspect_upgrade_plan(&pool).await?;
    for warning in &compat.warnings {
        ctx.ui.print_warning(warning);
    }

    if !drift.is_empty_database && pending.is_empty() {
        let outcome = SchemaUpgradeOutcome {
            dialect: pool.kind(),
            previous_revision: drift.current_revision,
            current_revision: LATEST_SCHEMA_REVISION.to_string(),
            bootstrapped: false,
            applied_revisions: Vec::new(),
            warnings: compat.warnings,
        };
        pool.close().await;
        let report = DatabaseUpgradeReport { endpoint, outcome };
        ctx.ui.render(&report);
        return Ok(());
    }

    if ctx.ui.format() == OutputFormat::Human && !ctx.global.yes {
        let mut preview = KeyValueTable::new("Database Upgrade Plan");
        preview
            .row("Dialect", pool.kind().to_string())
            .row("Target", endpoint.clone())
            .row(
                "Action",
                if drift.is_empty_database {
                    "Bootstrap empty database to HEAD"
                } else {
                    "Apply incremental native migrations"
                },
            )
            .row(
                "Current Revision",
                drift
                    .current_revision
                    .clone()
                    .unwrap_or_else(|| "(empty)".to_string()),
            )
            .row("Target Head Revision", LATEST_SCHEMA_REVISION.to_string())
            .row("Steps", pending.len().to_string());
        preview.print();
    }

    let prompt = if drift.is_empty_database {
        format!(
            "Bootstrap empty {} database '{}' to HEAD '{}'?",
            pool.kind(),
            endpoint,
            LATEST_SCHEMA_REVISION
        )
    } else {
        format!(
            "Upgrade {} database '{}' across {} revision step(s) to HEAD '{}'?",
            pool.kind(),
            endpoint,
            pending.len(),
            LATEST_SCHEMA_REVISION
        )
    };
    confirm_or_abort(&prompt, ctx.global.yes)?;

    let outcome = upgrade_database_schema(&pool).await?;
    pool.close().await;

    let report = DatabaseUpgradeReport { endpoint, outcome };
    ctx.ui.render(&report);
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

    let source = DbPool::connect(&source_cfg, &paths).await?;
    // Validate source readiness before opening/creating the target SQLite file.
    let _ = source.validate_server_compatibility().await?;
    let source_drift = SchemaInspector::inspect(&source).await?;
    if source_drift.current_revision.as_deref() != Some(LATEST_SCHEMA_REVISION) {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database revision is {:?}, expected HEAD '{LATEST_SCHEMA_REVISION}'. Run `cfms-ctl database upgrade` first.",
            source_drift.current_revision
        )));
    }
    if !source_drift.missing_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database is missing required CFMS tables: {}",
            source_drift.missing_tables.join(", ")
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
    let plan = inspect_migration_readiness(&source, &target).await?;

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

    let res = migrate_database_contents(&source, &target, |ev| {
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

async fn handle_stamp(_ctx: &AppContext, _args: DatabaseStampArgs) -> Result<()> {
    Err(CfmsError::NotImplementedYet("database stamp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalOpts;
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
        handle(&ctx, DatabaseCommand::Upgrade)
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
}
