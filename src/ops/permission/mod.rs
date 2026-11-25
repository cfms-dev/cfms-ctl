//! `cfms-ctl permission`: Expired permission record purging and default group
//! permission synchronization (`user`, `sysop`).
//!
//! Designed for online, cluster-safe execution using database-side UTC clocks,
//! index-aligned short batch deletions, row-locked idempotent default syncs,
//! dependency-free Python AST metadata discovery, and structured reporting.

pub mod db;
pub mod defaults;
pub mod policy;

use std::time::Duration;

use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

use crate::cli::permission::{
    PermissionCommand, PermissionPurgeExpiredArgs, PermissionSyncDefaultsArgs,
};
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::backend::DbPool;
use crate::ops::AppContext;
use crate::ops::audit::filter::format_unix_utc;
use crate::ops::permission::db::{
    GroupSyncStatus, inspect_default_groups, inspect_expired_permissions, preflight_purge_schema,
    preflight_sync_schema, purge_expired_permissions, sync_default_groups,
};
use crate::ops::permission::defaults::DefaultGroupPermissions;
use crate::ops::permission::policy::{database_now, resolve_purge_config, validate_purge_args};
use crate::ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort, styled_table};

/// Report for `cfms-ctl permission purge-expired`.
#[derive(Debug, Clone, Serialize)]
pub struct PermissionPurgeReport {
    pub dry_run: bool,
    pub cutoff_timestamp: f64,
    pub cutoff_utc: String,
    pub cutoff_source: String,
    pub scope: String,
    pub retention_days: Option<u64>,
    pub batch_size: usize,
    pub eligible_count: u64,
    pub purged_count: u64,
    pub user_entries_eligible: u64,
    pub user_entries_purged: u64,
    pub group_entries_eligible: u64,
    pub group_entries_purged: u64,
    pub grants_eligible: u64,
    pub grants_purged: u64,
    pub revocations_eligible: u64,
    pub revocations_purged: u64,
    pub oldest_expired_utc: Option<String>,
    pub newest_expired_utc: Option<String>,
    pub batches_executed: u64,
    pub audit_logged: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl CommandReport for PermissionPurgeReport {
    fn render_human(&self, ui: &UiConsole) {
        let title = if self.dry_run {
            "Expired Permission Purge (Dry Run)"
        } else {
            "Expired Permission Purge"
        };
        let mut table = KeyValueTable::new(title);
        table
            .row("Dry Run", self.dry_run.to_string())
            .row("Scope", &self.scope)
            .row(
                "Cutoff (UTC)",
                format!(
                    "{} ({:.3}; source={})",
                    self.cutoff_utc, self.cutoff_timestamp, self.cutoff_source
                ),
            )
            .row(
                "Retention Days",
                self.retention_days
                    .map_or_else(|| "n/a (--before)".to_string(), |d| d.to_string()),
            )
            .row("Batch Size", self.batch_size.to_string())
            .row(
                "Eligible Entries",
                format!(
                    "{} (user={}, group={}; grants={}, revocations={})",
                    self.eligible_count,
                    self.user_entries_eligible,
                    self.group_entries_eligible,
                    self.grants_eligible,
                    self.revocations_eligible
                ),
            );

        if let (Some(oldest), Some(newest)) = (&self.oldest_expired_utc, &self.newest_expired_utc) {
            table.row("Expired Window (UTC)", format!("{oldest} .. {newest}"));
        }

        if !self.dry_run {
            table
                .row(
                    "Purged Entries",
                    format!(
                        "{} (user={}, group={}; grants={}, revocations={})",
                        self.purged_count,
                        self.user_entries_purged,
                        self.group_entries_purged,
                        self.grants_purged,
                        self.revocations_purged
                    ),
                )
                .row("Batches Executed", self.batches_executed.to_string())
                .row("Audit Logged", self.audit_logged.to_string());
        }
        table.print();

        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.dry_run {
            ui.print_success(&format!(
                "Dry run complete: {} expired permission entry(ies) eligible for purge.",
                self.eligible_count
            ));
        } else if self.purged_count == 0 {
            ui.print_success("No expired permission entries matched the retention cutoff.");
        } else {
            ui.print_success(&format!(
                "Purged {} expired permission entry(ies) across {} batch(es).",
                self.purged_count, self.batches_executed
            ));
        }
    }
}

/// Report for `cfms-ctl permission sync-defaults`.
#[derive(Debug, Clone, Serialize)]
pub struct PermissionSyncReport {
    pub dry_run: bool,
    pub check_only: bool,
    pub in_sync: bool,
    pub defaults_source: String,
    pub groups: Vec<String>,
    pub missing_groups: Vec<String>,
    pub missing_count: u64,
    pub inserted_count: u64,
    pub group_details: Vec<GroupSyncStatus>,
    pub audit_logged: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl CommandReport for PermissionSyncReport {
    fn render_human(&self, ui: &UiConsole) {
        let title = if self.check_only {
            "Default Group Permission Check"
        } else if self.dry_run {
            "Default Group Permission Sync (Dry Run)"
        } else {
            "Default Group Permission Sync"
        };

        let mut summary = KeyValueTable::new(title);
        summary
            .row("Dry Run", self.dry_run.to_string())
            .row("Check Only", self.check_only.to_string())
            .row("In Sync", self.in_sync.to_string())
            .row("Defaults Source", &self.defaults_source)
            .row("Target Groups", self.groups.join(", "))
            .row(
                "Missing Groups",
                if self.missing_groups.is_empty() {
                    "none".to_string()
                } else {
                    self.missing_groups.join(", ")
                },
            )
            .row("Missing Grants", self.missing_count.to_string())
            .row("Inserted Grants", self.inserted_count.to_string());
        if !self.dry_run && !self.check_only {
            summary.row("Audit Logged", self.audit_logged.to_string());
        }
        summary.print();

        let mut grid = styled_table(&[
            "Group",
            "Status",
            "Expected",
            "Present",
            "Active",
            "Revoked/Inactive",
            "Missing",
            "Inserted",
        ]);
        for detail in &self.group_details {
            grid.add_row(vec![
                detail.group_name.clone(),
                detail.status.clone(),
                detail.expected_count.to_string(),
                detail.present_count.to_string(),
                detail.active_grant_count.to_string(),
                detail.inactive_or_revoked_count.to_string(),
                detail.missing_permissions.len().to_string(),
                detail.inserted_permissions.len().to_string(),
            ]);
        }
        println!("\n{}", style("Per-Group Summary").bold().underlined());
        println!("{grid}");

        for detail in &self.group_details {
            if !detail.missing_permissions.is_empty() {
                let verb = if self.dry_run || self.check_only {
                    "Missing"
                } else {
                    "Pending"
                };
                ui.print_warning(&format!(
                    "{verb} default grants for `{}` ({}): {}",
                    detail.group_name,
                    detail.missing_permissions.len(),
                    detail.missing_permissions.join(", ")
                ));
            }
            if !detail.inserted_permissions.is_empty() {
                ui.print_success(&format!(
                    "Inserted {} default grant(s) for `{}`: {}",
                    detail.inserted_permissions.len(),
                    detail.group_name,
                    detail.inserted_permissions.join(", ")
                ));
            }
            if !detail.inactive_or_revoked_permissions.is_empty() {
                ui.print_warning(&format!(
                    "Group `{}` has {} existing default permission(s) currently revoked/inactive (preserved verbatim): {}",
                    detail.group_name,
                    detail.inactive_or_revoked_permissions.len(),
                    detail.inactive_or_revoked_permissions.join(", ")
                ));
            }
        }

        if !self.missing_groups.is_empty() {
            ui.print_warning(&format!(
                "Default group(s) absent from `user_groups` (not auto-created): {}",
                self.missing_groups.join(", ")
            ));
        }

        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.check_only {
            if self.in_sync {
                ui.print_success("Default group permissions are in sync.");
            }
        } else if self.dry_run {
            ui.print_success(&format!(
                "Dry run complete: {} missing default grant(s) detected across target group(s).",
                self.missing_count
            ));
        } else if self.inserted_count == 0 && self.missing_groups.is_empty() {
            ui.print_success("All targeted default groups are already in sync.");
        } else if self.inserted_count > 0 {
            ui.print_success(&format!(
                "Inserted {} missing default group permission grant(s).",
                self.inserted_count
            ));
        }
    }
}

/// Dispatch `cfms-ctl permission` subcommands.
pub async fn handle(ctx: &AppContext, cmd: PermissionCommand) -> Result<()> {
    match cmd {
        PermissionCommand::PurgeExpired(args) => {
            let report = purge_expired(ctx, &args).await?;
            ctx.ui.render(&report);
            Ok(())
        }
        PermissionCommand::SyncDefaults(args) => {
            let report = sync_defaults(ctx, &args).await?;
            if args.check && !report.in_sync {
                if ctx.ui.format() == OutputFormat::Human {
                    report.render_human(&ctx.ui);
                }
                return Err(build_check_drift_error(&report));
            }
            ctx.ui.render(&report);
            Ok(())
        }
    }
}

/// Inspect or purge expired permission records using a CLI `AppContext`.
pub async fn purge_expired(
    ctx: &AppContext,
    args: &PermissionPurgeExpiredArgs,
) -> Result<PermissionPurgeReport> {
    let _ = validate_purge_args(args)?;
    ensure_json_confirmed(
        &ctx.ui,
        !args.dry_run,
        ctx.global.yes,
        "Refusing interactive confirmation in JSON output mode; pass --yes to purge or --dry-run to preview",
    )?;

    let paths = ctx.resolve_paths()?;
    let pool = ctx.connect_db(&paths).await?;
    purge_expired_with_context(&pool, Some(&paths), args, &ctx.ui, ctx.global.yes).await
}

/// Core testable implementation of `purge-expired` with an injected pool.
pub async fn purge_expired_with_context(
    pool: &DbPool,
    _paths: Option<&WorkspacePaths>,
    args: &PermissionPurgeExpiredArgs,
    ui: &UiConsole,
    yes: bool,
) -> Result<PermissionPurgeReport> {
    let _ = validate_purge_args(args)?;
    ensure_json_confirmed(
        ui,
        !args.dry_run,
        yes,
        "Refusing interactive confirmation in JSON output mode; pass --yes to purge or --dry-run to preview",
    )?;

    let warnings = preflight_purge_schema(pool, args.scope).await?;
    let cfg = resolve_purge_config(pool, args).await?;
    let inspect = inspect_expired_permissions(pool, args.scope, cfg.cutoff_timestamp).await?;

    let eligible_count = inspect.total_eligible();
    let oldest_expired_utc = inspect.oldest_end_time().map(format_unix_utc);
    let newest_expired_utc = inspect.newest_end_time().map(format_unix_utc);

    if args.dry_run || eligible_count == 0 {
        return Ok(PermissionPurgeReport {
            dry_run: args.dry_run,
            cutoff_timestamp: cfg.cutoff_timestamp,
            cutoff_utc: cfg.cutoff_utc,
            cutoff_source: cfg.cutoff_source.as_str().to_string(),
            scope: args.scope.as_str().to_string(),
            retention_days: cfg.retention_days,
            batch_size: cfg.batch_size,
            eligible_count,
            purged_count: 0,
            user_entries_eligible: inspect.user.total,
            user_entries_purged: 0,
            group_entries_eligible: inspect.group.total,
            group_entries_purged: 0,
            grants_eligible: inspect.grants_eligible(),
            grants_purged: 0,
            revocations_eligible: inspect.revocations_eligible(),
            revocations_purged: 0,
            oldest_expired_utc,
            newest_expired_utc,
            batches_executed: 0,
            audit_logged: false,
            warnings,
        });
    }

    if !yes && ui.format() == OutputFormat::Human {
        let preview = PermissionPurgeReport {
            dry_run: true,
            cutoff_timestamp: cfg.cutoff_timestamp,
            cutoff_utc: cfg.cutoff_utc.clone(),
            cutoff_source: cfg.cutoff_source.as_str().to_string(),
            scope: args.scope.as_str().to_string(),
            retention_days: cfg.retention_days,
            batch_size: cfg.batch_size,
            eligible_count,
            purged_count: 0,
            user_entries_eligible: inspect.user.total,
            user_entries_purged: 0,
            group_entries_eligible: inspect.group.total,
            group_entries_purged: 0,
            grants_eligible: inspect.grants_eligible(),
            grants_purged: 0,
            revocations_eligible: inspect.revocations_eligible(),
            revocations_purged: 0,
            oldest_expired_utc: oldest_expired_utc.clone(),
            newest_expired_utc: newest_expired_utc.clone(),
            batches_executed: 0,
            audit_logged: false,
            warnings: warnings.clone(),
        };
        preview.render_human(ui);
        confirm_or_abort(
            &format!(
                "Purge {eligible_count} expired permission entry(ies) with end_time < {}?",
                cfg.cutoff_utc
            ),
            yes,
        )?;
    }

    let pb = make_progress_bar(ui, eligible_count, "Purging expired permissions");
    let exec_res = purge_expired_permissions(pool, args.scope, &cfg, &pb).await;
    pb.finish_and_clear();
    let outcome = exec_res?;

    Ok(PermissionPurgeReport {
        dry_run: false,
        cutoff_timestamp: cfg.cutoff_timestamp,
        cutoff_utc: cfg.cutoff_utc,
        cutoff_source: cfg.cutoff_source.as_str().to_string(),
        scope: args.scope.as_str().to_string(),
        retention_days: cfg.retention_days,
        batch_size: cfg.batch_size,
        eligible_count,
        purged_count: outcome.total_purged(),
        user_entries_eligible: inspect.user.total,
        user_entries_purged: outcome.user.total,
        group_entries_eligible: inspect.group.total,
        group_entries_purged: outcome.group.total,
        grants_eligible: inspect.grants_eligible(),
        grants_purged: outcome.grants_purged(),
        revocations_eligible: inspect.revocations_eligible(),
        revocations_purged: outcome.revocations_purged(),
        oldest_expired_utc,
        newest_expired_utc,
        batches_executed: outcome.batches_executed(),
        audit_logged: outcome.audit_logged,
        warnings,
    })
}

/// Inspect, verify (`--check`), or synchronize missing default group permissions.
pub async fn sync_defaults(
    ctx: &AppContext,
    args: &PermissionSyncDefaultsArgs,
) -> Result<PermissionSyncReport> {
    if args.check && ctx.global.yes {
        return Err(CfmsError::InvalidArgument(
            "--check cannot be combined with --yes".to_string(),
        ));
    }
    ensure_json_confirmed(
        &ctx.ui,
        !args.dry_run && !args.check,
        ctx.global.yes,
        "Refusing interactive confirmation in JSON output mode; pass --yes to apply or --dry-run to preview",
    )?;

    let paths = ctx.resolve_paths()?;
    let defaults = DefaultGroupPermissions::resolve(&paths, args.defaults_file.as_deref())?;
    let target_groups = defaults.select_target_groups(&args.groups)?;
    let pool = ctx.connect_db(&paths).await?;

    sync_defaults_with_context(&pool, &defaults, &target_groups, args, &ctx.ui, ctx.global.yes)
        .await
}

/// Core testable implementation of `sync-defaults` with injected pool and resolved defaults.
pub async fn sync_defaults_with_context(
    pool: &DbPool,
    defaults: &DefaultGroupPermissions,
    target_groups: &[String],
    args: &PermissionSyncDefaultsArgs,
    ui: &UiConsole,
    yes: bool,
) -> Result<PermissionSyncReport> {
    if args.check && yes {
        return Err(CfmsError::InvalidArgument(
            "--check cannot be combined with --yes".to_string(),
        ));
    }
    if args.dry_run && args.check {
        return Err(CfmsError::InvalidArgument(
            "--dry-run cannot be combined with --check".to_string(),
        ));
    }
    ensure_json_confirmed(
        ui,
        !args.dry_run && !args.check,
        yes,
        "Refusing interactive confirmation in JSON output mode; pass --yes to apply or --dry-run to preview",
    )?;

    preflight_sync_schema(pool).await?;
    let db_now = database_now(pool).await?;

    if args.dry_run || args.check {
        let inspection = inspect_default_groups(pool, defaults, target_groups, db_now).await?;
        return Ok(build_sync_report(
            args,
            defaults,
            target_groups,
            inspection,
        ));
    }

    if yes {
        let outcome =
            sync_default_groups(pool, defaults, target_groups, db_now, None).await?;
        return Ok(build_sync_report(args, defaults, target_groups, outcome));
    }

    let preview = inspect_default_groups(pool, defaults, target_groups, db_now).await?;
    if preview.missing_count == 0 {
        return Ok(build_sync_report(args, defaults, target_groups, preview));
    }

    if ui.format() == OutputFormat::Human {
        let mut preview_args = args.clone();
        preview_args.dry_run = true;
        let preview_report = build_sync_report(
            &preview_args,
            defaults,
            target_groups,
            preview.clone(),
        );
        preview_report.render_human(ui);
    }

    confirm_or_abort(
        &format!(
            "Insert {} missing default permission grant(s) into `group_permissions`?",
            preview.missing_count
        ),
        yes,
    )?;

    let outcome = sync_default_groups(
        pool,
        defaults,
        target_groups,
        db_now,
        Some(&preview.missing_by_group),
    )
    .await?;
    Ok(build_sync_report(args, defaults, target_groups, outcome))
}

fn build_sync_report(
    args: &PermissionSyncDefaultsArgs,
    defaults: &DefaultGroupPermissions,
    target_groups: &[String],
    outcome: db::SyncInspectionResult,
) -> PermissionSyncReport {
    PermissionSyncReport {
        dry_run: args.dry_run,
        check_only: args.check,
        in_sync: outcome.in_sync(),
        defaults_source: defaults.source.as_str().to_string(),
        groups: target_groups.to_vec(),
        missing_groups: outcome.missing_groups,
        missing_count: outcome.missing_count,
        inserted_count: outcome.inserted_count,
        group_details: outcome.group_details,
        audit_logged: outcome.audit_logged,
        warnings: defaults.warnings.clone(),
    }
}

fn build_check_drift_error(report: &PermissionSyncReport) -> CfmsError {
    let mut reasons = Vec::new();
    if report.missing_count > 0 {
        reasons.push(format!("{} missing default grant(s)", report.missing_count));
    }
    if !report.missing_groups.is_empty() {
        reasons.push(format!(
            "missing default group(s): {}",
            report.missing_groups.join(", ")
        ));
    }
    CfmsError::Config(format!(
        "Default group permissions are out of sync ({})",
        reasons.join("; ")
    ))
}

fn ensure_json_confirmed(
    ui: &UiConsole,
    mutating: bool,
    yes: bool,
    message: &str,
) -> Result<()> {
    if mutating && !yes && ui.format() == OutputFormat::Json {
        return Err(CfmsError::InvalidArgument(message.to_string()));
    }
    Ok(())
}

fn make_progress_bar(ui: &UiConsole, total: u64, msg: &str) -> ProgressBar {
    match ui.format() {
        OutputFormat::Human => {
            let pb = ProgressBar::new(total);
            if let Ok(style) = ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
            ) {
                pb.set_style(style.progress_chars("=>-"));
            }
            pb.set_message(msg.to_string());
            pb.enable_steady_tick(Duration::from_millis(120));
            pb
        }
        OutputFormat::Json => ProgressBar::hidden(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalOpts;
    use crate::cli::permission::PermissionScope;
    use crate::core::lock::RuntimeLock;
    use crate::db::schema::create_head_schema;
    use crate::ops::user::db::DbTx;
    use sqlx::SqlitePool;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tempfile::TempDir;
    use uuid::Uuid;

    struct TestEnv {
        _dir: TempDir,
        root: PathBuf,
        paths: WorkspacePaths,
        pool: DbPool,
    }

    async fn setup_sqlite_env() -> TestEnv {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().to_path_buf();
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).expect("mkdir src");
        let db_path = root.join("app.db");
        fs::write(
            root.join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n",
        )
        .expect("write config");

        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
            .expect("sqlite opts")
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(30));
        let sqlite_pool = SqlitePool::connect_with(opts).await.expect("connect sqlite");
        let pool = DbPool::Sqlite(sqlite_pool);
        create_head_schema(&pool, false).await.expect("head schema");
        let paths = WorkspacePaths::discover(Some(&root), None).expect("discover paths");

        TestEnv {
            _dir: dir,
            root,
            paths,
            pool,
        }
    }

    fn sqlite_pool(pool: &DbPool) -> &SqlitePool {
        match pool {
            DbPool::Sqlite(p) => p,
            _ => unreachable!(),
        }
    }

    fn ctx_for(root: &Path, output: OutputFormat, yes: bool) -> AppContext {
        AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output,
                yes,
                verbose: false,
            },
            UiConsole::new(output),
        )
    }

    async fn seed_user_and_groups(pool: &DbPool) -> Uuid {
        let sq = sqlite_pool(pool);
        let uid = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, nickname, created_time, status, secret_key) VALUES (?, 'alice', 'Alice', 1.0, 0, 'sk')",
        )
        .bind(uid.simple().to_string())
        .execute(sq)
        .await
        .unwrap();

        for g in ["user", "sysop", "custom_team"] {
            sqlx::query("INSERT INTO user_groups (group_name, group_display_name) VALUES (?, ?)")
                .bind(g)
                .bind(format!("{g} Display"))
                .execute(sq)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO user_memberships (user_id, group_name, start_time, end_time) VALUES (?, 'custom_team', 0.0, NULL)",
        )
        .bind(uid.simple().to_string())
        .execute(sq)
        .await
        .unwrap();

        uid
    }

    #[tokio::test]
    async fn purge_expired_respects_boundaries_scope_batches_and_trigger_rollback() {
        let env = setup_sqlite_env().await;
        let uid = seed_user_and_groups(&env.pool).await;
        let sq = sqlite_pool(&env.pool);
        let cutoff = 1_700_000_000.0;

        // Eligible user rows: 2 grants + 1 revocation (< cutoff)
        sqlx::query(
            "INSERT INTO user_permissions (user_id, permission, granted, start_time, end_time) VALUES \
             (?, 'search', 1, 100.0, 1699999999.0), \
             (?, 'purge', 1, 100.0, 1699999000.0), \
             (?, 'block', 0, 100.0, 1699999500.0), \
             (?, 'eq_cutoff', 1, 100.0, 1700000000.0), \
             (?, 'future_end', 1, 100.0, 1700000001.0), \
             (?, 'perm_grant', 1, 100.0, NULL), \
             (?, 'perm_revoke', 0, 100.0, NULL)",
        )
        .bind(uid.simple().to_string())
        .bind(uid.simple().to_string())
        .bind(uid.simple().to_string())
        .bind(uid.simple().to_string())
        .bind(uid.simple().to_string())
        .bind(uid.simple().to_string())
        .bind(uid.simple().to_string())
        .execute(sq)
        .await
        .unwrap();

        // Eligible group rows: 1_100 rows (< cutoff) + 1 boundary row (== cutoff) + 1 permanent
        let mut tx = DbTx::begin(&env.pool).await.unwrap();
        let DbTx::Sqlite(ref mut stx) = tx else {
            unreachable!()
        };
        for i in 0..1_100 {
            let granted = i % 3 != 0;
            sqlx::query(
                "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES ('user', ?, ?, 0.0, ?)",
            )
            .bind(format!("perm_{i}"))
            .bind(granted)
            .bind(1_699_990_000.0 + f64::from(i))
            .execute(&mut **stx)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES ('user', 'eq_g', 1, 0.0, ?)",
        )
        .bind(cutoff)
        .execute(&mut **stx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES ('user', 'perm_g', 1, 0.0, NULL)",
        )
        .execute(&mut **stx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Hold server.lock & create transaction.json -> purge MUST NOT be blocked by local locks
        let _held_lock = RuntimeLock::acquire(&env.paths, true).unwrap();
        fs::create_dir_all(&env.paths.maintenance_root).unwrap();
        fs::write(env.paths.transaction_path(), "{}").unwrap();

        // JSON without --yes is rejected upfront when mutating
        let json_no_yes = ctx_for(&env.root, OutputFormat::Json, false);
        let refuse = purge_expired(
            &json_no_yes,
            &PermissionPurgeExpiredArgs {
                before: Some("2023-11-14T22:13:20Z".to_string()),
                retention_days: None,
                scope: PermissionScope::All,
                batch_size: Some(250),
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(refuse, CfmsError::InvalidArgument(_)));

        // Dry run preview
        let dry_report = purge_expired(
            &json_no_yes,
            &PermissionPurgeExpiredArgs {
                before: Some("2023-11-14T22:13:20Z".to_string()),
                retention_days: None,
                scope: PermissionScope::All,
                batch_size: Some(250),
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(dry_report.dry_run);
        assert_eq!(dry_report.eligible_count, 1_103);
        assert_eq!(dry_report.purged_count, 0);
        assert_eq!(dry_report.user_entries_eligible, 3);
        assert_eq!(dry_report.group_entries_eligible, 1_100);

        // User-only scope purge
        let json_yes = ctx_for(&env.root, OutputFormat::Json, true);
        let user_purge = purge_expired(
            &json_yes,
            &PermissionPurgeExpiredArgs {
                before: Some("2023-11-14T22:13:20Z".to_string()),
                retention_days: None,
                scope: PermissionScope::User,
                batch_size: Some(2),
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(user_purge.purged_count, 3);
        assert_eq!(user_purge.user_entries_purged, 3);
        assert_eq!(user_purge.group_entries_purged, 0);
        assert_eq!(user_purge.grants_purged, 2);
        assert_eq!(user_purge.revocations_purged, 1);
        assert_eq!(user_purge.batches_executed, 2);
        assert!(user_purge.audit_logged);

        // Remaining user rows == 4 preserved boundary/future/permanent rows
        let user_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_permissions")
            .fetch_one(sq)
            .await
            .unwrap();
        assert_eq!(user_left, 4);

        // Trigger abort on batch 2 of group purge reports partial progress cleanly
        sqlx::query(
            "CREATE TRIGGER abort_perm_delete BEFORE DELETE ON group_permissions \
             WHEN OLD.permission = 'perm_400' \
             BEGIN SELECT RAISE(ABORT, 'simulated delete trigger failure'); END;",
        )
        .execute(sq)
        .await
        .unwrap();

        let partial_err = purge_expired(
            &json_yes,
            &PermissionPurgeExpiredArgs {
                before: Some("2023-11-14T22:13:20Z".to_string()),
                retention_days: None,
                scope: PermissionScope::Group,
                batch_size: Some(250),
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        let err_msg = partial_err.to_string();
        assert!(err_msg.contains("1 committed batch(es)"));
        assert!(err_msg.contains("250 rows already deleted"));

        // Drop trigger and finish remaining 850 rows
        sqlx::query("DROP TRIGGER abort_perm_delete")
            .execute(sq)
            .await
            .unwrap();
        let final_purge = purge_expired(
            &json_yes,
            &PermissionPurgeExpiredArgs {
                before: Some("2023-11-14T22:13:20Z".to_string()),
                retention_days: None,
                scope: PermissionScope::Group,
                batch_size: Some(250),
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(final_purge.purged_count, 850);
        assert_eq!(final_purge.batches_executed, 4);

        // Next run is a no-op and does not append another audit_entries row
        let audit_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_entries WHERE action = 'purge_expired_permissions'",
        )
        .fetch_one(sq)
        .await
        .unwrap();
        let noop = purge_expired(
            &json_yes,
            &PermissionPurgeExpiredArgs {
                before: Some("2023-11-14T22:13:20Z".to_string()),
                retention_days: None,
                scope: PermissionScope::All,
                batch_size: Some(250),
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(noop.purged_count, 0);
        assert!(!noop.audit_logged);
        let audit_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_entries WHERE action = 'purge_expired_permissions'",
        )
        .fetch_one(sq)
        .await
        .unwrap();
        assert_eq!(audit_before, audit_after);
    }

    #[tokio::test]
    async fn sync_defaults_preserves_revocations_custom_state_missing_groups_and_concurrency() {
        let env = setup_sqlite_env().await;
        let uid = seed_user_and_groups(&env.pool).await;
        let sq = sqlite_pool(&env.pool);

        // Seed existing states on `user` and `sysop` + custom extra perm:
        // - `user`/`search`: explicit revocation (must be preserved, NOT re-granted)
        // - `user`/`set_username`: expired row (presence check satisfied, reported as inactive/revoked)
        // - `user`/`configure_auth_methods`: missing -> will be inserted
        // - `custom_team`/`custom_perm`: custom group untouched
        sqlx::query(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES \
             ('user', 'search', 0, 0.0, NULL), \
             ('user', 'set_username', 1, 0.0, 100.0), \
             ('custom_team', 'custom_perm', 1, 0.0, NULL)",
        )
        .execute(sq)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO user_permissions (user_id, permission, granted, start_time, end_time) VALUES (?, 'custom_user_perm', 1, 0.0, NULL)",
        )
        .bind(uid.simple().to_string())
        .execute(sq)
        .await
        .unwrap();

        // Write local lock & transaction.json to verify online execution ignores them
        let _held_lock = RuntimeLock::acquire(&env.paths, true).unwrap();

        // Check mode detects drift and fails in `handle`
        let json_no_yes = ctx_for(&env.root, OutputFormat::Json, false);
        let check_err = handle(
            &json_no_yes,
            PermissionCommand::SyncDefaults(PermissionSyncDefaultsArgs {
                groups: vec![],
                defaults_file: None,
                dry_run: false,
                check: true,
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(check_err, CfmsError::Config(_)));

        // Unknown group is rejected cleanly before DB changes
        let bad_group_err = sync_defaults(
            &ctx_for(&env.root, OutputFormat::Json, true),
            &PermissionSyncDefaultsArgs {
                groups: vec!["nonexistent".to_string()],
                defaults_file: None,
                dry_run: false,
                check: false,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(bad_group_err, CfmsError::InvalidArgument(_)));

        // Dry run inspects missing permissions accurately without inserting
        let dry = sync_defaults(
            &json_no_yes,
            &PermissionSyncDefaultsArgs {
                groups: vec!["user".to_string()],
                defaults_file: None,
                dry_run: true,
                check: false,
            },
        )
        .await
        .unwrap();
        assert!(!dry.in_sync);
        assert_eq!(dry.missing_count, 1);
        assert_eq!(dry.inserted_count, 0);
        assert_eq!(dry.defaults_source, "builtin_fallback");
        assert_eq!(dry.group_details[0].missing_permissions, vec!["configure_auth_methods"]);
        assert_eq!(
            dry.group_details[0].inactive_or_revoked_permissions,
            vec!["search".to_string(), "set_username".to_string()]
        );

        // Concurrent tasks racing on `sync_defaults` produce ZERO duplicates!
        let ctx_a = ctx_for(&env.root, OutputFormat::Json, true);
        let ctx_b = ctx_for(&env.root, OutputFormat::Json, true);
        let args = PermissionSyncDefaultsArgs {
            groups: vec![],
            defaults_file: None,
            dry_run: false,
            check: false,
        };
        let (rep_a, rep_b) = tokio::join!(sync_defaults(&ctx_a, &args), sync_defaults(&ctx_b, &args));
        let ra = rep_a.unwrap();
        let rb = rep_b.unwrap();
        assert_eq!(ra.inserted_count + rb.inserted_count, 43);
        assert!(ra.in_sync && rb.in_sync);

        // Check total `group_permissions` rows for user (3) + sysop (42) + custom_team (1) == 46
        let total_gp: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_permissions")
            .fetch_one(sq)
            .await
            .unwrap();
        assert_eq!(total_gp, 46);

        // Verify revocation of `user`/`search` is completely untouched (`granted = 0`)
        let search_granted: bool = sqlx::query_scalar(
            "SELECT granted FROM group_permissions WHERE group_name = 'user' AND permission = 'search'",
        )
        .fetch_one(sq)
        .await
        .unwrap();
        assert!(!search_granted);

        // Verify custom display name, user permissions, and user memberships remain intact
        let custom_display: String = sqlx::query_scalar(
            "SELECT group_display_name FROM user_groups WHERE group_name = 'custom_team'",
        )
        .fetch_one(sq)
        .await
        .unwrap();
        assert_eq!(custom_display, "custom_team Display");
        let user_perm_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_permissions")
            .fetch_one(sq)
            .await
            .unwrap();
        assert_eq!(user_perm_cnt, 1);
        let mem_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_memberships")
            .fetch_one(sq)
            .await
            .unwrap();
        assert_eq!(mem_cnt, 1);

        // Re-running sync-defaults is a complete no-op and does not append duplicate audit entries
        let audit_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_entries WHERE action = 'sync_default_group_permissions'",
        )
        .fetch_one(sq)
        .await
        .unwrap();
        assert_eq!(audit_before, 1);
        let noop_sync = sync_defaults(&ctx_for(&env.root, OutputFormat::Json, true), &args)
            .await
            .unwrap();
        assert!(noop_sync.in_sync);
        assert_eq!(noop_sync.inserted_count, 0);
        assert!(!noop_sync.audit_logged);

        // Concurrent `purge_expired` tasks racing on SQLite complete safely without double-counting
        for i in 0..40 {
            sqlx::query(
                "INSERT INTO user_permissions (user_id, permission, granted, start_time, end_time) VALUES (?, ?, 1, 0.0, ?)",
            )
            .bind(uid.simple().to_string())
            .bind(format!("race_{i}"))
            .bind(1_600_000_000.0 + f64::from(i))
            .execute(sq)
            .await
            .unwrap();
        }
        let purge_args = PermissionPurgeExpiredArgs {
            before: Some("2023-11-14T22:13:20Z".to_string()),
            retention_days: None,
            scope: PermissionScope::User,
            batch_size: Some(7),
            dry_run: false,
        };
        let ctx_p1 = ctx_for(&env.root, OutputFormat::Json, true);
        let ctx_p2 = ctx_for(&env.root, OutputFormat::Json, true);
        let (p1, p2) = tokio::join!(
            purge_expired(&ctx_p1, &purge_args),
            purge_expired(&ctx_p2, &purge_args),
        );
        assert_eq!(p1.unwrap().purged_count + p2.unwrap().purged_count, 40);

        // Verify `--check` now passes
        handle(
            &json_no_yes,
            PermissionCommand::SyncDefaults(PermissionSyncDefaultsArgs {
                groups: vec![],
                defaults_file: None,
                dry_run: false,
                check: true,
            }),
        )
        .await
        .unwrap();

        // Verify missing `user_groups` row (`sysop` deleted) is reported and never auto-created
        sqlx::query("DELETE FROM user_groups WHERE group_name = 'sysop'")
            .execute(sq)
            .await
            .unwrap();
        let json_yes = ctx_for(&env.root, OutputFormat::Json, true);
        let missing_rep = sync_defaults(
            &json_yes,
            &PermissionSyncDefaultsArgs {
                groups: vec!["sysop".to_string()],
                defaults_file: None,
                dry_run: false,
                check: false,
            },
        )
        .await
        .unwrap();
        assert!(!missing_rep.in_sync);
        assert_eq!(missing_rep.missing_groups, vec!["sysop".to_string()]);
        assert_eq!(missing_rep.inserted_count, 0);
        assert!(!missing_rep.audit_logged);
    }

    #[tokio::test]
    async fn sync_defaults_confirmed_preview_aborts_on_new_concurrent_drift() {
        let env = setup_sqlite_env().await;
        seed_user_and_groups(&env.pool).await;
        let sq = sqlite_pool(&env.pool);

        // Initial preview sees only `configure_auth_methods` missing for `user`
        sqlx::query(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES \
             ('user', 'search', 1, 0.0, NULL), \
             ('user', 'set_username', 1, 0.0, NULL)",
        )
        .execute(sq)
        .await
        .unwrap();

        let defaults = DefaultGroupPermissions::builtin();
        let target_groups = vec!["user".to_string()];
        let preview = inspect_default_groups(&env.pool, &defaults, &target_groups, 100.0)
            .await
            .unwrap();
        assert_eq!(
            preview.missing_by_group["user"],
            vec!["configure_auth_methods".to_string()]
        );

        // Concurrent deletion creates a NEW unconfirmed missing permission (`search`)
        sqlx::query(
            "DELETE FROM group_permissions WHERE group_name = 'user' AND permission = 'search'",
        )
        .execute(sq)
        .await
        .unwrap();

        let err = sync_default_groups(
            &env.pool,
            &defaults,
            &target_groups,
            100.0,
            Some(&preview.missing_by_group),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CfmsError::Database(_)));
        assert!(err.to_string().contains("search"));
    }
}
