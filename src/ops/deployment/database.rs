//! Pure-Rust Alembic DAG preflight, schema drift diagnosis, hybrid upgrade execution,
//! SQLite pre-upgrade physical checkpoints, transaction-abort DB rollback, and pre-mutation
//! encrypted `.confbak` integration.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::config::DatabaseSectionConfig;
use crate::core::{CfmsError, Result, WorkspacePaths, retry_fs_op};
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::probe::ExtractorMode;
use crate::db::schema::{
    AlembicDirectoryAnalysis, AlembicDirection, HybridUpgradeOptions, SchemaDriftReport,
    SchemaInspector, UpgradeStrategy, analyze_alembic_directory, builtin_schema_ir,
    execute_hybrid_upgrade, extract_code_schema_ir, plan_hybrid_upgrade, run_alembic_revision,
};
use crate::ops::AppContext;
use crate::ops::backup::export::{BackupExportReport, export_pre_mutation_backup};

use super::manifest::hash_file_sha256;
use super::models::DeploymentTransaction;
use super::repository::copy_file_atomic_with_retry;

#[derive(Debug, Clone)]
pub struct DatabaseUpgradePreflight {
    pub dialect: DatabaseKind,
    pub source_head: String,
    pub target_head: String,
    pub live_revision: String,
    pub strategy: Option<UpgradeStrategy>,
    pub planned_sql_count: usize,
    pub dml_revisions: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeDbClassification {
    AtSource,
    AtTarget,
    Intermediate(String),
    Unknown(Option<String>),
}

#[derive(Debug, Clone)]
pub struct ResumeDbDiagnosis {
    pub dialect: DatabaseKind,
    pub classification: ResumeDbClassification,
    pub drift: SchemaDriftReport,
}

/// Analyze a release tree (`<project_root>/src/alembic/versions` or `<project_root>/alembic/versions`)
/// natively in pure Rust and verify it has a single unbroken Alembic head.
pub fn analyze_release_alembic(code_root: &Path) -> Result<AlembicDirectoryAnalysis> {
    let paths = WorkspacePaths::from_code_dir(code_root)?;
    let alembic_paths = paths.discover_alembic_paths().ok_or_else(|| {
        CfmsError::Deployment(format!(
            "Unable to locate `alembic/versions` under '{}'",
            code_root.display()
        ))
    })?;
    let analysis = analyze_alembic_directory(&alembic_paths.versions_dir)?;
    if analysis.heads.len() != 1 || analysis.single_head.is_none() {
        return Err(CfmsError::SchemaDrift(format!(
            "Alembic history under '{}' must have exactly one head, found {:?}",
            alembic_paths.versions_dir.display(),
            analysis.heads
        )));
    }
    Ok(analysis)
}

/// Return true if `ancestor` equals `descendant` or precedes `descendant` along `down_revisions`.
#[must_use]
pub fn is_revision_ancestor(
    dag: &AlembicDirectoryAnalysis,
    ancestor: &str,
    descendant: &str,
) -> bool {
    if ancestor == descendant {
        return dag.scripts.contains_key(descendant);
    }
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(descendant.to_string());
    while let Some(cur) = queue.pop_front() {
        if !visited.insert(cur.clone()) {
            continue;
        }
        if let Some(meta) = dag.scripts.get(&cur) {
            for parent in &meta.down_revisions {
                if parent == ancestor {
                    return true;
                }
                queue.push_back(parent.clone());
            }
        }
    }
    false
}

/// Connect to the configured database ONLY if a non-empty / existing SQLite file (or MySQL/Postgres)
/// is already present, returning `Ok(None)` when SQLite file does not yet exist on disk.
pub async fn connect_existing_db_non_creating(
    paths: &WorkspacePaths,
    db_cfg: &DatabaseSectionConfig,
) -> Result<Option<DbPool>> {
    if db_cfg.kind == DatabaseKind::Sqlite && db_cfg.file != ":memory:" {
        let sqlite_path = paths.resolve_sqlite_path(&db_cfg.file);
        if !sqlite_path.exists() {
            return Ok(None);
        }
    }
    let pool = DbPool::connect(db_cfg, paths).await?;
    Ok(Some(pool))
}

fn non_transactional_ddl_warning(dialect: DatabaseKind) -> Option<String> {
    match dialect {
        DatabaseKind::Mysql => Some(
            "MySQL DDL executes with implicit commit (non-transactional); pass `--backup` to create an encrypted checkpoint before upgrading."
                .to_string(),
        ),
        DatabaseKind::Sqlite => Some(
            "SQLite DDL/batch rebuilds are non-transactional; an automatic pre-upgrade SQLite checkpoint will be captured for abort rollback, and you may also pass `--backup` for an encrypted external checkpoint."
                .to_string(),
        ),
        DatabaseKind::Postgresql => None,
    }
}

/// Preflight DB readiness, Alembic ancestry, live `alembic_version`, and schema risk audit
/// purely in Rust BEFORE mutating any workspace files.
pub async fn preflight_upgrade_database(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    staged_code_root: &Path,
    allow_destructive: bool,
) -> Result<DatabaseUpgradePreflight> {
    let source_dag = analyze_release_alembic(&paths.project_root)?;
    let target_dag = analyze_release_alembic(staged_code_root)?;
    let source_head = source_dag.single_head.clone().unwrap();
    let target_head = target_dag.single_head.clone().unwrap();

    if !is_revision_ancestor(&target_dag, &source_head, &target_head) {
        return Err(CfmsError::SchemaDrift(format!(
            "Target Alembic head '{target_head}' does not descend from active head '{source_head}'"
        )));
    }

    let cfg = ctx.load_config(paths)?;
    let db_cfg = cfg.database_config()?;
    let pool = connect_existing_db_non_creating(paths, &db_cfg)
        .await?
        .ok_or_else(|| {
            CfmsError::Database(format!(
                "Configured SQLite database file '{}' does not exist yet; initialize or start server before upgrading",
                paths.resolve_sqlite_path(&db_cfg.file).display()
            ))
        })?;

    let dialect = pool.kind();
    let live_rev = pool.current_revision().await?.ok_or_else(|| {
        CfmsError::SchemaDrift(
            "Live database has no `alembic_version` revision; run `cfms-ctl database upgrade` or `stamp` first"
                .to_string(),
        )
    })?;

    if live_rev != source_head {
        pool.close().await;
        return Err(CfmsError::SchemaDrift(format!(
            "Live database revision '{live_rev}' does not match active release head '{source_head}'; align schema first with `cfms-ctl database upgrade`"
        )));
    }

    let mut warnings = Vec::new();
    let mut strategy = None;
    let mut planned_sql_count = 0usize;
    let mut dml_revisions = Vec::new();

    if source_head != target_head {
        if let Some(ddl_warn) = non_transactional_ddl_warning(dialect) {
            warnings.push(ddl_warn);
        }

        let staged_paths = WorkspacePaths::from_code_dir(staged_code_root)?;
        let target_ir = if staged_paths
            .discover_schema_ir_path(None)
            .ok()
            .flatten()
            .is_some()
        {
            extract_code_schema_ir(
                &staged_paths,
                ExtractorMode::Json,
                None,
                None,
                false,
                true,
            )
            .await
            .unwrap_or_else(|_| builtin_schema_ir(false))
        } else {
            let extracted = extract_code_schema_ir(
                &staged_paths,
                ExtractorMode::Static,
                None,
                None,
                false,
                true,
            )
            .await
            .unwrap_or_else(|_| builtin_schema_ir(false));
            if extracted.tables.is_empty() {
                builtin_schema_ir(false)
            } else {
                extracted
            }
        };

        let opts = HybridUpgradeOptions {
            allow_destructive,
            dry_run: true,
            ..Default::default()
        };
        if let Ok(plan) = plan_hybrid_upgrade(&pool, Some(&staged_paths), &target_ir, &opts).await {
            strategy = Some(plan.strategy);
            dml_revisions = plan
                .dml_revisions
                .iter()
                .map(|(rev, _)| rev.clone())
                .collect();
            if plan.strategy == UpgradeStrategy::DelegateAlembic {
                // When data-DML scripts trigger Alembic delegation, native DDL diff ops
                // will not be executed; surface only the Alembic-delegation notice.
                for f in &plan.risk_audit.findings {
                    if f.code == "CFMS-MIG-008" {
                        warnings.push(format!(
                            "[{}] {} (database upgrade will run via Alembic)",
                            f.level, f.summary
                        ));
                    }
                }
            } else {
                if let Some(diff) = plan.diff_plan {
                    planned_sql_count = diff.operations.len();
                }
                for f in &plan.risk_audit.findings {
                    warnings.push(format!("[{}] {}", f.level, f.summary));
                }
            }
        }
    }

    pool.close().await;
    Ok(DatabaseUpgradePreflight {
        dialect,
        source_head,
        target_head,
        live_revision: live_rev,
        strategy,
        planned_sql_count,
        dml_revisions,
        warnings,
    })
}

/// Capture a consistent, WAL-safe pre-upgrade SQLite physical checkpoint via `VACUUM INTO`
/// inside the transaction directory so explicit abort (`deployment resume --rollback`) can
/// atomically undo all in-flight DDL, table rebuilds, and DML changes.
///
/// Returns `Ok(None)` for MySQL, PostgreSQL, or `:memory:` SQLite databases.
pub async fn capture_sqlite_upgrade_checkpoint(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    checkpoint_path: &Path,
) -> Result<Option<(PathBuf, String)>> {
    let cfg = ctx.load_config(paths)?;
    let db_cfg = cfg.database_config()?;
    if db_cfg.kind != DatabaseKind::Sqlite || db_cfg.file == ":memory:" {
        return Ok(None);
    }

    if let Some(parent) = checkpoint_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if checkpoint_path.exists() {
        retry_fs_op(|| match fs::remove_file(checkpoint_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        })?;
    }

    let pool = DbPool::connect(&db_cfg, paths).await?;
    let DbPool::Sqlite(ref sq) = pool else {
        unreachable!("checked SQLite dialect");
    };
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE);").execute(sq).await;
    let normalized_path = checkpoint_path
        .to_string_lossy()
        .replace('\\', "/")
        .replace('\'', "''");
    let sql = format!("VACUUM INTO '{normalized_path}';");
    let vacuum_res = sqlx::query(sqlx::AssertSqlSafe(sql)).execute(sq).await;
    pool.close().await;
    vacuum_res?;

    let (sha256, _) = hash_file_sha256(checkpoint_path)?;
    Ok(Some((checkpoint_path.to_path_buf(), sha256)))
}

/// Atomically restore a live SQLite database from a SHA-256-verified pre-upgrade checkpoint
/// and clear stale `-wal` / `-shm` sidecar files.
pub fn restore_sqlite_upgrade_checkpoint(
    paths: &WorkspacePaths,
    db_cfg: &DatabaseSectionConfig,
    checkpoint_path: &Path,
    expected_sha256: &str,
) -> Result<()> {
    if db_cfg.kind != DatabaseKind::Sqlite || db_cfg.file == ":memory:" {
        return Err(CfmsError::Deployment(
            "SQLite checkpoint restore attempted on a non-file SQLite database".to_string(),
        ));
    }
    let (actual_sha256, _) = hash_file_sha256(checkpoint_path)?;
    if actual_sha256 != expected_sha256 {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "SQLite pre-upgrade checkpoint '{}' failed SHA-256 verification (expected {expected_sha256}, got {actual_sha256})",
            checkpoint_path.display()
        )));
    }

    let live_path = paths.resolve_sqlite_path(&db_cfg.file);
    copy_file_atomic_with_retry(checkpoint_path, &live_path)?;

    for suffix in ["-wal", "-shm"] {
        let mut sidecar = live_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar_path = PathBuf::from(sidecar);
        if sidecar_path.exists() {
            let _ = retry_fs_op(|| match fs::remove_file(&sidecar_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            });
        }
    }
    Ok(())
}

/// Undo all in-flight database modifications when an operator explicitly aborts an interrupted
/// upgrade via `cfms-ctl deployment resume --rollback`.
///
/// Strategy:
/// - **SQLite (with verified pre-upgrade checkpoint)**: atomically replaces the live database file
///   from `tx.db_checkpoint_path` (clearing `-wal`/`-shm`), reverting 100% of partial DDL/DML even
///   from `Intermediate` or `Unknown` states.
/// - **PostgreSQL / MySQL (or fallback)**: runs internal `alembic downgrade <source_head>` while the
///   new release's Alembic scripts remain active on disk, then verifies `alembic_version == source_head`
///   and checks the live schema against the source snapshot's Schema IR when available.
pub async fn rollback_upgrade_database(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    tx: &DeploymentTransaction,
    source_release_dir: Option<&Path>,
) -> Result<String> {
    let source_head = tx.source_head.as_deref().ok_or_else(|| {
        CfmsError::Deployment("Missing source_head in transaction.json".to_string())
    })?;
    let cfg = ctx.load_config(paths)?;
    let db_cfg = cfg.database_config()?;

    // Tier 1: Exact physical checkpoint restore for file-backed SQLite.
    if db_cfg.kind == DatabaseKind::Sqlite
        && db_cfg.file != ":memory:"
        && let (Some(cp_path), Some(cp_sha)) =
            (tx.db_checkpoint_path.as_deref(), tx.db_checkpoint_sha256.as_deref())
    {
        restore_sqlite_upgrade_checkpoint(paths, &db_cfg, Path::new(cp_path), cp_sha)?;
        let verify_pool = DbPool::connect(&db_cfg, paths).await?;
        let observed = verify_pool.current_revision().await?;
        verify_pool.close().await;
        if observed.as_deref() != Some(source_head) {
            return Err(CfmsError::SchemaDrift(format!(
                "Restored SQLite checkpoint revision {:?} does not match expected source_head '{source_head}'",
                observed
            )));
        }
        return Ok(source_head.to_string());
    }

    // Tier 2: Transactional / Alembic rollback for PostgreSQL & MySQL (or SQLite without checkpoint).
    let pool = DbPool::connect(&db_cfg, paths).await?;
    let live_rev = pool.current_revision().await?;
    pool.close().await;

    match live_rev.as_deref() {
        Some(rev) if rev == source_head => {}
        Some(rev) => {
            let active_dag = analyze_release_alembic(&paths.project_root).ok();
            let can_downgrade = active_dag
                .as_ref()
                .is_some_and(|dag| is_revision_ancestor(dag, source_head, rev));
            if !can_downgrade {
                return Err(CfmsError::SchemaDrift(format!(
                    "Cannot automatically roll back database from unrecognized revision '{rev}' to '{source_head}'. Restore your pre-upgrade `.confbak` backup and run `cfms-ctl deployment resume --abort-clear`."
                )));
            }
            execute_deployment_db_downgrade(ctx, paths, source_head).await?;
        }
        None => {
            return Err(CfmsError::SchemaDrift(format!(
                "Live database has no `alembic_version` revision while attempting rollback to '{source_head}'. Restore your pre-upgrade backup and run `cfms-ctl deployment resume --abort-clear`."
            )));
        }
    }

    // Verify source schema alignment when source Schema IR is extractable (catches non-transactional
    // partial DDL leftovers on MySQL when `alembic_version` stayed at `source_head`).
    if let Some(src_dir) = source_release_dir
        && let Ok(src_paths) = WorkspacePaths::from_code_dir(src_dir)
    {
        let src_ir = if src_paths
            .discover_schema_ir_path(None)
            .ok()
            .flatten()
            .is_some()
        {
            extract_code_schema_ir(&src_paths, ExtractorMode::Json, None, None, false, false)
                .await
                .ok()
        } else {
            extract_code_schema_ir(&src_paths, ExtractorMode::Static, None, None, false, false)
                .await
                .ok()
        };
        if let Some(ir) = src_ir
            && !ir.tables.is_empty()
        {
            let verify_pool = DbPool::connect(&db_cfg, paths).await?;
            let drift = SchemaInspector::inspect_against_ir(&verify_pool, &ir).await?;
            verify_pool.close().await;
            if !drift.missing_tables.is_empty() || !drift.column_mismatches.is_empty() {
                return Err(CfmsError::SchemaDrift(format!(
                    "Database revision is at '{source_head}', but residual schema drift remains against source release (missing_tables={:?}, column_mismatches={:?}). Restore your pre-upgrade `.confbak` backup before clearing the transaction.",
                    drift.missing_tables, drift.column_mismatches
                )));
            }
        }
    }

    Ok(source_head.to_string())
}

/// Create optional encrypted `.confbak` safety backup before mutating workspace/DB.
pub async fn maybe_create_safety_backup(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    backup_path: Option<PathBuf>,
    key_out: Option<PathBuf>,
) -> Result<Option<BackupExportReport>> {
    let Some(out_path) = backup_path else {
        return Ok(None);
    };
    let report = export_pre_mutation_backup(ctx, paths, out_path, key_out).await?;
    Ok(Some(report))
}

/// Execute database upgrade after active code & `.venv` & `config.toml` are in place.
/// Returns `(verified_revision, post_upgrade_warnings)`.
pub async fn execute_deployment_db_upgrade(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    expected_target_head: &str,
    allow_destructive: bool,
) -> Result<(String, Vec<String>)> {
    let pool = ctx.connect_db(paths).await?;
    let current = pool.current_revision().await?;
    if current.as_deref() == Some(expected_target_head) {
        pool.close().await;
        return Ok((expected_target_head.to_string(), Vec::new()));
    }

    let target_ir = extract_code_schema_ir(paths, ExtractorMode::Auto, None, None, true, true)
        .await
        .unwrap_or_else(|_| builtin_schema_ir(false));
    let opts = HybridUpgradeOptions {
        allow_destructive,
        dry_run: false,
        ..Default::default()
    };
    let outcome = execute_hybrid_upgrade(&pool, Some(paths), &target_ir, &opts).await?;
    let verified_rev = pool.current_revision().await?.unwrap_or(outcome.current_revision);
    pool.close().await;

    if verified_rev != expected_target_head {
        return Err(CfmsError::SchemaDrift(format!(
            "Database migration finished at revision '{verified_rev}' instead of expected head '{expected_target_head}'"
        )));
    }
    Ok((verified_rev, outcome.warnings))
}

/// Internal helper: execute Alembic downgrade against active target code ONLY when aborting an
/// unfinished upgrade transaction (`cfms-ctl deployment resume --rollback`).
pub async fn execute_deployment_db_downgrade(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    target_head: &str,
) -> Result<String> {
    let pool = ctx.connect_db(paths).await?;
    if pool.current_revision().await?.as_deref() == Some(target_head) {
        pool.close().await;
        return Ok(target_head.to_string());
    }
    pool.close().await;

    let alembic_paths = paths.discover_alembic_paths().ok_or_else(|| {
        CfmsError::Deployment(format!(
            "Missing Alembic configuration under '{}'",
            paths.server_root.display()
        ))
    })?;
    run_alembic_revision(
        paths,
        &alembic_paths,
        AlembicDirection::DowngradeTo(target_head.to_string()),
    )
    .await?;

    let verify_pool = ctx.connect_db(paths).await?;
    let observed = verify_pool.current_revision().await?;
    verify_pool.close().await;

    if observed.as_deref() != Some(target_head) {
        return Err(CfmsError::SchemaDrift(format!(
            "Database downgrade completed at revision {:?} instead of expected '{target_head}'",
            observed
        )));
    }
    Ok(target_head.to_string())
}

/// Bootstrap an uninitialized database during fresh `cfms-ctl deployment install`.
pub async fn initialize_fresh_database(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    expected_head: &str,
) -> Result<String> {
    let pool = ctx.connect_db(paths).await?;
    let target_ir = extract_code_schema_ir(paths, ExtractorMode::Auto, None, None, true, true)
        .await
        .unwrap_or_else(|_| builtin_schema_ir(false));
    let opts = HybridUpgradeOptions::default();
    let outcome = execute_hybrid_upgrade(&pool, Some(paths), &target_ir, &opts).await?;
    let final_rev = pool
        .current_revision()
        .await?
        .unwrap_or(outcome.current_revision);
    pool.close().await;
    if final_rev != expected_head {
        return Err(CfmsError::SchemaDrift(format!(
            "Fresh DB initialized at '{final_rev}' instead of release head '{expected_head}'"
        )));
    }
    Ok(final_rev)
}

/// Diagnose live database state relative to `source_head` and `target_head` during `resume`.
pub async fn diagnose_resume_database(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    dag: Option<&AlembicDirectoryAnalysis>,
    source_head: Option<&str>,
    target_head: Option<&str>,
) -> Result<ResumeDbDiagnosis> {
    let pool = ctx.connect_db(paths).await?;
    let dialect = pool.kind();
    let target_ir = extract_code_schema_ir(paths, ExtractorMode::Auto, None, None, false, true)
        .await
        .unwrap_or_else(|_| builtin_schema_ir(false));
    let drift = SchemaInspector::inspect_against_ir(&pool, &target_ir).await?;
    let rev_opt = drift.current_revision.clone();
    pool.close().await;

    let classification = match (rev_opt.as_deref(), source_head, target_head) {
        (Some(rev), _, Some(tgt)) if rev == tgt => ResumeDbClassification::AtTarget,
        (Some(rev), Some(src), _) if rev == src => ResumeDbClassification::AtSource,
        (Some(rev), Some(src), Some(tgt)) => {
            if let Some(d) = dag {
                let forward_mid = is_revision_ancestor(d, src, rev) && is_revision_ancestor(d, rev, tgt);
                if forward_mid {
                    ResumeDbClassification::Intermediate(rev.to_string())
                } else {
                    ResumeDbClassification::Unknown(Some(rev.to_string()))
                }
            } else {
                ResumeDbClassification::Unknown(Some(rev.to_string()))
            }
        }
        (other, _, _) => ResumeDbClassification::Unknown(other.map(str::to_string)),
    };

    Ok(ResumeDbDiagnosis {
        dialect,
        classification,
        drift,
    })
}

/// Read current DB dialect, live revision, and Alembic head for read-only `deployment status`.
pub async fn inspect_status_database(
    ctx: &AppContext,
    paths: &WorkspacePaths,
) -> (Option<String>, Option<String>, Option<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let alembic_head = analyze_release_alembic(&paths.project_root)
        .ok()
        .and_then(|d| d.single_head);

    let cfg = match ctx.load_config(paths) {
        Ok(c) => c,
        Err(err) => {
            warnings.push(format!("Configuration unavailable for DB status check: {err}"));
            return (None, None, alembic_head, warnings);
        }
    };
    let db_cfg = match cfg.database_config() {
        Ok(d) => d,
        Err(err) => {
            warnings.push(format!("Database configuration invalid: {err}"));
            return (None, None, alembic_head, warnings);
        }
    };
    let backend_name = db_cfg.kind.as_str().to_string();
    match connect_existing_db_non_creating(paths, &db_cfg).await {
        Ok(Some(pool)) => {
            let rev = match pool.current_revision().await {
                Ok(r) => r,
                Err(err) => {
                    warnings.push(format!("Unable to query alembic_version: {err}"));
                    None
                }
            };
            pool.close().await;
            (Some(backend_name), rev, alembic_head, warnings)
        }
        Ok(None) => {
            warnings.push("Configured SQLite database file does not exist yet".to_string());
            (Some(backend_name), None, alembic_head, warnings)
        }
        Err(err) => {
            warnings.push(format!("Database connection check failed: {err}"));
            (Some(backend_name), None, alembic_head, warnings)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use crate::db::schema::static_ast::AlembicScriptMeta;
    use super::*;

    fn fake_dag() -> AlembicDirectoryAnalysis {
        let mut scripts = BTreeMap::new();
        scripts.insert(
            "rev1".to_string(),
            AlembicScriptMeta {
                revision: "rev1".to_string(),
                down_revisions: vec![],
                file_path: PathBuf::from("1.py"),
                has_data_dml: false,
                dml_reasons: vec![],
            },
        );
        scripts.insert(
            "rev2".to_string(),
            AlembicScriptMeta {
                revision: "rev2".to_string(),
                down_revisions: vec!["rev1".to_string()],
                file_path: PathBuf::from("2.py"),
                has_data_dml: false,
                dml_reasons: vec![],
            },
        );
        scripts.insert(
            "rev3".to_string(),
            AlembicScriptMeta {
                revision: "rev3".to_string(),
                down_revisions: vec!["rev2".to_string()],
                file_path: PathBuf::from("3.py"),
                has_data_dml: false,
                dml_reasons: vec![],
            },
        );
        AlembicDirectoryAnalysis {
            scripts,
            heads: vec!["rev3".to_string()],
            single_head: Some("rev3".to_string()),
            warnings: vec![],
        }
    }

    #[test]
    fn ancestry_check_works() {
        let dag = fake_dag();
        assert!(is_revision_ancestor(&dag, "rev1", "rev3"));
        assert!(is_revision_ancestor(&dag, "rev2", "rev2"));
        assert!(!is_revision_ancestor(&dag, "rev3", "rev1"));
    }
}
