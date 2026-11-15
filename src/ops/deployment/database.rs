//! Pure-Rust Alembic DAG preflight, schema drift diagnosis, hybrid upgrade execution,
//! downgrade `options` protection, and pre-mutation encrypted `.confbak` integration.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::core::config::DatabaseSectionConfig;
use crate::core::{CfmsError, Result, WorkspacePaths};
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::probe::ExtractorMode;
use crate::db::schema::{
    AlembicDirectoryAnalysis, AlembicDirection, HybridUpgradeOptions, SchemaDriftReport,
    SchemaInspector, analyze_alembic_directory, builtin_schema_ir, execute_hybrid_upgrade,
    extract_code_schema_ir, plan_hybrid_upgrade, run_alembic_revision,
};
use crate::ops::AppContext;
use crate::ops::backup::export::{BackupExportReport, export_pre_mutation_backup};

const OPTIONS_TABLE_REVISION: &str = "16c86712512a";

#[derive(Debug, Clone)]
pub struct DatabaseUpgradePreflight {
    pub dialect: DatabaseKind,
    pub source_head: String,
    pub target_head: String,
    pub live_revision: String,
    pub planned_sql_count: usize,
    pub dml_revisions: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DatabaseDowngradePreflight {
    pub dialect: DatabaseKind,
    pub source_head: String,
    pub target_head: String,
    pub live_revision: String,
    pub undone_revisions: Vec<String>,
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

/// Collect revisions strictly after `ancestor` up to and including `descendant`.
#[must_use]
pub fn collect_revisions_between(
    dag: &AlembicDirectoryAnalysis,
    ancestor: &str,
    descendant: &str,
) -> Vec<String> {
    if ancestor == descendant || !is_revision_ancestor(dag, ancestor, descendant) {
        return Vec::new();
    }
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut between = Vec::new();
    queue.push_back(descendant.to_string());
    while let Some(cur) = queue.pop_front() {
        if cur == ancestor || !visited.insert(cur.clone()) {
            continue;
        }
        between.push(cur.clone());
        if let Some(meta) = dag.scripts.get(&cur) {
            for parent in &meta.down_revisions {
                if parent != ancestor {
                    queue.push_back(parent.clone());
                }
            }
        }
    }
    between
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
            "MySQL DDL executes with implicit commit (non-transactional); pass `--backup` to create an encrypted checkpoint before upgrading/downgrading."
                .to_string(),
        ),
        DatabaseKind::Sqlite => Some(
            "SQLite DDL/batch rebuilds may not automatically roll back across Alembic statements; pass `--backup` to create an encrypted checkpoint before mutating."
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
            dml_revisions = plan
                .dml_revisions
                .iter()
                .map(|(rev, _)| rev.clone())
                .collect();
            if let Some(diff) = plan.diff_plan {
                planned_sql_count = diff.operations.len();
            }
            for f in &plan.risk_audit.findings {
                warnings.push(format!("[{}] {}", f.level, f.summary));
            }
        }
    }

    pool.close().await;
    Ok(DatabaseUpgradePreflight {
        dialect,
        source_head,
        target_head,
        live_revision: live_rev,
        planned_sql_count,
        dml_revisions,
        warnings,
    })
}

/// Preflight Alembic downgrade ancestry, live DB revision, and `16c86712512a` (`options` table)
/// data preservation checks in pure Rust before touching code or DB.
pub async fn preflight_downgrade_database(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    target_snapshot_release_root: &Path,
) -> Result<DatabaseDowngradePreflight> {
    let source_dag = analyze_release_alembic(&paths.project_root)?;
    let target_dag = analyze_release_alembic(target_snapshot_release_root)?;
    let source_head = source_dag.single_head.clone().unwrap();
    let target_head = target_dag.single_head.clone().unwrap();

    if !is_revision_ancestor(&source_dag, &target_head, &source_head) {
        return Err(CfmsError::SchemaDrift(format!(
            "Target snapshot Alembic head '{target_head}' is not an ancestor of active head '{source_head}'"
        )));
    }

    let cfg = ctx.load_config(paths)?;
    let db_cfg = cfg.database_config()?;
    let pool = connect_existing_db_non_creating(paths, &db_cfg)
        .await?
        .ok_or_else(|| {
            CfmsError::Database("Configured SQLite database file does not exist".to_string())
        })?;

    let dialect = pool.kind();
    let live_rev = pool.current_revision().await?.ok_or_else(|| {
        CfmsError::SchemaDrift("Live database has no `alembic_version` revision".to_string())
    })?;

    if live_rev != source_head {
        pool.close().await;
        return Err(CfmsError::SchemaDrift(format!(
            "Live database revision '{live_rev}' does not match active release head '{source_head}'"
        )));
    }

    let undone_revisions = collect_revisions_between(&source_dag, &target_head, &source_head);
    let mut warnings = Vec::new();
    if source_head != target_head {
        if let Some(ddl_warn) = non_transactional_ddl_warning(dialect) {
            warnings.push(ddl_warn);
        }
        if undone_revisions.iter().any(|rev| rev == OPTIONS_TABLE_REVISION)
            && options_table_has_rows(&pool).await?
        {
            pool.close().await;
            return Err(CfmsError::DestructiveMigrationBlocked(
                "Downgrading across revision `16c86712512a` would drop the `options` table while persistent database options exist; export/clear options explicitly first"
                    .to_string(),
            ));
        }
        warnings.push(format!(
            "Database downgrade will revert {} Alembic revision(s) ({source_head} -> {target_head})",
            undone_revisions.len()
        ));
    }

    pool.close().await;
    Ok(DatabaseDowngradePreflight {
        dialect,
        source_head,
        target_head,
        live_revision: live_rev,
        undone_revisions,
        warnings,
    })
}

async fn options_table_has_rows(pool: &DbPool) -> Result<bool> {
    let tables = pool.list_tables().await?;
    if !tables.iter().any(|t| t == "options") {
        return Ok(false);
    }
    let has_row = match pool {
        DbPool::Sqlite(p) => sqlx::query("SELECT 1 FROM options LIMIT 1")
            .fetch_optional(p)
            .await?
            .is_some(),
        DbPool::Mysql(p) => sqlx::query("SELECT 1 FROM options LIMIT 1")
            .fetch_optional(p)
            .await?
            .is_some(),
        DbPool::Postgres(p) => sqlx::query("SELECT 1 FROM options LIMIT 1")
            .fetch_optional(p)
            .await?
            .is_some(),
    };
    Ok(has_row)
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
pub async fn execute_deployment_db_upgrade(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    expected_target_head: &str,
    allow_destructive: bool,
) -> Result<String> {
    let pool = ctx.connect_db(paths).await?;
    let current = pool.current_revision().await?;
    if current.as_deref() == Some(expected_target_head) {
        pool.close().await;
        return Ok(expected_target_head.to_string());
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
    Ok(verified_rev)
}

/// Execute Alembic downgrade against active source code BEFORE swapping files back to target snapshot.
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
    let drift = SchemaInspector::inspect(&pool).await?;
    let rev_opt = drift.current_revision.clone();
    pool.close().await;

    let classification = match (rev_opt.as_deref(), source_head, target_head) {
        (Some(rev), _, Some(tgt)) if rev == tgt => ResumeDbClassification::AtTarget,
        (Some(rev), Some(src), _) if rev == src => ResumeDbClassification::AtSource,
        (Some(rev), Some(src), Some(tgt)) => {
            if let Some(d) = dag {
                let forward_mid = is_revision_ancestor(d, src, rev) && is_revision_ancestor(d, rev, tgt);
                let downgrade_mid = is_revision_ancestor(d, tgt, rev) && is_revision_ancestor(d, rev, src);
                if forward_mid || downgrade_mid {
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
    fn ancestry_and_between_revisions_work() {
        let dag = fake_dag();
        assert!(is_revision_ancestor(&dag, "rev1", "rev3"));
        assert!(is_revision_ancestor(&dag, "rev2", "rev2"));
        assert!(!is_revision_ancestor(&dag, "rev3", "rev1"));
        assert_eq!(
            collect_revisions_between(&dag, "rev1", "rev3"),
            vec!["rev3".to_string(), "rev2".to_string()]
        );
    }
}
