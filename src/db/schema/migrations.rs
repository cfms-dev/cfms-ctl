//! Native multi-backend (SQLite, MySQL, PostgreSQL) schema bootstrap and incremental
//! migration engine covering CFMS 0.14.0 (`e952c02c1454`) -> CEP-0002 CACL (`a66108639ed7`).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use serde::Serialize;
use sqlx::{Acquire, Row};
use tokio::process::Command;

use crate::core::error::{CfmsError, Result};
use crate::core::paths::{AlembicPaths, WorkspacePaths};
use crate::db::backend::{DatabaseKind, DbPool, ServerCompatibility};
use crate::db::schema::ddl::{
    builtin_schema_ir, create_head_schema, execute_ddl_statements, set_alembic_version, table_def,
};
use crate::db::schema::diff::{DiffOptions, SchemaDiffPlan, SchemaOp, diff_schemas};
use crate::db::schema::inspector::{SchemaDriftReport, SchemaInspector};
use crate::db::schema::ir::{ExtractionSource, SchemaIr, TableOwnership};
use crate::db::schema::live_ir::introspect_live_schema_ir;
use crate::db::schema::probe::discover_python_candidates;
use crate::db::schema::registry::{
    LATEST_SCHEMA_REVISION, is_known_revision, revisions_after,
};
use crate::db::schema::rename::RenameConfig;
use crate::db::schema::render::{compile_full_schema_ddl, compile_op_to_sql_statements};
use crate::db::schema::risk::{RiskAuditReport, audit_diff_plan, run_live_preflight_checks};
use crate::db::schema::static_ast::{PendingAlembicAnalysis, analyze_alembic_directory};

/// Result produced by [`upgrade_database_schema`].
#[derive(Debug, Clone, Serialize)]
pub struct SchemaUpgradeOutcome {
    pub dialect: DatabaseKind,
    pub previous_revision: Option<String>,
    pub current_revision: String,
    pub bootstrapped: bool,
    pub applied_revisions: Vec<String>,
    pub warnings: Vec<String>,
}

/// Inspect the target database and either bootstrap an empty database to HEAD (`a66108639ed7`)
/// or execute the remaining linear upgrade steps to HEAD.
pub async fn upgrade_database_schema(pool: &DbPool) -> Result<SchemaUpgradeOutcome> {
    let compatibility = pool.validate_server_compatibility().await?;
    let report = SchemaInspector::inspect(pool).await?;

    if report.is_empty_database {
        create_head_schema(pool, false).await?;
        set_alembic_version(pool, LATEST_SCHEMA_REVISION).await?;
        return Ok(SchemaUpgradeOutcome {
            dialect: pool.kind(),
            previous_revision: None,
            current_revision: LATEST_SCHEMA_REVISION.to_string(),
            bootstrapped: true,
            applied_revisions: vec![LATEST_SCHEMA_REVISION.to_string()],
            warnings: compatibility.warnings,
        });
    }

    let Some(ref current_rev) = report.current_revision else {
        return Err(CfmsError::SchemaDrift(
            "Database contains application tables without an alembic_version revision; refusing to guess a migration revision".to_string(),
        ));
    };

    if !is_known_revision(current_rev) {
        return Err(CfmsError::SchemaDrift(format!(
            "Revision '{current_rev}' is not supported by this cfms-ctl release"
        )));
    }

    if current_rev == LATEST_SCHEMA_REVISION {
        if !report.missing_tables.is_empty() {
            return Err(CfmsError::SchemaDrift(format!(
                "Database is stamped at HEAD ({LATEST_SCHEMA_REVISION}) but is missing core tables: {}",
                report.missing_tables.join(", ")
            )));
        }
        return Ok(SchemaUpgradeOutcome {
            dialect: pool.kind(),
            previous_revision: Some(current_rev.clone()),
            current_revision: LATEST_SCHEMA_REVISION.to_string(),
            bootstrapped: false,
            applied_revisions: Vec::new(),
            warnings: compatibility.warnings,
        });
    }

    let pending = revisions_after(current_rev).ok_or_else(|| {
        CfmsError::SchemaDrift(format!("Unable to resolve upgrade path from '{current_rev}'"))
    })?;

    let mut applied = Vec::with_capacity(pending.len());
    for rev in pending {
        apply_revision_step(pool, rev.id, &compatibility).await?;
        set_alembic_version(pool, rev.id).await?;
        applied.push(rev.id.to_string());
    }

    let final_report = SchemaInspector::inspect(pool).await?;
    if !final_report.healthy {
        return Err(CfmsError::SchemaDrift(format!(
            "Database upgrade reached '{}' but schema inspection still reports drift (missing: {:?})",
            LATEST_SCHEMA_REVISION, final_report.missing_tables
        )));
    }

    Ok(SchemaUpgradeOutcome {
        dialect: pool.kind(),
        previous_revision: Some(current_rev.clone()),
        current_revision: LATEST_SCHEMA_REVISION.to_string(),
        bootstrapped: false,
        applied_revisions: applied,
        warnings: compatibility.warnings,
    })
}

/// Preview what [`upgrade_database_schema`] would do without mutating the database.
pub async fn inspect_upgrade_plan(
    pool: &DbPool,
) -> Result<(SchemaDriftReport, ServerCompatibility, Vec<String>)> {
    let compatibility = pool.validate_server_compatibility().await?;
    let report = SchemaInspector::inspect(pool).await?;

    if report.is_empty_database {
        return Ok((
            report,
            compatibility,
            vec![LATEST_SCHEMA_REVISION.to_string()],
        ));
    }

    let Some(ref current_rev) = report.current_revision else {
        return Err(CfmsError::SchemaDrift(
            "Database contains application tables without an alembic_version revision; refusing to guess a migration revision".to_string(),
        ));
    };

    if !is_known_revision(current_rev) {
        return Err(CfmsError::SchemaDrift(format!(
            "Revision '{current_rev}' is not supported by this cfms-ctl release"
        )));
    }

    if current_rev == LATEST_SCHEMA_REVISION && !report.missing_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database is stamped at HEAD ({LATEST_SCHEMA_REVISION}) but is missing core tables: {}",
            report.missing_tables.join(", ")
        )));
    }

    let pending: Vec<String> = revisions_after(current_rev)
        .unwrap_or(&[])
        .iter()
        .map(|r| r.id.to_string())
        .collect();
    Ok((report, compatibility, pending))
}

/// Strategy selected by the hybrid schema upgrade planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStrategy {
    AlreadyAtTarget,
    BootstrapTarget,
    HistoricalNative,
    HybridNativeDdl,
    HistoricalThenHybridDdl,
    DelegateAlembic,
}

impl std::fmt::Display for UpgradeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::AlreadyAtTarget => "already_at_target",
            Self::BootstrapTarget => "bootstrap_target",
            Self::HistoricalNative => "historical_native",
            Self::HybridNativeDdl => "hybrid_native_ddl",
            Self::HistoricalThenHybridDdl => "historical_then_hybrid_ddl",
            Self::DelegateAlembic => "delegate_alembic",
        };
        f.write_str(s)
    }
}

/// Execution policy flags controlling the hybrid schema upgrade engine.
#[derive(Debug, Clone, Default)]
pub struct HybridUpgradeOptions {
    pub dry_run: bool,
    pub allow_destructive: bool,
    pub rename_overrides: Vec<String>,
    pub schema_only: bool,
    pub no_alembic_delegate: bool,
    pub include_extensions: bool,
}

/// Non-mutating upgrade inspection and risk audit plan.
#[derive(Debug, Clone)]
pub struct HybridUpgradePlan {
    pub dialect: DatabaseKind,
    pub compatibility: ServerCompatibility,
    pub drift: SchemaDriftReport,
    pub strategy: UpgradeStrategy,
    pub target_revision: String,
    pub historical_steps: Vec<String>,
    pub diff_plan: Option<SchemaDiffPlan>,
    pub risk_audit: RiskAuditReport,
    pub pending_alembic: Option<PendingAlembicAnalysis>,
    pub dml_revisions: Vec<(String, Vec<String>)>,
    pub bootstrap_statements: Vec<String>,
    pub effective_target_ir: SchemaIr,
    pub warnings: Vec<String>,
}

/// Rich outcome returned by [`execute_hybrid_upgrade`].
#[derive(Debug, Clone, Serialize)]
pub struct HybridUpgradeOutcome {
    pub dialect: DatabaseKind,
    pub strategy: UpgradeStrategy,
    pub dry_run: bool,
    pub previous_revision: Option<String>,
    pub current_revision: String,
    pub bootstrapped: bool,
    pub delegated_to_alembic: bool,
    pub applied_revisions: Vec<String>,
    pub executed_sql_count: usize,
    pub risk_audit: RiskAuditReport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dml_scripts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Outcome returned by [`stamp_database_revision`].
#[derive(Debug, Clone, Serialize)]
pub struct StampOutcome {
    pub dialect: DatabaseKind,
    pub previous_revision: Option<String>,
    pub stamped_revision: String,
    pub forced: bool,
    pub validated_against: String,
}

/// Explicitly set `alembic_version` to `revision` (or resolve `head`) with optional DAG validation.
pub async fn stamp_database_revision(
    pool: &DbPool,
    alembic_versions_dir: Option<&Path>,
    revision: &str,
    force: bool,
) -> Result<StampOutcome> {
    let trimmed = revision.trim();
    if trimmed.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "Target revision must not be empty".to_string(),
        ));
    }

    let analysis = match alembic_versions_dir {
        Some(dir) if dir.is_dir() => Some(analyze_alembic_directory(dir)?),
        _ => None,
    };

    let (resolved_revision, validated_against) = if trimmed.eq_ignore_ascii_case("head") {
        if let Some(ref dag) = analysis {
            if let Some(ref single) = dag.single_head {
                (single.clone(), "workspace alembic/versions DAG".to_string())
            } else if dag.heads.len() > 1 {
                return Err(CfmsError::SchemaDrift(format!(
                    "Workspace Alembic repository has multiple branch heads ({}); specify an explicit revision id",
                    dag.heads.join(", ")
                )));
            } else {
                (
                    LATEST_SCHEMA_REVISION.to_string(),
                    "built-in CFMS schema registry (empty workspace alembic directory)".to_string(),
                )
            }
        } else {
            (
                LATEST_SCHEMA_REVISION.to_string(),
                "built-in CFMS schema registry".to_string(),
            )
        }
    } else if let Some(ref dag) = analysis {
        if dag.scripts.contains_key(trimmed) {
            (
                trimmed.to_string(),
                "workspace alembic/versions DAG".to_string(),
            )
        } else if is_known_revision(trimmed) {
            (
                trimmed.to_string(),
                "built-in CFMS historical registry".to_string(),
            )
        } else if force {
            (
                trimmed.to_string(),
                "forced unverified revision".to_string(),
            )
        } else {
            return Err(CfmsError::InvalidArgument(format!(
                "Revision '{trimmed}' was not found in workspace alembic/versions or built-in history (pass --force to stamp anyway)"
            )));
        }
    } else if is_known_revision(trimmed) {
        (
            trimmed.to_string(),
            "built-in CFMS historical registry".to_string(),
        )
    } else if force {
        (
            trimmed.to_string(),
            "forced unverified revision".to_string(),
        )
    } else {
        return Err(CfmsError::InvalidArgument(format!(
            "Revision '{trimmed}' is not in the built-in CFMS revision list and no workspace alembic/versions directory was found (pass --force to stamp anyway)"
        )));
    };

    let previous_revision = pool.current_revision().await?;
    set_alembic_version(pool, &resolved_revision).await?;

    Ok(StampOutcome {
        dialect: pool.kind(),
        previous_revision,
        stamped_revision: resolved_revision,
        forced: force,
        validated_against,
    })
}

fn filter_target_ir(
    target: &SchemaIr,
    live_tables: Option<&HashSet<String>>,
    include_all_extensions: bool,
) -> SchemaIr {
    let mut filtered = SchemaIr::new(target.source, target.schema_revision.clone());
    filtered.warnings = target.warnings.clone();
    for (name, table) in &target.tables {
        let include = match &table.ownership {
            TableOwnership::Core => true,
            TableOwnership::Extension(_) => {
                include_all_extensions || live_tables.is_some_and(|set| set.contains(name))
            }
        };
        if include {
            filtered.tables.insert(name.clone(), table.clone());
        }
    }
    filtered
}

fn parse_rename_config(specs: &[String]) -> Result<RenameConfig> {
    let mut cfg = RenameConfig::default();
    for spec in specs {
        cfg.insert_override_spec(spec)
            .map_err(|e| CfmsError::InvalidArgument(format!("Invalid --rename '{spec}': {e}")))?;
    }
    Ok(cfg)
}

/// Build an inspection and risk-audited hybrid upgrade plan without mutating the database.
pub async fn plan_hybrid_upgrade(
    pool: &DbPool,
    paths: Option<&WorkspacePaths>,
    target_ir: &SchemaIr,
    opts: &HybridUpgradeOptions,
) -> Result<HybridUpgradePlan> {
    let compatibility = pool.validate_server_compatibility().await?;
    let mut warnings = compatibility.warnings.clone();
    warnings.extend(target_ir.warnings.clone());

    let rename_cfg = parse_rename_config(&opts.rename_overrides)?;
    let alembic_paths = paths.and_then(|p| p.discover_alembic_paths());
    let alembic_analysis = match alembic_paths {
        Some(ref ap) if ap.versions_dir.is_dir() => Some(analyze_alembic_directory(&ap.versions_dir)?),
        _ => None,
    };

    let mut target_revision = target_ir
        .schema_revision
        .clone()
        .or_else(|| alembic_analysis.as_ref().and_then(|a| a.single_head.clone()))
        .unwrap_or_else(|| LATEST_SCHEMA_REVISION.to_string());
    if let Some(ref dag) = alembic_analysis {
        warnings.extend(dag.warnings.clone());
    }

    let drift = SchemaInspector::inspect_against_ir(pool, target_ir).await?;

    if drift.is_empty_database {
        let effective_target = filter_target_ir(target_ir, None, opts.include_extensions);
        let bootstrap_statements = compile_full_schema_ddl(&effective_target, pool.kind());
        return Ok(HybridUpgradePlan {
            dialect: pool.kind(),
            compatibility,
            drift,
            strategy: UpgradeStrategy::BootstrapTarget,
            historical_steps: vec![target_revision.clone()],
            target_revision,
            diff_plan: None,
            risk_audit: RiskAuditReport::default(),
            pending_alembic: None,
            dml_revisions: Vec::new(),
            bootstrap_statements,
            effective_target_ir: effective_target,
            warnings,
        });
    }

    let Some(ref current_rev) = drift.current_revision else {
        return Err(CfmsError::SchemaDrift(
            "Database contains application tables without an alembic_version revision; verify state and run `cfms-ctl database stamp <rev>` before upgrading"
                .to_string(),
        ));
    };

    if current_rev == &target_revision && drift.healthy {
        let effective_target = filter_target_ir(target_ir, None, opts.include_extensions);
        return Ok(HybridUpgradePlan {
            dialect: pool.kind(),
            compatibility,
            drift,
            strategy: UpgradeStrategy::AlreadyAtTarget,
            target_revision,
            historical_steps: Vec::new(),
            diff_plan: None,
            risk_audit: RiskAuditReport::default(),
            pending_alembic: None,
            dml_revisions: Vec::new(),
            bootstrap_statements: Vec::new(),
            effective_target_ir: effective_target,
            warnings,
        });
    }

    // Preserve the native upgrade path from CFMS 0.14.0 (`e952c02c1454`) to HEAD (`a66108639ed7`),
    // including root DACL seeding, permission pruning/grants, and legacy table cleanup.
    if is_known_revision(current_rev)
        && current_rev != LATEST_SCHEMA_REVISION
        && target_revision == LATEST_SCHEMA_REVISION
        && target_ir.source == ExtractionSource::BuiltinFallback
    {
        let pending = revisions_after(current_rev)
            .ok_or_else(|| {
                CfmsError::SchemaDrift(format!(
                    "Unable to resolve historical upgrade path from '{current_rev}'"
                ))
            })?
            .iter()
            .map(|r| r.id.to_string())
            .collect();
        let effective_target = filter_target_ir(target_ir, None, opts.include_extensions);
        return Ok(HybridUpgradePlan {
            dialect: pool.kind(),
            compatibility,
            drift,
            strategy: UpgradeStrategy::HistoricalNative,
            target_revision,
            historical_steps: pending,
            diff_plan: None,
            risk_audit: RiskAuditReport::default(),
            pending_alembic: None,
            dml_revisions: Vec::new(),
            bootstrap_statements: Vec::new(),
            effective_target_ir: effective_target,
            warnings,
        });
    }

    let ownership_hints: BTreeMap<String, TableOwnership> = target_ir
        .tables
        .iter()
        .map(|(k, t)| (k.clone(), t.ownership.clone()))
        .collect();
    let live_ir = introspect_live_schema_ir(pool, true, Some(&ownership_hints)).await?;
    let live_table_names: HashSet<String> = live_ir.tables.keys().cloned().collect();
    let effective_target =
        filter_target_ir(target_ir, Some(&live_table_names), opts.include_extensions);
    if target_ir.schema_revision.is_none()
        && let Some(ref single_head) = alembic_analysis.as_ref().and_then(|a| a.single_head.clone())
    {
        target_revision = single_head.clone();
    }

    let historical_steps: Vec<String> = if is_known_revision(current_rev) && current_rev != LATEST_SCHEMA_REVISION {
        revisions_after(current_rev)
            .unwrap_or(&[])
            .iter()
            .map(|r| r.id.to_string())
            .collect()
    } else {
        Vec::new()
    };

    let diff_base = if !historical_steps.is_empty() {
        // Historical native steps will first advance the live DB to `a66108639ed7`.
        let mut base = builtin_schema_ir(true);
        base.schema_revision = Some(LATEST_SCHEMA_REVISION.to_string());
        filter_target_ir(&base, Some(&live_table_names), opts.include_extensions)
    } else {
        live_ir
    };

    let diff_plan = diff_schemas(
        &diff_base,
        &effective_target,
        &DiffOptions {
            dialect: Some(pool.kind()),
            rename: rename_cfg,
            coalesce_sqlite_rebuilds: true,
            include_extensions: true,
            compare_comments: pool.kind() == DatabaseKind::Postgresql,
        },
    );

    let pending_alembic = alembic_analysis
        .as_ref()
        .map(|dag| dag.pending_since(Some(current_rev)));
    let dml_revisions = pending_alembic
        .as_ref()
        .map(|p| p.dml_revisions.clone())
        .unwrap_or_default();

    let mut risk_audit =
        audit_diff_plan(&diff_plan, Some(&effective_target), pending_alembic.as_ref());
    if historical_steps.is_empty() {
        run_live_preflight_checks(pool, &diff_plan, &mut risk_audit).await;
    }

    let should_delegate_alembic = pending_alembic.as_ref().is_some_and(|p| p.has_data_dml)
        && !opts.schema_only
        && !opts.no_alembic_delegate
        && alembic_paths.is_some();

    let strategy = if should_delegate_alembic {
        UpgradeStrategy::DelegateAlembic
    } else if !historical_steps.is_empty() {
        UpgradeStrategy::HistoricalThenHybridDdl
    } else {
        UpgradeStrategy::HybridNativeDdl
    };

    warnings.extend(diff_plan.warnings.clone());

    Ok(HybridUpgradePlan {
        dialect: pool.kind(),
        compatibility,
        drift,
        strategy,
        target_revision,
        historical_steps,
        diff_plan: Some(diff_plan),
        risk_audit,
        pending_alembic,
        dml_revisions,
        bootstrap_statements: Vec::new(),
        effective_target_ir: effective_target,
        warnings,
    })
}

/// Execute a previously planned hybrid upgrade (or preview cleanly when `opts.dry_run` is true).
pub async fn execute_hybrid_upgrade(
    pool: &DbPool,
    paths: Option<&WorkspacePaths>,
    target_ir: &SchemaIr,
    opts: &HybridUpgradeOptions,
) -> Result<HybridUpgradeOutcome> {
    let plan = plan_hybrid_upgrade(pool, paths, target_ir, opts).await?;

    if opts.dry_run {
        let planned_sql_count = match plan.strategy {
            UpgradeStrategy::BootstrapTarget => plan.bootstrap_statements.len(),
            UpgradeStrategy::HybridNativeDdl | UpgradeStrategy::HistoricalThenHybridDdl => plan
                .diff_plan
                .as_ref()
                .map(|p| {
                    p.operations
                        .iter()
                        .map(|op| compile_op_to_sql_statements(op, pool.kind()).len())
                        .sum()
                })
                .unwrap_or(0),
            UpgradeStrategy::AlreadyAtTarget
            | UpgradeStrategy::HistoricalNative
            | UpgradeStrategy::DelegateAlembic => 0,
        };
        return Ok(HybridUpgradeOutcome {
            dialect: plan.dialect,
            strategy: plan.strategy,
            dry_run: true,
            previous_revision: plan.drift.current_revision,
            current_revision: plan.target_revision,
            bootstrapped: false,
            delegated_to_alembic: false,
            applied_revisions: Vec::new(),
            executed_sql_count: planned_sql_count,
            risk_audit: plan.risk_audit,
            dml_scripts: plan.dml_revisions.into_iter().map(|(rev, _)| rev).collect(),
            warnings: plan.warnings,
        });
    }

    match plan.strategy {
        UpgradeStrategy::AlreadyAtTarget => Ok(HybridUpgradeOutcome {
            dialect: plan.dialect,
            strategy: UpgradeStrategy::AlreadyAtTarget,
            dry_run: false,
            previous_revision: plan.drift.current_revision,
            current_revision: plan.target_revision,
            bootstrapped: false,
            delegated_to_alembic: false,
            applied_revisions: Vec::new(),
            executed_sql_count: 0,
            risk_audit: plan.risk_audit,
            dml_scripts: Vec::new(),
            warnings: plan.warnings,
        }),
        UpgradeStrategy::BootstrapTarget => {
            execute_ddl_statements(pool, &plan.bootstrap_statements).await?;
            set_alembic_version(pool, &plan.target_revision).await?;
            Ok(HybridUpgradeOutcome {
                dialect: plan.dialect,
                strategy: UpgradeStrategy::BootstrapTarget,
                dry_run: false,
                previous_revision: None,
                current_revision: plan.target_revision.clone(),
                bootstrapped: true,
                delegated_to_alembic: false,
                applied_revisions: vec![plan.target_revision],
                executed_sql_count: plan.bootstrap_statements.len(),
                risk_audit: plan.risk_audit,
                dml_scripts: Vec::new(),
                warnings: plan.warnings,
            })
        }
        UpgradeStrategy::HistoricalNative => {
            let mut applied = Vec::with_capacity(plan.historical_steps.len());
            for rev in &plan.historical_steps {
                apply_revision_step(pool, rev, &plan.compatibility).await?;
                set_alembic_version(pool, rev).await?;
                applied.push(rev.clone());
            }
            let final_report =
                SchemaInspector::inspect_against_ir(pool, &plan.effective_target_ir).await?;
            if !final_report.healthy {
                return Err(CfmsError::SchemaDrift(format!(
                    "Historical database upgrade reached '{}' but schema inspection still reports drift (missing: {:?}, column_mismatches: {:?})",
                    plan.target_revision, final_report.missing_tables, final_report.column_mismatches
                )));
            }
            Ok(HybridUpgradeOutcome {
                dialect: plan.dialect,
                strategy: UpgradeStrategy::HistoricalNative,
                dry_run: false,
                previous_revision: plan.drift.current_revision,
                current_revision: plan.target_revision,
                bootstrapped: false,
                delegated_to_alembic: false,
                applied_revisions: applied,
                executed_sql_count: 0,
                risk_audit: plan.risk_audit,
                dml_scripts: Vec::new(),
                warnings: plan.warnings,
            })
        }
        UpgradeStrategy::DelegateAlembic => {
            let ws_paths = paths.ok_or_else(|| {
                CfmsError::Config(
                    "Cannot delegate to `alembic upgrade head` without resolved workspace paths"
                        .to_string(),
                )
            })?;
            let alembic_paths = ws_paths.discover_alembic_paths().ok_or_else(|| {
                CfmsError::Config(
                    "Unable to locate workspace alembic.ini and alembic/versions for Alembic delegation"
                        .to_string(),
                )
            })?;
            run_alembic_upgrade_head(ws_paths, &alembic_paths).await?;

            let post_rev = pool
                .current_revision()
                .await?
                .unwrap_or_else(|| plan.target_revision.clone());
            let final_report =
                SchemaInspector::inspect_against_ir(pool, &plan.effective_target_ir).await?;
            let mut warnings = plan.warnings;
            if !final_report.healthy {
                warnings.push(format!(
                    "Post-Alembic schema check reported residual differences (missing: {:?}, column_mismatches: {:?})",
                    final_report.missing_tables, final_report.column_mismatches
                ));
            }
            let applied = plan
                .pending_alembic
                .map(|p| p.pending_revisions)
                .unwrap_or_default();
            Ok(HybridUpgradeOutcome {
                dialect: plan.dialect,
                strategy: UpgradeStrategy::DelegateAlembic,
                dry_run: false,
                previous_revision: plan.drift.current_revision,
                current_revision: post_rev,
                bootstrapped: false,
                delegated_to_alembic: true,
                applied_revisions: applied,
                executed_sql_count: 0,
                risk_audit: plan.risk_audit,
                dml_scripts: plan.dml_revisions.into_iter().map(|(r, _)| r).collect(),
                warnings,
            })
        }
        UpgradeStrategy::HybridNativeDdl | UpgradeStrategy::HistoricalThenHybridDdl => {
            if plan.risk_audit.has_blocking_risks && !opts.allow_destructive {
                let blocking_summaries: Vec<String> = plan
                    .risk_audit
                    .findings
                    .iter()
                    .filter(|f| f.blocking)
                    .map(|f| format!("[{}] {}", f.code, f.summary))
                    .collect();
                return Err(CfmsError::DestructiveMigrationBlocked(format!(
                    "{} blocking migration risk(s) detected: {}. Re-run with `--allow-destructive` or resolve `--rename table.old=new` first",
                    blocking_summaries.len(),
                    blocking_summaries.join("; ")
                )));
            }

            let mut applied = Vec::new();
            if !plan.historical_steps.is_empty() {
                for rev in &plan.historical_steps {
                    apply_revision_step(pool, rev, &plan.compatibility).await?;
                    set_alembic_version(pool, rev).await?;
                    applied.push(rev.clone());
                }
            }

            // Recompute from live DB if historical steps mutated it cleanly; otherwise use planned diff.
            let final_diff = if !plan.historical_steps.is_empty() {
                let rename_cfg = parse_rename_config(&opts.rename_overrides)?;
                let ownership_hints: BTreeMap<String, TableOwnership> = plan
                    .effective_target_ir
                    .tables
                    .iter()
                    .map(|(k, t)| (k.clone(), t.ownership.clone()))
                    .collect();
                let live_ir = introspect_live_schema_ir(pool, true, Some(&ownership_hints)).await?;
                let live_diff = diff_schemas(
                    &live_ir,
                    &plan.effective_target_ir,
                    &DiffOptions {
                        dialect: Some(pool.kind()),
                        rename: rename_cfg,
                        coalesce_sqlite_rebuilds: true,
                        include_extensions: true,
                        compare_comments: pool.kind() == DatabaseKind::Postgresql,
                    },
                );
                let mut post_audit = audit_diff_plan(
                    &live_diff,
                    Some(&plan.effective_target_ir),
                    plan.pending_alembic.as_ref(),
                );
                run_live_preflight_checks(pool, &live_diff, &mut post_audit).await;
                if post_audit.has_blocking_risks && !opts.allow_destructive {
                    let blocking: Vec<String> = post_audit
                        .findings
                        .iter()
                        .filter(|f| f.blocking)
                        .map(|f| format!("[{}] {}", f.code, f.summary))
                        .collect();
                    return Err(CfmsError::DestructiveMigrationBlocked(blocking.join("; ")));
                }
                live_diff
            } else {
                plan.diff_plan.unwrap_or_default()
            };

            let executed_sql_count = execute_diff_plan_sql(pool, &final_diff).await?;
            set_alembic_version(pool, &plan.target_revision).await?;
            if !applied.iter().any(|r| r == &plan.target_revision) {
                applied.push(plan.target_revision.clone());
            }

            let final_report =
                SchemaInspector::inspect_against_ir(pool, &plan.effective_target_ir).await?;
            if !final_report.healthy {
                return Err(CfmsError::SchemaDrift(format!(
                    "Hybrid upgrade reached '{}' but live verification still reports drift (missing: {:?}, column_mismatches: {:?})",
                    plan.target_revision, final_report.missing_tables, final_report.column_mismatches
                )));
            }

            Ok(HybridUpgradeOutcome {
                dialect: plan.dialect,
                strategy: plan.strategy,
                dry_run: false,
                previous_revision: plan.drift.current_revision,
                current_revision: plan.target_revision,
                bootstrapped: false,
                delegated_to_alembic: false,
                applied_revisions: applied,
                executed_sql_count,
                risk_audit: plan.risk_audit,
                dml_scripts: Vec::new(),
                warnings: plan.warnings,
            })
        }
    }
}

async fn execute_diff_plan_sql(pool: &DbPool, plan: &SchemaDiffPlan) -> Result<usize> {
    let kind = pool.kind();
    let mut stmts = Vec::new();
    let mut needs_sqlite_fk_toggle = false;
    for op in &plan.operations {
        if kind == DatabaseKind::Sqlite
            && matches!(
                op,
                SchemaOp::SqliteRebuildTable { .. } | SchemaOp::DropTable { .. }
            )
        {
            needs_sqlite_fk_toggle = true;
        }
        stmts.extend(compile_op_to_sql_statements(op, kind));
    }
    if stmts.is_empty() {
        return Ok(0);
    }
    let count = stmts.len();

    if needs_sqlite_fk_toggle && let DbPool::Sqlite(p) = pool {
        let mut conn = p.acquire().await?;
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await?;

        let tx_res: Result<()> = async {
            sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
            for sql in &stmts {
                if let Err(err) = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                    .execute(&mut *conn)
                    .await
                {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(CfmsError::from(err));
                }
            }
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(())
        }
        .await;

        let _ = sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await;
        tx_res?;

        let violations = sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&mut *conn)
            .await?;
        if !violations.is_empty() {
            return Err(CfmsError::SchemaDrift(format!(
                "SQLite post-migration PRAGMA foreign_key_check detected {} violation(s)",
                violations.len()
            )));
        }
        return Ok(count);
    }

    execute_ddl_statements(pool, &stmts).await?;
    Ok(count)
}

/// Direction and target revision for delegating an Alembic execution to Python.
#[derive(Debug, Clone)]
pub enum AlembicDirection {
    UpgradeHead,
    UpgradeTo(String),
    DowngradeTo(String),
}

impl AlembicDirection {
    fn command_name(&self) -> &'static str {
        match self {
            Self::UpgradeHead | Self::UpgradeTo(_) => "upgrade",
            Self::DowngradeTo(_) => "downgrade",
        }
    }

    fn target_arg(&self) -> &str {
        match self {
            Self::UpgradeHead => "head",
            Self::UpgradeTo(rev) | Self::DowngradeTo(rev) => rev.as_str(),
        }
    }

    fn display_label(&self) -> String {
        format!("alembic {} {}", self.command_name(), self.target_arg())
    }
}

pub async fn run_alembic_upgrade_head(
    paths: &WorkspacePaths,
    alembic_paths: &AlembicPaths,
) -> Result<()> {
    run_alembic_revision(paths, alembic_paths, AlembicDirection::UpgradeHead).await
}

/// Execute `alembic upgrade <rev>` or `alembic downgrade <rev>` using discovered Python environments
/// inside `paths.server_root` without writing `.pyc` files.
pub async fn run_alembic_revision(
    paths: &WorkspacePaths,
    alembic_paths: &AlembicPaths,
    direction: AlembicDirection,
) -> Result<()> {
    let label = direction.display_label();
    let candidates = discover_python_candidates(paths);
    if candidates.is_empty() {
        return Err(CfmsError::Config(format!(
            "Unable to locate a Python interpreter to run `{label}`; install/activate CFMS virtualenv or configure CFMS_PYTHON"
        )));
    }

    const ALEMBIC_RUNNER_PY: &str = r#"
import os, sys, tomllib
cwd = os.environ["CFMS_SERVER_ROOT"]
if cwd not in sys.path:
    sys.path.insert(0, cwd)
from alembic.config import Config
from alembic import command
from include.database.engine import create_database_engine

ini_path = os.environ["CFMS_ALEMBIC_INI"]
alembic_cfg = Config(ini_path) if os.path.isfile(ini_path) else Config()
alembic_cfg.set_main_option("script_location", os.environ["CFMS_SCRIPT_LOCATION"])

with open(os.environ["CFMS_CONFIG_TOML"], "rb") as f:
    cfg_data = tomllib.load(f)

direction = os.environ["CFMS_ALEMBIC_DIRECTION"]
target = os.environ["CFMS_ALEMBIC_TARGET"]
engine = create_database_engine(cfg_data["database"])
try:
    with engine.connect() as conn:
        alembic_cfg.attributes["connection"] = conn
        if direction == "upgrade":
            command.upgrade(alembic_cfg, target)
        elif direction == "downgrade":
            command.downgrade(alembic_cfg, target)
        else:
            raise ValueError(f"Unsupported Alembic direction: {direction}")
finally:
    engine.dispose()
"#;

    let mut errors = Vec::new();
    for candidate in candidates {
        let mut cmd = Command::new(&candidate.program);
        for arg in &candidate.prefix_args {
            cmd.arg(arg);
        }
        cmd.arg("-B")
            .arg("-c")
            .arg(ALEMBIC_RUNNER_PY)
            .current_dir(&paths.server_root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONUTF8", "1")
            .env("CFMS_SERVER_ROOT", &paths.server_root)
            .env("CFMS_ALEMBIC_INI", &alembic_paths.ini_path)
            .env("CFMS_SCRIPT_LOCATION", &alembic_paths.script_location)
            .env("CFMS_CONFIG_TOML", &paths.config_path)
            .env("CFMS_ALEMBIC_DIRECTION", direction.command_name())
            .env("CFMS_ALEMBIC_TARGET", direction.target_arg())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("{}: spawn failed: {e}", candidate.description));
                continue;
            }
        };

        let output = match tokio::time::timeout(Duration::from_secs(120), child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                errors.push(format!("{}: wait failed: {e}", candidate.description));
                continue;
            }
            Err(_) => {
                return Err(CfmsError::Database(format!(
                    "Timed out after 120s while executing `{label}`"
                )));
            }
        };

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        errors.push(format!(
            "{} exited with {}: {}{}",
            candidate.description,
            output.status,
            stderr,
            if stdout.is_empty() {
                String::new()
            } else {
                format!(" | stdout: {stdout}")
            }
        ));
    }

    Err(CfmsError::Database(format!(
        "`{label}` failed across all Python candidates: {}",
        errors.join("; ")
    )))
}

/// Execute the native `e952c02c1454` -> `a66108639ed7` CEP-0002 CACL migration step.
pub(crate) async fn apply_cacl_migration_step(pool: &DbPool) -> Result<()> {
    step_a66108639ed7(pool).await
}

async fn apply_revision_step(
    pool: &DbPool,
    revision: &str,
    _compat: &ServerCompatibility,
) -> Result<()> {
    match revision {
        "a66108639ed7" => step_a66108639ed7(pool).await,
        other => Err(CfmsError::SchemaDrift(format!(
            "Unsupported migration revision step '{other}'"
        ))),
    }
}

// ============================================================================
// Shared Low-Level Helpers
// ============================================================================

fn now_unix_seconds() -> f64 {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_secs_f64()
}

async fn has_column(pool: &DbPool, table: &str, col: &str) -> Result<bool> {
    Ok(pool.list_table_columns(table).await?.iter().any(|c| c == col))
}

async fn has_table(pool: &DbPool, table: &str) -> Result<bool> {
    Ok(pool.list_tables().await?.iter().any(|t| t == table))
}

async fn has_index(pool: &DbPool, table: &str, index_name: &str) -> Result<bool> {
    let found = match pool {
        DbPool::Sqlite(p) => {
            let escaped = table.replace('\'', "''");
            let sql = format!("PRAGMA index_list('{escaped}')");
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?;
            rows.into_iter()
                .any(|r| r.get::<String, _>("name") == index_name)
        }
        DbPool::Mysql(p) => {
            let cnt: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?",
            )
            .bind(table)
            .bind(index_name)
            .fetch_one(p)
            .await?;
            cnt > 0
        }
        DbPool::Postgres(p) => {
            let cnt: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public' AND tablename = $1 AND indexname = $2",
            )
            .bind(table)
            .bind(index_name)
            .fetch_one(p)
            .await?;
            cnt > 0
        }
    };
    Ok(found)
}

async fn has_mysql_fk(pool: &DbPool, table: &str, fk_name: &str) -> Result<bool> {
    let DbPool::Mysql(p) = pool else {
        return Ok(false);
    };
    let cnt: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.table_constraints \
         WHERE constraint_schema = DATABASE() AND table_name = ? AND constraint_name = ? AND constraint_type = 'FOREIGN KEY'",
    )
    .bind(table)
    .bind(fk_name)
    .fetch_one(p)
    .await?;
    Ok(cnt > 0)
}

/// Safely rebuild a SQLite table using the 12-step copy-and-swap pattern with `PRAGMA foreign_keys = OFF`
/// set outside the transaction and `PRAGMA foreign_key_check` verified afterward.
async fn sqlite_rebuild_table(
    pool: &DbPool,
    table_name: &str,
    new_table_sql_with_temp_name: &str,
    copy_insert_sql: &str,
    recreate_index_sqls: &[String],
) -> Result<()> {
    let DbPool::Sqlite(p) = pool else {
        return Err(CfmsError::Database(
            "sqlite_rebuild_table called on non-SQLite backend".to_string(),
        ));
    };

    let tmp_name = format!("_cfms_rebuild_{table_name}");
    let mut conn = p.acquire().await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;

    let rebuild_result: Result<()> = async {
        let mut tx = conn.begin().await?;
        let drop_tmp = format!("DROP TABLE IF EXISTS {tmp_name}");
        sqlx::query(sqlx::AssertSqlSafe(drop_tmp))
            .execute(&mut *tx)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(new_table_sql_with_temp_name))
            .execute(&mut *tx)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(copy_insert_sql))
            .execute(&mut *tx)
            .await?;
        let drop_old = format!("DROP TABLE {table_name}");
        sqlx::query(sqlx::AssertSqlSafe(drop_old))
            .execute(&mut *tx)
            .await?;
        let rename_sql = format!("ALTER TABLE {tmp_name} RENAME TO {table_name}");
        sqlx::query(sqlx::AssertSqlSafe(rename_sql))
            .execute(&mut *tx)
            .await?;
        for idx_sql in recreate_index_sqls {
            sqlx::query(sqlx::AssertSqlSafe(idx_sql.as_str()))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    .await;

    let fk_restore = sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await;
    rebuild_result?;
    fk_restore?;

    let fk_check_sql = format!("PRAGMA foreign_key_check(\"{table_name}\")");
    let fk_errors = sqlx::query(sqlx::AssertSqlSafe(fk_check_sql))
        .fetch_all(&mut *conn)
        .await?;
    if !fk_errors.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "SQLite foreign_key_check failed after rebuilding '{table_name}'"
        )));
    }
    Ok(())
}

async fn grant_sysop_permissions(
    pool: &DbPool,
    owner_tag: Option<&str>,
    permissions: &[&str],
) -> Result<()> {
    let sysop_count: i64 = match pool {
        DbPool::Sqlite(p) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM user_groups WHERE group_name = ?")
                .bind("sysop")
                .fetch_one(p)
                .await?
        }
        DbPool::Mysql(p) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM user_groups WHERE group_name = ?")
                .bind("sysop")
                .fetch_one(p)
                .await?
        }
        DbPool::Postgres(p) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM user_groups WHERE group_name = $1")
                .bind("sysop")
                .fetch_one(p)
                .await?
        }
    };
    if sysop_count == 0 {
        return Ok(());
    }

    for &perm in permissions {
        let already_granted: i64 = match pool {
            DbPool::Sqlite(p) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM group_permissions WHERE group_name = ? AND permission = ? AND granted = 1 AND end_time IS NULL",
                )
                .bind("sysop")
                .bind(perm)
                .fetch_one(p)
                .await?
            }
            DbPool::Mysql(p) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM group_permissions WHERE group_name = ? AND permission = ? AND granted = true AND end_time IS NULL",
                )
                .bind("sysop")
                .bind(perm)
                .fetch_one(p)
                .await?
            }
            DbPool::Postgres(p) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM group_permissions WHERE group_name = $1 AND permission = $2 AND granted = true AND end_time IS NULL",
                )
                .bind("sysop")
                .bind(perm)
                .fetch_one(p)
                .await?
            }
        };
        if already_granted > 0 {
            continue;
        }

        let inserted_id: i64 = match pool {
            DbPool::Sqlite(p) => {
                let res = sqlx::query(
                    "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES (?, ?, 1, 0.0, NULL)",
                )
                .bind("sysop")
                .bind(perm)
                .execute(p)
                .await?;
                res.last_insert_rowid()
            }
            DbPool::Mysql(p) => {
                let res = sqlx::query(
                    "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES (?, ?, true, 0.0, NULL)",
                )
                .bind("sysop")
                .bind(perm)
                .execute(p)
                .await?;
                i64::try_from(res.last_insert_id()).unwrap_or(0)
            }
            DbPool::Postgres(p) => {
                let id: i32 = sqlx::query_scalar(
                    "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES ($1, $2, true, 0.0, NULL) RETURNING id",
                )
                .bind("sysop")
                .bind(perm)
                .fetch_one(p)
                .await?;
                i64::from(id)
            }
        };

        if let Some(owner) = owner_tag {
            let payload = serde_json::json!({ "group_permission_id": inserted_id });
            let now = now_unix_seconds();
            match pool {
                DbPool::Sqlite(p) => {
                    sqlx::query(
                        "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES (?, ?, 2, 1, ?, ?)",
                    )
                    .bind(owner)
                    .bind(perm)
                    .bind(payload.to_string())
                    .bind(now)
                    .execute(p)
                    .await?;
                }
                DbPool::Mysql(p) => {
                    sqlx::query(
                        "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES (?, ?, 2, 1, ?, ?)",
                    )
                    .bind(owner)
                    .bind(perm)
                    .bind(&payload)
                    .bind(now)
                    .execute(p)
                    .await?;
                }
                DbPool::Postgres(p) => {
                    sqlx::query(
                        "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES ($1, $2, 2, 1, $3, $4)",
                    )
                    .bind(owner)
                    .bind(perm)
                    .bind(&payload)
                    .bind(now)
                    .execute(p)
                    .await?;
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Forward Step Transition: e952c02c1454 (0.14.0) -> a66108639ed7 (CEP-0002 CACL)
// ============================================================================

async fn step_a66108639ed7(pool: &DbPool) -> Result<()> {
    const LEGACY_DROP_ORDER: &[&str] = &[
        "compiled_access_rule_rights",
        "compiled_access_rule_memberships",
        "compiled_access_rule_groups",
        "compiled_access_rules",
        "compiled_access_rule_sets",
        "userblock_sub_entries",
        "userblock_entries",
        "object_access_entries",
    ];
    const REMOVED_PERMISSIONS: &[&str] = &[
        "move",
        "create_document",
        "delete_document",
        "rename_document",
        "create_directory",
        "delete_directory",
        "rename_directory",
        "list_deleted_items",
        "restore",
        "super_create_document",
        "super_create_directory",
        "super_list_directory",
        "view_access_rules",
        "set_access_rules",
        "view_metadata",
        "set_metadata_tags",
        "manage_access",
        "view_access_entries",
        "block",
        "unblock",
        "list_user_blocks",
        "list_revisions",
        "view_revision",
        "set_current_revision",
    ];

    let kind = pool.kind();

    // 1. Detach and drop `nodes.access_rule_set_id` before dropping `compiled_access_rule_sets`.
    if has_table(pool, "nodes").await? && has_column(pool, "nodes", "access_rule_set_id").await? {
        execute_ddl_statements(
            pool,
            &["UPDATE nodes SET access_rule_set_id = NULL".to_string()],
        )
        .await?;
        if has_table(pool, "compiled_access_rule_sets").await? {
            execute_ddl_statements(
                pool,
                &["DELETE FROM compiled_access_rule_sets".to_string()],
            )
            .await?;
        }

        match kind {
            DatabaseKind::Sqlite => {
                let def = table_def("nodes").expect("nodes def");
                let create_tmp = def
                    .compile_create_table(DatabaseKind::Sqlite)
                    .replacen("CREATE TABLE nodes", "CREATE TABLE _cfms_rebuild_nodes", 1);
                let copy_sql = "INSERT INTO _cfms_rebuild_nodes (id, type, name, parent_id, inherit, status, status_operation_id) \
                    SELECT id, type, name, parent_id, inherit, status, status_operation_id FROM nodes";
                let indexes = def.compile_create_indexes(DatabaseKind::Sqlite);
                sqlite_rebuild_table(pool, "nodes", &create_tmp, copy_sql, &indexes).await?;
            }
            DatabaseKind::Mysql => {
                let mut clauses = Vec::new();
                if has_mysql_fk(
                    pool,
                    "nodes",
                    "fk_nodes_access_rule_set_id_compiled_access_rule_sets",
                )
                .await?
                {
                    clauses.push(
                        "DROP FOREIGN KEY fk_nodes_access_rule_set_id_compiled_access_rule_sets"
                            .to_string(),
                    );
                }
                if has_index(pool, "nodes", "ix_nodes_access_rule_set_id").await? {
                    clauses.push("DROP INDEX ix_nodes_access_rule_set_id".to_string());
                }
                clauses.push("DROP COLUMN access_rule_set_id".to_string());
                execute_ddl_statements(
                    pool,
                    &[format!("ALTER TABLE nodes {}", clauses.join(", "))],
                )
                .await?;
            }
            DatabaseKind::Postgresql => {
                execute_ddl_statements(
                    pool,
                    &[
                        "ALTER TABLE nodes DROP CONSTRAINT IF EXISTS fk_nodes_access_rule_set_id_compiled_access_rule_sets".to_string(),
                        "DROP INDEX IF EXISTS ix_nodes_access_rule_set_id".to_string(),
                        "ALTER TABLE nodes DROP COLUMN access_rule_set_id".to_string(),
                    ],
                )
                .await?;
            }
        }
    }

    // 2. Create CEP-0002 DACL tables in parent -> child order.
    let mut create_stmts = Vec::new();
    for tbl_name in ["dacl_rules", "dacl_rule_clauses", "dacl_rule_atoms"] {
        if !has_table(pool, tbl_name).await? {
            let def = table_def(tbl_name).expect("cacl table def");
            create_stmts.push(def.compile_create_table(kind));
            create_stmts.extend(def.compile_create_indexes(kind));
        }
    }
    if !create_stmts.is_empty() {
        execute_ddl_statements(pool, &create_stmts).await?;
    }

    // 3. Drop legacy access-rule and userblock tables in child -> parent order.
    let mut drop_stmts = Vec::new();
    for legacy_tbl in LEGACY_DROP_ORDER {
        if has_table(pool, legacy_tbl).await? {
            drop_stmts.push(format!("DROP TABLE IF EXISTS {legacy_tbl}"));
        }
    }
    if !drop_stmts.is_empty() {
        execute_ddl_statements(pool, &drop_stmts).await?;
    }

    // 4. Seed default root `/` DACL rules when root node exists and has no DACL rules yet.
    seed_default_root_dacl(pool).await?;

    // 5. Remove obsolete recursive-check option row if `options` exists.
    if has_table(pool, "options").await? {
        let del_opt_sql = "DELETE FROM options WHERE namespace = 'access' AND option_key = 'enable_access_recursive_check'";
        execute_ddl_statements(pool, &[del_opt_sql.to_string()]).await?;
    }

    // 6. Prune the 24 removed core permissions from `group_permissions` and `user_permissions`.
    let quoted_perms: Vec<String> = REMOVED_PERMISSIONS.iter().map(|p| format!("'{p}'")).collect();
    let in_clause = quoted_perms.join(", ");
    for perm_tbl in ["group_permissions", "user_permissions"] {
        if has_table(pool, perm_tbl).await? {
            let sql = format!("DELETE FROM {perm_tbl} WHERE permission IN ({in_clause})");
            execute_ddl_statements(pool, &[sql]).await?;
        }
    }

    // 7. Grant new CEP-0002 capabilities to `sysop` with migration ownership markers.
    if has_table(pool, "user_groups").await?
        && has_table(pool, "group_permissions").await?
        && has_table(pool, "system_states").await?
    {
        grant_sysop_permissions(
            pool,
            Some("migration:a66108639ed7"),
            &["bypass_dacl", "bypass_traverse_checking"],
        )
        .await?;
    }

    Ok(())
}

async fn seed_default_root_dacl(pool: &DbPool) -> Result<()> {
    const PRESET_READ_MASK: i64 = 1043; // TRAVERSE | LIST_DIRECTORY | READ_CONTENT | READ_METADATA
    const DEFAULT_SYSOP_ALL_OPS_MASK: i64 = 2_097_151; // All 21 CEP-0002 v1 AtomicOps (bits 0..20)

    if !has_table(pool, "nodes").await? || !has_table(pool, "dacl_rules").await? {
        return Ok(());
    }

    let root_count: i64 = match pool {
        DbPool::Sqlite(p) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE id = '/'")
                .fetch_one(p)
                .await?
        }
        DbPool::Mysql(p) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE id = '/'")
                .fetch_one(p)
                .await?
        }
        DbPool::Postgres(p) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE id = '/'")
                .fetch_one(p)
                .await?
        }
    };
    if root_count == 0 {
        return Ok(());
    }

    let existing_rules: i64 = match pool {
        DbPool::Sqlite(p) => {
            sqlx::query("UPDATE nodes SET inherit = 0 WHERE id = '/'")
                .execute(p)
                .await?;
            sqlx::query_scalar("SELECT COUNT(*) FROM dacl_rules WHERE node_id = '/'")
                .fetch_one(p)
                .await?
        }
        DbPool::Mysql(p) => {
            sqlx::query("UPDATE nodes SET inherit = false WHERE id = '/'")
                .execute(p)
                .await?;
            sqlx::query_scalar("SELECT COUNT(*) FROM dacl_rules WHERE node_id = '/'")
                .fetch_one(p)
                .await?
        }
        DbPool::Postgres(p) => {
            sqlx::query("UPDATE nodes SET inherit = false WHERE id = '/'")
                .execute(p)
                .await?;
            sqlx::query_scalar("SELECT COUNT(*) FROM dacl_rules WHERE node_id = '/'")
                .fetch_one(p)
                .await?
        }
    };
    if existing_rules > 0 {
        return Ok(());
    }

    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            let read_rule_id = sqlx::query(
                "INSERT INTO dacl_rules (node_id, effect, permission_mask, scope, valid_from, valid_until, remark) \
                 VALUES ('/', 'allow', ?, 'all', NULL, NULL, 'Default read access for authenticated users')",
            )
            .bind(PRESET_READ_MASK)
            .execute(&mut *tx)
            .await?
            .last_insert_rowid();
            sqlx::query("INSERT INTO dacl_rule_clauses (rule_id) VALUES (?)")
                .bind(read_rule_id)
                .execute(&mut *tx)
                .await?;

            let admin_rule_id = sqlx::query(
                "INSERT INTO dacl_rules (node_id, effect, permission_mask, scope, valid_from, valid_until, remark) \
                 VALUES ('/', 'allow', ?, 'all', NULL, NULL, 'Default administrator full access')",
            )
            .bind(DEFAULT_SYSOP_ALL_OPS_MASK)
            .execute(&mut *tx)
            .await?
            .last_insert_rowid();
            let admin_clause_id = sqlx::query("INSERT INTO dacl_rule_clauses (rule_id) VALUES (?)")
                .bind(admin_rule_id)
                .execute(&mut *tx)
                .await?
                .last_insert_rowid();
            sqlx::query(
                "INSERT INTO dacl_rule_atoms (clause_id, predicate_kind, predicate_value, is_negated) VALUES (?, 'group', 'sysop', 0)",
            )
            .bind(admin_clause_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
        DbPool::Mysql(p) => {
            let mut tx = p.begin().await?;
            let read_rule_id = i64::try_from(
                sqlx::query(
                    "INSERT INTO dacl_rules (node_id, effect, permission_mask, scope, valid_from, valid_until, remark) \
                     VALUES ('/', 'allow', ?, 'all', NULL, NULL, 'Default read access for authenticated users')",
                )
                .bind(PRESET_READ_MASK)
                .execute(&mut *tx)
                .await?
                .last_insert_id(),
            )
            .map_err(|_| CfmsError::Database("dacl_rules.id overflowed i64".to_string()))?;
            sqlx::query("INSERT INTO dacl_rule_clauses (rule_id) VALUES (?)")
                .bind(read_rule_id)
                .execute(&mut *tx)
                .await?;

            let admin_rule_id = i64::try_from(
                sqlx::query(
                    "INSERT INTO dacl_rules (node_id, effect, permission_mask, scope, valid_from, valid_until, remark) \
                     VALUES ('/', 'allow', ?, 'all', NULL, NULL, 'Default administrator full access')",
                )
                .bind(DEFAULT_SYSOP_ALL_OPS_MASK)
                .execute(&mut *tx)
                .await?
                .last_insert_id(),
            )
            .map_err(|_| CfmsError::Database("dacl_rules.id overflowed i64".to_string()))?;
            let admin_clause_id = i64::try_from(
                sqlx::query("INSERT INTO dacl_rule_clauses (rule_id) VALUES (?)")
                    .bind(admin_rule_id)
                    .execute(&mut *tx)
                    .await?
                    .last_insert_id(),
            )
            .map_err(|_| CfmsError::Database("dacl_rule_clauses.id overflowed i64".to_string()))?;
            sqlx::query(
                "INSERT INTO dacl_rule_atoms (clause_id, predicate_kind, predicate_value, is_negated) VALUES (?, 'group', 'sysop', false)",
            )
            .bind(admin_clause_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            let read_rule_id: i64 = sqlx::query_scalar(
                "INSERT INTO dacl_rules (node_id, effect, permission_mask, scope, valid_from, valid_until, remark) \
                 VALUES ('/', 'allow', $1, 'all', NULL, NULL, 'Default read access for authenticated users') RETURNING id",
            )
            .bind(PRESET_READ_MASK)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO dacl_rule_clauses (rule_id) VALUES ($1)")
                .bind(read_rule_id)
                .execute(&mut *tx)
                .await?;

            let admin_rule_id: i64 = sqlx::query_scalar(
                "INSERT INTO dacl_rules (node_id, effect, permission_mask, scope, valid_from, valid_until, remark) \
                 VALUES ('/', 'allow', $1, 'all', NULL, NULL, 'Default administrator full access') RETURNING id",
            )
            .bind(DEFAULT_SYSOP_ALL_OPS_MASK)
            .fetch_one(&mut *tx)
            .await?;
            let admin_clause_id: i64 = sqlx::query_scalar(
                "INSERT INTO dacl_rule_clauses (rule_id) VALUES ($1) RETURNING id",
            )
            .bind(admin_rule_id)
            .fetch_one(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO dacl_rule_atoms (clause_id, predicate_kind, predicate_value, is_negated) VALUES ($1, 'group', 'sysop', false)",
            )
            .bind(admin_clause_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::registry::ROOT_SCHEMA_REVISION;
    use sqlx::sqlite::SqlitePoolOptions;
    use tempfile::tempdir;

    async fn open_sqlite_test_pool(path: &std::path::Path) -> DbPool {
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect sqlite test pool");
        DbPool::Sqlite(pool)
    }

    #[tokio::test]
    async fn empty_database_bootstraps_to_head_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let pool = open_sqlite_test_pool(&dir.path().join("empty.db")).await;

        let (_, _, pending) = inspect_upgrade_plan(&pool).await.unwrap();
        assert_eq!(pending, vec![LATEST_SCHEMA_REVISION.to_string()]);

        let first = upgrade_database_schema(&pool).await.unwrap();
        assert!(first.bootstrapped);
        assert!(first.previous_revision.is_none());
        assert_eq!(first.current_revision, LATEST_SCHEMA_REVISION);

        let inspector = SchemaInspector::inspect(&pool).await.unwrap();
        assert!(inspector.healthy);
        assert_eq!(inspector.present_core_tables, 35);

        let second = upgrade_database_schema(&pool).await.unwrap();
        assert!(!second.bootstrapped);
        assert!(second.applied_revisions.is_empty());
        assert_eq!(
            second.previous_revision.as_deref(),
            Some(LATEST_SCHEMA_REVISION)
        );
    }

    #[tokio::test]
    async fn unversioned_non_empty_and_unknown_revisions_are_rejected() {
        let dir = tempdir().unwrap();
        let unversioned = open_sqlite_test_pool(&dir.path().join("unversioned.db")).await;
        create_head_schema(&unversioned, false).await.unwrap();
        let err = upgrade_database_schema(&unversioned)
            .await
            .expect_err("unversioned non-empty DB must be rejected");
        assert!(err.to_string().contains("without an alembic_version"));

        let unknown = open_sqlite_test_pool(&dir.path().join("unknown.db")).await;
        create_head_schema(&unknown, false).await.unwrap();
        set_alembic_version(&unknown, "deadbeef1234").await.unwrap();
        let err = upgrade_database_schema(&unknown)
            .await
            .expect_err("unknown revision must be rejected");
        assert!(err.to_string().contains("not supported"));
    }

    #[tokio::test]
    async fn upgrade_from_0_14_0_e952c02c1454_to_a66108639ed7_migrates_cacl_dacl_and_preserves_data() {
        let dir = tempdir().unwrap();
        let pool = open_sqlite_test_pool(&dir.path().join("v014.db")).await;
        let DbPool::Sqlite(p) = &pool else {
            unreachable!();
        };

        // Construct CFMS 0.14.0 (`e952c02c1454`) 40-table SQLite schema.
        let mut stmts: Vec<String> = Vec::new();
        for name in [
            "files",
            "comments",
            "users",
            "user_passwords",
            "user_totp_credentials",
            "user_auth_public_keys",
            "user_auth_policies",
            "user_groups",
            "group_permissions",
            "user_memberships",
            "user_permissions",
            "keyrings",
        ] {
            let def = table_def(name).unwrap();
            stmts.push(def.compile_create_table(DatabaseKind::Sqlite));
            stmts.extend(def.compile_create_indexes(DatabaseKind::Sqlite));
        }

        // Legacy 0.14.0 `nodes` with `access_rule_set_id` + index.
        stmts.push(
            "CREATE TABLE nodes (\n\
                id VARCHAR(255) NOT NULL,\n\
                type VARCHAR(16) NOT NULL,\n\
                name VARCHAR(255) NOT NULL,\n\
                parent_id VARCHAR(255),\n\
                active_name VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN status = 1 THEN NULL ELSE name END) STORED,\n\
                inherit BOOLEAN NOT NULL,\n\
                status INTEGER NOT NULL,\n\
                status_operation_id VARCHAR(255),\n\
                access_rule_set_id VARCHAR(32),\n\
                CONSTRAINT pk_nodes PRIMARY KEY (id),\n\
                CONSTRAINT ck_nodes_root_parent CHECK (id = '/' AND parent_id IS NULL AND type = 'directory' OR id != '/' AND parent_id IS NOT NULL),\n\
                CONSTRAINT uq_nodes_active_parent_name UNIQUE (parent_id, active_name),\n\
                CONSTRAINT fk_nodes_parent_id_folders FOREIGN KEY(parent_id) REFERENCES folders (id) ON DELETE CASCADE,\n\
                CONSTRAINT fk_nodes_access_rule_set_id_compiled_access_rule_sets FOREIGN KEY(access_rule_set_id) REFERENCES compiled_access_rule_sets (id)\n\
            )"
            .to_string(),
        );
        stmts.push("CREATE INDEX ix_nodes_access_rule_set_id ON nodes (access_rule_set_id)".to_string());
        stmts.extend(
            table_def("nodes")
                .unwrap()
                .compile_create_indexes(DatabaseKind::Sqlite),
        );

        for name in [
            "folders",
            "documents",
            "document_revisions",
            "document_metadata",
            "document_metadata_tags",
        ] {
            let def = table_def(name).unwrap();
            stmts.push(def.compile_create_table(DatabaseKind::Sqlite));
            stmts.extend(def.compile_create_indexes(DatabaseKind::Sqlite));
        }

        // Legacy access & userblock tables dropped in `a66108639ed7`.
        stmts.extend([
            "CREATE TABLE object_access_entries (\n\
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n\
                entity_type VARCHAR(16) NOT NULL,\n\
                entity_identifier VARCHAR(255) NOT NULL,\n\
                target_type VARCHAR(16) NOT NULL,\n\
                target_identifier VARCHAR(255) NOT NULL,\n\
                access_type VARCHAR(16) NOT NULL,\n\
                start_time DOUBLE NOT NULL,\n\
                end_time DOUBLE\n\
            )"
            .to_string(),
            "CREATE TABLE compiled_access_rule_sets (\n\
                id VARCHAR(32) NOT NULL,\n\
                node_id VARCHAR(255) NOT NULL,\n\
                created_at DOUBLE NOT NULL,\n\
                CONSTRAINT pk_compiled_access_rule_sets PRIMARY KEY (id),\n\
                CONSTRAINT fk_compiled_access_rule_sets_node_id_nodes FOREIGN KEY(node_id) REFERENCES nodes (id) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE compiled_access_rules (\n\
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n\
                rule_set_id VARCHAR(32) NOT NULL,\n\
                access_type VARCHAR(64) NOT NULL,\n\
                match_mode VARCHAR(8) NOT NULL,\n\
                CONSTRAINT fk_compiled_access_rules_rule_set_id_compiled_access_rule_sets FOREIGN KEY(rule_set_id) REFERENCES compiled_access_rule_sets (id) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE compiled_access_rule_groups (\n\
                id VARCHAR(32) NOT NULL,\n\
                rule_id INTEGER NOT NULL,\n\
                group_index INTEGER NOT NULL,\n\
                match_mode VARCHAR(8) NOT NULL,\n\
                rights_match_mode VARCHAR(8) NOT NULL,\n\
                rights_empty BOOLEAN NOT NULL,\n\
                groups_match_mode VARCHAR(8) NOT NULL,\n\
                groups_empty BOOLEAN NOT NULL,\n\
                CONSTRAINT pk_compiled_access_rule_groups PRIMARY KEY (id),\n\
                CONSTRAINT fk_compiled_access_rule_groups_rule_id_compiled_access_rules FOREIGN KEY(rule_id) REFERENCES compiled_access_rules (id) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE compiled_access_rule_memberships (\n\
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n\
                group_id VARCHAR(32) NOT NULL,\n\
                group_name VARCHAR(255) NOT NULL,\n\
                CONSTRAINT fk_compiled_access_rule_memberships_group_id_compiled_access_rule_groups FOREIGN KEY(group_id) REFERENCES compiled_access_rule_groups (id) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE compiled_access_rule_rights (\n\
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n\
                group_id VARCHAR(32) NOT NULL,\n\
                permission VARCHAR(64) NOT NULL,\n\
                CONSTRAINT fk_compiled_access_rule_rights_group_id_compiled_access_rule_groups FOREIGN KEY(group_id) REFERENCES compiled_access_rule_groups (id) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE userblock_entries (\n\
                block_id VARCHAR(32) NOT NULL,\n\
                user_id CHAR(32) NOT NULL,\n\
                timestamp DOUBLE NOT NULL,\n\
                not_before DOUBLE NOT NULL,\n\
                not_after DOUBLE NOT NULL,\n\
                target_type VARCHAR(32) NOT NULL,\n\
                target_id VARCHAR(255),\n\
                reason_comment_id INTEGER,\n\
                CONSTRAINT pk_userblock_entries PRIMARY KEY (block_id),\n\
                CONSTRAINT fk_userblock_entries_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,\n\
                CONSTRAINT fk_userblock_entries_reason_comment_id_comments FOREIGN KEY(reason_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL\n\
            )"
            .to_string(),
            "CREATE TABLE userblock_sub_entries (\n\
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n\
                parent_id VARCHAR(32) NOT NULL,\n\
                block_type VARCHAR(64) NOT NULL,\n\
                CONSTRAINT fk_userblock_sub_entries_parent_id_userblock_entries FOREIGN KEY(parent_id) REFERENCES userblock_entries (block_id) ON DELETE CASCADE\n\
            )"
            .to_string(),
        ]);

        for name in [
            "audit_entries",
            "banned_subnets",
            "account_throttles",
            "file_tasks",
            "login_throttles",
            "rate_limit_buckets",
            "risk_ip_accounts",
            "system_states",
            "options",
            "traffic_throttles",
            "file_deduplication_tasks",
            "schedules",
            "schedule_executions",
            "scheduling_runtime_state",
        ] {
            let def = table_def(name).unwrap();
            stmts.push(def.compile_create_table(DatabaseKind::Sqlite));
            stmts.extend(def.compile_create_indexes(DatabaseKind::Sqlite));
        }

        execute_ddl_statements(&pool, &stmts).await.unwrap();
        set_alembic_version(&pool, ROOT_SCHEMA_REVISION).await.unwrap();

        // Seed 0.14.0 data including tree nodes, compiled rules, userblocks, options, and permissions.
        sqlx::query("INSERT INTO user_groups (group_name, group_display_name) VALUES ('sysop', 'Sysop Admins')")
            .execute(p)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, nickname, created_time, status, secret_key) \
             VALUES ('019481f23c1b70008000000000000001', 'alice', 'Alice', 1.0, 0, 'secret-key-64-chars-placeholder-00000000000000000000000000000001')",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query("INSERT INTO files (id, path, size, sha256, active, created_time) VALUES ('f-1', 'blobs/1', 12, 'abcd', 1, 1.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO nodes (id, type, name, parent_id, inherit, status) VALUES ('/', 'directory', '/', NULL, 1, 0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO folders (id, created_time) VALUES ('/', 1.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO nodes (id, type, name, parent_id, inherit, status) VALUES ('/doc', 'document', 'doc', '/', 1, 0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO documents (id, created_time, current_revision_id) VALUES ('/doc', 2.0, NULL)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO document_revisions (id, document_id, file_id, created_time, status) VALUES ('rev-1', '/doc', 'f-1', 2.0, 0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("UPDATE documents SET current_revision_id = 'rev-1' WHERE id = '/doc'")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO compiled_access_rule_sets (id, node_id, created_at) VALUES ('ars-1', '/', 1.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("UPDATE nodes SET access_rule_set_id = 'ars-1' WHERE id = '/'")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO userblock_entries (block_id, user_id, timestamp, not_before, not_after, target_type) VALUES ('blk-1', '019481f23c1b70008000000000000001', 1.0, 1.0, 9.0, 'login')")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('access', 'builtin', 'enable_access_recursive_check', 1, 1, 'bool', 'true', 1.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('server', 'builtin', 'name', 1, 1, 'str', '\"CFMS\"', 1.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO group_permissions (group_name, permission, granted, start_time) VALUES ('sysop', 'manage_access', 1, 0.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO group_permissions (group_name, permission, granted, start_time) VALUES ('sysop', 'view_settings', 1, 0.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_permissions (user_id, permission, granted, start_time) VALUES ('019481f23c1b70008000000000000001', 'create_document', 1, 0.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_permissions (user_id, permission, granted, start_time) VALUES ('019481f23c1b70008000000000000001', 'search', 1, 0.0)")
            .execute(p)
            .await
            .unwrap();

        let outcome = upgrade_database_schema(&pool)
            .await
            .expect("upgrade from 0.14.0 e952c02c1454 to a66108639ed7");
        assert!(!outcome.bootstrapped);
        assert_eq!(outcome.previous_revision.as_deref(), Some("e952c02c1454"));
        assert_eq!(outcome.current_revision, LATEST_SCHEMA_REVISION);
        assert_eq!(outcome.applied_revisions, vec!["a66108639ed7".to_string()]);

        let inspector = SchemaInspector::inspect(&pool).await.unwrap();
        assert!(
            inspector.healthy,
            "inspector drift: missing={:?}, extra={:?}, cols={:?}, constraints={:?}, idx={:?}",
            inspector.missing_tables,
            inspector.extra_tables,
            inspector.column_mismatches,
            inspector.constraint_mismatches,
            inspector.index_mismatches
        );
        assert_eq!(inspector.present_core_tables, 35);

        // Node hierarchy & documents survived SQLite table rebuild without FK cascade wipe.
        let doc_rev: String =
            sqlx::query_scalar("SELECT current_revision_id FROM documents WHERE id = '/doc'")
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(doc_rev, "rev-1");

        // Root `/` inherit cleared and default DACL seeded cleanly.
        let root_inherit: i64 = sqlx::query_scalar("SELECT inherit FROM nodes WHERE id = '/'")
            .fetch_one(p)
            .await
            .unwrap();
        assert_eq!(root_inherit, 0);

        let rules: Vec<(i64, String, i64, String)> = sqlx::query_as(
            "SELECT id, effect, permission_mask, scope FROM dacl_rules WHERE node_id = '/' ORDER BY id",
        )
        .fetch_all(p)
        .await
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].1, "allow");
        assert_eq!(rules[0].2, 1043);
        assert_eq!(rules[0].3, "all");
        assert_eq!(rules[1].2, 2_097_151);

        let atom: (String, String, i64) = sqlx::query_as(
            "SELECT predicate_kind, predicate_value, is_negated FROM dacl_rule_atoms",
        )
        .fetch_one(p)
        .await
        .unwrap();
        assert_eq!(atom, ("group".to_string(), "sysop".to_string(), 0));

        // Obsolete option removed, valid option preserved.
        let opt_cnt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM options WHERE namespace = 'access' AND option_key = 'enable_access_recursive_check'",
        )
        .fetch_one(p)
        .await
        .unwrap();
        assert_eq!(opt_cnt, 0);
        let kept_opt: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM options WHERE namespace = 'server' AND option_key = 'name'",
        )
        .fetch_one(p)
        .await
        .unwrap();
        assert_eq!(kept_opt, 1);

        // Removed permissions pruned, kept & new permissions present with migration markers.
        let user_perms: Vec<String> = sqlx::query_scalar(
            "SELECT permission FROM user_permissions ORDER BY permission",
        )
        .fetch_all(p)
        .await
        .unwrap();
        assert_eq!(user_perms, vec!["search".to_string()]);

        let sysop_perms: Vec<String> = sqlx::query_scalar(
            "SELECT permission FROM group_permissions WHERE group_name = 'sysop' ORDER BY permission",
        )
        .fetch_all(p)
        .await
        .unwrap();
        assert_eq!(
            sysop_perms,
            vec![
                "bypass_dacl".to_string(),
                "bypass_traverse_checking".to_string(),
                "view_settings".to_string(),
            ]
        );

        let markers: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT state_key, schema_version, revision FROM system_states WHERE owner = 'migration:a66108639ed7' ORDER BY state_key",
        )
        .fetch_all(p)
        .await
        .unwrap();
        assert_eq!(
            markers,
            vec![
                ("bypass_dacl".to_string(), 2, 1),
                ("bypass_traverse_checking".to_string(), 2, 1),
            ]
        );
    }

    #[tokio::test]
    async fn hybrid_upgrade_sqlite_e2e_evolves_cyclic_fks_renames_widens_and_blocks_destructive() {
        use crate::db::schema::ir::{
            CanonicalType, ColumnIr, ConfidenceLevel, ExtractionSource, ForeignKeyIr,
            PrimaryKeyIr, ReferentialAction, TableIr,
        };
        use sqlx::sqlite::SqlitePoolOptions;

        fn make_test_col(
            name: &str,
            ordinal: usize,
            canonical_type: CanonicalType,
            nullable: bool,
        ) -> ColumnIr {
            ColumnIr {
                name: name.to_string(),
                ordinal,
                canonical_type,
                dialect_types: BTreeMap::new(),
                nullable,
                autoincrement: false,
                server_default: None,
                computed: None,
                comment: None,
                confidence: ConfidenceLevel::High,
            }
        }

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("hybrid_e2e.db");
        let pool = DbPool::Sqlite(
            SqlitePoolOptions::new()
                .max_connections(2)
                .connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
                .await
                .unwrap(),
        );

        let mut v1 = SchemaIr::new(ExtractionSource::PrebuiltJson, Some("rev_001".to_string()));
        v1.tables.insert(
            "dept".to_string(),
            TableIr {
                name: "dept".to_string(),
                ownership: TableOwnership::Core,
                columns: vec![
                    make_test_col("id", 0, CanonicalType::Integer, false),
                    make_test_col("manager_id", 1, CanonicalType::Integer, true),
                    make_test_col("label", 2, CanonicalType::Varchar { length: Some(32) }, false),
                ],
                primary_key: PrimaryKeyIr {
                    name: Some("pk_dept".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["id".to_string()],
                },
                foreign_keys: vec![ForeignKeyIr {
                    name: Some("fk_dept_manager_staff".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["manager_id".to_string()],
                    ref_table: "staff".to_string(),
                    ref_columns: vec!["id".to_string()],
                    on_delete: Some(ReferentialAction::SetNull),
                    on_update: None,
                    defer_on_create: false,
                }],
                uniques: Vec::new(),
                checks: Vec::new(),
                indexes: Vec::new(),
                comment: None,
                confidence: ConfidenceLevel::High,
            },
        );
        v1.tables.insert(
            "staff".to_string(),
            TableIr {
                name: "staff".to_string(),
                ownership: TableOwnership::Core,
                columns: vec![
                    make_test_col("id", 0, CanonicalType::Integer, false),
                    make_test_col("dept_id", 1, CanonicalType::Integer, false),
                    make_test_col("nick", 2, CanonicalType::Varchar { length: Some(32) }, true),
                ],
                primary_key: PrimaryKeyIr {
                    name: Some("pk_staff".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["id".to_string()],
                },
                foreign_keys: vec![ForeignKeyIr {
                    name: Some("fk_staff_dept".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["dept_id".to_string()],
                    ref_table: "dept".to_string(),
                    ref_columns: vec!["id".to_string()],
                    on_delete: Some(ReferentialAction::Cascade),
                    on_update: None,
                    defer_on_create: false,
                }],
                uniques: Vec::new(),
                checks: Vec::new(),
                indexes: Vec::new(),
                comment: None,
                confidence: ConfidenceLevel::High,
            },
        );
        v1.tables.insert(
            "audit_logs".to_string(),
            TableIr {
                name: "audit_logs".to_string(),
                ownership: TableOwnership::Core,
                columns: vec![
                    make_test_col("id", 0, CanonicalType::Integer, false),
                    make_test_col(
                        "legacy_col",
                        1,
                        CanonicalType::Varchar { length: Some(16) },
                        true,
                    ),
                ],
                primary_key: PrimaryKeyIr {
                    name: Some("pk_audit_logs".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["id".to_string()],
                },
                foreign_keys: Vec::new(),
                uniques: Vec::new(),
                checks: Vec::new(),
                indexes: Vec::new(),
                comment: None,
                confidence: ConfidenceLevel::High,
            },
        );

        let boot = execute_hybrid_upgrade(&pool, None, &v1, &HybridUpgradeOptions::default())
            .await
            .unwrap();
        assert!(boot.bootstrapped);
        assert_eq!(boot.current_revision, "rev_001");

        // Populate cyclic FK rows + audit_logs row.
        let DbPool::Sqlite(ref p) = pool else {
            unreachable!()
        };
        sqlx::query("PRAGMA foreign_keys = ON").execute(p).await.unwrap();
        sqlx::query("INSERT INTO dept (id, manager_id, label) VALUES (1, NULL, 'Engineering')")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO staff (id, dept_id, nick) VALUES (10, 1, 'Alice')")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("UPDATE dept SET manager_id = 10 WHERE id = 1")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO audit_logs (id, legacy_col) VALUES (1, 'old')")
            .execute(p)
            .await
            .unwrap();

        // Build v2: widen `dept.label`, add `dept.notes`, rename `staff.nick` -> `display_name`,
        // add `badges` referencing `staff`, and drop `audit_logs.legacy_col`.
        let mut v2 = v1.clone();
        v2.schema_revision = Some("rev_002".to_string());
        let dept = v2.tables.get_mut("dept").unwrap();
        dept.columns[2].canonical_type = CanonicalType::Varchar { length: Some(128) };
        dept.columns.push(make_test_col("notes", 3, CanonicalType::Text, true));
        let staff = v2.tables.get_mut("staff").unwrap();
        staff.columns[2].name = "display_name".to_string();
        let audit = v2.tables.get_mut("audit_logs").unwrap();
        audit.columns.retain(|c| c.name != "legacy_col");
        v2.tables.insert(
            "badges".to_string(),
            TableIr {
                name: "badges".to_string(),
                ownership: TableOwnership::Core,
                columns: vec![
                    make_test_col("id", 0, CanonicalType::Integer, false),
                    make_test_col("staff_id", 1, CanonicalType::Integer, false),
                    make_test_col("badge", 2, CanonicalType::Varchar { length: Some(64) }, false),
                ],
                primary_key: PrimaryKeyIr {
                    name: Some("pk_badges".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["id".to_string()],
                },
                foreign_keys: vec![ForeignKeyIr {
                    name: Some("fk_badges_staff".to_string()),
                    dialect_names: BTreeMap::new(),
                    columns: vec!["staff_id".to_string()],
                    ref_table: "staff".to_string(),
                    ref_columns: vec!["id".to_string()],
                    on_delete: Some(ReferentialAction::Cascade),
                    on_update: None,
                    defer_on_create: false,
                }],
                uniques: Vec::new(),
                checks: Vec::new(),
                indexes: Vec::new(),
                comment: None,
                confidence: ConfidenceLevel::High,
            },
        );

        // Without `--allow-destructive`, dropping `audit_logs.legacy_col` must be blocked cleanly.
        let blocked = execute_hybrid_upgrade(
            &pool,
            None,
            &v2,
            &HybridUpgradeOptions {
                allow_destructive: false,
                rename_overrides: vec!["staff.nick=display_name".to_string()],
                ..Default::default()
            },
        )
        .await;
        assert!(
            matches!(blocked, Err(CfmsError::DestructiveMigrationBlocked(_))),
            "expected DestructiveMigrationBlocked, got: {blocked:?}"
        );
        assert_eq!(pool.current_revision().await.unwrap().as_deref(), Some("rev_001"));

        // With `--allow-destructive` + `--rename staff.nick=display_name`, evolution succeeds.
        let outcome = execute_hybrid_upgrade(
            &pool,
            None,
            &v2,
            &HybridUpgradeOptions {
                allow_destructive: true,
                rename_overrides: vec!["staff.nick=display_name".to_string()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.strategy, UpgradeStrategy::HybridNativeDdl);
        assert_eq!(outcome.current_revision, "rev_002");

        // Verify data preserved through rename + table rebuild, FK integrity clean, and inspector passes.
        let nick_after: String =
            sqlx::query_scalar("SELECT display_name FROM staff WHERE id = 10")
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(nick_after, "Alice");
        let label_after: String = sqlx::query_scalar("SELECT label FROM dept WHERE id = 1")
            .fetch_one(p)
            .await
            .unwrap();
        assert_eq!(label_after, "Engineering");
        let fk_violations: Vec<(String, i64, String, i64)> =
            sqlx::query_as("PRAGMA foreign_key_check")
                .fetch_all(p)
                .await
                .unwrap();
        assert!(fk_violations.is_empty(), "FK violations: {fk_violations:?}");

        let inspector = SchemaInspector::inspect_against_ir(&pool, &v2).await.unwrap();
        assert!(
            inspector.healthy,
            "drift after hybrid upgrade: missing={:?}, cols={:?}, constraints={:?}, idx={:?}",
            inspector.missing_tables,
            inspector.column_mismatches,
            inspector.constraint_mismatches,
            inspector.index_mismatches
        );

        pool.close().await;
    }

    #[tokio::test]
    async fn stamp_database_revision_validates_dag_head_and_force() {
        use sqlx::sqlite::SqlitePoolOptions;

        let dir = tempdir().unwrap();
        let versions = dir.path().join("alembic").join("versions");
        std::fs::create_dir_all(&versions).unwrap();
        std::fs::write(
            versions.join("0001_init.py"),
            "revision = 'rev_a'\ndown_revision = None\ndef upgrade(): pass\n",
        )
        .unwrap();
        std::fs::write(
            versions.join("0002_next.py"),
            "revision = 'rev_b'\ndown_revision = 'rev_a'\ndef upgrade(): pass\n",
        )
        .unwrap();

        let db_path = dir.path().join("stamp.db");
        let pool = DbPool::Sqlite(
            SqlitePoolOptions::new()
                .max_connections(2)
                .connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
                .await
                .unwrap(),
        );

        let head_out = stamp_database_revision(&pool, Some(&versions), "head", false)
            .await
            .unwrap();
        assert_eq!(head_out.stamped_revision, "rev_b");
        assert_eq!(pool.current_revision().await.unwrap().as_deref(), Some("rev_b"));

        let err = stamp_database_revision(&pool, Some(&versions), "nonexistent_rev", false).await;
        assert!(matches!(err, Err(CfmsError::InvalidArgument(_))));

        let forced = stamp_database_revision(&pool, Some(&versions), "custom_rev_x", true)
            .await
            .unwrap();
        assert_eq!(forced.stamped_revision, "custom_rev_x");
        assert!(forced.forced);
        assert_eq!(
            pool.current_revision().await.unwrap().as_deref(),
            Some("custom_rev_x")
        );

        pool.close().await;
    }
}
