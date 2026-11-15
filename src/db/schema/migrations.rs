//! Native multi-backend (SQLite, MySQL, PostgreSQL) schema bootstrap and incremental
//! migration engine covering all 20 CFMS Alembic revisions (`fe8863687aa4` .. `e952c02c1454`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use rand::Rng;
use serde::Serialize;
use sqlx::{Acquire, Row};
use tokio::process::Command;
use uuid::Uuid;

use crate::core::error::{CfmsError, Result};
use crate::core::paths::{AlembicPaths, WorkspacePaths};
use crate::db::backend::{DatabaseKind, DbPool, ServerCompatibility};
use crate::db::schema::ddl::{
    USER_OIDC_CREDENTIALS_TABLE, builtin_schema_ir, create_head_schema, execute_ddl_statements,
    set_alembic_version, table_def,
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

/// Inspect the target database and either bootstrap an empty database to HEAD (`e952c02c1454`)
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

    // Preserve the battle-tested 19-step native historical upgrade path (including complex
    // UUID backfills, password/TOTP splits, and rate limit pruning) when upgrading from 0.13.x/0.14.x
    // straight to 0.14.x HEAD (`e952c02c1454`).
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
        // Historical native steps will first advance the live DB to `e952c02c1454`.
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

async fn apply_revision_step(
    pool: &DbPool,
    revision: &str,
    _compat: &ServerCompatibility,
) -> Result<()> {
    match revision {
        "b4b3061f385c" => step_b4b3061f385c(pool).await,
        "76f1c7621e23" => step_76f1c7621e23(pool).await,
        "f239d439f893" => step_f239d439f893(pool).await,
        "170e0a16133e" => step_170e0a16133e(pool).await,
        "7bddfba0d8aa" => step_7bddfba0d8aa(pool).await,
        "ab7efda19079" => step_ab7efda19079(pool).await,
        "8c130010a943" => step_8c130010a943(pool).await,
        "39084f380eaa" => step_39084f380eaa(pool).await,
        "adc1283fb393" => step_adc1283fb393(pool).await,
        "6dba0956fa9d" => step_6dba0956fa9d(pool).await,
        "3c496a214a87" => step_3c496a214a87(pool).await,
        "0460356a5ba6" => step_0460356a5ba6(pool).await,
        "5ad5aca75635" => step_5ad5aca75635(pool).await,
        "d252e662fc05" => step_d252e662fc05(pool).await,
        "b2ea9cac8462" => step_b2ea9cac8462(pool).await,
        "3815ba18197b" => step_3815ba18197b(pool).await,
        "03197fed3401" => step_03197fed3401(pool).await,
        "16c86712512a" => step_16c86712512a(pool).await,
        "e952c02c1454" => step_e952c02c1454(pool).await,
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

fn random_hex(num_bytes: usize) -> String {
    let mut bytes = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
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

async fn execute_single_ddl(pool: &DbPool, sql: &str) -> Result<()> {
    execute_ddl_statements(pool, &[sql.to_string()]).await
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
                    "SELECT COUNT(*) FROM group_permissions WHERE group_name = ? AND permission = ? AND granted = 1",
                )
                .bind("sysop")
                .bind(perm)
                .fetch_one(p)
                .await?
            }
            DbPool::Mysql(p) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM group_permissions WHERE group_name = ? AND permission = ? AND granted = true",
                )
                .bind("sysop")
                .bind(perm)
                .fetch_one(p)
                .await?
            }
            DbPool::Postgres(p) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM group_permissions WHERE group_name = $1 AND permission = $2 AND granted = true",
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
// 19 Forward Step Transitions: b4b3061f385c .. e952c02c1454
// ============================================================================

async fn step_b4b3061f385c(pool: &DbPool) -> Result<()> {
    grant_sysop_permissions(pool, None, &["diagnostics"]).await
}

async fn step_76f1c7621e23(pool: &DbPool) -> Result<()> {
    if has_column(pool, "userblock_entries", "reason_comment_id").await? {
        return Ok(());
    }
    match pool.kind() {
        DatabaseKind::Sqlite => {
            // Works identically whether called during old username-keyed or newer user_id-keyed rebuild.
            let has_user_id = has_column(pool, "userblock_entries", "user_id").await?;
            let id_col = if has_user_id {
                "user_id CHAR(32) NOT NULL"
            } else {
                "username VARCHAR(256) NOT NULL"
            };
            let id_name = if has_user_id { "user_id" } else { "username" };
            let fk_user = if has_user_id {
                "CONSTRAINT fk_userblock_entries_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE"
            } else {
                "CONSTRAINT fk_userblock_entries_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE"
            };
            let create_tmp = format!(
                "CREATE TABLE _cfms_rebuild_userblock_entries (\n\
                    block_id VARCHAR(32) NOT NULL,\n\
                    {id_col},\n\
                    timestamp DOUBLE NOT NULL,\n\
                    not_before DOUBLE NOT NULL,\n\
                    not_after DOUBLE NOT NULL,\n\
                    target_type VARCHAR(32) NOT NULL,\n\
                    target_id VARCHAR(255),\n\
                    reason_comment_id INTEGER,\n\
                    CONSTRAINT pk_userblock_entries PRIMARY KEY (block_id),\n\
                    {fk_user},\n\
                    CONSTRAINT fk_userblock_entries_reason_comment_id_comments FOREIGN KEY(reason_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL\n\
                )"
            );
            let copy_sql = format!(
                "INSERT INTO _cfms_rebuild_userblock_entries (block_id, {id_name}, timestamp, not_before, not_after, target_type, target_id, reason_comment_id) \
                 SELECT block_id, {id_name}, timestamp, not_before, not_after, target_type, target_id, NULL FROM userblock_entries"
            );
            sqlite_rebuild_table(pool, "userblock_entries", &create_tmp, &copy_sql, &[]).await
        }
        DatabaseKind::Mysql | DatabaseKind::Postgresql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE userblock_entries ADD COLUMN reason_comment_id BIGINT".to_string(),
                    "ALTER TABLE userblock_entries ADD CONSTRAINT fk_userblock_entries_reason_comment_id_comments FOREIGN KEY (reason_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL".to_string(),
                ],
            )
            .await
        }
    }
}

async fn step_f239d439f893(pool: &DbPool) -> Result<()> {
    let mut stmts = Vec::new();
    if !has_index(pool, "group_permissions", "ix_group_permissions_end_time_id").await? {
        stmts.push("CREATE INDEX ix_group_permissions_end_time_id ON group_permissions (end_time, id)".to_string());
    }
    if !has_index(pool, "user_permissions", "ix_user_permissions_end_time_id").await? {
        stmts.push("CREATE INDEX ix_user_permissions_end_time_id ON user_permissions (end_time, id)".to_string());
    }
    if !stmts.is_empty() {
        execute_ddl_statements(pool, &stmts).await?;
    }
    Ok(())
}

async fn step_170e0a16133e(pool: &DbPool) -> Result<()> {
    if has_column(pool, "nodes", "active_name").await? {
        return Ok(());
    }
    if !has_column(pool, "nodes", "active_parent_id").await? {
        return Err(CfmsError::SchemaDrift(
            "Cannot migrate node namespace: neither active_parent_id nor active_name exists on nodes".to_string(),
        ));
    }

    match pool.kind() {
        DatabaseKind::Sqlite => {
            let create_tmp = "CREATE TABLE _cfms_rebuild_nodes (\n\
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
            )";
            let copy_sql = "INSERT INTO _cfms_rebuild_nodes (id, type, name, parent_id, inherit, status, status_operation_id, access_rule_set_id) \
                SELECT id, type, name, parent_id, inherit, status, status_operation_id, access_rule_set_id FROM nodes";
            let indexes = table_def("nodes")
                .expect("nodes def")
                .compile_create_indexes(DatabaseKind::Sqlite);
            sqlite_rebuild_table(pool, "nodes", create_tmp, copy_sql, &indexes).await
        }
        DatabaseKind::Mysql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE nodes DROP INDEX uq_nodes_active_parent_name, DROP COLUMN active_parent_id, ADD COLUMN active_name VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN status = 1 THEN NULL ELSE name END) STORED, ADD CONSTRAINT uq_nodes_active_parent_name UNIQUE (parent_id, active_name)".to_string(),
                ],
            )
            .await
        }
        DatabaseKind::Postgresql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE nodes DROP CONSTRAINT IF EXISTS uq_nodes_active_parent_name".to_string(),
                    "ALTER TABLE nodes DROP COLUMN active_parent_id".to_string(),
                    "ALTER TABLE nodes ADD COLUMN active_name VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN status = 1 THEN NULL ELSE name END) STORED".to_string(),
                    "ALTER TABLE nodes ADD CONSTRAINT uq_nodes_active_parent_name UNIQUE (parent_id, active_name)".to_string(),
                ],
            )
            .await
        }
    }
}

async fn step_7bddfba0d8aa(pool: &DbPool) -> Result<()> {
    if pool.kind() != DatabaseKind::Mysql {
        return Ok(());
    }
    const FLOAT_COLS: &[(&str, &[(&str, bool)])] = &[
        ("audit_entries", &[("logged_time", false)]),
        ("compiled_access_rule_sets", &[("created_at", false)]),
        ("document_revisions", &[("created_time", false)]),
        ("documents", &[("created_time", false)]),
        (
            "file_deduplication_tasks",
            &[
                ("available_at", false),
                ("lease_expires_at", true),
                ("created_time", false),
            ],
        ),
        ("file_tasks", &[("start_time", false), ("end_time", true)]),
        ("files", &[("created_time", false)]),
        ("folders", &[("created_time", false)]),
        ("group_permissions", &[("start_time", false), ("end_time", true)]),
        ("keyrings", &[("created_time", false)]),
        ("object_access_entries", &[("start_time", false), ("end_time", true)]),
        (
            "rate_limit_buckets",
            &[
                ("tokens", false),
                ("last_refill_at", false),
                ("last_denied_at", true),
                ("last_attempt", false),
            ],
        ),
        ("risk_ip_accounts", &[("last_attempt", false)]),
        ("system_states", &[("updated_at", false)]),
        ("user_memberships", &[("start_time", false), ("end_time", true)]),
        ("user_permissions", &[("start_time", false), ("end_time", true)]),
        (
            "userblock_entries",
            &[("timestamp", false), ("not_before", false), ("not_after", false)],
        ),
        (
            "users",
            &[
                ("passwd_last_modified", false),
                ("last_login", true),
                ("created_time", false),
            ],
        ),
    ];

    let mut stmts = Vec::new();
    for (table, cols) in FLOAT_COLS {
        let clauses: Vec<String> = cols
            .iter()
            .map(|(col, nullable)| {
                let null_kw = if *nullable { "NULL" } else { "NOT NULL" };
                format!("MODIFY COLUMN {col} DOUBLE {null_kw}")
            })
            .collect();
        stmts.push(format!("ALTER TABLE {table} {}", clauses.join(", ")));
    }
    execute_ddl_statements(pool, &stmts).await
}

async fn step_ab7efda19079(pool: &DbPool) -> Result<()> {
    let kind = pool.kind();
    let double_ty = match kind {
        DatabaseKind::Postgresql => "DOUBLE PRECISION",
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "DOUBLE",
    };
    let bool_ty = match kind {
        DatabaseKind::Mysql => "BOOL",
        DatabaseKind::Sqlite | DatabaseKind::Postgresql => "BOOLEAN",
    };

    let mut stmts = Vec::new();
    stmts.push(format!(
        "CREATE TABLE scheduling_runtime_state (\n\
            id INTEGER NOT NULL,\n\
            provider VARCHAR(16) NOT NULL,\n\
            generation BIGINT NOT NULL,\n\
            schema_version INTEGER NOT NULL,\n\
            updated_at {double_ty} NOT NULL,\n\
            CONSTRAINT pk_scheduling_runtime_state PRIMARY KEY (id),\n\
            CONSTRAINT ck_scheduling_runtime_provider CHECK (provider IN ('local', 'redis')),\n\
            CONSTRAINT ck_scheduling_generation_positive CHECK (generation > 0),\n\
            CONSTRAINT ck_scheduling_runtime_state_singleton CHECK (id = 1)\n\
        )"
    ));
    stmts.push(format!(
        "CREATE TABLE schedules (\n\
            id VARCHAR(32) NOT NULL,\n\
            task_name VARCHAR(255) NOT NULL,\n\
            task_contract_version INTEGER NOT NULL,\n\
            payload JSON NOT NULL,\n\
            trigger_type VARCHAR(16) NOT NULL,\n\
            trigger_data JSON NOT NULL,\n\
            timezone VARCHAR(255) NOT NULL,\n\
            enabled {bool_ty} NOT NULL,\n\
            status VARCHAR(16) NOT NULL,\n\
            revision BIGINT NOT NULL,\n\
            next_run_at {double_ty},\n\
            active_execution_id VARCHAR(64),\n\
            pending_scheduled_for {double_ty},\n\
            created_by VARCHAR(256) NOT NULL,\n\
            created_at {double_ty} NOT NULL,\n\
            updated_by VARCHAR(256) NOT NULL,\n\
            updated_at {double_ty} NOT NULL,\n\
            deleted_at {double_ty},\n\
            CONSTRAINT pk_schedules PRIMARY KEY (id),\n\
            CONSTRAINT ck_schedules_status CHECK (status IN ('active', 'completed', 'failed', 'deleted')),\n\
            CONSTRAINT ck_schedules_trigger_type CHECK (trigger_type IN ('cron', 'date', 'interval')),\n\
            CONSTRAINT ck_schedules_revision_positive CHECK (revision > 0),\n\
            CONSTRAINT ck_schedules_task_contract_version_positive CHECK (task_contract_version > 0),\n\
            CONSTRAINT fk_schedules_created_by_users FOREIGN KEY(created_by) REFERENCES users (username),\n\
            CONSTRAINT fk_schedules_updated_by_users FOREIGN KEY(updated_by) REFERENCES users (username)\n\
        )"
    ));
    stmts.push("CREATE INDEX ix_schedules_due ON schedules (enabled, status, next_run_at)".to_string());
    stmts.push(format!(
        "CREATE TABLE schedule_executions (\n\
            id VARCHAR(64) NOT NULL,\n\
            schedule_id VARCHAR(32) NOT NULL,\n\
            provider_generation BIGINT NOT NULL,\n\
            scheduled_for {double_ty} NOT NULL,\n\
            state VARCHAR(16) NOT NULL,\n\
            dispatch_state VARCHAR(16) NOT NULL,\n\
            attempt INTEGER NOT NULL,\n\
            retry_at {double_ty},\n\
            lease_owner VARCHAR(64),\n\
            lease_expires_at {double_ty},\n\
            started_at {double_ty},\n\
            completed_at {double_ty},\n\
            result JSON,\n\
            error VARCHAR(1024),\n\
            created_at {double_ty} NOT NULL,\n\
            CONSTRAINT pk_schedule_executions PRIMARY KEY (id),\n\
            CONSTRAINT uq_schedule_executions_occurrence UNIQUE (schedule_id, scheduled_for),\n\
            CONSTRAINT ck_schedule_executions_dispatch_state CHECK (dispatch_state IN ('pending', 'sent')),\n\
            CONSTRAINT ck_schedule_executions_state CHECK (state IN ('pending', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled')),\n\
            CONSTRAINT ck_schedule_executions_attempt CHECK (attempt >= 0),\n\
            CONSTRAINT fk_schedule_executions_schedule_id_schedules FOREIGN KEY(schedule_id) REFERENCES schedules (id) ON DELETE CASCADE\n\
        )"
    ));
    stmts.push(
        "CREATE INDEX ix_schedule_executions_claim ON schedule_executions (state, dispatch_state, retry_at, lease_expires_at)"
            .to_string(),
    );
    stmts.push(
        "CREATE INDEX ix_schedule_executions_schedule_id ON schedule_executions (schedule_id)"
            .to_string(),
    );
    execute_ddl_statements(pool, &stmts).await
}

async fn step_8c130010a943(pool: &DbPool) -> Result<()> {
    grant_sysop_permissions(
        pool,
        Some("migration:8c130010a943"),
        &["view_schedules", "manage_schedules"],
    )
    .await
}

async fn step_39084f380eaa(pool: &DbPool) -> Result<()> {
    match pool.kind() {
        DatabaseKind::Sqlite => {
            let create_tmp = "CREATE TABLE _cfms_rebuild_schedules (\n\
                id VARCHAR(32) NOT NULL,\n\
                task_name VARCHAR(255) NOT NULL,\n\
                task_contract_version INTEGER NOT NULL,\n\
                payload JSON NOT NULL,\n\
                trigger_type VARCHAR(16) NOT NULL,\n\
                trigger_data JSON NOT NULL,\n\
                timezone VARCHAR(255) NOT NULL,\n\
                system_managed BOOLEAN DEFAULT 0 NOT NULL,\n\
                enabled BOOLEAN NOT NULL,\n\
                status VARCHAR(16) NOT NULL,\n\
                revision BIGINT NOT NULL,\n\
                next_run_at DOUBLE,\n\
                active_execution_id VARCHAR(64),\n\
                pending_scheduled_for DOUBLE,\n\
                created_by VARCHAR(256),\n\
                created_at DOUBLE NOT NULL,\n\
                updated_by VARCHAR(256),\n\
                updated_at DOUBLE NOT NULL,\n\
                deleted_at DOUBLE,\n\
                CONSTRAINT pk_schedules PRIMARY KEY (id),\n\
                CONSTRAINT ck_schedules_status CHECK (status IN ('active', 'completed', 'failed', 'deleted')),\n\
                CONSTRAINT ck_schedules_trigger_type CHECK (trigger_type IN ('cron', 'date', 'interval')),\n\
                CONSTRAINT ck_schedules_revision_positive CHECK (revision > 0),\n\
                CONSTRAINT ck_schedules_task_contract_version_positive CHECK (task_contract_version > 0),\n\
                CONSTRAINT fk_schedules_created_by_users FOREIGN KEY(created_by) REFERENCES users (username) ON DELETE SET NULL,\n\
                CONSTRAINT fk_schedules_updated_by_users FOREIGN KEY(updated_by) REFERENCES users (username) ON DELETE SET NULL\n\
            )";
            let copy_sql = "INSERT INTO _cfms_rebuild_schedules (id, task_name, task_contract_version, payload, trigger_type, trigger_data, timezone, system_managed, enabled, status, revision, next_run_at, active_execution_id, pending_scheduled_for, created_by, created_at, updated_by, updated_at, deleted_at) \
                SELECT id, task_name, task_contract_version, payload, trigger_type, trigger_data, timezone, 0, enabled, status, revision, next_run_at, active_execution_id, pending_scheduled_for, created_by, created_at, updated_by, updated_at, deleted_at FROM schedules";
            let idxs = vec![
                "CREATE INDEX ix_schedules_due ON schedules (enabled, status, next_run_at)"
                    .to_string(),
            ];
            sqlite_rebuild_table(pool, "schedules", create_tmp, copy_sql, &idxs).await
        }
        DatabaseKind::Mysql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE schedules DROP FOREIGN KEY fk_schedules_created_by_users, DROP FOREIGN KEY fk_schedules_updated_by_users, ADD COLUMN system_managed BOOL NOT NULL DEFAULT false, MODIFY COLUMN created_by VARCHAR(256) NULL, MODIFY COLUMN updated_by VARCHAR(256) NULL, ADD CONSTRAINT fk_schedules_created_by_users FOREIGN KEY (created_by) REFERENCES users (username) ON DELETE SET NULL, ADD CONSTRAINT fk_schedules_updated_by_users FOREIGN KEY (updated_by) REFERENCES users (username) ON DELETE SET NULL".to_string(),
                ],
            )
            .await
        }
        DatabaseKind::Postgresql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE schedules DROP CONSTRAINT fk_schedules_created_by_users".to_string(),
                    "ALTER TABLE schedules DROP CONSTRAINT fk_schedules_updated_by_users".to_string(),
                    "ALTER TABLE schedules ADD COLUMN system_managed BOOLEAN DEFAULT false NOT NULL".to_string(),
                    "ALTER TABLE schedules ALTER COLUMN created_by DROP NOT NULL".to_string(),
                    "ALTER TABLE schedules ALTER COLUMN updated_by DROP NOT NULL".to_string(),
                    "ALTER TABLE schedules ADD CONSTRAINT fk_schedules_created_by_users FOREIGN KEY (created_by) REFERENCES users (username) ON DELETE SET NULL".to_string(),
                    "ALTER TABLE schedules ADD CONSTRAINT fk_schedules_updated_by_users FOREIGN KEY (updated_by) REFERENCES users (username) ON DELETE SET NULL".to_string(),
                ],
            )
            .await
        }
    }
}

async fn step_adc1283fb393(pool: &DbPool) -> Result<()> {
    if has_column(pool, "scheduling_runtime_state", "redis_namespace").await? {
        return Ok(());
    }
    execute_single_ddl(
        pool,
        "ALTER TABLE scheduling_runtime_state ADD COLUMN redis_namespace VARCHAR(63)",
    )
    .await
}

async fn step_6dba0956fa9d(pool: &DbPool) -> Result<()> {
    if has_column(pool, "schedule_executions", "dispatched_at").await? {
        return Ok(());
    }
    let double_ty = match pool.kind() {
        DatabaseKind::Postgresql => "DOUBLE PRECISION",
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "DOUBLE",
    };
    execute_single_ddl(
        pool,
        &format!("ALTER TABLE schedule_executions ADD COLUMN dispatched_at {double_ty}"),
    )
    .await
}

async fn step_3c496a214a87(pool: &DbPool) -> Result<()> {
    if has_column(pool, "schedule_executions", "task_name").await? {
        return Ok(());
    }
    execute_ddl_statements(
        pool,
        &[
            "ALTER TABLE schedule_executions ADD COLUMN task_name VARCHAR(255)".to_string(),
            "ALTER TABLE schedule_executions ADD COLUMN task_contract_version INTEGER".to_string(),
            "ALTER TABLE schedule_executions ADD COLUMN payload JSON".to_string(),
        ],
    )
    .await?;

    let backfill = "UPDATE schedule_executions \
        SET task_name = (SELECT schedules.task_name FROM schedules WHERE schedules.id = schedule_executions.schedule_id), \
            task_contract_version = (SELECT schedules.task_contract_version FROM schedules WHERE schedules.id = schedule_executions.schedule_id), \
            payload = (SELECT schedules.payload FROM schedules WHERE schedules.id = schedule_executions.schedule_id)";
    match pool {
        DbPool::Sqlite(p) => {
            sqlx::query(backfill).execute(p).await?;
        }
        DbPool::Mysql(p) => {
            sqlx::query(backfill).execute(p).await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query(backfill).execute(p).await?;
        }
    }

    match pool.kind() {
        DatabaseKind::Sqlite => {
            let def = table_def("schedule_executions").expect("schedule_executions def");
            let temp_sql = def
                .compile_create_table(DatabaseKind::Sqlite)
                .replacen(
                    "CREATE TABLE schedule_executions",
                    "CREATE TABLE _cfms_rebuild_schedule_executions",
                    1,
                );
            let cols: Vec<&str> = def.columns.iter().map(|c| c.name).collect();
            let col_list = cols.join(", ");
            let copy_sql = format!(
                "INSERT INTO _cfms_rebuild_schedule_executions ({col_list}) SELECT {col_list} FROM schedule_executions"
            );
            let idxs = def.compile_create_indexes(DatabaseKind::Sqlite);
            sqlite_rebuild_table(pool, "schedule_executions", &temp_sql, &copy_sql, &idxs).await
        }
        DatabaseKind::Mysql => {
            execute_single_ddl(
                pool,
                "ALTER TABLE schedule_executions MODIFY COLUMN task_name VARCHAR(255) NOT NULL, MODIFY COLUMN task_contract_version INTEGER NOT NULL, MODIFY COLUMN payload JSON NOT NULL",
            )
            .await
        }
        DatabaseKind::Postgresql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE schedule_executions ALTER COLUMN task_name SET NOT NULL".to_string(),
                    "ALTER TABLE schedule_executions ALTER COLUMN task_contract_version SET NOT NULL".to_string(),
                    "ALTER TABLE schedule_executions ALTER COLUMN payload SET NOT NULL".to_string(),
                ],
            )
            .await
        }
    }
}

async fn step_0460356a5ba6(pool: &DbPool) -> Result<()> {
    let mut stmts = Vec::new();
    if !has_index(
        pool,
        "document_revisions",
        "ix_document_revisions_document_created_id",
    )
    .await?
    {
        stmts.push(
            "CREATE INDEX ix_document_revisions_document_created_id ON document_revisions (document_id, created_time, id)"
                .to_string(),
        );
    }
    if !has_index(
        pool,
        "document_revisions",
        "ix_document_revisions_parent_revision_id",
    )
    .await?
    {
        stmts.push(
            "CREATE INDEX ix_document_revisions_parent_revision_id ON document_revisions (parent_revision_id)"
                .to_string(),
        );
    }
    if !has_index(pool, "documents", "ix_documents_current_revision_id").await? {
        stmts.push(
            "CREATE INDEX ix_documents_current_revision_id ON documents (current_revision_id)"
                .to_string(),
        );
    }
    if !stmts.is_empty() {
        execute_ddl_statements(pool, &stmts).await?;
    }
    Ok(())
}

async fn step_5ad5aca75635(pool: &DbPool) -> Result<()> {
    let kind = pool.kind();
    let double_ty = match kind {
        DatabaseKind::Postgresql => "DOUBLE PRECISION",
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "DOUBLE",
    };
    let bool_ty = match kind {
        DatabaseKind::Mysql => "BOOL",
        DatabaseKind::Sqlite | DatabaseKind::Postgresql => "BOOLEAN",
    };
    let blob_ty = match kind {
        DatabaseKind::Postgresql => "BYTEA",
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "BLOB",
    };
    let fixed32_ty = match kind {
        DatabaseKind::Sqlite => "BLOB",
        DatabaseKind::Mysql => "BINARY(32)",
        DatabaseKind::Postgresql => "BYTEA",
    };

    execute_ddl_statements(
        pool,
        &[
            format!(
                "CREATE TABLE user_auth_public_keys (\n\
                    id VARCHAR(32) NOT NULL,\n\
                    username VARCHAR(256) NOT NULL,\n\
                    public_key_der {blob_ty} NOT NULL,\n\
                    fingerprint {fixed32_ty} NOT NULL,\n\
                    label VARCHAR(255),\n\
                    created_time {double_ty} NOT NULL,\n\
                    last_used_time {double_ty},\n\
                    CONSTRAINT pk_user_auth_public_keys PRIMARY KEY (id),\n\
                    CONSTRAINT uq_user_auth_public_keys_user_fingerprint UNIQUE (username, fingerprint),\n\
                    CONSTRAINT fk_user_auth_public_keys_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE\n\
                )"
            ),
            "CREATE INDEX ix_user_auth_public_keys_fingerprint ON user_auth_public_keys (fingerprint)".to_string(),
            format!(
                "CREATE TABLE user_passwords (\n\
                    username VARCHAR(256) NOT NULL,\n\
                    pass_hash TEXT NOT NULL,\n\
                    passwd_last_modified {double_ty} NOT NULL,\n\
                    CONSTRAINT pk_user_passwords PRIMARY KEY (username),\n\
                    CONSTRAINT fk_user_passwords_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE\n\
                )"
            ),
            format!(
                "CREATE TABLE user_totp_credentials (\n\
                    username VARCHAR(256) NOT NULL,\n\
                    secret VARCHAR(32) NOT NULL,\n\
                    enabled {bool_ty} NOT NULL,\n\
                    backup_codes TEXT,\n\
                    created_time {double_ty} NOT NULL,\n\
                    CONSTRAINT pk_user_totp_credentials PRIMARY KEY (username),\n\
                    CONSTRAINT fk_user_totp_credentials_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE\n\
                )"
            ),
        ],
    )
    .await?;

    let false_lit = match kind {
        DatabaseKind::Sqlite => "0",
        DatabaseKind::Mysql | DatabaseKind::Postgresql => "false",
    };
    let copy_passwords = "INSERT INTO user_passwords (username, pass_hash, passwd_last_modified) \
        SELECT username, pass_hash, COALESCE(passwd_last_modified, 0) FROM users WHERE pass_hash IS NOT NULL";
    let copy_totp = format!(
        "INSERT INTO user_totp_credentials (username, secret, enabled, backup_codes, created_time) \
         SELECT username, totp_secret, COALESCE(totp_enabled, {false_lit}), totp_backup_codes, COALESCE(created_time, 0) FROM users WHERE totp_secret IS NOT NULL"
    );

    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            sqlx::query(copy_passwords).execute(&mut *tx).await?;
            sqlx::query(sqlx::AssertSqlSafe(copy_totp))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        DbPool::Mysql(p) => {
            let mut tx = p.begin().await?;
            sqlx::query(copy_passwords).execute(&mut *tx).await?;
            sqlx::query(sqlx::AssertSqlSafe(copy_totp))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            sqlx::query(copy_passwords).execute(&mut *tx).await?;
            sqlx::query(sqlx::AssertSqlSafe(copy_totp))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
    }

    let drop_stmts: Vec<String> = [
        "passwd_last_modified",
        "totp_enabled",
        "totp_secret",
        "totp_backup_codes",
        "pass_hash",
    ]
    .into_iter()
    .map(|col| format!("ALTER TABLE users DROP COLUMN {col}"))
    .collect();
    execute_ddl_statements(pool, &drop_stmts).await
}

async fn step_d252e662fc05(pool: &DbPool) -> Result<()> {
    // 1. Load usernames and check non-null non-nullable references before mutating schema.
    let usernames = query_strings(pool, "SELECT username FROM users").await?;
    let name_set: HashSet<String> = usernames.iter().cloned().collect();

    const NON_NULLABLE_REFS: &[(&str, &str)] = &[
        ("user_passwords", "username"),
        ("user_totp_credentials", "username"),
        ("user_auth_public_keys", "username"),
        ("user_permissions", "username"),
        ("user_memberships", "username"),
        ("keyrings", "username"),
        ("userblock_entries", "username"),
    ];
    for &(table, col) in NON_NULLABLE_REFS {
        let distinct_vals =
            query_strings(pool, &format!("SELECT DISTINCT {col} FROM {table}")).await?;
        for val in distinct_vals {
            if !name_set.contains(&val) {
                return Err(CfmsError::SchemaDrift(format!(
                    "Orphaned account reference in {table}.{col}: '{val}'"
                )));
            }
        }
    }

    let identities: HashMap<String, Uuid> = usernames
        .into_iter()
        .map(|name| (name, Uuid::new_v4()))
        .collect();

    // 2. Rewrite `users` (add `id` UUID, drop PK `username`, add PK `id`, add unique index `ix_users_username`)
    // and convert all 13 referencing columns + `object_access_entries` + `risk_ip_accounts` + `rate_limit_buckets`.
    match pool.kind() {
        DatabaseKind::Sqlite => {
            d252_sqlite(pool, &identities).await?;
        }
        DatabaseKind::Mysql | DatabaseKind::Postgresql => {
            d252_mysql_or_postgres(pool, &identities).await?;
        }
    }

    Ok(())
}

async fn query_strings(pool: &DbPool, sql: &str) -> Result<Vec<String>> {
    let vals = match pool {
        DbPool::Sqlite(p) => {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_all(p)
                .await?
        }
        DbPool::Mysql(p) => {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_all(p)
                .await?
        }
        DbPool::Postgres(p) => {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_all(p)
                .await?
        }
    };
    Ok(vals)
}

async fn d252_sqlite(pool: &DbPool, identities: &HashMap<String, Uuid>) -> Result<()> {
    let DbPool::Sqlite(p) = pool else {
        unreachable!();
    };
    let mut conn = p.acquire().await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;

    let migration_res: Result<()> = async {
        let mut tx = conn.begin().await?;

        // 1. Rebuild `users` with `id CHAR(32) NOT NULL`, `secret_key VARCHAR(64)` still nullable before 3815ba18197b.
        sqlx::query("DROP TABLE IF EXISTS _cfms_rebuild_users")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "CREATE TABLE _cfms_rebuild_users (\n\
                id CHAR(32) NOT NULL,\n\
                username VARCHAR(256) NOT NULL,\n\
                nickname VARCHAR(255),\n\
                avatar_id VARCHAR(255),\n\
                last_login DOUBLE,\n\
                created_time DOUBLE NOT NULL,\n\
                status INTEGER NOT NULL,\n\
                status_comment_id INTEGER,\n\
                secret_key VARCHAR(64),\n\
                preference_dek_id VARCHAR(64),\n\
                CONSTRAINT pk_users PRIMARY KEY (id),\n\
                CONSTRAINT fk_users_avatar_id_files FOREIGN KEY(avatar_id) REFERENCES files (id),\n\
                CONSTRAINT fk_users_status_comment_id_comments FOREIGN KEY(status_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL,\n\
                CONSTRAINT uq_users_preference_dek_id UNIQUE (preference_dek_id),\n\
                CONSTRAINT fk_users_preference_dek_id FOREIGN KEY(preference_dek_id) REFERENCES keyrings (id) ON DELETE SET NULL\n\
            )",
        )
        .execute(&mut *tx)
        .await?;

        let user_rows = sqlx::query(
            "SELECT username, nickname, avatar_id, last_login, created_time, status, status_comment_id, secret_key, preference_dek_id FROM users",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in user_rows {
            let uname: String = row.get("username");
            let uid = identities[&uname].simple().to_string();
            sqlx::query(
                "INSERT INTO _cfms_rebuild_users (id, username, nickname, avatar_id, last_login, created_time, status, status_comment_id, secret_key, preference_dek_id) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(uid)
            .bind(&uname)
            .bind(row.get::<Option<String>, _>("nickname"))
            .bind(row.get::<Option<String>, _>("avatar_id"))
            .bind(row.get::<Option<f64>, _>("last_login"))
            .bind(row.get::<f64, _>("created_time"))
            .bind(row.get::<i64, _>("status"))
            .bind(row.get::<Option<i64>, _>("status_comment_id"))
            .bind(row.get::<Option<String>, _>("secret_key"))
            .bind(row.get::<Option<String>, _>("preference_dek_id"))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DROP TABLE users").execute(&mut *tx).await?;
        sqlx::query("ALTER TABLE _cfms_rebuild_users RENAME TO users")
            .execute(&mut *tx)
            .await?;
        sqlx::query("CREATE INDEX ix_users_avatar_id ON users (avatar_id)")
            .execute(&mut *tx)
            .await?;
        sqlx::query("CREATE UNIQUE INDEX ix_users_username ON users (username)")
            .execute(&mut *tx)
            .await?;

        // 2. Rebuild each of the 11 dependent tables converting username -> CHAR(32) user_id.
        // Note: SQL subquery against `users(username)` cleanly maps non-null hits and NULLs missing nullable orphans.
        let join_expr = |col: &str| {
            format!("(SELECT u.id FROM users u WHERE u.username = {col})")
        };

        // user_passwords (pre-credential_id)
        sqlx::query(
            "CREATE TABLE _cfms_rebuild_user_passwords (\n\
                user_id CHAR(32) NOT NULL,\n\
                pass_hash TEXT NOT NULL,\n\
                passwd_last_modified DOUBLE NOT NULL,\n\
                CONSTRAINT pk_user_passwords PRIMARY KEY (user_id),\n\
                CONSTRAINT fk_user_passwords_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE\n\
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO _cfms_rebuild_user_passwords (user_id, pass_hash, passwd_last_modified) SELECT {}, pass_hash, passwd_last_modified FROM user_passwords",
            join_expr("user_passwords.username")
        )))
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE user_passwords").execute(&mut *tx).await?;
        sqlx::query("ALTER TABLE _cfms_rebuild_user_passwords RENAME TO user_passwords")
            .execute(&mut *tx)
            .await?;

        // user_totp_credentials (pre-credential_id)
        sqlx::query(
            "CREATE TABLE _cfms_rebuild_user_totp_credentials (\n\
                user_id CHAR(32) NOT NULL,\n\
                secret VARCHAR(32) NOT NULL,\n\
                enabled BOOLEAN NOT NULL,\n\
                backup_codes TEXT,\n\
                created_time DOUBLE NOT NULL,\n\
                CONSTRAINT pk_user_totp_credentials PRIMARY KEY (user_id),\n\
                CONSTRAINT fk_user_totp_credentials_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE\n\
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO _cfms_rebuild_user_totp_credentials (user_id, secret, enabled, backup_codes, created_time) SELECT {}, secret, enabled, backup_codes, created_time FROM user_totp_credentials",
            join_expr("user_totp_credentials.username")
        )))
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE user_totp_credentials")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE _cfms_rebuild_user_totp_credentials RENAME TO user_totp_credentials")
            .execute(&mut *tx)
            .await?;

        // user_auth_public_keys
        sqlx::query(
            "CREATE TABLE _cfms_rebuild_user_auth_public_keys (\n\
                id VARCHAR(32) NOT NULL,\n\
                user_id CHAR(32) NOT NULL,\n\
                public_key_der BLOB NOT NULL,\n\
                fingerprint BLOB NOT NULL,\n\
                label VARCHAR(255),\n\
                created_time DOUBLE NOT NULL,\n\
                last_used_time DOUBLE,\n\
                CONSTRAINT pk_user_auth_public_keys PRIMARY KEY (id),\n\
                CONSTRAINT uq_user_auth_public_keys_user_fingerprint UNIQUE (user_id, fingerprint),\n\
                CONSTRAINT fk_user_auth_public_keys_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE\n\
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO _cfms_rebuild_user_auth_public_keys (id, user_id, public_key_der, fingerprint, label, created_time, last_used_time) SELECT id, {}, public_key_der, fingerprint, label, created_time, last_used_time FROM user_auth_public_keys",
            join_expr("user_auth_public_keys.username")
        )))
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE user_auth_public_keys")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE _cfms_rebuild_user_auth_public_keys RENAME TO user_auth_public_keys")
            .execute(&mut *tx)
            .await?;
        sqlx::query("CREATE INDEX ix_user_auth_public_keys_fingerprint ON user_auth_public_keys (fingerprint)")
            .execute(&mut *tx)
            .await?;

        // user_permissions, user_memberships, keyrings, userblock_entries, audit_entries, document_metadata, file_tasks, schedules
        for (tbl, copy_sql, idxs) in [
            (
                "user_permissions",
                format!(
                    "INSERT INTO _cfms_rebuild_user_permissions (id, user_id, permission, granted, start_time, end_time) SELECT id, {}, permission, granted, start_time, end_time FROM user_permissions",
                    join_expr("user_permissions.username")
                ),
                table_def("user_permissions").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "user_memberships",
                format!(
                    "INSERT INTO _cfms_rebuild_user_memberships (id, user_id, group_name, start_time, end_time) SELECT id, {}, group_name, start_time, end_time FROM user_memberships",
                    join_expr("user_memberships.username")
                ),
                table_def("user_memberships").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "keyrings",
                format!(
                    "INSERT INTO _cfms_rebuild_keyrings (id, user_id, content, label, created_time) SELECT id, {}, content, label, created_time FROM keyrings",
                    join_expr("keyrings.username")
                ),
                table_def("keyrings").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "userblock_entries",
                format!(
                    "INSERT INTO _cfms_rebuild_userblock_entries (block_id, user_id, timestamp, not_before, not_after, target_type, target_id, reason_comment_id) SELECT block_id, {}, timestamp, not_before, not_after, target_type, target_id, reason_comment_id FROM userblock_entries",
                    join_expr("userblock_entries.username")
                ),
                table_def("userblock_entries").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "audit_entries",
                format!(
                    "INSERT INTO _cfms_rebuild_audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) SELECT id, action, {}, target, data, result, remote_address, logged_time FROM audit_entries",
                    join_expr("audit_entries.username")
                ),
                table_def("audit_entries").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "document_metadata",
                format!(
                    "INSERT INTO _cfms_rebuild_document_metadata (document_id, creator_id, last_modified_by_id) SELECT document_id, {}, {} FROM document_metadata",
                    join_expr("document_metadata.creator_username"),
                    join_expr("document_metadata.last_modified_by_username")
                ),
                table_def("document_metadata").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "file_tasks",
                format!(
                    "INSERT INTO _cfms_rebuild_file_tasks (id, file_id, status, mode, start_time, end_time, issued_by_id, encryption_key, chunk_size, upload_file_size, upload_sha256, upload_session_id, upload_checkpoint_size, upload_checkpoint_data) SELECT id, file_id, status, mode, start_time, end_time, {}, encryption_key, chunk_size, upload_file_size, upload_sha256, upload_session_id, upload_checkpoint_size, upload_checkpoint_data FROM file_tasks",
                    join_expr("file_tasks.issued_by_username")
                ),
                table_def("file_tasks").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
            (
                "schedules",
                format!(
                    "INSERT INTO _cfms_rebuild_schedules (id, task_name, task_contract_version, payload, trigger_type, trigger_data, timezone, system_managed, enabled, status, revision, next_run_at, active_execution_id, pending_scheduled_for, created_by, created_at, updated_by, updated_at, deleted_at) SELECT id, task_name, task_contract_version, payload, trigger_type, trigger_data, timezone, system_managed, enabled, status, revision, next_run_at, active_execution_id, pending_scheduled_for, {}, created_at, {}, updated_at, deleted_at FROM schedules",
                    join_expr("schedules.created_by"),
                    join_expr("schedules.updated_by")
                ),
                table_def("schedules").unwrap().compile_create_indexes(DatabaseKind::Sqlite),
            ),
        ] {
            let def = table_def(tbl).unwrap();
            let create_tmp = def.compile_create_table(DatabaseKind::Sqlite).replacen(
                &format!("CREATE TABLE {tbl}"),
                &format!("CREATE TABLE _cfms_rebuild_{tbl}"),
                1,
            );
            sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE IF EXISTS _cfms_rebuild_{tbl}")))
                .execute(&mut *tx)
                .await?;
            sqlx::query(sqlx::AssertSqlSafe(create_tmp))
                .execute(&mut *tx)
                .await?;
            sqlx::query(sqlx::AssertSqlSafe(copy_sql))
                .execute(&mut *tx)
                .await?;
            sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {tbl}")))
                .execute(&mut *tx)
                .await?;
            sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE _cfms_rebuild_{tbl} RENAME TO {tbl}")))
                .execute(&mut *tx)
                .await?;
            for idx_sql in idxs {
                sqlx::query(sqlx::AssertSqlSafe(idx_sql))
                    .execute(&mut *tx)
                    .await?;
            }
        }

        // 3. Rewrite `object_access_entries` entity_type = 'user' -> hyphenated UUID str(mapped) or delete orphaned.
        let grants = sqlx::query(
            "SELECT id, entity_identifier FROM object_access_entries WHERE entity_type = 'user'",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in grants {
            let entry_id: i64 = row.get("id");
            let uname: String = row.get("entity_identifier");
            if let Some(uid) = identities.get(&uname) {
                sqlx::query("UPDATE object_access_entries SET entity_identifier = ? WHERE id = ?")
                    .bind(uid.hyphenated().to_string())
                    .bind(entry_id)
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query("DELETE FROM object_access_entries WHERE id = ?")
                    .bind(entry_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        // 4. Rebuild empty `risk_ip_accounts` with `user_id CHAR(32) NOT NULL`.
        sqlx::query("DELETE FROM risk_ip_accounts").execute(&mut *tx).await?;
        sqlx::query("DROP TABLE risk_ip_accounts").execute(&mut *tx).await?;
        let risk_def = table_def("risk_ip_accounts").unwrap();
        sqlx::query(sqlx::AssertSqlSafe(risk_def.compile_create_table(DatabaseKind::Sqlite)))
            .execute(&mut *tx)
            .await?;
        for idx_sql in risk_def.compile_create_indexes(DatabaseKind::Sqlite) {
            sqlx::query(sqlx::AssertSqlSafe(idx_sql))
                .execute(&mut *tx)
                .await?;
        }

        // 5. Prune account-scoped rate_limit_buckets.
        sqlx::query("DELETE FROM rate_limit_buckets WHERE scope = 'account'")
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
    .await;

    let fk_restore = sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await;
    migration_res?;
    fk_restore?;

    let fk_errors = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *conn)
        .await?;
    if !fk_errors.is_empty() {
        return Err(CfmsError::SchemaDrift(
            "SQLite foreign_key_check failed after d252e662fc05 identity migration".to_string(),
        ));
    }
    Ok(())
}

async fn d252_mysql_or_postgres(
    pool: &DbPool,
    identities: &HashMap<String, Uuid>,
) -> Result<()> {
    let kind = pool.kind();
    let is_pg = kind == DatabaseKind::Postgresql;
    let uuid_ty = if is_pg { "UUID" } else { "CHAR(32)" };

    // Drop FKs pointing to users(username) cleanly.
    let drop_fk_pairs: &[(&str, &str)] = &[
        ("user_passwords", "fk_user_passwords_username_users"),
        ("user_totp_credentials", "fk_user_totp_credentials_username_users"),
        ("user_auth_public_keys", "fk_user_auth_public_keys_username_users"),
        ("user_permissions", "fk_user_permissions_username_users"),
        ("user_memberships", "fk_user_memberships_username_users"),
        ("keyrings", "fk_keyrings_username_users"),
        ("userblock_entries", "fk_userblock_entries_username_users"),
        ("audit_entries", "fk_audit_entries_username_users"),
        ("document_metadata", "fk_document_metadata_creator_username_users"),
        ("document_metadata", "fk_document_metadata_last_modified_by_username_users"),
        ("file_tasks", "fk_file_tasks_issued_by_username_users"),
        ("schedules", "fk_schedules_created_by_users"),
        ("schedules", "fk_schedules_updated_by_users"),
    ];
    let mut pre_drop_stmts = Vec::new();
    for (tbl, fk_name) in drop_fk_pairs {
        if is_pg {
            pre_drop_stmts.push(format!("ALTER TABLE {tbl} DROP CONSTRAINT IF EXISTS {fk_name}"));
        } else {
            pre_drop_stmts.push(format!("ALTER TABLE {tbl} DROP FOREIGN KEY {fk_name}"));
        }
    }
    execute_ddl_statements(pool, &pre_drop_stmts).await?;

    // Add `users.id` and populate it.
    execute_single_ddl(pool, &format!("ALTER TABLE users ADD COLUMN id {uuid_ty}")).await?;
    for (uname, uid) in identities {
        match pool {
            DbPool::Mysql(p) => {
                sqlx::query("UPDATE users SET id = ? WHERE username = ?")
                    .bind(uid.simple().to_string())
                    .bind(uname)
                    .execute(p)
                    .await?;
            }
            DbPool::Postgres(p) => {
                sqlx::query("UPDATE users SET id = $1 WHERE username = $2")
                    .bind(*uid)
                    .bind(uname)
                    .execute(p)
                    .await?;
            }
            DbPool::Sqlite(_) => unreachable!(),
        }
    }

    if is_pg {
        execute_ddl_statements(
            pool,
            &[
                "ALTER TABLE users DROP CONSTRAINT IF EXISTS pk_users".to_string(),
                "ALTER TABLE users ALTER COLUMN id SET NOT NULL".to_string(),
                "ALTER TABLE users ADD CONSTRAINT pk_users PRIMARY KEY (id)".to_string(),
                "CREATE UNIQUE INDEX ix_users_username ON users (username)".to_string(),
            ],
        )
        .await?;
    } else {
        execute_ddl_statements(
            pool,
            &[
                "ALTER TABLE users DROP PRIMARY KEY, MODIFY COLUMN id CHAR(32) NOT NULL, ADD CONSTRAINT pk_users PRIMARY KEY (id)".to_string(),
                "CREATE UNIQUE INDEX ix_users_username ON users (username)".to_string(),
            ],
        )
        .await?;
    }

    // Helper for adding temporary UUID column, populating from `users`, dropping old col, renaming tmp col.
    struct ColMove {
        table: &'static str,
        old_col: &'static str,
        new_col: &'static str,
        nullable: bool,
        in_pk: bool,
        pk_name: &'static str,
        new_pk_cols: &'static str,
        drop_unique: Option<&'static str>,
        create_unique: Option<(&'static str, &'static str)>,
        drop_index: Option<&'static str>,
        create_index: Option<(&'static str, &'static str)>,
        on_delete: &'static str,
    }

    let moves = &[
        ColMove {
            table: "user_passwords",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: true,
            pk_name: "pk_user_passwords",
            new_pk_cols: "user_id",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "CASCADE",
        },
        ColMove {
            table: "user_totp_credentials",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: true,
            pk_name: "pk_user_totp_credentials",
            new_pk_cols: "user_id",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "CASCADE",
        },
        ColMove {
            table: "user_auth_public_keys",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: Some("uq_user_auth_public_keys_user_fingerprint"),
            create_unique: Some(("uq_user_auth_public_keys_user_fingerprint", "user_id, fingerprint")),
            drop_index: None,
            create_index: None,
            on_delete: "CASCADE",
        },
        ColMove {
            table: "user_permissions",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "CASCADE",
        },
        ColMove {
            table: "user_memberships",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "CASCADE",
        },
        ColMove {
            table: "keyrings",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: Some("ix_keyrings_username"),
            create_index: Some(("ix_keyrings_user_id", "user_id")),
            on_delete: "CASCADE",
        },
        ColMove {
            table: "userblock_entries",
            old_col: "username",
            new_col: "user_id",
            nullable: false,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "CASCADE",
        },
        ColMove {
            table: "audit_entries",
            old_col: "username",
            new_col: "user_id",
            nullable: true,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "SET NULL",
        },
        ColMove {
            table: "document_metadata",
            old_col: "creator_username",
            new_col: "creator_id",
            nullable: true,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: Some("ix_document_metadata_creator_username"),
            create_index: Some(("ix_document_metadata_creator_id", "creator_id")),
            on_delete: "SET NULL",
        },
        ColMove {
            table: "document_metadata",
            old_col: "last_modified_by_username",
            new_col: "last_modified_by_id",
            nullable: true,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: Some("ix_document_metadata_last_modified_by_username"),
            create_index: Some(("ix_document_metadata_last_modified_by_id", "last_modified_by_id")),
            on_delete: "SET NULL",
        },
        ColMove {
            table: "file_tasks",
            old_col: "issued_by_username",
            new_col: "issued_by_id",
            nullable: true,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "SET NULL",
        },
        ColMove {
            table: "schedules",
            old_col: "created_by",
            new_col: "created_by",
            nullable: true,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "SET NULL",
        },
        ColMove {
            table: "schedules",
            old_col: "updated_by",
            new_col: "updated_by",
            nullable: true,
            in_pk: false,
            pk_name: "",
            new_pk_cols: "",
            drop_unique: None,
            create_unique: None,
            drop_index: None,
            create_index: None,
            on_delete: "SET NULL",
        },
    ];

    for mv in moves {
        execute_single_ddl(
            pool,
            &format!("ALTER TABLE {} ADD COLUMN _cfms_identity {uuid_ty}", mv.table),
        )
        .await?;

        let update_sql = format!(
            "UPDATE {} SET _cfms_identity = (SELECT u.id FROM users u WHERE u.username = {}.{})",
            mv.table, mv.table, mv.old_col
        );
        match pool {
            DbPool::Mysql(p) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql)).execute(p).await?;
            }
            DbPool::Postgres(p) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql)).execute(p).await?;
            }
            DbPool::Sqlite(_) => unreachable!(),
        }

        let mut stmts = Vec::new();
        if let Some(uq) = mv.drop_unique {
            if is_pg {
                stmts.push(format!("ALTER TABLE {} DROP CONSTRAINT IF EXISTS {uq}", mv.table));
            } else {
                stmts.push(format!("ALTER TABLE {} DROP INDEX {uq}", mv.table));
            }
        }
        if let Some(idx) = mv.drop_index
            && has_index(pool, mv.table, idx).await?
        {
            if is_pg {
                stmts.push(format!("DROP INDEX IF EXISTS {idx}"));
            } else {
                stmts.push(format!("DROP INDEX {idx} ON {}", mv.table));
            }
        }
        if mv.in_pk {
            if is_pg {
                stmts.push(format!("ALTER TABLE {} DROP CONSTRAINT {}", mv.table, mv.pk_name));
            } else {
                stmts.push(format!("ALTER TABLE {} DROP PRIMARY KEY", mv.table));
            }
        }
        stmts.push(format!("ALTER TABLE {} DROP COLUMN {}", mv.table, mv.old_col));
        if is_pg {
            stmts.push(format!(
                "ALTER TABLE {} RENAME COLUMN _cfms_identity TO {}",
                mv.table, mv.new_col
            ));
            if !mv.nullable {
                stmts.push(format!(
                    "ALTER TABLE {} ALTER COLUMN {} SET NOT NULL",
                    mv.table, mv.new_col
                ));
            }
        } else {
            let null_kw = if mv.nullable { "NULL" } else { "NOT NULL" };
            stmts.push(format!(
                "ALTER TABLE {} CHANGE COLUMN _cfms_identity {} CHAR(32) {null_kw}",
                mv.table, mv.new_col
            ));
        }
        if mv.in_pk {
            stmts.push(format!(
                "ALTER TABLE {} ADD CONSTRAINT {} PRIMARY KEY ({})",
                mv.table, mv.pk_name, mv.new_pk_cols
            ));
        }
        if let Some((uq_name, uq_cols)) = mv.create_unique {
            stmts.push(format!(
                "ALTER TABLE {} ADD CONSTRAINT {uq_name} UNIQUE ({uq_cols})",
                mv.table
            ));
        }
        if let Some((idx_name, idx_cols)) = mv.create_index {
            stmts.push(format!("CREATE INDEX {idx_name} ON {} ({idx_cols})", mv.table));
        }
        stmts.push(format!(
            "ALTER TABLE {} ADD CONSTRAINT fk_{}_{}_users FOREIGN KEY ({}) REFERENCES users (id) ON DELETE {}",
            mv.table, mv.table, mv.new_col, mv.new_col, mv.on_delete
        ));
        execute_ddl_statements(pool, &stmts).await?;
    }

    // Rewrite `object_access_entries` grants for entity_type = 'user'.
    let grants: Vec<(i32, String)> = match pool {
        DbPool::Mysql(p) => {
            sqlx::query_as(
                "SELECT id, entity_identifier FROM object_access_entries WHERE entity_type = 'user'",
            )
            .fetch_all(p)
            .await?
        }
        DbPool::Postgres(p) => {
            sqlx::query_as(
                "SELECT id, entity_identifier FROM object_access_entries WHERE entity_type = 'user'",
            )
            .fetch_all(p)
            .await?
        }
        DbPool::Sqlite(_) => unreachable!(),
    };
    for (entry_id, uname) in grants {
        match pool {
            DbPool::Mysql(p) => {
                if let Some(uid) = identities.get(&uname) {
                    sqlx::query("UPDATE object_access_entries SET entity_identifier = ? WHERE id = ?")
                        .bind(uid.hyphenated().to_string())
                        .bind(entry_id)
                        .execute(p)
                        .await?;
                } else {
                    sqlx::query("DELETE FROM object_access_entries WHERE id = ?")
                        .bind(entry_id)
                        .execute(p)
                        .await?;
                }
            }
            DbPool::Postgres(p) => {
                if let Some(uid) = identities.get(&uname) {
                    sqlx::query("UPDATE object_access_entries SET entity_identifier = $1 WHERE id = $2")
                        .bind(uid.hyphenated().to_string())
                        .bind(entry_id)
                        .execute(p)
                        .await?;
                } else {
                    sqlx::query("DELETE FROM object_access_entries WHERE id = $1")
                        .bind(entry_id)
                        .execute(p)
                        .await?;
                }
            }
            DbPool::Sqlite(_) => unreachable!(),
        }
    }

    // risk_ip_accounts & rate_limit_buckets cleanup.
    match pool {
        DbPool::Mysql(p) => {
            sqlx::query("DELETE FROM risk_ip_accounts").execute(p).await?;
            sqlx::query("DELETE FROM rate_limit_buckets WHERE scope = 'account'")
                .execute(p)
                .await?;
        }
        DbPool::Postgres(p) => {
            sqlx::query("DELETE FROM risk_ip_accounts").execute(p).await?;
            sqlx::query("DELETE FROM rate_limit_buckets WHERE scope = 'account'")
                .execute(p)
                .await?;
        }
        DbPool::Sqlite(_) => unreachable!(),
    }

    if is_pg {
        execute_ddl_statements(
            pool,
            &[
                "ALTER TABLE risk_ip_accounts DROP CONSTRAINT pk_risk_ip_accounts".to_string(),
                "ALTER TABLE risk_ip_accounts DROP COLUMN username".to_string(),
                "ALTER TABLE risk_ip_accounts ADD COLUMN user_id UUID NOT NULL".to_string(),
                "ALTER TABLE risk_ip_accounts ADD CONSTRAINT pk_risk_ip_accounts PRIMARY KEY (namespace, ip_address, user_id)".to_string(),
            ],
        )
        .await?;
    } else {
        execute_single_ddl(
            pool,
            "ALTER TABLE risk_ip_accounts DROP PRIMARY KEY, DROP COLUMN username, ADD COLUMN user_id CHAR(32) NOT NULL, ADD CONSTRAINT pk_risk_ip_accounts PRIMARY KEY (namespace, ip_address, user_id)",
        )
        .await?;
    }

    Ok(())
}

async fn step_b2ea9cac8462(pool: &DbPool) -> Result<()> {
    let kind = pool.kind();
    let policies_def = table_def("user_auth_policies").unwrap();
    let mut ddl = vec![policies_def.compile_create_table(kind)];
    ddl.extend(policies_def.compile_create_indexes(kind));
    if !has_table(pool, USER_OIDC_CREDENTIALS_TABLE.name).await? {
        ddl.push(USER_OIDC_CREDENTIALS_TABLE.compile_create_table(kind));
        ddl.extend(USER_OIDC_CREDENTIALS_TABLE.compile_create_indexes(kind));
    }
    execute_ddl_statements(pool, &ddl).await?;

    // Add credential_id to user_passwords and user_totp_credentials.
    for tbl in ["user_passwords", "user_totp_credentials"] {
        if !has_column(pool, tbl, "credential_id").await? {
            execute_single_ddl(pool, &format!("ALTER TABLE {tbl} ADD COLUMN credential_id VARCHAR(32)"))
                .await?;
        }
        let existing_users: Vec<String> = match pool {
            DbPool::Sqlite(p) => {
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT user_id FROM {tbl}")))
                    .fetch_all(p)
                    .await?
            }
            DbPool::Mysql(p) => {
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT user_id FROM {tbl}")))
                    .fetch_all(p)
                    .await?
            }
            DbPool::Postgres(p) => {
                let ids: Vec<Uuid> =
                    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT user_id FROM {tbl}")))
                        .fetch_all(p)
                        .await?;
                ids.into_iter().map(|u| u.hyphenated().to_string()).collect()
            }
        };
        for uid_str in existing_users {
            let token = random_hex(16);
            match pool {
                DbPool::Sqlite(p) => {
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "UPDATE {tbl} SET credential_id = ? WHERE user_id = ?"
                    )))
                    .bind(&token)
                    .bind(&uid_str)
                    .execute(p)
                    .await?;
                }
                DbPool::Mysql(p) => {
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "UPDATE {tbl} SET credential_id = ? WHERE user_id = ?"
                    )))
                    .bind(&token)
                    .bind(&uid_str)
                    .execute(p)
                    .await?;
                }
                DbPool::Postgres(p) => {
                    let uid = Uuid::parse_str(&uid_str).map_err(|e| CfmsError::Database(e.to_string()))?;
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "UPDATE {tbl} SET credential_id = $1 WHERE user_id = $2"
                    )))
                    .bind(&token)
                    .bind(uid)
                    .execute(p)
                    .await?;
                }
            }
        }
        match kind {
            DatabaseKind::Sqlite => {
                let def = table_def(tbl).unwrap();
                let tmp_sql = def.compile_create_table(DatabaseKind::Sqlite).replacen(
                    &format!("CREATE TABLE {tbl}"),
                    &format!("CREATE TABLE _cfms_rebuild_{tbl}"),
                    1,
                );
                let col_list: Vec<&str> = def.columns.iter().map(|c| c.name).collect();
                let joined = col_list.join(", ");
                let copy_sql = format!(
                    "INSERT INTO _cfms_rebuild_{tbl} ({joined}) SELECT {joined} FROM {tbl}"
                );
                sqlite_rebuild_table(pool, tbl, &tmp_sql, &copy_sql, &[]).await?;
            }
            DatabaseKind::Mysql => {
                execute_single_ddl(
                    pool,
                    &format!(
                        "ALTER TABLE {tbl} MODIFY COLUMN credential_id VARCHAR(32) NOT NULL, ADD CONSTRAINT uq_{tbl}_credential_id UNIQUE (credential_id)"
                    ),
                )
                .await?;
            }
            DatabaseKind::Postgresql => {
                execute_ddl_statements(
                    pool,
                    &[
                        format!("ALTER TABLE {tbl} ALTER COLUMN credential_id SET NOT NULL"),
                        format!("ALTER TABLE {tbl} ADD CONSTRAINT uq_{tbl}_credential_id UNIQUE (credential_id)"),
                    ],
                )
                .await?;
            }
        }
    }

    // Seed default policies for all existing users.
    let all_users = fetch_uuid_keys(pool, "SELECT id FROM users").await?;
    let pwd_map = fetch_uuid_string_map(pool, "SELECT user_id, credential_id FROM user_passwords").await?;
    let totp_map = match kind {
        DatabaseKind::Sqlite => {
            fetch_uuid_string_map(
                pool,
                "SELECT user_id, credential_id FROM user_totp_credentials WHERE enabled = 1",
            )
            .await?
        }
        DatabaseKind::Mysql | DatabaseKind::Postgresql => {
            fetch_uuid_string_map(
                pool,
                "SELECT user_id, credential_id FROM user_totp_credentials WHERE enabled = true",
            )
            .await?
        }
    };

    for uid in all_users {
        let login_chains = if let Some(cid) = pwd_map.get(&uid) {
            serde_json::json!([[{ "method": "password", "credential_ids": [cid] }]])
        } else {
            serde_json::json!([])
        };
        let mfa_chains = if let Some(cid) = totp_map.get(&uid) {
            serde_json::json!([[{ "method": "totp", "credential_ids": [cid] }]])
        } else {
            serde_json::json!([])
        };
        let esc_chains = serde_json::json!([]);
        let defaults = [
            ("login", login_chains),
            ("mfa", mfa_chains),
            ("escalation", esc_chains),
        ];
        for (purpose, chains) in defaults {
            match pool {
                DbPool::Sqlite(p) => {
                    sqlx::query(
                        "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES (?, ?, 1, ?)",
                    )
                    .bind(uid.simple().to_string())
                    .bind(purpose)
                    .bind(chains.to_string())
                    .execute(p)
                    .await?;
                }
                DbPool::Mysql(p) => {
                    sqlx::query(
                        "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES (?, ?, 1, ?)",
                    )
                    .bind(uid.simple().to_string())
                    .bind(purpose)
                    .bind(&chains)
                    .execute(p)
                    .await?;
                }
                DbPool::Postgres(p) => {
                    sqlx::query(
                        "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES ($1, $2, 1, $3)",
                    )
                    .bind(uid)
                    .bind(purpose)
                    .bind(&chains)
                    .execute(p)
                    .await?;
                }
            }
        }
    }

    Ok(())
}

async fn fetch_uuid_keys(pool: &DbPool, sql: &str) -> Result<Vec<Uuid>> {
    match pool {
        DbPool::Sqlite(p) => {
            let strs: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?;
            strs.into_iter()
                .map(|s| Uuid::parse_str(&s).map_err(|e| CfmsError::Database(e.to_string())))
                .collect()
        }
        DbPool::Mysql(p) => {
            let strs: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?;
            strs.into_iter()
                .map(|s| Uuid::parse_str(&s).map_err(|e| CfmsError::Database(e.to_string())))
                .collect()
        }
        DbPool::Postgres(p) => Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?),
    }
}

async fn fetch_uuid_string_map(pool: &DbPool, sql: &str) -> Result<BTreeMap<Uuid, String>> {
    let mut map = BTreeMap::new();
    match pool {
        DbPool::Sqlite(p) => {
            let rows: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?;
            for (u, val) in rows {
                map.insert(
                    Uuid::parse_str(&u).map_err(|e| CfmsError::Database(e.to_string()))?,
                    val,
                );
            }
        }
        DbPool::Mysql(p) => {
            let rows: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?;
            for (u, val) in rows {
                map.insert(
                    Uuid::parse_str(&u).map_err(|e| CfmsError::Database(e.to_string()))?,
                    val,
                );
            }
        }
        DbPool::Postgres(p) => {
            let rows: Vec<(Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?;
            for (u, val) in rows {
                map.insert(u, val);
            }
        }
    }
    Ok(map)
}

async fn step_3815ba18197b(pool: &DbPool) -> Result<()> {
    let missing_ids = fetch_uuid_keys(
        pool,
        "SELECT id FROM users WHERE secret_key IS NULL OR length(secret_key) = 0",
    )
    .await?;
    for uid in missing_ids {
        let secret = random_hex(32);
        match pool {
            DbPool::Sqlite(p) => {
                sqlx::query("UPDATE users SET secret_key = ? WHERE id = ?")
                    .bind(&secret)
                    .bind(uid.simple().to_string())
                    .execute(p)
                    .await?;
            }
            DbPool::Mysql(p) => {
                sqlx::query("UPDATE users SET secret_key = ? WHERE id = ?")
                    .bind(&secret)
                    .bind(uid.simple().to_string())
                    .execute(p)
                    .await?;
            }
            DbPool::Postgres(p) => {
                sqlx::query("UPDATE users SET secret_key = $1 WHERE id = $2")
                    .bind(&secret)
                    .bind(uid)
                    .execute(p)
                    .await?;
            }
        }
    }

    match pool.kind() {
        DatabaseKind::Sqlite => {
            let def = table_def("users").unwrap();
            let tmp_sql = def.compile_create_table(DatabaseKind::Sqlite).replacen(
                "CREATE TABLE users",
                "CREATE TABLE _cfms_rebuild_users",
                1,
            );
            let cols: Vec<&str> = def.columns.iter().map(|c| c.name).collect();
            let joined = cols.join(", ");
            let copy_sql =
                format!("INSERT INTO _cfms_rebuild_users ({joined}) SELECT {joined} FROM users");
            let idxs = def.compile_create_indexes(DatabaseKind::Sqlite);
            sqlite_rebuild_table(pool, "users", &tmp_sql, &copy_sql, &idxs).await
        }
        DatabaseKind::Mysql => {
            execute_single_ddl(
                pool,
                "ALTER TABLE users MODIFY COLUMN secret_key VARCHAR(64) NOT NULL, ADD CONSTRAINT ck_users_secret_key_nonempty CHECK (length(secret_key) > 0)",
            )
            .await
        }
        DatabaseKind::Postgresql => {
            execute_ddl_statements(
                pool,
                &[
                    "ALTER TABLE users ALTER COLUMN secret_key SET NOT NULL".to_string(),
                    "ALTER TABLE users ADD CONSTRAINT ck_users_secret_key_nonempty CHECK (length(secret_key) > 0)".to_string(),
                ],
            )
            .await
        }
    }
}

async fn step_03197fed3401(pool: &DbPool) -> Result<()> {
    const RENAMES: &[(&str, &str)] = &[
        ("rename_user", "set_nickname"),
        ("super_rename_user", "super_set_nickname"),
    ];
    for table in ["user_permissions", "group_permissions"] {
        for &(old_name, new_name) in RENAMES {
            match pool {
                DbPool::Sqlite(p) => {
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "UPDATE {table} SET permission = ? WHERE permission = ?"
                    )))
                    .bind(new_name)
                    .bind(old_name)
                    .execute(p)
                    .await?;
                }
                DbPool::Mysql(p) => {
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "UPDATE {table} SET permission = ? WHERE permission = ?"
                    )))
                    .bind(new_name)
                    .bind(old_name)
                    .execute(p)
                    .await?;
                }
                DbPool::Postgres(p) => {
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "UPDATE {table} SET permission = $1 WHERE permission = $2"
                    )))
                    .bind(new_name)
                    .bind(old_name)
                    .execute(p)
                    .await?;
                }
            }
        }
    }
    Ok(())
}

async fn step_16c86712512a(pool: &DbPool) -> Result<()> {
    if has_table(pool, "options").await? {
        return Ok(());
    }
    let kind = pool.kind();
    let def = table_def("options").unwrap();
    let mut ddl = vec![def.compile_create_table(kind)];
    ddl.extend(def.compile_create_indexes(kind));
    execute_ddl_statements(pool, &ddl).await
}

async fn step_e952c02c1454(pool: &DbPool) -> Result<()> {
    grant_sysop_permissions(
        pool,
        Some("migration:e952c02c1454"),
        &["view_settings", "manage_settings"],
    )
    .await
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
        assert_eq!(inspector.present_core_tables, 40);

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
    async fn full_historical_upgrade_from_fe8863687aa4_to_head_preserves_and_migrates_data() {
        let dir = tempdir().unwrap();
        let pool = open_sqlite_test_pool(&dir.path().join("legacy.db")).await;
        let DbPool::Sqlite(p) = &pool else {
            unreachable!();
        };

        // Construct realistic historical schema at root revision `fe8863687aa4`.
        let stmts: Vec<String> = vec![
            table_def("files").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("comments").unwrap().compile_create_table(DatabaseKind::Sqlite),
            // Legacy `users` keyed by `username` before `5ad5aca75635` and `d252e662fc05`
            "CREATE TABLE users (\n\
                username VARCHAR(256) NOT NULL,\n\
                nickname VARCHAR(255),\n\
                pass_hash TEXT,\n\
                passwd_last_modified DOUBLE NOT NULL,\n\
                avatar_id VARCHAR(255),\n\
                last_login DOUBLE,\n\
                created_time DOUBLE NOT NULL,\n\
                status INTEGER NOT NULL,\n\
                status_comment_id INTEGER,\n\
                totp_secret VARCHAR(32),\n\
                totp_enabled BOOLEAN NOT NULL,\n\
                totp_backup_codes TEXT,\n\
                secret_key VARCHAR(64),\n\
                preference_dek_id VARCHAR(64),\n\
                CONSTRAINT pk_users PRIMARY KEY (username),\n\
                CONSTRAINT fk_users_avatar_id_files FOREIGN KEY(avatar_id) REFERENCES files (id) ON DELETE RESTRICT,\n\
                CONSTRAINT fk_users_status_comment_id_comments FOREIGN KEY(status_comment_id) REFERENCES comments (comment_id) ON DELETE SET NULL,\n\
                CONSTRAINT fk_users_preference_dek_id FOREIGN KEY(preference_dek_id) REFERENCES keyrings (id) ON DELETE SET NULL\n\
            )"
            .to_string(),
            table_def("user_groups").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("group_permissions").unwrap().compile_create_table(DatabaseKind::Sqlite),
            "CREATE TABLE user_memberships (\n\
                id INTEGER NOT NULL,\n\
                username VARCHAR(256) NOT NULL,\n\
                group_name VARCHAR(256) NOT NULL,\n\
                start_time DOUBLE,\n\
                end_time DOUBLE,\n\
                CONSTRAINT pk_user_memberships PRIMARY KEY (id),\n\
                CONSTRAINT uq_user_memberships_username_group UNIQUE (username, group_name),\n\
                CONSTRAINT fk_user_memberships_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE,\n\
                CONSTRAINT fk_user_memberships_group_name_user_groups FOREIGN KEY(group_name) REFERENCES user_groups (group_name) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE user_permissions (\n\
                id INTEGER NOT NULL,\n\
                username VARCHAR(256) NOT NULL,\n\
                permission VARCHAR(64) NOT NULL,\n\
                granted BOOLEAN NOT NULL,\n\
                start_time DOUBLE NOT NULL,\n\
                end_time DOUBLE,\n\
                CONSTRAINT pk_user_permissions PRIMARY KEY (id),\n\
                CONSTRAINT fk_user_permissions_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE\n\
            )"
            .to_string(),
            "CREATE TABLE keyrings (\n\
                id VARCHAR(64) NOT NULL,\n\
                username VARCHAR(256) NOT NULL,\n\
                content TEXT NOT NULL,\n\
                label VARCHAR(255),\n\
                created_time DOUBLE NOT NULL,\n\
                CONSTRAINT pk_keyrings PRIMARY KEY (id),\n\
                CONSTRAINT fk_keyrings_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE\n\
            )"
            .to_string(),
            // Legacy `nodes` with `active_parent_id` prior to `170e0a16133e`
            "CREATE TABLE nodes (\n\
                id VARCHAR(255) NOT NULL,\n\
                type VARCHAR(16) NOT NULL,\n\
                name VARCHAR(255) NOT NULL,\n\
                parent_id VARCHAR(255),\n\
                active_parent_id VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN status = 1 THEN NULL ELSE parent_id END) STORED,\n\
                inherit BOOLEAN NOT NULL,\n\
                status INTEGER NOT NULL,\n\
                status_operation_id VARCHAR(255),\n\
                access_rule_set_id VARCHAR(32),\n\
                CONSTRAINT pk_nodes PRIMARY KEY (id),\n\
                CONSTRAINT ck_nodes_root_parent CHECK (id = '/' AND parent_id IS NULL AND type = 'directory' OR id != '/' AND parent_id IS NOT NULL),\n\
                CONSTRAINT uq_nodes_active_parent_name UNIQUE (active_parent_id, name),\n\
                CONSTRAINT fk_nodes_parent_id_folders FOREIGN KEY(parent_id) REFERENCES folders (id) ON DELETE CASCADE,\n\
                CONSTRAINT fk_nodes_access_rule_set_id_compiled_access_rule_sets FOREIGN KEY(access_rule_set_id) REFERENCES compiled_access_rule_sets (id)\n\
            )"
            .to_string(),
            table_def("folders").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("documents").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("document_revisions").unwrap().compile_create_table(DatabaseKind::Sqlite),
            "CREATE TABLE document_metadata (\n\
                document_id VARCHAR(255) NOT NULL,\n\
                creator_username VARCHAR(256),\n\
                last_modified_by_username VARCHAR(256),\n\
                CONSTRAINT pk_document_metadata PRIMARY KEY (document_id),\n\
                CONSTRAINT fk_document_metadata_document_id_documents FOREIGN KEY(document_id) REFERENCES documents (id) ON DELETE CASCADE,\n\
                CONSTRAINT fk_document_metadata_creator_username_users FOREIGN KEY(creator_username) REFERENCES users (username) ON DELETE SET NULL,\n\
                CONSTRAINT fk_document_metadata_last_modified_by_username_users FOREIGN KEY(last_modified_by_username) REFERENCES users (username) ON DELETE SET NULL\n\
            )"
            .to_string(),
            table_def("document_metadata_tags").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("object_access_entries").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("compiled_access_rule_sets").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("compiled_access_rules").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("compiled_access_rule_groups").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("compiled_access_rule_memberships").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("compiled_access_rule_rights").unwrap().compile_create_table(DatabaseKind::Sqlite),
            "CREATE TABLE audit_entries (\n\
                id VARCHAR(255) NOT NULL,\n\
                action VARCHAR(255) NOT NULL,\n\
                username VARCHAR(256),\n\
                target VARCHAR(255),\n\
                data JSON,\n\
                result INTEGER NOT NULL,\n\
                remote_address VARCHAR(64),\n\
                logged_time DOUBLE NOT NULL,\n\
                CONSTRAINT pk_audit_entries PRIMARY KEY (id),\n\
                CONSTRAINT fk_audit_entries_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE SET NULL\n\
            )"
            .to_string(),
            "CREATE TABLE userblock_entries (\n\
                block_id VARCHAR(32) NOT NULL,\n\
                username VARCHAR(256) NOT NULL,\n\
                timestamp DOUBLE NOT NULL,\n\
                not_before DOUBLE NOT NULL,\n\
                not_after DOUBLE NOT NULL,\n\
                target_type VARCHAR(32) NOT NULL,\n\
                target_id VARCHAR(255),\n\
                CONSTRAINT pk_userblock_entries PRIMARY KEY (block_id),\n\
                CONSTRAINT fk_userblock_entries_username_users FOREIGN KEY(username) REFERENCES users (username) ON DELETE CASCADE\n\
            )"
            .to_string(),
            table_def("userblock_sub_entries").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("banned_subnets").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("account_throttles").unwrap().compile_create_table(DatabaseKind::Sqlite),
            "CREATE TABLE file_tasks (\n\
                id VARCHAR(255) NOT NULL,\n\
                file_id VARCHAR(255) NOT NULL,\n\
                status INTEGER NOT NULL,\n\
                mode INTEGER NOT NULL,\n\
                start_time DOUBLE NOT NULL,\n\
                end_time DOUBLE,\n\
                issued_by_username VARCHAR(256),\n\
                encryption_key VARCHAR(256),\n\
                chunk_size INTEGER,\n\
                upload_file_size BIGINT,\n\
                upload_sha256 VARCHAR(64),\n\
                upload_session_id TEXT,\n\
                upload_checkpoint_size BIGINT,\n\
                upload_checkpoint_data TEXT,\n\
                CONSTRAINT pk_file_tasks PRIMARY KEY (id),\n\
                CONSTRAINT ck_file_tasks_status_value CHECK (status IN (0, 1, 2, 3, 4)),\n\
                CONSTRAINT fk_file_tasks_file_id_files FOREIGN KEY(file_id) REFERENCES files (id) ON DELETE CASCADE,\n\
                CONSTRAINT fk_file_tasks_issued_by_username_users FOREIGN KEY(issued_by_username) REFERENCES users (username) ON DELETE SET NULL\n\
            )"
            .to_string(),
            table_def("login_throttles").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("rate_limit_buckets").unwrap().compile_create_table(DatabaseKind::Sqlite),
            "CREATE TABLE risk_ip_accounts (\n\
                namespace VARCHAR(64) NOT NULL,\n\
                ip_address VARCHAR(45) NOT NULL,\n\
                username VARCHAR(256) NOT NULL,\n\
                last_attempt DOUBLE NOT NULL,\n\
                CONSTRAINT pk_risk_ip_accounts PRIMARY KEY (namespace, ip_address, username)\n\
            )"
            .to_string(),
            table_def("system_states").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("traffic_throttles").unwrap().compile_create_table(DatabaseKind::Sqlite),
            table_def("file_deduplication_tasks").unwrap().compile_create_table(DatabaseKind::Sqlite),
        ];

        execute_ddl_statements(&pool, &stmts).await.unwrap();
        set_alembic_version(&pool, ROOT_SCHEMA_REVISION).await.unwrap();

        // Populate legacy rows across users, passwords, TOTP, keyrings, groups, permissions (with rename_user),
        // nodes tree, object_access_entries, audit_entries, userblock_entries, and rate_limit_buckets.
        sqlx::query("INSERT INTO user_groups (group_name, group_display_name) VALUES ('sysop', 'Sysop Admins')")
            .execute(p)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO users (username, nickname, pass_hash, passwd_last_modified, created_time, status, totp_secret, totp_enabled) \
             VALUES ('alice', 'Alice', 'argon2$hash', 10.0, 1.0, 0, 'JBSWY3DPEHPK3PXP', 1)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query("INSERT INTO keyrings (id, username, content, label, created_time) VALUES ('dek-1', 'alice', '{}', 'k1', 2.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET preference_dek_id = 'dek-1' WHERE username = 'alice'")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_permissions (username, permission, granted, start_time) VALUES ('alice', 'rename_user', 1, 0.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO group_permissions (group_name, permission, granted, start_time) VALUES ('sysop', 'super_rename_user', 1, 0.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_memberships (username, group_name, start_time) VALUES ('alice', 'sysop', 0.0)")
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
        sqlx::query("INSERT INTO object_access_entries (entity_type, entity_identifier, target_type, target_identifier, access_type, start_time) VALUES ('user', 'alice', 'folder', '/', 'read', 0.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO userblock_entries (block_id, username, timestamp, not_before, not_after, target_type) VALUES ('blk-1', 'alice', 1.0, 1.0, 9.0, 'login')")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO risk_ip_accounts (namespace, ip_address, username, last_attempt) VALUES ('auth', '127.0.0.1', 'alice', 5.0)")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("INSERT INTO rate_limit_buckets (namespace, scope, identity, tokens, last_refill_at, denial_count, last_attempt) VALUES ('login', 'account', 'alice', 5.0, 5.0, 0, 5.0)")
            .execute(p)
            .await
            .unwrap();

        let outcome = upgrade_database_schema(&pool)
            .await
            .expect("full 19-step upgrade from fe8863687aa4");
        assert!(!outcome.bootstrapped);
        assert_eq!(outcome.previous_revision.as_deref(), Some(ROOT_SCHEMA_REVISION));
        assert_eq!(outcome.current_revision, LATEST_SCHEMA_REVISION);
        assert_eq!(outcome.applied_revisions.len(), 19);

        let inspector = SchemaInspector::inspect(&pool).await.unwrap();
        assert!(inspector.healthy);
        assert_eq!(inspector.present_core_tables, 40);

        // Verify data migrations across revisions:
        let alice_id: String =
            sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
                .fetch_one(p)
                .await
                .unwrap();
        let parsed_uid = Uuid::parse_str(&alice_id).expect("valid uuid");
        let secret_key: String =
            sqlx::query_scalar("SELECT secret_key FROM users WHERE username = 'alice'")
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(secret_key.len(), 64);

        // 5ad5aca75635 + b2ea9cac8462: password & TOTP moved & credential_id generated & policy seeded
        let pwd_cred_id: String =
            sqlx::query_scalar("SELECT credential_id FROM user_passwords WHERE user_id = ?")
                .bind(&alice_id)
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(pwd_cred_id.len(), 32);

        let policy_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM user_auth_policies WHERE user_id = ?")
                .bind(&alice_id)
                .fetch_one(p)
                .await
                .unwrap();
        assert!(policy_count >= 1);

        // d252e662fc05: object_access_entries rewritten to hyphenated UUID, account rate limit pruned
        let entity_id: String = sqlx::query_scalar(
            "SELECT entity_identifier FROM object_access_entries WHERE entity_type = 'user'",
        )
        .fetch_one(p)
        .await
        .unwrap();
        assert_eq!(entity_id, parsed_uid.hyphenated().to_string());

        let acct_buckets: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_buckets WHERE scope = 'account'")
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(acct_buckets, 0);

        // 03197fed3401: rename_user / super_rename_user renamed
        let user_perm: String =
            sqlx::query_scalar("SELECT permission FROM user_permissions WHERE user_id = ?")
                .bind(&alice_id)
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(user_perm, "set_nickname");

        // b4b3061f385c + 8c130010a943 + e952c02c1454: sysop permissions seeded
        let sysop_perms: Vec<String> = sqlx::query_scalar(
            "SELECT permission FROM group_permissions WHERE group_name = 'sysop'",
        )
        .fetch_all(p)
        .await
        .unwrap();
        for expected in [
            "super_set_nickname",
            "diagnostics",
            "view_schedules",
            "manage_schedules",
            "view_settings",
            "manage_settings",
        ] {
            assert!(
                sysop_perms.iter().any(|x| x == expected),
                "missing expected sysop permission '{expected}', found: {sysop_perms:?}"
            );
        }
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
