//! Orchestrators for deployment `status`, `verify`, `check`, `upgrade`, `update`,
//! `resume`, `prune`, `install`, and `adopt`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;

use crate::cli::deployment::{
    DeploymentAdoptArgs, DeploymentCheckArgs, DeploymentInstallArgs, DeploymentPruneArgs,
    DeploymentResumeArgs, DeploymentStatusArgs, DeploymentUpdateArgs, DeploymentUpgradeArgs,
    DeploymentVerifyArgs, LocalChecksumArgs,
};
use crate::core::{
    CfmsError, ConfigDocument, Result, RuntimeLock, WorkspacePaths, atomic_write,
    ensure_safe_directory_chain, retry_fs_op,
};
use crate::db::schema::analyze_alembic_directory;
use crate::ops::AppContext;
use crate::ops::extension::catalog::discover_catalog;
use crate::ops::extension::version::{
    CfmsServerVersion, check_server_compatibility, discover_server_version,
};
use crate::ui::{OutputFormat, confirm_or_abort};

use super::archive::{stage_release_archive, verify_staged_release_tree};
use super::database::{
    ResumeDbClassification, analyze_release_alembic, capture_sqlite_upgrade_checkpoint,
    diagnose_resume_database, execute_deployment_db_upgrade, initialize_fresh_database,
    inspect_status_database, maybe_create_safety_backup, preflight_upgrade_database,
    rollback_upgrade_database,
};
use super::environment::{
    check_target_python_compatibility, plan_environment_options, sync_python_environment,
};
use super::manifest::{hash_file_sha256, load_manifest_file, validate_workspace_layout};
use super::models::{
    DeploymentMutationReport, DeploymentPruneReport, DeploymentSettings, DeploymentStatusReport,
    DeploymentTransaction, DeploymentVerifyReport, RELEASE_MANIFEST_FILENAME, RELEASE_SUBDIR,
    ReleaseIntegrityReport, ReleaseManifestSummary, TRANSACTION_FORMAT_VERSION,
    TransactionOperation, TransactionPhase,
};
use super::online::{
    OnlineClientConfig, check_github_release_with_config, download_verified_github_release,
    fetch_and_resolve_release, fetch_and_resolve_release_with_config, resolve_online_config,
};
use super::repository::{
    PruneSelector, apply_swap_with_journal, auto_prune_versions_keep_limit,
    clear_transaction_artifacts, compute_delta_counts, copy_file_atomic_with_retry, execute_prune,
    inspect_active_release, list_stored_releases, load_settings, load_transaction, plan_prune,
    remove_stored_release_dir, requirements_lock_path, resolve_stored_release,
    restore_snapshot_config, rollback_swap_journal, save_settings, save_transaction,
    snapshot_active_release, staging_dir, sync_persisted_requirements_lock, tx_root_dir,
    versions_dir,
};

fn ensure_confirmed(ctx: &AppContext, prompt: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    if ctx.ui.format() == OutputFormat::Json && !ctx.global.yes {
        return Err(CfmsError::InvalidArgument(
            "Pass `--yes` (`-y`) when running mutating deployment commands with `--output json`"
                .to_string(),
        ));
    }
    confirm_or_abort(prompt, ctx.global.yes)
}

fn preview_or_apply_config_merge(
    paths: &WorkspacePaths,
    base_template_doc: Option<&ConfigDocument>,
    new_template_path: &Path,
    write: bool,
) -> Result<(bool, Option<String>, Vec<String>)> {
    if !paths.config_path.is_file() || !new_template_path.is_file() {
        return Ok((false, None, Vec::new()));
    }
    let mut current = ConfigDocument::load(&paths.config_path)?;
    let new_template = ConfigDocument::load(new_template_path)?;
    let plan = match base_template_doc {
        Some(base) => current.merge_three_way(base, &new_template, &[], false)?,
        None => current.sync_with_template(&new_template, &[], false)?,
    };

    if plan.changed && write {
        let bak = current.save_with_backup()?;
        return Ok((true, Some(bak.display().to_string()), plan.warnings));
    }
    Ok((plan.changed, None, plan.warnings))
}

fn check_extension_compat_warnings(
    paths: &WorkspacePaths,
    target_version_raw: &str,
) -> Result<Vec<String>> {
    if !paths.extensions_root.is_dir() {
        return Ok(Vec::new());
    }
    let target_ver = CfmsServerVersion::parse(target_version_raw)?;
    let catalog = discover_catalog(&paths.extensions_root)?;
    let mut warnings = Vec::new();
    for ext in catalog.extensions.values() {
        if ext.builtin {
            continue;
        }
        if let Err(reason) = check_server_compatibility(
            &target_ver,
            ext.minimum_server_version.as_ref(),
            ext.maximum_server_version.as_ref(),
        ) {
            warnings.push(format!(
                "Third-party extension '{}' may be incompatible with v{target_version_raw}: {reason}",
                ext.identifier
            ));
        }
    }
    Ok(warnings)
}

/// Inspect deployment metadata, lock/transaction state, DB revision, and stored snapshots.
pub async fn handle_status(ctx: &AppContext, args: DeploymentStatusArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let active_manifest = if paths.release_manifest_path.is_file() {
        Some(load_manifest_file(&paths.release_manifest_path)?)
    } else {
        None
    };

    let mut warnings = Vec::new();
    let (active_healthy, active_issues) = if active_manifest.is_some() {
        let integrity = inspect_active_release(&paths, args.verify)?;
        let issues: Vec<String> = integrity
            .mismatches
            .into_iter()
            .map(|mm| format!("{} ({}): {}", mm.path, mm.kind, mm.detail))
            .collect();
        (issues.is_empty(), issues)
    } else {
        (true, Vec::new())
    };

    let active_id = active_manifest.as_ref().map(|m| m.release_id.clone());
    let detected_version = match active_manifest.as_ref() {
        Some(m) => Some(m.manifest.version.clone()),
        None => match discover_server_version(&paths) {
            Ok(detected) => Some(detected.version.to_string()),
            Err(err) => {
                warnings.push(format!("Unable to determine CFMS server version: {err}"));
                None
            }
        },
    };

    let active_summary = active_manifest.as_ref().map(|m| ReleaseManifestSummary {
        release_id: Some(m.release_id.clone()),
        version: Some(m.manifest.version.clone()),
        schema_revision: None,
        created_at: None,
    });

    let mode = if paths.project_root.join(".git").exists() {
        "git-checkout".to_string()
    } else if active_manifest.is_some() {
        "packaged-flat".to_string()
    } else {
        "unpacked-unmanaged".to_string()
    };

    let settings = load_settings(&paths).unwrap_or_else(|err| {
        warnings.push(format!("Unable to read deployment settings: {err}"));
        DeploymentSettings::default()
    });
    let has_requirements_lock = requirements_lock_path(&paths).is_file();
    let runtime_lock_holder_pid = RuntimeLock::holder_pid(&paths);
    let transaction = load_transaction(&paths).unwrap_or_else(|err| {
        warnings.push(format!("Unable to parse transaction.json: {err}"));
        None
    });

    let stored_releases =
        list_stored_releases(&paths, active_id.as_deref(), args.verify).unwrap_or_else(|err| {
            warnings.push(format!("Unable to inspect stored snapshots: {err}"));
            Vec::new()
        });

    let (database_backend, database_revision, alembic_head, db_warnings) =
        inspect_status_database(ctx, &paths).await;
    warnings.extend(db_warnings);

    let report = DeploymentStatusReport {
        project_root: paths.project_root.display().to_string(),
        mode,
        detected_version,
        active_release: active_summary,
        active_release_healthy: active_healthy,
        active_issues,
        verified_hashes: args.verify,
        extras: settings.extras,
        has_requirements_lock,
        runtime_lock_holder_pid,
        unfinished_transaction: transaction.is_some(),
        transaction,
        database_backend,
        database_revision,
        alembic_head,
        stored_releases,
        warnings,
    };
    ctx.ui.render(&report);
    Ok(())
}

/// Deep-verify cryptographic SHA-256 integrity of active deployment and/or stored snapshots.
pub async fn handle_verify(ctx: &AppContext, args: DeploymentVerifyArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    validate_workspace_layout(&paths, false)?;

    let mut reports = Vec::new();
    if let Some(ref target_query) = args.release {
        let active_id = paths
            .release_manifest_path
            .is_file()
            .then(|| load_manifest_file(&paths.release_manifest_path))
            .transpose()?
            .map(|m| m.release_id);
        match resolve_stored_release(&paths, Some(target_query), None, active_id.as_deref()) {
            Ok(handle) => {
                reports.push(ReleaseIntegrityReport {
                    target: format!("stored:{}", handle.summary.release_id),
                    release_id: Some(handle.summary.release_id),
                    version: handle.summary.version,
                    healthy: true,
                    checked_files: handle.summary.file_count,
                    verified_hashes: true,
                    mismatches: Vec::new(),
                });
            }
            Err(err) => {
                reports.push(ReleaseIntegrityReport {
                    target: format!("stored:{target_query}"),
                    release_id: None,
                    version: None,
                    healthy: false,
                    checked_files: 0,
                    verified_hashes: true,
                    mismatches: vec![super::models::IntegrityMismatch {
                        path: target_query.clone(),
                        kind: "verification-error".to_string(),
                        detail: err.to_string(),
                    }],
                });
            }
        }
    } else {
        if paths.release_manifest_path.is_file() {
            reports.push(inspect_active_release(&paths, true)?);
        }
        if !args.active_only {
            let active_id = reports.first().and_then(|r| r.release_id.as_deref()).map(str::to_string);
            for rel in list_stored_releases(&paths, active_id.as_deref(), true)? {
                let mismatches = rel
                    .issues
                    .into_iter()
                    .map(|detail| super::models::IntegrityMismatch {
                        path: rel.release_id.clone(),
                        kind: "snapshot-issue".to_string(),
                        detail,
                    })
                    .collect();
                reports.push(ReleaseIntegrityReport {
                    target: format!("stored:{}", rel.release_id),
                    release_id: Some(rel.release_id),
                    version: rel.version,
                    healthy: rel.healthy,
                    checked_files: rel.file_count,
                    verified_hashes: true,
                    mismatches,
                });
            }
        }
    }

    let overall_healthy = reports.iter().all(|r| r.healthy);
    let out = DeploymentVerifyReport {
        overall_healthy,
        reports,
    };
    ctx.ui.render(&out);
    if !overall_healthy {
        return Err(CfmsError::ArchiveIntegrity(
            "One or more deployment release trees failed SHA-256 verification".to_string(),
        ));
    }
    Ok(())
}

/// Check GitHub Releases against the active deployment.
pub async fn handle_check(ctx: &AppContext, args: DeploymentCheckArgs) -> Result<()> {
    let cfg = resolve_online_config(args.online.repo.as_deref())?;
    run_check_with_config(ctx, args, &cfg).await
}

/// Check GitHub Releases against the active deployment using an explicit client configuration.
pub async fn run_check_with_config(
    ctx: &AppContext,
    args: DeploymentCheckArgs,
    cfg: &OnlineClientConfig,
) -> Result<()> {
    let mut check_warnings = Vec::new();
    let current_version = match ctx.resolve_paths() {
        Ok(p) => {
            if p.release_manifest_path.is_file() {
                match load_manifest_file(&p.release_manifest_path) {
                    Ok(m) => Some(m.manifest.version),
                    Err(err) => {
                        check_warnings.push(format!(
                            "Unable to read release-manifest.json for current version comparison: {err}"
                        ));
                        None
                    }
                }
            } else {
                match discover_server_version(&p) {
                    Ok(d) => Some(d.version.to_string()),
                    Err(err) => {
                        check_warnings.push(format!(
                            "Unable to determine current CFMS server version: {err}"
                        ));
                        None
                    }
                }
            }
        }
        Err(_) => None,
    };
    let mut report =
        check_github_release_with_config(cfg, &args.online, current_version.as_deref(), false)
            .await?;
    report.warnings.extend(check_warnings);
    ctx.ui.render(&report);
    Ok(())
}

/// Stage, verify, migrate, and atomically activate a local archive upgrade.
pub async fn handle_upgrade(ctx: &AppContext, args: DeploymentUpgradeArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    run_upgrade_flow(
        ctx,
        &paths,
        "upgrade",
        &args.package,
        &args.checksum,
        &args.env,
        &args.backup,
        args.allow_destructive,
        args.dry_run,
        Vec::new(),
    )
    .await
}

/// Download and activate an official GitHub release when newer or pinned.
pub async fn handle_update(ctx: &AppContext, args: DeploymentUpdateArgs) -> Result<()> {
    let cfg = resolve_online_config(args.online.repo.as_deref())?;
    run_update_with_config(ctx, args, &cfg).await
}

/// Download and activate an official GitHub release using an explicit client configuration.
pub async fn run_update_with_config(
    ctx: &AppContext,
    args: DeploymentUpdateArgs,
    cfg: &OnlineClientConfig,
) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    validate_workspace_layout(&paths, true)?;
    let _pre_lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let active = load_manifest_file(&paths.release_manifest_path)?;
    let check = check_github_release_with_config(
        cfg,
        &args.online,
        Some(&active.manifest.version),
        args.require_github_digest,
    )
    .await?;

    if !check.update_available {
        let report = DeploymentMutationReport {
            operation: "update".to_string(),
            dry_run: args.dry_run,
            outcome: "up-to-date".to_string(),
            source_release_id: Some(active.release_id),
            source_version: Some(active.manifest.version.clone()),
            target_release_id: None,
            target_version: Some(check.target_version),
            checksum: None,
            files_added: 0,
            files_updated: 0,
            files_removed: 0,
            extras: load_settings(&paths)?.extras,
            config_changed: false,
            config_backup_path: None,
            db_revision_before: None,
            db_revision_after: None,
            backup_archive_path: None,
            backup_generated_key: None,
            warnings: check.warnings,
            next_steps: Vec::new(),
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    let resolved =
        fetch_and_resolve_release_with_config(cfg, &args.online, args.require_github_digest)
            .await?;
    let extra_warnings = resolved.warnings.clone();
    let downloaded = download_verified_github_release(resolved, ctx.ui.format()).await?;
    let checksum = LocalChecksumArgs {
        sha256: Some(downloaded.sha256.clone()),
        checksums: None,
    };

    // Release `_pre_lock` cleanly right before `run_upgrade_flow` acquires its own RAII lock.
    drop(_pre_lock);
    run_upgrade_flow(
        ctx,
        &paths,
        "update",
        &downloaded.package_path,
        &checksum,
        &args.env,
        &args.backup,
        args.allow_destructive,
        args.dry_run,
        extra_warnings,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_upgrade_flow(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    op_label: &str,
    package_path: &Path,
    checksum: &LocalChecksumArgs,
    env_args: &crate::cli::deployment::DeploymentEnvArgs,
    backup_args: &crate::cli::deployment::SafetyBackupArgs,
    allow_destructive: bool,
    dry_run: bool,
    mut warnings: Vec<String>,
) -> Result<()> {
    validate_workspace_layout(paths, true)?;
    let _lock = if dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(paths, false)?)
    };

    let source_manifest = load_manifest_file(&paths.release_manifest_path)?;
    let active_report = inspect_active_release(paths, true)?;
    if !active_report.healthy {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Active deployment release tree has integrity mismatches: {:?}",
            active_report.mismatches
        )));
    }

    let current_settings = load_settings(paths)?;
    let env_plan = plan_environment_options(
        paths,
        &current_settings,
        &env_args.extras,
        env_args.clear_extras,
        env_args.requirements_lock.as_deref(),
        env_args.clear_requirements_lock,
        env_args.skip_env,
    )?;
    if env_plan.skip_env {
        warnings.push("Skipped `uv` Python environment synchronization (`--skip-env`)".to_string());
    }
    if env_plan.extras_changed {
        warnings.push(format!(
            "Updated persisted extras (+{:?} / -{:?})",
            env_plan.extras_added, env_plan.extras_removed
        ));
    }

    let staging_parent = (!dry_run).then(|| staging_dir(paths));
    let staged = stage_release_archive(
        package_path,
        checksum.sha256.as_deref(),
        checksum.checksums.as_deref(),
        staging_parent.as_deref(),
    )?;

    let src_ver = CfmsServerVersion::parse(&source_manifest.manifest.version)?;
    let tgt_ver = CfmsServerVersion::parse(&staged.manifest.manifest.version)?;
    if tgt_ver <= src_ver {
        return Err(CfmsError::Deployment(format!(
            "Upgrade target version {} must be strictly newer than active version {}; downgrading a completed deployment is not supported",
            staged.manifest.manifest.version, source_manifest.manifest.version
        )));
    }

    if !env_plan.skip_env {
        let _py =
            check_target_python_compatibility(paths, &staged.manifest.manifest.requires_python).await?;
    }
    warnings.extend(check_extension_compat_warnings(
        paths,
        &staged.manifest.manifest.version,
    )?);

    let db_pre =
        preflight_upgrade_database(ctx, paths, &staged.extracted_dir, allow_destructive).await?;
    warnings.extend(db_pre.warnings);

    let delta = compute_delta_counts(Some(&source_manifest.manifest), &staged.manifest.manifest);
    let base_template_doc = paths
        .config_template_path
        .is_file()
        .then(|| ConfigDocument::load(&paths.config_template_path))
        .transpose()?;
    let staged_template = staged.extracted_dir.join("src").join("config.toml.sample");
    let (config_changed, _, cfg_warnings) =
        preview_or_apply_config_merge(paths, base_template_doc.as_ref(), &staged_template, false)?;
    warnings.extend(cfg_warnings);

    if dry_run {
        let report = DeploymentMutationReport {
            operation: op_label.to_string(),
            dry_run: true,
            outcome: "ready".to_string(),
            source_release_id: Some(source_manifest.release_id),
            source_version: Some(source_manifest.manifest.version),
            target_release_id: Some(staged.manifest.release_id),
            target_version: Some(staged.manifest.manifest.version),
            checksum: Some(staged.checksum),
            files_added: delta.added,
            files_updated: delta.updated,
            files_removed: delta.removed,
            extras: env_plan.extras,
            config_changed,
            config_backup_path: None,
            db_revision_before: Some(db_pre.live_revision),
            db_revision_after: Some(db_pre.target_head),
            backup_archive_path: None,
            backup_generated_key: None,
            warnings,
            next_steps: vec![
                "Re-run without `--dry-run` to execute the upgrade".to_string(),
            ],
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    ensure_confirmed(
        ctx,
        &format!(
            "Upgrade CFMS deployment from v{} to v{} (DB {} -> {})?",
            source_manifest.manifest.version,
            staged.manifest.manifest.version,
            db_pre.live_revision,
            db_pre.target_head
        ),
        false,
    )?;

    let safety_bak = maybe_create_safety_backup(
        ctx,
        paths,
        backup_args.backup.clone(),
        backup_args.backup_key_out.clone(),
    )
    .await?;

    snapshot_active_release(paths, &source_manifest, &current_settings)?;

    let tx_id = Uuid::new_v4().simple().to_string();
    let journal_dir = tx_root_dir(paths).join(&tx_id);
    let mut tx = DeploymentTransaction {
        format_version: TRANSACTION_FORMAT_VERSION,
        transaction_id: tx_id,
        operation: TransactionOperation::Upgrade,
        phase: TransactionPhase::Activation,
        started_at: Some(Utc::now().to_rfc3339()),
        source_release_id: source_manifest.release_id.clone(),
        target_release_id: staged.manifest.release_id.clone(),
        source_version: source_manifest.manifest.version.clone(),
        target_version: staged.manifest.manifest.version.clone(),
        source_head: Some(db_pre.source_head.clone()),
        target_head: Some(db_pre.target_head.clone()),
        staging_dir: Some(staged.extracted_dir.display().to_string()),
        journal_dir: Some(journal_dir.display().to_string()),
        db_checkpoint_path: None,
        db_checkpoint_sha256: None,
        last_error: None,
        observed_db_revision: Some(db_pre.live_revision.clone()),
        step_history: vec!["snapshot-created".to_string()],
    };
    save_transaction(paths, &tx)?;

    let swap_counts = match apply_swap_with_journal(
        paths,
        Some(&source_manifest),
        &staged.extracted_dir,
        &staged.manifest,
        &journal_dir,
    ) {
        Ok(counts) => counts,
        Err(err) => {
            let _ = rollback_swap_journal(paths, &journal_dir);
            let _ = clear_transaction_artifacts(paths, Some(&tx));
            let _ = remove_stored_release_dir(paths, &source_manifest.release_id);
            return Err(err);
        }
    };
    tx.step_history.push("files-swapped".to_string());
    save_transaction(paths, &tx)?;

    if let Err(err) = sync_persisted_requirements_lock(
        paths,
        env_args.requirements_lock.as_deref(),
        env_args.clear_requirements_lock,
    ) {
        let _ = rollback_swap_journal(paths, &journal_dir);
        let _ = clear_transaction_artifacts(paths, Some(&tx));
        let _ = remove_stored_release_dir(paths, &source_manifest.release_id);
        return Err(err);
    }

    if let Err(err) = sync_python_environment(paths, &env_plan).await {
        let _ = rollback_swap_journal(paths, &journal_dir);
        let _ = clear_transaction_artifacts(paths, Some(&tx));
        let _ = remove_stored_release_dir(paths, &source_manifest.release_id);
        return Err(err);
    }

    let (applied_cfg_changed, cfg_bak_path, apply_cfg_warnings) =
        match preview_or_apply_config_merge(
            paths,
            base_template_doc.as_ref(),
            &paths.config_template_path,
            true,
        ) {
            Ok(v) => v,
            Err(err) => {
                let _ = rollback_swap_journal(paths, &journal_dir);
                let _ = clear_transaction_artifacts(paths, Some(&tx));
                let _ = remove_stored_release_dir(paths, &source_manifest.release_id);
                return Err(err);
            }
        };
    for w in apply_cfg_warnings {
        if !warnings.contains(&w) {
            warnings.push(w);
        }
    }

    if db_pre.source_head != db_pre.target_head {
        let cp_dest = journal_dir.join("db_checkpoint.sqlite");
        match capture_sqlite_upgrade_checkpoint(ctx, paths, &cp_dest).await {
            Ok(Some((cp_path, cp_sha))) => {
                tx.db_checkpoint_path = Some(cp_path.display().to_string());
                tx.db_checkpoint_sha256 = Some(cp_sha);
                tx.step_history.push("db-checkpoint-captured".to_string());
            }
            Ok(None) => {}
            Err(err) => {
                let _ = rollback_swap_journal(paths, &journal_dir);
                let _ = clear_transaction_artifacts(paths, Some(&tx));
                let _ = remove_stored_release_dir(paths, &source_manifest.release_id);
                return Err(err);
            }
        }
    }

    tx.phase = TransactionPhase::DatabaseMigration;
    tx.step_history.push("environment-and-config-synced".to_string());
    save_transaction(paths, &tx)?;

    let db_rev_after = match execute_deployment_db_upgrade(
        ctx,
        paths,
        &db_pre.target_head,
        allow_destructive,
    )
    .await
    {
        Ok(rev) => rev,
        Err(err) => {
            // Preserve intermediate DB recovery state; only undo in-flight DB changes when
            // the operator explicitly aborts via `cfms-ctl deployment resume --rollback`.
            tx.phase = TransactionPhase::DatabaseRecoveryRequired;
            tx.last_error = Some(err.to_string());
            let _ = save_transaction(paths, &tx);
            return Err(CfmsError::Deployment(format!(
                "Database migration failed during upgrade; intermediate recovery state recorded in '{}'. Fix the issue and run `cfms-ctl deployment resume --continue-forward`, or abort and undo all in-flight changes with `cfms-ctl deployment resume --rollback`: {err}",
                paths.transaction_path().display()
            )));
        }
    };

    save_settings(
        paths,
        &DeploymentSettings {
            format_version: 1,
            extras: env_plan.extras.clone(),
        },
    )?;
    clear_transaction_artifacts(paths, Some(&tx))?;
    let _ = auto_prune_versions_keep_limit(
        paths,
        &tx.target_release_id,
        Some(&tx.source_release_id),
        1,
    );
    let staged_checksum = staged.checksum.clone();
    drop(staged);

    let report = DeploymentMutationReport {
        operation: op_label.to_string(),
        dry_run: false,
        outcome: "upgraded".to_string(),
        source_release_id: Some(source_manifest.release_id),
        source_version: Some(source_manifest.manifest.version),
        target_release_id: Some(tx.target_release_id),
        target_version: Some(tx.target_version),
        checksum: Some(staged_checksum),
        files_added: swap_counts.added,
        files_updated: swap_counts.updated,
        files_removed: swap_counts.removed,
        extras: env_plan.extras,
        config_changed: applied_cfg_changed,
        config_backup_path: cfg_bak_path,
        db_revision_before: Some(db_pre.live_revision),
        db_revision_after: Some(db_rev_after),
        backup_archive_path: safety_bak.as_ref().map(|b| b.archive_path.clone()),
        backup_generated_key: safety_bak.and_then(|b| b.generated_key),
        warnings,
        next_steps: Vec::new(),
    };
    ctx.ui.render(&report);
    Ok(())
}

/// Inspect, continue forward, or explicitly roll back an interrupted deployment transaction (`transaction.json`).
pub async fn handle_resume(ctx: &AppContext, args: DeploymentResumeArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let mut tx = load_transaction(&paths)?.ok_or_else(|| {
        CfmsError::Deployment(format!(
            "No interrupted deployment transaction exists at '{}'",
            paths.transaction_path().display()
        ))
    })?;

    let _lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, true)?)
    };

    let dag = paths
        .discover_alembic_paths()
        .and_then(|ap| analyze_alembic_directory(&ap.versions_dir).ok());
    let diagnosis = diagnose_resume_database(
        ctx,
        &paths,
        dag.as_ref(),
        tx.source_head.as_deref(),
        tx.target_head.as_deref(),
    )
    .await?;

    let mut warnings = Vec::new();
    if let Some(ref last_err) = tx.last_error {
        warnings.push(format!("Last failure: {last_err}"));
    }

    if args.dry_run {
        let guidance = recommend_resume_step(&tx, &diagnosis.classification);
        let report = DeploymentMutationReport {
            operation: "resume".to_string(),
            dry_run: true,
            outcome: format!("pending ({}, {})", tx.operation, tx.phase),
            source_release_id: Some(tx.source_release_id),
            source_version: Some(tx.source_version),
            target_release_id: Some(tx.target_release_id),
            target_version: Some(tx.target_version),
            checksum: None,
            files_added: 0,
            files_updated: 0,
            files_removed: 0,
            extras: load_settings(&paths).unwrap_or_default().extras,
            config_changed: false,
            config_backup_path: None,
            db_revision_before: diagnosis.drift.current_revision,
            db_revision_after: None,
            backup_archive_path: None,
            backup_generated_key: None,
            warnings,
            next_steps: vec![guidance],
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    if args.abort_clear {
        ensure_confirmed(
            ctx,
            "Clear `transaction.json` after verifying database and release files match manually?",
            false,
        )?;
        clear_transaction_artifacts(&paths, Some(&tx))?;
        let report = DeploymentMutationReport {
            operation: "resume".to_string(),
            dry_run: false,
            outcome: "transaction-cleared".to_string(),
            source_release_id: Some(tx.source_release_id),
            source_version: Some(tx.source_version),
            target_release_id: Some(tx.target_release_id),
            target_version: Some(tx.target_version),
            checksum: None,
            files_added: 0,
            files_updated: 0,
            files_removed: 0,
            extras: Vec::new(),
            config_changed: false,
            config_backup_path: None,
            db_revision_before: diagnosis.drift.current_revision,
            db_revision_after: None,
            backup_archive_path: None,
            backup_generated_key: None,
            warnings,
            next_steps: Vec::new(),
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    match (tx.operation, tx.phase) {
        (TransactionOperation::Upgrade, TransactionPhase::Activation) => {
            if args.continue_forward
                && let Some(ref st_dir) = tx.staging_dir
                && Path::new(st_dir).is_dir()
            {
                let staged_manifest = verify_staged_release_tree(Path::new(st_dir))?;
                let active_manifest = paths
                    .release_manifest_path
                    .is_file()
                    .then(|| load_manifest_file(&paths.release_manifest_path))
                    .transpose()
                    .ok()
                    .flatten();
                let journal_dir = tx
                    .journal_dir
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| tx_root_dir(&paths).join(&tx.transaction_id));
                let base_template_doc = load_resume_base_template(&paths, &tx, &journal_dir)?;
                apply_swap_with_journal(
                    &paths,
                    active_manifest.as_ref(),
                    Path::new(st_dir),
                    &staged_manifest,
                    &journal_dir,
                )?;
                let settings = load_settings(&paths)?;
                let env_plan = plan_environment_options(
                    &paths,
                    &settings,
                    &[],
                    false,
                    None,
                    false,
                    args.skip_env,
                )?;
                sync_python_environment(&paths, &env_plan).await?;
                let (cfg_changed, cfg_bak, cfg_warn) = preview_or_apply_config_merge(
                    &paths,
                    base_template_doc.as_ref(),
                    &paths.config_template_path,
                    true,
                )?;
                warnings.extend(cfg_warn);
                let target_head = tx.target_head.clone().ok_or_else(|| {
                    CfmsError::Deployment("Missing target_head in transaction.json".to_string())
                })?;
                if tx.source_head.as_deref() != Some(target_head.as_str())
                    && tx.db_checkpoint_path.is_none()
                    && let Some((cp_path, cp_sha)) = capture_sqlite_upgrade_checkpoint(
                        ctx,
                        &paths,
                        &journal_dir.join("db_checkpoint.sqlite"),
                    )
                    .await?
                {
                    tx.db_checkpoint_path = Some(cp_path.display().to_string());
                    tx.db_checkpoint_sha256 = Some(cp_sha);
                }
                tx.phase = TransactionPhase::DatabaseMigration;
                save_transaction(&paths, &tx)?;

                let db_after = match execute_deployment_db_upgrade(
                    ctx,
                    &paths,
                    &target_head,
                    args.allow_destructive,
                )
                .await
                {
                    Ok(rev) => rev,
                    Err(err) => {
                        tx.phase = TransactionPhase::DatabaseRecoveryRequired;
                        tx.last_error = Some(err.to_string());
                        let _ = save_transaction(&paths, &tx);
                        return Err(err);
                    }
                };
                clear_transaction_artifacts(&paths, Some(&tx))?;
                let _ = auto_prune_versions_keep_limit(
                    &paths,
                    &tx.target_release_id,
                    Some(&tx.source_release_id),
                    1,
                );
                emit_resume_done(
                    ctx,
                    &tx,
                    "continued-upgrade",
                    diagnosis.drift.current_revision,
                    Some(db_after),
                    cfg_changed,
                    cfg_bak,
                    warnings,
                );
                return Ok(());
            }
            // Safe default for interrupted activation: restore source via journal or `versions/` snapshot.
            restore_source_release_state(ctx, &paths, &tx, args.skip_env).await?;
            clear_transaction_artifacts(&paths, Some(&tx))?;
            let _ = remove_stored_release_dir(&paths, &tx.source_release_id);
            emit_resume_done(
                ctx,
                &tx,
                "rolled-back-activation",
                diagnosis.drift.current_revision.clone(),
                diagnosis.drift.current_revision,
                false,
                None,
                warnings,
            );
            Ok(())
        }
        (
            TransactionOperation::Upgrade,
            TransactionPhase::DatabaseMigration | TransactionPhase::DatabaseRecoveryRequired,
        ) => {
            if args.rollback {
                ensure_confirmed(
                    ctx,
                    &format!(
                        "Abort interrupted upgrade (v{} -> v{}), undo in-flight database changes back to {:?}, and restore source release?",
                        tx.source_version, tx.target_version, tx.source_head
                    ),
                    false,
                )?;
                let source_rel_dir = versions_dir(&paths)
                    .join(&tx.source_release_id)
                    .join(RELEASE_SUBDIR);
                let source_rel_opt = source_rel_dir.is_dir().then_some(source_rel_dir);
                let db_after = rollback_upgrade_database(
                    ctx,
                    &paths,
                    &tx,
                    source_rel_opt.as_deref(),
                )
                .await?;
                restore_source_release_state(ctx, &paths, &tx, args.skip_env).await?;
                clear_transaction_artifacts(&paths, Some(&tx))?;
                let _ = remove_stored_release_dir(&paths, &tx.source_release_id);
                emit_resume_done(
                    ctx,
                    &tx,
                    "rolled-back-to-source",
                    diagnosis.drift.current_revision,
                    Some(db_after),
                    false,
                    None,
                    warnings,
                );
                return Ok(());
            }

            match &diagnosis.classification {
                ResumeDbClassification::AtTarget => {
                    clear_transaction_artifacts(&paths, Some(&tx))?;
                    let _ = auto_prune_versions_keep_limit(
                        &paths,
                        &tx.target_release_id,
                        Some(&tx.source_release_id),
                        1,
                    );
                    emit_resume_done(
                        ctx,
                        &tx,
                        "finalized-already-migrated",
                        tx.target_head.clone(),
                        tx.target_head.clone(),
                        false,
                        None,
                        warnings,
                    );
                    Ok(())
                }
                ResumeDbClassification::AtSource | ResumeDbClassification::Intermediate(_) => {
                    let target_head = tx.target_head.as_deref().ok_or_else(|| {
                        CfmsError::Deployment("Missing target_head in transaction.json".to_string())
                    })?;
                    ensure_confirmed(
                        ctx,
                        &format!(
                            "Resume database upgrade from {:?} to {target_head}?",
                            diagnosis.drift.current_revision
                        ),
                        false,
                    )?;
                    let db_after = match execute_deployment_db_upgrade(
                        ctx,
                        &paths,
                        target_head,
                        args.allow_destructive,
                    )
                    .await
                    {
                        Ok(rev) => rev,
                        Err(err) => {
                            tx.phase = TransactionPhase::DatabaseRecoveryRequired;
                            tx.last_error = Some(err.to_string());
                            let _ = save_transaction(&paths, &tx);
                            return Err(err);
                        }
                    };
                    clear_transaction_artifacts(&paths, Some(&tx))?;
                    let _ = auto_prune_versions_keep_limit(
                        &paths,
                        &tx.target_release_id,
                        Some(&tx.source_release_id),
                        1,
                    );
                    emit_resume_done(
                        ctx,
                        &tx,
                        "resumed-database-upgrade",
                        diagnosis.drift.current_revision,
                        Some(db_after),
                        false,
                        None,
                        warnings,
                    );
                    Ok(())
                }
                ResumeDbClassification::Unknown(rev) => {
                    let hint = if tx.db_checkpoint_path.is_some() {
                        "Run `cfms-ctl deployment resume --rollback` to restore the pre-upgrade SQLite checkpoint, or inspect live tables with `cfms-ctl database check` and run `resume --abort-clear` after manual repair."
                    } else {
                        "Inspect live tables with `cfms-ctl database check`, restore backup, or run `resume --abort-clear` after manual repair."
                    };
                    Err(CfmsError::SchemaDrift(format!(
                        "Cannot automatically continue upgrade forward: observed DB revision {:?} matches neither source ({:?}), target ({:?}), nor any intermediate step. {hint}",
                        rev, tx.source_head, tx.target_head
                    )))
                }
            }
        }
        (TransactionOperation::Install, _) => {
            clear_transaction_artifacts(&paths, Some(&tx))?;
            emit_resume_done(
                ctx,
                &tx,
                "cleared-install-marker",
                diagnosis.drift.current_revision,
                None,
                false,
                None,
                warnings,
            );
            Ok(())
        }
    }
}

fn load_resume_base_template(
    paths: &WorkspacePaths,
    tx: &DeploymentTransaction,
    journal_dir: &Path,
) -> Result<Option<ConfigDocument>> {
    let journal_base = journal_dir
        .join("backup")
        .join("src")
        .join("config.toml.sample");
    if journal_base.is_file() {
        return Ok(Some(ConfigDocument::load(&journal_base)?));
    }
    let snapshot_base = versions_dir(paths)
        .join(&tx.source_release_id)
        .join(RELEASE_SUBDIR)
        .join("src")
        .join("config.toml.sample");
    if snapshot_base.is_file() {
        return Ok(Some(ConfigDocument::load(&snapshot_base)?));
    }
    if paths.config_template_path.is_file() {
        return Ok(Some(ConfigDocument::load(&paths.config_template_path)?));
    }
    Ok(None)
}

fn recommend_resume_step(tx: &DeploymentTransaction, cls: &ResumeDbClassification) -> String {
    match (tx.operation, tx.phase, cls) {
        (TransactionOperation::Upgrade, TransactionPhase::Activation, _) => {
            "Run `cfms-ctl deployment resume` to safely roll back to the source release, or `--continue-forward` if staging remains valid".to_string()
        }
        (_, _, ResumeDbClassification::AtTarget) => {
            "Database already matches target revision; run `cfms-ctl deployment resume` to finalize cleanup (or `--rollback` to explicitly abort before completion)".to_string()
        }
        (_, _, ResumeDbClassification::Intermediate(mid)) => format!(
            "Database stopped at intermediate revision {mid}; fix the issue and run `cfms-ctl deployment resume --continue-forward`, or abort and undo all in-flight changes with `--rollback`"
        ),
        (_, _, ResumeDbClassification::AtSource) => {
            "Database is at source revision; run `cfms-ctl deployment resume --continue-forward` to retry, or `--rollback` to abort and restore the source release".to_string()
        }
        (_, _, ResumeDbClassification::Unknown(rev)) => {
            if tx.db_checkpoint_path.is_some() {
                format!(
                    "Unrecognized DB revision {rev:?}; run `cfms-ctl deployment resume --rollback` to restore the pre-upgrade SQLite checkpoint, or repair manually and run `--abort-clear`"
                )
            } else {
                format!(
                    "Unrecognized DB revision {rev:?}; run `cfms-ctl database check`, repair or restore backup manually, then `cfms-ctl deployment resume --abort-clear`"
                )
            }
        }
    }
}

async fn restore_source_release_state(
    _ctx: &AppContext,
    paths: &WorkspacePaths,
    tx: &DeploymentTransaction,
    skip_env: bool,
) -> Result<()> {
    let mut restored_via_journal = false;
    if let Some(ref j_dir) = tx.journal_dir
        && Path::new(j_dir).join("journal.json").is_file()
    {
        rollback_swap_journal(paths, Path::new(j_dir))?;
        restored_via_journal = true;
    }

    if !restored_via_journal {
        let source = resolve_stored_release(paths, Some(&tx.source_release_id), None, None)?;
        let cur = paths
            .release_manifest_path
            .is_file()
            .then(|| load_manifest_file(&paths.release_manifest_path))
            .transpose()?;
        let fallback_j = tx_root_dir(paths).join(format!("restore-{}", tx.transaction_id));
        apply_swap_with_journal(
            paths,
            cur.as_ref(),
            &source.release_dir,
            &source.manifest,
            &fallback_j,
        )?;
        let _ = fs::remove_dir_all(&fallback_j);

        let _ = restore_snapshot_config(&source.state_dir, &paths.config_path)?;
        let saved_settings_file = source.state_dir.join("settings.json");
        if saved_settings_file.is_file()
            && let Ok(raw) = fs::read_to_string(&saved_settings_file)
            && let Ok(settings) = serde_json::from_str::<DeploymentSettings>(&raw)
        {
            let _ = save_settings(paths, &settings);
        }
        let saved_lock = source.state_dir.join("requirements.lock");
        if saved_lock.is_file() {
            sync_persisted_requirements_lock(paths, Some(&saved_lock), false)?;
        }
    }

    let settings = load_settings(paths)?;
    let env_plan = plan_environment_options(paths, &settings, &[], false, None, false, skip_env)?;
    sync_python_environment(paths, &env_plan).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_resume_done(
    ctx: &AppContext,
    tx: &DeploymentTransaction,
    outcome: &str,
    db_before: Option<String>,
    db_after: Option<String>,
    config_changed: bool,
    config_backup_path: Option<String>,
    warnings: Vec<String>,
) {
    let report = DeploymentMutationReport {
        operation: "resume".to_string(),
        dry_run: false,
        outcome: outcome.to_string(),
        source_release_id: Some(tx.source_release_id.clone()),
        source_version: Some(tx.source_version.clone()),
        target_release_id: Some(tx.target_release_id.clone()),
        target_version: Some(tx.target_version.clone()),
        checksum: None,
        files_added: 0,
        files_updated: 0,
        files_removed: 0,
        extras: Vec::new(),
        config_changed,
        config_backup_path,
        db_revision_before: db_before,
        db_revision_after: db_after,
        backup_archive_path: None,
        backup_generated_key: None,
        warnings,
        next_steps: Vec::new(),
    };
    ctx.ui.render(&report);
}

/// Remove inactive historical snapshots selectively (`--keep`, `--release`, `--corrupt`, or `--all`).
pub async fn handle_prune(ctx: &AppContext, args: DeploymentPruneArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    validate_workspace_layout(&paths, true)?;
    let _lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let selector = if let Some(n) = args.keep {
        PruneSelector::KeepNewest(n)
    } else if !args.release.is_empty() {
        PruneSelector::SpecificIds(args.release)
    } else if args.corrupt {
        PruneSelector::CorruptOnly
    } else {
        PruneSelector::AllInactive
    };

    let plan = plan_prune(&paths, &selector)?;
    let removed_ids: Vec<String> = plan.remove.iter().map(|r| r.release_id.clone()).collect();
    if !args.dry_run && !removed_ids.is_empty() {
        ensure_confirmed(
            ctx,
            &format!(
                "Delete {} stored release snapshot(s) freeing {} bytes?",
                removed_ids.len(),
                plan.freed_bytes
            ),
            false,
        )?;
        execute_prune(&paths, &plan)?;
    }

    let report = DeploymentPruneReport {
        dry_run: args.dry_run,
        active_release_id: plan.active_release_id,
        kept_release_ids: plan.keep_ids,
        removed_release_ids: removed_ids,
        freed_bytes: plan.freed_bytes,
        warnings: plan.warnings,
    };
    ctx.ui.render(&report);
    Ok(())
}

/// Cold-start install from a local archive or GitHub release into an empty target directory.
pub async fn handle_install(ctx: &AppContext, args: DeploymentInstallArgs) -> Result<()> {
    let target_root = args
        .target
        .clone()
        .or_else(|| ctx.global.root.clone())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if target_root.join(".git").exists() {
        return Err(CfmsError::Deployment(format!(
            "Refusing to install over existing git repository '{}'",
            target_root.display()
        )));
    }
    if target_root.join(RELEASE_MANIFEST_FILENAME).exists() || target_root.join("src").join("main.py").exists() {
        return Err(CfmsError::Deployment(format!(
            "Target '{}' already contains a CFMS installation; use `upgrade` or `adopt` instead",
            target_root.display()
        )));
    }

    let mut warnings = Vec::new();
    let _downloaded_holder;
    let (pkg_path, csum_args) = if args.from_github {
        let resolved = fetch_and_resolve_release(&args.online, args.require_github_digest).await?;
        warnings.extend(resolved.warnings.clone());
        _downloaded_holder = download_verified_github_release(resolved, ctx.ui.format()).await?;
        (
            _downloaded_holder.package_path.clone(),
            LocalChecksumArgs {
                sha256: Some(_downloaded_holder.sha256.clone()),
                checksums: None,
            },
        )
    } else {
        (
            args.package.clone().ok_or_else(|| {
                CfmsError::InvalidArgument("Pass a local package path or `--from-github`".to_string())
            })?,
            args.checksum.clone(),
        )
    };

    let staged = stage_release_archive(
        &pkg_path,
        csum_args.sha256.as_deref(),
        csum_args.checksums.as_deref(),
        None,
    )?;

    fs::create_dir_all(&target_root)?;
    let paths = WorkspacePaths::for_target_project_root(&target_root, ctx.global.config.as_deref());
    let env_plan = plan_environment_options(
        &paths,
        &DeploymentSettings::default(),
        &args.env.extras,
        args.env.clear_extras,
        args.env.requirements_lock.as_deref(),
        args.env.clear_requirements_lock,
        args.env.skip_env,
    )?;

    if !env_plan.skip_env {
        let _py =
            check_target_python_compatibility(&paths, &staged.manifest.manifest.requires_python)
                .await?;
    }

    let alembic = analyze_release_alembic(&staged.extracted_dir)?;
    let head_rev = alembic.single_head.clone();

    if args.dry_run {
        let report = DeploymentMutationReport {
            operation: "install".to_string(),
            dry_run: true,
            outcome: "ready".to_string(),
            source_release_id: None,
            source_version: None,
            target_release_id: Some(staged.manifest.release_id),
            target_version: Some(staged.manifest.manifest.version),
            checksum: Some(staged.checksum),
            files_added: staged.manifest.manifest.files.len(),
            files_updated: 0,
            files_removed: 0,
            extras: env_plan.extras,
            config_changed: true,
            config_backup_path: None,
            db_revision_before: None,
            db_revision_after: (!args.skip_db_init).then_some(head_rev).flatten(),
            backup_archive_path: None,
            backup_generated_key: None,
            warnings,
            next_steps: vec![format!(
                "Re-run without `--dry-run` to install into '{}'",
                paths.project_root.display()
            )],
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    ensure_confirmed(
        ctx,
        &format!(
            "Install CFMS v{} into '{}'?",
            staged.manifest.manifest.version,
            paths.project_root.display()
        ),
        false,
    )?;

    for rel_posix in staged.manifest.manifest.files.keys() {
        let src_file = staged.extracted_dir.join(rel_posix);
        let dst_file = paths.project_root.join(rel_posix);
        if let Some(parent) = Path::new(rel_posix).parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_safe_directory_chain(&paths.project_root, parent)?;
        }
        copy_file_atomic_with_retry(&src_file, &dst_file)?;
    }
    atomic_write(&paths.release_manifest_path, &staged.manifest.raw_bytes)?;

    initialize_fresh_config_from_template(&paths)?;
    sync_persisted_requirements_lock(
        &paths,
        args.env.requirements_lock.as_deref(),
        args.env.clear_requirements_lock,
    )?;
    sync_python_environment(&paths, &env_plan).await?;

    let settings = DeploymentSettings {
        format_version: 1,
        extras: env_plan.extras.clone(),
    };
    save_settings(&paths, &settings)?;

    let db_after = if args.skip_db_init {
        None
    } else if let Some(ref head) = head_rev {
        Some(initialize_fresh_database(ctx, &paths, head).await?)
    } else {
        None
    };

    let report = DeploymentMutationReport {
        operation: "install".to_string(),
        dry_run: false,
        outcome: "installed".to_string(),
        source_release_id: None,
        source_version: None,
        target_release_id: Some(staged.manifest.release_id),
        target_version: Some(staged.manifest.manifest.version),
        checksum: Some(staged.checksum),
        files_added: staged.manifest.manifest.files.len(),
        files_updated: 0,
        files_removed: 0,
        extras: env_plan.extras,
        config_changed: true,
        config_backup_path: None,
        db_revision_before: None,
        db_revision_after: db_after,
        backup_archive_path: None,
        backup_generated_key: None,
        warnings,
        next_steps: vec![
            format!("Review generated configuration at '{}'", paths.config_path.display()),
        ],
    };
    ctx.ui.render(&report);
    Ok(())
}

fn initialize_fresh_config_from_template(paths: &WorkspacePaths) -> Result<()> {
    if paths.config_path.exists() || !paths.config_template_path.is_file() {
        return Ok(());
    }
    let raw = fs::read_to_string(&paths.config_template_path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
        CfmsError::Config(format!(
            "Failed parsing template '{}': {e}",
            paths.config_template_path.display()
        ))
    })?;

    if let Some(sec) = doc.get_mut("security").and_then(|v| v.as_table_like_mut())
        && sec
            .get("pepper")
            .and_then(|v| v.as_str())
            .is_some_and(str::is_empty)
    {
        let secret_hex = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        sec.insert("pepper", toml_edit::value(secret_hex));
    }
    if let Some(srv) = doc.get_mut("server").and_then(|v| v.as_table_like_mut())
        && srv
            .get("secret_key")
            .and_then(|v| v.as_str())
            .is_some_and(str::is_empty)
    {
        let secret_hex = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        srv.insert("secret_key", toml_edit::value(secret_hex));
    }

    atomic_write(&paths.config_path, doc.to_string().as_bytes())
}

/// Adopt an unmanaged unpacked non-`.git` installation by verifying files against a matching release.
pub async fn handle_adopt(ctx: &AppContext, args: DeploymentAdoptArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    validate_workspace_layout(&paths, false)?;
    if paths.release_manifest_path.exists() {
        return Err(CfmsError::Deployment(format!(
            "Deployment at '{}' already tracks `{}`; no adoption needed",
            paths.project_root.display(),
            RELEASE_MANIFEST_FILENAME
        )));
    }
    let _lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let mut warnings = Vec::new();
    let _dl_guard;
    let (pkg_path, csum_args) = if args.from_github {
        let resolved = fetch_and_resolve_release(&args.online, args.require_github_digest).await?;
        warnings.extend(resolved.warnings.clone());
        _dl_guard = download_verified_github_release(resolved, ctx.ui.format()).await?;
        (
            _dl_guard.package_path.clone(),
            LocalChecksumArgs {
                sha256: Some(_dl_guard.sha256.clone()),
                checksums: None,
            },
        )
    } else {
        (
            args.package.clone().ok_or_else(|| {
                CfmsError::InvalidArgument("Pass a reference package path or `--from-github`".to_string())
            })?,
            args.checksum.clone(),
        )
    };

    let staged = stage_release_archive(
        &pkg_path,
        csum_args.sha256.as_deref(),
        csum_args.checksums.as_deref(),
        None,
    )?;

    let mut mismatched = Vec::new();
    for (rel_posix, expected_hash) in &staged.manifest.manifest.files {
        let live_path = paths.project_root.join(rel_posix);
        match hash_file_sha256(&live_path) {
            Ok((actual, _)) if &actual == expected_hash => {}
            Ok((actual, _)) => {
                mismatched.push(format!("{rel_posix}: hash mismatch ({actual} != {expected_hash})"));
            }
            Err(err) => mismatched.push(format!("{rel_posix}: {err}")),
        }
    }
    if !mismatched.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Cannot adopt workspace as v{}: {} tracked file(s) differ from reference manifest (first: {})",
            staged.manifest.manifest.version,
            mismatched.len(),
            mismatched[0]
        )));
    }

    let settings = DeploymentSettings {
        format_version: 1,
        extras: {
            let set: BTreeSet<String> = args
                .extras
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            set.into_iter().collect()
        },
    };

    if !args.dry_run {
        ensure_confirmed(
            ctx,
            &format!(
                "Adopt unpacked deployment '{}' as verified release v{} ({})?",
                paths.project_root.display(),
                staged.manifest.manifest.version,
                &staged.manifest.release_id[..12.min(staged.manifest.release_id.len())]
            ),
            false,
        )?;
        atomic_write(&paths.release_manifest_path, &staged.manifest.raw_bytes)?;
        sync_persisted_requirements_lock(&paths, args.requirements_lock.as_deref(), false)?;
        save_settings(&paths, &settings)?;
    }

    let report = DeploymentMutationReport {
        operation: "adopt".to_string(),
        dry_run: args.dry_run,
        outcome: if args.dry_run { "verified-ready" } else { "adopted" }.to_string(),
        source_release_id: None,
        source_version: None,
        target_release_id: Some(staged.manifest.release_id),
        target_version: Some(staged.manifest.manifest.version),
        checksum: Some(staged.checksum),
        files_added: 1,
        files_updated: 0,
        files_removed: 0,
        extras: settings.extras,
        config_changed: false,
        config_backup_path: None,
        db_revision_before: None,
        db_revision_after: None,
        backup_archive_path: None,
        backup_generated_key: None,
        warnings,
        next_steps: Vec::new(),
    };
    ctx.ui.render(&report);
    Ok(())
}

// Keep retry helper cleanly accessible when staging leftovers exist in future checks.
#[allow(dead_code)]
fn _clean_staging_best_effort(path: &Path) {
    if path.exists() {
        let _ = retry_fs_op(|| fs::remove_dir_all(path));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder as TarBuilder;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use url::Url;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    use super::*;
    use super::super::manifest::{
        parse_and_validate_manifest_bytes, sha256_hex,
    };
    use super::super::models::{
        RELEASE_MANIFEST_FORMAT_VERSION, RELEASE_PRODUCT_NAME, ReleaseManifest,
    };
    use super::super::online::OnlineClientConfig;
    use super::super::repository::staging_dir;
    use crate::cli::GlobalOpts;
    use crate::cli::deployment::{
        DeploymentEnvArgs, OnlineReleaseArgs, ReleaseArchiveFormat, SafetyBackupArgs,
    };
    use crate::db::DbPool;
    use crate::db::schema::{create_head_schema, set_alembic_version};
    use crate::ui::UiConsole;

    fn test_ctx(root: &Path) -> AppContext {
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

    fn alembic_script(rev: &str, down_rev: Option<&str>) -> Vec<u8> {
        let down = match down_rev {
            Some(d) => format!("'{d}'"),
            None => "None".to_string(),
        };
        format!(
            "revision = '{rev}'\ndown_revision = {down}\n\ndef upgrade():\n    pass\n\ndef downgrade():\n    pass\n"
        )
        .into_bytes()
    }

    fn base_config_template(extra_toml: &str) -> Vec<u8> {
        format!(
            "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n\n[security]\npepper = \"\"\n\n[server]\nsecret_key = \"\"\n{extra_toml}"
        )
        .into_bytes()
    }

    /// Build release file map + manifest JSON bytes deterministically.
    fn build_release_bundle_map(
        version: &str,
        alembic_chain: &[(&str, Option<&str>)],
        config_sample: &[u8],
        extra_files: &[(&str, &[u8])],
    ) -> (BTreeMap<String, Vec<u8>>, Vec<u8>) {
        let mut files_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files_bytes.insert(
            "pyproject.toml".to_string(),
            format!("[project]\nname = \"cfms\"\nversion = \"{version}\"\n").into_bytes(),
        );
        files_bytes.insert("uv.lock".to_string(), b"version = 1\n".to_vec());
        files_bytes.insert(
            "src/alembic.ini".to_string(),
            b"[alembic]\nscript_location = alembic\n".to_vec(),
        );
        files_bytes.insert(
            "src/config.toml.sample".to_string(),
            config_sample.to_vec(),
        );
        files_bytes.insert(
            "src/main.py".to_string(),
            format!("# CFMS server v{version}\n").into_bytes(),
        );
        for (idx, (rev, down)) in alembic_chain.iter().enumerate() {
            files_bytes.insert(
                format!("src/alembic/versions/{idx:02}_{rev}.py"),
                alembic_script(rev, *down),
            );
        }
        for (rel, bytes) in extra_files {
            files_bytes.insert((*rel).to_string(), bytes.to_vec());
        }

        let mut manifest_files = BTreeMap::new();
        for (rel, bytes) in &files_bytes {
            manifest_files.insert(rel.clone(), sha256_hex(bytes));
        }
        let manifest = ReleaseManifest {
            format_version: RELEASE_MANIFEST_FORMAT_VERSION,
            product: RELEASE_PRODUCT_NAME.to_string(),
            version: version.to_string(),
            requires_python: ">=3.12,<3.15".to_string(),
            managed_extensions: vec!["builtin".to_string()],
            files: manifest_files,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        (files_bytes, manifest_bytes)
    }

    fn write_release_targz(
        dest: &Path,
        prefix_dir: &str,
        files_bytes: &BTreeMap<String, Vec<u8>>,
        manifest_bytes: &[u8],
    ) {
        let f = fs::File::create(dest).unwrap();
        let gz = GzEncoder::new(f, Compression::default());
        let mut tar = TarBuilder::new(gz);

        let mut add = |rel: &str, bytes: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            let path = if prefix_dir.is_empty() {
                rel.to_string()
            } else {
                format!("{prefix_dir}/{rel}")
            };
            tar.append_data(&mut h, path, bytes).unwrap();
        };

        for (rel, bytes) in files_bytes {
            add(rel, bytes);
        }
        add(RELEASE_MANIFEST_FILENAME, manifest_bytes);
        tar.into_inner().unwrap().finish().unwrap();
    }

    fn write_release_zip(
        dest: &Path,
        prefix_dir: &str,
        files_bytes: &BTreeMap<String, Vec<u8>>,
        manifest_bytes: &[u8],
    ) {
        let f = fs::File::create(dest).unwrap();
        let mut zip = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();

        let mut add = |rel: &str, bytes: &[u8]| {
            let path = if prefix_dir.is_empty() {
                rel.to_string()
            } else {
                format!("{prefix_dir}/{rel}")
            };
            zip.start_file(path, opts).unwrap();
            zip.write_all(bytes).unwrap();
        };

        for (rel, bytes) in files_bytes {
            add(rel, bytes);
        }
        add(RELEASE_MANIFEST_FILENAME, manifest_bytes);
        zip.finish().unwrap();
    }

    fn write_unpacked_workspace(
        root: &Path,
        files_bytes: &BTreeMap<String, Vec<u8>>,
        manifest_bytes: Option<&[u8]>,
    ) {
        for (rel, bytes) in files_bytes {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }
        if let Some(mb) = manifest_bytes {
            fs::write(root.join(RELEASE_MANIFEST_FILENAME), mb).unwrap();
        }
    }

    async fn install_fixture_release(
        target_root: &Path,
        bundle_path: &Path,
        skip_db_init: bool,
    ) {
        let ctx = test_ctx(target_root);
        handle_install(
            &ctx,
            DeploymentInstallArgs {
                package: Some(bundle_path.to_path_buf()),
                from_github: false,
                target: Some(target_root.to_path_buf()),
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                skip_db_init,
                dry_run: false,
            },
        )
        .await
        .unwrap();
    }

    fn install_dummy_third_party_extension(
        root: &Path,
        id: &str,
        min_ver: Option<&str>,
        max_ver: Option<&str>,
    ) {
        let ext_dir = root.join("src").join("include").join("extensions").join(id);
        fs::create_dir_all(&ext_dir).unwrap();
        let mut toml = format!(
            "manifest_version = 3\n\n[extension]\nidentifier = \"{id}\"\nname = \"Test Ext\"\nversion = \"1.0.0\"\nlicense = \"MIT\"\nauthors = [\"QA\"]\n\n[compatibility]\n"
        );
        if let Some(min) = min_ver {
            toml.push_str(&format!("minimum_server_version = \"{min}\"\n"));
        }
        if let Some(max) = max_ver {
            toml.push_str(&format!("maximum_server_version = \"{max}\"\n"));
        }
        fs::write(ext_dir.join("manifest.toml"), toml).unwrap();
        fs::write(ext_dir.join("_extension.py"), b"def register():\n    pass\n").unwrap();
    }

    #[tokio::test]
    async fn install_cold_start_initializes_config_and_sqlite_schema() {
        let tmp = TempDir::new().unwrap();
        let pkg = tmp.path().join("cfms-0.14.0.tar.gz");
        let (files, manifest_bytes) = build_release_bundle_map(
            "0.14.0",
            &[("16c86712512a", None), ("e952c02c1454", Some("16c86712512a"))],
            &base_config_template(""),
            &[],
        );
        write_release_targz(&pkg, "cfms-0.14.0", &files, &manifest_bytes);

        let target = tmp.path().join("deploy-fresh");
        let ctx = test_ctx(&target);

        // Dry-run install leaves target untouched.
        handle_install(
            &ctx,
            DeploymentInstallArgs {
                package: Some(pkg.clone()),
                from_github: false,
                target: Some(target.clone()),
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                skip_db_init: false,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(!target.join("release-manifest.json").exists());

        // Real cold-start install without --skip-env? No, with --skip-env for host independence,
        // initializing fresh config.toml secrets and SQLite schema at HEAD e952c02c1454.
        install_fixture_release(&target, &pkg, false).await;

        assert!(target.join("release-manifest.json").is_file());
        let cfg_raw = fs::read_to_string(target.join("src").join("config.toml")).unwrap();
        let cfg_doc: toml::Value = toml::from_str(&cfg_raw).unwrap();
        assert!(!cfg_doc["security"]["pepper"].as_str().unwrap().is_empty());
        assert!(!cfg_doc["server"]["secret_key"].as_str().unwrap().is_empty());

        let paths = WorkspacePaths::discover(Some(&target), None).unwrap();
        let db = AppContext::new(ctx.global.clone(), ctx.ui.clone())
            .connect_db(&paths)
            .await
            .unwrap();
        assert_eq!(db.current_revision().await.unwrap().as_deref(), Some("e952c02c1454"));
        db.close().await;

        handle_verify(
            &ctx,
            DeploymentVerifyArgs {
                release: None,
                active_only: false,
            },
        )
        .await
        .unwrap();

        // Refusing install over existing CFMS install or .git checkout.
        let err_existing = handle_install(
            &ctx,
            DeploymentInstallArgs {
                package: Some(pkg.clone()),
                from_github: false,
                target: Some(target.clone()),
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                skip_db_init: true,
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert!(err_existing.to_string().contains("already contains"));

        let git_target = tmp.path().join("git-repo");
        fs::create_dir_all(git_target.join(".git")).unwrap();
        let err_git = handle_install(
            &test_ctx(&git_target),
            DeploymentInstallArgs {
                package: Some(pkg),
                from_github: false,
                target: Some(git_target),
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                skip_db_init: true,
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert!(err_git.to_string().contains("git repository"));
    }

    #[tokio::test]
    async fn adopt_verifies_unpacked_tree_and_rejects_mismatch() {
        let tmp = TempDir::new().unwrap();
        let pkg = tmp.path().join("cfms-0.14.0.zip");
        let (files, manifest_bytes) = build_release_bundle_map(
            "0.14.0",
            &[("e952c02c1454", None)],
            &base_config_template(""),
            &[],
        );
        write_release_zip(&pkg, "", &files, &manifest_bytes);

        let unpacked = tmp.path().join("unpacked");
        write_unpacked_workspace(&unpacked, &files, None);
        fs::write(unpacked.join("src").join("config.toml"), base_config_template("")).unwrap();

        let ctx = test_ctx(&unpacked);

        // Tamper one file -> adopt refuses.
        fs::write(unpacked.join("src").join("main.py"), b"# tampered\n").unwrap();
        let err = handle_adopt(
            &ctx,
            DeploymentAdoptArgs {
                package: Some(pkg.clone()),
                from_github: false,
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                extras: Vec::new(),
                requirements_lock: None,
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("differ from reference manifest"));
        assert!(!unpacked.join("release-manifest.json").exists());

        // Restore exact content -> dry-run then real adopt succeeds.
        fs::write(unpacked.join("src").join("main.py"), &files["src/main.py"]).unwrap();
        handle_adopt(
            &ctx,
            DeploymentAdoptArgs {
                package: Some(pkg.clone()),
                from_github: false,
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                extras: vec!["postgres".to_string()],
                requirements_lock: None,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(!unpacked.join("release-manifest.json").exists());

        handle_adopt(
            &ctx,
            DeploymentAdoptArgs {
                package: Some(pkg),
                from_github: false,
                online: OnlineReleaseArgs::default(),
                require_github_digest: false,
                checksum: LocalChecksumArgs::default(),
                extras: vec!["postgres".to_string()],
                requirements_lock: None,
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert!(unpacked.join("release-manifest.json").is_file());
        let settings = load_settings(&WorkspacePaths::discover(Some(&unpacked), None).unwrap()).unwrap();
        assert_eq!(settings.extras, vec!["postgres".to_string()]);
        handle_status(&ctx, DeploymentStatusArgs { verify: true })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_dry_run_real_sqlite_migration_config_sync_backup_and_extension_preservation() {
        let tmp = TempDir::new().unwrap();
        let v1_pkg = tmp.path().join("cfms-0.13.9.tar.gz");
        let (v1_files, v1_manifest_bytes) = build_release_bundle_map(
            "0.13.9",
            &[("16c86712512a", None)],
            &base_config_template(""),
            &[("src/legacy_only.py", b"# will be removed on upgrade\n")],
        );
        write_release_targz(&v1_pkg, "cfms-0.13.9", &v1_files, &v1_manifest_bytes);

        let deploy = tmp.path().join("live-deploy");
        install_fixture_release(&deploy, &v1_pkg, true).await;

        let paths = WorkspacePaths::discover(Some(&deploy), None).unwrap();
        let ctx = test_ctx(&deploy);

        // Customize live config secrets + DB path, create schema at 16c86712512a, add operator data & extension.
        let custom_cfg = "[database]\ntype = \"sqlite\"\nfile = \"custom_cfms.db\"\n\n[security]\npepper = \"operator-secret-999\"\n\n[server]\nsecret_key = \"operator-srv-key\"\n";
        fs::write(&paths.config_path, custom_cfg).unwrap();
        let db = ctx.connect_db(&paths).await.unwrap();
        create_head_schema(&db, false).await.unwrap();
        set_alembic_version(&db, "16c86712512a").await.unwrap();
        db.close().await;

        let content_upload = deploy.join("src").join("content").join("files").join("upload.bin");
        fs::create_dir_all(content_upload.parent().unwrap()).unwrap();
        fs::write(&content_upload, b"operator-binary-payload").unwrap();
        install_dummy_third_party_extension(&deploy, "acme_plugin", Some("0.13.0"), Some("0.15.9"));

        // Build v0.14.0 ZIP bundle adding a new file, removing legacy_only.py, adding [logging] config, advancing DB head to e952c02c1454.
        let v2_pkg = tmp.path().join("cfms-0.14.0.zip");
        let (v2_files, v2_manifest_bytes) = build_release_bundle_map(
            "0.14.0",
            &[("16c86712512a", None), ("e952c02c1454", Some("16c86712512a"))],
            &base_config_template("\n[logging]\nlevel = \"INFO\"\n"),
            &[("src/new_feature.py", b"NEW = True\n")],
        );
        write_release_zip(&v2_pkg, "cfms-0.14.0", &v2_files, &v2_manifest_bytes);

        // 1) Dry-run upgrade leaves files, config, and DB unchanged.
        handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v2_pkg.clone(),
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    extras: vec!["postgres".to_string()],
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(!deploy.join("src").join("new_feature.py").exists());
        assert!(deploy.join("src").join("legacy_only.py").is_file());
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.13.9"
        );

        // 2) Real upgrade migrating DB from `16c86712512a` -> `e952c02c1454` and preserving secrets/extensions.
        handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v2_pkg,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    extras: vec!["postgres".to_string()],
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.14.0"
        );
        assert!(deploy.join("src").join("new_feature.py").is_file());
        assert!(!deploy.join("src").join("legacy_only.py").exists());

        // Preserved live config secrets + DB filename + newly synced [logging] section.
        let new_cfg_raw = fs::read_to_string(&paths.config_path).unwrap();
        let new_cfg: toml::Value = toml::from_str(&new_cfg_raw).unwrap();
        assert_eq!(new_cfg["security"]["pepper"].as_str(), Some("operator-secret-999"));
        assert_eq!(new_cfg["database"]["file"].as_str(), Some("custom_cfms.db"));
        assert_eq!(new_cfg["logging"]["level"].as_str(), Some("INFO"));

        // Preserved operator content + third-party extension.
        assert_eq!(fs::read(&content_upload).unwrap(), b"operator-binary-payload");
        assert!(deploy.join("src/include/extensions/acme_plugin/manifest.toml").is_file());

        // DB migrated cleanly to e952c02c1454 without Python.
        let db = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(db.current_revision().await.unwrap().as_deref(), Some("e952c02c1454"));
        db.close().await;

        // 3) Patch upgrade 0.14.0 -> 0.14.1 WITH `--backup` + `--backup-key-out` verifies locked pre-mutation export.
        let v3_pkg = tmp.path().join("cfms-0.14.1.zip");
        let (v3_files, v3_manifest_bytes) = build_release_bundle_map(
            "0.14.1",
            &[("16c86712512a", None), ("e952c02c1454", Some("16c86712512a"))],
            &base_config_template("\n[logging]\nlevel = \"INFO\"\n"),
            &[("src/new_feature.py", b"NEW = 2\n")],
        );
        write_release_zip(&v3_pkg, "cfms-0.14.1", &v3_files, &v3_manifest_bytes);

        let bak_file = tmp.path().join("pre_upgrade.confbak");
        let bak_key = tmp.path().join("pre_upgrade.key");
        handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v3_pkg,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    extras: vec!["postgres".to_string()],
                    ..Default::default()
                },
                backup: SafetyBackupArgs {
                    backup: Some(bak_file.clone()),
                    backup_key_out: Some(bak_key.clone()),
                },
                allow_destructive: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();

        assert!(bak_file.is_file());
        assert!(bak_key.is_file());
        let header = crate::ops::backup::read_backup_header(&bak_file).unwrap();
        assert_eq!(header.schema_revision, "e952c02c1454");
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.14.1"
        );

        // After upgrading 0.13.9 -> 0.14.0 -> 0.14.1, versions/ auto-prunes to at most 1 old version (0.14.0).
        let v1_valid = parse_and_validate_manifest_bytes(&v1_manifest_bytes, "v1").unwrap();
        let v2_valid = parse_and_validate_manifest_bytes(&v2_manifest_bytes, "v2").unwrap();
        let snaps = list_stored_releases(&paths, None, true).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].release_id, v2_valid.release_id);
        assert!(snaps[0].healthy);
        assert!(!snaps.iter().any(|s| s.release_id == v1_valid.release_id));
        handle_status(&ctx, DeploymentStatusArgs { verify: true })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_rejects_downgrade_and_same_version_after_completion() {
        let tmp = TempDir::new().unwrap();
        let v1_pkg = tmp.path().join("cfms-0.14.0.tar.gz");
        let (v1_files, v1_mb) = build_release_bundle_map(
            "0.14.0",
            &[("e952c02c1454", None)],
            &base_config_template(""),
            &[],
        );
        write_release_targz(&v1_pkg, "", &v1_files, &v1_mb);

        let v2_pkg = tmp.path().join("cfms-0.14.1.tar.gz");
        let (v2_files, v2_mb) = build_release_bundle_map(
            "0.14.1",
            &[("e952c02c1454", None)],
            &base_config_template(""),
            &[("src/v141.py", b"V = 141\n")],
        );
        write_release_targz(&v2_pkg, "", &v2_files, &v2_mb);

        let deploy = tmp.path().join("no-downgrade-deploy");
        install_fixture_release(&deploy, &v1_pkg, false).await;
        let ctx = test_ctx(&deploy);

        // Complete upgrade 0.14.0 -> 0.14.1.
        handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v2_pkg.clone(),
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();

        // Attempting to upgrade back to 0.14.0 is strictly prohibited.
        let down_err = handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v1_pkg,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: false,
            },
        )
        .await
        .expect_err("completed deployment must reject downgrade via upgrade");
        assert!(
            down_err.to_string().contains("strictly newer") || down_err.to_string().contains("downgrading"),
            "unexpected error: {down_err}"
        );

        // Same version is also rejected.
        let same_err = handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v2_pkg,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: true,
            },
        )
        .await
        .expect_err("same-version upgrade must be rejected");
        assert!(same_err.to_string().contains("strictly newer"));
    }

    #[tokio::test]
    async fn upgrade_three_way_merges_config_and_preserves_extensions() {
        let tmp = TempDir::new().unwrap();
        let v1_template = base_config_template(
            "port = 5104\ntimeout = 30\nlegacy_flag = false\ncustom_deleted = \"default\"\n\n[extensions]\nenabled = []\n",
        );
        let v1_pkg = tmp.path().join("cfms-0.14.0.tar.gz");
        let (v1_files, v1_mb) = build_release_bundle_map(
            "0.14.0",
            &[("e952c02c1454", None)],
            &v1_template,
            &[],
        );
        write_release_targz(&v1_pkg, "", &v1_files, &v1_mb);

        let deploy = tmp.path().join("three-way-merge-deploy");
        install_fixture_release(&deploy, &v1_pkg, false).await;
        let paths = WorkspacePaths::discover(Some(&deploy), None).unwrap();
        let ctx = test_ctx(&deploy);

        // Operator customizes port (conflict vs v2), custom_deleted (modify/delete conflict vs v2),
        // keeps timeout & legacy_flag at v1 defaults, and adds an extension subtable + comments.
        let operator_cfg = r#"# Operator deployment header
[database]
type = "sqlite"
file = "cfms.db"

[security]
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[server]
secret_key = "deploy-secret-key"
port = 9000 # customized port
timeout = 30 # keep inline comment on default
legacy_flag = false
custom_deleted = "keep-my-override"
operator_only = "stays"

[extensions]
enabled = ["oidc_sso"]

[extensions.oidc_sso]
issuer = "https://sso.example.org"
client_id = "cfms-web"
"#;
        fs::write(&paths.config_path, operator_cfg).unwrap();

        // v2 template changes port default (5104 -> 8080), timeout default (30 -> 60),
        // removes legacy_flag and custom_deleted, and adds [logging].
        let v2_template = base_config_template(
            "port = 8080\ntimeout = 60\n\n[logging]\nlevel = \"INFO\"\n\n[extensions]\nenabled = []\n",
        );
        let v2_pkg = tmp.path().join("cfms-0.15.0.zip");
        let (v2_files, mut v2_mb) = build_release_bundle_map(
            "0.15.0",
            &[("e952c02c1454", None)],
            &v2_template,
            &[],
        );
        let mut parsed_manifest: ReleaseManifest = serde_json::from_slice(&v2_mb).unwrap();
        parsed_manifest.managed_extensions.push("oidc_sso".to_string());
        v2_mb = serde_json::to_vec_pretty(&parsed_manifest).unwrap();
        write_release_zip(&v2_pkg, "cfms-0.15.0", &v2_files, &v2_mb);

        // 1) Dry-run leaves live config untouched.
        handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v2_pkg.clone(),
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(fs::read_to_string(&paths.config_path).unwrap(), operator_cfg);

        // 2) Real upgrade performs non-destructive 3-way merge.
        handle_upgrade(
            &ctx,
            DeploymentUpgradeArgs {
                package: v2_pkg,
                checksum: LocalChecksumArgs::default(),
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                allow_destructive: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();

        let merged_raw = fs::read_to_string(&paths.config_path).unwrap();
        assert!(merged_raw.contains("# Operator deployment header"));
        assert!(merged_raw.contains("# keep inline comment on default"));
        assert!(!merged_raw.contains("legacy_flag"));

        let merged: toml::Value = toml::from_str(&merged_raw).unwrap();
        // Unmodified default updated automatically.
        assert_eq!(merged["server"]["timeout"].as_integer(), Some(60));
        // New template key added automatically.
        assert_eq!(merged["logging"]["level"].as_str(), Some("INFO"));
        // Conflicts keep operator values (ours-wins).
        assert_eq!(merged["server"]["port"].as_integer(), Some(9000));
        assert_eq!(
            merged["server"]["custom_deleted"].as_str(),
            Some("keep-my-override")
        );
        assert_eq!(merged["server"]["operator_only"].as_str(), Some("stays"));
        // Extension subtables preserved verbatim.
        assert_eq!(
            merged["extensions"]["oidc_sso"]["issuer"].as_str(),
            Some("https://sso.example.org")
        );
        assert_eq!(
            merged["extensions"]["oidc_sso"]["client_id"].as_str(),
            Some("cfms-web")
        );
    }

    #[tokio::test]
    async fn resume_rollback_restores_sqlite_checkpoint_and_source_release_on_explicit_abort() {
        let tmp = TempDir::new().unwrap();
        let v1_pkg = tmp.path().join("cfms-0.13.0.tar.gz");
        let (v1_files, v1_mb) = build_release_bundle_map(
            "0.13.0",
            &[("03197fed3401", None)],
            &base_config_template(""),
            &[("src/v1_only.py", b"V1 = True\n")],
        );
        write_release_targz(&v1_pkg, "", &v1_files, &v1_mb);
        let v1_valid = parse_and_validate_manifest_bytes(&v1_mb, "v1").unwrap();

        let (v2_files, v2_mb) = build_release_bundle_map(
            "0.14.0",
            &[
                ("03197fed3401", None),
                ("16c86712512a", Some("03197fed3401")),
                ("e952c02c1454", Some("16c86712512a")),
            ],
            &base_config_template("\n[logging]\nlevel = \"INFO\"\n"),
            &[("src/v2_only.py", b"V2 = True\n")],
        );
        let v2_valid = parse_and_validate_manifest_bytes(&v2_mb, "v2").unwrap();

        let deploy = tmp.path().join("abort-rollback-deploy");
        install_fixture_release(&deploy, &v1_pkg, true).await;
        let paths = WorkspacePaths::discover(Some(&deploy), None).unwrap();
        let ctx = test_ctx(&deploy);

        let v1_cfg = "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n\n[security]\npepper = \"v1-pepper\"\n\n[server]\nsecret_key = \"v1-secret\"\n";
        fs::write(&paths.config_path, v1_cfg).unwrap();

        // Seed pre-upgrade SQLite DB at source_head with a sentinel row.
        let db = ctx.connect_db(&paths).await.unwrap();
        create_head_schema(&db, false).await.unwrap();
        set_alembic_version(&db, "03197fed3401").await.unwrap();
        if let DbPool::Sqlite(ref sq) = db {
            sqlx::query("CREATE TABLE sentinel_state (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
                .execute(sq)
                .await
                .unwrap();
            sqlx::query("INSERT INTO sentinel_state (k, v) VALUES ('before', 'original')")
                .execute(sq)
                .await
                .unwrap();
        }
        db.close().await;

        // Snapshot source release into versions/ and capture SQLite checkpoint before swap.
        snapshot_active_release(&paths, &v1_valid, &DeploymentSettings::default()).unwrap();
        let stage_v2 = staging_dir(&paths).join("abort-stage-v2");
        write_unpacked_workspace(&stage_v2, &v2_files, Some(&v2_mb));
        let j_dir = paths.maintenance_root.join("tx").join("tx-abort-1");
        let (ckpt_path, ckpt_sha) = capture_sqlite_upgrade_checkpoint(
            &ctx,
            &paths,
            &j_dir.join("db_checkpoint.sqlite"),
        )
        .await
        .unwrap()
        .expect("sqlite deployment must produce checkpoint");
        apply_swap_with_journal(&paths, Some(&v1_valid), &stage_v2, &v2_valid, &j_dir).unwrap();

        // Mutate live config as if 3-way merge ran, then simulate partial DB migration failure
        // leaving DB at Intermediate revision with extra in-flight DDL and mutated data.
        fs::write(
            &paths.config_path,
            format!("{v1_cfg}\n[logging]\nlevel = \"INFO\"\n"),
        )
        .unwrap();
        let db = ctx.connect_db(&paths).await.unwrap();
        set_alembic_version(&db, "16c86712512a").await.unwrap();
        if let DbPool::Sqlite(ref sq) = db {
            sqlx::query("CREATE TABLE inflight_partial_ddl (id INTEGER PRIMARY KEY)")
                .execute(sq)
                .await
                .unwrap();
            sqlx::query("UPDATE sentinel_state SET v = 'mutated-mid-upgrade' WHERE k = 'before'")
                .execute(sq)
                .await
                .unwrap();
        }
        db.close().await;

        let tx = DeploymentTransaction {
            format_version: TRANSACTION_FORMAT_VERSION,
            transaction_id: "tx-abort-1".to_string(),
            operation: TransactionOperation::Upgrade,
            phase: TransactionPhase::DatabaseRecoveryRequired,
            started_at: Some("2026-11-22T00:00:00Z".to_string()),
            source_release_id: v1_valid.release_id.clone(),
            target_release_id: v2_valid.release_id.clone(),
            source_version: "0.13.0".to_string(),
            target_version: "0.14.0".to_string(),
            source_head: Some("03197fed3401".to_string()),
            target_head: Some("e952c02c1454".to_string()),
            staging_dir: Some(stage_v2.display().to_string()),
            journal_dir: Some(j_dir.display().to_string()),
            db_checkpoint_path: Some(ckpt_path.display().to_string()),
            db_checkpoint_sha256: Some(ckpt_sha.clone()),
            last_error: Some("simulated migration failure".to_string()),
            observed_db_revision: Some("16c86712512a".to_string()),
            step_history: vec!["files-swapped".to_string(), "db-migration-failed".to_string()],
        };
        save_transaction(&paths, &tx).unwrap();

        // Dry-run preserves intermediate DB state so operator can still inspect/fix or decide.
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                rollback: true,
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(paths.transaction_path().is_file());
        let db = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(db.current_revision().await.unwrap().as_deref(), Some("16c86712512a"));
        db.close().await;

        // Explicit operator abort (`resume --rollback`) reverts DB + files + config completely.
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                rollback: true,
                skip_env: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(!paths.transaction_path().exists());
        assert!(!deploy.join("src").join("v2_only.py").exists());
        assert!(deploy.join("src").join("v1_only.py").is_file());
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.13.0"
        );
        assert_eq!(fs::read_to_string(&paths.config_path).unwrap(), v1_cfg);
        assert!(!versions_dir(&paths).join(&v1_valid.release_id).exists());

        let db = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(db.current_revision().await.unwrap().as_deref(), Some("03197fed3401"));
        if let DbPool::Sqlite(ref sq) = db {
            let val: String = sqlx::query_scalar("SELECT v FROM sentinel_state WHERE k = 'before'")
                .fetch_one(sq)
                .await
                .unwrap();
            assert_eq!(val, "original");
            let partial_exists: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'inflight_partial_ddl'",
            )
            .fetch_one(sq)
            .await
            .unwrap();
            assert_eq!(partial_exists, 0);
        }
        db.close().await;

        // Also test fallback rollback when swap journal is missing (uses versions/<source_id>/)
        // and DB stopped at an Unknown revision with a valid checkpoint.
        snapshot_active_release(&paths, &v1_valid, &DeploymentSettings::default()).unwrap();
        write_unpacked_workspace(&stage_v2, &v2_files, Some(&v2_mb));
        let j_dir_2 = paths.maintenance_root.join("tx").join("tx-abort-2");
        let (ckpt_path_2, ckpt_sha_2) = capture_sqlite_upgrade_checkpoint(
            &ctx,
            &paths,
            &j_dir_2.join("db_checkpoint.sqlite"),
        )
        .await
        .unwrap()
        .unwrap();
        apply_swap_with_journal(&paths, Some(&v1_valid), &stage_v2, &v2_valid, &j_dir_2).unwrap();
        // Delete journal.json to force fallback to versions/<source_release_id>/.
        fs::remove_file(j_dir_2.join("journal.json")).unwrap();
        fs::write(
            &paths.config_path,
            format!("{v1_cfg}\n[logging]\nlevel = \"DEBUG\"\n"),
        )
        .unwrap();
        let db = ctx.connect_db(&paths).await.unwrap();
        set_alembic_version(&db, "deadbeef0000").await.unwrap();
        db.close().await;

        let tx2 = DeploymentTransaction {
            transaction_id: "tx-abort-2".to_string(),
            journal_dir: Some(j_dir_2.display().to_string()),
            db_checkpoint_path: Some(ckpt_path_2.display().to_string()),
            db_checkpoint_sha256: Some(ckpt_sha_2),
            observed_db_revision: Some("deadbeef0000".to_string()),
            ..tx
        };
        save_transaction(&paths, &tx2).unwrap();

        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                rollback: true,
                skip_env: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(!paths.transaction_path().exists());
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.13.0"
        );
        assert_eq!(fs::read_to_string(&paths.config_path).unwrap(), v1_cfg);
        let db = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(db.current_revision().await.unwrap().as_deref(), Some("03197fed3401"));
        db.close().await;
    }

    #[tokio::test]
    async fn resume_handles_activation_rollback_forward_and_database_recovery_modes() {
        let tmp = TempDir::new().unwrap();
        let v1_pkg = tmp.path().join("cfms-0.13.0.tar.gz");
        let (v1_files, v1_mb) = build_release_bundle_map(
            "0.13.0",
            &[("03197fed3401", None)],
            &base_config_template(""),
            &[],
        );
        write_release_targz(&v1_pkg, "", &v1_files, &v1_mb);
        let v1_valid = parse_and_validate_manifest_bytes(&v1_mb, "v1").unwrap();

        let (v2_files, v2_mb) = build_release_bundle_map(
            "0.14.0",
            &[
                ("03197fed3401", None),
                ("16c86712512a", Some("03197fed3401")),
                ("e952c02c1454", Some("16c86712512a")),
            ],
            &base_config_template(""),
            &[("src/v2_file.py", b"V2 = 1\n")],
        );
        let v2_valid = parse_and_validate_manifest_bytes(&v2_mb, "v2").unwrap();

        let deploy = tmp.path().join("resume-deploy");
        install_fixture_release(&deploy, &v1_pkg, true).await;
        let paths = WorkspacePaths::discover(Some(&deploy), None).unwrap();
        let ctx = test_ctx(&deploy);
        let db = ctx.connect_db(&paths).await.unwrap();
        create_head_schema(&db, false).await.unwrap();
        set_alembic_version(&db, "03197fed3401").await.unwrap();
        db.close().await;

        snapshot_active_release(&paths, &v1_valid, &DeploymentSettings::default()).unwrap();

        // Stage v2 and simulate a swap interrupted in Activation phase with swap journal present.
        let stage_v2 = staging_dir(&paths).join("tx-stage-v2");
        write_unpacked_workspace(&stage_v2, &v2_files, Some(&v2_mb));
        let j_dir = paths.maintenance_root.join("tx").join("tx1");
        apply_swap_with_journal(&paths, Some(&v1_valid), &stage_v2, &v2_valid, &j_dir).unwrap();

        let mut tx = DeploymentTransaction {
            format_version: TRANSACTION_FORMAT_VERSION,
            transaction_id: "tx1".to_string(),
            operation: TransactionOperation::Upgrade,
            phase: TransactionPhase::Activation,
            started_at: Some("2026-11-15T00:00:00Z".to_string()),
            source_release_id: v1_valid.release_id.clone(),
            target_release_id: v2_valid.release_id.clone(),
            source_version: "0.13.0".to_string(),
            target_version: "0.14.0".to_string(),
            source_head: Some("03197fed3401".to_string()),
            target_head: Some("e952c02c1454".to_string()),
            staging_dir: Some(stage_v2.display().to_string()),
            journal_dir: Some(j_dir.display().to_string()),
            db_checkpoint_path: None,
            db_checkpoint_sha256: None,
            last_error: Some("simulated crash".to_string()),
            observed_db_revision: Some("03197fed3401".to_string()),
            step_history: vec!["files-swapped".to_string()],
        };
        save_transaction(&paths, &tx).unwrap();

        // Case 1: Dry-run detects active tx; plain resume rolls back Activation cleanly.
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                skip_env: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!paths.transaction_path().exists());
        assert!(!deploy.join("src").join("v2_file.py").exists());
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.13.0"
        );

        // Case 2: Re-stage v2, apply swap, DB stops at INTERMEDIATE revision `16c86712512a` ->
        // resume --continue-forward advances DB to `e952c02c1454` and cleans tx.
        write_unpacked_workspace(&stage_v2, &v2_files, Some(&v2_mb));
        let j_dir_2 = paths.maintenance_root.join("tx").join("tx2");
        apply_swap_with_journal(&paths, Some(&v1_valid), &stage_v2, &v2_valid, &j_dir_2).unwrap();
        let db = ctx.connect_db(&paths).await.unwrap();
        set_alembic_version(&db, "16c86712512a").await.unwrap();
        db.close().await;

        tx.transaction_id = "tx2".to_string();
        tx.phase = TransactionPhase::DatabaseRecoveryRequired;
        tx.journal_dir = Some(j_dir_2.display().to_string());
        tx.observed_db_revision = Some("16c86712512a".to_string());
        save_transaction(&paths, &tx).unwrap();

        // First dry-run inspects intermediate state without clearing tx.
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(paths.transaction_path().is_file());

        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                continue_forward: true,
                skip_env: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!paths.transaction_path().exists());
        let db = ctx.connect_db(&paths).await.unwrap();
        assert_eq!(db.current_revision().await.unwrap().as_deref(), Some("e952c02c1454"));
        db.close().await;

        // Case 3: AtTarget recovery finalizes cleanly, and --abort-clear clears unknown tx.
        save_transaction(&paths, &tx).unwrap();
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                skip_env: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!paths.transaction_path().exists());

        save_transaction(&paths, &tx).unwrap();
        handle_resume(
            &ctx,
            DeploymentResumeArgs {
                abort_clear: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!paths.transaction_path().exists());
    }

    #[tokio::test]
    async fn verify_and_prune_handle_tampering_prefixes_keep_corrupt_and_all() {
        let tmp = TempDir::new().unwrap();
        let mut pkgs = Vec::new();
        let mut ids = Vec::new();
        for (idx, ver) in ["0.14.0", "0.14.1", "0.14.2"].iter().enumerate() {
            let p = tmp.path().join(format!("cfms-{ver}.tar.gz"));
            let extra_path = format!("src/step_{idx}.py");
            let (files, mb) = build_release_bundle_map(
                ver,
                &[("e952c02c1454", None)],
                &base_config_template(""),
                &[(extra_path.as_str(), ver.as_bytes())],
            );
            write_release_targz(&p, "", &files, &mb);
            let valid = parse_and_validate_manifest_bytes(&mb, ver).unwrap();
            ids.push(valid.release_id);
            pkgs.push(p);
        }

        let deploy = tmp.path().join("prune-deploy");
        install_fixture_release(&deploy, &pkgs[0], false).await;
        let ctx = test_ctx(&deploy);
        for pkg in &pkgs[1..] {
            handle_upgrade(
                &ctx,
                DeploymentUpgradeArgs {
                    package: pkg.clone(),
                    checksum: LocalChecksumArgs::default(),
                    env: DeploymentEnvArgs {
                        skip_env: true,
                        ..Default::default()
                    },
                    backup: SafetyBackupArgs::default(),
                    allow_destructive: false,
                    dry_run: false,
                },
            )
            .await
            .unwrap();
        }
        let paths = WorkspacePaths::discover(Some(&deploy), None).unwrap();

        // After upgrading 0.14.0 -> 0.14.1 -> 0.14.2, auto-prune keeps at most 1 old version (0.14.1).
        assert!(!paths.maintenance_root.join("versions").join(&ids[0]).exists());
        assert!(paths.maintenance_root.join("versions").join(&ids[1]).is_dir());

        // Tamper active tracked file -> handle_verify fails; restoring passes.
        let main_py = deploy.join("src").join("main.py");
        let orig_main = fs::read(&main_py).unwrap();
        fs::write(&main_py, b"# malicious drift").unwrap();
        assert!(
            handle_verify(
                &ctx,
                DeploymentVerifyArgs {
                    release: None,
                    active_only: true,
                },
            )
            .await
            .is_err()
        );
        fs::write(&main_py, orig_main).unwrap();
        handle_verify(
            &ctx,
            DeploymentVerifyArgs {
                release: None,
                active_only: false,
            },
        )
        .await
        .unwrap();

        // Add corrupt snapshot sibling; ensure `--corrupt --dry-run` keeps it and `--corrupt` cleans only corrupt.
        let corrupt_dir = paths.maintenance_root.join("versions").join("bad_corrupt_snapshot");
        fs::create_dir_all(&corrupt_dir).unwrap();
        fs::write(corrupt_dir.join("junk.txt"), b"x").unwrap();

        handle_prune(
            &ctx,
            DeploymentPruneArgs {
                keep: None,
                release: Vec::new(),
                corrupt: true,
                all: false,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(corrupt_dir.is_dir());

        handle_prune(
            &ctx,
            DeploymentPruneArgs {
                keep: None,
                release: Vec::new(),
                corrupt: true,
                all: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert!(!corrupt_dir.exists());
        assert!(paths.maintenance_root.join("versions").join(&ids[1]).is_dir());

        // Re-add a damaged sibling and verify `--keep 1` retains the newest healthy snapshot
        // while pruning damaged directories.
        fs::create_dir_all(&corrupt_dir).unwrap();
        fs::write(corrupt_dir.join("junk.txt"), b"x").unwrap();

        handle_prune(
            &ctx,
            DeploymentPruneArgs {
                keep: Some(1),
                release: Vec::new(),
                corrupt: false,
                all: false,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(corrupt_dir.is_dir());

        handle_prune(
            &ctx,
            DeploymentPruneArgs {
                keep: Some(1),
                release: Vec::new(),
                corrupt: false,
                all: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert!(!corrupt_dir.exists());
        assert!(paths.maintenance_root.join("versions").join(&ids[1]).exists());

        // Active transaction protects its source_release_id from `--all` pruning.
        let active_tx = DeploymentTransaction {
            format_version: TRANSACTION_FORMAT_VERSION,
            transaction_id: "tx-protect".to_string(),
            operation: TransactionOperation::Upgrade,
            phase: TransactionPhase::DatabaseRecoveryRequired,
            started_at: Some("2026-11-22T00:00:00Z".to_string()),
            source_release_id: ids[1].clone(),
            target_release_id: ids[2].clone(),
            source_version: "0.14.1".to_string(),
            target_version: "0.14.2".to_string(),
            source_head: Some("e952c02c1454".to_string()),
            target_head: Some("e952c02c1454".to_string()),
            staging_dir: None,
            journal_dir: None,
            db_checkpoint_path: None,
            db_checkpoint_sha256: None,
            last_error: Some("in-progress".to_string()),
            observed_db_revision: None,
            step_history: Vec::new(),
        };
        save_transaction(&paths, &active_tx).unwrap();
        // Both CLI `handle_prune` (rejecting while transaction is active) and `plan_prune`
        // (retaining `tx.source_release_id`) protect the active transaction's rollback snapshot.
        let prune_during_tx_err = handle_prune(
            &ctx,
            DeploymentPruneArgs {
                keep: None,
                release: Vec::new(),
                corrupt: false,
                all: true,
                dry_run: false,
            },
        )
        .await
        .expect_err("handle_prune must refuse to run during an active transaction");
        assert!(matches!(prune_during_tx_err, CfmsError::UnfinishedTransaction(_)));
        let protected_plan = plan_prune(&paths, &PruneSelector::AllInactive).unwrap();
        assert!(protected_plan.keep_ids.contains(&ids[1]));
        assert!(protected_plan.remove.is_empty());
        assert!(paths.maintenance_root.join("versions").join(&ids[1]).exists());
        clear_transaction_artifacts(&paths, Some(&active_tx)).unwrap();

        // Once transaction is cleared, `--all` removes remaining inactive snapshot while never deleting active release or state.
        handle_prune(
            &ctx,
            DeploymentPruneArgs {
                keep: None,
                release: Vec::new(),
                corrupt: false,
                all: true,
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert!(!paths.maintenance_root.join("versions").join(&ids[1]).exists());
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.14.2"
        );
    }

    #[tokio::test]
    async fn check_and_update_work_end_to_end_against_mock_github_server() {
        let tmp = TempDir::new().unwrap();
        let v1_pkg = tmp.path().join("cfms-0.14.0.tar.gz");
        let (v1_files, v1_mb) = build_release_bundle_map(
            "0.14.0",
            &[("e952c02c1454", None)],
            &base_config_template(""),
            &[],
        );
        write_release_targz(&v1_pkg, "", &v1_files, &v1_mb);

        let v2_tar_name = "cfms-on-websocket-0.15.0.tar.gz";
        let v2_pkg = tmp.path().join(v2_tar_name);
        let (v2_files, v2_mb) = build_release_bundle_map(
            "0.15.0",
            &[("e952c02c1454", None)],
            &base_config_template("\n[logging]\nlevel = \"DEBUG\"\n"),
            &[("src/online_updated.py", b"ONLINE = True\n")],
        );
        write_release_targz(&v2_pkg, "cfms-0.15.0", &v2_files, &v2_mb);
        let v2_bytes = fs::read(&v2_pkg).unwrap();
        let v2_sha = sha256_hex(&v2_bytes);
        let sums_body = format!("{v2_sha}  {v2_tar_name}\n{v2_sha}  cfms-on-websocket-0.14.0.tar.gz\n");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let base_clone = base_url.clone();
        let server_task = tokio::spawn(async move {
            for _ in 0..12 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (status, ctype, body): (&str, &str, Vec<u8>) = if path.contains("/releases/latest") {
                    let json = serde_json::json!({
                        "tag_name": "v0.15.0",
                        "draft": false,
                        "prerelease": false,
                        "html_url": format!("{base_clone}/rel/v0.15.0"),
                        "published_at": "2026-11-15T00:00:00Z",
                        "assets": [
                            {
                                "name": v2_tar_name,
                                "size": v2_bytes.len(),
                                "browser_download_url": format!("{base_clone}/dl/{v2_tar_name}"),
                                "digest": serde_json::Value::Null
                            },
                            {
                                "name": "SHA256SUMS.txt",
                                "size": sums_body.len(),
                                "browser_download_url": format!("{base_clone}/dl/SHA256SUMS.txt"),
                                "digest": format!("sha256:{}", sha256_hex(sums_body.as_bytes()))
                            }
                        ]
                    });
                    ("200 OK", "application/json", serde_json::to_vec(&json).unwrap())
                } else if path.contains("/releases/tags/v0.14.0") {
                    let json = serde_json::json!({
                        "tag_name": "v0.14.0",
                        "draft": false,
                        "prerelease": false,
                        "html_url": format!("{base_clone}/rel/v0.14.0"),
                        "published_at": "2026-11-01T00:00:00Z",
                        "assets": [
                            {
                                "name": "cfms-on-websocket-0.14.0.tar.gz",
                                "size": 100,
                                "browser_download_url": format!("{base_clone}/dl/cfms-on-websocket-0.14.0.tar.gz"),
                                "digest": serde_json::Value::Null
                            },
                            {
                                "name": "SHA256SUMS.txt",
                                "size": sums_body.len(),
                                "browser_download_url": format!("{base_clone}/dl/SHA256SUMS.txt"),
                                "digest": format!("sha256:{}", sha256_hex(sums_body.as_bytes()))
                            }
                        ]
                    });
                    ("200 OK", "application/json", serde_json::to_vec(&json).unwrap())
                } else if path.ends_with(v2_tar_name) {
                    ("200 OK", "application/octet-stream", v2_bytes.clone())
                } else if path.ends_with("SHA256SUMS.txt") {
                    ("200 OK", "text/plain", sums_body.as_bytes().to_vec())
                } else {
                    ("404 Not Found", "text/plain", b"not found".to_vec())
                };

                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            }
        });

        let deploy = tmp.path().join("online-deploy");
        install_fixture_release(&deploy, &v1_pkg, false).await;
        let ctx = test_ctx(&deploy);
        let online_cfg = OnlineClientConfig {
            owner: "cfms-dev".to_string(),
            repo: "cfms_on_websocket".to_string(),
            api_base_url: Url::parse(&base_url).unwrap(),
            auth_token: None,
        };

        run_check_with_config(
            &ctx,
            DeploymentCheckArgs {
                online: OnlineReleaseArgs {
                    format: ReleaseArchiveFormat::TarGz,
                    ..Default::default()
                },
            },
            &online_cfg,
        )
        .await
        .unwrap();

        run_update_with_config(
            &ctx,
            DeploymentUpdateArgs {
                online: OnlineReleaseArgs {
                    format: ReleaseArchiveFormat::TarGz,
                    ..Default::default()
                },
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                require_github_digest: false,
                allow_destructive: false,
                dry_run: false,
            },
            &online_cfg,
        )
        .await
        .unwrap();

        let paths = WorkspacePaths::discover(Some(&deploy), None).unwrap();
        assert_eq!(
            load_manifest_file(&paths.release_manifest_path)
                .unwrap()
                .manifest
                .version,
            "0.15.0"
        );
        assert!(deploy.join("src").join("online_updated.py").is_file());

        // Second `update` reports already up-to-date.
        run_update_with_config(
            &ctx,
            DeploymentUpdateArgs {
                online: OnlineReleaseArgs {
                    format: ReleaseArchiveFormat::TarGz,
                    ..Default::default()
                },
                env: DeploymentEnvArgs {
                    skip_env: true,
                    ..Default::default()
                },
                backup: SafetyBackupArgs::default(),
                require_github_digest: false,
                allow_destructive: false,
                dry_run: false,
            },
            &online_cfg,
        )
        .await
        .unwrap();

        // Requesting an older version via `--version` is rejected (downgrades prohibited).
        let down_err = run_check_with_config(
            &ctx,
            DeploymentCheckArgs {
                online: OnlineReleaseArgs {
                    version: Some("0.14.0".to_string()),
                    format: ReleaseArchiveFormat::TarGz,
                    ..Default::default()
                },
            },
            &online_cfg,
        )
        .await
        .expect_err("pinned older version must be rejected");
        assert!(down_err.to_string().contains("older") || down_err.to_string().contains("downgrade"));

        server_task.abort();
    }

    #[tokio::test]
    async fn status_diagnostic_succeeds_when_unmanaged_server_version_is_missing() {
        let tmp = TempDir::new().unwrap();
        let (files, _manifest_bytes) = build_release_bundle_map(
            "0.14.0",
            &[("e952c02c1454", None)],
            &base_config_template(""),
            &[],
        );

        let unpacked = tmp.path().join("unpacked_no_ver");
        write_unpacked_workspace(&unpacked, &files, None);
        fs::write(unpacked.join("src").join("config.toml"), base_config_template("")).unwrap();
        let pyproject = unpacked.join("pyproject.toml");
        if pyproject.exists() {
            fs::remove_file(&pyproject).unwrap();
        }
        let constants = unpacked.join("src/include/config/constants.py");
        if constants.exists() {
            fs::remove_file(&constants).unwrap();
        }
        assert!(!unpacked.join("release-manifest.json").exists());

        let ctx = test_ctx(&unpacked);
        handle_status(&ctx, DeploymentStatusArgs { verify: false })
            .await
            .expect("diagnostic status must still succeed without detectable server version");
    }

}
