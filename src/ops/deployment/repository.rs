//! Workspace snapshot repository, isolated active/stored release verification,
//! reversible transaction-journalled delta swaps, and selective snapshot pruning.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::core::{
    CfmsError, Result, WorkspacePaths, atomic_write, ensure_safe_directory_chain,
    is_symlink_or_reparse_point, retry_fs_op,
};
use crate::ops::extension::version::CfmsServerVersion;

use super::manifest::{
    hash_file_sha256, is_preserved_workspace_path, load_manifest_file, validate_manifest_rel_path,
};
use super::models::{
    DeploymentSettings, DeploymentTransaction, IntegrityMismatch, MAX_STATE_BYTES,
    MAX_STORED_RELEASES, QUARANTINE_DIRNAME, RELEASE_MANIFEST_FILENAME, RELEASE_SUBDIR,
    REQUIREMENTS_LOCK_FILENAME, ReleaseIntegrityReport, ReleaseManifest, SETTINGS_FILENAME,
    SETTINGS_FORMAT_VERSION, STATE_DIRNAME, STAGING_DIRNAME, StoredReleaseSummary,
    TX_JOURNAL_DIRNAME, VERSIONS_DIRNAME, ValidatedManifest,
};

#[derive(Debug, Clone)]
pub struct StoredReleaseHandle {
    pub summary: StoredReleaseSummary,
    pub root_dir: PathBuf,
    pub release_dir: PathBuf,
    pub state_dir: PathBuf,
    pub manifest: ValidatedManifest,
}

#[derive(Debug, Clone)]
pub struct DeltaSwapCounts {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwapJournalRecord {
    added_files: Vec<String>,
    backed_up_files: Vec<String>,
    had_previous_manifest: bool,
    #[serde(default)]
    pre_swap_config_backed_up: bool,
}

#[must_use]
pub fn versions_dir(paths: &WorkspacePaths) -> PathBuf {
    paths.maintenance_root.join(VERSIONS_DIRNAME)
}

#[must_use]
pub fn staging_dir(paths: &WorkspacePaths) -> PathBuf {
    paths.maintenance_root.join(STAGING_DIRNAME)
}

#[must_use]
pub fn tx_root_dir(paths: &WorkspacePaths) -> PathBuf {
    paths.maintenance_root.join(TX_JOURNAL_DIRNAME)
}

#[must_use]
pub fn quarantine_dir(paths: &WorkspacePaths) -> PathBuf {
    paths.maintenance_root.join(QUARANTINE_DIRNAME)
}

#[must_use]
pub fn settings_path(paths: &WorkspacePaths) -> PathBuf {
    paths.maintenance_root.join(SETTINGS_FILENAME)
}

#[must_use]
pub fn requirements_lock_path(paths: &WorkspacePaths) -> PathBuf {
    paths.maintenance_root.join(REQUIREMENTS_LOCK_FILENAME)
}

pub fn load_settings(paths: &WorkspacePaths) -> Result<DeploymentSettings> {
    let path = settings_path(paths);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DeploymentSettings::default());
        }
        Err(err) => return Err(CfmsError::Io(err)),
    };
    if is_symlink_or_reparse_point(&meta) || !meta.is_file() {
        return Err(CfmsError::Deployment(format!(
            "Deployment settings path '{}' must be a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_STATE_BYTES {
        return Err(CfmsError::Deployment(format!(
            "Deployment settings file '{}' exceeds {MAX_STATE_BYTES}-byte limit",
            path.display()
        )));
    }
    let raw = fs::read_to_string(&path)?;
    let mut settings: DeploymentSettings = serde_json::from_str(&raw).map_err(|err| {
        CfmsError::Deployment(format!("Invalid settings JSON '{}': {err}", path.display()))
    })?;
    if settings.format_version != SETTINGS_FORMAT_VERSION {
        return Err(CfmsError::Deployment(format!(
            "Unsupported settings format_version {} in '{}'",
            settings.format_version,
            path.display()
        )));
    }
    settings.extras.sort();
    settings.extras.dedup();
    Ok(settings)
}

pub fn save_settings(paths: &WorkspacePaths, settings: &DeploymentSettings) -> Result<()> {
    let mut normalized = settings.clone();
    normalized.format_version = SETTINGS_FORMAT_VERSION;
    normalized.extras.sort();
    normalized.extras.dedup();
    let raw = serde_json::to_vec_pretty(&normalized).map_err(|err| {
        CfmsError::Deployment(format!("Failed to serialize settings: {err}"))
    })?;
    atomic_write(&settings_path(paths), &raw)
}

pub fn load_transaction(paths: &WorkspacePaths) -> Result<Option<DeploymentTransaction>> {
    let path = paths.transaction_path();
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CfmsError::Io(err)),
    };
    if is_symlink_or_reparse_point(&meta) || !meta.is_file() {
        return Err(CfmsError::Deployment(format!(
            "Transaction journal '{}' must be a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_STATE_BYTES {
        return Err(CfmsError::Deployment(format!(
            "Transaction journal '{}' exceeds {MAX_STATE_BYTES}-byte limit",
            path.display()
        )));
    }
    let raw = fs::read_to_string(&path)?;
    let tx: DeploymentTransaction = serde_json::from_str(&raw).map_err(|err| {
        CfmsError::Deployment(format!(
            "Corrupt transaction journal '{}': {err}",
            path.display()
        ))
    })?;
    Ok(Some(tx))
}

pub fn save_transaction(paths: &WorkspacePaths, tx: &DeploymentTransaction) -> Result<()> {
    let raw = serde_json::to_vec_pretty(tx).map_err(|err| {
        CfmsError::Deployment(format!("Failed to serialize transaction.json: {err}"))
    })?;
    atomic_write(&paths.transaction_path(), &raw)
}

pub fn clear_transaction_artifacts(paths: &WorkspacePaths, tx: Option<&DeploymentTransaction>) -> Result<()> {
    if let Some(record) = tx
        && let Some(ref j_dir) = record.journal_dir
    {
        let p = PathBuf::from(j_dir);
        if p.exists() {
            let _ = retry_fs_op(|| fs::remove_dir_all(&p));
        }
    }
    let tx_path = paths.transaction_path();
    if tx_path.exists() {
        retry_fs_op(|| match fs::remove_file(&tx_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        })?;
    }
    Ok(())
}

/// Validate external `requirements.lock` and copy/remove `src/.maintenance/requirements.lock`.
pub fn validate_requirements_lock_file(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if is_symlink_or_reparse_point(&meta) || !meta.is_file() {
        return Err(CfmsError::Deployment(format!(
            "requirements.lock '{}' must be a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_STATE_BYTES {
        return Err(CfmsError::Deployment(format!(
            "requirements.lock '{}' exceeds {MAX_STATE_BYTES}-byte limit",
            path.display()
        )));
    }
    let bytes = fs::read(path)?;
    std::str::from_utf8(&bytes).map_err(|err| {
        CfmsError::Deployment(format!(
            "requirements.lock '{}' must be valid UTF-8: {err}",
            path.display()
        ))
    })?;
    Ok(bytes)
}

pub fn sync_persisted_requirements_lock(
    paths: &WorkspacePaths,
    new_lock_source: Option<&Path>,
    clear_lock: bool,
) -> Result<()> {
    let dest = requirements_lock_path(paths);
    if clear_lock {
        if dest.exists() {
            retry_fs_op(|| match fs::remove_file(&dest) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            })?;
        }
        return Ok(());
    }
    if let Some(src) = new_lock_source {
        let bytes = validate_requirements_lock_file(src)?;
        atomic_write(&dest, &bytes)?;
    }
    Ok(())
}

/// Inspect active workspace release against `release-manifest.json`.
///
/// When `verify_hashes == false`, checks structural file presence and regular-file hygiene in O(files)
/// stat operations; when `verify_hashes == true`, streams SHA-256 digests of every managed file.
pub fn inspect_active_release(
    paths: &WorkspacePaths,
    verify_hashes: bool,
) -> Result<ReleaseIntegrityReport> {
    let validated = load_manifest_file(&paths.release_manifest_path)?;
    Ok(verify_tree_against_manifest(
        "active",
        &paths.project_root,
        &validated,
        verify_hashes,
        false,
    ))
}

fn verify_tree_against_manifest(
    target_label: &str,
    root_dir: &Path,
    validated: &ValidatedManifest,
    verify_hashes: bool,
    forbid_extra_files: bool,
) -> ReleaseIntegrityReport {
    let mut mismatches = Vec::new();
    let mut checked = 0usize;

    for (rel_posix, expected_hash) in &validated.manifest.files {
        checked += 1;
        let full = root_dir.join(rel_posix);
        match fs::symlink_metadata(&full) {
            Ok(meta) => {
                if is_symlink_or_reparse_point(&meta) {
                    mismatches.push(IntegrityMismatch {
                        path: rel_posix.clone(),
                        kind: "symlink".to_string(),
                        detail: "Tracked release file was replaced by a symlink or junction"
                            .to_string(),
                    });
                    continue;
                }
                if !meta.is_file() {
                    mismatches.push(IntegrityMismatch {
                        path: rel_posix.clone(),
                        kind: "not-a-file".to_string(),
                        detail: "Expected regular file".to_string(),
                    });
                    continue;
                }
                if verify_hashes {
                    match hash_file_sha256(&full) {
                        Ok((actual_hash, _)) => {
                            if &actual_hash != expected_hash {
                                mismatches.push(IntegrityMismatch {
                                    path: rel_posix.clone(),
                                    kind: "hash-mismatch".to_string(),
                                    detail: format!(
                                        "expected {expected_hash}, got {actual_hash}"
                                    ),
                                });
                            }
                        }
                        Err(err) => mismatches.push(IntegrityMismatch {
                            path: rel_posix.clone(),
                            kind: "read-error".to_string(),
                            detail: err.to_string(),
                        }),
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                mismatches.push(IntegrityMismatch {
                    path: rel_posix.clone(),
                    kind: "missing".to_string(),
                    detail: "File missing from release tree".to_string(),
                });
            }
            Err(err) => {
                mismatches.push(IntegrityMismatch {
                    path: rel_posix.clone(),
                    kind: "io-error".to_string(),
                    detail: err.to_string(),
                });
            }
        }
    }

    if forbid_extra_files
        && let Ok(actual) = super::archive::collect_regular_files_rel(root_dir)
    {
        let expected: BTreeSet<&str> =
            validated.manifest.files.keys().map(String::as_str).collect();
        for rel in actual {
            if rel != RELEASE_MANIFEST_FILENAME && !expected.contains(rel.as_str()) {
                mismatches.push(IntegrityMismatch {
                    path: rel,
                    kind: "unexpected".to_string(),
                    detail: "Untracked extra file inside snapshot release directory".to_string(),
                });
            }
        }
    }

    ReleaseIntegrityReport {
        target: target_label.to_string(),
        release_id: Some(validated.release_id.clone()),
        version: Some(validated.manifest.version.clone()),
        healthy: mismatches.is_empty(),
        checked_files: checked,
        verified_hashes: verify_hashes,
        mismatches,
    }
}

/// Enumerate all stored historical release directories under `src/.maintenance/versions/` without
/// letting a single corrupt entry crash status or prune reporting.
pub fn list_stored_releases(
    paths: &WorkspacePaths,
    active_release_id: Option<&str>,
    verify_hashes: bool,
) -> Result<Vec<StoredReleaseSummary>> {
    let dir = versions_dir(paths);
    let meta = match fs::symlink_metadata(&dir) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(CfmsError::Io(err)),
    };
    if is_symlink_or_reparse_point(&meta) || !meta.is_dir() {
        return Err(CfmsError::Deployment(format!(
            "Stored versions directory '{}' must be a real directory",
            dir.display()
        )));
    }

    let mut entries = Vec::new();
    for item in fs::read_dir(&dir)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        entries.push((name, item.path()));
    }
    if entries.len() > MAX_STORED_RELEASES {
        return Err(CfmsError::Deployment(format!(
            "Stored versions count ({}) exceeds safety limit {MAX_STORED_RELEASES}",
            entries.len()
        )));
    }

    let mut summaries = Vec::new();
    for (dir_name, entry_path) in entries {
        summaries.push(inspect_stored_release_dir(
            &dir_name,
            &entry_path,
            active_release_id,
            verify_hashes,
        ));
    }

    // Sort newest version / newest mtime first so `--keep N` retains the freshest releases.
    summaries.sort_by(|a, b| {
        let va = a.version.as_deref().and_then(|v| CfmsServerVersion::parse(v).ok());
        let vb = b.version.as_deref().and_then(|v| CfmsServerVersion::parse(v).ok());
        match (vb, va) {
            (Some(vb), Some(va)) => vb.cmp(&va),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
        .then_with(|| b.created_epoch_secs.cmp(&a.created_epoch_secs))
        .then_with(|| a.release_id.cmp(&b.release_id))
    });

    Ok(summaries)
}

fn inspect_stored_release_dir(
    dir_name: &str,
    entry_path: &Path,
    active_release_id: Option<&str>,
    verify_hashes: bool,
) -> StoredReleaseSummary {
    let mut issues = Vec::new();
    let created_epoch_secs = fs::symlink_metadata(entry_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let total_bytes = dir_size_bytes(entry_path).unwrap_or(0);
    let active = active_release_id.is_some_and(|a| a == dir_name);

    let meta = match fs::symlink_metadata(entry_path) {
        Ok(m) => m,
        Err(err) => {
            return StoredReleaseSummary {
                release_id: dir_name.to_string(),
                version: None,
                requires_python: None,
                file_count: 0,
                total_bytes,
                has_saved_state: false,
                active,
                healthy: false,
                verified_hashes: verify_hashes,
                created_epoch_secs,
                issues: vec![format!("Unable to stat snapshot directory: {err}")],
            };
        }
    };

    if is_symlink_or_reparse_point(&meta) || !meta.is_dir() {
        return StoredReleaseSummary {
            release_id: dir_name.to_string(),
            version: None,
            requires_python: None,
            file_count: 0,
            total_bytes,
            has_saved_state: false,
            active,
            healthy: false,
            verified_hashes: verify_hashes,
            created_epoch_secs,
            issues: vec!["Snapshot entry must be a real directory (not a symlink or file)".to_string()],
        };
    }

    let release_subdir = entry_path.join(RELEASE_SUBDIR);
    let manifest_path = release_subdir.join(RELEASE_MANIFEST_FILENAME);
    let has_saved_state = entry_path.join(STATE_DIRNAME).is_dir();

    match load_manifest_file(&manifest_path) {
        Ok(validated) => {
            if validated.release_id != dir_name {
                issues.push(format!(
                    "Snapshot directory name '{dir_name}' does not match manifest release_id '{}'",
                    validated.release_id
                ));
            }
            let report = verify_tree_against_manifest(
                &format!("stored:{dir_name}"),
                &release_subdir,
                &validated,
                verify_hashes,
                true,
            );
            for m in report.mismatches {
                issues.push(format!("{} ({}): {}", m.path, m.kind, m.detail));
            }
            StoredReleaseSummary {
                release_id: dir_name.to_string(),
                version: Some(validated.manifest.version),
                requires_python: Some(validated.manifest.requires_python),
                file_count: validated.manifest.files.len(),
                total_bytes,
                has_saved_state,
                active,
                healthy: issues.is_empty(),
                verified_hashes: verify_hashes,
                created_epoch_secs,
                issues,
            }
        }
        Err(err) => StoredReleaseSummary {
            release_id: dir_name.to_string(),
            version: None,
            requires_python: None,
            file_count: 0,
            total_bytes,
            has_saved_state,
            active,
            healthy: false,
            verified_hashes: verify_hashes,
            created_epoch_secs,
            issues: vec![err.to_string()],
        },
    }
}

/// Resolve a stored release cleanly by full ID, unambiguous hex prefix, or `--version`.
pub fn resolve_stored_release(
    paths: &WorkspacePaths,
    id_or_prefix: Option<&str>,
    version: Option<&str>,
    active_release_id: Option<&str>,
) -> Result<StoredReleaseHandle> {
    let summaries = list_stored_releases(paths, active_release_id, true)?;
    let matches: Vec<StoredReleaseSummary> = if let Some(raw_id) = id_or_prefix {
        let needle = raw_id.trim().to_ascii_lowercase();
        if needle.len() < 6 || !needle.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CfmsError::InvalidArgument(format!(
                "Invalid release ID or prefix '{raw_id}' (expected at least 6 hexadecimal characters)"
            )));
        }
        if let Some(exact) = summaries.iter().find(|s| s.release_id == needle) {
            vec![exact.clone()]
        } else {
            summaries
                .iter()
                .filter(|s| s.release_id.starts_with(&needle))
                .cloned()
                .collect()
        }
    } else if let Some(req_ver) = version {
        let trimmed = req_ver.trim().trim_start_matches('v');
        summaries
            .iter()
            .filter(|s| s.version.as_deref() == Some(trimmed))
            .cloned()
            .collect()
    } else {
        return Err(CfmsError::InvalidArgument(
            "Provide a stored release ID/prefix or `--version`".to_string(),
        ));
    };

    if matches.is_empty() {
        return Err(CfmsError::Deployment(format!(
            "No stored snapshot matching {} found under '{}'",
            id_or_prefix
                .map(|id| format!("ID/prefix '{id}'"))
                .unwrap_or_else(|| format!("version '{}'", version.unwrap_or(""))),
            versions_dir(paths).display()
        )));
    }
    if matches.len() > 1 {
        let candidates = matches
            .iter()
            .map(|m| {
                format!(
                    "{} (v{})",
                    &m.release_id[..12.min(m.release_id.len())],
                    m.version.as_deref().unwrap_or("unknown")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CfmsError::InvalidArgument(format!(
            "Release lookup is ambiguous across multiple snapshots: {candidates}; pass a longer release ID"
        )));
    }

    let summary = matches.into_iter().next().unwrap();
    if !summary.healthy {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Stored release '{}' is damaged and cannot be activated: {}",
            summary.release_id,
            summary.issues.join("; ")
        )));
    }

    let root_dir = versions_dir(paths).join(&summary.release_id);
    let release_dir = root_dir.join(RELEASE_SUBDIR);
    let state_dir = root_dir.join(STATE_DIRNAME);
    let manifest = load_manifest_file(&release_dir.join(RELEASE_MANIFEST_FILENAME))?;

    Ok(StoredReleaseHandle {
        summary,
        root_dir,
        release_dir,
        state_dir,
        manifest,
    })
}

/// Snapshot the active release tree AND operator state into `src/.maintenance/versions/<release_id>/`
/// atomically so rollbacks and downgrades never depend on fragile live workspace state.
pub fn snapshot_active_release(
    paths: &WorkspacePaths,
    validated: &ValidatedManifest,
    settings: &DeploymentSettings,
) -> Result<PathBuf> {
    let base_versions = versions_dir(paths);
    fs::create_dir_all(&base_versions)?;

    let final_dir = base_versions.join(&validated.release_id);
    let release_target = final_dir.join(RELEASE_SUBDIR);

    if final_dir.exists() {
        // Refresh saved `state/` cleanly while preserving verified immutable `release/` if intact.
        let existing_summary = inspect_stored_release_dir(
            &validated.release_id,
            &final_dir,
            Some(&validated.release_id),
            true,
        );
        if existing_summary.healthy {
            let state_dir = final_dir.join(STATE_DIRNAME);
            snapshot_state_into_dir(paths, validated, settings, &state_dir)?;
            return Ok(final_dir);
        }
        // Corrupt existing snapshot for the active version gets atomically rebuilt cleanly.
        retry_fs_op(|| fs::remove_dir_all(&final_dir))?;
    }

    let tmp_guard = tempfile::Builder::new()
        .prefix(&format!(".snap-{}-", &validated.release_id[..8.min(validated.release_id.len())]))
        .tempdir_in(&base_versions)?;
    let tmp_release = tmp_guard.path().join(RELEASE_SUBDIR);
    fs::create_dir_all(&tmp_release)?;

    for (rel_posix, expected_hash) in &validated.manifest.files {
        validate_manifest_rel_path(rel_posix)?;
        let src_file = paths.project_root.join(rel_posix);
        let (actual_hash, _) = hash_file_sha256(&src_file)?;
        if &actual_hash != expected_hash {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Cannot snapshot active release '{}': file '{rel_posix}' does not match manifest hash",
                validated.release_id
            )));
        }
        let dst_file = tmp_release.join(rel_posix);
        if let Some(parent) = Path::new(rel_posix).parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_safe_directory_chain(&tmp_release, parent)?;
        }
        fs::copy(&src_file, &dst_file)?;
    }

    atomic_write(&tmp_release.join(RELEASE_MANIFEST_FILENAME), &validated.raw_bytes)?;
    let tmp_state = tmp_guard.path().join(STATE_DIRNAME);
    snapshot_state_into_dir(paths, validated, settings, &tmp_state)?;

    let staged_root = tmp_guard.keep();
    if let Err(err) = retry_fs_op(|| fs::rename(&staged_root, &final_dir)) {
        let _ = retry_fs_op(|| fs::remove_dir_all(&staged_root));
        return Err(CfmsError::Io(err));
    }

    let _ = release_target;
    Ok(final_dir)
}

/// Persist an already-verified release directory (e.g. from staging during upgrade/install)
/// into `src/.maintenance/versions/<release_id>/release/` when needed (e.g. install / adopt).
pub fn snapshot_from_verified_tree(
    paths: &WorkspacePaths,
    source_tree: &Path,
    validated: &ValidatedManifest,
    settings: &DeploymentSettings,
) -> Result<PathBuf> {
    let base_versions = versions_dir(paths);
    fs::create_dir_all(&base_versions)?;
    let final_dir = base_versions.join(&validated.release_id);
    if final_dir.exists() {
        let summary = inspect_stored_release_dir(
            &validated.release_id,
            &final_dir,
            Some(&validated.release_id),
            true,
        );
        if summary.healthy {
            snapshot_state_into_dir(paths, validated, settings, &final_dir.join(STATE_DIRNAME))?;
            return Ok(final_dir);
        }
        retry_fs_op(|| fs::remove_dir_all(&final_dir))?;
    }

    let tmp_guard = tempfile::Builder::new()
        .prefix(".snap-")
        .tempdir_in(&base_versions)?;
    let tmp_release = tmp_guard.path().join(RELEASE_SUBDIR);
    fs::create_dir_all(&tmp_release)?;

    for rel_posix in validated.manifest.files.keys() {
        let src_file = source_tree.join(rel_posix);
        let dst_file = tmp_release.join(rel_posix);
        if let Some(parent) = Path::new(rel_posix).parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_safe_directory_chain(&tmp_release, parent)?;
        }
        fs::copy(&src_file, &dst_file)?;
    }
    atomic_write(&tmp_release.join(RELEASE_MANIFEST_FILENAME), &validated.raw_bytes)?;
    snapshot_state_into_dir(paths, validated, settings, &tmp_guard.path().join(STATE_DIRNAME))?;

    let staged_root = tmp_guard.keep();
    if let Err(err) = retry_fs_op(|| fs::rename(&staged_root, &final_dir)) {
        let _ = retry_fs_op(|| fs::remove_dir_all(&staged_root));
        return Err(CfmsError::Io(err));
    }
    Ok(final_dir)
}

fn snapshot_state_into_dir(
    paths: &WorkspacePaths,
    validated: &ValidatedManifest,
    settings: &DeploymentSettings,
    state_dir: &Path,
) -> Result<()> {
    let parent = state_dir.parent().unwrap_or(state_dir);
    fs::create_dir_all(parent)?;
    let tmp_state = tempfile::Builder::new().prefix(".state-").tempdir_in(parent)?;

    if paths.config_path.is_file() {
        fs::copy(&paths.config_path, tmp_state.path().join("config.toml"))?;
    }
    let settings_bytes = serde_json::to_vec_pretty(settings)
        .map_err(|e| CfmsError::Deployment(format!("Failed serializing snapshot settings: {e}")))?;
    fs::write(tmp_state.path().join(SETTINGS_FILENAME), settings_bytes)?;

    let lock_file = requirements_lock_path(paths);
    if lock_file.is_file() {
        fs::copy(&lock_file, tmp_state.path().join(REQUIREMENTS_LOCK_FILENAME))?;
    }

    let managed: BTreeSet<&str> = validated
        .manifest
        .managed_extensions
        .iter()
        .map(String::as_str)
        .collect();
    if paths.extensions_root.is_dir() {
        let ext_out = tmp_state.path().join("extensions");
        for entry in fs::read_dir(&paths.extensions_root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "__pycache__" || managed.contains(name.as_str()) {
                continue;
            }
            let src_ext = entry.path();
            let meta = fs::symlink_metadata(&src_ext)?;
            if meta.is_dir() && !is_symlink_or_reparse_point(&meta) {
                copy_dir_non_following(&src_ext, &ext_out.join(&name))?;
            }
        }
    }

    if state_dir.exists() {
        retry_fs_op(|| fs::remove_dir_all(state_dir))?;
    }
    let tmp_path = tmp_state.keep();
    if let Err(err) = retry_fs_op(|| fs::rename(&tmp_path, state_dir)) {
        let _ = retry_fs_op(|| fs::remove_dir_all(&tmp_path));
        return Err(CfmsError::Io(err));
    }
    Ok(())
}

/// Compute delta statistics between optional `source` manifest and `target` manifest.
#[must_use]
pub fn compute_delta_counts(
    source: Option<&ReleaseManifest>,
    target: &ReleaseManifest,
) -> DeltaSwapCounts {
    let Some(src) = source else {
        return DeltaSwapCounts {
            added: target.files.len(),
            updated: 0,
            removed: 0,
        };
    };

    let mut added = 0usize;
    let mut updated = 0usize;
    for (rel, tgt_hash) in &target.files {
        match src.files.get(rel) {
            None => added += 1,
            Some(src_hash) if src_hash != tgt_hash => updated += 1,
            Some(_) => {}
        }
    }
    let removed = src
        .files
        .keys()
        .filter(|rel| !target.files.contains_key(*rel))
        .count();

    DeltaSwapCounts {
        added,
        updated,
        removed,
    }
}

/// Atomically replace/update files in `paths.project_root` from `target_tree` while recording every
/// overwritten/removed/added path in `journal_dir` so any subsequent failure can roll back cleanly.
pub fn apply_swap_with_journal(
    paths: &WorkspacePaths,
    source_manifest: Option<&ValidatedManifest>,
    target_tree: &Path,
    target_manifest: &ValidatedManifest,
    journal_dir: &Path,
) -> Result<DeltaSwapCounts> {
    fs::create_dir_all(journal_dir)?;
    let backup_dir = journal_dir.join("backup");
    fs::create_dir_all(&backup_dir)?;

    let managed: BTreeSet<String> = target_manifest
        .manifest
        .managed_extensions
        .iter()
        .cloned()
        .chain(
            source_manifest
                .map(|s| s.manifest.managed_extensions.iter().cloned())
                .into_iter()
                .flatten(),
        )
        .collect();

    let mut added_files = Vec::new();
    let mut backed_up_files = Vec::new();
    let mut added_count = 0usize;
    let mut updated_count = 0usize;

    // 1. Snapshot previous manifest + config.toml in journal before modifying anything.
    let had_previous_manifest = if paths.release_manifest_path.is_file() {
        fs::copy(
            &paths.release_manifest_path,
            backup_dir.join(RELEASE_MANIFEST_FILENAME),
        )?;
        true
    } else {
        false
    };
    let pre_swap_config_backed_up = if paths.config_path.is_file() {
        fs::copy(&paths.config_path, backup_dir.join(".config.toml.pre-swap"))?;
        true
    } else {
        false
    };

    // Determine which files differ or are new.
    let mut files_to_write = Vec::new();
    for (rel_posix, target_hash) in &target_manifest.manifest.files {
        if is_preserved_workspace_path(rel_posix, &managed) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Target release attempts to overwrite protected workspace path '{rel_posix}'"
            )));
        }
        let dest = paths.project_root.join(rel_posix);
        if dest.exists() {
            let meta = fs::symlink_metadata(&dest)?;
            if is_symlink_or_reparse_point(&meta) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Refusing to overwrite symlink or junction '{}' in workspace",
                    dest.display()
                )));
            }
            if meta.is_file() {
                if let Ok((existing_hash, _)) = hash_file_sha256(&dest)
                    && &existing_hash == target_hash
                    && source_manifest
                        .and_then(|s| s.manifest.files.get(rel_posix))
                        .is_some_and(|h| h == target_hash)
                {
                    continue; // Identical file already in place.
                }
                backup_rel_file(&dest, &backup_dir, rel_posix)?;
                backed_up_files.push(rel_posix.clone());
                updated_count += 1;
            } else {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Workspace path conflict at '{}': expected file",
                    dest.display()
                )));
            }
        } else {
            added_files.push(rel_posix.clone());
            added_count += 1;
        }
        files_to_write.push(rel_posix.clone());
    }

    // Also back up obsolete tracked files to be deleted AFTER new files land cleanly.
    let mut files_to_remove = Vec::new();
    if let Some(src) = source_manifest {
        for rel_posix in src.manifest.files.keys() {
            if !target_manifest.manifest.files.contains_key(rel_posix)
                && !is_preserved_workspace_path(rel_posix, &managed)
            {
                let live = paths.project_root.join(rel_posix);
                if live.is_file() {
                    backup_rel_file(&live, &backup_dir, rel_posix)?;
                    backed_up_files.push(rel_posix.clone());
                }
                files_to_remove.push(rel_posix.clone());
            }
        }
    }

    // Write journal BEFORE touching live workspace files!
    let journal = SwapJournalRecord {
        added_files,
        backed_up_files,
        had_previous_manifest,
        pre_swap_config_backed_up,
    };
    let journal_bytes = serde_json::to_vec_pretty(&journal)
        .map_err(|e| CfmsError::Deployment(format!("Failed serializing swap journal: {e}")))?;
    atomic_write(&journal_dir.join("journal.json"), &journal_bytes)?;

    // 2. Atomically place every new/updated file into project_root.
    for rel_posix in &files_to_write {
        let src_file = target_tree.join(rel_posix);
        let dest_file = paths.project_root.join(rel_posix);
        if let Some(parent) = Path::new(rel_posix).parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_safe_directory_chain(&paths.project_root, parent)?;
        }
        copy_file_atomic_with_retry(&src_file, &dest_file)?;
    }

    // 3. Write new release-manifest.json atomically.
    atomic_write(&paths.release_manifest_path, &target_manifest.raw_bytes)?;

    // 4. Remove obsolete tracked files and tidy empty directories cleanly.
    let removed_count = files_to_remove.len();
    for rel_posix in &files_to_remove {
        let live = paths.project_root.join(rel_posix);
        if live.exists() {
            retry_fs_op(|| match fs::remove_file(&live) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            })?;
            prune_empty_ancestors(&paths.project_root, live.parent());
        }
    }

    Ok(DeltaSwapCounts {
        added: added_count,
        updated: updated_count,
        removed: removed_count,
    })
}

/// Replay `journal.json` in reverse to restore exact pre-swap files and config on failure.
pub fn rollback_swap_journal(paths: &WorkspacePaths, journal_dir: &Path) -> Result<()> {
    let journal_path = journal_dir.join("journal.json");
    if !journal_path.is_file() {
        return Err(CfmsError::Deployment(format!(
            "Swap journal missing at '{}'; cannot roll back automatically",
            journal_path.display()
        )));
    }
    let raw = fs::read_to_string(&journal_path)?;
    let journal: SwapJournalRecord = serde_json::from_str(&raw).map_err(|e| {
        CfmsError::Deployment(format!("Corrupt swap journal '{}': {e}", journal_path.display()))
    })?;
    let backup_dir = journal_dir.join("backup");

    for added in &journal.added_files {
        let live = paths.project_root.join(added);
        if live.is_file() {
            let _ = retry_fs_op(|| fs::remove_file(&live));
            prune_empty_ancestors(&paths.project_root, live.parent());
        }
    }

    for rel in &journal.backed_up_files {
        let bak = backup_dir.join(rel);
        let live = paths.project_root.join(rel);
        if bak.is_file() {
            if let Some(parent) = Path::new(rel).parent()
                && !parent.as_os_str().is_empty()
            {
                ensure_safe_directory_chain(&paths.project_root, parent)?;
            }
            copy_file_atomic_with_retry(&bak, &live)?;
        }
    }

    let manifest_bak = backup_dir.join(RELEASE_MANIFEST_FILENAME);
    if journal.had_previous_manifest && manifest_bak.is_file() {
        copy_file_atomic_with_retry(&manifest_bak, &paths.release_manifest_path)?;
    } else if !journal.had_previous_manifest && paths.release_manifest_path.is_file() {
        let _ = retry_fs_op(|| fs::remove_file(&paths.release_manifest_path));
    }

    let config_bak = backup_dir.join(".config.toml.pre-swap");
    if journal.pre_swap_config_backed_up && config_bak.is_file() {
        copy_file_atomic_with_retry(&config_bak, &paths.config_path)?;
    }

    Ok(())
}

/// Restore `src/config.toml` or third-party extensions from `<snapshot>/state/` when explicitly requested,
/// or quarantine extensions that declare incompatibility with `target_version`.
pub fn handle_downgrade_extensions(
    paths: &WorkspacePaths,
    target_version: &CfmsServerVersion,
    quarantine_incompatible: bool,
) -> Result<Vec<String>> {
    if !quarantine_incompatible || !paths.extensions_root.is_dir() {
        return Ok(Vec::new());
    }
    let catalog = crate::ops::extension::catalog::discover_catalog(&paths.extensions_root)?;
    let mut quarantined = Vec::new();
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let q_root = quarantine_dir(paths).join(&stamp);

    for ext in catalog.extensions.values() {
        if ext.builtin {
            continue;
        }
        let compat_res = crate::ops::extension::version::check_server_compatibility(
            target_version,
            ext.minimum_server_version.as_ref(),
            ext.maximum_server_version.as_ref(),
        );
        if compat_res.is_err() {
            fs::create_dir_all(&q_root)?;
            let dest = q_root.join(&ext.identifier);
            retry_fs_op(|| fs::rename(&ext.directory, &dest))?;
            quarantined.push(ext.identifier.clone());
        }
    }
    Ok(quarantined)
}

pub fn restore_snapshot_config(state_dir: &Path, config_dest: &Path) -> Result<bool> {
    let snap_cfg = state_dir.join("config.toml");
    if !snap_cfg.is_file() {
        return Ok(false);
    }
    copy_file_atomic_with_retry(&snap_cfg, config_dest)?;
    Ok(true)
}

#[derive(Debug, Clone)]
pub enum PruneSelector {
    AllInactive,
    KeepNewest(usize),
    SpecificIds(Vec<String>),
    CorruptOnly,
}

#[derive(Debug, Clone)]
pub struct PrunePlan {
    pub active_release_id: String,
    pub keep_ids: Vec<String>,
    pub remove: Vec<StoredReleaseSummary>,
    pub freed_bytes: u64,
    pub warnings: Vec<String>,
}

/// Compute which snapshots in `src/.maintenance/versions/` should be retained vs deleted.
/// Never crashes on unrelated damaged snapshots unless `--release` directly asks for a nonexistent ID.
pub fn plan_prune(paths: &WorkspacePaths, selector: &PruneSelector) -> Result<PrunePlan> {
    let active_manifest = load_manifest_file(&paths.release_manifest_path)?;
    let active_id = active_manifest.release_id.clone();
    // Use deep hash checks on stored releases so `--corrupt` or reporting sees real health cleanly.
    let all = list_stored_releases(paths, Some(&active_id), true)?;

    let mut warnings = Vec::new();
    let mut remove = Vec::new();
    let mut keep_ids = Vec::new();

    match selector {
        PruneSelector::AllInactive => {
            for rel in all {
                if rel.active {
                    keep_ids.push(rel.release_id);
                } else {
                    if !rel.healthy {
                        warnings.push(format!(
                            "Pruning damaged snapshot {}: {}",
                            rel.release_id,
                            rel.issues.join("; ")
                        ));
                    }
                    remove.push(rel);
                }
            }
        }
        PruneSelector::KeepNewest(keep_n) => {
            let mut healthy_kept = 0usize;
            for rel in all {
                if rel.active {
                    keep_ids.push(rel.release_id);
                } else if rel.healthy && healthy_kept < *keep_n {
                    healthy_kept += 1;
                    keep_ids.push(rel.release_id);
                } else {
                    if !rel.healthy {
                        warnings.push(format!(
                            "Pruning damaged snapshot {} outside retention budget: {}",
                            rel.release_id,
                            rel.issues.join("; ")
                        ));
                    }
                    remove.push(rel);
                }
            }
        }
        PruneSelector::CorruptOnly => {
            for rel in all {
                if rel.active || rel.healthy {
                    keep_ids.push(rel.release_id);
                } else {
                    remove.push(rel);
                }
            }
        }
        PruneSelector::SpecificIds(queries) => {
            let mut target_ids = BTreeSet::new();
            for q in queries {
                let needle = q.trim().to_ascii_lowercase();
                if needle.len() < 6 || !needle.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(CfmsError::InvalidArgument(format!(
                        "Invalid snapshot ID or prefix '{q}'"
                    )));
                }
                let matched: Vec<&StoredReleaseSummary> = all
                    .iter()
                    .filter(|s| s.release_id == needle || s.release_id.starts_with(&needle))
                    .collect();
                if matched.is_empty() {
                    return Err(CfmsError::Deployment(format!(
                        "No stored snapshot matches '{q}'"
                    )));
                }
                if matched.len() > 1 {
                    return Err(CfmsError::InvalidArgument(format!(
                        "Snapshot prefix '{q}' matches multiple releases"
                    )));
                }
                let item = matched[0];
                if item.active {
                    return Err(CfmsError::Deployment(format!(
                        "Refusing to prune currently active release '{}'",
                        item.release_id
                    )));
                }
                target_ids.insert(item.release_id.clone());
            }
            for rel in all {
                if target_ids.contains(&rel.release_id) {
                    remove.push(rel);
                } else {
                    keep_ids.push(rel.release_id);
                }
            }
        }
    }

    let freed_bytes = remove.iter().map(|r| r.total_bytes).sum();
    Ok(PrunePlan {
        active_release_id: active_id,
        keep_ids,
        remove,
        freed_bytes,
        warnings,
    })
}

pub fn execute_prune(paths: &WorkspacePaths, plan: &PrunePlan) -> Result<()> {
    let base = versions_dir(paths);
    for rel in &plan.remove {
        let dir = base.join(&rel.release_id);
        if dir.exists() {
            retry_fs_op(|| match fs::remove_dir_all(&dir) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            })?;
        }
    }
    Ok(())
}

fn backup_rel_file(src: &Path, backup_root: &Path, rel_posix: &str) -> Result<()> {
    let dest = backup_root.join(rel_posix);
    if let Some(parent) = Path::new(rel_posix).parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_safe_directory_chain(backup_root, parent)?;
    }
    fs::copy(src, dest)?;
    Ok(())
}

pub(crate) fn copy_file_atomic_with_retry(src: &Path, dest: &Path) -> Result<()> {
    let parent = dest.parent().ok_or_else(|| {
        CfmsError::InvalidArgument(format!("Path has no parent: '{}'", dest.display()))
    })?;
    fs::create_dir_all(parent)?;
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let mut temp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(parent)?;
    {
        let mut reader = BufReader::with_capacity(64 * 1024, File::open(src)?);
        std::io::copy(&mut reader, &mut temp)?;
        temp.as_file().sync_all()?;
    }
    let (file, temp_path) = temp.keep().map_err(|e| CfmsError::Io(e.error))?;
    drop(file);
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(src) {
        let _ = fs::set_permissions(&temp_path, meta.permissions());
    }
    if let Err(err) = crate::core::atomic_rename_with_retry(&temp_path, dest) {
        let _ = fs::remove_file(&temp_path);
        return Err(CfmsError::Io(err));
    }
    Ok(())
}

fn copy_dir_non_following(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "__pycache__" {
            continue;
        }
        let src_path = entry.path();
        let meta = fs::symlink_metadata(&src_path)?;
        if is_symlink_or_reparse_point(&meta) {
            continue;
        }
        let dst_path = dest.join(&name);
        if meta.is_dir() {
            copy_dir_non_following(&src_path, &dst_path)?;
        } else if meta.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn prune_empty_ancestors(stop_root: &Path, start: Option<&Path>) {
    let mut cur = start.map(Path::to_path_buf);
    while let Some(dir) = cur {
        if dir == stop_root || !dir.starts_with(stop_root) {
            break;
        }
        let is_empty = fs::read_dir(&dir)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false);
        if !is_empty {
            break;
        }
        if fs::remove_dir(&dir).is_err() {
            break;
        }
        cur = dir.parent().map(Path::to_path_buf);
    }
}

fn dir_size_bytes(path: &Path) -> IoResult<u64> {
    let mut total = 0u64;
    let meta = fs::symlink_metadata(path)?;
    if is_symlink_or_reparse_point(&meta) {
        return Ok(0);
    }
    if meta.is_file() {
        return Ok(meta.len());
    }
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            total = total.saturating_add(dir_size_bytes(&entry.path()).unwrap_or(0));
        }
    }
    Ok(total)
}

type IoResult<T> = std::io::Result<T>;

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use super::*;
    use super::super::manifest::tests::minimal_valid_manifest_bytes;
    use super::super::manifest::parse_and_validate_manifest_bytes;
    use super::super::models::REQUIRED_RELEASE_FILES;

    pub(crate) fn write_workspace_tree(
        root: &Path,
        version: &str,
        main_bytes: &[u8],
    ) -> ValidatedManifest {
        let raw_manifest = minimal_valid_manifest_bytes(version, main_bytes);
        let validated = parse_and_validate_manifest_bytes(&raw_manifest, "fixture").unwrap();
        for req in REQUIRED_RELEASE_FILES {
            let content = if *req == "src/main.py" {
                main_bytes.to_vec()
            } else {
                format!("content-for-{req}").into_bytes()
            };
            let full = root.join(req);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, content).unwrap();
        }
        fs::write(root.join(RELEASE_MANIFEST_FILENAME), &raw_manifest).unwrap();
        validated
    }

    #[test]
    fn corrupt_snapshot_does_not_crash_status_and_prune_corrupt_cleans_it() {
        let tmp = TempDir::new().unwrap();
        let active = write_workspace_tree(tmp.path(), "0.15.0", b"active\n");
        let paths = WorkspacePaths::for_target_project_root(tmp.path(), None);
        fs::create_dir_all(&paths.maintenance_root).unwrap();

        let bad_id = "deadbeef".repeat(8);
        let bad_dir = versions_dir(&paths).join(&bad_id);
        fs::create_dir_all(bad_dir.join(RELEASE_SUBDIR)).unwrap();
        fs::write(bad_dir.join(RELEASE_SUBDIR).join(RELEASE_MANIFEST_FILENAME), "{bad").unwrap();

        let listed = list_stored_releases(&paths, Some(&active.release_id), true).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].healthy);

        let plan = plan_prune(&paths, &PruneSelector::CorruptOnly).unwrap();
        assert_eq!(plan.remove.len(), 1);
        execute_prune(&paths, &plan).unwrap();
        assert!(!bad_dir.exists());
    }

    #[test]
    fn reversible_swap_journal_rolls_back_cleanly() {
        let tmp = TempDir::new().unwrap();
        let source = write_workspace_tree(tmp.path(), "0.14.0", b"old_main\n");
        let paths = WorkspacePaths::for_target_project_root(tmp.path(), None);

        let stage_dir = TempDir::new().unwrap();
        let target = write_workspace_tree(stage_dir.path(), "0.15.0", b"new_main\n");

        let journal_dir = tx_root_dir(&paths).join("tx-1");
        let counts = apply_swap_with_journal(
            &paths,
            Some(&source),
            stage_dir.path(),
            &target,
            &journal_dir,
        )
        .unwrap();
        assert_eq!(counts.updated, 1);
        assert_eq!(fs::read(tmp.path().join("src/main.py")).unwrap(), b"new_main\n");

        rollback_swap_journal(&paths, &journal_dir).unwrap();
        assert_eq!(fs::read(tmp.path().join("src/main.py")).unwrap(), b"old_main\n");
        let restored = load_manifest_file(&paths.release_manifest_path).unwrap();
        assert_eq!(restored.release_id, source.release_id);
    }
}
