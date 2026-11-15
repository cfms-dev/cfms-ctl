//! Safe local extension `.zip` verification, in-memory preflight inspection,
//! bounded staging extraction, and reversible directory swap/rollback primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use rand::RngExt;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempDirBuilder, TempDir};
use zip::CompressionMethod;
use zip::read::ZipArchive;
use zip::result::ZipError;

use crate::core::{CfmsError, Result};
use crate::ops::extension::catalog::{
    ENTRYPOINT_FILENAME, InstalledExtension, MANIFEST_FILENAME, MAX_MANIFEST_BYTES,
    is_symlink_or_reparse_point, parse_extension_manifest_str, symlink_stat_if_present,
};

pub const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ARCHIVE_MEMBERS: usize = 4096;

pub const TRUSTED_CODE_NOTICE: &str = "SHA-256 verification confirms package integrity only; install or upgrade only extensions from trusted sources because extension Python code executes inside the CFMS server.";

/// Validated metadata extracted from an inspected `.zip` package before staging.
#[derive(Debug, Clone)]
pub struct VerifiedExtensionPackage {
    pub package_path: PathBuf,
    pub package_sha256: String,
    pub manifest: InstalledExtension,
    pub member_count: usize,
    pub declared_uncompressed_bytes: u64,
}

#[derive(Debug, Clone)]
struct ValidatedZipMember {
    index: usize,
    rel_path: PathBuf,
    is_dir: bool,
    sanitized_unix_mode: Option<u32>,
    declared_size: u64,
}

/// Verified open archive holding its file handle so interactive confirmation does
/// not re-open, re-hash, or expose a TOCTOU window before commit.
pub struct OpenedExtensionPackage {
    pub summary: VerifiedExtensionPackage,
    archive: ZipArchive<BufReader<File>>,
    members: Vec<ValidatedZipMember>,
}

impl OpenedExtensionPackage {
    /// Validate package size, compute SHA-256 once, enforce ZIP security constraints,
    /// and parse `manifest.toml` in memory without creating staging files on disk.
    pub fn open_and_verify(
        package_path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<Self> {
        let expected_digest = expected_sha256.map(normalize_expected_sha256).transpose()?;

        let meta = fs::metadata(package_path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' does not exist",
                    package_path.display()
                ))
            } else {
                CfmsError::Io(err)
            }
        })?;
        if !meta.is_file() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' must be a regular file",
                package_path.display()
            )));
        }
        if meta.len() > MAX_PACKAGE_BYTES {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' exceeds the {MAX_PACKAGE_BYTES}-byte safety limit",
                package_path.display()
            )));
        }

        let mut file = File::open(package_path)?;
        let actual_digest = stream_sha256_bounded(&mut file, package_path, MAX_PACKAGE_BYTES)?;
        if let Some(expected) = expected_digest.as_deref()
            && actual_digest != expected
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "SHA-256 mismatch for extension package '{}': expected {expected}, got {actual_digest}",
                package_path.display()
            )));
        }

        file.seek(SeekFrom::Start(0))?;
        let mut archive = ZipArchive::new(BufReader::new(file)).map_err(|err| {
            CfmsError::ArchiveIntegrity(format!(
                "Invalid ZIP extension package '{}': {err}",
                package_path.display()
            ))
        })?;

        let member_count = archive.len();
        if member_count == 0 {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' is empty",
                package_path.display()
            )));
        }
        if member_count > MAX_ARCHIVE_MEMBERS {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' has {member_count} entries, exceeding the {MAX_ARCHIVE_MEMBERS}-member safety limit",
                package_path.display()
            )));
        }

        let mut seen_paths_lower: BTreeMap<String, String> = BTreeMap::new();
        let mut dir_paths_lower: BTreeSet<String> = BTreeSet::new();
        let mut file_paths_lower: BTreeSet<String> = BTreeSet::new();
        let mut declared_total: u64 = 0;
        let mut manifest_index: Option<usize> = None;
        let mut has_entrypoint = false;
        let mut members = Vec::with_capacity(member_count);

        for index in 0..member_count {
            let entry = archive.by_index_raw(index).map_err(|err| {
                CfmsError::ArchiveIntegrity(format!(
                    "Failed to inspect member #{index} in '{}': {err}",
                    package_path.display()
                ))
            })?;

            let raw_name = entry
                .name()
                .map_err(|err| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Extension package '{}' contains invalid member name encoding at #{index}: {err}",
                        package_path.display()
                    ))
                })?
                .into_owned();

            if entry.encrypted() {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' contains encrypted member '{raw_name}'",
                    package_path.display()
                )));
            }

            if entry.is_symlink() {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' contains forbidden symlink member '{raw_name}'",
                    package_path.display()
                )));
            }

            match entry.compression() {
                CompressionMethod::Stored | CompressionMethod::Deflated => {}
                other => {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Extension package '{}' uses unsupported compression {:?} for '{raw_name}'; only Stored and Deflated are allowed",
                        package_path.display(),
                        other
                    )));
                }
            }

            let is_dir_entry = entry.is_dir();
            let sanitized_unix_mode = validate_unix_mode(
                entry.unix_mode(),
                is_dir_entry,
                &raw_name,
                package_path,
            )?;

            let Some(enclosed) = entry.enclosed_name() else {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' contains unsafe traversal path '{}'",
                    package_path.display(),
                    raw_name
                )));
            };

            let (rel_path, norm_key) =
                validate_archive_entry_path(&raw_name, &enclosed, is_dir_entry, package_path)?;
            let lower_key = norm_key.to_ascii_lowercase();

            if let Some(prev) = seen_paths_lower.insert(lower_key.clone(), raw_name.clone()) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' has conflicting paths '{}' and '{}'",
                    package_path.display(),
                    prev,
                    raw_name
                )));
            }

            check_file_directory_conflicts(
                &lower_key,
                is_dir_entry,
                &mut dir_paths_lower,
                &mut file_paths_lower,
                &raw_name,
                package_path,
            )?;

            let declared_size = entry.size();
            declared_total = declared_total
                .checked_add(declared_size)
                .filter(|&sum| sum <= MAX_UNCOMPRESSED_BYTES)
                .ok_or_else(|| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Extension package '{}' declared uncompressed size exceeds the {MAX_UNCOMPRESSED_BYTES}-byte safety limit",
                        package_path.display()
                    ))
                })?;

            if !is_dir_entry && norm_key == MANIFEST_FILENAME {
                manifest_index = Some(index);
            } else if !is_dir_entry && norm_key == ENTRYPOINT_FILENAME {
                has_entrypoint = true;
            }

            members.push(ValidatedZipMember {
                index,
                rel_path,
                is_dir: is_dir_entry,
                sanitized_unix_mode,
                declared_size,
            });
        }

        let manifest_idx = manifest_index.ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' is missing root '{}'",
                package_path.display(),
                MANIFEST_FILENAME
            ))
        })?;
        if !has_entrypoint {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' is missing root '{}'",
                package_path.display(),
                ENTRYPOINT_FILENAME
            )));
        }

        let manifest_raw =
            read_bounded_entry_to_string(&mut archive, manifest_idx, package_path, MANIFEST_FILENAME)?;

        let virtual_dir = Path::new(package_path);
        let virtual_manifest = virtual_dir.join(MANIFEST_FILENAME);
        let virtual_entry = virtual_dir.join(ENTRYPOINT_FILENAME);
        let manifest = parse_extension_manifest_str(
            &manifest_raw,
            &virtual_manifest,
            virtual_dir,
            &virtual_entry,
        )?;

        Ok(Self {
            summary: VerifiedExtensionPackage {
                package_path: package_path.to_path_buf(),
                package_sha256: actual_digest,
                manifest,
                member_count,
                declared_uncompressed_bytes: declared_total,
            },
            archive,
            members,
        })
    }

    /// Extract all validated members once into a temporary staging directory under `extensions_root`.
    /// The returned `TempDir` removes the staging folder automatically if dropped before `.keep()`.
    pub fn stage_into(&mut self, extensions_root: &Path) -> Result<TempDir> {
        ensure_extensions_root_safe(extensions_root)?;

        let stage_prefix = format!(".cfms-extension-stage-{}-", self.summary.manifest.identifier);
        let stage_dir = TempDirBuilder::new()
            .prefix(&stage_prefix)
            .rand_bytes(8)
            .tempdir_in(extensions_root)?;
        let stage_root = stage_dir.path();

        let mut total_written: u64 = 0;

        for member in &self.members {
            let dest = stage_root.join(&member.rel_path);
            if member.is_dir {
                ensure_safe_directory_tree(stage_root, &member.rel_path)?;
                if let Some(mode) = member.sanitized_unix_mode {
                    apply_unix_dir_mode(&dest, mode)?;
                }
                continue;
            }

            if let Some(rel_parent) = member.rel_path.parent()
                && !rel_parent.as_os_str().is_empty()
            {
                ensure_safe_directory_tree(stage_root, rel_parent)?;
            }

            let remaining = MAX_UNCOMPRESSED_BYTES.saturating_sub(total_written);
            let mut zip_entry = self.archive.by_index(member.index).map_err(|err| {
                map_zip_read_error(&self.summary.package_path, &member.rel_path, err)
            })?;

            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)?;

            let copied = copy_bounded(&mut zip_entry, &mut out, remaining, &self.summary.package_path)?;
            if copied != member.declared_size {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Member '{}' in '{}' decompressed to {copied} bytes (header declared {})",
                    member.rel_path.display(),
                    self.summary.package_path.display(),
                    member.declared_size
                )));
            }
            out.flush()?;
            drop(out);

            total_written = total_written
                .checked_add(copied)
                .filter(|&sum| sum <= MAX_UNCOMPRESSED_BYTES)
                .ok_or_else(|| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Extension package '{}' exceeds the {MAX_UNCOMPRESSED_BYTES}-byte uncompressed limit",
                        self.summary.package_path.display()
                    ))
                })?;

            if let Some(mode) = member.sanitized_unix_mode {
                apply_unix_file_mode(&dest, mode)?;
            }
        }

        // Verify the extracted root manifest & entrypoint are regular files without links.
        let staged_manifest = stage_root.join(MANIFEST_FILENAME);
        let staged_entry = stage_root.join(ENTRYPOINT_FILENAME);
        if symlink_stat_if_present(&staged_manifest)?
            .is_none_or(|m| !m.is_file())
            || symlink_stat_if_present(&staged_entry)?
                .is_none_or(|m| !m.is_file())
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Staged package '{}' failed post-extraction entrypoint integrity verification",
                self.summary.package_path.display()
            )));
        }

        Ok(stage_dir)
    }
}

/// Move a freshly staged directory into an empty target destination (`install`).
pub fn commit_install_directory(staged: TempDir, target_dir: &Path) -> Result<()> {
    let staged_path = staged.keep();
    if let Err(err) = retry_fs_op(|| fs::rename(&staged_path, target_dir)) {
        let _ = cleanup_directory_best_effort(&staged_path);
        return Err(CfmsError::Io(err));
    }
    Ok(())
}

/// Reversible swap handle for replacing an existing installed directory during `upgrade`.
pub struct ActiveUpgradeRollback {
    live_dir: PathBuf,
    rollback_dir: PathBuf,
    completed: bool,
}

impl ActiveUpgradeRollback {
    /// Swap `live_dir` -> temporary rollback folder and `staged` -> `live_dir`.
    pub fn begin(live_dir: PathBuf, staged: TempDir, identifier: &str) -> Result<Self> {
        let parent = live_dir.parent().ok_or_else(|| {
            CfmsError::Extension(format!(
                "Extension directory '{}' has no parent directory",
                live_dir.display()
            ))
        })?;
        let rollback_dir = parent.join(format!(
            ".cfms-extension-rollback-{identifier}-{}",
            random_hex_suffix()
        ));

        remove_readonly_non_following(&live_dir)?;
        retry_fs_op(|| fs::rename(&live_dir, &rollback_dir)).map_err(|err| {
            CfmsError::Extension(format!(
                "Failed to move existing extension directory '{}' for upgrade (ensure the CFMS server does not hold open file handles): {err}",
                live_dir.display()
            ))
        })?;

        let staged_path = staged.keep();
        if let Err(err) = retry_fs_op(|| fs::rename(&staged_path, &live_dir)) {
            let restore_res = retry_fs_op(|| fs::rename(&rollback_dir, &live_dir));
            let _ = cleanup_directory_best_effort(&staged_path);
            let restore_note = match restore_res {
                Ok(()) => "previous installation was restored".to_string(),
                Err(re) => format!("failed to restore rollback '{}': {re}", rollback_dir.display()),
            };
            return Err(CfmsError::Extension(format!(
                "Failed to move staged upgrade into '{}': {err} ({restore_note})",
                live_dir.display()
            )));
        }

        Ok(Self {
            live_dir,
            rollback_dir,
            completed: false,
        })
    }

    fn revert_in_place(&mut self) -> io::Result<()> {
        if self.completed {
            return Ok(());
        }
        let discard_dir = self.rollback_dir.with_extension("discard");
        if self.live_dir.exists() {
            let _ = remove_readonly_non_following(&self.live_dir);
            retry_fs_op(|| fs::rename(&self.live_dir, &discard_dir))?;
        }
        retry_fs_op(|| fs::rename(&self.rollback_dir, &self.live_dir))?;
        self.completed = true;
        let _ = cleanup_directory_best_effort(&discard_dir);
        Ok(())
    }

    /// Restore the original directory if a subsequent config commit step failed.
    pub fn revert(mut self) -> Result<()> {
        self.revert_in_place().map_err(CfmsError::Io)
    }

    /// Commit the upgrade and attempt rollback folder cleanup, returning any non-fatal cleanup warning.
    pub fn finish(mut self) -> Option<String> {
        self.completed = true;
        cleanup_directory_best_effort(&self.rollback_dir)
            .err()
            .map(|e| {
                format!(
                    "Upgrade succeeded, but residual rollback directory '{}' could not be removed automatically: {e}",
                    self.rollback_dir.display()
                )
            })
    }
}

impl Drop for ActiveUpgradeRollback {
    fn drop(&mut self) {
        if !self.completed && self.rollback_dir.exists() {
            let _ = self.revert_in_place();
        }
    }
}

/// Reversible handle for moving an uninstalled extension directory out of `extensions_root`.
pub struct ActiveUninstallRollback {
    live_dir: PathBuf,
    rollback_dir: PathBuf,
    completed: bool,
}

impl ActiveUninstallRollback {
    /// Move `live_dir` out of `extensions_root` into a reversible rollback path.
    pub fn begin(live_dir: PathBuf, identifier: &str) -> Result<Self> {
        let parent = live_dir.parent().ok_or_else(|| {
            CfmsError::Extension(format!(
                "Extension directory '{}' has no parent directory",
                live_dir.display()
            ))
        })?;
        let rollback_dir = parent.join(format!(
            ".cfms-extension-rollback-{identifier}-{}",
            random_hex_suffix()
        ));
        remove_readonly_non_following(&live_dir)?;
        retry_fs_op(|| fs::rename(&live_dir, &rollback_dir)).map_err(|err| {
            CfmsError::Extension(format!(
                "Failed to remove extension directory '{}' (ensure no running server or editor locks files inside it): {err}",
                live_dir.display()
            ))
        })?;
        Ok(Self {
            live_dir,
            rollback_dir,
            completed: false,
        })
    }

    /// Restore the directory back to `live_dir` when config persistence fails.
    pub fn revert(mut self) -> Result<()> {
        retry_fs_op(|| fs::rename(&self.rollback_dir, &self.live_dir))?;
        self.completed = true;
        Ok(())
    }

    /// Delete the moved rollback directory best-effort, returning a warning if removal fails.
    pub fn finish(mut self) -> Option<String> {
        self.completed = true;
        cleanup_directory_best_effort(&self.rollback_dir)
            .err()
            .map(|e| {
                format!(
                    "Extension was removed from '{}' and disabled, but temporary rollback directory '{}' could not be deleted: {e}",
                    self.live_dir.display(),
                    self.rollback_dir.display()
                )
            })
    }
}

impl Drop for ActiveUninstallRollback {
    fn drop(&mut self) {
        if !self.completed && self.rollback_dir.exists() && !self.live_dir.exists() {
            let _ = retry_fs_op(|| fs::rename(&self.rollback_dir, &self.live_dir));
        }
    }
}

/// Normalize and validate an operator-supplied 64-hex-digit SHA-256 string.
pub fn normalize_expected_sha256(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid --sha256 digest '{raw}': expected 64 hexadecimal characters"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn stream_sha256_bounded(file: &mut File, path: &Path, limit: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut read_total: u64 = 0;

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read_total = read_total.saturating_add(n as u64);
        if read_total > limit {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' exceeds the {limit}-byte safety limit",
                path.display()
            )));
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn validate_unix_mode(
    unix_mode: Option<u32>,
    is_dir: bool,
    raw_name: &str,
    package_path: &Path,
) -> Result<Option<u32>> {
    let Some(mode) = unix_mode else {
        return Ok(None);
    };
    let file_type = mode & 0o170000;
    let valid_type = if is_dir {
        file_type == 0 || file_type == 0o040000
    } else {
        file_type == 0 || file_type == 0o100000
    };
    if !valid_type {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Extension package '{}' contains unsupported file type mode {file_type:#o} on '{raw_name}'",
            package_path.display()
        )));
    }
    Ok(Some(mode & 0o777))
}

fn validate_archive_entry_path(
    raw_name: &str,
    enclosed: &Path,
    is_dir_entry: bool,
    package_path: &Path,
) -> Result<(PathBuf, String)> {
    if raw_name.is_empty()
        || raw_name.contains('\0')
        || raw_name.contains('\\')
        || raw_name.contains(':')
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Extension package '{}' contains invalid path '{}'",
            package_path.display(),
            raw_name
        )));
    }

    let trimmed = raw_name.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Extension package '{}' contains empty member path '{}'",
            package_path.display(),
            raw_name
        )));
    }

    let mut clean_segments = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.ends_with(' ')
            || seg.ends_with('.')
            || is_windows_reserved_name(seg)
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' contains unsafe path segment '{}' in '{}'",
                package_path.display(),
                seg,
                raw_name
            )));
        }
        clean_segments.push(seg);
    }

    let mut rel_path = PathBuf::new();
    let mut count = 0usize;
    for comp in enclosed.components() {
        match comp {
            Component::Normal(part) => {
                let s = part.to_str().ok_or_else(|| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Extension package '{}' contains non-UTF-8 path '{}'",
                        package_path.display(),
                        raw_name
                    ))
                })?;
                if s != clean_segments.get(count).copied().unwrap_or("") {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Extension package '{}' contains non-canonical member path '{}'",
                        package_path.display(),
                        raw_name
                    )));
                }
                rel_path.push(s);
                count += 1;
            }
            _ => {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' contains non-relative member path '{}'",
                    package_path.display(),
                    raw_name
                )));
            }
        }
    }

    if count == 0 || count != clean_segments.len() || (!is_dir_entry && raw_name.ends_with('/')) {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Extension package '{}' contains malformed path '{}'",
            package_path.display(),
            raw_name
        )));
    }

    Ok((rel_path, clean_segments.join("/")))
}

fn is_windows_reserved_name(segment: &str) -> bool {
    let base = segment.split('.').next().unwrap_or(segment);
    if base.eq_ignore_ascii_case("CON")
        || base.eq_ignore_ascii_case("PRN")
        || base.eq_ignore_ascii_case("AUX")
        || base.eq_ignore_ascii_case("NUL")
    {
        return true;
    }
    let bytes = base.as_bytes();
    if bytes.len() == 4
        && (base[..3].eq_ignore_ascii_case("COM") || base[..3].eq_ignore_ascii_case("LPT"))
        && matches!(bytes[3], b'1'..=b'9')
    {
        return true;
    }
    false
}

fn check_file_directory_conflicts(
    lower_key: &str,
    is_dir_entry: bool,
    dir_paths_lower: &mut BTreeSet<String>,
    file_paths_lower: &mut BTreeSet<String>,
    raw_name: &str,
    package_path: &Path,
) -> Result<()> {
    // Check all parent directories against existing files.
    let mut prefix = String::new();
    let segments: Vec<&str> = lower_key.split('/').collect();
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            prefix.push('/');
        }
        prefix.push_str(seg);
        let is_leaf = idx + 1 == segments.len();
        if !is_leaf || is_dir_entry {
            if file_paths_lower.contains(&prefix) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' has file/directory conflict at '{}'",
                    package_path.display(),
                    raw_name
                )));
            }
            dir_paths_lower.insert(prefix.clone());
        } else {
            if dir_paths_lower.contains(&prefix) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Extension package '{}' has directory/file conflict at '{}'",
                    package_path.display(),
                    raw_name
                )));
            }
            file_paths_lower.insert(prefix);
            break;
        }
    }
    Ok(())
}

fn read_bounded_entry_to_string(
    archive: &mut ZipArchive<BufReader<File>>,
    index: usize,
    package_path: &Path,
    member_name: &str,
) -> Result<String> {
    let mut entry = archive.by_index(index).map_err(|err| {
        map_zip_read_error(package_path, Path::new(member_name), err)
    })?;
    let mut bytes = Vec::new();
    (&mut entry)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest '{}' inside '{}' exceeds the 1 MiB safety limit",
            member_name,
            package_path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|e| {
        CfmsError::Extension(format!(
            "Manifest '{}' inside '{}' is not valid UTF-8: {e}",
            member_name,
            package_path.display()
        ))
    })
}

fn copy_bounded(
    src: &mut impl Read,
    dst: &mut impl Write,
    limit: u64,
    package_path: &Path,
) -> Result<u64> {
    let mut limited = src.take(limit.saturating_add(1));
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;

    loop {
        let n = limited.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > limit {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Extension package '{}' exceeded the {MAX_UNCOMPRESSED_BYTES}-byte uncompressed limit during extraction",
                package_path.display()
            )));
        }
        dst.write_all(&buf[..n])?;
    }

    Ok(total)
}

fn map_zip_read_error(package_path: &Path, member: &Path, err: ZipError) -> CfmsError {
    CfmsError::ArchiveIntegrity(format!(
        "Failed to read member '{}' from '{}': {err}",
        member.display(),
        package_path.display()
    ))
}

fn ensure_extensions_root_safe(extensions_root: &Path) -> Result<()> {
    match fs::symlink_metadata(extensions_root) {
        Ok(meta) => {
            if is_symlink_or_reparse_point(&meta) {
                return Err(CfmsError::Extension(format!(
                    "Extension directory '{}' cannot be a symlink or junction",
                    extensions_root.display()
                )));
            }
            if !meta.is_dir() {
                return Err(CfmsError::Extension(format!(
                    "Extension path '{}' exists but is not a directory",
                    extensions_root.display()
                )));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(extensions_root)?;
            Ok(())
        }
        Err(err) => Err(CfmsError::Io(err)),
    }
}

fn ensure_safe_directory_tree(base: &Path, rel: &Path) -> Result<()> {
    let mut cur = base.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_symlink_or_reparse_point(&meta) {
                    return Err(CfmsError::Extension(format!(
                        "Refusing to traverse symlinked staging directory '{}'",
                        cur.display()
                    )));
                }
                if !meta.is_dir() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Staging path conflict: '{}' already exists as non-directory",
                        cur.display()
                    )));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur)?;
            }
            Err(err) => return Err(CfmsError::Io(err)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn apply_unix_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Never keep read-only barriers if owner write is missing? Preserve explicit sanitized rwx bits while ensuring owner read/write if empty.
    let safe_mode = mode & 0o777;
    if safe_mode != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(safe_mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_unix_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn apply_unix_dir_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let safe_mode = (mode & 0o777) | 0o700;
    fs::set_permissions(path, fs::Permissions::from_mode(safe_mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_unix_dir_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Recursively clear read-only permissions without ever following symlinks or junctions.
fn remove_readonly_non_following(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(CfmsError::Io(err)),
    };
    if is_symlink_or_reparse_point(&meta) {
        return Err(CfmsError::Extension(format!(
            "Refusing to mutate symlink or junction path '{}'",
            path.display()
        )));
    }

    let mut perms = meta.permissions();
    if perms.readonly() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(perms.mode() | 0o200);
        }
        #[cfg(not(unix))]
        {
            // Safe on non-Unix (Windows): clears FILE_ATTRIBUTE_READONLY without ACL widening.
            #[expect(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
        }
        fs::set_permissions(path, perms)?;
    }

    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            remove_readonly_non_following(&entry.path())?;
        }
    }
    Ok(())
}

fn cleanup_directory_best_effort(path: &Path) -> io::Result<()> {
    if let Err(err) = remove_readonly_non_following(path) {
        return Err(io::Error::other(err.to_string()));
    }
    retry_fs_op(|| match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    })
}

fn retry_fs_op<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    #[cfg(windows)]
    const RETRY_DELAYS_MS: &[u64] = &[20, 40, 80, 120];
    #[cfg(not(windows))]
    const RETRY_DELAYS_MS: &[u64] = &[0];

    let mut attempt = 0usize;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(err) if is_transient_lock_error(&err) && attempt < RETRY_DELAYS_MS.len() => {
                let delay = RETRY_DELAYS_MS[attempt];
                attempt += 1;
                if delay > 0 {
                    std::thread::sleep(Duration::from_millis(delay));
                }
            }
            Err(err) => return Err(err),
        }
    }
}

fn is_transient_lock_error(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::PermissionDenied {
        return cfg!(windows);
    }
    #[cfg(windows)]
    {
        // ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32)
        if matches!(err.raw_os_error(), Some(5 | 32)) {
            return true;
        }
    }
    false
}

fn random_hex_suffix() -> String {
    let bytes: [u8; 6] = rand::rng().random();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    pub(crate) type ZipFixtureEntry<'a> =
        (&'a str, &'a [u8], CompressionMethod, Option<u32>, bool);

    pub(crate) fn build_zip(path: &Path, entries: &[ZipFixtureEntry<'_>]) {
        let file = File::create(path).expect("create zip");
        let mut writer = ZipWriter::new(file);
        for (name, data, method, mode, is_dir) in entries {
            let mut opts = SimpleFileOptions::default().compression_method(*method);
            if let Some(m) = mode {
                opts = opts.unix_permissions(*m);
            }
            if *is_dir {
                writer.add_directory(*name, opts).expect("add dir");
            } else {
                writer.start_file(*name, opts).expect("start file");
                writer.write_all(data).expect("write data");
            }
        }
        writer.finish().expect("finish zip");
    }

    fn valid_manifest(id: &str, version: &str) -> String {
        format!(
            "manifest_version = 3\n\
             [extension]\n\
             identifier = \"{id}\"\n\
             name = \"Sample\"\n\
             version = \"{version}\"\n\
             license = \"MIT\"\n\
             authors = [\"Dev\"]\n"
        )
    }

    #[test]
    fn accepts_valid_deflated_package_and_computes_sha256() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = dir.path().join("sample.zip");
        let manifest = valid_manifest("sample_ext", "1.0.0");
        build_zip(
            &pkg,
            &[
                ("manifest.toml", manifest.as_bytes(), CompressionMethod::Deflated, Some(0o100644), false),
                ("_extension.py", b"# hook\n", CompressionMethod::Stored, Some(0o100644), false),
                ("sub/", b"", CompressionMethod::Stored, Some(0o040755), true),
                ("sub/helper.py", b"x = 1\n", CompressionMethod::Deflated, Some(0o100644), false),
            ],
        );

        let opened = OpenedExtensionPackage::open_and_verify(&pkg, None).expect("open valid zip");
        assert_eq!(opened.summary.manifest.identifier, "sample_ext");
        assert_eq!(opened.summary.package_sha256.len(), 64);

        let recheck = OpenedExtensionPackage::open_and_verify(
            &pkg,
            Some(&opened.summary.package_sha256.to_uppercase()),
        )
        .expect("uppercase sha256 matches");
        assert_eq!(recheck.summary.member_count, 4);
    }

    #[test]
    fn rejects_sha256_mismatch_and_malformed_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = dir.path().join("sample.zip");
        let manifest = valid_manifest("sample_ext", "1.0.0");
        build_zip(
            &pkg,
            &[
                ("manifest.toml", manifest.as_bytes(), CompressionMethod::Stored, None, false),
                ("_extension.py", b"", CompressionMethod::Stored, None, false),
            ],
        );

        assert!(OpenedExtensionPackage::open_and_verify(&pkg, Some("bad")).is_err());
        let wrong = "0".repeat(64);
        let err = OpenedExtensionPackage::open_and_verify(&pkg, Some(&wrong))
            .err()
            .expect("mismatch fails");
        assert!(err.to_string().contains("SHA-256 mismatch"));
    }

    #[test]
    fn rejects_zipslip_reserved_windows_names_and_case_collisions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = valid_manifest("bad_pkg", "1.0.0");

        for bad_name in [
            "../escape.py",
            "/abs.py",
            "dir\\file.py",
            "stream:zone.txt",
            "sub/NUL.py",
            "sub/com1.txt",
            "trailingdot.",
            "trailingspace ",
        ] {
            let pkg = dir.path().join("bad.zip");
            build_zip(
                &pkg,
                &[
                    ("manifest.toml", manifest.as_bytes(), CompressionMethod::Stored, None, false),
                    ("_extension.py", b"", CompressionMethod::Stored, None, false),
                    (bad_name, b"x", CompressionMethod::Stored, None, false),
                ],
            );
            let res = OpenedExtensionPackage::open_and_verify(&pkg, None);
            assert!(res.is_err(), "expected failure for '{bad_name}'");
        }

        // Case-insensitive collision
        let dup_pkg = dir.path().join("dup.zip");
        build_zip(
            &dup_pkg,
            &[
                ("manifest.toml", manifest.as_bytes(), CompressionMethod::Stored, None, false),
                ("_extension.py", b"", CompressionMethod::Stored, None, false),
                ("Helper.py", b"1", CompressionMethod::Stored, None, false),
                ("helper.py", b"2", CompressionMethod::Stored, None, false),
            ],
        );
        assert!(OpenedExtensionPackage::open_and_verify(&dup_pkg, None).is_err());

        // File vs directory conflict
        let conflict_pkg = dir.path().join("conflict.zip");
        build_zip(
            &conflict_pkg,
            &[
                ("manifest.toml", manifest.as_bytes(), CompressionMethod::Stored, None, false),
                ("_extension.py", b"", CompressionMethod::Stored, None, false),
                ("a", b"file", CompressionMethod::Stored, None, false),
                ("a/b.py", b"nested", CompressionMethod::Stored, None, false),
            ],
        );
        assert!(OpenedExtensionPackage::open_and_verify(&conflict_pkg, None).is_err());
    }

    #[test]
    fn rejects_symlinks_and_special_unix_modes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = valid_manifest("sym_pkg", "1.0.0");

        for bad_mode in [0o120777_u32, 0o010644_u32, 0o020644_u32, 0o040755_u32, 0o140644_u32] {
            let pkg = dir.path().join("sym_attr.zip");
            let file = File::create(&pkg).expect("create zip");
            let mut writer = ZipWriter::new(file);
            writer
                .start_file("manifest.toml", SimpleFileOptions::default())
                .expect("start manifest");
            writer.write_all(manifest.as_bytes()).expect("write manifest");
            writer
                .start_file("_extension.py", SimpleFileOptions::default())
                .expect("start entry");
            let bad_opts = SimpleFileOptions::default()
                .system(zip::System::Unix)
                .external_attributes(bad_mode << 16);
            writer.start_file("bad.bin", bad_opts).expect("start bad");
            writer.write_all(b"payload").expect("write bad");
            writer.finish().expect("finish");

            assert!(
                OpenedExtensionPackage::open_and_verify(&pkg, None).is_err(),
                "expected failure for external unix_mode {bad_mode:#o}"
            );
        }

        // Also reject explicit ZipWriter symlinks and wrong-case/oversize manifests.
        let symlink_pkg = dir.path().join("symlink.zip");
        let file = File::create(&symlink_pkg).expect("create zip");
        let mut writer = ZipWriter::new(file);
        writer
            .start_file("manifest.toml", SimpleFileOptions::default())
            .expect("start manifest");
        writer.write_all(manifest.as_bytes()).expect("write manifest");
        writer
            .start_file("_extension.py", SimpleFileOptions::default())
            .expect("start entry");
        writer
            .add_symlink("escape.py", "../secret.py", SimpleFileOptions::default())
            .expect("add symlink");
        writer.finish().expect("finish");
        assert!(OpenedExtensionPackage::open_and_verify(&symlink_pkg, None).is_err());

        let wrong_case_pkg = dir.path().join("wrong_case.zip");
        build_zip(
            &wrong_case_pkg,
            &[
                ("MANIFEST.TOML", manifest.as_bytes(), CompressionMethod::Stored, None, false),
                ("_extension.py", b"", CompressionMethod::Stored, None, false),
            ],
        );
        assert!(OpenedExtensionPackage::open_and_verify(&wrong_case_pkg, None).is_err());

        let oversize_pkg = dir.path().join("oversize_manifest.zip");
        let huge = format!("{manifest}# {}\n", "x".repeat(MAX_MANIFEST_BYTES as usize + 16));
        build_zip(
            &oversize_pkg,
            &[
                ("manifest.toml", huge.as_bytes(), CompressionMethod::Deflated, None, false),
                ("_extension.py", b"", CompressionMethod::Stored, None, false),
            ],
        );
        assert!(OpenedExtensionPackage::open_and_verify(&oversize_pkg, None).is_err());
    }

    #[test]
    fn stage_and_atomic_upgrade_rollback_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ext_root = dir.path().join("extensions");
        let live_dir = ext_root.join("custom_dir");
        fs::create_dir_all(&live_dir).expect("mkdir live");
        fs::write(live_dir.join("old.txt"), b"v1").expect("write old");
        let mut ro = fs::metadata(live_dir.join("old.txt")).unwrap().permissions();
        ro.set_readonly(true);
        fs::set_permissions(live_dir.join("old.txt"), ro).expect("set readonly");

        let pkg = dir.path().join("v2.zip");
        let manifest = valid_manifest("sample_ext", "2.0.0");
        build_zip(
            &pkg,
            &[
                ("manifest.toml", manifest.as_bytes(), CompressionMethod::Stored, None, false),
                ("_extension.py", b"# v2\n", CompressionMethod::Stored, None, false),
            ],
        );
        let mut opened = OpenedExtensionPackage::open_and_verify(&pkg, None).expect("open v2");
        let staged = opened.stage_into(&ext_root).expect("stage");

        let swap = ActiveUpgradeRollback::begin(live_dir.clone(), staged, "sample_ext")
            .expect("swap");
        assert!(live_dir.join("_extension.py").exists());
        assert!(!live_dir.join("old.txt").exists());

        swap.revert().expect("revert upgrade");
        assert!(live_dir.join("old.txt").exists());
        assert!(!live_dir.join("_extension.py").exists());
    }
}
