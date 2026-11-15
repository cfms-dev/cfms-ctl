//! Atomic file replacement, Windows-resilient retry helpers, symlink guards,
//! and timestamped backup utilities.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use chrono::Utc;
use tempfile::Builder;
use crate::core::error::{CfmsError, Result};

/// Execute a filesystem mutation with bounded backoff retries on transient Windows file locks.
pub fn retry_fs_op<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    #[cfg(windows)]
    const RETRY_DELAYS_MS: &[u64] = &[20, 40, 80, 120, 200];
    #[cfg(not(windows))]
    const RETRY_DELAYS_MS: &[u64] = &[];

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

/// Rename `from` to `to` with transient Windows lock retries.
pub fn atomic_rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    retry_fs_op(|| std::fs::rename(from, to))
}

/// Return true if filesystem metadata describes a symlink or Windows reparse point (junction/mount).
#[must_use]
pub fn is_symlink_or_reparse_point(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

/// Return true if a path segment matches a reserved Windows DOS device name (e.g. `CON`, `NUL`, `COM1`).
#[must_use]
pub fn is_windows_reserved_name(segment: &str) -> bool {
    let base = segment.split('.').next().unwrap_or(segment);
    if base.eq_ignore_ascii_case("CON")
        || base.eq_ignore_ascii_case("PRN")
        || base.eq_ignore_ascii_case("AUX")
        || base.eq_ignore_ascii_case("NUL")
    {
        return true;
    }
    let bytes = base.as_bytes();
    bytes.len() == 4
        && (base[..3].eq_ignore_ascii_case("COM") || base[..3].eq_ignore_ascii_case("LPT"))
        && matches!(bytes[3], b'1'..=b'9')
}

/// Walk each component of `rel` below `base`, verifying existing components are real directories
/// (never symlinks or reparse points) and creating missing directories step-by-step.
pub fn ensure_safe_directory_chain(base: &Path, rel: &Path) -> Result<()> {
    let base_meta = std::fs::symlink_metadata(base)?;
    if is_symlink_or_reparse_point(&base_meta) || !base_meta.is_dir() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Target base directory '{}' must be a real directory (not a symlink or file)",
            base.display()
        )));
    }

    let mut cur = base.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_symlink_or_reparse_point(&meta) {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Refusing to traverse symlink or junction directory '{}'",
                        cur.display()
                    )));
                }
                if !meta.is_dir() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Directory path conflict: '{}' already exists as a non-directory",
                        cur.display()
                    )));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                retry_fs_op(|| std::fs::create_dir(&cur))?;
            }
            Err(err) => return Err(CfmsError::Io(err)),
        }
    }
    Ok(())
}

/// Atomically write `contents` to `target_path` using a sibling temporary file and fsync.
pub fn atomic_write(target_path: &Path, contents: &[u8]) -> Result<()> {
    let parent = target_path.parent().ok_or_else(|| {
        CfmsError::InvalidArgument(format!("Path has no parent directory: '{}'", target_path.display()))
    })?;
    std::fs::create_dir_all(parent)?;

    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("cfms");
    let mut temp = Builder::new()
        .prefix(&format!(".{file_name}."))
        .suffix(".tmp")
        .tempfile_in(parent)?;

    temp.write_all(contents)?;
    temp.as_file().sync_all()?;
    let (file, temp_path) = temp.keep().map_err(|e| CfmsError::Io(e.error))?;
    drop(file);
    if let Err(err) = atomic_rename_with_retry(&temp_path, target_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(CfmsError::Io(err));
    }
    Ok(())
}

/// Back up `target_path` (verifying `expected_current_source`) and atomically replace it with `new_contents`.
pub fn write_with_timestamped_backup(
    target_path: &Path,
    expected_current_source: &str,
    new_contents: &[u8],
) -> Result<PathBuf> {
    let current_on_disk = std::fs::read_to_string(target_path)?;
    if current_on_disk != expected_current_source {
        return Err(CfmsError::Config(format!(
            "File '{}' changed on disk during operation; please retry",
            target_path.display()
        )));
    }

    let timestamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ");
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.toml");
    let backup_path = target_path.with_file_name(format!("{file_name}.backup-{timestamp}"));

    if std::fs::hard_link(target_path, &backup_path).is_err() {
        std::fs::copy(target_path, &backup_path)?;
    }

    atomic_write(target_path, new_contents)?;
    Ok(backup_path)
}
