//! Atomic file replacement and timestamped backup helpers.

use std::io::Write;
use std::path::{Path, PathBuf};
use chrono::Utc;
use tempfile::Builder;
use crate::core::error::{CfmsError, Result};

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
    temp.persist(target_path).map_err(|e| CfmsError::Io(e.error))?;
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
