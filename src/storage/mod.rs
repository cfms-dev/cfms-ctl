//! Storage backend abstraction for streaming backup/restore and file asset verification.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use crate::core::config::ConfigDocument;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;

/// Write handle representing an atomic staged storage write that commits without overwriting.
pub trait StagedStorageFile: Write + Send {
    /// Promote the staged file to its final logical path, refusing to clobber existing objects.
    fn finish(self: Box<Self>) -> Result<()>;
}

/// Trait abstracting file storage operations (local filesystem by default, extensible to S3).
pub trait StorageBackend: Send + Sync {
    /// Backend identifier (`local`).
    fn kind(&self) -> &'static str;

    /// Check whether a logical storage path exists.
    fn exists(&self, relative_path: &str) -> Result<bool>;

    /// Open a streaming reader for a stored object.
    fn open_read(&self, relative_path: &str) -> Result<Box<dyn Read + Send>>;

    /// Begin a streaming atomic write to a non-existent logical storage path.
    fn begin_staged_write(&self, relative_path: &str) -> Result<Box<dyn StagedStorageFile>>;

    /// Remove a stored object (used for transactional rollback).
    fn remove_file(&self, relative_path: &str) -> Result<()>;

    /// Read a stored file's bytes into memory.
    fn read_bytes(&self, relative_path: &str) -> Result<Vec<u8>> {
        let mut reader = self.open_read(relative_path)?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Atomically write bytes to a non-existent logical storage path.
    fn write_bytes(&self, relative_path: &str, data: &[u8]) -> Result<()> {
        let mut writer = self.begin_staged_write(relative_path)?;
        writer.write_all(data)?;
        writer.finish()
    }
}

/// Validate a logical storage relative path against traversal and OS-reserved pitfalls.
pub fn validate_storage_relative_path(relative_path: &str) -> Result<&str> {
    if relative_path.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Storage path must not be empty".to_string(),
        ));
    }
    if relative_path.contains('\0') {
        return Err(CfmsError::ArchiveIntegrity(
            "Storage path contains a NUL byte".to_string(),
        ));
    }
    if relative_path.starts_with('/') || relative_path.starts_with('\\') || relative_path.contains('\\') {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Invalid relative storage path '{relative_path}'"
        )));
    }
    for segment in relative_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unsafe path segment in storage path '{relative_path}'"
            )));
        }
        if segment.contains(':') || segment.ends_with(' ') || segment.ends_with('.') {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unsupported filename character in storage path '{relative_path}'"
            )));
        }
    }
    Ok(relative_path)
}

/// Inspect `[provider].storage` in `config.toml` and build the active [`LocalFsStorage`],
/// rejecting unsupported backends such as `s3` explicitly.
pub fn resolve_local_storage(
    paths: &WorkspacePaths,
    config: &ConfigDocument,
) -> Result<LocalFsStorage> {
    if let Some(provider_item) = config.document().get("provider") {
        let Some(provider_tbl) = provider_item.as_table_like() else {
            return Err(CfmsError::Config(
                "Configuration section 'provider' must be a table".to_string(),
            ));
        };
        if let Some(storage_item) = provider_tbl.get("storage") {
            let Some(storage_kind) = storage_item.as_str() else {
                return Err(CfmsError::Config(
                    "Configuration key 'provider.storage' must be a string".to_string(),
                ));
            };
            match storage_kind {
                "local" => {}
                "s3" => {
                    return Err(CfmsError::Config(
                        "Storage provider 's3' is not supported by `cfms-ctl backup` yet; only 'local' storage is supported."
                            .to_string(),
                    ));
                }
                other => {
                    return Err(CfmsError::Config(format!(
                        "Unsupported storage provider '{other}' in 'provider.storage'"
                    )));
                }
            }
        }
    }
    Ok(LocalFsStorage::new(paths.server_root.clone()))
}

/// Local filesystem storage rooted at `<server_root>` (matching `files.path` e.g. `content/files/...`).
#[derive(Debug, Clone)]
pub struct LocalFsStorage {
    root: PathBuf,
}

impl LocalFsStorage {
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve_checked(&self, relative_path: &str) -> Result<PathBuf> {
        let valid = validate_storage_relative_path(relative_path)?;
        let mut out = self.root.clone();
        for seg in valid.split('/') {
            out.push(seg);
        }
        Ok(out)
    }

    /// Directly copy an already-written logical file to another non-existent logical path.
    pub fn copy_within(&self, src_relative_path: &str, dst_relative_path: &str) -> Result<u64> {
        let mut src = self.open_read(src_relative_path)?;
        let mut dst = self.begin_staged_write(dst_relative_path)?;
        let copied = std::io::copy(&mut src, &mut dst)?;
        dst.finish()?;
        Ok(copied)
    }
}

struct LocalStagedWrite {
    writer: BufWriter<NamedTempFile>,
    target: PathBuf,
    relative_path: String,
}

impl Write for LocalStagedWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl StagedStorageFile for LocalStagedWrite {
    fn finish(mut self: Box<Self>) -> Result<()> {
        self.writer.flush()?;
        let temp = self.writer.into_inner().map_err(|e| e.into_error())?;
        if std::fs::symlink_metadata(&self.target).is_ok() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Refusing to overwrite existing storage file '{}'",
                self.relative_path
            )));
        }
        temp.persist_noclobber(&self.target).map_err(|err| {
            CfmsError::ArchiveIntegrity(format!(
                "Failed to persist restored storage file '{}': {}",
                self.relative_path, err.error
            ))
        })?;
        Ok(())
    }
}

impl StorageBackend for LocalFsStorage {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn exists(&self, relative_path: &str) -> Result<bool> {
        let path = self.resolve_checked(relative_path)?;
        Ok(std::fs::symlink_metadata(path).is_ok())
    }

    fn open_read(&self, relative_path: &str) -> Result<Box<dyn Read + Send>> {
        let path = self.resolve_checked(relative_path)?;
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CfmsError::ArchiveIntegrity(format!(
                    "Missing storage file '{relative_path}' at '{}'",
                    path.display()
                ))
            } else {
                CfmsError::Io(e)
            }
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Storage object '{relative_path}' must be a regular file"
            )));
        }
        let file = File::open(&path)?;
        Ok(Box::new(file))
    }

    fn begin_staged_write(&self, relative_path: &str) -> Result<Box<dyn StagedStorageFile>> {
        let target = self.resolve_checked(relative_path)?;
        if std::fs::symlink_metadata(&target).is_ok() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Target storage path already exists: '{relative_path}'"
            )));
        }
        let parent = target.parent().ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!("Invalid storage target path '{relative_path}'"))
        })?;
        std::fs::create_dir_all(parent)?;
        let temp = tempfile::Builder::new()
            .prefix(".cfms-import-part-")
            .tempfile_in(parent)?;
        Ok(Box::new(LocalStagedWrite {
            writer: BufWriter::with_capacity(64 * 1024, temp),
            target,
            relative_path: relative_path.to_string(),
        }))
    }

    fn remove_file(&self, relative_path: &str) -> Result<()> {
        let target = self.resolve_checked(relative_path)?;
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(CfmsError::Io(e)),
        }
        let mut cursor = target.parent();
        while let Some(dir) = cursor {
            if dir == self.root {
                break;
            }
            if std::fs::remove_dir(dir).is_err() {
                break;
            }
            cursor = dir.parent();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn validate_storage_path_rejects_unsafe_paths() {
        for bad in [
            "",
            "/etc/passwd",
            "\\windows\\system",
            "a\\b",
            "../secret",
            "content/../secret",
            "content/./secret",
            "content//secret",
            "content/file/",
            "C:secret",
            "content/file:stream",
            "content/trailing.",
            "content/trailing ",
            "content/\0file",
        ] {
            assert!(
                validate_storage_relative_path(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
        assert!(validate_storage_relative_path("content/files/2026/11/blob.bin").is_ok());
    }

    #[test]
    fn local_storage_staged_write_refuses_clobber_and_supports_rollback() {
        let dir = tempdir().unwrap();
        let storage = LocalFsStorage::new(dir.path().to_path_buf());
        storage
            .write_bytes("content/files/ab/cd/test.bin", b"hello")
            .unwrap();
        assert!(storage.exists("content/files/ab/cd/test.bin").unwrap());
        assert_eq!(
            storage.read_bytes("content/files/ab/cd/test.bin").unwrap(),
            b"hello"
        );
        assert!(
            storage
                .write_bytes("content/files/ab/cd/test.bin", b"overwrite")
                .is_err()
        );
        storage.remove_file("content/files/ab/cd/test.bin").unwrap();
        assert!(!storage.exists("content/files/ab/cd/test.bin").unwrap());
        assert!(!dir.path().join("content").exists());
    }
}
