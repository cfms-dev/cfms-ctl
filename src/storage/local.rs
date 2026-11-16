//! Local filesystem storage backend rooted at CFMS `<server_root>`.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bytes::Bytes;
use futures_util::stream;
use tempfile::NamedTempFile;
use tokio::sync::mpsc;
use crate::core::error::{CfmsError, Result};
use crate::storage::{
    BoxFuture, RollbackOutcome, RollbackTracker, StagedStorageWriter, StorageBackend,
    StorageByteStream, validate_storage_relative_path,
};

const LOCAL_READ_CHUNK_BYTES: usize = 256 * 1024;
const LOCAL_STAGED_BUF_BYTES: usize = 256 * 1024;

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

    pub(crate) fn resolve_checked(&self, relative_path: &str) -> Result<PathBuf> {
        let valid = validate_storage_relative_path(relative_path)?;
        let mut out = self.root.clone();
        for seg in valid.split('/') {
            out.push(seg);
        }
        Ok(out)
    }

    /// Synchronous existence check used by unit tests and blocking filesystem helpers.
    pub fn exists_sync(&self, relative_path: &str) -> Result<bool> {
        let path = self.resolve_checked(relative_path)?;
        Ok(std::fs::symlink_metadata(path).is_ok())
    }

    /// Synchronous byte read helper for local filesystem tests.
    pub fn read_bytes_sync(&self, relative_path: &str) -> Result<Vec<u8>> {
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
        Ok(std::fs::read(&path)?)
    }

    /// Synchronous atomic no-clobber write helper for local filesystem tests.
    pub fn write_bytes_sync(&self, relative_path: &str, data: &[u8]) -> Result<()> {
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
        let mut temp = tempfile::Builder::new()
            .prefix(".cfms-write-part-")
            .tempfile_in(parent)?;
        temp.write_all(data)?;
        temp.flush()?;
        temp.persist_noclobber(&target).map_err(|err| {
            CfmsError::ArchiveIntegrity(format!(
                "Failed to persist storage file '{relative_path}': {}",
                err.error
            ))
        })?;
        Ok(())
    }

    /// Synchronous removal helper that also prunes empty parent directories up to `self.root`.
    pub fn remove_file_sync(&self, relative_path: &str) -> Result<()> {
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

struct LocalStagedWrite {
    writer: Option<BufWriter<NamedTempFile>>,
    target: PathBuf,
    relative_path: String,
    tracker: Arc<RollbackTracker>,
}

impl StagedStorageWriter for LocalStagedWrite {
    fn write_chunk(&mut self, chunk: Bytes) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let Some(mut writer) = self.writer.take() else {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Attempted to write after close on '{}'",
                    self.relative_path
                )));
            };
            let writer = tokio::task::spawn_blocking(move || -> std::io::Result<BufWriter<NamedTempFile>> {
                writer.write_all(&chunk)?;
                Ok(writer)
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;
            self.writer = Some(writer);
            Ok(())
        })
    }

    fn finish(mut self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            let Some(mut writer) = self.writer.take() else {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Staged storage file '{}' already finalized or aborted",
                    self.relative_path
                )));
            };
            let target = self.target.clone();
            let relative_path = self.relative_path.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                writer.flush()?;
                let temp = writer.into_inner().map_err(|e| e.into_error())?;
                if std::fs::symlink_metadata(&target).is_ok() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Refusing to overwrite existing storage file '{relative_path}'"
                    )));
                }
                temp.persist_noclobber(&target).map_err(|err| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Failed to persist restored storage file '{relative_path}': {}",
                        err.error
                    ))
                })?;
                Ok(())
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

            self.tracker.record_written(self.relative_path).await;
            Ok(())
        })
    }

    fn abort(mut self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            if let Some(writer) = self.writer.take() {
                let _ = tokio::task::spawn_blocking(move || drop(writer)).await;
            }
            Ok(())
        })
    }
}

impl StorageBackend for LocalFsStorage {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn target_description(&self) -> String {
        self.root.display().to_string()
    }

    fn recommended_concurrency(&self) -> usize {
        1
    }

    fn preflight(&self) -> BoxFuture<'_, Result<()>> {
        let root = self.root.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<()> {
                if root.exists() {
                    let meta = std::fs::symlink_metadata(&root)?;
                    if !meta.is_dir() {
                        return Err(CfmsError::Config(format!(
                            "Local storage root '{}' exists and is not a directory",
                            root.display()
                        )));
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?
        })
    }

    fn open_read_optional(
        &self,
        relative_path: &str,
    ) -> BoxFuture<'_, Result<Option<StorageByteStream>>> {
        let storage = self.clone();
        let rel = relative_path.to_string();
        Box::pin(async move {
            let path = storage.resolve_checked(&rel)?;
            let rel_for_open = rel.clone();
            let opened = tokio::task::spawn_blocking(move || -> Result<Option<File>> {
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(CfmsError::Io(e)),
                };
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Storage object '{rel_for_open}' must be a regular file"
                    )));
                }
                let file = File::open(&path)?;
                Ok(Some(file))
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

            let Some(mut file) = opened else {
                return Ok(None);
            };

            let (tx, rx) = mpsc::channel::<Result<Bytes>>(4);
            tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; LOCAL_READ_CHUNK_BYTES];
                loop {
                    match file.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = Bytes::copy_from_slice(&buf[..n]);
                            if tx.blocking_send(Ok(chunk)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = tx.blocking_send(Err(CfmsError::Io(e)));
                            break;
                        }
                    }
                }
            });

            let byte_stream: StorageByteStream = Box::pin(stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|item| (item, rx))
            }));
            Ok(Some(byte_stream))
        })
    }

    fn check_paths_absent(&self, relative_paths: &[String]) -> BoxFuture<'_, Result<()>> {
        let storage = self.clone();
        let paths: Vec<String> = relative_paths.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<()> {
                for rel in &paths {
                    if storage.exists_sync(rel)? {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Refusing to overwrite pre-existing storage object '{rel}'"
                        )));
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?
        })
    }

    fn begin_staged_write(
        &self,
        relative_path: &str,
        _size_hint: Option<u64>,
        tracker: Arc<RollbackTracker>,
    ) -> BoxFuture<'_, Result<Box<dyn StagedStorageWriter>>> {
        let storage = self.clone();
        let rel = relative_path.to_string();
        Box::pin(async move {
            let target = storage.resolve_checked(&rel)?;
            let rel_err = rel.clone();
            let target_create = target.clone();
            let temp = tokio::task::spawn_blocking(move || -> Result<NamedTempFile> {
                if std::fs::symlink_metadata(&target_create).is_ok() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Target storage path already exists: '{rel_err}'"
                    )));
                }
                let parent = target_create.parent().ok_or_else(|| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Invalid storage target path '{rel_err}'"
                    ))
                })?;
                std::fs::create_dir_all(parent)?;
                let temp = tempfile::Builder::new()
                    .prefix(".cfms-import-part-")
                    .tempfile_in(parent)?;
                Ok(temp)
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

            let boxed: Box<dyn StagedStorageWriter> = Box::new(LocalStagedWrite {
                writer: Some(BufWriter::with_capacity(LOCAL_STAGED_BUF_BYTES, temp)),
                target,
                relative_path: rel,
                tracker,
            });
            Ok(boxed)
        })
    }

    fn copy_within<'a>(
        &'a self,
        src_relative_path: &str,
        dst_relative_path: &str,
        tracker: &'a RollbackTracker,
    ) -> BoxFuture<'a, Result<u64>> {
        let storage = self.clone();
        let src = src_relative_path.to_string();
        let dst = dst_relative_path.to_string();
        let tracker_clone = tracker.clone_paths_handle();
        Box::pin(async move {
            let src_path = storage.resolve_checked(&src)?;
            let dst_path = storage.resolve_checked(&dst)?;
            let dst_err = dst.clone();
            let src_err = src.clone();
            let copied = tokio::task::spawn_blocking(move || -> Result<u64> {
                let meta = std::fs::symlink_metadata(&src_path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        CfmsError::ArchiveIntegrity(format!(
                            "Missing storage file '{src_err}' during copy"
                        ))
                    } else {
                        CfmsError::Io(e)
                    }
                })?;
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Storage object '{src_err}' must be a regular file"
                    )));
                }
                if std::fs::symlink_metadata(&dst_path).is_ok() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Target storage path already exists: '{dst_err}'"
                    )));
                }
                let parent = dst_path.parent().ok_or_else(|| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Invalid storage target path '{dst_err}'"
                    ))
                })?;
                std::fs::create_dir_all(parent)?;
                let mut reader = File::open(&src_path)?;
                let mut temp = tempfile::Builder::new()
                    .prefix(".cfms-copy-part-")
                    .tempfile_in(parent)?;
                let copied = std::io::copy(&mut reader, &mut temp)?;
                temp.flush()?;
                temp.persist_noclobber(&dst_path).map_err(|err| {
                    CfmsError::ArchiveIntegrity(format!(
                        "Failed to persist copied storage file '{dst_err}': {}",
                        err.error
                    ))
                })?;
                Ok(copied)
            })
            .await
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

            tracker_clone.record_written(dst).await;
            Ok(copied)
        })
    }

    fn rollback_written<'a>(&'a self, tracker: &'a RollbackTracker) -> BoxFuture<'a, RollbackOutcome> {
        let storage = self.clone();
        let written = tracker.snapshot_written_blocking_order();
        Box::pin(async move {
            let paths = written.await;
            tokio::task::spawn_blocking(move || {
                let mut outcome = RollbackOutcome::default();
                for path in paths.iter().rev() {
                    match storage.remove_file_sync(path) {
                        Ok(()) => outcome.deleted_objects += 1,
                        Err(e) => outcome.errors.push(format!("{path}: {e}")),
                    }
                }
                outcome
            })
            .await
            .unwrap_or_else(|e| RollbackOutcome {
                deleted_objects: 0,
                aborted_multiparts: 0,
                errors: vec![format!("Local rollback worker panicked: {e}")],
            })
        })
    }
}
