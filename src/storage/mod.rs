//! Storage backend abstraction for streaming backup/restore and deployment diagnostics.

pub mod local;
pub mod s3;

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use bytes::Bytes;
use futures_util::Stream;
use tokio::sync::Mutex;
use crate::core::config::{ConfigDocument, StorageProviderKind};
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;

pub use local::LocalFsStorage;
pub use s3::S3Storage;

/// Boxed future alias used by async [`StorageBackend`] and [`StagedStorageWriter`] methods
/// to preserve object safety without procedural macro crates.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Streaming byte source yielded by [`StorageBackend::open_read_optional`].
pub type StorageByteStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

#[derive(Debug, Default)]
struct RollbackState {
    written_paths: Vec<String>,
    active_multiparts: BTreeMap<String, String>,
}

/// Shared rollback ledger tracking newly created keys and uncommitted multipart uploads so a
/// failed import never leaks orphan S3 parts or deletes pre-existing objects.
#[derive(Debug, Default)]
pub struct RollbackTracker {
    state: Mutex<RollbackState>,
}

impl RollbackTracker {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn record_written(&self, path: String) {
        let mut guard = self.state.lock().await;
        guard.written_paths.push(path);
    }

    pub async fn register_multipart(&self, key: String, upload_id: String) {
        let mut guard = self.state.lock().await;
        guard.active_multiparts.insert(key, upload_id);
    }

    pub async fn clear_multipart(&self, key: &str) {
        let mut guard = self.state.lock().await;
        guard.active_multiparts.remove(key);
    }

    pub(crate) fn clone_paths_handle(&self) -> RollbackHandle<'_> {
        RollbackHandle(self)
    }

    pub(crate) async fn snapshot_written_blocking_order(&self) -> Vec<String> {
        let guard = self.state.lock().await;
        guard.written_paths.clone()
    }

    pub async fn snapshot_for_rollback(&self) -> (Vec<String>, Vec<(String, String)>) {
        let guard = self.state.lock().await;
        let mut seen = HashSet::new();
        let mut unique_paths = Vec::with_capacity(guard.written_paths.len());
        for p in guard.written_paths.iter().rev() {
            if seen.insert(p.clone()) {
                unique_paths.push(p.clone());
            }
        }
        let multiparts: Vec<(String, String)> = guard
            .active_multiparts
            .iter()
            .map(|(k, id)| (k.clone(), id.clone()))
            .collect();
        (unique_paths, multiparts)
    }
}

pub(crate) struct RollbackHandle<'a>(&'a RollbackTracker);

impl RollbackHandle<'_> {
    pub(crate) async fn record_written(self, path: String) {
        self.0.record_written(path).await;
    }
}

/// Summary returned when rolling back storage side effects after an aborted import.
#[derive(Debug, Default, Clone)]
pub struct RollbackOutcome {
    pub deleted_objects: usize,
    pub aborted_multiparts: usize,
    pub errors: Vec<String>,
}

/// Streaming atomic no-clobber write handle targeting a storage backend.
pub trait StagedStorageWriter: Send {
    /// Feed decrypted bytes into the staged upload/file writer.
    fn write_chunk(&mut self, chunk: Bytes) -> BoxFuture<'_, Result<()>>;

    /// Atomically commit the object without overwriting pre-existing keys.
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<()>>;

    /// Discard temporary files or abort an uncommitted multipart upload.
    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<()>>;
}

/// Async storage backend abstraction (`local` filesystem and `s3` object storage).
pub trait StorageBackend: Send + Sync {
    /// Backend identifier recorded in archive envelope/manifest (`local` or `s3`).
    fn kind(&self) -> &'static str;

    /// Redacted human-readable description of the active storage destination.
    fn target_description(&self) -> String;

    /// Suggested bounded transfer concurrency for pipelined export/import.
    fn recommended_concurrency(&self) -> usize;

    /// Non-fatal warnings surfaced by the backend (e.g., conditional write compatibility fallback).
    fn collected_warnings(&self) -> Vec<String> {
        Vec::new()
    }

    /// Verify bucket/root reachability and credentials before mutating database or writing archives.
    fn preflight(&self) -> BoxFuture<'_, Result<()>>;

    /// Open a single-RTT streaming reader for `relative_path`, returning `Ok(None)` ONLY when
    /// the object does not exist (`NotFound` / `NoSuchKey`). Bucket, permission, or network errors
    /// always return `Err`.
    fn open_read_optional(&self, relative_path: &str) -> BoxFuture<'_, Result<Option<StorageByteStream>>>;

    /// Verify none of the given deduplicated relative paths exist in storage.
    fn check_paths_absent(&self, relative_paths: &[String]) -> BoxFuture<'_, Result<()>>;

    /// Begin a streaming atomic write targeting a non-existent logical path.
    fn begin_staged_write(
        &self,
        relative_path: &str,
        size_hint: Option<u64>,
        tracker: Arc<RollbackTracker>,
    ) -> BoxFuture<'_, Result<Box<dyn StagedStorageWriter>>>;

    /// Copy an already-committed logical object to another non-existent logical path.
    fn copy_within<'a>(
        &'a self,
        src_relative_path: &str,
        dst_relative_path: &str,
        tracker: &'a RollbackTracker,
    ) -> BoxFuture<'a, Result<u64>>;

    /// Clean up all uncommitted multipart uploads and committed objects tracked in `tracker`.
    fn rollback_written<'a>(&'a self, tracker: &'a RollbackTracker) -> BoxFuture<'a, RollbackOutcome>;
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
    if relative_path.starts_with('/')
        || relative_path.starts_with('\\')
        || relative_path.contains('\\')
    {
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

/// Resolve and configure the active [`StorageBackend`] (`local` or `s3`) from `config.toml`.
pub async fn resolve_storage(
    paths: &WorkspacePaths,
    config: &ConfigDocument,
) -> Result<Arc<dyn StorageBackend>> {
    match config.storage_provider()? {
        StorageProviderKind::Local => {
            Ok(Arc::new(LocalFsStorage::new(paths.server_root.clone())))
        }
        StorageProviderKind::S3 => {
            let s3_cfg = config.s3_config()?;
            let s3 = S3Storage::from_config(&s3_cfg).await?;
            Ok(Arc::new(s3))
        }
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

    #[tokio::test]
    async fn local_storage_staged_write_refuses_clobber_and_supports_rollback() {
        let dir = tempdir().unwrap();
        let storage = LocalFsStorage::new(dir.path().to_path_buf());
        storage
            .write_bytes_sync("content/files/ab/cd/test.bin", b"hello")
            .unwrap();
        assert!(storage.exists_sync("content/files/ab/cd/test.bin").unwrap());
        assert_eq!(
            storage
                .read_bytes_sync("content/files/ab/cd/test.bin")
                .unwrap(),
            b"hello"
        );
        assert!(
            storage
                .write_bytes_sync("content/files/ab/cd/test.bin", b"overwrite")
                .is_err()
        );
        storage
            .remove_file_sync("content/files/ab/cd/test.bin")
            .unwrap();
        assert!(!storage.exists_sync("content/files/ab/cd/test.bin").unwrap());
        assert!(!dir.path().join("content").exists());
    }
}
