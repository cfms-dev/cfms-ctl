//! Storage backend abstraction for backup/restore and file asset verification.

use std::path::{Path, PathBuf};
use crate::core::error::Result;

/// Trait abstracting file storage operations (local filesystem by default, extensible to S3).
pub trait StorageBackend: Send + Sync {
    /// Backend identifier (`local`).
    fn kind(&self) -> &'static str;

    /// Check whether a logical storage path exists.
    fn exists(&self, relative_path: &str) -> Result<bool>;

    /// Read a stored file's bytes.
    fn read_bytes(&self, relative_path: &str) -> Result<Vec<u8>>;

    /// Atomically write bytes to a logical storage path.
    fn write_bytes(&self, relative_path: &str, data: &[u8]) -> Result<()>;
}

/// Local filesystem storage rooted at `<server_root>/content/files` (or `<server_root>`).
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

    fn resolve(&self, relative_path: &str) -> PathBuf {
        self.root.join(relative_path)
    }
}

impl StorageBackend for LocalFsStorage {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn exists(&self, relative_path: &str) -> Result<bool> {
        Ok(self.resolve(relative_path).is_file())
    }

    fn read_bytes(&self, relative_path: &str) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.resolve(relative_path))?)
    }

    fn write_bytes(&self, relative_path: &str, data: &[u8]) -> Result<()> {
        let target = self.resolve(relative_path);
        crate::core::atomic::atomic_write(&target, data)
    }
}
