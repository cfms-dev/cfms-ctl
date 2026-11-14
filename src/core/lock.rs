//! Cross-platform runtime lock compatible with CFMS `src/.maintenance/server.lock`.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use fs4::fs_std::FileExt;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;

/// Exclusive RAII guard over `src/.maintenance/server.lock`.
#[derive(Debug)]
pub struct ServerLockGuard {
    path: PathBuf,
    file: File,
}

impl Drop for ServerLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl ServerLockGuard {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Manages acquisition and inspection of the server runtime lock.
pub struct RuntimeLock;

impl RuntimeLock {
    /// Acquire the non-blocking exclusive lock on `src/.maintenance/server.lock`.
    ///
    /// Also checks `src/.maintenance/transaction.json` unless `allow_unfinished_deployment` is true.
    pub fn acquire(
        paths: &WorkspacePaths,
        allow_unfinished_deployment: bool,
    ) -> Result<ServerLockGuard> {
        let tx_path = paths.transaction_path();
        if tx_path.exists() && !allow_unfinished_deployment {
            return Err(CfmsError::UnfinishedTransaction(tx_path));
        }

        std::fs::create_dir_all(&paths.maintenance_root)?;
        let lock_path = paths.server_lock_path();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        if file.seek(SeekFrom::End(0))? == 0 {
            file.write_all(b"\0")?;
            file.flush()?;
        }
        file.seek(SeekFrom::Start(0))?;

        file.try_lock_exclusive()
            .map_err(|_| CfmsError::RuntimeLocked(paths.server_root.clone()))?;

        let metadata = serde_json::json!({ "pid": std::process::id() }).to_string();
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(metadata.as_bytes())?;
        file.flush()?;

        Ok(ServerLockGuard {
            path: lock_path,
            file,
        })
    }

    /// Probe whether the server lock is currently free without modifying state.
    #[must_use]
    pub fn is_locked(paths: &WorkspacePaths) -> bool {
        let lock_path = paths.server_lock_path();
        if !lock_path.exists() {
            return false;
        }
        let Ok(file) = OpenOptions::new().read(true).write(true).open(&lock_path) else {
            return false;
        };
        if file.try_lock_exclusive().is_ok() {
            let _ = file.unlock();
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_lock_acquire_and_release() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("src");
        std::fs::create_dir_all(&src).expect("create src");
        std::fs::write(src.join("main.py"), "# cfms").expect("write main.py");

        let paths = WorkspacePaths::discover(Some(temp.path()), None).expect("discover");
        assert!(!RuntimeLock::is_locked(&paths));

        {
            let _guard = RuntimeLock::acquire(&paths, false).expect("acquire lock");
            assert!(RuntimeLock::is_locked(&paths));
            let second = RuntimeLock::acquire(&paths, false);
            assert!(matches!(second, Err(CfmsError::RuntimeLocked(_))));
        }

        assert!(!RuntimeLock::is_locked(&paths));
    }
}
