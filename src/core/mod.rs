//! Core infrastructure for `cfms-ctl`: error contracts, path discovery,
//! lossless configuration management, runtime locks, and atomic file operations.

pub mod atomic;
pub mod config;
pub mod error;
pub mod lock;
pub mod paths;

pub use atomic::{
    atomic_rename_with_retry, atomic_write, ensure_safe_directory_chain,
    is_symlink_or_reparse_point, is_windows_reserved_name, retry_fs_op,
    write_with_timestamped_backup,
};
pub use config::{
    ConfigDocument, ConfigMergeConflict, ConfigMergeConflictKind, DatabaseSectionConfig,
    RedactedSecret, S3AddressingStyle, S3SectionConfig, S3SectionSummary, ServerConfigSummary,
    StorageProviderKind, TemplateSyncPlan,
};
pub use error::{CfmsError, ErrorCode, Result};
pub use lock::{RuntimeLock, ServerLockGuard};
pub use paths::WorkspacePaths;
