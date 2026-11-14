//! Core infrastructure for `cfms-ctl`: error contracts, path discovery,
//! lossless configuration management, runtime locks, and atomic file operations.

pub mod atomic;
pub mod config;
pub mod error;
pub mod lock;
pub mod paths;

pub use config::{ConfigDocument, DatabaseSectionConfig, ServerConfigSummary, TemplateSyncPlan};
pub use error::{CfmsError, ErrorCode, Result};
pub use lock::{RuntimeLock, ServerLockGuard};
pub use paths::WorkspacePaths;
