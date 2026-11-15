//! Core infrastructure for `cfms-ctl`: error contracts, path discovery,
//! lossless configuration management, runtime locks, and atomic file operations.

pub mod atomic;
pub mod config;
pub mod error;
pub mod lock;
pub mod paths;
pub mod schema;

pub use atomic::{
    atomic_rename_with_retry, atomic_write, ensure_safe_directory_chain,
    is_symlink_or_reparse_point, is_windows_reserved_name, retry_fs_op,
    write_with_timestamped_backup,
};
pub use config::{ConfigDocument, DatabaseSectionConfig, ServerConfigSummary, TemplateSyncPlan};
pub use error::{CfmsError, ErrorCode, Result};
pub use lock::{RuntimeLock, ServerLockGuard};
pub use paths::WorkspacePaths;
pub use schema::{
    InvariantRule, InvariantSeverity, cmp_numeric_values, evaluate_invariants,
    evaluate_schema_invariants, format_canonical_float, is_canonical_int_str,
    load_json_schema_file, normalize_and_precheck_value, validate_instance_against_schema,
};
