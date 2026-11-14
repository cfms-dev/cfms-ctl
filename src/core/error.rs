//! Unified error hierarchy and machine-readable error codes for `cfms-ctl`.

use std::path::PathBuf;
use serde::Serialize;
use thiserror::Error;

/// Stable machine-readable error codes emitted in `--output json` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    WorkspaceNotFound,
    ConfigError,
    OptionConflict,
    RuntimeLocked,
    UnfinishedTransaction,
    DatabaseError,
    SchemaDrift,
    BackupError,
    ArchiveIntegrityError,
    ExtensionError,
    InvalidArgument,
    OperationAborted,
    NotImplementedYet,
    IoError,
}

/// Top-level error type for all maintenance operations.
#[derive(Debug, Error)]
pub enum CfmsError {
    #[error("Unable to locate a valid CFMS deployment or server root from '{0}'")]
    WorkspaceNotFound(PathBuf),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Option revision conflict: {0}")]
    OptionConflict(String),

    #[error("CFMS server or another maintenance process holds the runtime lock at '{0}'")]
    RuntimeLocked(PathBuf),

    #[error("An unfinished deployment transaction exists at '{0}'; run `cfms-ctl deployment resume` first")]
    UnfinishedTransaction(PathBuf),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Database schema validation failed: {0}")]
    SchemaDrift(String),

    #[error("Backup operation error: {0}")]
    Backup(String),

    #[error("Archive integrity error: {0}")]
    ArchiveIntegrity(String),

    #[error("Extension error: {0}")]
    Extension(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Operation aborted by operator")]
    OperationAborted,

    #[error("Operation `{0}` is part of the scaffold and will be implemented in the next stage")]
    NotImplementedYet(&'static str),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl CfmsError {
    /// Map the error variant to its stable [`ErrorCode`].
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::WorkspaceNotFound(_) => ErrorCode::WorkspaceNotFound,
            Self::Config(_) => ErrorCode::ConfigError,
            Self::OptionConflict(_) => ErrorCode::OptionConflict,
            Self::RuntimeLocked(_) => ErrorCode::RuntimeLocked,
            Self::UnfinishedTransaction(_) => ErrorCode::UnfinishedTransaction,
            Self::Database(_) => ErrorCode::DatabaseError,
            Self::SchemaDrift(_) => ErrorCode::SchemaDrift,
            Self::Backup(_) => ErrorCode::BackupError,
            Self::ArchiveIntegrity(_) => ErrorCode::ArchiveIntegrityError,
            Self::Extension(_) => ErrorCode::ExtensionError,
            Self::InvalidArgument(_) => ErrorCode::InvalidArgument,
            Self::OperationAborted => ErrorCode::OperationAborted,
            Self::NotImplementedYet(_) => ErrorCode::NotImplementedYet,
            Self::Io(_) => ErrorCode::IoError,
        }
    }

    /// Exit code to return from `main`.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::OperationAborted => 130,
            Self::InvalidArgument(_) => 2,
            _ => 1,
        }
    }
}

impl From<sqlx::Error> for CfmsError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<toml_edit::TomlError> for CfmsError {
    fn from(err: toml_edit::TomlError) -> Self {
        Self::Config(err.to_string())
    }
}

/// Standard result alias used across `cfms-ctl`.
pub type Result<T> = std::result::Result<T, CfmsError>;
