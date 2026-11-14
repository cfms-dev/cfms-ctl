//! `cfms-ctl`: Standalone, high-performance, multi-database maintenance CLI for CFMS servers.
//!
//! # Architecture
//! - [`cli`]: `clap` derive command and argument tree (`doctor`, `deployment`, `database`, `backup`, `config`, `extension`, `user`, `permission`, `audit`).
//! - [`core`]: Unified error contract, side-effect-free workspace path discovery, lossless `toml_edit` configuration management, cross-platform runtime lock (`server.lock`), and atomic file operations.
//! - [`db`]: Multi-backend (`SQLite`, `MySQL`, `PostgreSQL`) connection pools, schema registry, live schema drift inspector, and cross-engine transfer types.
//! - [`storage`]: Pluggable object storage trait (`StorageBackend`) and local filesystem backend.
//! - [`ops`]: Domain operation orchestrators and typed reports implementing [`ui::CommandReport`].
//! - [`ui`]: Dual-mode (`Human` vs `Json`) console renderer, table builders, and interactive prompt guards.

pub mod cli;
pub mod core;
pub mod db;
pub mod ops;
pub mod storage;
pub mod ui;

#[cfg(test)]
mod tests {
    use std::io::Write;
    use clap::CommandFactory;
    use crate::cli::Cli;
    use crate::ops::backup::{BACKUP_V2_MAGIC, read_backup_v2_header};

    #[test]
    fn verify_cli_command_tree() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_read_backup_v2_header_roundtrip() {
        let mut temp = tempfile::NamedTempFile::new().expect("temp file");
        let header_json = serde_json::json!({
            "format_version": 2,
            "created_at": "2026-11-14T12:00:00Z",
            "server_version": "0.14.0",
            "schema_revision": "e952c02c1454",
            "components": ["database", "files", "config"],
            "cipher": "AES-256-GCM",
            "future_metadata_field": "tolerated"
        });
        let header_bytes = serde_json::to_vec(&header_json).expect("serialize header");
        let len_be = u32::try_from(header_bytes.len())
            .expect("header len")
            .to_be_bytes();

        temp.write_all(BACKUP_V2_MAGIC).expect("write magic");
        temp.write_all(&len_be).expect("write len");
        temp.write_all(&header_bytes).expect("write header");
        temp.flush().expect("flush");

        let parsed = read_backup_v2_header(temp.path()).expect("parse v2 header");
        assert_eq!(parsed.format_version, 2);
        assert_eq!(parsed.server_version, "0.14.0");
        assert_eq!(parsed.schema_revision, "e952c02c1454");
        assert_eq!(parsed.components.len(), 3);
        assert!(parsed.extra.contains_key("future_metadata_field"));
    }
}
