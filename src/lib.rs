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
    use crate::ops::backup::{BACKUP_MAGIC, read_backup_header};

    #[test]
    fn verify_cli_command_tree() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_read_backup_header_roundtrip() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use crate::ops::backup::format::{
            BACKUP_CIPHER, BACKUP_CONTAINER, BACKUP_CONTENT_TYPE, BACKUP_FORMAT_VERSION,
            BACKUP_KDF,
        };

        let mut temp = tempfile::NamedTempFile::new().expect("temp file");
        let kdf_salt = URL_SAFE_NO_PAD.encode([0x11u8; 16]);
        let nonce_prefix = URL_SAFE_NO_PAD.encode([0x22u8; 7]);
        let header_json = serde_json::json!({
            "content_type": BACKUP_CONTENT_TYPE,
            "version": BACKUP_FORMAT_VERSION,
            "critical": [
                "content_type",
                "version",
                "schema_revision",
                "components",
                "cipher",
                "compression",
                "container",
                "kdf",
                "chunk_size",
                "kdf_salt",
                "nonce_prefix"
            ],
            "created_at": "2026-11-14T12:00:00Z",
            "server_version": "0.14.0",
            "schema_revision": "e952c02c1454",
            "components": ["accounts", "documents", "configuration"],
            "cipher": BACKUP_CIPHER,
            "compression": "zstd",
            "container": BACKUP_CONTAINER,
            "kdf": BACKUP_KDF,
            "chunk_size": 1_048_576,
            "kdf_salt": kdf_salt,
            "nonce_prefix": nonce_prefix,
            "storage_provider": "local",
            "future_metadata_field": "tolerated"
        });
        let header_bytes = serde_json::to_vec(&header_json).expect("serialize header");
        let len_le = u32::try_from(header_bytes.len())
            .expect("header len")
            .to_le_bytes();

        temp.write_all(BACKUP_MAGIC).expect("write magic");
        temp.write_all(&len_le).expect("write len");
        temp.write_all(&header_bytes).expect("write header");
        temp.flush().expect("flush");

        let parsed = read_backup_header(temp.path()).expect("parse backup header");
        assert_eq!(parsed.content_type, BACKUP_CONTENT_TYPE);
        assert_eq!(parsed.version, BACKUP_FORMAT_VERSION);
        assert_eq!(parsed.server_version, "0.14.0");
        assert_eq!(parsed.schema_revision, "e952c02c1454");
        assert_eq!(parsed.components.len(), 3);
        assert_eq!(parsed.compression, "zstd");
        assert_eq!(parsed.container, BACKUP_CONTAINER);
        assert_eq!(
            parsed
                .non_critical_fields
                .get("future_metadata_field")
                .and_then(|v| v.as_str()),
            Some("tolerated")
        );

        // An unrecognized field declared in `critical` must be refused
        let mut critical_temp = tempfile::NamedTempFile::new().expect("temp file");
        let bad_header = serde_json::json!({
            "content_type": BACKUP_CONTENT_TYPE,
            "version": BACKUP_FORMAT_VERSION,
            "critical": [
                "content_type",
                "version",
                "schema_revision",
                "components",
                "cipher",
                "compression",
                "container",
                "kdf",
                "chunk_size",
                "kdf_salt",
                "nonce_prefix",
                "unknown_required_ext"
            ],
            "schema_revision": "e952c02c1454",
            "components": ["accounts"],
            "cipher": BACKUP_CIPHER,
            "compression": "zstd",
            "container": BACKUP_CONTAINER,
            "kdf": BACKUP_KDF,
            "chunk_size": 1_048_576,
            "kdf_salt": URL_SAFE_NO_PAD.encode([0x11u8; 16]),
            "nonce_prefix": URL_SAFE_NO_PAD.encode([0x22u8; 7]),
            "unknown_required_ext": true
        });
        let bad_bytes = serde_json::to_vec(&bad_header).expect("serialize bad header");
        let bad_len_le = u32::try_from(bad_bytes.len())
            .expect("bad len")
            .to_le_bytes();
        critical_temp.write_all(BACKUP_MAGIC).expect("write magic");
        critical_temp.write_all(&bad_len_le).expect("write len");
        critical_temp.write_all(&bad_bytes).expect("write header");
        critical_temp.flush().expect("flush");

        let err = read_backup_header(critical_temp.path()).unwrap_err();
        assert!(err.to_string().contains("unknown_required_ext"));
    }
}
