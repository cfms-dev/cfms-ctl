//! `cfms-ctl backup`: Streaming encrypted CFMS logical backup (`CFMSCBK1`) inspection,
//! cryptographic verification, export, and transactional import.

pub mod export;
pub mod format;
pub mod import;
pub mod selection;
pub mod stream;
pub mod verify;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use crate::cli::backup::{BackupCommand, BackupInfoArgs};
use crate::core::Result;
use crate::ops::AppContext;
use crate::ui::OutputFormat;

pub use format::{BACKUP_MAGIC, BackupHeaderReport, read_backup_header};

/// Dispatch `cfms-ctl backup` subcommands.
pub async fn handle(ctx: &AppContext, cmd: BackupCommand) -> Result<()> {
    match cmd {
        BackupCommand::Info(args) => handle_info(ctx, args),
        BackupCommand::Export(args) => export::run_export(ctx, args).await,
        BackupCommand::Import(args) => import::run_import(ctx, args).await,
        BackupCommand::Verify(args) => verify::run_verify(ctx, args).await,
    }
}

fn handle_info(ctx: &AppContext, args: BackupInfoArgs) -> Result<()> {
    let report = read_backup_header(&args.backup_path)?;
    ctx.ui.render(&report);
    Ok(())
}

/// Build a shared stderr progress bar hidden in JSON output mode.
pub(super) fn backup_progress_bar(format: OutputFormat, len: u64) -> ProgressBar {
    match format {
        OutputFormat::Human => {
            let bar = ProgressBar::with_draw_target(Some(len), ProgressDrawTarget::stderr());
            let style = ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:32.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("##-");
            bar.set_style(style);
            bar
        }
        OutputFormat::Json => ProgressBar::hidden(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use crate::cli::GlobalOpts;
    use crate::cli::backup::{
        BackupComponentArg, BackupExportArgs, BackupImportArgs, BackupVerifyArgs,
    };
    use crate::core::config::ConfigDocument;
    use crate::core::error::CfmsError;
    use crate::core::paths::WorkspacePaths;
    use crate::db::schema::{
        LATEST_SCHEMA_REVISION, SchemaInspector, builtin_schema_ir, create_head_schema,
        set_alembic_version,
    };
    use crate::db::{DatabaseKind, DbPool};
    use crate::storage::{LocalFsStorage, StorageBackend};
    use crate::ui::UiConsole;

    fn test_ctx(root: &Path) -> AppContext {
        let global = GlobalOpts {
            root: Some(root.to_path_buf()),
            config: None,
            output: OutputFormat::Json,
            yes: true,
            verbose: false,
        };
        AppContext::new(global, UiConsole::new(OutputFormat::Json))
    }

    fn create_test_workspace(
        dir: &Path,
        db_rel: &str,
        storage_provider: &str,
        pepper: &str,
        secret_key: &str,
    ) -> PathBuf {
        let project_root = dir.to_path_buf();
        let server_root = project_root.join("src");
        fs::create_dir_all(&server_root).unwrap();
        fs::write(server_root.join("main.py"), "# stub\n").unwrap();
        fs::write(
            project_root.join("release-manifest.json"),
            r#"{"version":"0.14.0-test"}"#,
        )
        .unwrap();

        let config_toml = format!(
            r#"# preserved comment header
[database]
type = "sqlite"
file = "{db_rel}"

[provider]
storage = "{storage_provider}"

[security]
# preserved pepper comment
pepper = "{pepper}"

[server]
secret_key = "{secret_key}"
"#
        );
        fs::write(server_root.join("config.toml"), config_toml).unwrap();
        project_root
    }

    async fn open_sqlite_pool(ws: &Path) -> DbPool {
        let paths = WorkspacePaths::discover(Some(ws), None).unwrap();
        let doc = ConfigDocument::load(&paths.config_path).unwrap();
        let cfg = doc.database_config().unwrap();
        assert_eq!(cfg.kind, DatabaseKind::Sqlite);
        DbPool::connect(&cfg, &paths).await.unwrap()
    }

    async fn seed_source_database(ws: &Path) -> Vec<u8> {
        let pool = open_sqlite_pool(ws).await;
        create_head_schema(&pool, true).await.unwrap();
        set_alembic_version(&pool, LATEST_SCHEMA_REVISION)
            .await
            .unwrap();

        let DbPool::Sqlite(ref p) = pool else {
            unreachable!();
        };

        // Users & FK references (nullable status comment + avatar file)
        let digest1 = [0x11u8; 32];
        let digest2 = [0x22u8; 32];
        sqlx::query(
            "INSERT INTO comments (comment_id, digest_version, content_digest, comment_text, comment_data) VALUES \
             (1, 1, ?, 'User note', NULL), \
             (2, 1, ?, 'Ban note', NULL)",
        )
        .bind(digest1.as_slice())
        .bind(digest2.as_slice())
        .execute(p)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO files (id, sha256, path, size, created_time, active) VALUES \
             ('f-big', '0000', 'content/files/ab/big.bin', 1300000, 100.0, 1), \
             ('f-dedup', '0000', 'content/files/ab/big.bin', 1300000, 100.0, 1), \
             ('f-missing-inactive', '1111', 'content/files/cd/gone.bin', 12, 101.0, 0), \
             ('f-avatar', '2222', 'content/files/ef/avatar.png', 6, 102.0, 1)",
        )
        .execute(p)
        .await
        .unwrap();

        let alice_uuid = uuid::Uuid::from_bytes([0x42u8; 16]);
        let alice_uuid_str = alice_uuid.simple().to_string();
        sqlx::query(
            "INSERT INTO users (id, username, nickname, avatar_id, last_login, created_time, status, status_comment_id, secret_key, preference_dek_id) VALUES \
             (?, 'alice', 'Alice', 'f-avatar', 105.0, 100.0, 0, 1, 'user-secret-key', NULL)",
        )
        .bind(&alice_uuid_str)
        .execute(p)
        .await
        .unwrap();

        // Extension table `user_oidc_credentials` with SHA-256([issuer, subject]) digest
        let oidc_payload = serde_json::to_vec(&["https://idp.example", "alice-sub"]).unwrap();
        let oidc_digest = Sha256::digest(&oidc_payload);
        sqlx::query(
            "INSERT INTO user_oidc_credentials (id, user_id, issuer, subject, identity_digest) VALUES \
             ('oidc-1', ?, 'https://idp.example', 'alice-sub', ?)",
        )
        .bind(&alice_uuid_str)
        .bind(oidc_digest.as_slice())
        .execute(p)
        .await
        .unwrap();

        // Coupled hierarchy depth-by-depth: '/' (node+folder) -> '/sub' (node+folder) -> '/sub/spec' (node+document)
        sqlx::query(
            "INSERT INTO nodes (id, type, name, parent_id, inherit, status, status_operation_id, access_rule_set_id) VALUES \
             ('/', 'directory', '/', NULL, 1, 0, NULL, NULL)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query("INSERT INTO folders (id, created_time) VALUES ('/', 100.0)")
            .execute(p)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO nodes (id, type, name, parent_id, inherit, status, status_operation_id, access_rule_set_id) VALUES \
             ('/sub', 'directory', 'Subfolder', '/', 1, 0, NULL, NULL)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query("INSERT INTO folders (id, created_time) VALUES ('/sub', 101.0)")
            .execute(p)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO nodes (id, type, name, parent_id, inherit, status, status_operation_id, access_rule_set_id) VALUES \
             ('/sub/spec', 'document', 'Spec.md', '/sub', 1, 0, NULL, NULL)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO documents (id, created_time, current_revision_id) VALUES ('/sub/spec', 102.0, NULL)",
        )
        .execute(p)
        .await
        .unwrap();

        // Self-referencing revision chain where id 'a-child' < 'z-root' lexicographically!
        sqlx::query(
            "INSERT INTO document_revisions (id, document_id, file_id, created_time, parent_revision_id, status) VALUES \
             ('z-root', '/sub/spec', 'f-big', 102.0, NULL, 1)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO document_revisions (id, document_id, file_id, created_time, parent_revision_id, status) VALUES \
             ('a-child', '/sub/spec', 'f-dedup', 103.0, 'z-root', 1)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query("UPDATE documents SET current_revision_id = 'a-child' WHERE id = '/sub/spec'")
            .execute(p)
            .await
            .unwrap();

        // Active vs orphaned compiled_access_rule_sets
        sqlx::query(
            "INSERT INTO compiled_access_rule_sets (id, node_id, created_at) VALUES \
             ('ars-active', '/sub', 100.0), \
             ('ars-empty', '/', 100.0)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO compiled_access_rules (id, rule_set_id, access_type, match_mode) VALUES \
             (1, 'ars-active', 'read', 'allow')",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query("UPDATE nodes SET access_rule_set_id = 'ars-active' WHERE id = '/sub'")
            .execute(p)
            .await
            .unwrap();
        sqlx::query("UPDATE nodes SET access_rule_set_id = 'ars-empty' WHERE id = '/'")
            .execute(p)
            .await
            .unwrap();

        // Banned subnets & audit
        sqlx::query(
            "INSERT INTO banned_subnets (subnet, reason_comment_id, created_at, starts_at, expires_at) VALUES ('192.0.2.0/24', 2, 100.0, 100.0, NULL)",
        )
        .execute(p)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES \
             ('audit-1', 'login', ?, 'auth', '{\"ok\":true}', 0, '127.0.0.1', 110.0)",
        )
        .bind(&alice_uuid_str)
        .execute(p)
        .await
        .unwrap();

        // Storage files (> 1.2 MiB binary blob to exercise multiple chunked AEAD & 256KiB blob frames)
        let paths = WorkspacePaths::discover(Some(ws), None).unwrap();
        let storage = LocalFsStorage::new(paths.server_root);
        let big_blob: Vec<u8> = (0..1_300_000usize).map(|i| ((i * 31 + 7) % 251) as u8).collect();
        storage.write_bytes("content/files/ab/big.bin", &big_blob).unwrap();
        storage
            .write_bytes("content/files/ef/avatar.png", b"AVATAR")
            .unwrap();

        pool.close().await;
        big_blob
    }

    #[tokio::test]
    async fn full_export_verify_info_and_import_into_blank_db_succeeds() {
        let tmp = TempDir::new().unwrap();
        let src_ws = create_test_workspace(
            &tmp.path().join("src_ws"),
            "app.db",
            "local",
            "src-pepper-secret",
            "src-server-secret",
        );
        let expected_big_blob = seed_source_database(&src_ws).await;

        let archive_path = tmp.path().join("full.confbak");
        let key_path = tmp.path().join("full.key");

        export::run_export(
            &test_ctx(&src_ws),
            BackupExportArgs {
                output_path: Some(archive_path.clone()),
                key_out: Some(key_path.clone()),
                components: vec![],
                interactive: false,
            },
        )
        .await
        .unwrap();

        // Header inspection works without key
        let header = read_backup_header(&archive_path).unwrap();
        assert_eq!(header.format_version, 1);
        assert_eq!(header.server_version, "0.14.0-test");
        assert_eq!(header.compression, "zstd");
        assert_eq!(header.container, "cfms-stream-v1");
        assert_eq!(header.components.len(), 5);

        // No sibling temp files left behind
        let left_tmp: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".part"))
            .collect();
        assert!(left_tmp.is_empty());

        // Standalone verify succeeds with zero DB access
        verify::run_verify(
            &AppContext::new(
                GlobalOpts {
                    root: None,
                    config: None,
                    output: OutputFormat::Json,
                    yes: true,
                    verbose: false,
                },
                UiConsole::new(OutputFormat::Json),
            ),
            BackupVerifyArgs {
                backup_path: archive_path.clone(),
                key: None,
                key_file: Some(key_path.clone()),
            },
        )
        .await
        .unwrap();

        // Wrong key must fail authentication
        let wrong_key_res = verify::run_verify(
            &test_ctx(&src_ws),
            BackupVerifyArgs {
                backup_path: archive_path.clone(),
                key: Some(
                    format::encode_backup_key_base31(&format::generate_backup_key()).to_string(),
                ),
                key_file: None,
            },
        )
        .await;
        assert!(wrong_key_res.is_err());

        // Import into a brand-new completely blank SQLite database
        let dst_ws = create_test_workspace(
            &tmp.path().join("dst_ws"),
            "fresh.db",
            "local",
            "old-pepper",
            "old-secret",
        );
        import::run_import(
            &test_ctx(&dst_ws),
            BackupImportArgs {
                backup_path: archive_path.clone(),
                key: None,
                key_file: Some(key_path.clone()),
            },
        )
        .await
        .unwrap();

        // Check DB schema + restored rows + normalized orphaned ars-empty + fallback server.name option
        let dst_pool = open_sqlite_pool(&dst_ws).await;
        let report = SchemaInspector::inspect_against_ir(&dst_pool, &builtin_schema_ir(true))
            .await
            .unwrap();
        assert!(report.healthy);

        let DbPool::Sqlite(ref dp) = dst_pool else {
            unreachable!();
        };
        let doc_rev: Option<String> =
            sqlx::query_scalar("SELECT current_revision_id FROM documents WHERE id = '/sub/spec'")
                .fetch_one(dp)
                .await
                .unwrap();
        assert_eq!(doc_rev.as_deref(), Some("a-child"));

        let root_ars: Option<String> =
            sqlx::query_scalar("SELECT access_rule_set_id FROM nodes WHERE id = '/'")
                .fetch_one(dp)
                .await
                .unwrap();
        assert_eq!(root_ars, None, "orphaned rule set must be cleared to NULL");

        let sub_ars: Option<String> =
            sqlx::query_scalar("SELECT access_rule_set_id FROM nodes WHERE id = '/sub'")
                .fetch_one(dp)
                .await
                .unwrap();
        assert_eq!(sub_ars.as_deref(), Some("ars-active"));

        let server_name: Option<String> = sqlx::query_scalar(
            "SELECT option_value FROM options WHERE namespace = 'server' AND option_key = 'name'",
        )
        .fetch_optional(dp)
        .await
        .unwrap();
        assert_eq!(server_name.as_deref(), Some("CFMS WebSocket Server"));

        let oidc_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_oidc_credentials")
            .fetch_one(dp)
            .await
            .unwrap();
        assert_eq!(oidc_count, 1);

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_entries")
            .fetch_one(dp)
            .await
            .unwrap();
        assert_eq!(audit_count, 1);

        // Verify big blob & avatar & config secrets & comments & init marker restored
        let dst_paths = WorkspacePaths::discover(Some(&dst_ws), None).unwrap();
        let dst_storage = LocalFsStorage::new(dst_paths.server_root.clone());
        assert_eq!(
            dst_storage.read_bytes("content/files/ab/big.bin").unwrap(),
            expected_big_blob
        );
        assert_eq!(
            dst_storage.read_bytes("content/files/ef/avatar.png").unwrap(),
            b"AVATAR"
        );
        assert!(!dst_storage.exists("content/files/cd/gone.bin").unwrap());

        let dst_cfg = fs::read_to_string(&dst_paths.config_path).unwrap();
        assert!(dst_cfg.contains("# preserved comment header"));
        assert!(dst_cfg.contains("# preserved pepper comment"));
        assert!(dst_cfg.contains("src-pepper-secret"));
        assert!(dst_cfg.contains("src-server-secret"));
        assert!(dst_paths.server_root.join("init").is_file());

        dst_pool.close().await;
    }

    #[tokio::test]
    async fn partial_export_resolves_dependencies_and_preserves_target_config_when_excluded() {
        let tmp = TempDir::new().unwrap();
        let src_ws = create_test_workspace(
            &tmp.path().join("src_ws"),
            "app.db",
            "local",
            "src-pepper",
            "src-secret",
        );
        seed_source_database(&src_ws).await;

        let archive_path = tmp.path().join("partial.confbak");
        let key_path = tmp.path().join("partial.key");

        // Request ONLY `documents`; `accounts` must be auto-added, while `audit`, `banned_subnets`, `configuration` omitted.
        export::run_export(
            &test_ctx(&src_ws),
            BackupExportArgs {
                output_path: Some(archive_path.clone()),
                key_out: Some(key_path.clone()),
                components: vec![BackupComponentArg::Documents],
                interactive: false,
            },
        )
        .await
        .unwrap();

        let header = read_backup_header(&archive_path).unwrap();
        assert_eq!(header.components, vec!["accounts", "documents"]);

        // Pre-initialized empty target database (with all tables created and empty)
        let dst_ws = create_test_workspace(
            &tmp.path().join("dst_ws"),
            "preinit.db",
            "local",
            "keep-pepper",
            "keep-secret",
        );
        let pre_pool = open_sqlite_pool(&dst_ws).await;
        create_head_schema(&pre_pool, true).await.unwrap();
        set_alembic_version(&pre_pool, LATEST_SCHEMA_REVISION)
            .await
            .unwrap();
        pre_pool.close().await;

        import::run_import(
            &test_ctx(&dst_ws),
            BackupImportArgs {
                backup_path: archive_path,
                key: None,
                key_file: Some(key_path),
            },
        )
        .await
        .unwrap();

        let dst_pool = open_sqlite_pool(&dst_ws).await;
        let DbPool::Sqlite(ref dp) = dst_pool else {
            unreachable!();
        };
        let audit_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_entries")
            .fetch_one(dp)
            .await
            .unwrap();
        let ban_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM banned_subnets")
            .fetch_one(dp)
            .await
            .unwrap();
        let comment_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM comments")
            .fetch_one(dp)
            .await
            .unwrap();
        assert_eq!(audit_cnt, 0);
        assert_eq!(ban_cnt, 0);
        assert_eq!(comment_cnt, 1, "only account status comment c-user should be exported");
        dst_pool.close().await;

        let dst_cfg = fs::read_to_string(dst_ws.join("src").join("config.toml")).unwrap();
        assert!(dst_cfg.contains("keep-pepper"));
        assert!(!dst_cfg.contains("src-pepper"));
    }

    #[tokio::test]
    async fn corrupted_archive_or_storage_collision_rolls_back_all_resources() {
        let tmp = TempDir::new().unwrap();
        let src_ws = create_test_workspace(
            &tmp.path().join("src_ws"),
            "app.db",
            "local",
            "src-pepper",
            "src-secret",
        );
        seed_source_database(&src_ws).await;

        let archive_path = tmp.path().join("good.confbak");
        let key_path = tmp.path().join("good.key");
        export::run_export(
            &test_ctx(&src_ws),
            BackupExportArgs {
                output_path: Some(archive_path.clone()),
                key_out: Some(key_path.clone()),
                components: vec![],
                interactive: false,
            },
        )
        .await
        .unwrap();

        // 1. Corrupt last byte of encrypted file -> verify & import into blank DB must fail and leave 0 tables + 0 storage files + intact config
        let corrupt_path = tmp.path().join("corrupt.confbak");
        let mut bytes = fs::read(&archive_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x5A;
        fs::write(&corrupt_path, &bytes).unwrap();

        assert!(
            verify::run_verify(
                &test_ctx(&src_ws),
                BackupVerifyArgs {
                    backup_path: corrupt_path.clone(),
                    key: None,
                    key_file: Some(key_path.clone()),
                }
            )
            .await
            .is_err()
        );

        let dst_blank = create_test_workspace(
            &tmp.path().join("dst_blank"),
            "blank.db",
            "local",
            "orig-pepper",
            "orig-secret",
        );
        let err = import::run_import(
            &test_ctx(&dst_blank),
            BackupImportArgs {
                backup_path: corrupt_path,
                key: None,
                key_file: Some(key_path.clone()),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));

        let blank_pool = open_sqlite_pool(&dst_blank).await;
        let report = SchemaInspector::inspect_against_ir(&blank_pool, &builtin_schema_ir(false))
            .await
            .unwrap();
        assert!(
            report.is_empty_database,
            "blank target database must remain completely empty after rollback"
        );
        blank_pool.close().await;
        assert!(!dst_blank.join("src").join("content").exists());
        assert!(!dst_blank.join("src").join("init").exists());

        // 2. Append unauthenticated trailing byte -> verify must reject
        let trailing_path = tmp.path().join("trailing.confbak");
        let mut tbytes = fs::read(&archive_path).unwrap();
        tbytes.push(0x99);
        fs::write(&trailing_path, &tbytes).unwrap();
        assert!(
            verify::run_verify(
                &test_ctx(&src_ws),
                BackupVerifyArgs {
                    backup_path: trailing_path,
                    key: None,
                    key_file: Some(key_path.clone()),
                }
            )
            .await
            .is_err()
        );

        // 3. Pre-existing storage object collision -> blank target initialized for transaction must roll back cleanly
        let dst_collide = create_test_workspace(
            &tmp.path().join("dst_collide"),
            "collide.db",
            "local",
            "orig-pepper",
            "orig-secret",
        );
        let collide_file = dst_collide
            .join("src")
            .join("content")
            .join("files")
            .join("ef")
            .join("avatar.png");
        fs::create_dir_all(collide_file.parent().unwrap()).unwrap();
        fs::write(&collide_file, b"EXISTING").unwrap();

        let collide_err = import::run_import(
            &test_ctx(&dst_collide),
            BackupImportArgs {
                backup_path: archive_path.clone(),
                key: None,
                key_file: Some(key_path.clone()),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(collide_err, CfmsError::ArchiveIntegrity(_)));
        assert_eq!(fs::read(&collide_file).unwrap(), b"EXISTING");
        let cp = open_sqlite_pool(&dst_collide).await;
        assert!(
            SchemaInspector::inspect_against_ir(&cp, &builtin_schema_ir(false))
                .await
                .unwrap()
                .is_empty_database
        );
        cp.close().await;

        // 4. Non-empty target database must be refused
        let err_nonempty = import::run_import(
            &test_ctx(&src_ws),
            BackupImportArgs {
                backup_path: archive_path,
                key: None,
                key_file: Some(key_path),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_nonempty, CfmsError::Backup(_)));
    }

    #[tokio::test]
    async fn s3_storage_and_existing_key_out_are_rejected_without_orphans() {
        let tmp = TempDir::new().unwrap();
        let s3_ws = create_test_workspace(
            &tmp.path().join("s3_ws"),
            "app.db",
            "s3",
            "p",
            "s",
        );
        let p = open_sqlite_pool(&s3_ws).await;
        create_head_schema(&p, false).await.unwrap();
        p.close().await;

        let out = tmp.path().join("should_not_exist.confbak");
        let err = export::run_export(
            &test_ctx(&s3_ws),
            BackupExportArgs {
                output_path: Some(out.clone()),
                key_out: None,
                components: vec![],
                interactive: false,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CfmsError::Config(_)));
        assert!(!out.exists());

        // Existing `--key-out` file must fail preflight cleanly
        let local_ws = create_test_workspace(
            &tmp.path().join("local_ws"),
            "app.db",
            "local",
            "p",
            "s",
        );
        let lp = open_sqlite_pool(&local_ws).await;
        create_head_schema(&lp, false).await.unwrap();
        lp.close().await;

        let existing_key = tmp.path().join("existing.key");
        let mut f = fs::File::create(&existing_key).unwrap();
        writeln!(f, "DO NOT OVERWRITE").unwrap();

        let key_err = export::run_export(
            &test_ctx(&local_ws),
            BackupExportArgs {
                output_path: Some(out.clone()),
                key_out: Some(existing_key.clone()),
                components: vec![],
                interactive: false,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(key_err, CfmsError::Backup(_)));
        assert!(!out.exists());
        assert_eq!(fs::read_to_string(&existing_key).unwrap(), "DO NOT OVERWRITE\n");
    }
}
