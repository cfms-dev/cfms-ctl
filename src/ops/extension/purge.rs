//! Transactional extension database purge (`--purge-data`) combining static AST hook
//! inspection, isolated Python `ext_purge_data` execution when present, and multi-backend
//! SQLx deletion of `options` / `system_states` with `audit_entries` recording.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ruff_python_ast::{self as ast, Stmt};
use ruff_python_parser::parse_module;
use serde::Serialize;
use serde_json::json;
use tokio::process::Command;
use uuid::Uuid;

use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::backend::DbPool;
use crate::db::schema::probe::discover_python_candidates;
use crate::ops::extension::catalog::symlink_stat_if_present;

const PYTHON_HOOK_TIMEOUT: Duration = Duration::from_secs(60);

/// Preview metadata returned for `--uninstall --purge-data --dry-run`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionPurgeSummary {
    pub option_entries_deleted: u64,
    pub state_entries_deleted: u64,
    pub python_hook_detected: bool,
    pub python_hook_executed: bool,
    pub audit_logged: bool,
}

/// Statically inspect `_extension.py` via `ruff_python_parser` to determine whether
/// it defines a module-level function or class method named `ext_purge_data`.
pub fn detect_ext_purge_data_hook(
    entrypoint: &Path,
    data_module: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<bool> {
    let meta = match symlink_stat_if_present(entrypoint)? {
        Some(m) if m.is_file() => m,
        _ => {
            if let Some(mod_name) = data_module {
                warnings.push(format!(
                    "Extension declares [data] module '{mod_name}' but '{}' is missing; custom extension tables could not be inspected or purged",
                    entrypoint.display()
                ));
            }
            return Ok(false);
        }
    };

    if meta.len() > 2 * 1024 * 1024 {
        return Err(CfmsError::Extension(format!(
            "Extension entrypoint '{}' exceeds 2 MiB AST analysis limit",
            entrypoint.display()
        )));
    }

    let source = std::fs::read_to_string(entrypoint)?;
    let parsed = match parse_module(&source) {
        Ok(module) => module,
        Err(err) => {
            warnings.push(format!(
                "Could not statically parse '{}' ({err}); custom ext_purge_data hooks were not executed",
                entrypoint.display()
            ));
            return Ok(false);
        }
    };

    let has_hook = contains_ext_purge_data(&parsed.syntax().body);
    if !has_hook && let Some(mod_name) = data_module {
        warnings.push(format!(
            "Extension declares [data] module '{mod_name}' without an `ext_purge_data` hook in '{}'; only options and system states will be purged",
            entrypoint.display()
        ));
    }
    Ok(has_hook)
}

fn contains_ext_purge_data(stmts: &[Stmt]) -> bool {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(ast::StmtFunctionDef { name, .. })
                if name.as_str() == "ext_purge_data" =>
            {
                return true;
            }
            Stmt::ClassDef(ast::StmtClassDef { body, .. }) if contains_ext_purge_data(body) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Preview the number of `options` and `system_states` rows owned by `identifier`
/// without mutating the database.
pub async fn preview_extension_purge(
    pool: &DbPool,
    identifier: &str,
    entrypoint: &Path,
    data_module: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<ExtensionPurgeSummary> {
    let has_hook = detect_ext_purge_data_hook(entrypoint, data_module, warnings)?;
    let (option_count, state_count) = count_owner_rows(pool, identifier).await?;

    Ok(ExtensionPurgeSummary {
        option_entries_deleted: option_count,
        state_entries_deleted: state_count,
        python_hook_detected: has_hook,
        python_hook_executed: false,
        audit_logged: false,
    })
}

/// Execute `ext_purge_data` (when declared in `_extension.py`), delete `options` and
/// `system_states` owned by `identifier`, and log `purge_extension_data` into `audit_entries`.
pub async fn execute_extension_purge(
    paths: &WorkspacePaths,
    db_cfg: &crate::core::config::DatabaseSectionConfig,
    identifier: &str,
    entrypoint: &Path,
    data_module: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<ExtensionPurgeSummary> {
    let has_hook = detect_ext_purge_data_hook(entrypoint, data_module, warnings)?;
    if has_hook {
        run_python_purge_hook(paths, identifier).await?;
    }

    let pool = DbPool::connect(db_cfg, paths).await?;
    let res = delete_owner_rows_and_audit(&pool, identifier, has_hook).await;
    pool.close().await;
    res
}

async fn count_owner_rows(pool: &DbPool, identifier: &str) -> Result<(u64, u64)> {
    match pool {
        DbPool::Sqlite(p) => {
            let opt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM options WHERE owner = ?")
                .bind(identifier)
                .fetch_one(p)
                .await?;
            let state: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM system_states WHERE owner = ?")
                    .bind(identifier)
                    .fetch_one(p)
                    .await?;
            Ok((u64::try_from(opt).unwrap_or(0), u64::try_from(state).unwrap_or(0)))
        }
        DbPool::Mysql(p) => {
            let opt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM options WHERE owner = ?")
                .bind(identifier)
                .fetch_one(p)
                .await?;
            let state: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM system_states WHERE owner = ?")
                    .bind(identifier)
                    .fetch_one(p)
                    .await?;
            Ok((u64::try_from(opt).unwrap_or(0), u64::try_from(state).unwrap_or(0)))
        }
        DbPool::Postgres(p) => {
            let opt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM options WHERE owner = $1")
                .bind(identifier)
                .fetch_one(p)
                .await?;
            let state: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM system_states WHERE owner = $1")
                    .bind(identifier)
                    .fetch_one(p)
                    .await?;
            Ok((u64::try_from(opt).unwrap_or(0), u64::try_from(state).unwrap_or(0)))
        }
    }
}

async fn delete_owner_rows_and_audit(
    pool: &DbPool,
    identifier: &str,
    python_hook_executed: bool,
) -> Result<ExtensionPurgeSummary> {
    let audit_id = Uuid::new_v4().simple().to_string();
    let logged_time = now_unix_seconds();

    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            let opt_del = sqlx::query("DELETE FROM options WHERE owner = ?")
                .bind(identifier)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let state_del = sqlx::query("DELETE FROM system_states WHERE owner = ?")
                .bind(identifier)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let audit_data = build_audit_payload(opt_del, state_del, python_hook_executed);
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'purge_extension_data', NULL, ?, ?, 0, NULL, ?)",
            )
            .bind(&audit_id)
            .bind(identifier)
            .bind(&audit_data)
            .bind(logged_time)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(ExtensionPurgeSummary {
                option_entries_deleted: opt_del,
                state_entries_deleted: state_del,
                python_hook_detected: python_hook_executed,
                python_hook_executed,
                audit_logged: true,
            })
        }
        DbPool::Mysql(p) => {
            let mut tx = p.begin().await?;
            let opt_del = sqlx::query("DELETE FROM options WHERE owner = ?")
                .bind(identifier)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let state_del = sqlx::query("DELETE FROM system_states WHERE owner = ?")
                .bind(identifier)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let audit_data = build_audit_payload(opt_del, state_del, python_hook_executed);
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'purge_extension_data', NULL, ?, ?, 0, NULL, ?)",
            )
            .bind(&audit_id)
            .bind(identifier)
            .bind(&audit_data)
            .bind(logged_time)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(ExtensionPurgeSummary {
                option_entries_deleted: opt_del,
                state_entries_deleted: state_del,
                python_hook_detected: python_hook_executed,
                python_hook_executed,
                audit_logged: true,
            })
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            let opt_del = sqlx::query("DELETE FROM options WHERE owner = $1")
                .bind(identifier)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let state_del = sqlx::query("DELETE FROM system_states WHERE owner = $1")
                .bind(identifier)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let audit_data = build_audit_payload(opt_del, state_del, python_hook_executed);
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES ($1, 'purge_extension_data', NULL, $2, $3::json, 0, NULL, $4)",
            )
            .bind(&audit_id)
            .bind(identifier)
            .bind(&audit_data)
            .bind(logged_time)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(ExtensionPurgeSummary {
                option_entries_deleted: opt_del,
                state_entries_deleted: state_del,
                python_hook_detected: python_hook_executed,
                python_hook_executed,
                audit_logged: true,
            })
        }
    }
}

fn build_audit_payload(opt_del: u64, state_del: u64, python_hook_executed: bool) -> String {
    json!({
        "options_only": false,
        "option_entries": opt_del,
        "state_entries": state_del,
        "python_hook_executed": python_hook_executed,
    })
    .to_string()
}

fn now_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

const PYTHON_PURGE_RUNNER: &str = r#"
import sys
from pathlib import Path

server_root = Path(sys.argv[1]).resolve()
config_path = Path(sys.argv[2]).resolve()
ext_id = sys.argv[3]

if str(server_root) not in sys.path:
    sys.path.insert(0, str(server_root))

from include.config import settings
if settings.global_config._config_path.resolve() != config_path:
    settings.global_config._config_path = config_path
    settings.global_config._load()

from include.database.session import Session
from include.extensions import manager as ext_mgr

with ext_mgr.maintenance_extension_context(ext_id):
    with Session() as session:
        with session.begin():
            ext_mgr.purge_extension_data(ext_id, session)
"#;

async fn run_python_purge_hook(paths: &WorkspacePaths, identifier: &str) -> Result<()> {
    let candidates = discover_python_candidates(paths);
    if candidates.is_empty() {
        return Err(CfmsError::Extension(format!(
            "Extension '{identifier}' defines an `ext_purge_data` hook, but no Python runtime was found; set CFMS_PYTHON or omit --purge-data"
        )));
    }

    let mut errors = Vec::new();
    for candidate in candidates {
        let mut cmd = Command::new(&candidate.program);
        cmd.args(&candidate.prefix_args)
            .arg("-c")
            .arg(PYTHON_PURGE_RUNNER)
            .arg(&paths.server_root)
            .arg(&paths.config_path)
            .arg(identifier)
            .current_dir(&paths.server_root)
            .env("PYTHONPATH", &paths.server_root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONUTF8", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                errors.push(format!("{}: spawn failed ({err})", candidate.description));
                continue;
            }
        };

        let output = match tokio::time::timeout(PYTHON_HOOK_TIMEOUT, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(err)) => {
                errors.push(format!("{}: wait failed ({err})", candidate.description));
                continue;
            }
            Err(_) => {
                return Err(CfmsError::Extension(format!(
                    "Timed out executing ext_purge_data hook for '{identifier}' via {}",
                    candidate.description
                )));
            }
        };

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("exit status {}", output.status)
        } else {
            stderr
        };
        errors.push(format!("{}: {detail}", candidate.description));
    }

    Err(CfmsError::Extension(format!(
        "Failed to execute `ext_purge_data` hook for '{identifier}' ({})",
        errors.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ConfigDocument;
    use crate::db::schema::ddl::create_head_schema;
    use sqlx::Row;

    #[test]
    fn ast_detects_module_and_class_purge_hooks() {
        let dir = tempfile::tempdir().expect("tempdir");

        let plain = dir.path().join("plain.py");
        std::fs::write(&plain, "def ext_on_startup():\n    pass\n").expect("write plain");
        let mut w = Vec::new();
        assert!(!detect_ext_purge_data_hook(&plain, None, &mut w).expect("ast plain"));
        assert!(w.is_empty());

        let class_hook = dir.path().join("class_hook.py");
        std::fs::write(
            &class_hook,
            "class Plugin:\n    def ext_purge_data(self, session):\n        pass\n",
        )
        .expect("write class_hook");
        assert!(detect_ext_purge_data_hook(&class_hook, Some("ext.data"), &mut w).expect("ast class"));

        let top_hook = dir.path().join("top_hook.py");
        std::fs::write(
            &top_hook,
            "async def ext_purge_data(session):\n    pass\n",
        )
        .expect("write top_hook");
        assert!(detect_ext_purge_data_hook(&top_hook, None, &mut w).expect("ast top"));

        let missing = dir.path().join("missing.py");
        assert!(!detect_ext_purge_data_hook(&missing, Some("ext.data"), &mut w).expect("missing"));
        assert_eq!(w.len(), 1);
    }

    #[tokio::test]
    async fn execute_purge_deletes_owner_rows_and_writes_audit_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            src.join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n",
        )
        .expect("config");
        let entrypoint = src.join("_extension.py");
        std::fs::write(&entrypoint, "def ext_init():\n    pass\n").expect("entry");

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let db_cfg = ConfigDocument::load(&paths.config_path)
            .expect("load config")
            .database_config()
            .expect("db config");

        let pool = DbPool::connect(&db_cfg, &paths).await.expect("connect sqlite");
        create_head_schema(&pool, false).await.expect("create schema");
        let DbPool::Sqlite(ref sp) = pool else {
            panic!("expected sqlite pool");
        };
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES (?, ?, ?, 1, 1, 'str', '\"val\"', 1.0)",
        )
        .bind("ext.sample")
        .bind("sample_ext")
        .bind("k1")
        .execute(sp)
        .await
        .expect("insert ext opt");
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES (?, ?, ?, 1, 1, 'str', '\"keep\"', 1.0)",
        )
        .bind("core.other")
        .bind("builtin")
        .bind("k2")
        .execute(sp)
        .await
        .expect("insert core opt");
        sqlx::query(
            "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES (?, 's1', 1, 1, '{}', 1.0)",
        )
        .bind("sample_ext")
        .execute(sp)
        .await
        .expect("insert ext state");

        let mut warnings = Vec::new();
        let preview = preview_extension_purge(&pool, "sample_ext", &entrypoint, None, &mut warnings)
            .await
            .expect("preview purge");
        assert_eq!(preview.option_entries_deleted, 1);
        assert_eq!(preview.state_entries_deleted, 1);
        assert!(!preview.python_hook_detected);
        pool.close().await;

        let summary = execute_extension_purge(
            &paths,
            &db_cfg,
            "sample_ext",
            &entrypoint,
            None,
            &mut warnings,
        )
        .await
        .expect("execute purge");
        assert_eq!(summary.option_entries_deleted, 1);
        assert_eq!(summary.state_entries_deleted, 1);
        assert!(!summary.python_hook_executed);
        assert!(summary.audit_logged);

        let verify_pool = DbPool::connect(&db_cfg, &paths).await.expect("reconnect");
        let DbPool::Sqlite(ref sp2) = verify_pool else {
            panic!("expected sqlite");
        };
        let remaining_opts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM options")
            .fetch_one(sp2)
            .await
            .expect("count options");
        assert_eq!(remaining_opts, 1);
        let remaining_states: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM system_states")
            .fetch_one(sp2)
            .await
            .expect("count states");
        assert_eq!(remaining_states, 0);
        let row = sqlx::query("SELECT action, target, result, data FROM audit_entries")
            .fetch_one(sp2)
            .await
            .expect("audit row");
        assert_eq!(row.get::<String, _>("action"), "purge_extension_data");
        assert_eq!(row.get::<String, _>("target"), "sample_ext");
        assert_eq!(row.get::<i64, _>("result"), 0);
        assert!(row.get::<String, _>("data").contains("\"option_entries\":1"));
        verify_pool.close().await;
    }
}
