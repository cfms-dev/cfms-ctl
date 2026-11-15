//! Transactional extension database purge combining static AST hook & `[data]` table
//! inspection, fault-isolated single-transaction Python `ext_purge_data` execution when
//! present, and multi-backend SQLx deletion of declared extension tables, `options`, and
//! `system_states` with `audit_entries` recording.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use regex::Regex;
use ruff_python_ast::{self as ast, Expr, Stmt};
use ruff_python_parser::parse_module;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{MySql, Postgres, Sqlite, Transaction};
use tokio::process::Command;
use uuid::Uuid;

use crate::core::config::DatabaseSectionConfig;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::graph::plan_table_subset;
use crate::db::schema::ir::{TableIr, TableOwnership};
use crate::db::schema::live_ir::introspect_live_schema_ir;
use crate::db::schema::probe::discover_python_candidates;
use crate::db::schema::static_ast::extract_static_schema_ir;
use crate::db::schema::{APPLICATION_TABLE_NAMES, KNOWN_EXTENSION_TABLES};
use crate::db::transfer::{placeholder, quote_ident};
use crate::ops::extension::catalog::symlink_stat_if_present;
use crate::ops::extension::planner::ExtensionLoadEntry;

const PYTHON_HOOK_TIMEOUT: Duration = Duration::from_secs(60);
const REQUIRED_PURGE_TABLES: &[&str] = &["options", "system_states", "audit_entries"];
const PYTHON_RESULT_PREFIX: &str = "__CFMS_PURGE_RESULT__:";

/// Preview or execution summary returned for extension data purge operations.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionPurgeSummary {
    pub options_only: bool,
    pub option_entries_deleted: u64,
    pub state_entries_deleted: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_table_rows: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub option_namespaces: Vec<String>,
    pub python_hook_detected: bool,
    pub python_hook_executed: bool,
    pub audit_logged: bool,
}

/// Target metadata supplied to [`preview_extension_purge`] and [`execute_extension_purge`].
#[derive(Debug, Clone)]
pub struct PurgeTargetSpec<'a> {
    pub identifier: &'a str,
    pub options_only: bool,
    pub target_directory: Option<&'a Path>,
    pub entrypoint: Option<&'a Path>,
    pub data_module: Option<&'a str>,
    pub manifest_namespaces: &'a [String],
    pub load_closure: &'a [ExtensionLoadEntry],
    pub dependency_error: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
struct DeclaredDataDiscovery {
    ordered_tables: Vec<String>,
    needs_python_data_discovery: bool,
}

enum PurgeTx {
    Sqlite(Transaction<'static, Sqlite>),
    Mysql(Transaction<'static, MySql>),
    Postgres(Transaction<'static, Postgres>),
}

impl PurgeTx {
    async fn begin(pool: &DbPool) -> Result<Self> {
        match pool {
            DbPool::Sqlite(p) => Ok(Self::Sqlite(p.begin_with("BEGIN IMMEDIATE").await?)),
            DbPool::Mysql(p) => Ok(Self::Mysql(p.begin().await?)),
            DbPool::Postgres(p) => Ok(Self::Postgres(p.begin().await?)),
        }
    }

    const fn kind(&self) -> DatabaseKind {
        match self {
            Self::Sqlite(_) => DatabaseKind::Sqlite,
            Self::Mysql(_) => DatabaseKind::Mysql,
            Self::Postgres(_) => DatabaseKind::Postgresql,
        }
    }

    async fn execute_delete_all(&mut self, table: &str) -> Result<u64> {
        let sql = format!("DELETE FROM {}", quote_ident(self.kind(), table));
        let affected = match self {
            Self::Sqlite(tx) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut **tx)
                .await?
                .rows_affected(),
            Self::Mysql(tx) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut **tx)
                .await?
                .rows_affected(),
            Self::Postgres(tx) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&mut **tx)
                .await?
                .rows_affected(),
        };
        Ok(affected)
    }

    async fn execute_delete_by_owner(&mut self, table: &str, owner: &str) -> Result<u64> {
        let kind = self.kind();
        let sql = format!(
            "DELETE FROM {} WHERE owner = {}",
            quote_ident(kind, table),
            placeholder(kind, 1)
        );
        let affected = match self {
            Self::Sqlite(tx) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .execute(&mut **tx)
                .await?
                .rows_affected(),
            Self::Mysql(tx) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .execute(&mut **tx)
                .await?
                .rows_affected(),
            Self::Postgres(tx) => sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .execute(&mut **tx)
                .await?
                .rows_affected(),
        };
        Ok(affected)
    }

    async fn fetch_owner_namespaces(&mut self, owner: &str) -> Result<Vec<String>> {
        let kind = self.kind();
        let sql = format!(
            "SELECT DISTINCT namespace FROM options WHERE owner = {} ORDER BY namespace",
            placeholder(kind, 1)
        );
        let rows: Vec<String> = match self {
            Self::Sqlite(tx) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .fetch_all(&mut **tx)
                .await?,
            Self::Mysql(tx) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .fetch_all(&mut **tx)
                .await?,
            Self::Postgres(tx) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .fetch_all(&mut **tx)
                .await?,
        };
        Ok(rows)
    }

    async fn insert_purge_audit(
        &mut self,
        audit_id: &str,
        identifier: &str,
        audit_data: &str,
        logged_time: f64,
    ) -> Result<()> {
        match self {
            Self::Sqlite(tx) => {
                sqlx::query(
                    "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'purge_extension_data', NULL, ?, ?, 0, NULL, ?)",
                )
                .bind(audit_id)
                .bind(identifier)
                .bind(audit_data)
                .bind(logged_time)
                .execute(&mut **tx)
                .await?;
            }
            Self::Mysql(tx) => {
                sqlx::query(
                    "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'purge_extension_data', NULL, ?, ?, 0, NULL, ?)",
                )
                .bind(audit_id)
                .bind(identifier)
                .bind(audit_data)
                .bind(logged_time)
                .execute(&mut **tx)
                .await?;
            }
            Self::Postgres(tx) => {
                sqlx::query(
                    "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES ($1, 'purge_extension_data', NULL, $2, $3::json, 0, NULL, $4)",
                )
                .bind(audit_id)
                .bind(identifier)
                .bind(audit_data)
                .bind(logged_time)
                .execute(&mut **tx)
                .await?;
            }
        }
        Ok(())
    }

    async fn commit(self) -> Result<()> {
        match self {
            Self::Sqlite(tx) => tx.commit().await?,
            Self::Mysql(tx) => tx.commit().await?,
            Self::Postgres(tx) => tx.commit().await?,
        }
        Ok(())
    }
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
    let _ = data_module;
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

/// Verify that required purge tables (`options`, `system_states`, `audit_entries`) exist
/// and return the live table inventory.
pub async fn preflight_purge_schema(pool: &DbPool) -> Result<BTreeSet<String>> {
    let live_tables: BTreeSet<String> = pool.list_tables().await?.into_iter().collect();
    let missing: Vec<&str> = REQUIRED_PURGE_TABLES
        .iter()
        .copied()
        .filter(|tbl| !live_tables.contains(*tbl))
        .collect();
    if !missing.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database is missing required purge tables ({}); run `cfms-ctl database upgrade` first",
            missing.join(", ")
        )));
    }
    Ok(live_tables)
}

struct ResolvedPurgeDiscovery {
    has_hook: bool,
    live_ext_tables: Vec<String>,
    needs_python_data_discovery: bool,
}

async fn resolve_purge_discovery(
    paths: &WorkspacePaths,
    pool: &DbPool,
    target: &PurgeTargetSpec<'_>,
    live_tables: &BTreeSet<String>,
    warnings: &mut Vec<String>,
    emit_dynamic_preview_warning: bool,
) -> Result<ResolvedPurgeDiscovery> {
    if target.options_only {
        return Ok(ResolvedPurgeDiscovery {
            has_hook: false,
            live_ext_tables: Vec::new(),
            needs_python_data_discovery: false,
        });
    }

    let has_hook = match target.entrypoint {
        Some(entry) => detect_ext_purge_data_hook(entry, target.data_module, warnings)?,
        None => false,
    };

    let mut data_discovery = discover_declared_data_tables(paths, target, pool.kind(), warnings);
    if target.data_module.is_some() && data_discovery.ordered_tables.is_empty() {
        data_discovery.needs_python_data_discovery = true;
        if emit_dynamic_preview_warning
            && let Some(mod_name) = target.data_module
        {
            warnings.push(format!(
                "Could not statically resolve custom [data] tables for module '{mod_name}'; table cleanup will resolve `register_data()` via Python on apply"
            ));
        }
    }

    let candidate_live: Vec<String> = data_discovery
        .ordered_tables
        .into_iter()
        .filter(|tbl| live_tables.contains(tbl))
        .collect();
    let live_ext_tables = if candidate_live.len() > 1 {
        order_live_extension_tables_by_fk(pool, &candidate_live).await
    } else {
        candidate_live
    };

    Ok(ResolvedPurgeDiscovery {
        has_hook,
        live_ext_tables,
        needs_python_data_discovery: data_discovery.needs_python_data_discovery,
    })
}

async fn order_live_extension_tables_by_fk(pool: &DbPool, tables: &[String]) -> Vec<String> {
    let table_set: BTreeSet<&str> = tables.iter().map(String::as_str).collect();
    let Ok(live_ir) = introspect_live_schema_ir(pool, true, None).await else {
        return tables.to_vec();
    };
    let subset: BTreeMap<String, TableIr> = live_ir
        .tables
        .into_iter()
        .filter(|(name, _)| table_set.contains(name.as_str()))
        .collect();
    if subset.len() <= 1 {
        return tables.to_vec();
    }

    let mut ordered = plan_table_subset(&subset, pool.kind()).drop_order;
    for name in tables {
        if !ordered.contains(name) {
            ordered.push(name.clone());
        }
    }
    ordered
}

/// Preview the number of `options`, `system_states`, and declared extension `[data]` rows
/// owned by `target.identifier` without acquiring runtime locks, importing extension code, or mutating the database.
pub async fn preview_extension_purge(
    paths: &WorkspacePaths,
    pool: &DbPool,
    target: &PurgeTargetSpec<'_>,
    warnings: &mut Vec<String>,
) -> Result<ExtensionPurgeSummary> {
    let live_tables = preflight_purge_schema(pool).await?;
    let resolved = resolve_purge_discovery(paths, pool, target, &live_tables, warnings, true).await?;

    let option_count = count_owner_rows(pool, "options", target.identifier).await?;
    let state_count = count_owner_rows(pool, "system_states", target.identifier).await?;
    let mut extension_table_rows = BTreeMap::new();
    for table in &resolved.live_ext_tables {
        let count = count_all_rows(pool, table).await?;
        extension_table_rows.insert(table.clone(), count);
    }

    let db_namespaces = fetch_owner_option_namespaces(pool, target.identifier).await?;
    let option_namespaces = merge_namespaces(target.manifest_namespaces, &db_namespaces);

    if resolved.has_hook {
        warnings.push(format!(
            "Extension '{}' defines an `ext_purge_data` hook; additional row deletions performed inside that hook are determined only during execution",
            target.identifier
        ));
    }

    Ok(ExtensionPurgeSummary {
        options_only: target.options_only,
        option_entries_deleted: option_count,
        state_entries_deleted: state_count,
        extension_table_rows,
        option_namespaces,
        python_hook_detected: resolved.has_hook,
        python_hook_executed: false,
        audit_logged: false,
    })
}

/// Atomically purge database state owned by `target.identifier` in a single transaction
/// (`ext_purge_data` hook when declared, declared `[data]` tables in reverse FK order,
/// `options`, `system_states`, and `audit_entries`).
pub async fn execute_extension_purge(
    paths: &WorkspacePaths,
    db_cfg: &DatabaseSectionConfig,
    target: &PurgeTargetSpec<'_>,
    warnings: &mut Vec<String>,
) -> Result<ExtensionPurgeSummary> {
    let pool = DbPool::connect(db_cfg, paths).await?;
    let resolved = match preflight_purge_schema(&pool).await {
        Ok(live_tables) => {
            match resolve_purge_discovery(paths, &pool, target, &live_tables, warnings, false).await {
                Ok(r) => r,
                Err(err) => {
                    pool.close().await;
                    return Err(err);
                }
            }
        }
        Err(err) => {
            pool.close().await;
            return Err(err);
        }
    };

    let needs_python =
        !target.options_only && (resolved.has_hook || resolved.needs_python_data_discovery);

    if needs_python {
        if let Some(dep_err) = target.dependency_error {
            pool.close().await;
            return Err(CfmsError::Extension(format!(
                "Cannot execute Python cleanup for '{}' because its dependency closure failed to resolve ({dep_err}); repair dependencies or pass --options-only",
                target.identifier
            )));
        }

        // Release Rust DB handles cleanly before handing the single transaction to Python.
        pool.close().await;
        return run_python_atomic_purge(
            paths,
            target,
            resolved.has_hook,
            &resolved.live_ext_tables,
            warnings,
        )
        .await;
    }

    let res = execute_rust_purge_tx(
        &pool,
        target.identifier,
        target.options_only,
        resolved.has_hook,
        &resolved.live_ext_tables,
        target.manifest_namespaces,
    )
    .await;
    pool.close().await;
    res
}

async fn count_owner_rows(pool: &DbPool, table: &str, owner: &str) -> Result<u64> {
    let kind = pool.kind();
    let sql = format!(
        "SELECT COUNT(*) FROM {} WHERE owner = {}",
        quote_ident(kind, table),
        placeholder(kind, 1)
    );
    let cnt: i64 = match pool {
        DbPool::Sqlite(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .fetch_one(p)
            .await?,
        DbPool::Mysql(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .fetch_one(p)
            .await?,
        DbPool::Postgres(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .fetch_one(p)
            .await?,
    };
    Ok(u64::try_from(cnt).unwrap_or(0))
}

async fn count_all_rows(pool: &DbPool, table: &str) -> Result<u64> {
    let sql = format!("SELECT COUNT(*) FROM {}", quote_ident(pool.kind(), table));
    let cnt: i64 = match pool {
        DbPool::Sqlite(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(p)
            .await?,
        DbPool::Mysql(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(p)
            .await?,
        DbPool::Postgres(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(p)
            .await?,
    };
    Ok(u64::try_from(cnt).unwrap_or(0))
}

async fn fetch_owner_option_namespaces(pool: &DbPool, owner: &str) -> Result<Vec<String>> {
    let kind = pool.kind();
    let sql = format!(
        "SELECT DISTINCT namespace FROM options WHERE owner = {} ORDER BY namespace",
        placeholder(kind, 1)
    );
    let rows: Vec<String> = match pool {
        DbPool::Sqlite(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .fetch_all(p)
            .await?,
        DbPool::Mysql(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .fetch_all(p)
            .await?,
        DbPool::Postgres(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .fetch_all(p)
            .await?,
    };
    Ok(rows)
}

async fn execute_rust_purge_tx(
    pool: &DbPool,
    identifier: &str,
    options_only: bool,
    python_hook_detected: bool,
    live_ext_tables: &[String],
    manifest_namespaces: &[String],
) -> Result<ExtensionPurgeSummary> {
    let audit_id = Uuid::new_v4().simple().to_string();
    let logged_time = now_unix_seconds();

    let mut tx = PurgeTx::begin(pool).await?;
    let db_namespaces = tx.fetch_owner_namespaces(identifier).await?;
    let option_namespaces = merge_namespaces(manifest_namespaces, &db_namespaces);

    let mut extension_table_rows = BTreeMap::new();
    for table in live_ext_tables {
        let deleted = tx.execute_delete_all(table).await?;
        extension_table_rows.insert(table.clone(), deleted);
    }

    let opt_del = tx.execute_delete_by_owner("options", identifier).await?;
    let state_del = tx.execute_delete_by_owner("system_states", identifier).await?;
    let audit_data = build_audit_payload(
        identifier,
        options_only,
        opt_del,
        state_del,
        false,
        &extension_table_rows,
    );
    tx.insert_purge_audit(&audit_id, identifier, &audit_data, logged_time)
        .await?;
    tx.commit().await?;

    Ok(ExtensionPurgeSummary {
        options_only,
        option_entries_deleted: opt_del,
        state_entries_deleted: state_del,
        extension_table_rows,
        option_namespaces,
        python_hook_detected,
        python_hook_executed: false,
        audit_logged: true,
    })
}

fn build_audit_payload(
    identifier: &str,
    options_only: bool,
    opt_del: u64,
    state_del: u64,
    python_hook_executed: bool,
    extension_table_rows: &BTreeMap<String, u64>,
) -> String {
    let mut payload = json!({
        "owner": identifier,
        "options_only": options_only,
        "option_entries": opt_del,
        "state_entries": state_del,
        "python_hook_executed": python_hook_executed,
    });
    if !extension_table_rows.is_empty()
        && let Some(obj) = payload.as_object_mut()
    {
        obj.insert(
            "extension_tables".to_string(),
            json!(extension_table_rows),
        );
    }
    payload.to_string()
}

fn merge_namespaces(manifest_ns: &[String], db_ns: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for ns in manifest_ns.iter().chain(db_ns.iter()) {
        if !ns.trim().is_empty() {
            set.insert(ns.clone());
        }
    }
    set.into_iter().collect()
}

fn discover_declared_data_tables(
    paths: &WorkspacePaths,
    target: &PurgeTargetSpec<'_>,
    kind: DatabaseKind,
    warnings: &mut Vec<String>,
) -> DeclaredDataDiscovery {
    let Some(data_mod) = target.data_module else {
        return DeclaredDataDiscovery::default();
    };

    let mut owned_irs: BTreeMap<String, TableIr> = BTreeMap::new();
    let mut extra_table_names: BTreeSet<String> = BTreeSet::new();

    if let Ok(ir) = extract_static_schema_ir(paths, true) {
        let dir_owner = target
            .target_directory
            .and_then(|d| d.file_name())
            .and_then(|n| n.to_str());
        for (tbl_name, table_ir) in ir.tables {
            let matches_owner = match &table_ir.ownership {
                TableOwnership::Extension(owner) => {
                    owner == target.identifier || dir_owner == Some(owner.as_str())
                }
                TableOwnership::Core => false,
            };
            if matches_owner && is_safe_extension_table_name(&tbl_name, warnings) {
                owned_irs.insert(tbl_name, table_ir);
            }
        }
    }

    let mut scan_files: Vec<PathBuf> = Vec::new();
    if let Some(dir) = target.target_directory {
        collect_py_files_shallow_recursive(dir, &mut scan_files);
    }
    if let Some(data_path) = resolve_dotted_python_module(&paths.server_root, data_mod)
        && !scan_files.contains(&data_path)
    {
        scan_files.push(data_path);
    }

    for py_path in scan_files {
        let Ok(src) = std::fs::read_to_string(&py_path) else {
            continue;
        };
        let Ok(parsed) = parse_module(&src) else {
            continue;
        };
        collect_table_names_from_ast(&parsed.syntax().body, &mut extra_table_names, warnings);
    }

    let mut ordered_tables = Vec::new();
    if !owned_irs.is_empty() {
        let graph_plan = plan_table_subset(&owned_irs, kind);
        ordered_tables.extend(graph_plan.drop_order);
    }
    for name in extra_table_names {
        if !ordered_tables.contains(&name) {
            ordered_tables.push(name);
        }
    }

    // Known built-in extension table mapping fallback when manifest matches but ORM AST wasn't found.
    if ordered_tables.is_empty() && target.identifier == "oidc_sso" {
        for known in KNOWN_EXTENSION_TABLES {
            ordered_tables.push((*known).to_string());
        }
    }

    DeclaredDataDiscovery {
        ordered_tables,
        needs_python_data_discovery: false,
    }
}

fn is_safe_extension_table_name(name: &str, warnings: &mut Vec<String>) -> bool {
    static IDENT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = IDENT_RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid table identifier regex")
    });
    if !re.is_match(name) {
        return false;
    }
    if APPLICATION_TABLE_NAMES.contains(&name) || name == "alembic_version" {
        let msg = format!(
            "Ignoring protected core table name '{name}' referenced by extension source"
        );
        if !warnings.contains(&msg) {
            warnings.push(msg);
        }
        return false;
    }
    true
}

fn resolve_dotted_python_module(server_root: &Path, module_name: &str) -> Option<PathBuf> {
    let mut parts = Vec::new();
    for seg in module_name.split('.') {
        if seg.is_empty()
            || !seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return None;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        return None;
    }
    let mut file_candidate = server_root.to_path_buf();
    for seg in &parts[..parts.len() - 1] {
        file_candidate.push(seg);
    }
    let last = parts[parts.len() - 1];
    let py_file = file_candidate.join(format!("{last}.py"));
    if py_file.is_file() {
        return Some(py_file);
    }
    let init_file = file_candidate.join(last).join("__init__.py");
    if init_file.is_file() {
        return Some(init_file);
    }
    None
}

fn collect_py_files_shallow_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && (name.starts_with("__") || name.starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            collect_py_files_shallow_recursive(&path, out);
        } else if path.extension().is_some_and(|e| e == "py") {
            out.push(path);
        }
    }
}

fn collect_table_names_from_ast(
    stmts: &[Stmt],
    out: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::ClassDef(cls) => {
                for body_stmt in &cls.body {
                    match body_stmt {
                        Stmt::Assign(a) if a.targets.len() == 1 => {
                            if matches!(&a.targets[0], Expr::Name(n) if n.id.as_str() == "__tablename__")
                                && let Some(tbl) = eval_literal_string(&a.value)
                                && is_safe_extension_table_name(&tbl, warnings)
                            {
                                out.insert(tbl);
                            }
                        }
                        Stmt::AnnAssign(a) => {
                            if matches!(a.target.as_ref(), Expr::Name(n) if n.id.as_str() == "__tablename__")
                                && let Some(val) = &a.value
                                && let Some(tbl) = eval_literal_string(val)
                                && is_safe_extension_table_name(&tbl, warnings)
                            {
                                out.insert(tbl);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Stmt::Assign(a) => extract_table_calls_from_expr(&a.value, out, warnings),
            Stmt::AnnAssign(a) => {
                if let Some(v) = &a.value {
                    extract_table_calls_from_expr(v, out, warnings);
                }
            }
            Stmt::Return(r) => {
                if let Some(v) = &r.value {
                    extract_table_calls_from_expr(v, out, warnings);
                }
            }
            Stmt::Expr(e) => extract_table_calls_from_expr(&e.value, out, warnings),
            Stmt::FunctionDef(f) => collect_table_names_from_ast(&f.body, out, warnings),
            _ => {}
        }
    }
}

fn extract_table_calls_from_expr(
    expr: &Expr,
    out: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    match expr {
        Expr::Call(call) => {
            let is_table_ctor = match call.func.as_ref() {
                Expr::Name(n) => n.id.as_str() == "Table",
                Expr::Attribute(attr) => attr.attr.as_str() == "Table",
                _ => false,
            };
            if is_table_ctor {
                let literal = call
                    .arguments
                    .args
                    .first()
                    .and_then(eval_literal_string)
                    .or_else(|| {
                        call.arguments
                            .keywords
                            .iter()
                            .find(|kw| kw.arg.as_ref().is_some_and(|k| k.as_str() == "name"))
                            .and_then(|kw| eval_literal_string(&kw.value))
                    });
                if let Some(tbl) = literal
                    && is_safe_extension_table_name(&tbl, warnings)
                {
                    out.insert(tbl);
                }
            }
            for arg in &call.arguments.args {
                extract_table_calls_from_expr(arg, out, warnings);
            }
            for kw in &call.arguments.keywords {
                extract_table_calls_from_expr(&kw.value, out, warnings);
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                extract_table_calls_from_expr(e, out, warnings);
            }
        }
        Expr::List(l) => {
            for e in &l.elts {
                extract_table_calls_from_expr(e, out, warnings);
            }
        }
        _ => {}
    }
}

fn eval_literal_string(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        _ => None,
    }
}

fn now_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[derive(Debug, Deserialize)]
struct PythonPurgeOutput {
    option_entries_deleted: u64,
    state_entries_deleted: u64,
    #[serde(default)]
    extension_table_rows: BTreeMap<String, u64>,
    #[serde(default)]
    option_namespaces: Vec<String>,
    python_hook_executed: bool,
    #[serde(default)]
    warnings: Vec<String>,
}

const PYTHON_PURGE_RUNNER: &str = r#"
import importlib
import importlib.util
import json
import re
import sys
from graphlib import TopologicalSorter
from pathlib import Path

from sqlalchemy import delete, func, inspect, select, text

RESULT_PREFIX = "__CFMS_PURGE_RESULT__:"
TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

cfg = json.loads(sys.argv[1])
server_root = Path(cfg["server_root"]).resolve()
config_path = Path(cfg["config_path"]).resolve()
target = cfg["target"]
load_closure = cfg.get("load_closure", [])
run_hook = bool(cfg.get("run_hook", False))
data_module = cfg.get("data_module")
static_tables = list(cfg.get("static_tables", []))
protected_tables = set(cfg.get("protected_tables", []))

if str(server_root) not in sys.path:
    sys.path.insert(0, str(server_root))

from include.config import settings
if settings.global_config._config_path.resolve() != config_path:
    settings.global_config._config_path = config_path
    settings.global_config._load()

from include.config.options import register_options, unregister_options
from include.database.models.operations import AuditEntry, OptionEntry, SystemStateEntry
from include.database.session import Session
from include.extensions import manager as ext_mgr

loaded_ext_ids = []
saved_modules = {}
warnings = []

def _rollback_isolated():
    for ext_id in reversed(loaded_ext_ids):
        try:
            ext_mgr.pm.unregister(name=ext_id)
        except Exception:
            pass
        try:
            unregister_options(ext_id)
        except Exception:
            pass
        for mod_name in tuple(sys.modules):
            if mod_name == ext_id or mod_name.startswith(f"{ext_id}."):
                sys.modules.pop(mod_name, None)
    sys.modules.update(saved_modules)

try:
    for entry in load_closure:
        ext_id = entry["identifier"]
        if ext_mgr.pm.has_plugin(ext_id):
            continue
        for mod_name, mod_obj in tuple(sys.modules.items()):
            if mod_name == ext_id or mod_name.startswith(f"{ext_id}."):
                saved_modules[mod_name] = mod_obj
        spec = importlib.util.spec_from_file_location(ext_id, entry["entrypoint"])
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Failed to create module spec for {ext_id!r}")
        spec.submodule_search_locations = [entry["directory"]]
        module = importlib.util.module_from_spec(spec)
        sys.modules[ext_id] = module
        spec.loader.exec_module(module)
        ext_mgr.pm.register(module, name=ext_id)
        loaded_ext_ids.append(ext_id)

        opt_caller = ext_mgr._extension_hook(ext_id, "ext_register_options")
        if opt_caller.get_hookimpls():
            val_caller = ext_mgr._extension_hook(ext_id, "ext_validate_options")
            for declared in opt_caller():
                if not isinstance(declared, dict):
                    continue
                for ns, defs in declared.items():
                    register_options(
                        ns,
                        tuple(defs),
                        owner=ext_id,
                        validator=(lambda *, values, ns=ns, vc=val_caller: vc(namespace=ns, values=values))
                        if val_caller.get_hookimpls()
                        else None,
                    )

    dynamic_tables_reverse = []
    if data_module:
        mod = importlib.import_module(data_module)
        reg_fn = getattr(mod, "register_data", None)
        if callable(reg_fn):
            entries = list(reg_fn())
            decl_map = {}
            for item in entries:
                if getattr(item, "owner", None) != target:
                    raise RuntimeError(f"Invalid data table owner in {data_module!r}: expected {target!r}")
                tbl = item.table
                tbl_name = str(tbl.name)
                if tbl.schema is not None or not TABLE_NAME_RE.fullmatch(tbl_name) or tbl_name in protected_tables:
                    raise RuntimeError(f"Unsupported or protected extension table name: {tbl_name!r}")
                decl_map[tbl_name] = tbl
            graph = {
                name: {
                    fk.target_fullname.rsplit(".", 1)[0]
                    for fk in tbl.foreign_keys
                } & set(decl_map) - {name}
                for name, tbl in decl_map.items()
            }
            dynamic_tables_reverse = list(reversed(list(TopologicalSorter(graph).static_order())))

    candidate_tables = []
    for tbl_name in [*dynamic_tables_reverse, *static_tables]:
        if tbl_name not in candidate_tables and TABLE_NAME_RE.fullmatch(tbl_name) and tbl_name not in protected_tables:
            candidate_tables.append(tbl_name)

    def _quote_ident(dialect_name, ident):
        if dialect_name == "mysql":
            return "`" + ident.replace("`", "``") + "`"
        return '"' + ident.replace('"', '""') + '"'

    with Session() as session:
        with session.begin():
            conn = session.connection()
            if conn.dialect.name == "sqlite":
                driver_conn = getattr(conn.connection, "driver_connection", None)
                if driver_conn is not None and not getattr(driver_conn, "in_transaction", False):
                    conn.exec_driver_sql("BEGIN IMMEDIATE")

            existing_tables = set(inspect(conn).get_table_names())
            live_ext_tables = [t for t in candidate_tables if t in existing_tables]

            option_before = int(
                session.execute(
                    select(func.count()).select_from(OptionEntry).where(OptionEntry.owner == target)
                ).scalar_one()
            )
            state_before = int(
                session.execute(
                    select(func.count()).select_from(SystemStateEntry).where(SystemStateEntry.owner == target)
                ).scalar_one()
            )
            namespaces = [
                str(row)
                for row in session.scalars(
                    select(OptionEntry.namespace).where(OptionEntry.owner == target).distinct()
                ).all()
            ]
            before_table_counts = {}
            for tbl_name in live_ext_tables:
                qtbl = _quote_ident(conn.dialect.name, tbl_name)
                before_table_counts[tbl_name] = int(
                    session.execute(text(f"SELECT COUNT(*) FROM {qtbl}")).scalar_one()
                )

            hook_executed = False
            if run_hook:
                caller = ext_mgr._extension_hook(target, "ext_purge_data")
                if caller.get_hookimpls():
                    caller(session=session)
                    hook_executed = True
                else:
                    warnings.append(
                        f"Extension '{target}' defines 'ext_purge_data' without @hookimpl; hook was skipped"
                    )
                session.flush()

            table_rows_purged = {}
            for tbl_name in live_ext_tables:
                qtbl = _quote_ident(conn.dialect.name, tbl_name)
                del_res = session.execute(text(f"DELETE FROM {qtbl}"))
                rc = del_res.rowcount if del_res.rowcount is not None and del_res.rowcount >= 0 else 0
                table_rows_purged[tbl_name] = max(before_table_counts[tbl_name], int(rc))

            opt_res = session.execute(delete(OptionEntry).where(OptionEntry.owner == target))
            state_res = session.execute(delete(SystemStateEntry).where(SystemStateEntry.owner == target))
            opt_deleted = max(option_before, int(opt_res.rowcount or 0))
            state_deleted = max(state_before, int(state_res.rowcount or 0))

            audit_data = {
                "owner": target,
                "options_only": False,
                "option_entries": opt_deleted,
                "state_entries": state_deleted,
                "python_hook_executed": hook_executed,
            }
            if table_rows_purged:
                audit_data["extension_tables"] = table_rows_purged

            session.add(
                AuditEntry(
                    action="purge_extension_data",
                    result=0,
                    target=target,
                    data=audit_data,
                )
            )

    summary = {
        "option_entries_deleted": opt_deleted,
        "state_entries_deleted": state_deleted,
        "extension_table_rows": table_rows_purged,
        "option_namespaces": sorted(set(namespaces)),
        "python_hook_executed": hook_executed,
        "warnings": warnings,
    }
    print(f"{RESULT_PREFIX}{json.dumps(summary)}", flush=True)
finally:
    _rollback_isolated()
"#;

async fn run_python_atomic_purge(
    paths: &WorkspacePaths,
    target: &PurgeTargetSpec<'_>,
    has_hook: bool,
    static_tables: &[String],
    warnings: &mut Vec<String>,
) -> Result<ExtensionPurgeSummary> {
    let candidates = discover_python_candidates(paths);
    if candidates.is_empty() {
        return Err(CfmsError::Extension(format!(
            "Extension '{}' requires Python execution to purge its data, but no Python runtime was found; set CFMS_PYTHON, use --options-only, or omit --purge-data when uninstalling",
            target.identifier
        )));
    }

    let mut protected_tables: Vec<&str> = APPLICATION_TABLE_NAMES.to_vec();
    protected_tables.push("alembic_version");

    let payload = json!({
        "server_root": paths.server_root,
        "config_path": paths.config_path,
        "target": target.identifier,
        "load_closure": target.load_closure,
        "run_hook": has_hook,
        "data_module": target.data_module,
        "static_tables": static_tables,
        "protected_tables": protected_tables,
    })
    .to_string();

    let mut errors = Vec::new();
    for candidate in candidates {
        let mut cmd = Command::new(&candidate.program);
        cmd.args(&candidate.prefix_args)
            .arg("-c")
            .arg(PYTHON_PURGE_RUNNER)
            .arg(&payload)
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
                    "Timed out executing atomic purge for '{}' via {}; database changes were rolled back",
                    target.identifier, candidate.description
                )));
            }
        };

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(json_line) = stdout
                .lines()
                .rev()
                .find_map(|line| line.strip_prefix(PYTHON_RESULT_PREFIX))
            {
                let parsed: PythonPurgeOutput = serde_json::from_str(json_line).map_err(|err| {
                    CfmsError::Extension(format!(
                        "Failed to decode Python purge summary for '{}': {err}",
                        target.identifier
                    ))
                })?;
                warnings.extend(parsed.warnings);
                let option_namespaces =
                    merge_namespaces(target.manifest_namespaces, &parsed.option_namespaces);
                return Ok(ExtensionPurgeSummary {
                    options_only: false,
                    option_entries_deleted: parsed.option_entries_deleted,
                    state_entries_deleted: parsed.state_entries_deleted,
                    extension_table_rows: parsed.extension_table_rows,
                    option_namespaces,
                    python_hook_detected: has_hook,
                    python_hook_executed: parsed.python_hook_executed,
                    audit_logged: true,
                });
            }
            errors.push(format!(
                "{}: runner exited 0 without emitting {PYTHON_RESULT_PREFIX} summary",
                candidate.description
            ));
            continue;
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
        "Failed to purge data for '{}' ({}); database changes were rolled back",
        target.identifier,
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
        let target = PurgeTargetSpec {
            identifier: "sample_ext",
            options_only: false,
            target_directory: Some(&src),
            entrypoint: Some(&entrypoint),
            data_module: None,
            manifest_namespaces: &[],
            load_closure: &[],
            dependency_error: None,
        };
        let preview = preview_extension_purge(&paths, &pool, &target, &mut warnings)
            .await
            .expect("preview purge");
        assert_eq!(preview.option_entries_deleted, 1);
        assert_eq!(preview.state_entries_deleted, 1);
        assert!(!preview.python_hook_detected);
        pool.close().await;

        let summary = execute_extension_purge(&paths, &db_cfg, &target, &mut warnings)
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

    #[tokio::test]
    async fn preflight_and_data_table_purge_handles_oidc_and_preserves_options_revision_and_core_tables() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let ext_dir = src.join("include").join("extensions").join("oidc_sso");
        std::fs::create_dir_all(&ext_dir).expect("ext_dir");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            src.join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n",
        )
        .expect("config");
        let entrypoint = ext_dir.join("_extension.py");
        std::fs::write(&entrypoint, "def ext_init():\n    pass\n").expect("entry");
        // Declare OIDC table PLUS a core table decoy (`users`) to verify core-table protection!
        std::fs::write(
            ext_dir.join("models.py"),
            "class UserOidcCredential:\n    __tablename__ = \"user_oidc_credentials\"\nclass CoreUsersDecoy:\n    __tablename__ = \"users\"\n",
        )
        .expect("models");

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let db_cfg = ConfigDocument::load(&paths.config_path)
            .expect("cfg")
            .database_config()
            .expect("db");

        // 1. Missing required core tables fails preflight cleanly with SchemaDrift.
        let empty_pool = DbPool::connect(&db_cfg, &paths).await.expect("connect empty");
        let drift_err = preflight_purge_schema(&empty_pool)
            .await
            .expect_err("missing tables rejected by preflight");
        assert!(matches!(drift_err, CfmsError::SchemaDrift(_)));

        // 2. Create head schema including `user_oidc_credentials` and seed data.
        create_head_schema(&empty_pool, true).await.expect("create oidc schema");
        let DbPool::Sqlite(ref sp) = empty_pool else {
            panic!("sqlite");
        };
        let uid = Uuid::new_v4().simple().to_string();
        sqlx::query(
            "INSERT INTO users (id, username, nickname, created_time, status, secret_key) VALUES (?, 'alice', 'Alice', 1.0, 0, 'sec')",
        )
        .bind(&uid)
        .execute(sp)
        .await
        .expect("insert user");
        sqlx::query(
            "INSERT INTO user_oidc_credentials (id, user_id, issuer, subject, identity_digest) VALUES ('cred-1', ?, 'https://idp.example', 'sub-1', ?)",
        )
        .bind(&uid)
        .bind(vec![7u8; 32])
        .execute(sp)
        .await
        .expect("insert oidc cred");

        for (ns, owner, key) in [
            ("ext.oidc", "oidc_sso", "client_id"),
            ("core.security", "core", "min_len"),
        ] {
            sqlx::query(
                "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES (?, ?, ?, 1, 1, 'str', '\"v\"', 1.0)",
            )
            .bind(ns)
            .bind(owner)
            .bind(key)
            .execute(sp)
            .await
            .expect("insert option");
        }
        sqlx::query(
            "INSERT INTO system_states (owner, state_key, schema_version, revision, payload, updated_at) VALUES \
             ('oidc_sso', 'jwks_cache', 1, 1, '{}', 1.0), \
             ('core', 'options_revision.ext.oidc', 1, 2, '{}', 1.0)",
        )
        .execute(sp)
        .await
        .expect("insert states");
        empty_pool.close().await;

        // 3. --options-only deletes owner options/states ONLY and leaves `user_oidc_credentials` + `options_revision` + `users` intact!
        let mut opt_warnings = Vec::new();
        let opt_target = PurgeTargetSpec {
            identifier: "oidc_sso",
            options_only: true,
            target_directory: Some(&ext_dir),
            entrypoint: Some(&entrypoint),
            data_module: Some("models.py"),
            manifest_namespaces: &[],
            load_closure: &[],
            dependency_error: None,
        };
        let opt_summary = execute_extension_purge(&paths, &db_cfg, &opt_target, &mut opt_warnings)
            .await
            .expect("options-only purge");
        assert_eq!(opt_summary.option_entries_deleted, 1);
        assert_eq!(opt_summary.state_entries_deleted, 1);
        assert!(opt_summary.extension_table_rows.is_empty());

        let pool2 = DbPool::connect(&db_cfg, &paths).await.expect("reconnect 2");
        let DbPool::Sqlite(ref sp2) = pool2 else {
            panic!("sqlite");
        };
        let oidc_kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_oidc_credentials")
            .fetch_one(sp2)
            .await
            .expect("count oidc kept");
        assert_eq!(oidc_kept, 1);
        let rev_kept: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM system_states WHERE owner = 'core' AND state_key = 'options_revision.ext.oidc'",
        )
        .fetch_one(sp2)
        .await
        .expect("count options_revision kept");
        assert_eq!(rev_kept, 1);

        // Re-insert ext option/state, then run FULL purge.
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('ext.oidc', 'oidc_sso', 'client_id', 1, 2, 'str', '\"v2\"', 2.0)",
        )
        .execute(sp2)
        .await
        .expect("reinsert opt");
        pool2.close().await;

        let mut full_warnings = Vec::new();
        let full_target = PurgeTargetSpec {
            identifier: "oidc_sso",
            options_only: false,
            target_directory: Some(&ext_dir),
            entrypoint: Some(&entrypoint),
            data_module: Some("models.py"),
            manifest_namespaces: &[],
            load_closure: &[],
            dependency_error: None,
        };
        let full_summary =
            execute_extension_purge(&paths, &db_cfg, &full_target, &mut full_warnings)
                .await
                .expect("full purge");
        assert_eq!(full_summary.option_entries_deleted, 1);
        assert_eq!(full_summary.state_entries_deleted, 0);
        assert_eq!(
            full_summary.extension_table_rows.get("user_oidc_credentials"),
            Some(&1)
        );
        assert!(
            !full_summary.extension_table_rows.contains_key("users"),
            "core table `users` must never be in extension_tables"
        );
        assert!(
            full_warnings
                .iter()
                .any(|w| w.contains("protected core table name 'users'")),
            "expected core-table protection warning, got {full_warnings:?}"
        );

        let pool3 = DbPool::connect(&db_cfg, &paths).await.expect("reconnect 3");
        let DbPool::Sqlite(ref sp3) = pool3 else {
            panic!("sqlite");
        };
        let oidc_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_oidc_credentials")
            .fetch_one(sp3)
            .await
            .expect("count oidc after");
        assert_eq!(oidc_after, 0);
        let users_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(sp3)
            .await
            .expect("count users after");
        assert_eq!(users_after, 1);
        let core_opts_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM options WHERE owner = 'core'")
                .fetch_one(sp3)
                .await
                .expect("count core opts");
        assert_eq!(core_opts_after, 1);
        pool3.close().await;

        // 4. Repeat purge must be cleanly idempotent (0 rows deleted, audit row still written).
        let mut repeat_warnings = Vec::new();
        let repeat_summary =
            execute_extension_purge(&paths, &db_cfg, &full_target, &mut repeat_warnings)
                .await
                .expect("repeat idempotent purge");
        assert_eq!(repeat_summary.option_entries_deleted, 0);
        assert_eq!(repeat_summary.state_entries_deleted, 0);
        assert_eq!(
            repeat_summary.extension_table_rows.get("user_oidc_credentials"),
            Some(&0)
        );
        assert!(repeat_summary.audit_logged);
    }

    #[tokio::test]
    async fn custom_fk_tables_order_children_before_parents_transactional_and_hook_closure_guarded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let ext_dir = src.join("include").join("extensions").join("custom_ext");
        std::fs::create_dir_all(&ext_dir).expect("ext_dir");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            src.join("config.toml"),
            "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n",
        )
        .expect("config");
        let entrypoint = ext_dir.join("_extension.py");
        std::fs::write(
            &entrypoint,
            "def ext_purge_data(session):\n    pass\n",
        )
        .expect("entry with hook");
        std::fs::write(
            ext_dir.join("data.py"),
            "import sqlalchemy as sa\n\nclass ExtParent:\n    __tablename__ = \"ext_parent\"\n\ndef make_child(metadata):\n    return sa.Table(\"ext_child\", metadata)\n",
        )
        .expect("data.py");

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let db_cfg = ConfigDocument::load(&paths.config_path)
            .expect("cfg")
            .database_config()
            .expect("db");

        let pool = DbPool::connect(&db_cfg, &paths).await.expect("connect");
        create_head_schema(&pool, false).await.expect("head schema");
        let DbPool::Sqlite(ref sp) = pool else {
            panic!("sqlite");
        };
        sqlx::query("CREATE TABLE ext_parent (id TEXT PRIMARY KEY)")
            .execute(sp)
            .await
            .expect("create parent");
        sqlx::query(
            "CREATE TABLE ext_child (id TEXT PRIMARY KEY, parent_id TEXT NOT NULL REFERENCES ext_parent(id))",
        )
        .execute(sp)
        .await
        .expect("create child");
        sqlx::query("INSERT INTO ext_parent (id) VALUES ('p1')")
            .execute(sp)
            .await
            .expect("insert parent");
        sqlx::query("INSERT INTO ext_child (id, parent_id) VALUES ('c1', 'p1')")
            .execute(sp)
            .await
            .expect("insert child");

        // When ext_purge_data hook exists + dependency_error is set:
        // preview still works safely, while execution fails cleanly unless --options-only.
        let blocked_target = PurgeTargetSpec {
            identifier: "custom_ext",
            options_only: false,
            target_directory: Some(&ext_dir),
            entrypoint: Some(&entrypoint),
            data_module: Some("data.py"),
            manifest_namespaces: &[],
            load_closure: &[],
            dependency_error: Some("Missing dependency 'missing_dep'"),
        };
        let mut w1 = Vec::new();
        let preview = preview_extension_purge(&paths, &pool, &blocked_target, &mut w1)
            .await
            .expect("preview works");
        assert!(preview.python_hook_detected);
        assert_eq!(preview.extension_table_rows.get("ext_child"), Some(&1));
        assert_eq!(preview.extension_table_rows.get("ext_parent"), Some(&1));
        pool.close().await;

        let mut w2 = Vec::new();
        let closure_err = execute_extension_purge(&paths, &db_cfg, &blocked_target, &mut w2)
            .await
            .expect_err("broken closure rejects hook execution");
        assert!(closure_err.to_string().contains("Missing dependency"));

        // Removing the hook exercises pure-Rust topological deletion: child MUST delete before parent
        // under SQLite PRAGMA foreign_keys = ON!
        std::fs::write(&entrypoint, "def ext_init():\n    pass\n").expect("entry without hook");
        let rust_target = PurgeTargetSpec {
            identifier: "custom_ext",
            options_only: false,
            target_directory: Some(&ext_dir),
            entrypoint: Some(&entrypoint),
            data_module: Some("data.py"),
            manifest_namespaces: &[],
            load_closure: &[],
            dependency_error: None,
        };
        let mut w3 = Vec::new();
        let rust_summary = execute_extension_purge(&paths, &db_cfg, &rust_target, &mut w3)
            .await
            .expect("fk-ordered child->parent delete succeeds");
        assert_eq!(rust_summary.extension_table_rows.get("ext_child"), Some(&1));
        assert_eq!(rust_summary.extension_table_rows.get("ext_parent"), Some(&1));

        let verify_pool = DbPool::connect(&db_cfg, &paths).await.expect("reconnect");
        let DbPool::Sqlite(ref sp2) = verify_pool else {
            panic!("sqlite");
        };
        let c_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ext_child")
            .fetch_one(sp2)
            .await
            .expect("child count");
        let p_cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ext_parent")
            .fetch_one(sp2)
            .await
            .expect("parent count");
        assert_eq!(c_cnt, 0);
        assert_eq!(p_cnt, 0);
        verify_pool.close().await;
    }
}
