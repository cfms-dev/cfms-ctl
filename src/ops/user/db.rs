//! Multi-dialect (`SQLite`, `MySQL`, `PostgreSQL`) persistence helpers for `cfms-ctl user`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use sqlx::mysql::MySqlRow;
use sqlx::postgres::PgRow;
use sqlx::sqlite::SqliteRow;
use sqlx::{MySql, Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;
use crate::core::error::{CfmsError, Result};
use crate::db::schema::{LATEST_SCHEMA_REVISION, SchemaInspector};
use crate::db::{DatabaseKind, DbPool};
use crate::ops::user::auth_policy::{AuthPurpose, AuthStep, PolicyMutation, PolicyRow};

const REQUIRED_USER_TABLES: &[&str] = &[
    "users",
    "user_passwords",
    "user_totp_credentials",
    "user_auth_public_keys",
    "user_auth_policies",
    "options",
    "audit_entries",
];

const ID_CHUNK_SIZE: usize = 200;

/// Schema readiness metadata verified before inspecting or mutating user auth tables.
#[derive(Debug, Clone)]
pub struct SchemaPreflight {
    pub has_oidc_table: bool,
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub status: i32,
    pub secret_key: String,
}

#[derive(Debug, Clone)]
pub struct PasswordRow {
    pub user_id: Uuid,
    pub credential_id: String,
}

#[derive(Debug, Clone)]
pub struct TotpRow {
    pub user_id: Uuid,
    pub credential_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct PublicKeyRow {
    pub id: String,
    pub user_id: Uuid,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone)]
pub struct OidcRow {
    pub id: String,
    pub user_id: Uuid,
    pub issuer: String,
}

#[derive(Debug, Clone)]
pub struct UserPolicyRow {
    pub user_id: Uuid,
    pub policy: PolicyRow,
}

/// Active write transaction across SQLite (`BEGIN IMMEDIATE`), MySQL, and PostgreSQL.
pub enum DbTx {
    Sqlite(Transaction<'static, Sqlite>),
    Mysql(Transaction<'static, MySql>),
    Postgres(Transaction<'static, Postgres>),
}

impl DbTx {
    /// Open a write transaction (`BEGIN IMMEDIATE` on SQLite so `busy_timeout` is respected).
    pub async fn begin(pool: &DbPool) -> Result<Self> {
        match pool {
            DbPool::Sqlite(p) => Ok(Self::Sqlite(p.begin_with("BEGIN IMMEDIATE").await?)),
            DbPool::Mysql(p) => Ok(Self::Mysql(p.begin().await?)),
            DbPool::Postgres(p) => Ok(Self::Postgres(p.begin().await?)),
        }
    }

    pub async fn commit(self) -> Result<()> {
        match self {
            Self::Sqlite(tx) => tx.commit().await?,
            Self::Mysql(tx) => tx.commit().await?,
            Self::Postgres(tx) => tx.commit().await?,
        }
        Ok(())
    }

    #[must_use]
    pub const fn kind(&self) -> DatabaseKind {
        match self {
            Self::Sqlite(_) => DatabaseKind::Sqlite,
            Self::Mysql(_) => DatabaseKind::Mysql,
            Self::Postgres(_) => DatabaseKind::Postgresql,
        }
    }
}

/// Execution handle shared between read-only `--dry-run` queries (`Pool`) and write transactions (`Tx`).
pub enum DbExec<'a> {
    Pool(&'a DbPool),
    Tx(&'a mut DbTx),
}

impl DbExec<'_> {
    #[must_use]
    pub const fn kind(&self) -> DatabaseKind {
        match self {
            Self::Pool(p) => p.kind(),
            Self::Tx(tx) => tx.kind(),
        }
    }

    #[must_use]
    const fn for_update_suffix(&self) -> &'static str {
        match self {
            Self::Tx(DbTx::Mysql(_) | DbTx::Postgres(_)) => " FOR UPDATE",
            _ => "",
        }
    }
}

trait CfmsRowExt: Row {
    fn get_uuid(&self, col: &str) -> Result<Uuid>;
}

impl CfmsRowExt for SqliteRow {
    fn get_uuid(&self, col: &str) -> Result<Uuid> {
        let raw: String = self.try_get(col)?;
        Uuid::parse_str(raw.trim()).map_err(|e| {
            CfmsError::Database(format!("Invalid SQLite UUID '{raw}' in '{col}': {e}"))
        })
    }
}

impl CfmsRowExt for MySqlRow {
    fn get_uuid(&self, col: &str) -> Result<Uuid> {
        let raw: String = self.try_get(col)?;
        Uuid::parse_str(raw.trim()).map_err(|e| {
            CfmsError::Database(format!("Invalid MySQL UUID '{raw}' in '{col}': {e}"))
        })
    }
}

impl CfmsRowExt for PgRow {
    fn get_uuid(&self, col: &str) -> Result<Uuid> {
        self.try_get::<Uuid, _>(col).map_err(CfmsError::from)
    }
}

/// Execute a parameterized query across `DbExec` (`Pool` or `Tx`) for SQLite, MySQL, and Postgres
/// using one shared generic row decoder.
macro_rules! exec_fetch_all {
    ($exec:expr, $sql:expr, |$q:ident| $bind:expr, $map_fn:path) => {{
        let sql = $sql;
        match &mut *$exec {
            DbExec::Pool(DbPool::Sqlite(p)) => {
                let $q = sqlx::query(sqlx::AssertSqlSafe(sql));
                $bind
                    .fetch_all(p)
                    .await?
                    .iter()
                    .map($map_fn)
                    .collect::<Result<Vec<_>>>()?
            }
            DbExec::Pool(DbPool::Mysql(p)) => {
                let $q = sqlx::query(sqlx::AssertSqlSafe(sql));
                $bind
                    .fetch_all(p)
                    .await?
                    .iter()
                    .map($map_fn)
                    .collect::<Result<Vec<_>>>()?
            }
            DbExec::Pool(DbPool::Postgres(p)) => {
                let $q = sqlx::query(sqlx::AssertSqlSafe(sql));
                $bind
                    .fetch_all(p)
                    .await?
                    .iter()
                    .map($map_fn)
                    .collect::<Result<Vec<_>>>()?
            }
            DbExec::Tx(DbTx::Sqlite(tx)) => {
                let $q = sqlx::query(sqlx::AssertSqlSafe(sql));
                $bind
                    .fetch_all(&mut **tx)
                    .await?
                    .iter()
                    .map($map_fn)
                    .collect::<Result<Vec<_>>>()?
            }
            DbExec::Tx(DbTx::Mysql(tx)) => {
                let $q = sqlx::query(sqlx::AssertSqlSafe(sql));
                $bind
                    .fetch_all(&mut **tx)
                    .await?
                    .iter()
                    .map($map_fn)
                    .collect::<Result<Vec<_>>>()?
            }
            DbExec::Tx(DbTx::Postgres(tx)) => {
                let $q = sqlx::query(sqlx::AssertSqlSafe(sql));
                $bind
                    .fetch_all(&mut **tx)
                    .await?
                    .iter()
                    .map($map_fn)
                    .collect::<Result<Vec<_>>>()?
            }
        }
    }};
}

/// Dispatch chunked `WHERE <prefix> (<ph>) <order>` selects with dialect UUID binding.
macro_rules! exec_fetch_chunked_uuids {
    ($exec:expr, $user_ids:expr, $prefix:expr, $order:expr, $map_fn:path) => {{
        let mut out = Vec::new();
        let kind = $exec.kind();
        let suffix = $exec.for_update_suffix();
        for chunk in $user_ids.chunks(ID_CHUNK_SIZE) {
            let ph = placeholders_from(kind, 1, chunk.len());
            let sql = format!("{} ({}) {}{}", $prefix, ph, $order, suffix);
            let rows = match &mut *$exec {
                DbExec::Pool(DbPool::Sqlite(p)) => {
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id.simple().to_string());
                    }
                    q.fetch_all(p)
                        .await?
                        .iter()
                        .map($map_fn)
                        .collect::<Result<Vec<_>>>()?
                }
                DbExec::Pool(DbPool::Mysql(p)) => {
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id.simple().to_string());
                    }
                    q.fetch_all(p)
                        .await?
                        .iter()
                        .map($map_fn)
                        .collect::<Result<Vec<_>>>()?
                }
                DbExec::Pool(DbPool::Postgres(p)) => {
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(*id);
                    }
                    q.fetch_all(p)
                        .await?
                        .iter()
                        .map($map_fn)
                        .collect::<Result<Vec<_>>>()?
                }
                DbExec::Tx(DbTx::Sqlite(tx)) => {
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id.simple().to_string());
                    }
                    q.fetch_all(&mut **tx)
                        .await?
                        .iter()
                        .map($map_fn)
                        .collect::<Result<Vec<_>>>()?
                }
                DbExec::Tx(DbTx::Mysql(tx)) => {
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id.simple().to_string());
                    }
                    q.fetch_all(&mut **tx)
                        .await?
                        .iter()
                        .map($map_fn)
                        .collect::<Result<Vec<_>>>()?
                }
                DbExec::Tx(DbTx::Postgres(tx)) => {
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(*id);
                    }
                    q.fetch_all(&mut **tx)
                        .await?
                        .iter()
                        .map($map_fn)
                        .collect::<Result<Vec<_>>>()?
                }
            };
            out.extend(rows);
        }
        Ok::<Vec<_>, CfmsError>(out)
    }};
}

fn placeholders_from(kind: DatabaseKind, start_idx: usize, count: usize) -> String {
    (0..count)
        .map(|i| match kind {
            DatabaseKind::Postgresql => format!("${}", start_idx + i),
            DatabaseKind::Sqlite | DatabaseKind::Mysql => "?".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn now_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Verify required auth/user tables, columns, and `alembic_version` parity before user ops.
pub async fn preflight_user_schema(pool: &DbPool) -> Result<SchemaPreflight> {
    let report = SchemaInspector::inspect(pool).await?;

    let missing_required: Vec<&str> = REQUIRED_USER_TABLES
        .iter()
        .copied()
        .filter(|tbl| report.missing_tables.iter().any(|m| m == tbl))
        .collect();
    if !missing_required.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database is missing required authentication/audit tables ({}); run `cfms-ctl database upgrade` first",
            missing_required.join(", ")
        )));
    }

    if !report.revision_matches {
        let current = report.current_revision.as_deref().unwrap_or("<none>");
        return Err(CfmsError::SchemaDrift(format!(
            "Database schema revision '{current}' does not match expected '{LATEST_SCHEMA_REVISION}'; run `cfms-ctl database upgrade` first"
        )));
    }

    if !report.column_mismatches.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database schema has column drift ({} mismatch(es)); run `cfms-ctl database check` for details",
            report.column_mismatches.len()
        )));
    }

    let has_oidc_table = report
        .extra_tables
        .iter()
        .any(|t| t == "user_oidc_credentials");

    Ok(SchemaPreflight { has_oidc_table })
}

/// Fetch one user row by exact username (locked `FOR UPDATE` when executed on MySQL/Postgres Tx).
pub async fn fetch_user_by_username(
    exec: &mut DbExec<'_>,
    username: &str,
) -> Result<Option<UserRow>> {
    let kind = exec.kind();
    let suffix = exec.for_update_suffix();
    let ph = placeholders_from(kind, 1, 1);
    let sql = format!("SELECT id, username, status, secret_key FROM users WHERE username = {ph}{suffix}");
    let mut rows = exec_fetch_all!(exec, sql, |q| q.bind(username), decode_user_row);
    Ok(rows.pop())
}

/// Fetch all user `(id, username)` pairs ordered by `id` (lightweight scan for `rotate-secrets`).
pub async fn fetch_all_user_ids(exec: &mut DbExec<'_>) -> Result<Vec<(Uuid, String)>> {
    let suffix = exec.for_update_suffix();
    let sql = format!("SELECT id, username FROM users ORDER BY id{suffix}");
    Ok(exec_fetch_all!(exec, sql, |q| q, decode_user_id_name_row))
}

/// Count users matching optional username (for read-only `--dry-run`).
pub async fn count_target_users(pool: &DbPool, username: Option<&str>) -> Result<u64> {
    let cnt: i64 = match (pool, username) {
        (DbPool::Sqlite(p), None) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(p)
                .await?
        }
        (DbPool::Mysql(p), None) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(p)
                .await?
        }
        (DbPool::Postgres(p), None) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(p)
                .await?
        }
        (DbPool::Sqlite(p), Some(u)) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ?")
                .bind(u)
                .fetch_one(p)
                .await?
        }
        (DbPool::Mysql(p), Some(u)) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ?")
                .bind(u)
                .fetch_one(p)
                .await?
        }
        (DbPool::Postgres(p), Some(u)) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
                .bind(u)
                .fetch_one(p)
                .await?
        }
    };
    u64::try_from(cnt).map_err(|_| CfmsError::Database(format!("Negative user count: {cnt}")))
}

/// Collect sorted distinct `user_id`s that hold either a `user_totp_credentials` row OR any
/// `"totp"` step inside `user_auth_policies` (catching orphaned policy references too).
pub async fn fetch_totp_candidate_user_ids(exec: &mut DbExec<'_>) -> Result<Vec<Uuid>> {
    let cred_ids: Vec<Uuid> = exec_fetch_all!(
        exec,
        "SELECT user_id FROM user_totp_credentials ORDER BY user_id".to_string(),
        |q| q,
        decode_only_user_id
    );
    let mut target_set: BTreeSet<Uuid> = cred_ids.into_iter().collect();

    let all_policies = exec_fetch_all!(
        exec,
        "SELECT user_id, purpose, revision, chains FROM user_auth_policies ORDER BY user_id, purpose"
            .to_string(),
        |q| q,
        decode_policy_row
    );
    for row in all_policies {
        if row
            .policy
            .chains
            .iter()
            .any(|chain| chain.iter().any(|step| step.method == "totp"))
        {
            target_set.insert(row.user_id);
        }
    }

    Ok(target_set.into_iter().collect())
}

/// Lock/load `users` rows by ID chunks in `ORDER BY id` order.
pub async fn fetch_users_by_ids(exec: &mut DbExec<'_>, user_ids: &[Uuid]) -> Result<Vec<UserRow>> {
    exec_fetch_chunked_uuids!(
        exec,
        user_ids,
        "SELECT id, username, status, secret_key FROM users WHERE id IN",
        "ORDER BY id",
        decode_user_row
    )
}

pub async fn fetch_passwords_by_users(
    exec: &mut DbExec<'_>,
    user_ids: &[Uuid],
) -> Result<Vec<PasswordRow>> {
    exec_fetch_chunked_uuids!(
        exec,
        user_ids,
        "SELECT user_id, credential_id FROM user_passwords WHERE user_id IN",
        "ORDER BY user_id",
        decode_password_row
    )
}

pub async fn fetch_totps_by_users(
    exec: &mut DbExec<'_>,
    user_ids: &[Uuid],
) -> Result<Vec<TotpRow>> {
    exec_fetch_chunked_uuids!(
        exec,
        user_ids,
        "SELECT user_id, credential_id, enabled FROM user_totp_credentials WHERE user_id IN",
        "ORDER BY user_id",
        decode_totp_row
    )
}

pub async fn fetch_public_keys_by_users(
    exec: &mut DbExec<'_>,
    user_ids: &[Uuid],
) -> Result<Vec<PublicKeyRow>> {
    exec_fetch_chunked_uuids!(
        exec,
        user_ids,
        "SELECT id, user_id, fingerprint FROM user_auth_public_keys WHERE user_id IN",
        "ORDER BY user_id, id",
        decode_public_key_row
    )
}

pub async fn fetch_oidc_by_users(exec: &mut DbExec<'_>, user_ids: &[Uuid]) -> Result<Vec<OidcRow>> {
    exec_fetch_chunked_uuids!(
        exec,
        user_ids,
        "SELECT id, user_id, issuer FROM user_oidc_credentials WHERE user_id IN",
        "ORDER BY user_id, id",
        decode_oidc_row
    )
}

pub async fn fetch_policies_by_users(
    exec: &mut DbExec<'_>,
    user_ids: &[Uuid],
) -> Result<Vec<UserPolicyRow>> {
    exec_fetch_chunked_uuids!(
        exec,
        user_ids,
        "SELECT user_id, purpose, revision, chains FROM user_auth_policies WHERE user_id IN",
        "ORDER BY user_id, purpose",
        decode_policy_row
    )
}

fn decode_only_user_id<R: CfmsRowExt>(r: &R) -> Result<Uuid> {
    r.get_uuid("user_id")
}

fn decode_user_id_name_row<'r, R>(r: &'r R) -> Result<(Uuid, String)>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok((r.get_uuid("id")?, r.try_get("username")?))
}

fn decode_user_row<'r, R>(r: &'r R) -> Result<UserRow>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i32: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(UserRow {
        id: r.get_uuid("id")?,
        username: r.try_get("username")?,
        status: r.try_get("status")?,
        secret_key: r.try_get("secret_key")?,
    })
}

fn decode_password_row<'r, R>(r: &'r R) -> Result<PasswordRow>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(PasswordRow {
        user_id: r.get_uuid("user_id")?,
        credential_id: r.try_get("credential_id")?,
    })
}

fn decode_totp_row<'r, R>(r: &'r R) -> Result<TotpRow>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    bool: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(TotpRow {
        user_id: r.get_uuid("user_id")?,
        credential_id: r.try_get("credential_id")?,
        enabled: r.try_get("enabled")?,
    })
}

fn decode_public_key_row<'r, R>(r: &'r R) -> Result<PublicKeyRow>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Vec<u8>: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let fp_bytes: Vec<u8> = r.try_get("fingerprint")?;
    Ok(PublicKeyRow {
        id: r.try_get("id")?,
        user_id: r.get_uuid("user_id")?,
        fingerprint_hex: hex::encode(&fp_bytes),
    })
}

fn decode_oidc_row<'r, R>(r: &'r R) -> Result<OidcRow>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    Ok(OidcRow {
        id: r.try_get("id")?,
        user_id: r.get_uuid("user_id")?,
        issuer: r.try_get("issuer")?,
    })
}

fn decode_policy_row<'r, R>(r: &'r R) -> Result<UserPolicyRow>
where
    R: CfmsRowExt,
    &'r str: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    i32: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    sqlx::types::Json<serde_json::Value>:
        sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let user_id = r.get_uuid("user_id")?;
    let raw_purpose: String = r.try_get("purpose")?;
    let purpose = AuthPurpose::parse(&raw_purpose).ok_or_else(|| {
        CfmsError::Database(format!(
            "Unsupported auth policy purpose '{raw_purpose}' for user {user_id}"
        ))
    })?;
    let revision: i32 = r.try_get("revision")?;
    let chains_json: sqlx::types::Json<serde_json::Value> = r.try_get("chains")?;
    let chains: Vec<Vec<AuthStep>> = serde_json::from_value(chains_json.0).map_err(|e| {
        CfmsError::Database(format!(
            "Corrupted chains JSON in user_auth_policies ({user_id}, '{raw_purpose}'): {e}"
        ))
    })?;
    Ok(UserPolicyRow {
        user_id,
        policy: PolicyRow {
            purpose,
            revision,
            chains,
        },
    })
}

/// Insert or update `user_passwords` inside `tx`.
pub async fn upsert_user_password(
    tx: &mut DbTx,
    user_id: Uuid,
    credential_id: &str,
    pass_hash: &str,
    passwd_last_modified: f64,
    insert: bool,
) -> Result<()> {
    let kind = tx.kind();
    let sql = if insert {
        match kind {
            DatabaseKind::Postgresql => {
                "INSERT INTO user_passwords (user_id, credential_id, pass_hash, passwd_last_modified) VALUES ($1, $2, $3, $4)"
            }
            DatabaseKind::Sqlite | DatabaseKind::Mysql => {
                "INSERT INTO user_passwords (user_id, credential_id, pass_hash, passwd_last_modified) VALUES (?, ?, ?, ?)"
            }
        }
    } else {
        match kind {
            DatabaseKind::Postgresql => {
                "UPDATE user_passwords SET pass_hash = $1, passwd_last_modified = $2 WHERE user_id = $3"
            }
            DatabaseKind::Sqlite | DatabaseKind::Mysql => {
                "UPDATE user_passwords SET pass_hash = ?, passwd_last_modified = ? WHERE user_id = ?"
            }
        }
    };

    let affected = match tx {
        DbTx::Sqlite(t) => {
            let uid = user_id.simple().to_string();
            let q = if insert {
                sqlx::query(sql)
                    .bind(&uid)
                    .bind(credential_id)
                    .bind(pass_hash)
                    .bind(passwd_last_modified)
            } else {
                sqlx::query(sql)
                    .bind(pass_hash)
                    .bind(passwd_last_modified)
                    .bind(&uid)
            };
            q.execute(&mut **t).await?.rows_affected()
        }
        DbTx::Mysql(t) => {
            let uid = user_id.simple().to_string();
            let q = if insert {
                sqlx::query(sql)
                    .bind(&uid)
                    .bind(credential_id)
                    .bind(pass_hash)
                    .bind(passwd_last_modified)
            } else {
                sqlx::query(sql)
                    .bind(pass_hash)
                    .bind(passwd_last_modified)
                    .bind(&uid)
            };
            q.execute(&mut **t).await?.rows_affected()
        }
        DbTx::Postgres(t) => {
            let q = if insert {
                sqlx::query(sql)
                    .bind(user_id)
                    .bind(credential_id)
                    .bind(pass_hash)
                    .bind(passwd_last_modified)
            } else {
                sqlx::query(sql)
                    .bind(pass_hash)
                    .bind(passwd_last_modified)
                    .bind(user_id)
            };
            q.execute(&mut **t).await?.rows_affected()
        }
    };

    if affected != 1 {
        return Err(CfmsError::Database(format!(
            "Unexpected row count updating user_passwords for user {user_id}: {affected}"
        )));
    }
    Ok(())
}

/// Update `users.secret_key` in chunked batches inside `tx`, verifying affected row counts.
pub async fn update_user_secrets_chunked(
    tx: &mut DbTx,
    updates: &[(Uuid, String)],
) -> Result<u64> {
    let mut total_updated = 0u64;
    let kind = tx.kind();

    for chunk in updates.chunks(ID_CHUNK_SIZE) {
        if chunk.is_empty() {
            continue;
        }
        let expected = chunk.len() as u64;
        let sql = if chunk.len() == 1 {
            match kind {
                DatabaseKind::Postgresql => {
                    "UPDATE users SET secret_key = $1 WHERE id = $2".to_string()
                }
                DatabaseKind::Sqlite | DatabaseKind::Mysql => {
                    "UPDATE users SET secret_key = ? WHERE id = ?".to_string()
                }
            }
        } else {
            let mut idx = 1usize;
            let mut whens = Vec::with_capacity(chunk.len());
            for _ in chunk {
                let w = match kind {
                    DatabaseKind::Postgresql => format!("WHEN id = ${} THEN ${}", idx, idx + 1),
                    DatabaseKind::Sqlite | DatabaseKind::Mysql => "WHEN id = ? THEN ?".to_string(),
                };
                idx += 2;
                whens.push(w);
            }
            let in_ph = placeholders_from(kind, idx, chunk.len());
            format!(
                "UPDATE users SET secret_key = CASE {} END WHERE id IN ({})",
                whens.join(" "),
                in_ph
            )
        };

        let affected = match tx {
            DbTx::Sqlite(t) => bind_secret_chunk_strs(sqlx::query(sqlx::AssertSqlSafe(sql)), chunk)
                .execute(&mut **t)
                .await?
                .rows_affected(),
            DbTx::Mysql(t) => bind_secret_chunk_strs(sqlx::query(sqlx::AssertSqlSafe(sql)), chunk)
                .execute(&mut **t)
                .await?
                .rows_affected(),
            DbTx::Postgres(t) => {
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                if chunk.len() == 1 {
                    q = q.bind(&chunk[0].1).bind(chunk[0].0);
                } else {
                    for (uid, sk) in chunk {
                        q = q.bind(*uid).bind(sk);
                    }
                    for (uid, _) in chunk {
                        q = q.bind(*uid);
                    }
                }
                q.execute(&mut **t).await?.rows_affected()
            }
        };

        if affected != expected {
            return Err(CfmsError::Database(format!(
                "Unexpected row count updating users.secret_key: expected {expected}, updated {affected}"
            )));
        }
        total_updated += affected;
    }

    Ok(total_updated)
}

fn bind_secret_chunk_strs<'q, DB>(
    mut q: sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments>,
    chunk: &'q [(Uuid, String)],
) -> sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments>
where
    DB: sqlx::Database,
    String: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    &'q str: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
{
    if chunk.len() == 1 {
        q.bind(chunk[0].1.as_str())
            .bind(chunk[0].0.simple().to_string())
    } else {
        for (uid, sk) in chunk {
            q = q.bind(uid.simple().to_string()).bind(sk.as_str());
        }
        for (uid, _) in chunk {
            q = q.bind(uid.simple().to_string());
        }
        q
    }
}

/// Delete `user_totp_credentials` rows for `user_ids` in chunks inside `tx`.
pub async fn delete_totp_credentials_by_users(tx: &mut DbTx, user_ids: &[Uuid]) -> Result<u64> {
    let mut deleted = 0u64;
    let kind = tx.kind();

    for chunk in user_ids.chunks(ID_CHUNK_SIZE) {
        let ph = placeholders_from(kind, 1, chunk.len());
        let sql = format!("DELETE FROM user_totp_credentials WHERE user_id IN ({ph})");
        let affected = match tx {
            DbTx::Sqlite(t) => {
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id.simple().to_string());
                }
                q.execute(&mut **t).await?.rows_affected()
            }
            DbTx::Mysql(t) => {
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id.simple().to_string());
                }
                q.execute(&mut **t).await?.rows_affected()
            }
            DbTx::Postgres(t) => {
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(*id);
                }
                q.execute(&mut **t).await?.rows_affected()
            }
        };
        deleted += affected;
    }

    Ok(deleted)
}

/// Apply CAS policy inserts/updates for `(user_id, purpose)` inside `tx`.
pub async fn apply_policy_mutations(
    tx: &mut DbTx,
    user_id: Uuid,
    mutations: &[PolicyMutation],
) -> Result<u64> {
    let mut updated_count = 0u64;

    for m in mutations {
        let chains_str = serde_json::to_string(&m.new_chains).map_err(|e| {
            CfmsError::Database(format!("Failed to serialize auth policy chains: {e}"))
        })?;
        let purpose = m.purpose.as_str();

        if m.expected_revision == 0 {
            match tx {
                DbTx::Sqlite(t) => {
                    sqlx::query(
                        "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES (?, ?, ?, ?)",
                    )
                    .bind(user_id.simple().to_string())
                    .bind(purpose)
                    .bind(m.new_revision)
                    .bind(&chains_str)
                    .execute(&mut **t)
                    .await?;
                }
                DbTx::Mysql(t) => {
                    sqlx::query(
                        "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES (?, ?, ?, ?)",
                    )
                    .bind(user_id.simple().to_string())
                    .bind(purpose)
                    .bind(m.new_revision)
                    .bind(&chains_str)
                    .execute(&mut **t)
                    .await?;
                }
                DbTx::Postgres(t) => {
                    sqlx::query(
                        "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES ($1, $2, $3, $4::json)",
                    )
                    .bind(user_id)
                    .bind(purpose)
                    .bind(m.new_revision)
                    .bind(&chains_str)
                    .execute(&mut **t)
                    .await?;
                }
            }
            updated_count += 1;
        } else {
            let rows = match tx {
                DbTx::Sqlite(t) => {
                    sqlx::query(
                        "UPDATE user_auth_policies SET chains = ?, revision = ? WHERE user_id = ? AND purpose = ? AND revision = ?",
                    )
                    .bind(&chains_str)
                    .bind(m.new_revision)
                    .bind(user_id.simple().to_string())
                    .bind(purpose)
                    .bind(m.expected_revision)
                    .execute(&mut **t)
                    .await?
                    .rows_affected()
                }
                DbTx::Mysql(t) => {
                    sqlx::query(
                        "UPDATE user_auth_policies SET chains = ?, revision = ? WHERE user_id = ? AND purpose = ? AND revision = ?",
                    )
                    .bind(&chains_str)
                    .bind(m.new_revision)
                    .bind(user_id.simple().to_string())
                    .bind(purpose)
                    .bind(m.expected_revision)
                    .execute(&mut **t)
                    .await?
                    .rows_affected()
                }
                DbTx::Postgres(t) => {
                    sqlx::query(
                        "UPDATE user_auth_policies SET chains = $1::json, revision = $2 WHERE user_id = $3 AND purpose = $4 AND revision = $5",
                    )
                    .bind(&chains_str)
                    .bind(m.new_revision)
                    .bind(user_id)
                    .bind(purpose)
                    .bind(m.expected_revision)
                    .execute(&mut **t)
                    .await?
                    .rows_affected()
                }
            };
            if rows != 1 {
                return Err(CfmsError::OptionConflict(format!(
                    "Authentication policy ({user_id}, '{purpose}') changed concurrently during update"
                )));
            }
            updated_count += 1;
        }
    }

    Ok(updated_count)
}

/// Record a sanitized maintenance event in `audit_entries` within the active transaction.
pub async fn insert_audit_entry(
    tx: &mut DbTx,
    action: &str,
    target: &str,
    data: &serde_json::Value,
) -> Result<()> {
    let audit_id = Uuid::new_v4().simple().to_string();
    let logged_time = now_unix_seconds();
    let payload_str = data.to_string();

    match tx {
        DbTx::Sqlite(t) => {
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, ?, NULL, ?, ?, 0, NULL, ?)",
            )
            .bind(&audit_id)
            .bind(action)
            .bind(target)
            .bind(&payload_str)
            .bind(logged_time)
            .execute(&mut **t)
            .await?;
        }
        DbTx::Mysql(t) => {
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, ?, NULL, ?, ?, 0, NULL, ?)",
            )
            .bind(&audit_id)
            .bind(action)
            .bind(target)
            .bind(&payload_str)
            .bind(logged_time)
            .execute(&mut **t)
            .await?;
        }
        DbTx::Postgres(t) => {
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES ($1, $2, NULL, $3, $4::json, 0, NULL, $5)",
            )
            .bind(&audit_id)
            .bind(action)
            .bind(target)
            .bind(&payload_str)
            .bind(logged_time)
            .execute(&mut **t)
            .await?;
        }
    }
    Ok(())
}

/// Group policy rows by `user_id` -> `BTreeMap<AuthPurpose, PolicyRow>`.
#[must_use]
pub fn group_policies_by_user(
    rows: Vec<UserPolicyRow>,
) -> BTreeMap<Uuid, BTreeMap<AuthPurpose, PolicyRow>> {
    let mut map: BTreeMap<Uuid, BTreeMap<AuthPurpose, PolicyRow>> = BTreeMap::new();
    for row in rows {
        map.entry(row.user_id)
            .or_default()
            .insert(row.policy.purpose, row.policy);
    }
    map
}
