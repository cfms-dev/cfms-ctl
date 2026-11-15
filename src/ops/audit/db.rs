//! Multi-backend schema preflight, parameterized filter compilation, streaming export, and batch delete.

use std::collections::{BTreeMap, HashMap};
use futures_util::TryStreamExt;
use indicatif::ProgressBar;
use serde_json::Value;
use sqlx::types::Json;
use sqlx::{ColumnIndex, Database, Decode, Row, Type, mysql::MySqlRow, postgres::PgRow, sqlite::SqliteRow};
use uuid::Uuid;
use crate::core::error::{CfmsError, Result};
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::SchemaInspector;
use crate::ops::audit::archive::{AuditEntryRow, StagedArchiveWriter};
use crate::ops::audit::filter::ResolvedAuditFilter;

const REQUIRED_AUDIT_TABLES: [&str; 3] = ["audit_entries", "users", "options"];
const SQLITE_SAFE_BIND_CAP: usize = 500;
const NETWORK_DB_SAFE_BIND_CAP: usize = 5_000;
const SQLITE_MAX_FILTER_BINDS: usize = 900;

/// Database inspection aggregates returned before export or purge.
#[derive(Debug, Clone, Default)]
pub struct AuditDbInspectStats {
    pub matched_entries: u64,
    pub oldest_logged_time: Option<f64>,
    pub newest_logged_time: Option<f64>,
    pub by_action: BTreeMap<String, u64>,
    pub by_result: BTreeMap<i32, u64>,
}

/// Filter compiled against resolved DB usernames and dialect bind rules.
#[derive(Debug, Clone)]
pub struct CompiledAuditFilter {
    pub unresolved_usernames: Vec<String>,
    impossible: bool,
    where_sql: String,
    binds: Vec<SqlBind>,
}

#[derive(Debug, Clone)]
enum SqlBind {
    Text(String),
    I32(i32),
    F64(f64),
    Uuid(Uuid),
}

trait AuditUuidColumn {
    fn decode_uuid_col(&self, col: &str) -> Result<Option<Uuid>>;
}

impl AuditUuidColumn for SqliteRow {
    fn decode_uuid_col(&self, col: &str) -> Result<Option<Uuid>> {
        match self.try_get::<Option<String>, _>(col) {
            Ok(Some(raw)) => parse_uuid_text(&raw, col).map(Some),
            Ok(None) => Ok(None),
            Err(text_err) => match self.try_get::<Option<Vec<u8>>, _>(col) {
                Ok(Some(bytes)) => Uuid::from_slice(&bytes).map(Some).map_err(|e| {
                    CfmsError::Database(format!("Invalid binary UUID in `{col}`: {e}"))
                }),
                Ok(None) => Ok(None),
                Err(_) => Err(text_err.into()),
            },
        }
    }
}

impl AuditUuidColumn for MySqlRow {
    fn decode_uuid_col(&self, col: &str) -> Result<Option<Uuid>> {
        match self.try_get::<Option<String>, _>(col)? {
            Some(raw) => parse_uuid_text(&raw, col).map(Some),
            None => Ok(None),
        }
    }
}

impl AuditUuidColumn for PgRow {
    fn decode_uuid_col(&self, col: &str) -> Result<Option<Uuid>> {
        Ok(self.try_get::<Option<Uuid>, _>(col)?)
    }
}

fn parse_uuid_text(raw: &str, col: &str) -> Result<Uuid> {
    Uuid::parse_str(raw.trim()).map_err(|e| {
        CfmsError::Database(format!("Invalid UUID '{raw}' in column `{col}`: {e}"))
    })
}

/// Maximum number of `IN (...)` IDs allowed in a single delete batch for `kind`.
#[must_use]
pub const fn dialect_delete_chunk_cap(kind: DatabaseKind) -> usize {
    match kind {
        DatabaseKind::Sqlite => SQLITE_SAFE_BIND_CAP,
        DatabaseKind::Mysql | DatabaseKind::Postgresql => NETWORK_DB_SAFE_BIND_CAP,
    }
}

/// Verify `audit_entries`, `users`, and `options` tables and columns exist without drift.
pub async fn preflight_audit_schema(pool: &DbPool) -> Result<()> {
    let report = SchemaInspector::inspect(pool).await?;

    let missing: Vec<&str> = REQUIRED_AUDIT_TABLES
        .iter()
        .copied()
        .filter(|tbl| report.missing_tables.iter().any(|m| m == tbl))
        .collect();
    if !missing.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database is missing required audit tables ({}); run `cfms-ctl database upgrade` first",
            missing.join(", ")
        )));
    }

    let relevant_drift: Vec<&str> = report
        .column_mismatches
        .iter()
        .map(String::as_str)
        .filter(|msg| {
            msg.starts_with("audit_entries.")
                || msg.starts_with("users.")
                || msg.starts_with("options.")
        })
        .collect();
    if !relevant_drift.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database schema has column drift in audit-related tables ({}); run `cfms-ctl database check` for details",
            relevant_drift.join("; ")
        )));
    }

    Ok(())
}

/// Resolve usernames against `users` and compile parameterized `WHERE` SQL for `pool`.
pub async fn compile_filter(
    pool: &DbPool,
    filter: &ResolvedAuditFilter,
) -> Result<CompiledAuditFilter> {
    let kind = pool.kind();
    let (resolved_user_ids, unresolved_usernames) =
        resolve_usernames(pool, &filter.usernames).await?;

    let mut actor_ids = filter.user_ids.clone();
    for id in resolved_user_ids {
        if !actor_ids.contains(&id) {
            actor_ids.push(id);
        }
    }
    let has_actor_filter = !filter.usernames.is_empty() || !filter.user_ids.is_empty();
    let impossible = has_actor_filter && actor_ids.is_empty();

    let mut builder = SqlPredicateBuilder::new(kind);
    if impossible {
        builder.push_clause("1 = 0");
    } else {
        if let Some(after) = filter.after_unix {
            builder.push_cmp("logged_time", ">=", SqlBind::F64(after));
        }
        if let Some(before) = filter.before_unix {
            builder.push_cmp("logged_time", "<", SqlBind::F64(before));
        }
        if !filter.actions.is_empty() {
            builder.push_in(
                "action",
                false,
                filter.actions.iter().cloned().map(SqlBind::Text),
            );
        }
        if !filter.exclude_actions.is_empty() {
            builder.push_in(
                "action",
                true,
                filter.exclude_actions.iter().cloned().map(SqlBind::Text),
            );
        }
        if has_actor_filter {
            builder.push_in("user_id", false, actor_ids.into_iter().map(SqlBind::Uuid));
        }
        if !filter.targets.is_empty() {
            builder.push_in(
                "target",
                false,
                filter.targets.iter().cloned().map(SqlBind::Text),
            );
        }
        if !filter.results.is_empty() {
            builder.push_in("result", false, filter.results.iter().copied().map(SqlBind::I32));
        }
        if !filter.remote_addresses.is_empty() {
            builder.push_in(
                "remote_address",
                false,
                filter.remote_addresses.iter().cloned().map(SqlBind::Text),
            );
        }
    }

    let (where_sql, binds) = builder.finish();
    if kind == DatabaseKind::Sqlite && binds.len() > SQLITE_MAX_FILTER_BINDS {
        return Err(CfmsError::InvalidArgument(format!(
            "Too many combined filter values ({} > SQLite limit {SQLITE_MAX_FILTER_BINDS}); narrow the filter list",
            binds.len()
        )));
    }

    Ok(CompiledAuditFilter {
        unresolved_usernames,
        impossible,
        where_sql,
        binds,
    })
}

async fn resolve_usernames(
    pool: &DbPool,
    usernames: &[String],
) -> Result<(Vec<Uuid>, Vec<String>)> {
    if usernames.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let kind = pool.kind();
    let chunk_cap = dialect_delete_chunk_cap(kind);
    let mut name_to_id: HashMap<String, Uuid> = HashMap::with_capacity(usernames.len());

    for chunk in usernames.chunks(chunk_cap) {
        let mut ph = Vec::with_capacity(chunk.len());
        let mut binds = Vec::with_capacity(chunk.len());
        for (idx, uname) in chunk.iter().enumerate() {
            ph.push(placeholder(kind, idx + 1));
            binds.push(SqlBind::Text(uname.clone()));
        }
        let sql = format!(
            "SELECT username, id FROM users WHERE username IN ({})",
            ph.join(", ")
        );
        match pool {
            DbPool::Sqlite(p) => {
                collect_username_rows(
                    bind_sqlite(sqlx::query(sqlx::AssertSqlSafe(sql.as_str())), &binds)
                        .fetch_all(p)
                        .await?,
                    &mut name_to_id,
                )?;
            }
            DbPool::Mysql(p) => {
                collect_username_rows(
                    bind_mysql(sqlx::query(sqlx::AssertSqlSafe(sql.as_str())), &binds)
                        .fetch_all(p)
                        .await?,
                    &mut name_to_id,
                )?;
            }
            DbPool::Postgres(p) => {
                collect_username_rows(
                    bind_pg(sqlx::query(sqlx::AssertSqlSafe(sql.as_str())), &binds)
                        .fetch_all(p)
                        .await?,
                    &mut name_to_id,
                )?;
            }
        }
    }

    let mut resolved = Vec::with_capacity(name_to_id.len());
    let mut unresolved = Vec::new();
    for uname in usernames {
        if let Some(uid) = name_to_id.get(uname) {
            if !resolved.contains(uid) {
                resolved.push(*uid);
            }
        } else {
            unresolved.push(uname.clone());
        }
    }
    Ok((resolved, unresolved))
}

fn collect_username_rows<R>(rows: Vec<R>, out: &mut HashMap<String, Uuid>) -> Result<()>
where
    R: Row + AuditUuidColumn,
    for<'c> &'c str: ColumnIndex<R>,
    for<'c> String: Decode<'c, R::Database> + Type<R::Database>,
{
    for row in rows {
        let uname: String = row.try_get("username")?;
        let id = row
            .decode_uuid_col("id")?
            .ok_or_else(|| CfmsError::Database(format!("User '{uname}' has NULL id")))?;
        out.insert(uname, id);
    }
    Ok(())
}

/// Inspect eligible row counts, time bounds, and action/result histograms inside one snapshot tx.
pub async fn inspect_audit_entries(
    pool: &DbPool,
    filter: &CompiledAuditFilter,
) -> Result<AuditDbInspectStats> {
    if filter.impossible {
        return Ok(AuditDbInspectStats::default());
    }

    let summary_sql = format!(
        "SELECT COUNT(*) AS cnt, MIN(logged_time) AS min_ts, MAX(logged_time) AS max_ts FROM audit_entries WHERE {}",
        filter.where_sql
    );
    let action_sql = format!(
        "SELECT action, COUNT(*) AS cnt FROM audit_entries WHERE {} GROUP BY action ORDER BY action ASC",
        filter.where_sql
    );
    let result_sql = format!(
        "SELECT result, COUNT(*) AS cnt FROM audit_entries WHERE {} GROUP BY result ORDER BY result ASC",
        filter.where_sql
    );

    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            let sum_row = bind_sqlite(
                sqlx::query(sqlx::AssertSqlSafe(summary_sql.as_str())),
                &filter.binds,
            )
            .fetch_one(&mut *tx)
            .await?;
            let action_rows = bind_sqlite(
                sqlx::query(sqlx::AssertSqlSafe(action_sql.as_str())),
                &filter.binds,
            )
            .fetch_all(&mut *tx)
            .await?;
            let res_rows = bind_sqlite(
                sqlx::query(sqlx::AssertSqlSafe(result_sql.as_str())),
                &filter.binds,
            )
            .fetch_all(&mut *tx)
            .await?;
            tx.commit().await?;
            aggregate_inspect_stats(&sum_row, &action_rows, &res_rows)
        }
        DbPool::Mysql(p) => {
            let mut tx = p.begin().await?;
            let sum_row = bind_mysql(
                sqlx::query(sqlx::AssertSqlSafe(summary_sql.as_str())),
                &filter.binds,
            )
            .fetch_one(&mut *tx)
            .await?;
            let action_rows = bind_mysql(
                sqlx::query(sqlx::AssertSqlSafe(action_sql.as_str())),
                &filter.binds,
            )
            .fetch_all(&mut *tx)
            .await?;
            let res_rows = bind_mysql(
                sqlx::query(sqlx::AssertSqlSafe(result_sql.as_str())),
                &filter.binds,
            )
            .fetch_all(&mut *tx)
            .await?;
            tx.commit().await?;
            aggregate_inspect_stats(&sum_row, &action_rows, &res_rows)
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *tx)
                .await?;
            let sum_row = bind_pg(
                sqlx::query(sqlx::AssertSqlSafe(summary_sql.as_str())),
                &filter.binds,
            )
            .fetch_one(&mut *tx)
            .await?;
            let action_rows = bind_pg(
                sqlx::query(sqlx::AssertSqlSafe(action_sql.as_str())),
                &filter.binds,
            )
            .fetch_all(&mut *tx)
            .await?;
            let res_rows = bind_pg(
                sqlx::query(sqlx::AssertSqlSafe(result_sql.as_str())),
                &filter.binds,
            )
            .fetch_all(&mut *tx)
            .await?;
            tx.commit().await?;
            aggregate_inspect_stats(&sum_row, &action_rows, &res_rows)
        }
    }
}

fn aggregate_inspect_stats<R>(
    sum_row: &R,
    action_rows: &[R],
    res_rows: &[R],
) -> Result<AuditDbInspectStats>
where
    R: Row,
    for<'c> &'c str: ColumnIndex<R>,
    for<'c> i64: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> i32: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> Option<f64>: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> String: Decode<'c, R::Database> + Type<R::Database>,
{
    let cnt: i64 = sum_row.try_get("cnt")?;
    let mut stats = AuditDbInspectStats {
        matched_entries: u64::try_from(cnt).unwrap_or(0),
        oldest_logged_time: sum_row.try_get("min_ts")?,
        newest_logged_time: sum_row.try_get("max_ts")?,
        ..Default::default()
    };

    for row in action_rows {
        let act: String = row.try_get("action")?;
        let c: i64 = row.try_get("cnt")?;
        stats.by_action.insert(act, u64::try_from(c).unwrap_or(0));
    }
    for row in res_rows {
        let code: i32 = row.try_get("result")?;
        let c: i64 = row.try_get("cnt")?;
        stats.by_result.insert(code, u64::try_from(c).unwrap_or(0));
    }

    Ok(stats)
}

/// Stream matching `audit_entries` ordered by `(logged_time ASC, id ASC)` into `writer`.
pub async fn stream_export_entries(
    pool: &DbPool,
    filter: &CompiledAuditFilter,
    writer: &mut StagedArchiveWriter,
    progress: Option<&ProgressBar>,
) -> Result<()> {
    if filter.impossible {
        return Ok(());
    }

    let select_sql = format!(
        "SELECT id, action, user_id, target, data, result, remote_address, logged_time FROM audit_entries WHERE {} ORDER BY logged_time ASC, id ASC",
        filter.where_sql
    );

    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            {
                let mut stream = bind_sqlite(
                    sqlx::query(sqlx::AssertSqlSafe(select_sql.as_str())),
                    &filter.binds,
                )
                .fetch(&mut *tx);
                while let Some(row) = stream.try_next().await? {
                    let entry = decode_audit_entry(&row)?;
                    writer.write_entry(&entry)?;
                    if let Some(pb) = progress {
                        pb.inc(1);
                    }
                }
            }
            tx.commit().await?;
        }
        DbPool::Mysql(p) => {
            let mut tx = p.begin().await?;
            {
                let mut stream = bind_mysql(
                    sqlx::query(sqlx::AssertSqlSafe(select_sql.as_str())),
                    &filter.binds,
                )
                .fetch(&mut *tx);
                while let Some(row) = stream.try_next().await? {
                    let entry = decode_audit_entry(&row)?;
                    writer.write_entry(&entry)?;
                    if let Some(pb) = progress {
                        pb.inc(1);
                    }
                }
            }
            tx.commit().await?;
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *tx)
                .await?;
            {
                let mut stream = bind_pg(
                    sqlx::query(sqlx::AssertSqlSafe(select_sql.as_str())),
                    &filter.binds,
                )
                .fetch(&mut *tx);
                while let Some(row) = stream.try_next().await? {
                    let entry = decode_audit_entry(&row)?;
                    writer.write_entry(&entry)?;
                    if let Some(pb) = progress {
                        pb.inc(1);
                    }
                }
            }
            tx.commit().await?;
        }
    }

    Ok(())
}

fn decode_audit_entry<R>(row: &R) -> Result<AuditEntryRow>
where
    R: Row + AuditUuidColumn,
    for<'c> &'c str: ColumnIndex<R>,
    for<'c> String: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> Option<String>: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> Option<Json<Value>>: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> i32: Decode<'c, R::Database> + Type<R::Database>,
    for<'c> f64: Decode<'c, R::Database> + Type<R::Database>,
{
    let id: String = row.try_get("id")?;
    let action: String = row.try_get("action")?;
    let user_id = row
        .decode_uuid_col("user_id")?
        .map(|u| u.hyphenated().to_string());
    let target: Option<String> = row.try_get("target")?;
    let data: Option<Json<Value>> = row.try_get("data").map_err(|e| {
        CfmsError::Database(format!(
            "Failed to decode JSON column `data` for audit entry '{id}': {e}"
        ))
    })?;
    let result: i32 = row.try_get("result")?;
    let remote_address: Option<String> = row.try_get("remote_address")?;
    let logged_time: f64 = row.try_get("logged_time")?;
    if !logged_time.is_finite() {
        return Err(CfmsError::Database(format!(
            "Audit entry '{id}' has non-finite `logged_time` ({logged_time})"
        )));
    }

    Ok(AuditEntryRow {
        id,
        action,
        user_id,
        target,
        data: data.map(|j| j.0),
        result,
        remote_address,
        logged_time,
    })
}

/// Delete one batch of `audit_entries` primary keys inside a transaction, returning rows deleted.
pub async fn delete_id_batch(pool: &DbPool, ids: &[String]) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }

    let kind = pool.kind();
    let chunk_cap = dialect_delete_chunk_cap(kind);
    let mut deleted_total: u64 = 0;

    for chunk in ids.chunks(chunk_cap) {
        let ph: Vec<String> = (1..=chunk.len()).map(|i| placeholder(kind, i)).collect();
        let sql = format!("DELETE FROM audit_entries WHERE id IN ({})", ph.join(", "));
        let affected = match pool {
            DbPool::Sqlite(p) => {
                let mut conn = p.acquire().await?;
                sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
                for id in chunk {
                    q = q.bind(id.as_str());
                }
                match q.execute(&mut *conn).await {
                    Ok(done) => {
                        sqlx::query("COMMIT").execute(&mut *conn).await?;
                        done.rows_affected()
                    }
                    Err(err) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(err.into());
                    }
                }
            }
            DbPool::Mysql(p) => {
                let mut tx = p.begin().await?;
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
                for id in chunk {
                    q = q.bind(id.as_str());
                }
                let done = q.execute(&mut *tx).await?;
                tx.commit().await?;
                done.rows_affected()
            }
            DbPool::Postgres(p) => {
                let mut tx = p.begin().await?;
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
                for id in chunk {
                    q = q.bind(id.as_str());
                }
                let done = q.execute(&mut *tx).await?;
                tx.commit().await?;
                done.rows_affected()
            }
        };
        deleted_total = deleted_total.saturating_add(affected);
    }

    Ok(deleted_total)
}

fn placeholder(kind: DatabaseKind, one_based_idx: usize) -> String {
    match kind {
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "?".to_string(),
        DatabaseKind::Postgresql => format!("${one_based_idx}"),
    }
}

struct SqlPredicateBuilder {
    kind: DatabaseKind,
    clauses: Vec<String>,
    binds: Vec<SqlBind>,
}

impl SqlPredicateBuilder {
    fn new(kind: DatabaseKind) -> Self {
        Self {
            kind,
            clauses: Vec::new(),
            binds: Vec::new(),
        }
    }

    fn next_placeholder(&self) -> String {
        placeholder(self.kind, self.binds.len() + 1)
    }

    fn push_clause(&mut self, literal: &str) {
        self.clauses.push(literal.to_string());
    }

    fn push_cmp(&mut self, column: &str, op: &str, bind: SqlBind) {
        let ph = self.next_placeholder();
        self.binds.push(bind);
        self.clauses.push(format!("{column} {op} {ph}"));
    }

    fn push_in(
        &mut self,
        column: &str,
        negate: bool,
        items: impl IntoIterator<Item = SqlBind>,
    ) {
        let mut ph = Vec::new();
        for item in items {
            ph.push(self.next_placeholder());
            self.binds.push(item);
        }
        if !ph.is_empty() {
            let kw = if negate { "NOT IN" } else { "IN" };
            self.clauses.push(format!("{column} {kw} ({})", ph.join(", ")));
        }
    }

    fn finish(self) -> (String, Vec<SqlBind>) {
        if self.clauses.is_empty() {
            ("1 = 1".to_string(), self.binds)
        } else {
            (self.clauses.join(" AND "), self.binds)
        }
    }
}

fn bind_sqlite<'q>(
    mut q: sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as Database>::Arguments>,
    binds: &'q [SqlBind],
) -> sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as Database>::Arguments> {
    for b in binds {
        q = match b {
            SqlBind::Text(s) => q.bind(s.as_str()),
            SqlBind::I32(v) => q.bind(*v),
            SqlBind::F64(v) => q.bind(*v),
            SqlBind::Uuid(u) => q.bind(u.simple().to_string()),
        };
    }
    q
}

fn bind_mysql<'q>(
    mut q: sqlx::query::Query<'q, sqlx::MySql, <sqlx::MySql as Database>::Arguments>,
    binds: &'q [SqlBind],
) -> sqlx::query::Query<'q, sqlx::MySql, <sqlx::MySql as Database>::Arguments> {
    for b in binds {
        q = match b {
            SqlBind::Text(s) => q.bind(s.as_str()),
            SqlBind::I32(v) => q.bind(*v),
            SqlBind::F64(v) => q.bind(*v),
            SqlBind::Uuid(u) => q.bind(u.simple().to_string()),
        };
    }
    q
}

fn bind_pg<'q>(
    mut q: sqlx::query::Query<'q, sqlx::Postgres, <sqlx::Postgres as Database>::Arguments>,
    binds: &'q [SqlBind],
) -> sqlx::query::Query<'q, sqlx::Postgres, <sqlx::Postgres as Database>::Arguments> {
    for b in binds {
        q = match b {
            SqlBind::Text(s) => q.bind(s.as_str()),
            SqlBind::I32(v) => q.bind(*v),
            SqlBind::F64(v) => q.bind(*v),
            SqlBind::Uuid(u) => q.bind(*u),
        };
    }
    q
}
