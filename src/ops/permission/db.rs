//! Database schema preflight, inspection queries, online-safe batch purging,
//! and row-locked default permission synchronization across SQLite, MySQL, and PostgreSQL.

use std::collections::{BTreeMap, BTreeSet};

use indicatif::ProgressBar;
use serde::Serialize;
use serde_json::json;
use sqlx::Row;

use crate::cli::permission::PermissionScope;
use crate::core::error::{CfmsError, Result};
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::SchemaInspector;
use crate::ops::audit::db::dialect_delete_chunk_cap;
use crate::ops::permission::defaults::DefaultGroupPermissions;
use crate::ops::permission::policy::ResolvedPurgeConfig;
use crate::ops::user::db::{DbExec, DbTx, insert_audit_entry};

const PURGE_REQUIRED_TABLES: &[&str] = &[
    "user_permissions",
    "group_permissions",
    "options",
    "audit_entries",
];
const SYNC_REQUIRED_TABLES: &[&str] = &["user_groups", "group_permissions", "audit_entries"];

const SQLITE_INSERT_CHUNK_ROWS: usize = 100;
const NETWORK_INSERT_CHUNK_ROWS: usize = 1_000;

/// Permission table selector (`user_permissions` vs `group_permissions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionTable {
    User,
    Group,
}

impl PermissionTable {
    #[must_use]
    pub const fn table_name(self) -> &'static str {
        match self {
            Self::User => "user_permissions",
            Self::Group => "group_permissions",
        }
    }

    #[must_use]
    pub const fn index_name(self) -> &'static str {
        match self {
            Self::User => "ix_user_permissions_end_time_id",
            Self::Group => "ix_group_permissions_end_time_id",
        }
    }
}

/// Aggregated inspection or deletion tallies for a single permission table.
#[derive(Debug, Clone, Default)]
pub struct TablePurgeTally {
    pub total: u64,
    pub grants: u64,
    pub revocations: u64,
    pub oldest_end_time: Option<f64>,
    pub newest_end_time: Option<f64>,
    pub batches_executed: u64,
}

/// Aggregated preview across selected permission tables before deletion.
#[derive(Debug, Clone, Default)]
pub struct PurgeInspection {
    pub user: TablePurgeTally,
    pub group: TablePurgeTally,
}

impl PurgeInspection {
    #[must_use]
    pub const fn total_eligible(&self) -> u64 {
        self.user.total + self.group.total
    }

    #[must_use]
    pub const fn grants_eligible(&self) -> u64 {
        self.user.grants + self.group.grants
    }

    #[must_use]
    pub const fn revocations_eligible(&self) -> u64 {
        self.user.revocations + self.group.revocations
    }

    #[must_use]
    pub fn oldest_end_time(&self) -> Option<f64> {
        match (self.user.oldest_end_time, self.group.oldest_end_time) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    #[must_use]
    pub fn newest_end_time(&self) -> Option<f64> {
        match (self.user.newest_end_time, self.group.newest_end_time) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
}

/// Execution outcome of running the batched purge loop.
#[derive(Debug, Clone, Default)]
pub struct PurgeExecutionOutcome {
    pub user: TablePurgeTally,
    pub group: TablePurgeTally,
    pub audit_logged: bool,
}

impl PurgeExecutionOutcome {
    #[must_use]
    pub const fn total_purged(&self) -> u64 {
        self.user.total + self.group.total
    }

    #[must_use]
    pub const fn grants_purged(&self) -> u64 {
        self.user.grants + self.group.grants
    }

    #[must_use]
    pub const fn revocations_purged(&self) -> u64 {
        self.user.revocations + self.group.revocations
    }

    #[must_use]
    pub const fn batches_executed(&self) -> u64 {
        self.user.batches_executed + self.group.batches_executed
    }
}

#[derive(Debug, Clone)]
struct ExistingGroupPermRow {
    group_name: String,
    permission: String,
    granted: bool,
    start_time: f64,
    end_time: Option<f64>,
}

/// Sync state for a single default group (`user` or `sysop`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GroupSyncStatus {
    pub group_name: String,
    pub status: String,
    pub group_exists: bool,
    pub expected_count: u64,
    pub present_count: u64,
    pub active_grant_count: u64,
    pub inactive_or_revoked_count: u64,
    pub missing_permissions: Vec<String>,
    pub inactive_or_revoked_permissions: Vec<String>,
    pub inserted_permissions: Vec<String>,
}

/// Combined inspection or apply state across all selected target default groups.
#[derive(Debug, Clone)]
pub struct SyncInspectionResult {
    pub group_details: Vec<GroupSyncStatus>,
    pub missing_groups: Vec<String>,
    pub missing_by_group: BTreeMap<String, Vec<String>>,
    pub missing_count: u64,
    pub inserted_count: u64,
    pub audit_logged: bool,
}

impl SyncInspectionResult {
    #[must_use]
    pub fn in_sync(&self) -> bool {
        self.missing_count == 0 && self.missing_groups.is_empty()
    }
}

/// Verify required tables/columns for `purge-expired` and return non-fatal index warnings.
pub async fn preflight_purge_schema(
    pool: &DbPool,
    scope: PermissionScope,
) -> Result<Vec<String>> {
    let report = SchemaInspector::inspect(pool).await?;
    check_required_tables(&report, PURGE_REQUIRED_TABLES, "permission purge")?;

    let mut warnings = Vec::new();
    let mut tables = Vec::new();
    if scope.includes_user() {
        tables.push(PermissionTable::User);
    }
    if scope.includes_group() {
        tables.push(PermissionTable::Group);
    }

    for tbl in tables {
        let missing_idx_msg = format!("{}: missing INDEX '{}'", tbl.table_name(), tbl.index_name());
        if report.index_mismatches.iter().any(|m| m == &missing_idx_msg) {
            warnings.push(format!(
                "Index '{}' is missing on `{}`; batch purge may fall back to table scans — run `cfms-ctl database upgrade` when convenient",
                tbl.index_name(),
                tbl.table_name()
            ));
        }
    }

    Ok(warnings)
}

/// Verify required tables/columns for `sync-defaults`.
pub async fn preflight_sync_schema(pool: &DbPool) -> Result<()> {
    let report = SchemaInspector::inspect(pool).await?;
    check_required_tables(&report, SYNC_REQUIRED_TABLES, "permission sync")
}

fn check_required_tables(
    report: &crate::db::schema::SchemaDriftReport,
    required_tables: &[&str],
    context_label: &str,
) -> Result<()> {
    let missing: Vec<&str> = required_tables
        .iter()
        .copied()
        .filter(|tbl| report.missing_tables.iter().any(|m| m == tbl))
        .collect();
    if !missing.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database is missing required tables for {context_label} ({}); run `cfms-ctl database upgrade` first",
            missing.join(", ")
        )));
    }

    let drift: Vec<&str> = report
        .column_mismatches
        .iter()
        .map(String::as_str)
        .filter(|msg| {
            required_tables
                .iter()
                .any(|tbl| msg.starts_with(&format!("{tbl}.")))
        })
        .collect();
    if !drift.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Database schema has column drift in {context_label} tables ({}); run `cfms-ctl database check` for details",
            drift.join("; ")
        )));
    }

    Ok(())
}

/// Read-only inspection of expired entries matching `end_time IS NOT NULL AND end_time < cutoff`.
pub async fn inspect_expired_permissions(
    pool: &DbPool,
    scope: PermissionScope,
    cutoff_timestamp: f64,
) -> Result<PurgeInspection> {
    let mut result = PurgeInspection::default();
    if scope.includes_user() {
        result.user = inspect_expired_table(pool, PermissionTable::User, cutoff_timestamp).await?;
    }
    if scope.includes_group() {
        result.group =
            inspect_expired_table(pool, PermissionTable::Group, cutoff_timestamp).await?;
    }
    Ok(result)
}

async fn inspect_expired_table(
    pool: &DbPool,
    table: PermissionTable,
    cutoff: f64,
) -> Result<TablePurgeTally> {
    let tname = table.table_name();
    let placeholder = match pool.kind() {
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "?",
        DatabaseKind::Postgresql => "$1",
    };
    let sql = format!(
        "SELECT granted, COUNT(*) AS cnt, MIN(end_time) AS min_ts, MAX(end_time) AS max_ts \
         FROM {tname} \
         WHERE end_time IS NOT NULL AND end_time < {placeholder} \
         GROUP BY granted"
    );

    let mut tally = TablePurgeTally::default();
    macro_rules! run_inspect {
        ($exec:expr) => {{
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(cutoff)
                .fetch_all($exec)
                .await?;
            for row in rows {
                accumulate_inspect_row(
                    row.try_get::<bool, _>("granted")?,
                    row.try_get::<i64, _>("cnt")?,
                    row.try_get::<Option<f64>, _>("min_ts")?,
                    row.try_get::<Option<f64>, _>("max_ts")?,
                    &mut tally,
                )?;
            }
        }};
    }

    match pool {
        DbPool::Sqlite(p) => run_inspect!(p),
        DbPool::Mysql(p) => run_inspect!(p),
        DbPool::Postgres(p) => run_inspect!(p),
    }

    Ok(tally)
}

fn accumulate_inspect_row(
    granted: bool,
    cnt: i64,
    min_ts: Option<f64>,
    max_ts: Option<f64>,
    tally: &mut TablePurgeTally,
) -> Result<()> {
    let count = u64::try_from(cnt).map_err(|_| {
        CfmsError::Database(format!("Negative row count returned from database: {cnt}"))
    })?;
    tally.total += count;
    if granted {
        tally.grants += count;
    } else {
        tally.revocations += count;
    }
    if let Some(min_val) = min_ts {
        tally.oldest_end_time = Some(
            tally
                .oldest_end_time
                .map_or(min_val, |prev| prev.min(min_val)),
        );
    }
    if let Some(max_val) = max_ts {
        tally.newest_end_time = Some(
            tally
                .newest_end_time
                .map_or(max_val, |prev| prev.max(max_val)),
        );
    }
    Ok(())
}

/// Delete all expired permission rows across `scope` in short per-batch transactions,
/// then record one `audit_entries` row if at least one entry was purged.
pub async fn purge_expired_permissions(
    pool: &DbPool,
    scope: PermissionScope,
    config: &ResolvedPurgeConfig,
    progress: &ProgressBar,
) -> Result<PurgeExecutionOutcome> {
    let mut outcome = PurgeExecutionOutcome::default();

    if scope.includes_user() {
        outcome.user = purge_table_in_batches(
            pool,
            PermissionTable::User,
            config.cutoff_timestamp,
            config.batch_size,
            progress,
            &outcome,
        )
        .await?;
    }

    if scope.includes_group() {
        outcome.group = purge_table_in_batches(
            pool,
            PermissionTable::Group,
            config.cutoff_timestamp,
            config.batch_size,
            progress,
            &outcome,
        )
        .await?;
    }

    if outcome.total_purged() > 0 {
        let audit_data = json!({
            "scope": scope.as_str(),
            "cutoff_timestamp": config.cutoff_timestamp,
            "cutoff_utc": config.cutoff_utc,
            "cutoff_source": config.cutoff_source.as_str(),
            "retention_days": config.retention_days,
            "batch_size": config.batch_size,
            "user_entries": outcome.user.total,
            "group_entries": outcome.group.total,
            "grants": outcome.grants_purged(),
            "revocations": outcome.revocations_purged(),
            "total_purged": outcome.total_purged(),
            "batches_executed": outcome.batches_executed(),
        });
        let mut tx = DbTx::begin(pool).await?;
        insert_audit_entry(&mut tx, "purge_expired_permissions", scope.as_str(), &audit_data)
            .await?;
        tx.commit().await?;
        outcome.audit_logged = true;
    }

    Ok(outcome)
}

async fn purge_table_in_batches(
    pool: &DbPool,
    table: PermissionTable,
    cutoff: f64,
    batch_size: usize,
    progress: &ProgressBar,
    prior_outcome: &PurgeExecutionOutcome,
) -> Result<TablePurgeTally> {
    let mut tally = TablePurgeTally::default();

    loop {
        match delete_one_expired_batch(pool, table, cutoff, batch_size).await {
            Ok((0, 0)) => break,
            Ok((grants, revocations)) => {
                let batch_total = grants + revocations;
                tally.grants += grants;
                tally.revocations += revocations;
                tally.total += batch_total;
                tally.batches_executed += 1;
                progress.inc(batch_total);
            }
            Err(err) => {
                let already_committed = prior_outcome.total_purged() + tally.total;
                let total_batches = prior_outcome.batches_executed() + tally.batches_executed;
                if already_committed > 0 {
                    return Err(CfmsError::Database(format!(
                        "Failed while purging `{}` after {total_batches} committed batch(es) ({already_committed} rows already deleted: {} user, {} group); current batch rolled back: {err}",
                        table.table_name(),
                        prior_outcome.user.total
                            + if table == PermissionTable::User {
                                tally.total
                            } else {
                                0
                            },
                        prior_outcome.group.total
                            + if table == PermissionTable::Group {
                                tally.total
                            } else {
                                0
                            },
                    )));
                }
                return Err(err);
            }
        }
    }

    Ok(tally)
}

async fn delete_one_expired_batch(
    pool: &DbPool,
    table: PermissionTable,
    cutoff: f64,
    batch_size: usize,
) -> Result<(u64, u64)> {
    let tname = table.table_name();
    let limit_i64 = i64::try_from(batch_size)
        .map_err(|_| CfmsError::InvalidArgument("Batch size exceeds i64 range".to_string()))?;

    let mut tx = DbTx::begin(pool).await?;
    let mut grants: u64 = 0;
    let mut revocations: u64 = 0;

    match &mut tx {
        DbTx::Sqlite(t) => {
            let sql = format!(
                "DELETE FROM {tname} \
                 WHERE id IN ( \
                     SELECT id FROM {tname} \
                     WHERE end_time IS NOT NULL AND end_time < ?1 \
                     ORDER BY end_time ASC, id ASC \
                     LIMIT ?2 \
                 ) \
                 AND end_time IS NOT NULL AND end_time < ?1 \
                 RETURNING granted"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(cutoff)
                .bind(limit_i64)
                .fetch_all(&mut **t)
                .await?;
            for row in rows {
                if row.try_get::<bool, _>("granted")? {
                    grants += 1;
                } else {
                    revocations += 1;
                }
            }
        }
        DbTx::Postgres(t) => {
            let sql = format!(
                "WITH delete_batch AS ( \
                     SELECT id FROM {tname} \
                     WHERE end_time IS NOT NULL AND end_time < $1 \
                     ORDER BY end_time ASC, id ASC \
                     LIMIT $2 \
                     FOR UPDATE SKIP LOCKED \
                 ) \
                 DELETE FROM {tname} AS t \
                 USING delete_batch AS b \
                 WHERE t.id = b.id \
                   AND t.end_time IS NOT NULL AND t.end_time < $1 \
                 RETURNING t.granted"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(cutoff)
                .bind(limit_i64)
                .fetch_all(&mut **t)
                .await?;
            for row in rows {
                if row.try_get::<bool, _>("granted")? {
                    grants += 1;
                } else {
                    revocations += 1;
                }
            }
        }
        DbTx::Mysql(t) => {
            let select_sql = format!(
                "SELECT CAST(id AS SIGNED) AS id, granted FROM {tname} \
                 WHERE end_time IS NOT NULL AND end_time < ? \
                 ORDER BY end_time ASC, id ASC \
                 LIMIT ? \
                 FOR UPDATE"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(select_sql))
                .bind(cutoff)
                .bind(limit_i64)
                .fetch_all(&mut **t)
                .await?;
            if rows.is_empty() {
                tx.commit().await?;
                return Ok((0, 0));
            }

            let mut ids = Vec::with_capacity(rows.len());
            for row in rows {
                ids.push(row.try_get::<i64, _>("id")?);
                if row.try_get::<bool, _>("granted")? {
                    grants += 1;
                } else {
                    revocations += 1;
                }
            }

            let chunk_cap = dialect_delete_chunk_cap(DatabaseKind::Mysql);
            for chunk in ids.chunks(chunk_cap) {
                let ph = in_placeholders(DatabaseKind::Mysql, 1, chunk.len());
                let del_sql = format!(
                    "DELETE FROM {tname} WHERE id IN ({ph}) AND end_time IS NOT NULL AND end_time < ?"
                );
                let mut query = sqlx::query(sqlx::AssertSqlSafe(del_sql));
                for &id in chunk {
                    query = query.bind(id);
                }
                query = query.bind(cutoff);
                query.execute(&mut **t).await?;
            }
        }
    }

    tx.commit().await?;
    Ok((grants, revocations))
}

/// Inspect default group permissions in read-only mode against `db_now`.
pub async fn inspect_default_groups(
    pool: &DbPool,
    defaults: &DefaultGroupPermissions,
    target_groups: &[String],
    db_now: f64,
) -> Result<SyncInspectionResult> {
    let mut exec = DbExec::Pool(pool);
    compute_sync_inspection(&mut exec, defaults, target_groups, db_now).await
}

/// Synchronize missing default group permissions inside one online-safe locked transaction.
pub async fn sync_default_groups(
    pool: &DbPool,
    defaults: &DefaultGroupPermissions,
    target_groups: &[String],
    db_now: f64,
    confirmed_missing: Option<&BTreeMap<String, Vec<String>>>,
) -> Result<SyncInspectionResult> {
    let mut tx = DbTx::begin(pool).await?;
    let mut inspection = {
        let mut exec = DbExec::Tx(&mut tx);
        compute_sync_inspection(&mut exec, defaults, target_groups, db_now).await?
    };

    if let Some(expected_map) = confirmed_missing {
        validate_confirmed_missing_unchanged(&inspection, expected_map)?;
    }

    let mut pending_rows: Vec<(&str, &str)> = Vec::new();
    for detail in &inspection.group_details {
        for perm in &detail.missing_permissions {
            pending_rows.push((detail.group_name.as_str(), perm.as_str()));
        }
    }

    if !pending_rows.is_empty() {
        let inserted = insert_missing_group_permissions(&mut tx, &pending_rows).await?;
        inspection.inserted_count = inserted;

        let mut inserted_by_group = BTreeMap::new();
        for detail in &mut inspection.group_details {
            let added = detail.missing_permissions.len() as u64;
            detail.inserted_permissions = std::mem::take(&mut detail.missing_permissions);
            if !detail.inserted_permissions.is_empty() {
                detail.present_count += added;
                detail.active_grant_count += added;
                detail.status = "in_sync".to_string();
                inserted_by_group.insert(
                    detail.group_name.clone(),
                    detail.inserted_permissions.clone(),
                );
            }
        }
        inspection.missing_by_group.clear();
        inspection.missing_count = 0;

        let target_label = target_groups.join(",");
        let audit_data = json!({
            "groups": target_groups,
            "defaults_source": defaults.source.as_str(),
            "inserted_count": inserted,
            "inserted_by_group": inserted_by_group,
            "missing_groups": inspection.missing_groups,
        });
        insert_audit_entry(
            &mut tx,
            "sync_default_group_permissions",
            &target_label,
            &audit_data,
        )
        .await?;
        inspection.audit_logged = true;
    }

    tx.commit().await?;
    Ok(inspection)
}

fn validate_confirmed_missing_unchanged(
    live: &SyncInspectionResult,
    confirmed: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    for (group, live_missing) in &live.missing_by_group {
        let Some(confirmed_perms) = confirmed.get(group) else {
            return Err(CfmsError::Database(format!(
                "Default group permissions changed concurrently for group `{group}` since confirmation preview; please re-run"
            )));
        };
        let confirmed_set: BTreeSet<&str> = confirmed_perms.iter().map(String::as_str).collect();
        let unconfirmed: Vec<&str> = live_missing
            .iter()
            .map(String::as_str)
            .filter(|perm| !confirmed_set.contains(*perm))
            .collect();
        if !unconfirmed.is_empty() {
            return Err(CfmsError::Database(format!(
                "New missing default permissions appeared concurrently for group `{group}` ({}) since confirmation preview; please re-run",
                unconfirmed.join(", ")
            )));
        }
    }
    Ok(())
}

async fn compute_sync_inspection(
    exec: &mut DbExec<'_>,
    defaults: &DefaultGroupPermissions,
    target_groups: &[String],
    db_now: f64,
) -> Result<SyncInspectionResult> {
    let mut sorted_groups: Vec<String> = target_groups.to_vec();
    sorted_groups.sort();
    sorted_groups.dedup();

    let existing_groups = fetch_target_group_names(exec, &sorted_groups).await?;
    let present_group_list: Vec<String> = sorted_groups
        .iter()
        .filter(|g| existing_groups.contains(g.as_str()))
        .cloned()
        .collect();

    let rows = if present_group_list.is_empty() {
        Vec::new()
    } else {
        fetch_group_permission_rows(exec, &present_group_list).await?
    };

    let mut rows_by_group: BTreeMap<String, Vec<ExistingGroupPermRow>> = BTreeMap::new();
    for row in rows {
        rows_by_group
            .entry(row.group_name.clone())
            .or_default()
            .push(row);
    }

    let mut group_details = Vec::with_capacity(sorted_groups.len());
    let mut missing_groups = Vec::new();
    let mut missing_by_group = BTreeMap::new();
    let mut total_missing: u64 = 0;

    for group_name in &sorted_groups {
        let expected_perms = &defaults.groups[group_name];
        let expected_count = expected_perms.len() as u64;

        if !existing_groups.contains(group_name.as_str()) {
            missing_groups.push(group_name.clone());
            group_details.push(GroupSyncStatus {
                group_name: group_name.clone(),
                status: "missing_group".to_string(),
                group_exists: false,
                expected_count,
                present_count: 0,
                active_grant_count: 0,
                inactive_or_revoked_count: 0,
                missing_permissions: Vec::new(),
                inactive_or_revoked_permissions: Vec::new(),
                inserted_permissions: Vec::new(),
            });
            continue;
        }

        let group_rows = rows_by_group
            .get(group_name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let evaluated = evaluate_group_permissions(group_name, expected_perms, group_rows, db_now);
        total_missing += evaluated.missing_permissions.len() as u64;
        if !evaluated.missing_permissions.is_empty() {
            missing_by_group.insert(group_name.clone(), evaluated.missing_permissions.clone());
        }
        group_details.push(evaluated);
    }

    Ok(SyncInspectionResult {
        group_details,
        missing_groups,
        missing_by_group,
        missing_count: total_missing,
        inserted_count: 0,
        audit_logged: false,
    })
}

fn evaluate_group_permissions(
    group_name: &str,
    expected_perms: &[String],
    rows: &[ExistingGroupPermRow],
    db_now: f64,
) -> GroupSyncStatus {
    let mut present_set = BTreeSet::new();
    let mut active_granted = BTreeSet::new();
    let mut active_revoked = BTreeSet::new();

    for row in rows {
        present_set.insert(row.permission.as_str());
        let is_active = row.start_time <= db_now && row.end_time.is_none_or(|end| end >= db_now);
        if is_active {
            if row.granted {
                active_granted.insert(row.permission.as_str());
            } else {
                active_revoked.insert(row.permission.as_str());
            }
        }
    }

    let mut present_count: u64 = 0;
    let mut active_grant_count: u64 = 0;
    let mut missing_permissions = Vec::new();
    let mut inactive_or_revoked_permissions = Vec::new();

    for perm in expected_perms {
        let p = perm.as_str();
        if !present_set.contains(p) {
            missing_permissions.push(perm.clone());
            continue;
        }
        present_count += 1;
        if active_granted.contains(p) && !active_revoked.contains(p) {
            active_grant_count += 1;
        } else {
            inactive_or_revoked_permissions.push(perm.clone());
        }
    }

    let status = if missing_permissions.is_empty() {
        "in_sync"
    } else {
        "drift"
    };

    GroupSyncStatus {
        group_name: group_name.to_string(),
        status: status.to_string(),
        group_exists: true,
        expected_count: expected_perms.len() as u64,
        present_count,
        active_grant_count,
        inactive_or_revoked_count: inactive_or_revoked_permissions.len() as u64,
        missing_permissions,
        inactive_or_revoked_permissions,
        inserted_permissions: Vec::new(),
    }
}

async fn fetch_target_group_names(
    exec: &mut DbExec<'_>,
    sorted_groups: &[String],
) -> Result<BTreeSet<String>> {
    if sorted_groups.is_empty() {
        return Ok(BTreeSet::new());
    }

    let kind = exec.kind();
    let ph = in_placeholders(kind, 1, sorted_groups.len());
    let lock_suffix = match exec {
        DbExec::Tx(DbTx::Mysql(_) | DbTx::Postgres(_)) => " ORDER BY group_name ASC FOR UPDATE",
        _ => "",
    };
    let sql = format!("SELECT group_name FROM user_groups WHERE group_name IN ({ph}){lock_suffix}");

    let mut found = BTreeSet::new();
    macro_rules! fetch_groups {
        ($conn:expr) => {{
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for g in sorted_groups {
                q = q.bind(g);
            }
            for row in q.fetch_all($conn).await? {
                found.insert(row.try_get::<String, _>("group_name")?);
            }
        }};
    }

    match exec {
        DbExec::Pool(DbPool::Sqlite(p)) => fetch_groups!(p),
        DbExec::Pool(DbPool::Mysql(p)) => fetch_groups!(p),
        DbExec::Pool(DbPool::Postgres(p)) => fetch_groups!(p),
        DbExec::Tx(DbTx::Sqlite(t)) => fetch_groups!(&mut **t),
        DbExec::Tx(DbTx::Mysql(t)) => fetch_groups!(&mut **t),
        DbExec::Tx(DbTx::Postgres(t)) => fetch_groups!(&mut **t),
    }
    Ok(found)
}

async fn fetch_group_permission_rows(
    exec: &mut DbExec<'_>,
    present_groups: &[String],
) -> Result<Vec<ExistingGroupPermRow>> {
    if present_groups.is_empty() {
        return Ok(Vec::new());
    }

    let kind = exec.kind();
    let ph = in_placeholders(kind, 1, present_groups.len());
    let lock_suffix = match exec {
        DbExec::Tx(DbTx::Mysql(_) | DbTx::Postgres(_)) => " ORDER BY id ASC FOR UPDATE",
        _ => "",
    };
    let sql = format!(
        "SELECT group_name, permission, granted, start_time, end_time \
         FROM group_permissions WHERE group_name IN ({ph}){lock_suffix}"
    );

    macro_rules! fetch_perm_rows {
        ($conn:expr) => {{
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for g in present_groups {
                q = q.bind(g);
            }
            let rows = q.fetch_all($conn).await?;
            rows.into_iter()
                .map(|r| {
                    Ok(ExistingGroupPermRow {
                        group_name: r.try_get("group_name")?,
                        permission: r.try_get("permission")?,
                        granted: r.try_get("granted")?,
                        start_time: r.try_get("start_time")?,
                        end_time: r.try_get("end_time")?,
                    })
                })
                .collect()
        }};
    }

    match exec {
        DbExec::Pool(DbPool::Sqlite(p)) => fetch_perm_rows!(p),
        DbExec::Pool(DbPool::Mysql(p)) => fetch_perm_rows!(p),
        DbExec::Pool(DbPool::Postgres(p)) => fetch_perm_rows!(p),
        DbExec::Tx(DbTx::Sqlite(t)) => fetch_perm_rows!(&mut **t),
        DbExec::Tx(DbTx::Mysql(t)) => fetch_perm_rows!(&mut **t),
        DbExec::Tx(DbTx::Postgres(t)) => fetch_perm_rows!(&mut **t),
    }
}

async fn insert_missing_group_permissions(
    tx: &mut DbTx,
    rows: &[(&str, &str)],
) -> Result<u64> {
    let kind = tx.kind();
    let chunk_size = match kind {
        DatabaseKind::Sqlite => SQLITE_INSERT_CHUNK_ROWS,
        DatabaseKind::Mysql | DatabaseKind::Postgresql => NETWORK_INSERT_CHUNK_ROWS,
    };

    let mut total_inserted: u64 = 0;
    for chunk in rows.chunks(chunk_size) {
        let mut values_sql = Vec::with_capacity(chunk.len());
        for idx in 0..chunk.len() {
            match kind {
                DatabaseKind::Sqlite | DatabaseKind::Mysql => {
                    values_sql.push("(?, ?, ?, 0.0, NULL)".to_string());
                }
                DatabaseKind::Postgresql => {
                    let base = idx * 3;
                    values_sql.push(format!(
                        "(${}, ${}, ${}, 0.0, NULL)",
                        base + 1,
                        base + 2,
                        base + 3
                    ));
                }
            }
        }
        let sql = format!(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time, end_time) VALUES {}",
            values_sql.join(", ")
        );

        macro_rules! exec_insert {
            ($conn:expr) => {{
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                for &(group_name, permission) in chunk {
                    q = q.bind(group_name).bind(permission).bind(true);
                }
                q.execute($conn).await?.rows_affected()
            }};
        }

        let affected = match tx {
            DbTx::Sqlite(t) => exec_insert!(&mut **t),
            DbTx::Mysql(t) => exec_insert!(&mut **t),
            DbTx::Postgres(t) => exec_insert!(&mut **t),
        };
        total_inserted += affected;
    }

    Ok(total_inserted)
}

fn in_placeholders(kind: DatabaseKind, start_idx: usize, count: usize) -> String {
    match kind {
        DatabaseKind::Sqlite | DatabaseKind::Mysql => vec!["?"; count].join(", "),
        DatabaseKind::Postgresql => (start_idx..start_idx + count)
            .map(|i| format!("${i}"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}
