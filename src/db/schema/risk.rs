//! Automated schema migration risk auditor and live DB preflight verifier.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::diff::{SchemaDiffPlan, SchemaOp};
use crate::db::schema::ir::{CanonicalType, ConfidenceLevel, SchemaIr, TypeCompatibility, quote_ident_if_needed};
use crate::db::schema::static_ast::PendingAlembicAnalysis;

/// Risk severity levels aligned with destructive gate policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Single audited risk finding bound to an operation, table, or pending script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub code: String,
    pub level: RiskLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_index: Option<usize>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_evidence: Option<String>,
    pub blocking: bool,
}

/// Complete risk audit summary for a [`SchemaDiffPlan`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskAuditReport {
    pub max_level: RiskLevel,
    pub has_blocking_risks: bool,
    pub findings: Vec<RiskFinding>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub op_findings: BTreeMap<usize, Vec<RiskFinding>>,
}

impl RiskAuditReport {
    fn push(&mut self, finding: RiskFinding) {
        if finding.level > self.max_level {
            self.max_level = finding.level;
        }
        if finding.blocking {
            self.has_blocking_risks = true;
        }
        if let Some(op_idx) = finding.op_index {
            self.op_findings
                .entry(op_idx)
                .or_default()
                .push(finding.clone());
        }
        self.findings.push(finding);
    }

    pub fn recompute_flags(&mut self) {
        self.max_level = self
            .findings
            .iter()
            .map(|f| f.level)
            .max()
            .unwrap_or(RiskLevel::Low);
        self.has_blocking_risks = self.findings.iter().any(|f| f.blocking);
        self.op_findings.clear();
        for f in &self.findings {
            if let Some(op_idx) = f.op_index {
                self.op_findings.entry(op_idx).or_default().push(f.clone());
            }
        }
    }

    /// Format compact single-line risk annotation headers for a specific operation index.
    #[must_use]
    pub fn comments_for_op(&self, op_index: usize) -> Vec<String> {
        self.op_findings
            .get(&op_index)
            .map(|list| {
                list.iter()
                    .map(|f| {
                        if let Some(ev) = &f.preflight_evidence {
                            format!("[RISK: {} {}] {} ({ev})", f.level, f.code, f.summary)
                        } else {
                            format!("[RISK: {} {}] {}", f.level, f.code, f.summary)
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Audit every operation in `plan`, plus ambiguous renames, low-confidence extractions,
/// and pending Alembic data DML.
#[must_use]
pub fn audit_diff_plan(
    plan: &SchemaDiffPlan,
    target_ir: Option<&SchemaIr>,
    pending_alembic: Option<&PendingAlembicAnalysis>,
) -> RiskAuditReport {
    let mut report = RiskAuditReport::default();

    for (idx, op) in plan.operations.iter().enumerate() {
        audit_single_op(idx, op, &mut report);
    }

    for (table, cands) in &plan.ambiguous_renames {
        for cand in cands {
            report.push(RiskFinding {
                code: "CFMS-MIG-007".to_string(),
                level: RiskLevel::High,
                table: Some(table.clone()),
                column: Some(cand.old_column.clone()),
                op_index: None,
                summary: format!(
                    "Ambiguous rename candidate `{}.{}` -> `{}` (score {:.2}): {}",
                    table, cand.old_column, cand.new_column, cand.score.total, cand.reason
                ),
                remediation: Some(format!(
                    "Pass `--rename {table}.{}={}` to confirm rename, or `--allow-destructive` to drop & add",
                    cand.old_column, cand.new_column
                )),
                preflight_evidence: None,
                blocking: true,
            });
        }
    }

    for tr in &plan.table_rename_candidates {
        report.push(RiskFinding {
            code: "CFMS-MIG-007".to_string(),
            level: RiskLevel::High,
            table: Some(tr.old_table.clone()),
            column: None,
            op_index: None,
            summary: format!(
                "Possible table rename `{}` -> `{}` (similarity {:.2}) currently planned as DROP + CREATE",
                tr.old_table, tr.new_table, tr.score
            ),
            remediation: Some(
                "Verify whether data should be copied from old table via manual/Alembic script before dropping"
                    .to_string(),
            ),
            preflight_evidence: None,
            blocking: true,
        });
    }

    if let Some(alembic) = pending_alembic
        && alembic.has_data_dml
    {
        let revs = alembic
            .dml_revisions
            .iter()
            .map(|(rev, reasons)| format!("{rev} [{}]", reasons.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        report.push(RiskFinding {
            code: "CFMS-MIG-008".to_string(),
            level: RiskLevel::High,
            table: None,
            column: None,
            op_index: None,
            summary: format!("Pending Alembic revisions perform data DML / backfills: {revs}"),
            remediation: Some(
                "Run `alembic upgrade head` (recommended when confirmed) so application data backfills execute"
                    .to_string(),
            ),
            preflight_evidence: None,
            blocking: true,
        });
    }

    if let Some(ir) = target_ir {
        for (tname, table) in &ir.tables {
            if table.confidence == ConfidenceLevel::Low
                || table.columns.iter().any(|c| c.confidence == ConfidenceLevel::Low)
            {
                report.push(RiskFinding {
                    code: "CFMS-MIG-011".to_string(),
                    level: RiskLevel::Medium,
                    table: Some(tname.clone()),
                    column: None,
                    op_index: None,
                    summary: format!(
                        "Table `{tname}` has Low-confidence AST extraction (e.g. @declared_attr or dynamic kwargs)"
                    ),
                    remediation: Some(
                        "Run with a Python environment (`--extractor python`) or export `schema.ir.json` cleanly"
                            .to_string(),
                    ),
                    preflight_evidence: None,
                    blocking: false,
                });
            }
        }
    }

    report
}

fn audit_single_op(op_idx: usize, op: &SchemaOp, report: &mut RiskAuditReport) {
    match op {
        SchemaOp::DropTable { table, .. } => report.push(RiskFinding {
            code: "CFMS-MIG-001".to_string(),
            level: RiskLevel::Critical,
            table: Some(table.name.clone()),
            column: None,
            op_index: Some(op_idx),
            summary: format!("DROP TABLE `{}` permanently deletes all table rows", table.name),
            remediation: Some(
                "Back up rows first or pass `--allow-destructive` after confirming table removal".to_string(),
            ),
            preflight_evidence: None,
            blocking: true,
        }),
        SchemaOp::DropColumn { table, column } => report.push(RiskFinding {
            code: "CFMS-MIG-002".to_string(),
            level: RiskLevel::Critical,
            table: Some(table.clone()),
            column: Some(column.name.clone()),
            op_index: Some(op_idx),
            summary: format!("DROP COLUMN `{table}.{}` permanently destroys stored column data", column.name),
            remediation: Some(format!(
                "Verify data retention or use `--rename {table}.{}=<new_col>` if renamed",
                column.name
            )),
            preflight_evidence: None,
            blocking: true,
        }),
        SchemaOp::AddColumn { table, column } => {
            if !column.nullable && column.server_default.is_none() && column.computed.is_none() {
                report.push(RiskFinding {
                    code: "CFMS-MIG-003".to_string(),
                    level: RiskLevel::Critical,
                    table: Some(table.clone()),
                    column: Some(column.name.clone()),
                    op_index: Some(op_idx),
                    summary: format!(
                        "ADD COLUMN `{table}.{}` is NOT NULL without a server_default",
                        column.name
                    ),
                    remediation: Some(
                        "Add a `server_default` or make the column initially nullable, then backfill before enforcing NOT NULL"
                            .to_string(),
                    ),
                    preflight_evidence: None,
                    blocking: true,
                });
            } else {
                report.push(RiskFinding {
                    code: "CFMS-MIG-012".to_string(),
                    level: RiskLevel::Low,
                    table: Some(table.clone()),
                    column: Some(column.name.clone()),
                    op_index: Some(op_idx),
                    summary: format!("Additive column `{table}.{}`", column.name),
                    remediation: None,
                    preflight_evidence: None,
                    blocking: false,
                });
            }
        }
        SchemaOp::AlterColumn {
            table,
            old_column,
            new_column,
            type_changed,
            nullable_changed,
            ..
        } => {
            let mut recorded = false;
            if *type_changed {
                let compat = old_column
                    .canonical_type
                    .classify_transition(&new_column.canonical_type);
                match compat {
                    TypeCompatibility::Incompatible => {
                        recorded = true;
                        report.push(RiskFinding {
                            code: "CFMS-MIG-004".to_string(),
                            level: RiskLevel::Critical,
                            table: Some(table.clone()),
                            column: Some(new_column.name.clone()),
                            op_index: Some(op_idx),
                            summary: format!(
                                "Incompatible type alteration on `{table}.{}` ({:?} -> {:?})",
                                new_column.name, old_column.canonical_type, new_column.canonical_type
                            ),
                            remediation: Some(
                                "Provide an explicit CAST / data backfill script before altering column type"
                                    .to_string(),
                            ),
                            preflight_evidence: None,
                            blocking: true,
                        });
                    }
                    TypeCompatibility::Narrowing => {
                        recorded = true;
                        let reason = old_column
                            .canonical_type
                            .narrowing_reason(&new_column.canonical_type)
                            .unwrap_or_else(|| "type narrowing".to_string());
                        report.push(RiskFinding {
                            code: "CFMS-MIG-005".to_string(),
                            level: RiskLevel::High,
                            table: Some(table.clone()),
                            column: Some(new_column.name.clone()),
                            op_index: Some(op_idx),
                            summary: format!(
                                "Narrowing alteration on `{table}.{}` ({reason})",
                                new_column.name
                            ),
                            remediation: Some(
                                "Verify existing values fit within target width/range or pass `--allow-destructive`"
                                    .to_string(),
                            ),
                            preflight_evidence: None,
                            blocking: true,
                        });
                    }
                    _ => {}
                }
            }
            if *nullable_changed
                && old_column.nullable
                && !new_column.nullable
                && new_column.server_default.is_none()
            {
                recorded = true;
                report.push(RiskFinding {
                    code: "CFMS-MIG-006".to_string(),
                    level: RiskLevel::High,
                    table: Some(table.clone()),
                    column: Some(new_column.name.clone()),
                    op_index: Some(op_idx),
                    summary: format!(
                        "Tightening `{table}.{}` from NULL to NOT NULL without default",
                        new_column.name
                    ),
                    remediation: Some(
                        "Verify zero NULL rows remain or populate NULL rows prior to ALTER".to_string(),
                    ),
                    preflight_evidence: None,
                    blocking: true,
                });
            }
            if !recorded {
                report.push(RiskFinding {
                    code: "CFMS-MIG-012".to_string(),
                    level: RiskLevel::Low,
                    table: Some(table.clone()),
                    column: Some(new_column.name.clone()),
                    op_index: Some(op_idx),
                    summary: format!("Compatible alteration on `{table}.{}`", new_column.name),
                    remediation: None,
                    preflight_evidence: None,
                    blocking: false,
                });
            }
        }
        SchemaOp::RenameColumn {
            table,
            old_column,
            new_column,
            score,
        } => {
            report.push(RiskFinding {
                code: if score.explicit_override {
                    "CFMS-MIG-012"
                } else {
                    "CFMS-MIG-009"
                }
                .to_string(),
                level: if score.explicit_override {
                    RiskLevel::Low
                } else {
                    RiskLevel::Medium
                },
                table: Some(table.clone()),
                column: Some(new_column.name.clone()),
                op_index: Some(op_idx),
                summary: format!(
                    "Rename `{table}.{}` -> `{}` (score {:.2}: name={:.2}, type={:.2}, pos={:.2}{})",
                    old_column.name,
                    new_column.name,
                    score.total,
                    score.name_score,
                    score.type_score,
                    score.pos_score,
                    if score.explicit_override {
                        ", explicit"
                    } else {
                        ", inferred"
                    }
                ),
                remediation: None,
                preflight_evidence: None,
                blocking: false,
            });
            if matches!(
                old_column.canonical_type.classify_transition(&new_column.canonical_type),
                TypeCompatibility::Narrowing | TypeCompatibility::Incompatible
            ) {
                audit_single_op(
                    op_idx,
                    &SchemaOp::AlterColumn {
                        table: table.clone(),
                        old_column: old_column.clone(),
                        new_column: new_column.clone(),
                        type_changed: true,
                        nullable_changed: old_column.nullable != new_column.nullable,
                        default_changed: false,
                        computed_changed: false,
                        comment_changed: false,
                    },
                    report,
                );
            }
        }
        SchemaOp::SqliteRebuildTable {
            new_table,
            reasons,
            folded_ops,
            ..
        } => {
            report.push(RiskFinding {
                code: "CFMS-MIG-010".to_string(),
                level: RiskLevel::Medium,
                table: Some(new_table.name.clone()),
                column: None,
                op_index: Some(op_idx),
                summary: format!(
                    "SQLite 12-step table rebuild on `{}` ({})",
                    new_table.name,
                    reasons.join(", ")
                ),
                remediation: None,
                preflight_evidence: None,
                blocking: false,
            });
            // Audit every underlying logical op inside the rebuild under the same op_idx!
            for sub_op in folded_ops {
                audit_single_op(op_idx, sub_op, report);
            }
        }
        SchemaOp::AddUnique { table, unique } => report.push(RiskFinding {
            code: "CFMS-MIG-010".to_string(),
            level: RiskLevel::Medium,
            table: Some(table.clone()),
            column: None,
            op_index: Some(op_idx),
            summary: format!(
                "Add UNIQUE constraint on `{table}` ({}) — fails if duplicate rows exist",
                unique.columns.join(", ")
            ),
            remediation: None,
            preflight_evidence: None,
            blocking: false,
        }),
        SchemaOp::AddCheck { table, check } => report.push(RiskFinding {
            code: "CFMS-MIG-010".to_string(),
            level: RiskLevel::Medium,
            table: Some(table.clone()),
            column: None,
            op_index: Some(op_idx),
            summary: format!(
                "Add CHECK constraint on `{table}` ({}) — fails if existing rows violate predicate",
                check.expression
            ),
            remediation: None,
            preflight_evidence: None,
            blocking: false,
        }),
        SchemaOp::CreateIndex { table, index } if index.unique => report.push(RiskFinding {
            code: "CFMS-MIG-010".to_string(),
            level: RiskLevel::Medium,
            table: Some(table.clone()),
            column: None,
            op_index: Some(op_idx),
            summary: format!(
                "Add UNIQUE INDEX `{}` on `{table}` ({}) — fails if duplicate rows exist",
                index.name,
                index.expressions.join(", ")
            ),
            remediation: None,
            preflight_evidence: None,
            blocking: false,
        }),
        SchemaOp::CreateTable { table, .. } => report.push(RiskFinding {
            code: "CFMS-MIG-012".to_string(),
            level: RiskLevel::Low,
            table: Some(table.name.clone()),
            column: None,
            op_index: Some(op_idx),
            summary: format!("Create table `{}`", table.name),
            remediation: None,
            preflight_evidence: None,
            blocking: false,
        }),
        _ => {}
    }
}

/// Execute read-only `SELECT COUNT(*)` preflight checks against `pool` to empirically
/// validate NOT NULL, narrowing, UNIQUE, and CHECK preconditions.
pub async fn run_live_preflight_checks(
    pool: &DbPool,
    plan: &SchemaDiffPlan,
    audit: &mut RiskAuditReport,
) {
    let kind = pool.kind();
    let existing_tables = pool.list_tables().await.unwrap_or_default();

    for finding in &mut audit.findings {
        let Some(op_idx) = finding.op_index else {
            continue;
        };
        let Some(op) = plan.operations.get(op_idx) else {
            continue;
        };
        let Some(tname) = finding.table.as_deref() else {
            continue;
        };
        if !existing_tables.iter().any(|t| t == tname) {
            continue;
        }
        let q_table = quote_ident_if_needed(tname, kind).into_owned();

        match finding.code.as_str() {
            "CFMS-MIG-003" => {
                // Add NOT NULL without default: safe only if table has 0 rows!
                let sql = format!("SELECT COUNT(*) FROM {q_table}");
                if let Ok(cnt) = fetch_count(pool, &sql).await {
                    finding.preflight_evidence = Some(format!("{cnt} rows currently in `{tname}`"));
                    if cnt == 0 {
                        finding.blocking = false;
                        finding.level = RiskLevel::Medium;
                    }
                }
            }
            "CFMS-MIG-006" => {
                if let Some(col) = &finding.column {
                    let q_col = quote_ident_if_needed(col, kind).into_owned();
                    let sql = format!("SELECT COUNT(*) FROM {q_table} WHERE {q_col} IS NULL");
                    if let Ok(cnt) = fetch_count(pool, &sql).await {
                        finding.preflight_evidence = Some(format!("{cnt} NULL row(s) found"));
                        if cnt == 0 {
                            finding.blocking = false;
                            finding.level = RiskLevel::Medium;
                        }
                    }
                }
            }
            "CFMS-MIG-005" => {
                if let Some(col_name) = &finding.column
                    && let Some(SchemaOp::AlterColumn {
                        new_column,
                        ..
                    }) = find_alter_op(op, col_name)
                    && let CanonicalType::Varchar { length: Some(max_len) } | CanonicalType::Char { length: Some(max_len) } = new_column.canonical_type
                {
                    let q_col = quote_ident_if_needed(col_name, kind).into_owned();
                    let len_fn = match kind {
                        DatabaseKind::Mysql => "CHAR_LENGTH",
                        DatabaseKind::Sqlite | DatabaseKind::Postgresql => "LENGTH",
                    };
                    let sql = format!(
                        "SELECT COUNT(*) FROM {q_table} WHERE {len_fn}({q_col}) > {max_len}"
                    );
                    if let Ok(cnt) = fetch_count(pool, &sql).await {
                        finding.preflight_evidence =
                            Some(format!("{cnt} row(s) exceed length {max_len}"));
                        if cnt > 0 {
                            finding.level = RiskLevel::Critical;
                            finding.blocking = true;
                        }
                    }
                }
            }
            "CFMS-MIG-010" => {
                if let SchemaOp::AddUnique { unique, .. } = op
                    && !unique.columns.is_empty()
                {
                    let cols = unique
                        .columns
                        .iter()
                        .map(|c| quote_ident_if_needed(c, kind).into_owned())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let sql = format!(
                        "SELECT COUNT(*) FROM (SELECT 1 FROM {q_table} GROUP BY {cols} HAVING COUNT(*) > 1) AS dups"
                    );
                    if let Ok(cnt) = fetch_count(pool, &sql).await {
                        finding.preflight_evidence = Some(format!("{cnt} duplicate key group(s)"));
                        if cnt > 0 {
                            finding.level = RiskLevel::Critical;
                            finding.blocking = true;
                        }
                    }
                } else if let SchemaOp::AddCheck { check, .. } = op {
                    let sql = format!(
                        "SELECT COUNT(*) FROM {q_table} WHERE NOT ({})",
                        check.expr_for(kind)
                    );
                    if let Ok(cnt) = fetch_count(pool, &sql).await {
                        finding.preflight_evidence = Some(format!("{cnt} violating row(s)"));
                        if cnt > 0 {
                            finding.level = RiskLevel::Critical;
                            finding.blocking = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    audit.recompute_flags();
}

fn find_alter_op<'a>(op: &'a SchemaOp, col_name: &str) -> Option<&'a SchemaOp> {
    match op {
        SchemaOp::AlterColumn { new_column, .. } if new_column.name == col_name => Some(op),
        SchemaOp::SqliteRebuildTable { folded_ops, .. } => folded_ops
            .iter()
            .find(|sub| matches!(sub, SchemaOp::AlterColumn { new_column, .. } if new_column.name == col_name)),
        _ => None,
    }
}

async fn fetch_count(pool: &DbPool, sql: &str) -> std::result::Result<i64, sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            let row = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch_one(p).await?;
            Ok(row.get::<i64, _>(0))
        }
        DbPool::Mysql(p) => {
            let row = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch_one(p).await?;
            Ok(row.get::<i64, _>(0))
        }
        DbPool::Postgres(p) => {
            let row = sqlx::query(sqlx::AssertSqlSafe(sql)).fetch_one(p).await?;
            Ok(row.get::<i64, _>(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ddl::builtin_schema_ir;
    use crate::db::schema::diff::{DiffOptions, diff_schemas};
    use crate::db::schema::ir::{ColumnIr, TableOwnership};

    #[test]
    fn risk_auditor_flags_all_destructive_and_narrowing_rules() {
        let old = builtin_schema_ir(false);
        let mut new = builtin_schema_ir(false);

        // CFMS-MIG-001: drop table `system_states`
        new.tables.remove("system_states");

        // On `users`:
        let users = new.tables.get_mut("users").unwrap();
        // CFMS-MIG-002: drop column `nickname`
        users.columns.retain(|c| c.name != "nickname");
        // CFMS-MIG-005: narrow `username` VARCHAR(256) -> VARCHAR(32)
        if let Some(u) = users.columns.iter_mut().find(|c| c.name == "username") {
            u.canonical_type = CanonicalType::Varchar { length: Some(32) };
        }
        // CFMS-MIG-003: add NOT NULL column without server_default
        users.columns.push(ColumnIr {
            name: "brand_new_req".to_string(),
            ordinal: 99,
            canonical_type: CanonicalType::Varchar { length: Some(64) },
            dialect_types: BTreeMap::new(),
            nullable: false,
            autoincrement: false,
            server_default: None,
            computed: None,
            comment: None,
            confidence: ConfidenceLevel::High,
        });

        let mut old_low = old.clone();
        old_low
            .tables
            .values_mut()
            .for_each(|t| t.ownership = TableOwnership::Core);
        let mut new_low = new;
        new_low
            .tables
            .get_mut("documents")
            .unwrap()
            .confidence = ConfidenceLevel::Low;

        let plan = diff_schemas(&old_low, &new_low, &DiffOptions::default());
        let audit = audit_diff_plan(&plan, Some(&new_low), None);

        assert!(audit.has_blocking_risks);
        assert_eq!(audit.max_level, RiskLevel::Critical);
        let codes: Vec<&str> = audit.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains(&"CFMS-MIG-001"), "{codes:?}");
        assert!(codes.contains(&"CFMS-MIG-002"), "{codes:?}");
        assert!(codes.contains(&"CFMS-MIG-003"), "{codes:?}");
        assert!(codes.contains(&"CFMS-MIG-005"), "{codes:?}");
        assert!(codes.contains(&"CFMS-MIG-011"), "{codes:?}");
    }
}
