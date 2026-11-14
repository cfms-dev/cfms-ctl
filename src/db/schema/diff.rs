//! Structural schema diff engine, 5-phase operation planner, and SQLite rebuild coalescer.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::db::backend::DatabaseKind;
use crate::db::schema::graph::plan_table_subset;
use crate::db::schema::ir::{
    CheckIr, ColumnIr, ForeignKeyIr, IndexIr, SchemaIr, TableIr, UniqueIr, quote_ident_if_needed,
};
use crate::db::schema::rename::{
    AmbiguousRenameCandidate, ColumnRenameAnalysis, RenameConfig, RenameScoreBreakdown,
    TableRenameCandidate, detect_column_renames, detect_table_rename_candidates,
};

/// Options controlling diff semantics, rename heuristics, and dialect coalescing.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub dialect: Option<DatabaseKind>,
    pub rename: RenameConfig,
    pub coalesce_sqlite_rebuilds: bool,
    pub include_extensions: bool,
    pub compare_comments: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            dialect: None,
            rename: RenameConfig::default(),
            coalesce_sqlite_rebuilds: true,
            include_extensions: true,
            compare_comments: true,
        }
    }
}

/// Ordered execution phases for DDL generation and live migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    PreDropConstraints,
    DropTables,
    CreateTables,
    TableMigrations,
    PostConstraintsAndIndexes,
}

/// Atomic or coalesced schema migration operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SchemaOp {
    DropForeignKey {
        table: String,
        fk: ForeignKeyIr,
    },
    DropIndex {
        table: String,
        index: IndexIr,
    },
    DropUnique {
        table: String,
        unique: UniqueIr,
    },
    DropCheck {
        table: String,
        check: CheckIr,
    },
    DropTable {
        table: TableIr,
        cascade: bool,
    },
    CreateTable {
        table: TableIr,
        deferred_fk_names: BTreeSet<String>,
    },
    RenameColumn {
        table: String,
        old_column: ColumnIr,
        new_column: ColumnIr,
        score: RenameScoreBreakdown,
    },
    AddColumn {
        table: String,
        column: ColumnIr,
    },
    AlterColumn {
        table: String,
        old_column: ColumnIr,
        new_column: ColumnIr,
        type_changed: bool,
        nullable_changed: bool,
        default_changed: bool,
        computed_changed: bool,
        comment_changed: bool,
    },
    DropColumn {
        table: String,
        column: ColumnIr,
    },
    SqliteRebuildTable {
        old_table: TableIr,
        new_table: TableIr,
        /// `(new_column_name, select_expr_from_old_table)` pairs for `INSERT INTO ... SELECT ...`.
        column_mapping: Vec<(String, String)>,
        reasons: Vec<String>,
        /// Underlying logical operations folded into this rebuild so risk auditing keeps full visibility.
        folded_ops: Vec<SchemaOp>,
    },
    AddUnique {
        table: String,
        unique: UniqueIr,
    },
    AddCheck {
        table: String,
        check: CheckIr,
    },
    AddForeignKey {
        table: String,
        fk: ForeignKeyIr,
        from_deferred_cycle: bool,
    },
    CreateIndex {
        table: String,
        index: IndexIr,
    },
    SetColumnCommentPg {
        table: String,
        column: String,
        comment: Option<String>,
    },
}

impl SchemaOp {
    #[must_use]
    pub const fn phase(&self) -> ExecutionPhase {
        match self {
            Self::DropForeignKey { .. }
            | Self::DropIndex { .. }
            | Self::DropUnique { .. }
            | Self::DropCheck { .. } => ExecutionPhase::PreDropConstraints,
            Self::DropTable { .. } => ExecutionPhase::DropTables,
            Self::CreateTable { .. } => ExecutionPhase::CreateTables,
            Self::RenameColumn { .. }
            | Self::AddColumn { .. }
            | Self::AlterColumn { .. }
            | Self::DropColumn { .. }
            | Self::SqliteRebuildTable { .. } => ExecutionPhase::TableMigrations,
            Self::AddUnique { .. }
            | Self::AddCheck { .. }
            | Self::AddForeignKey { .. }
            | Self::CreateIndex { .. }
            | Self::SetColumnCommentPg { .. } => ExecutionPhase::PostConstraintsAndIndexes,
        }
    }

    #[must_use]
    pub fn table_name(&self) -> &str {
        match self {
            Self::DropForeignKey { table, .. }
            | Self::DropIndex { table, .. }
            | Self::DropUnique { table, .. }
            | Self::DropCheck { table, .. }
            | Self::RenameColumn { table, .. }
            | Self::AddColumn { table, .. }
            | Self::AlterColumn { table, .. }
            | Self::DropColumn { table, .. }
            | Self::AddUnique { table, .. }
            | Self::AddCheck { table, .. }
            | Self::AddForeignKey { table, .. }
            | Self::CreateIndex { table, .. }
            | Self::SetColumnCommentPg { table, .. } => table,
            Self::DropTable { table, .. } | Self::CreateTable { table, .. } => &table.name,
            Self::SqliteRebuildTable { new_table, .. } => &new_table.name,
        }
    }
}

/// Complete planned structural diff between two schemas.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaDiffPlan {
    pub from_revision: Option<String>,
    pub to_revision: Option<String>,
    pub dialect: Option<DatabaseKind>,
    pub operations: Vec<SchemaOp>,
    pub ambiguous_renames: BTreeMap<String, Vec<AmbiguousRenameCandidate>>,
    pub table_rename_candidates: Vec<TableRenameCandidate>,
    pub warnings: Vec<String>,
}

impl SchemaDiffPlan {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty() && self.ambiguous_renames.is_empty()
    }
}

/// Compute a safe, dependency-ordered diff plan from `old_ir` -> `new_ir`.
#[must_use]
pub fn diff_schemas(
    old_ir: &SchemaIr,
    new_ir: &SchemaIr,
    opts: &DiffOptions,
) -> SchemaDiffPlan {
    let old_filtered = old_ir.with_extensions(opts.include_extensions);
    let new_filtered = new_ir.with_extensions(opts.include_extensions);

    let effective_dialect = opts.dialect.unwrap_or(DatabaseKind::Postgresql);
    let compare_comments = opts.compare_comments && opts.dialect != Some(DatabaseKind::Sqlite);

    let mut warnings = old_filtered.warnings.clone();
    for w in &new_filtered.warnings {
        if !warnings.contains(w) {
            warnings.push(w.clone());
        }
    }

    let old_names: BTreeSet<&str> = old_filtered.tables.keys().map(String::as_str).collect();
    let new_names: BTreeSet<&str> = new_filtered.tables.keys().map(String::as_str).collect();

    let mut dropped_map = BTreeMap::new();
    for &name in old_names.difference(&new_names) {
        if let Some(t) = old_filtered.tables.get(name) {
            dropped_map.insert(name.to_string(), t.clone());
        }
    }

    let mut added_map = BTreeMap::new();
    for &name in new_names.difference(&old_names) {
        if let Some(t) = new_filtered.tables.get(name) {
            added_map.insert(name.to_string(), t.clone());
        }
    }

    let dropped_refs: Vec<&TableIr> = dropped_map.values().collect();
    let added_refs: Vec<&TableIr> = added_map.values().collect();
    let table_rename_candidates = detect_table_rename_candidates(&dropped_refs, &added_refs);

    let drop_plan = plan_table_subset(&dropped_map, effective_dialect);
    let add_plan = plan_table_subset(&added_map, effective_dialect);

    let mut pre_drop_ops: Vec<SchemaOp> = Vec::new();
    let mut drop_table_ops: Vec<SchemaOp> = Vec::new();
    let mut create_table_ops: Vec<SchemaOp> = Vec::new();
    let mut table_mig_ops: Vec<SchemaOp> = Vec::new();
    let mut post_ops: Vec<SchemaOp> = Vec::new();
    let mut ambiguous_renames: BTreeMap<String, Vec<AmbiguousRenameCandidate>> = BTreeMap::new();

    // If a surviving table has a ForeignKey pointing to a dropped table, drop that FK first.
    let dropped_table_names: BTreeSet<&str> = dropped_map.keys().map(String::as_str).collect();

    // 1. Collect per-table diffs for tables existing in both old and new.
    let common_names: Vec<&str> = old_names.intersection(&new_names).copied().collect();
    for table_name in common_names {
        let old_table = &old_filtered.tables[table_name];
        let new_table = &new_filtered.tables[table_name];

        let mut table_pre: Vec<SchemaOp> = Vec::new();
        let mut table_mid: Vec<SchemaOp> = Vec::new();
        let mut table_post: Vec<SchemaOp> = Vec::new();

        diff_single_table(
            old_table,
            new_table,
            opts,
            compare_comments,
            &mut table_pre,
            &mut table_mid,
            &mut table_post,
            &mut ambiguous_renames,
            &mut warnings,
        );

        let needs_sqlite_rebuild = opts.coalesce_sqlite_rebuilds
            && opts.dialect == Some(DatabaseKind::Sqlite)
            && requires_sqlite_rebuild(old_table, new_table, &table_pre, &table_mid, &table_post);

        if needs_sqlite_rebuild {
            let mut rename_map = BTreeMap::new();
            let mut reasons = Vec::new();
            for op in table_pre.iter().chain(&table_mid).chain(&table_post) {
                match op {
                    SchemaOp::RenameColumn {
                        old_column,
                        new_column,
                        ..
                    } => {
                        rename_map.insert(new_column.name.clone(), old_column.name.clone());
                    }
                    SchemaOp::AlterColumn { new_column, .. } => {
                        reasons.push(format!("alter column `{}`", new_column.name));
                    }
                    SchemaOp::DropColumn { column, .. } => {
                        reasons.push(format!("drop column `{}`", column.name));
                    }
                    SchemaOp::AddColumn { column, .. } => {
                        reasons.push(format!("add column `{}`", column.name));
                    }
                    SchemaOp::DropForeignKey { fk, .. } => {
                        reasons.push(format!(
                            "drop FK `{}`",
                            fk.effective_name(table_name, DatabaseKind::Sqlite)
                        ));
                    }
                    SchemaOp::AddForeignKey { fk, .. } => {
                        reasons.push(format!(
                            "add FK `{}`",
                            fk.effective_name(table_name, DatabaseKind::Sqlite)
                        ));
                    }
                    SchemaOp::DropUnique { unique, .. } => {
                        reasons.push(format!(
                            "drop unique `{}`",
                            unique.effective_name(table_name, DatabaseKind::Sqlite)
                        ));
                    }
                    SchemaOp::AddUnique { unique, .. } => {
                        reasons.push(format!(
                            "add unique `{}`",
                            unique.effective_name(table_name, DatabaseKind::Sqlite)
                        ));
                    }
                    SchemaOp::DropCheck { check, .. } => {
                        reasons.push(format!(
                            "drop check `{}`",
                            check.effective_name(table_name, DatabaseKind::Sqlite)
                        ));
                    }
                    SchemaOp::AddCheck { check, .. } => {
                        reasons.push(format!(
                            "add check `{}`",
                            check.effective_name(table_name, DatabaseKind::Sqlite)
                        ));
                    }
                    _ => {}
                }
            }
            if reasons.is_empty() {
                reasons.push("schema constraint / PK change".to_string());
            }

            let column_mapping = build_sqlite_copy_mapping(old_table, new_table, &rename_map);
            let mut folded_ops = Vec::new();
            folded_ops.extend(table_pre);
            folded_ops.extend(table_mid);
            for op in &table_post {
                if !matches!(op, SchemaOp::CreateIndex { .. }) {
                    folded_ops.push(op.clone());
                }
            }

            table_mig_ops.push(SchemaOp::SqliteRebuildTable {
                old_table: old_table.clone(),
                new_table: new_table.clone(),
                column_mapping,
                reasons,
                folded_ops,
            });
            // Dropping/renaming the SQLite table removes all old indexes, so recreate all new ones.
            for idx in &new_table.indexes {
                post_ops.push(SchemaOp::CreateIndex {
                    table: table_name.to_string(),
                    index: idx.clone(),
                });
            }
        } else {
            pre_drop_ops.extend(table_pre);
            table_mig_ops.extend(table_mid);
            post_ops.extend(table_post);
        }
    }

    // 2. Dropped tables (in reverse topological order) + FKs targeting them.
    for tname in &drop_plan.drop_order {
        if let Some(table) = dropped_map.get(tname) {
            for col_fk in &table.foreign_keys {
                if !dropped_table_names.contains(col_fk.ref_table.as_str())
                    && effective_dialect != DatabaseKind::Sqlite
                {
                    // Dropped child table FKs vanish with DROP TABLE; surviving child FKs referencing
                    // dropped parent must be dropped beforehand if not handled above.
                }
            }
            drop_table_ops.push(SchemaOp::DropTable {
                table: table.clone(),
                cascade: effective_dialect == DatabaseKind::Postgresql,
            });
        }
    }
    for old_t in old_filtered.tables.values() {
        if dropped_table_names.contains(old_t.name.as_str()) {
            continue;
        }
        for fk in &old_t.foreign_keys {
            if dropped_table_names.contains(fk.ref_table.as_str())
                && !already_dropping_fk(&pre_drop_ops, &old_t.name, fk, effective_dialect)
            {
                pre_drop_ops.push(SchemaOp::DropForeignKey {
                    table: old_t.name.clone(),
                    fk: fk.clone(),
                });
            }
        }
    }

    // 3. Created tables (in forward topological order) + indexes + deferred cycle FKs.
    for tname in &add_plan.creation_order {
        if let Some(table) = added_map.get(tname) {
            let deferred = add_plan
                .deferred_fks_by_table
                .get(tname)
                .cloned()
                .unwrap_or_default();
            create_table_ops.push(SchemaOp::CreateTable {
                table: table.clone(),
                deferred_fk_names: deferred.clone(),
            });
            for idx in &table.indexes {
                post_ops.push(SchemaOp::CreateIndex {
                    table: table.name.clone(),
                    index: idx.clone(),
                });
            }
            if effective_dialect == DatabaseKind::Postgresql {
                for col in &table.columns {
                    if let Some(comment) = &col.comment {
                        post_ops.push(SchemaOp::SetColumnCommentPg {
                            table: table.name.clone(),
                            column: col.name.clone(),
                            comment: Some(comment.clone()),
                        });
                    }
                }
            }
            if effective_dialect != DatabaseKind::Sqlite {
                for fk in &table.foreign_keys {
                    let fk_name = fk.effective_name(&table.name, effective_dialect);
                    if deferred.contains(&fk_name) {
                        post_ops.push(SchemaOp::AddForeignKey {
                            table: table.name.clone(),
                            fk: fk.clone(),
                            from_deferred_cycle: true,
                        });
                    }
                }
            }
        }
    }

    let mut operations = Vec::new();
    operations.extend(pre_drop_ops);
    operations.extend(drop_table_ops);
    operations.extend(create_table_ops);
    operations.extend(table_mig_ops);
    operations.extend(post_ops);

    SchemaDiffPlan {
        from_revision: old_filtered.schema_revision,
        to_revision: new_filtered.schema_revision,
        dialect: opts.dialect,
        operations,
        ambiguous_renames,
        table_rename_candidates,
        warnings,
    }
}

fn already_dropping_fk(
    pre_ops: &[SchemaOp],
    table_name: &str,
    fk: &ForeignKeyIr,
    dialect: DatabaseKind,
) -> bool {
    let target_name = fk.effective_name(table_name, dialect);
    pre_ops.iter().any(|op| {
        matches!(
            op,
            SchemaOp::DropForeignKey { table, fk: existing }
            if table == table_name && existing.effective_name(table_name, dialect) == target_name
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn diff_single_table(
    old_table: &TableIr,
    new_table: &TableIr,
    opts: &DiffOptions,
    compare_comments: bool,
    pre_ops: &mut Vec<SchemaOp>,
    mid_ops: &mut Vec<SchemaOp>,
    post_ops: &mut Vec<SchemaOp>,
    ambiguous_map: &mut BTreeMap<String, Vec<AmbiguousRenameCandidate>>,
    warnings: &mut Vec<String>,
) {
    let old_cols: BTreeMap<&str, &ColumnIr> =
        old_table.columns.iter().map(|c| (c.name.as_str(), c)).collect();
    let new_cols: BTreeMap<&str, &ColumnIr> =
        new_table.columns.iter().map(|c| (c.name.as_str(), c)).collect();

    let mut exact_anchors = Vec::new();
    let mut matched_pairs = Vec::new();

    for (name, old_col) in &old_cols {
        if let Some(new_col) = new_cols.get(name) {
            exact_anchors.push((old_col.ordinal, new_col.ordinal));
            matched_pairs.push((*old_col, *new_col));
        }
    }
    exact_anchors.sort_by_key(|(o, _)| *o);

    let dropped_only: Vec<&ColumnIr> = old_table
        .columns
        .iter()
        .filter(|c| !new_cols.contains_key(c.name.as_str()))
        .collect();
    let added_only: Vec<&ColumnIr> = new_table
        .columns
        .iter()
        .filter(|c| !old_cols.contains_key(c.name.as_str()))
        .collect();

    let rename_analysis: ColumnRenameAnalysis = if dropped_only.is_empty() && added_only.is_empty()
    {
        ColumnRenameAnalysis::default()
    } else {
        detect_column_renames(
            old_table,
            new_table,
            &exact_anchors,
            &dropped_only,
            &added_only,
            &opts.rename,
        )
    };

    if !rename_analysis.ambiguous.is_empty() {
        ambiguous_map.insert(new_table.name.clone(), rename_analysis.ambiguous.clone());
    }

    let mut rename_col_map: BTreeMap<String, String> = BTreeMap::new();
    for renamed in &rename_analysis.confirmed {
        rename_col_map.insert(renamed.old_column.clone(), renamed.new_column.clone());
        let old_col = old_cols[renamed.old_column.as_str()];
        let new_col = new_cols[renamed.new_column.as_str()];
        mid_ops.push(SchemaOp::RenameColumn {
            table: new_table.name.clone(),
            old_column: old_col.clone(),
            new_column: new_col.clone(),
            score: renamed.score.clone(),
        });
        matched_pairs.push((old_col, new_col));
    }

    for added_name in &rename_analysis.unmatched_added {
        let new_col = new_cols[added_name.as_str()];
        mid_ops.push(SchemaOp::AddColumn {
            table: new_table.name.clone(),
            column: new_col.clone(),
        });
    }

    for dropped_name in &rename_analysis.unmatched_dropped {
        let old_col = old_cols[dropped_name.as_str()];
        mid_ops.push(SchemaOp::DropColumn {
            table: new_table.name.clone(),
            column: old_col.clone(),
        });
    }

    // Compare properties of exact-matched and renamed column pairs.
    for (old_col, new_col) in matched_pairs {
        let type_changed = !old_col
            .canonical_type
            .semantic_eq(&new_col.canonical_type, opts.dialect);
        let nullable_changed = old_col.nullable != new_col.nullable;
        let default_changed = match (&old_col.server_default, &new_col.server_default) {
            (None, None) => false,
            (Some(a), Some(b)) => !a.semantic_eq(b),
            _ => true,
        };
        let computed_changed = !computed_semantic_eq(old_col, new_col);
        let comment_changed = compare_comments && old_col.comment != new_col.comment;

        if type_changed || nullable_changed || default_changed || computed_changed || comment_changed
        {
            if opts.dialect == Some(DatabaseKind::Postgresql)
                && comment_changed
                && !(type_changed || nullable_changed || default_changed || computed_changed)
            {
                post_ops.push(SchemaOp::SetColumnCommentPg {
                    table: new_table.name.clone(),
                    column: new_col.name.clone(),
                    comment: new_col.comment.clone(),
                });
            } else {
                mid_ops.push(SchemaOp::AlterColumn {
                    table: new_table.name.clone(),
                    old_column: old_col.clone(),
                    new_column: new_col.clone(),
                    type_changed,
                    nullable_changed,
                    default_changed,
                    computed_changed,
                    comment_changed,
                });
            }
        }
    }

    // Rewrite old constraints/indexes using rename_col_map before comparing sets!
    let dialect_ref = opts.dialect.unwrap_or(DatabaseKind::Postgresql);
    let dropped_col_set: BTreeSet<&str> = rename_analysis
        .unmatched_dropped
        .iter()
        .map(String::as_str)
        .collect();

    if old_table.primary_key.columns != new_table.primary_key.columns {
        warnings.push(format!(
            "Primary key changed on table `{}`: {:?} -> {:?}",
            new_table.name, old_table.primary_key.columns, new_table.primary_key.columns
        ));
    }

    // Foreign Keys
    let old_fks: Vec<ForeignKeyIr> = old_table
        .foreign_keys
        .iter()
        .map(|fk| substitute_fk_columns(fk, &rename_col_map))
        .collect();
    for old_fk in &old_fks {
        let touches_dropped = old_fk
            .columns
            .iter()
            .any(|c| dropped_col_set.contains(c.as_str()));
        let sig = old_fk.structural_signature();
        let kept = new_table
            .foreign_keys
            .iter()
            .any(|nfk| nfk.structural_signature() == sig);
        if touches_dropped || !kept {
            pre_ops.push(SchemaOp::DropForeignKey {
                table: new_table.name.clone(),
                fk: old_fk.clone(),
            });
        }
    }
    for new_fk in &new_table.foreign_keys {
        let sig = new_fk.structural_signature();
        let existed = old_fks.iter().any(|ofk| ofk.structural_signature() == sig);
        if !existed {
            post_ops.push(SchemaOp::AddForeignKey {
                table: new_table.name.clone(),
                fk: new_fk.clone(),
                from_deferred_cycle: false,
            });
        }
    }

    // Unique Constraints
    let old_uniques: Vec<UniqueIr> = old_table
        .uniques
        .iter()
        .map(|u| UniqueIr {
            columns: substitute_col_list(&u.columns, &rename_col_map),
            ..u.clone()
        })
        .collect();
    for old_uq in &old_uniques {
        let touches_dropped = old_uq
            .columns
            .iter()
            .any(|c| dropped_col_set.contains(c.as_str()));
        if touches_dropped
            || !new_table
                .uniques
                .iter()
                .any(|nu| nu.columns == old_uq.columns)
        {
            pre_ops.push(SchemaOp::DropUnique {
                table: new_table.name.clone(),
                unique: old_uq.clone(),
            });
        }
    }
    for new_uq in &new_table.uniques {
        if !old_uniques.iter().any(|ou| ou.columns == new_uq.columns) {
            post_ops.push(SchemaOp::AddUnique {
                table: new_table.name.clone(),
                unique: new_uq.clone(),
            });
        }
    }

    // Check Constraints
    for old_ck in &old_table.checks {
        let old_norm = normalize_sql_expr(old_ck.expr_for(dialect_ref));
        let matches_new = new_table
            .checks
            .iter()
            .any(|nck| normalize_sql_expr(nck.expr_for(dialect_ref)) == old_norm);
        if !matches_new {
            pre_ops.push(SchemaOp::DropCheck {
                table: new_table.name.clone(),
                check: old_ck.clone(),
            });
        }
    }
    for new_ck in &new_table.checks {
        let new_norm = normalize_sql_expr(new_ck.expr_for(dialect_ref));
        let matches_old = old_table
            .checks
            .iter()
            .any(|ock| normalize_sql_expr(ock.expr_for(dialect_ref)) == new_norm);
        if !matches_old {
            post_ops.push(SchemaOp::AddCheck {
                table: new_table.name.clone(),
                check: new_ck.clone(),
            });
        }
    }

    // Indexes
    let old_indexes: Vec<IndexIr> = old_table
        .indexes
        .iter()
        .map(|idx| IndexIr {
            expressions: substitute_col_list(&idx.expressions, &rename_col_map),
            ..idx.clone()
        })
        .collect();
    let idx_sig = |idx: &IndexIr| {
        (
            idx.unique,
            idx.expressions
                .iter()
                .map(|e| normalize_sql_expr(e))
                .collect::<Vec<_>>(),
            idx.where_clause.as_deref().map(normalize_sql_expr),
        )
    };
    for old_idx in &old_indexes {
        let sig = idx_sig(old_idx);
        let touches_dropped = old_idx
            .expressions
            .iter()
            .any(|e| dropped_col_set.contains(e.trim()));
        if touches_dropped || !new_table.indexes.iter().any(|ni| idx_sig(ni) == sig) {
            pre_ops.push(SchemaOp::DropIndex {
                table: new_table.name.clone(),
                index: old_idx.clone(),
            });
        }
    }
    for new_idx in &new_table.indexes {
        let sig = idx_sig(new_idx);
        if !old_indexes.iter().any(|oi| idx_sig(oi) == sig) {
            post_ops.push(SchemaOp::CreateIndex {
                table: new_table.name.clone(),
                index: new_idx.clone(),
            });
        }
    }
}

fn requires_sqlite_rebuild(
    old_table: &TableIr,
    new_table: &TableIr,
    pre: &[SchemaOp],
    mid: &[SchemaOp],
    post: &[SchemaOp],
) -> bool {
    if old_table.primary_key.columns != new_table.primary_key.columns {
        return true;
    }
    if pre.iter().any(|op| !matches!(op, SchemaOp::DropIndex { .. })) {
        return true;
    }
    if post
        .iter()
        .any(|op| matches!(op, SchemaOp::AddUnique { .. } | SchemaOp::AddCheck { .. } | SchemaOp::AddForeignKey { .. }))
    {
        return true;
    }
    for op in mid {
        match op {
            SchemaOp::AlterColumn { .. } => return true,
            SchemaOp::AddColumn { column, .. } => {
                if column.computed.is_some() {
                    return true;
                }
                if let Some(def) = &column.server_default
                    && matches!(
                        def,
                        crate::db::schema::ir::ServerDefaultIr::CurrentTimestamp
                            | crate::db::schema::ir::ServerDefaultIr::Expression { .. }
                    )
                {
                    return true;
                }
            }
            SchemaOp::DropColumn { column, .. } => {
                let referenced_in_old = old_table.primary_key.columns.contains(&column.name)
                    || old_table
                        .uniques
                        .iter()
                        .any(|u| u.columns.contains(&column.name))
                    || old_table
                        .foreign_keys
                        .iter()
                        .any(|f| f.columns.contains(&column.name))
                    || old_table
                        .indexes
                        .iter()
                        .any(|i| i.expressions.iter().any(|e| e.contains(&column.name)));
                if referenced_in_old {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn build_sqlite_copy_mapping(
    old_table: &TableIr,
    new_table: &TableIr,
    new_to_old_override: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let old_col_names: BTreeSet<&str> = old_table.columns.iter().map(|c| c.name.as_str()).collect();
    let mut rev_rename = BTreeMap::new();
    for (old_c, new_c) in new_to_old_override {
        rev_rename.insert(new_c.as_str(), old_c.as_str());
    }

    let mut mapping = Vec::new();
    for new_col in new_table.data_columns() {
        let select_expr = if let Some(&old_name) = rev_rename.get(new_col.name.as_str()) {
            quote_ident_if_needed(old_name, DatabaseKind::Sqlite).into_owned()
        } else if old_col_names.contains(new_col.name.as_str()) {
            quote_ident_if_needed(&new_col.name, DatabaseKind::Sqlite).into_owned()
        } else if let Some(def) = &new_col.server_default {
            def.render_expr(DatabaseKind::Sqlite)
        } else {
            "NULL".to_string()
        };
        mapping.push((new_col.name.clone(), select_expr));
    }
    mapping
}

fn substitute_fk_columns(fk: &ForeignKeyIr, rename_map: &BTreeMap<String, String>) -> ForeignKeyIr {
    ForeignKeyIr {
        columns: substitute_col_list(&fk.columns, rename_map),
        ..fk.clone()
    }
}

fn substitute_col_list(items: &[String], rename_map: &BTreeMap<String, String>) -> Vec<String> {
    items
        .iter()
        .map(|s| rename_map.get(s).cloned().unwrap_or_else(|| s.clone()))
        .collect()
}

fn computed_semantic_eq(a: &ColumnIr, b: &ColumnIr) -> bool {
    match (&a.computed, &b.computed) {
        (None, None) => true,
        (Some(ca), Some(cb)) => {
            ca.persisted == cb.persisted
                && normalize_sql_expr(&ca.expression) == normalize_sql_expr(&cb.expression)
        }
        _ => false,
    }
}

fn normalize_sql_expr(expr: &str) -> String {
    let collapsed = expr
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('`', "");
    let trimmed = collapsed.trim();
    if let Some(inner) = trimmed.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        return inner.trim().to_ascii_lowercase();
    }
    trimmed.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ddl::builtin_schema_ir;

    #[test]
    fn identical_builtin_schemas_produce_empty_diff() {
        let a = builtin_schema_ir(true);
        let b = builtin_schema_ir(true);
        let plan = diff_schemas(&a, &b, &DiffOptions::default());
        assert!(plan.is_empty(), "ops: {:?}", plan.operations);
    }

    #[test]
    fn diff_coalesces_sqlite_column_alter_into_rebuild_preserving_folded_ops() {
        let old = builtin_schema_ir(false);
        let mut new = builtin_schema_ir(false);

        let users = new.tables.get_mut("users").unwrap();
        let uname = users
            .columns
            .iter_mut()
            .find(|c| c.name == "username")
            .unwrap();
        uname.canonical_type = crate::db::schema::ir::CanonicalType::Varchar { length: Some(64) };

        let opts = DiffOptions {
            dialect: Some(DatabaseKind::Sqlite),
            ..Default::default()
        };
        let plan = diff_schemas(&old, &new, &opts);
        assert!(plan
            .operations
            .iter()
            .any(|op| matches!(op, SchemaOp::SqliteRebuildTable { .. })));
    }
}
