//! MiniJinja template rendering for risk-annotated Alembic migration scripts
//! and multi-dialect native DDL SQL, plus shared executable SQL statement compilation.

use std::collections::BTreeMap;

use minijinja::{Environment, context, value::Serde};
use serde::Serialize;

use crate::core::error::{CfmsError, Result};
use crate::db::backend::DatabaseKind;
use crate::db::schema::diff::{SchemaDiffPlan, SchemaOp};
use crate::db::schema::graph::plan_schema_graph;
use crate::db::schema::ir::{
    ColumnIr, ForeignKeyIr, IndexIr, SchemaIr, quote_ident_if_needed,
};
use crate::db::schema::risk::RiskAuditReport;

const NATIVE_DDL_TEMPLATE: &str = include_str!("templates/native_ddl.sql.j2");
const ALEMBIC_MIGRATION_TEMPLATE: &str = include_str!("templates/alembic_migration.py.j2");

/// Options when rendering an Alembic Python migration script.
#[derive(Debug, Clone)]
pub struct AlembicRenderOptions {
    pub revision: String,
    pub down_revision: Option<String>,
    pub summary_title: String,
}

impl Default for AlembicRenderOptions {
    fn default() -> Self {
        Self {
            revision: "auto_evolution".to_string(),
            down_revision: None,
            summary_title: "Auto-generated CFMS schema evolution".to_string(),
        }
    }
}

/// Options when rendering a native dialect SQL script.
#[derive(Debug, Clone)]
pub struct SqlRenderOptions {
    pub dialect: DatabaseKind,
    pub wrap_in_transaction: bool,
    pub include_alembic_version_stamp: bool,
}

impl SqlRenderOptions {
    #[must_use]
    pub const fn new(dialect: DatabaseKind) -> Self {
        Self {
            dialect,
            wrap_in_transaction: !matches!(dialect, DatabaseKind::Mysql),
            include_alembic_version_stamp: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct SqlOpBlock {
    phase: &'static str,
    risk_comments: Vec<String>,
    statements: Vec<String>,
}

/// Compile a full `SchemaIr` (arbitrary table count + dynamic cycle breaking) into ordered DDL statements.
#[must_use]
pub fn compile_full_schema_ddl(ir: &SchemaIr, kind: DatabaseKind) -> Vec<String> {
    let graph = plan_schema_graph(ir, kind);
    let mut stmts = Vec::new();
    for table_name in &graph.creation_order {
        if let Some(table) = ir.tables.get(table_name) {
            let deferred = graph.deferred_fks_by_table.get(table_name);
            stmts.push(table.compile_create_table(kind, deferred));
            stmts.extend(table.compile_create_indexes(kind));
        }
    }
    for table_name in &graph.creation_order {
        if let Some(table) = ir.tables.get(table_name) {
            let deferred = graph.deferred_fks_by_table.get(table_name);
            stmts.extend(table.compile_deferred_foreign_keys(kind, deferred));
        }
    }
    stmts
}

/// Compile a single [`SchemaOp`] into dialect-accurate SQL statement(s) for execution or rendering.
#[must_use]
pub fn compile_op_to_sql_statements(op: &SchemaOp, kind: DatabaseKind) -> Vec<String> {
    match op {
        SchemaOp::DropForeignKey { table, fk } => {
            if kind == DatabaseKind::Sqlite {
                return Vec::new();
            }
            let qt = quote_ident_if_needed(table, kind);
            let fk_name = fk.effective_name(table, kind);
            let qname = quote_ident_if_needed(&fk_name, kind);
            let sql = match kind {
                DatabaseKind::Mysql => format!("ALTER TABLE {qt} DROP FOREIGN KEY {qname}"),
                DatabaseKind::Postgresql => format!("ALTER TABLE {qt} DROP CONSTRAINT {qname}"),
                DatabaseKind::Sqlite => unreachable!(),
            };
            vec![sql]
        }
        SchemaOp::DropIndex { table, index } => {
            let qidx = quote_ident_if_needed(index.effective_name(kind), kind);
            let sql = match kind {
                DatabaseKind::Mysql => {
                    let qt = quote_ident_if_needed(table, kind);
                    format!("DROP INDEX {qidx} ON {qt}")
                }
                DatabaseKind::Sqlite | DatabaseKind::Postgresql => {
                    format!("DROP INDEX IF EXISTS {qidx}")
                }
            };
            vec![sql]
        }
        SchemaOp::DropUnique { table, unique } => {
            if kind == DatabaseKind::Sqlite {
                return Vec::new();
            }
            let qt = quote_ident_if_needed(table, kind);
            let unique_name = unique.effective_name(table, kind);
            let qname = quote_ident_if_needed(&unique_name, kind);
            let sql = match kind {
                DatabaseKind::Mysql => format!("ALTER TABLE {qt} DROP INDEX {qname}"),
                DatabaseKind::Postgresql => format!("ALTER TABLE {qt} DROP CONSTRAINT {qname}"),
                DatabaseKind::Sqlite => unreachable!(),
            };
            vec![sql]
        }
        SchemaOp::DropCheck { table, check } => {
            if kind == DatabaseKind::Sqlite {
                return Vec::new();
            }
            let qt = quote_ident_if_needed(table, kind);
            let check_name = check.effective_name(table, kind);
            let qname = quote_ident_if_needed(&check_name, kind);
            let sql = match kind {
                DatabaseKind::Mysql => format!("ALTER TABLE {qt} DROP CHECK {qname}"),
                DatabaseKind::Postgresql => format!("ALTER TABLE {qt} DROP CONSTRAINT {qname}"),
                DatabaseKind::Sqlite => unreachable!(),
            };
            vec![sql]
        }
        SchemaOp::DropTable { table, cascade } => {
            let qt = match kind {
                DatabaseKind::Mysql => format!("`{}`", table.name.replace('`', "``")),
                DatabaseKind::Sqlite | DatabaseKind::Postgresql => {
                    format!("\"{}\"", table.name.replace('"', "\"\""))
                }
            };
            let suffix = if *cascade && kind == DatabaseKind::Postgresql {
                " CASCADE"
            } else {
                ""
            };
            vec![format!("DROP TABLE IF EXISTS {qt}{suffix}")]
        }
        SchemaOp::CreateTable {
            table,
            deferred_fk_names,
        } => {
            vec![table.compile_create_table(kind, Some(deferred_fk_names))]
        }
        SchemaOp::RenameColumn {
            table,
            old_column,
            new_column,
            ..
        } => {
            vec![format!(
                "ALTER TABLE {} RENAME COLUMN {} TO {}",
                quote_ident_if_needed(table, kind),
                quote_ident_if_needed(&old_column.name, kind),
                quote_ident_if_needed(&new_column.name, kind)
            )]
        }
        SchemaOp::AddColumn { table, column } => {
            let qt = quote_ident_if_needed(table, kind);
            let mut stmts = vec![format!(
                "ALTER TABLE {qt} ADD COLUMN {}",
                column.compile_definition_sql(kind)
            )];
            if kind == DatabaseKind::Postgresql
                && let Some(comment) = &column.comment
            {
                stmts.push(pg_comment_sql(table, &column.name, Some(comment)));
            }
            stmts
        }
        SchemaOp::AlterColumn {
            table,
            old_column,
            new_column,
            type_changed,
            nullable_changed,
            default_changed,
            comment_changed,
            ..
        } => compile_alter_column_sql(
            table,
            old_column,
            new_column,
            *type_changed,
            *nullable_changed,
            *default_changed,
            *comment_changed,
            kind,
        ),
        SchemaOp::DropColumn { table, column } => {
            vec![format!(
                "ALTER TABLE {} DROP COLUMN {}",
                quote_ident_if_needed(table, kind),
                quote_ident_if_needed(&column.name, kind)
            )]
        }
        SchemaOp::SqliteRebuildTable {
            old_table,
            new_table,
            column_mapping,
            ..
        } => compile_sqlite_rebuild_sql(&old_table.name, new_table, column_mapping),
        SchemaOp::AddUnique { table, unique } => {
            if kind == DatabaseKind::Sqlite {
                return Vec::new();
            }
            let cols = unique
                .columns
                .iter()
                .map(|c| quote_ident_if_needed(c, kind))
                .collect::<Vec<_>>()
                .join(", ");
            vec![format!(
                "ALTER TABLE {} ADD CONSTRAINT {} UNIQUE ({cols})",
                quote_ident_if_needed(table, kind),
                quote_ident_if_needed(&unique.effective_name(table, kind), kind)
            )]
        }
        SchemaOp::AddCheck { table, check } => {
            if kind == DatabaseKind::Sqlite {
                return Vec::new();
            }
            vec![format!(
                "ALTER TABLE {} ADD CONSTRAINT {} CHECK ({})",
                quote_ident_if_needed(table, kind),
                quote_ident_if_needed(&check.effective_name(table, kind), kind),
                check.expr_for(kind)
            )]
        }
        SchemaOp::AddForeignKey { table, fk, .. } => {
            if kind == DatabaseKind::Sqlite {
                return Vec::new();
            }
            vec![format!(
                "ALTER TABLE {} ADD {}",
                quote_ident_if_needed(table, kind),
                fk.constraint_sql(table, kind)
            )]
        }
        SchemaOp::CreateIndex { table, index } => {
            vec![index.create_sql(kind, table)]
        }
        SchemaOp::SetColumnCommentPg {
            table,
            column,
            comment,
        } => {
            if kind != DatabaseKind::Postgresql {
                return Vec::new();
            }
            vec![pg_comment_sql(table, column, comment.as_deref())]
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_alter_column_sql(
    table: &str,
    _old_column: &ColumnIr,
    new_column: &ColumnIr,
    type_changed: bool,
    nullable_changed: bool,
    default_changed: bool,
    comment_changed: bool,
    kind: DatabaseKind,
) -> Vec<String> {
    let qt = quote_ident_if_needed(table, kind);
    let qcol = quote_ident_if_needed(&new_column.name, kind);
    match kind {
        DatabaseKind::Mysql => {
            // MySQL MODIFY COLUMN always replaces full type + nullability + default + comment.
            vec![format!(
                "ALTER TABLE {qt} MODIFY COLUMN {}",
                new_column.compile_definition_sql(DatabaseKind::Mysql)
            )]
        }
        DatabaseKind::Postgresql => {
            let mut stmts = Vec::new();
            if type_changed {
                stmts.push(format!(
                    "ALTER TABLE {qt} ALTER COLUMN {qcol} TYPE {}",
                    new_column.render_ddl_type(DatabaseKind::Postgresql)
                ));
            }
            if default_changed {
                match &new_column.server_default {
                    Some(def) => stmts.push(format!(
                        "ALTER TABLE {qt} ALTER COLUMN {qcol} SET DEFAULT {}",
                        def.render_expr(DatabaseKind::Postgresql)
                    )),
                    None => stmts.push(format!("ALTER TABLE {qt} ALTER COLUMN {qcol} DROP DEFAULT")),
                }
            }
            if nullable_changed {
                if new_column.nullable {
                    stmts.push(format!("ALTER TABLE {qt} ALTER COLUMN {qcol} DROP NOT NULL"));
                } else {
                    stmts.push(format!("ALTER TABLE {qt} ALTER COLUMN {qcol} SET NOT NULL"));
                }
            }
            if comment_changed {
                stmts.push(pg_comment_sql(
                    table,
                    &new_column.name,
                    new_column.comment.as_deref(),
                ));
            }
            stmts
        }
        DatabaseKind::Sqlite => Vec::new(),
    }
}

fn compile_sqlite_rebuild_sql(
    table_name: &str,
    new_table: &crate::db::schema::ir::TableIr,
    column_mapping: &[(String, String)],
) -> Vec<String> {
    let tmp_name = format!("_cfms_new_{table_name}");
    let mut staged = new_table.clone();
    staged.name = tmp_name.clone();

    let mut stmts = vec![staged.compile_create_table(DatabaseKind::Sqlite, None)];
    if !column_mapping.is_empty() {
        let dst_cols = column_mapping
            .iter()
            .map(|(col, _)| quote_ident_if_needed(col, DatabaseKind::Sqlite).into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        let src_exprs = column_mapping
            .iter()
            .map(|(_, expr)| expr.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        stmts.push(format!(
            "INSERT INTO \"{}\" ({dst_cols}) SELECT {src_exprs} FROM \"{}\"",
            tmp_name.replace('"', "\"\""),
            table_name.replace('"', "\"\"")
        ));
    }
    stmts.push(format!(
        "DROP TABLE \"{}\"",
        table_name.replace('"', "\"\"")
    ));
    stmts.push(format!(
        "ALTER TABLE \"{}\" RENAME TO \"{}\"",
        tmp_name.replace('"', "\"\""),
        table_name.replace('"', "\"\"")
    ));
    stmts
}

fn pg_comment_sql(table: &str, column: &str, comment: Option<&str>) -> String {
    let qt = quote_ident_if_needed(table, DatabaseKind::Postgresql);
    let qcol = quote_ident_if_needed(column, DatabaseKind::Postgresql);
    match comment {
        Some(text) => format!(
            "COMMENT ON COLUMN {qt}.{qcol} IS '{}'",
            text.replace('\'', "''")
        ),
        None => format!("COMMENT ON COLUMN {qt}.{qcol} IS NULL"),
    }
}

/// Render a risk-annotated native SQL migration file via MiniJinja.
pub fn render_native_ddl_sql(
    plan: &SchemaDiffPlan,
    audit: &RiskAuditReport,
    opts: &SqlRenderOptions,
) -> Result<String> {
    let mut env = Environment::new();
    env.add_template("native_ddl", NATIVE_DDL_TEMPLATE)
        .map_err(|e| CfmsError::Database(format!("Failed to load SQL template: {e}")))?;

    let mut op_blocks = Vec::new();
    let mut needs_sqlite_fk_toggle = false;

    for (idx, op) in plan.operations.iter().enumerate() {
        let stmts = compile_op_to_sql_statements(op, opts.dialect);
        if stmts.is_empty() {
            continue;
        }
        if opts.dialect == DatabaseKind::Sqlite
            && matches!(
                op,
                SchemaOp::SqliteRebuildTable { .. } | SchemaOp::DropTable { .. }
            )
        {
            needs_sqlite_fk_toggle = true;
        }
        op_blocks.push(SqlOpBlock {
            phase: op.phase().phase_label(),
            risk_comments: audit.comments_for_op(idx),
            statements: stmts,
        });
    }

    let set_alembic_version_sql = if opts.include_alembic_version_stamp {
        plan.to_revision.as_ref().map(|rev| {
            format!(
                "DELETE FROM alembic_version; INSERT INTO alembic_version (version_num) VALUES ('{}')",
                rev.replace('\'', "''")
            )
        })
    } else {
        None
    };

    // SQLite forbids toggling PRAGMA foreign_keys inside an explicit transaction.
    let wrap_in_transaction = opts.wrap_in_transaction && !needs_sqlite_fk_toggle;

    let tmpl = env
        .get_template("native_ddl")
        .map_err(|e| CfmsError::Database(format!("Failed to fetch SQL template: {e}")))?;
    tmpl.render(context! {
        dialect => opts.dialect.as_str(),
        from_revision => plan.from_revision.as_deref().unwrap_or("<live/unknown>"),
        to_revision => plan.to_revision.as_deref().unwrap_or("<target/unknown>"),
        max_risk_level => audit.max_level.label(),
        has_blocking_risks => audit.has_blocking_risks,
        findings => Serde(&audit.findings),
        warnings => &plan.warnings,
        needs_sqlite_fk_toggle => needs_sqlite_fk_toggle,
        wrap_in_transaction => wrap_in_transaction,
        op_blocks => Serde(&op_blocks),
        set_alembic_version_sql => &set_alembic_version_sql,
    })
    .map_err(|e| CfmsError::Database(format!("Failed to render native DDL SQL: {e}")))
}

/// Render a risk-annotated multi-engine Alembic Python migration file via MiniJinja.
pub fn render_alembic_migration_script(
    plan: &SchemaDiffPlan,
    audit: &RiskAuditReport,
    opts: &AlembicRenderOptions,
) -> Result<String> {
    let mut env = Environment::new();
    env.add_template("alembic_migration", ALEMBIC_MIGRATION_TEMPLATE)
        .map_err(|e| CfmsError::Database(format!("Failed to load Alembic template: {e}")))?;

    let (upgrade_lines, downgrade_lines) = build_alembic_body_lines(plan, audit);

    let down_rev = opts
        .down_revision
        .as_ref()
        .or(plan.from_revision.as_ref());
    let down_revision_repr = match down_rev {
        Some(r) => format!("{r:?}"),
        None => "None".to_string(),
    };
    let revision_repr = format!("{:?}", opts.revision);

    let tmpl = env
        .get_template("alembic_migration")
        .map_err(|e| CfmsError::Database(format!("Failed to fetch Alembic template: {e}")))?;
    tmpl.render(context! {
        summary_title => &opts.summary_title,
        revision => &opts.revision,
        revision_repr => revision_repr,
        down_revision_repr => down_revision_repr,
        max_risk_level => audit.max_level.label(),
        has_blocking_risks => audit.has_blocking_risks,
        findings => Serde(&audit.findings),
        warnings => &plan.warnings,
        upgrade_lines => upgrade_lines,
        downgrade_lines => downgrade_lines,
    })
    .map_err(|e| CfmsError::Database(format!("Failed to render Alembic script: {e}")))
}

fn build_alembic_body_lines(
    plan: &SchemaDiffPlan,
    audit: &RiskAuditReport,
) -> (Vec<String>, Vec<String>) {
    let mut upgrade_lines = Vec::new();
    let mut downgrade_entries: Vec<Vec<String>> = Vec::new();

    // Group contiguous batch-alterable operations per table so Alembic stays concise.
    let mut batch_up_by_table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut batch_down_by_table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut non_batch_ops: Vec<(usize, &SchemaOp)> = Vec::new();

    for (idx, op) in plan.operations.iter().enumerate() {
        let risk_lines = audit
            .comments_for_op(idx)
            .into_iter()
            .map(|c| format!("# {c}"))
            .collect::<Vec<_>>();

        match op {
            SchemaOp::AddColumn { table, column } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.add_column({})",
                    alembic_sa_column(column)
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!("batch_op.drop_column({:?})", column.name));
            }
            SchemaOp::DropColumn { table, column } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!("batch_op.drop_column({:?})", column.name));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "# [IRREVERSIBLE] Column `{table}.{}` cannot restore previous row data",
                    column.name
                ));
                dn.push(format!("batch_op.add_column({})", alembic_sa_column(column)));
            }
            SchemaOp::RenameColumn {
                table,
                old_column,
                new_column,
                ..
            } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.alter_column({:?}, new_column_name={:?}, existing_type={}, existing_nullable={})",
                    old_column.name,
                    new_column.name,
                    old_column.canonical_type.alembic_type_expr(),
                    py_bool(old_column.nullable)
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "batch_op.alter_column({:?}, new_column_name={:?}, existing_type={}, existing_nullable={})",
                    new_column.name,
                    old_column.name,
                    new_column.canonical_type.alembic_type_expr(),
                    py_bool(new_column.nullable)
                ));
            }
            SchemaOp::AlterColumn {
                table,
                old_column,
                new_column,
                type_changed,
                nullable_changed,
                default_changed,
                ..
            } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format_alembic_alter_column(
                    old_column,
                    new_column,
                    *type_changed,
                    *nullable_changed,
                    *default_changed,
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format_alembic_alter_column(
                    new_column,
                    old_column,
                    *type_changed,
                    *nullable_changed,
                    *default_changed,
                ));
            }
            SchemaOp::AddUnique { table, unique } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.create_unique_constraint({:?}, {:?})",
                    unique.effective_name(table, DatabaseKind::Postgresql),
                    unique.columns
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "batch_op.drop_constraint({:?}, type_='unique')",
                    unique.effective_name(table, DatabaseKind::Postgresql)
                ));
            }
            SchemaOp::DropUnique { table, unique } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.drop_constraint({:?}, type_='unique')",
                    unique.effective_name(table, DatabaseKind::Postgresql)
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "batch_op.create_unique_constraint({:?}, {:?})",
                    unique.effective_name(table, DatabaseKind::Postgresql),
                    unique.columns
                ));
            }
            SchemaOp::AddCheck { table, check } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.create_check_constraint({:?}, {:?})",
                    check.effective_name(table, DatabaseKind::Postgresql),
                    check.expression
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "batch_op.drop_constraint({:?}, type_='check')",
                    check.effective_name(table, DatabaseKind::Postgresql)
                ));
            }
            SchemaOp::DropCheck { table, check } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.drop_constraint({:?}, type_='check')",
                    check.effective_name(table, DatabaseKind::Postgresql)
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "batch_op.create_check_constraint({:?}, {:?})",
                    check.effective_name(table, DatabaseKind::Postgresql),
                    check.expression
                ));
            }
            SchemaOp::AddForeignKey { table, fk, .. } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format_alembic_batch_fk(table, fk));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format!(
                    "batch_op.drop_constraint({:?}, type_='foreignkey')",
                    fk.effective_name(table, DatabaseKind::Postgresql)
                ));
            }
            SchemaOp::DropForeignKey { table, fk } => {
                let up = batch_up_by_table.entry(table.clone()).or_default();
                up.extend(risk_lines);
                up.push(format!(
                    "batch_op.drop_constraint({:?}, type_='foreignkey')",
                    fk.effective_name(table, DatabaseKind::Postgresql)
                ));
                let dn = batch_down_by_table.entry(table.clone()).or_default();
                dn.push(format_alembic_batch_fk(table, fk));
            }
            other => {
                non_batch_ops.push((idx, other));
            }
        }
    }

    // Emit pre-drops, drop_table, create_table cleanly in order, then batch blocks, then indexes.
    for (idx, op) in non_batch_ops {
        let risk_lines: Vec<String> = audit
            .comments_for_op(idx)
            .into_iter()
            .map(|c| format!("# {c}"))
            .collect();
        match op {
            SchemaOp::DropIndex { table, index } => {
                upgrade_lines.extend(risk_lines);
                upgrade_lines.push(format!("op.drop_index({:?}, table_name={table:?})", index.name));
                downgrade_entries.push(vec![alembic_create_index(table, index)]);
            }
            SchemaOp::DropTable { table, .. } => {
                upgrade_lines.extend(risk_lines);
                upgrade_lines.push(format!("op.drop_table({:?})", table.name));
                downgrade_entries.push(vec![format!(
                    "# [IRREVERSIBLE] Recreating dropped table `{}` will NOT restore lost rows",
                    table.name
                )]);
            }
            SchemaOp::CreateTable { table, .. } => {
                upgrade_lines.extend(risk_lines);
                upgrade_lines.extend(alembic_create_table_lines(table));
                downgrade_entries.push(vec![format!("op.drop_table({:?})", table.name)]);
            }
            SchemaOp::CreateIndex { table, index } => {
                upgrade_lines.extend(risk_lines);
                upgrade_lines.push(alembic_create_index(table, index));
                downgrade_entries.push(vec![format!(
                    "op.drop_index({:?}, table_name={table:?})",
                    index.name
                )]);
            }
            _ => {}
        }
    }

    for (table, stmts) in batch_up_by_table {
        upgrade_lines.push(format!(
            "with op.batch_alter_table({table:?}, schema=None) as batch_op:"
        ));
        for line in stmts {
            upgrade_lines.push(format!("    {line}"));
        }
    }

    for (table, stmts) in batch_down_by_table.into_iter().rev() {
        let mut block = vec![format!(
            "with op.batch_alter_table({table:?}, schema=None) as batch_op:"
        )];
        for line in stmts.into_iter().rev() {
            block.push(format!("    {line}"));
        }
        downgrade_entries.push(block);
    }

    let downgrade_lines = downgrade_entries.into_iter().rev().flatten().collect();
    (upgrade_lines, downgrade_lines)
}

fn alembic_sa_column(col: &ColumnIr) -> String {
    let mut parts = vec![
        format!("{:?}", col.name),
        col.canonical_type.alembic_type_expr(),
        format!("nullable={}", py_bool(col.nullable)),
    ];
    if let Some(comp) = &col.computed {
        parts.insert(
            2,
            format!(
                "sa.Computed({:?}, persisted={})",
                comp.expression,
                py_bool(comp.persisted)
            ),
        );
    }
    if let Some(def) = &col.server_default {
        parts.push(format!("server_default={}", def.alembic_server_default()));
    }
    if let Some(comment) = &col.comment {
        parts.push(format!("comment={comment:?}"));
    }
    format!("sa.Column({})", parts.join(", "))
}

fn format_alembic_alter_column(
    old_col: &ColumnIr,
    new_col: &ColumnIr,
    type_changed: bool,
    nullable_changed: bool,
    default_changed: bool,
) -> String {
    let mut args = vec![format!("{:?}", new_col.name)];
    args.push(format!(
        "existing_type={}",
        old_col.canonical_type.alembic_type_expr()
    ));
    args.push(format!("existing_nullable={}", py_bool(old_col.nullable)));
    if type_changed {
        args.push(format!("type_={}", new_col.canonical_type.alembic_type_expr()));
    }
    if nullable_changed {
        args.push(format!("nullable={}", py_bool(new_col.nullable)));
    }
    if default_changed {
        match &new_col.server_default {
            Some(def) => args.push(format!("server_default={}", def.alembic_server_default())),
            None => args.push("server_default=None".to_string()),
        }
    }
    format!("batch_op.alter_column({})", args.join(", "))
}

fn format_alembic_batch_fk(table: &str, fk: &ForeignKeyIr) -> String {
    let name = fk.effective_name(table, DatabaseKind::Postgresql);
    let mut args = vec![
        format!("{name:?}"),
        format!("{:?}", fk.ref_table),
        format!("{:?}", fk.columns),
        format!("{:?}", fk.ref_columns),
    ];
    if let Some(act) = fk.on_delete.and_then(|a| a.alembic_str()) {
        args.push(format!("ondelete={act:?}"));
    }
    if let Some(act) = fk.on_update.and_then(|a| a.alembic_str()) {
        args.push(format!("onupdate={act:?}"));
    }
    format!("batch_op.create_foreign_key({})", args.join(", "))
}

fn alembic_create_table_lines(table: &crate::db::schema::ir::TableIr) -> Vec<String> {
    let mut lines = vec!["op.create_table(".to_string(), format!("    {:?},", table.name)];
    for col in &table.columns {
        lines.push(format!("    {},", alembic_sa_column(col)));
    }
    if !table.primary_key.columns.is_empty() {
        let pk_name = table.primary_key.effective_name(&table.name, DatabaseKind::Postgresql);
        let pk_cols = table
            .primary_key
            .columns
            .iter()
            .map(|c| format!("{c:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "    sa.PrimaryKeyConstraint({pk_cols}, name={pk_name:?}),"
        ));
    }
    for ck in &table.checks {
        let ck_name = ck.effective_name(&table.name, DatabaseKind::Postgresql);
        lines.push(format!(
            "    sa.CheckConstraint({:?}, name={ck_name:?}),",
            ck.expression
        ));
    }
    for uq in &table.uniques {
        let uq_name = uq.effective_name(&table.name, DatabaseKind::Postgresql);
        let cols = uq
            .columns
            .iter()
            .map(|c| format!("{c:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "    sa.UniqueConstraint({cols}, name={uq_name:?}),"
        ));
    }
    for fk in &table.foreign_keys {
        let fk_name = fk.effective_name(&table.name, DatabaseKind::Postgresql);
        let ref_targets: Vec<String> = fk
            .ref_columns
            .iter()
            .map(|rc| format!("{}.{rc}", fk.ref_table))
            .collect();
        let mut extra = String::new();
        if let Some(act) = fk.on_delete.and_then(|a| a.alembic_str()) {
            extra.push_str(&format!(", ondelete={act:?}"));
        }
        extra.push_str(&format!(", name={fk_name:?}"));
        lines.push(format!(
            "    sa.ForeignKeyConstraint({:?}, {:?}{extra}),",
            fk.columns, ref_targets
        ));
    }
    lines.push(")".to_string());
    lines
}

fn alembic_create_index(table: &str, index: &IndexIr) -> String {
    let cols = index
        .expressions
        .iter()
        .map(|expr| {
            let trimmed = expr.trim();
            if trimmed.contains('(') {
                format!("sa.text({trimmed:?})")
            } else {
                format!("{trimmed:?}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut base = format!(
        "op.create_index({:?}, {table:?}, [{cols}], unique={}",
        index.name,
        py_bool(index.unique)
    );
    if let Some(w) = &index.where_clause {
        base.push_str(&format!(", sqlite_where=sa.text({w:?}), postgresql_where=sa.text({w:?})"));
    }
    base.push(')');
    base
}

const fn py_bool(v: bool) -> &'static str {
    if v { "True" } else { "False" }
}

trait ExecutionPhaseLabel {
    fn phase_label(self) -> &'static str;
}

impl ExecutionPhaseLabel for crate::db::schema::diff::ExecutionPhase {
    fn phase_label(self) -> &'static str {
        match self {
            Self::PreDropConstraints => "pre_drop_constraints",
            Self::DropTables => "drop_tables",
            Self::CreateTables => "create_tables",
            Self::TableMigrations => "table_migrations",
            Self::PostConstraintsAndIndexes => "post_constraints_and_indexes",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ddl::builtin_schema_ir;
    use crate::db::schema::diff::{DiffOptions, diff_schemas};
    use crate::db::schema::ir::{CanonicalType, ConfidenceLevel, ServerDefaultIr};
    use crate::db::schema::risk::audit_diff_plan;
    use crate::db::schema::static_ast::parse_python_syntax_check;

    #[test]
    fn renders_valid_alembic_python_and_native_sql_across_dialects() {
        let old = builtin_schema_ir(false);
        let mut new = builtin_schema_ir(false);
        new.schema_revision = Some("next_rev_0001".to_string());

        let users = new.tables.get_mut("users").unwrap();
        users.columns.push(ColumnIr {
            name: "bio".to_string(),
            ordinal: 99,
            canonical_type: CanonicalType::Text,
            dialect_types: BTreeMap::new(),
            nullable: true,
            autoincrement: false,
            server_default: Some(ServerDefaultIr::String {
                value: "".to_string(),
            }),
            computed: None,
            comment: Some("User profile bio".to_string()),
            confidence: ConfidenceLevel::High,
        });
        if let Some(uname) = users.columns.iter_mut().find(|c| c.name == "username") {
            uname.canonical_type = CanonicalType::Varchar { length: Some(64) };
        }

        // Alembic rendering (syntax verified via ruff_python_parser!)
        let ag_plan = diff_schemas(&old, &new, &DiffOptions::default());
        let ag_audit = audit_diff_plan(&ag_plan, Some(&new), None);
        let py = render_alembic_migration_script(
            &ag_plan,
            &ag_audit,
            &AlembicRenderOptions {
                revision: "next_rev_0001".to_string(),
                down_revision: old.schema_revision.clone(),
                summary_title: "Add user bio & resize username".to_string(),
            },
        )
        .expect("render alembic");
        parse_python_syntax_check(&py).expect("valid Python syntax");
        assert!(py.contains("[RISK: HIGH CFMS-MIG-005]"));
        assert!(py.contains("batch_op.add_column"));

        // Native SQL across all 3 engines
        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Mysql,
            DatabaseKind::Postgresql,
        ] {
            let plan = diff_schemas(
                &old,
                &new,
                &DiffOptions {
                    dialect: Some(kind),
                    ..Default::default()
                },
            );
            let audit = audit_diff_plan(&plan, Some(&new), None);
            let sql = render_native_ddl_sql(&plan, &audit, &SqlRenderOptions::new(kind))
                .expect("render sql");
            assert!(sql.contains("CFMS-MIG-005"), "sql for {kind}:\n{sql}");
            match kind {
                DatabaseKind::Sqlite => assert!(sql.contains("PRAGMA foreign_key_check;")),
                DatabaseKind::Mysql => assert!(sql.contains("MODIFY COLUMN username VARCHAR(64) NOT NULL")),
                DatabaseKind::Postgresql => assert!(sql.contains("COMMENT ON COLUMN users.bio")),
            }
        }
    }
}
