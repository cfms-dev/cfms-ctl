//! Live database schema introspector for SQLite, MySQL 8.0+, and PostgreSQL 12+.
//!
//! Converts live catalog tables (`sqlite_master` / `PRAGMA`, `information_schema`,
//! and `pg_catalog`) into the unified [`SchemaIr`] for column-level drift inspection,
//! preflight verification, and live-to-code diffs.

use std::collections::{BTreeMap, HashMap};

use sqlx::Row;

use crate::core::error::Result;
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::ir::{
    CanonicalType, CheckIr, ColumnIr, ComputedColumnIr, ConfidenceLevel, ExtractionSource,
    ForeignKeyIr, IndexIr, PrimaryKeyIr, ReferentialAction, SchemaIr, ServerDefaultIr, TableIr,
    TableOwnership, UniqueIr,
};
use crate::db::schema::registry::KNOWN_EXTENSION_TABLES;

/// Introspect a running database backend into a normalized [`SchemaIr`].
pub async fn introspect_live_schema_ir(
    pool: &DbPool,
    include_extensions: bool,
    ownership_hints: Option<&BTreeMap<String, TableOwnership>>,
) -> Result<SchemaIr> {
    let revision = pool.current_revision().await?;
    let mut ir = SchemaIr::new(ExtractionSource::LiveDatabase, revision);

    let tables = match pool {
        DbPool::Sqlite(p) => introspect_sqlite(p).await?,
        DbPool::Mysql(p) => introspect_mysql(p).await?,
        DbPool::Postgres(p) => introspect_postgres(p).await?,
    };

    for (name, mut table) in tables {
        let ownership = ownership_hints
            .and_then(|h| h.get(&name).cloned())
            .unwrap_or_else(|| default_table_ownership(&name));
        table.ownership = ownership;
        if !include_extensions && table.ownership.is_extension() {
            continue;
        }
        table.sort_columns_by_ordinal();
        ir.tables.insert(name, table);
    }

    Ok(ir)
}

fn default_table_ownership(table_name: &str) -> TableOwnership {
    if KNOWN_EXTENSION_TABLES.contains(&table_name) {
        TableOwnership::Extension("oidc_sso".to_string())
    } else {
        TableOwnership::Core
    }
}

async fn introspect_sqlite(pool: &sqlx::SqlitePool) -> Result<BTreeMap<String, TableIr>> {
    let master_rows = sqlx::query(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    let idx_sql_rows = sqlx::query(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(pool)
    .await?;
    let mut idx_sql_map: HashMap<String, String> = HashMap::new();
    for row in idx_sql_rows {
        let idx_name: String = row.get(0);
        let sql_opt: Option<String> = row.get(1);
        if let Some(s) = sql_opt {
            idx_sql_map.insert(idx_name, s);
        }
    }

    let mut tables = BTreeMap::new();
    for row in master_rows {
        let table_name: String = row.get(0);
        if table_name == "alembic_version" {
            continue;
        }
        let table_sql: String = row.try_get::<Option<String>, _>(1)?.unwrap_or_default();
        let escaped = table_name.replace('"', "\"\"");

        let parsed_ddl = parse_sqlite_table_ddl(&table_sql);

        let col_rows = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_xinfo(\"{escaped}\")")))
            .fetch_all(pool)
            .await?;

        let mut pk_pairs: Vec<(i64, String)> = Vec::new();
        let mut columns = Vec::new();
        for (idx, r) in col_rows.into_iter().enumerate() {
            let hidden: i64 = r.get("hidden");
            if hidden == 1 {
                continue;
            }
            let name: String = r.get("name");
            let raw_ty: String = r.get("type");
            let notnull: i64 = r.get("notnull");
            let dflt: Option<String> = r.get("dflt_value");
            let pk_pos: i64 = r.get("pk");

            if pk_pos > 0 {
                pk_pairs.push((pk_pos, name.clone()));
            }

            let computed = if matches!(hidden, 2 | 3) {
                parsed_ddl
                    .generated_cols
                    .get(&name)
                    .map(|(expr, persisted)| ComputedColumnIr {
                        expression: expr.clone(),
                        persisted: *persisted,
                        dialect_expressions: BTreeMap::new(),
                    })
                    .or_else(|| {
                        Some(ComputedColumnIr {
                            expression: String::new(),
                            persisted: hidden == 3,
                            dialect_expressions: BTreeMap::new(),
                        })
                    })
            } else {
                None
            };

            let canonical_type = parse_sql_type_name(&raw_ty, DatabaseKind::Sqlite);
            let server_default = if computed.is_some() {
                None
            } else {
                parse_reflected_default(dflt.as_deref(), &canonical_type)
            };

            columns.push(ColumnIr {
                name,
                ordinal: idx,
                dialect_types: BTreeMap::from([(DatabaseKind::Sqlite, raw_ty)]),
                canonical_type,
                nullable: notnull == 0 && pk_pos == 0,
                autoincrement: false,
                server_default,
                computed,
                comment: None,
                confidence: ConfidenceLevel::High,
            });
        }

        pk_pairs.sort_by_key(|(pos, _)| *pos);
        let pk_columns: Vec<String> = pk_pairs.into_iter().map(|(_, c)| c).collect();
        if pk_columns.len() == 1 {
            let pk_name = &pk_columns[0];
            if let Some(col) = columns.iter_mut().find(|c| c.name == *pk_name)
                && matches!(col.canonical_type, CanonicalType::Integer)
            {
                col.autoincrement = true;
                col.nullable = false;
            }
        }

        // Foreign keys
        struct SqliteFkEntry {
            seq: i64,
            from_col: String,
            ref_table: String,
            to_col: String,
            on_delete: String,
            on_update: String,
        }
        let fk_rows =
            sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA foreign_key_list(\"{escaped}\")")))
                .fetch_all(pool)
                .await?;
        let mut fk_groups: BTreeMap<i64, Vec<SqliteFkEntry>> = BTreeMap::new();
        for r in fk_rows {
            let id: i64 = r.get("id");
            let entry = SqliteFkEntry {
                seq: r.get("seq"),
                from_col: r.get("from"),
                ref_table: r.get("table"),
                to_col: r
                    .try_get::<Option<String>, _>("to")?
                    .unwrap_or_else(|| "id".to_string()),
                on_delete: r.get("on_delete"),
                on_update: r.get("on_update"),
            };
            fk_groups.entry(id).or_default().push(entry);
        }

        let mut foreign_keys = Vec::new();
        for (_, mut elems) in fk_groups {
            elems.sort_by_key(|e| e.seq);
            let cols: Vec<String> = elems.iter().map(|e| e.from_col.clone()).collect();
            let ref_table = elems[0].ref_table.clone();
            let ref_cols: Vec<String> = elems.iter().map(|e| e.to_col.clone()).collect();
            let on_delete = ReferentialAction::from_sql_str(&elems[0].on_delete);
            let on_update = ReferentialAction::from_sql_str(&elems[0].on_update);
            let fk_name = parsed_ddl
                .fk_names
                .get(&(cols.clone(), ref_table.clone()))
                .cloned()
                .or_else(|| {
                    Some(format!(
                        "fk_{table_name}_{}_{}",
                        cols.first().map_or("col", String::as_str),
                        ref_table
                    ))
                });
            foreign_keys.push(ForeignKeyIr {
                name: fk_name,
                dialect_names: BTreeMap::new(),
                columns: cols,
                ref_table,
                ref_columns: ref_cols,
                on_delete,
                on_update,
                defer_on_create: false,
            });
        }

        // Indexes & Unique constraints
        let idx_list =
            sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA index_list(\"{escaped}\")")))
                .fetch_all(pool)
                .await?;
        let mut uniques = Vec::new();
        let mut indexes = Vec::new();

        for r in idx_list {
            let idx_name: String = r.get("name");
            let is_unique: i64 = r.get("unique");
            let origin: String = r.get("origin");
            if origin == "pk" {
                continue;
            }
            let esc_idx = idx_name.replace('"', "\"\"");
            let xinfo = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA index_xinfo(\"{esc_idx}\")")))
                .fetch_all(pool)
                .await?;

            let mut expr_cols: Vec<(i64, Option<String>)> = xinfo
                .into_iter()
                .filter_map(|xr| {
                    let seqno: i64 = xr.get("seqno");
                    let key: i64 = xr.get("key");
                    let col_name: Option<String> = xr.get("name");
                    if key == 1 {
                        Some((seqno, col_name))
                    } else {
                        None
                    }
                })
                .collect();
            expr_cols.sort_by_key(|(s, _)| *s);

            if origin == "u" {
                let cols: Vec<String> = expr_cols.into_iter().filter_map(|(_, c)| c).collect();
                let uq_name = parsed_ddl
                    .uq_names
                    .get(&cols)
                    .cloned()
                    .or_else(|| {
                        if idx_name.starts_with("sqlite_autoindex_") {
                            Some(format!(
                                "uq_{table_name}_{}",
                                cols.first().map_or("col", String::as_str)
                            ))
                        } else {
                            Some(idx_name)
                        }
                    });
                uniques.push(UniqueIr {
                    name: uq_name,
                    dialect_names: BTreeMap::new(),
                    columns: cols,
                });
            } else {
                let (exprs, where_clause) = if let Some(raw_idx_sql) = idx_sql_map.get(&idx_name) {
                    parse_sqlite_index_sql(raw_idx_sql)
                } else {
                    (
                        expr_cols.into_iter().filter_map(|(_, c)| c).collect(),
                        None,
                    )
                };
                indexes.push(IndexIr {
                    name: idx_name,
                    dialect_names: BTreeMap::new(),
                    unique: is_unique != 0,
                    expressions: exprs,
                    dialect_clauses: BTreeMap::new(),
                    where_clause,
                });
            }
        }

        tables.insert(
            table_name.clone(),
            TableIr {
                name: table_name.clone(),
                ownership: TableOwnership::Core,
                columns,
                primary_key: PrimaryKeyIr {
                    name: parsed_ddl.pk_name.or_else(|| Some(format!("pk_{table_name}"))),
                    dialect_names: BTreeMap::new(),
                    columns: pk_columns,
                },
                foreign_keys,
                uniques,
                checks: parsed_ddl.checks,
                indexes,
                comment: None,
                confidence: ConfidenceLevel::High,
            },
        );
    }

    Ok(tables)
}

#[derive(Default)]
struct ParsedSqliteDdl {
    pk_name: Option<String>,
    checks: Vec<CheckIr>,
    uq_names: HashMap<Vec<String>, String>,
    fk_names: HashMap<(Vec<String>, String), String>,
    generated_cols: HashMap<String, (String, bool)>,
}

fn parse_sqlite_table_ddl(sql: &str) -> ParsedSqliteDdl {
    let mut parsed = ParsedSqliteDdl::default();
    let Some(open) = sql.find('(') else {
        return parsed;
    };
    let Some(close) = sql.rfind(')') else {
        return parsed;
    };
    let body = &sql[open + 1..close];
    for item in split_top_level_sql_items(body) {
        let trimmed = item.trim();
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("CONSTRAINT ") {
            let rest = trimmed["CONSTRAINT ".len()..].trim();
            if let Some((cname, clause)) = split_ident_and_rest(rest) {
                let c_upper = clause.to_ascii_uppercase();
                if c_upper.starts_with("PRIMARY KEY") {
                    parsed.pk_name = Some(cname);
                } else if c_upper.starts_with("CHECK")
                    && let Some(expr) = extract_paren_inner(&clause[5..])
                {
                    parsed.checks.push(CheckIr {
                        name: Some(cname),
                        dialect_names: BTreeMap::new(),
                        expression: expr,
                        dialect_expressions: BTreeMap::new(),
                    });
                } else if c_upper.starts_with("UNIQUE")
                    && let Some(inner) = extract_paren_inner(&clause[6..])
                {
                    let cols = split_ident_list(&inner);
                    parsed.uq_names.insert(cols, cname);
                } else if c_upper.starts_with("FOREIGN KEY")
                    && let Some(fk_cols_inner) = extract_paren_inner(&clause[11..])
                {
                    let cols = split_ident_list(&fk_cols_inner);
                    if let Some(ref_pos) = c_upper.find("REFERENCES ") {
                        let ref_rest = clause[ref_pos + 11..].trim();
                        if let Some((ref_table, _)) = split_ident_and_rest(ref_rest) {
                            parsed.fk_names.insert((cols, ref_table), cname);
                        }
                    }
                }
            }
        } else if upper.contains("GENERATED ALWAYS AS")
            && let Some((col_name, col_rest)) = split_ident_and_rest(trimmed)
        {
            let rest_up = col_rest.to_ascii_uppercase();
            if let Some(pos) = rest_up.find("GENERATED ALWAYS AS")
                && let Some(expr) = extract_paren_inner(&col_rest[pos + 19..])
            {
                let persisted = !rest_up.contains("VIRTUAL");
                parsed.generated_cols.insert(col_name, (expr, persisted));
            }
        }
    }
    parsed
}

fn parse_sqlite_index_sql(sql: &str) -> (Vec<String>, Option<String>) {
    let Some(open) = sql.find('(') else {
        return (Vec::new(), None);
    };
    let mut depth = 0usize;
    let mut in_single = false;
    let mut close_idx = None;
    for (offset, ch) in sql[open..].char_indices() {
        match ch {
            '\'' => in_single = !in_single,
            '(' if !in_single => depth += 1,
            ')' if !in_single => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close_idx = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close_idx else {
        return (Vec::new(), None);
    };
    let exprs = split_top_level_sql_items(&sql[open + 1..close])
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let after = sql[close + 1..].trim();
    let where_clause = after
        .to_ascii_uppercase()
        .find("WHERE ")
        .map(|pos| after[pos + 6..].trim().to_string());
    (exprs, where_clause)
}

async fn introspect_mysql(pool: &sqlx::MySqlPool) -> Result<BTreeMap<String, TableIr>> {
    let mut tables: BTreeMap<String, TableIr> = BTreeMap::new();

    let col_rows = sqlx::query(
        "SELECT table_name, column_name, CAST(ordinal_position AS SIGNED) AS pos, \
         column_type, is_nullable, column_default, extra, generation_expression, column_comment \
         FROM information_schema.columns \
         WHERE table_schema = DATABASE() \
         ORDER BY table_name, ordinal_position",
    )
    .fetch_all(pool)
    .await?;

    for row in col_rows {
        let table_name: String = row.get(0);
        if table_name == "alembic_version" {
            continue;
        }
        let col_name: String = row.get(1);
        let pos: i64 = row.get(2);
        let raw_ty: String = row.get(3);
        let is_nullable: String = row.get(4);
        let dflt: Option<String> = row.get(5);
        let extra: String = row.try_get::<Option<String>, _>(6)?.unwrap_or_default();
        let gen_expr: String = row.try_get::<Option<String>, _>(7)?.unwrap_or_default();
        let comment: String = row.try_get::<Option<String>, _>(8)?.unwrap_or_default();

        let extra_upper = extra.to_ascii_uppercase();
        let autoinc = extra_upper.contains("AUTO_INCREMENT");
        let mut canonical_type = parse_sql_type_name(&raw_ty, DatabaseKind::Mysql);
        if autoinc {
            canonical_type = match canonical_type {
                CanonicalType::BigInt | CanonicalType::SqliteIntElseBigInt => CanonicalType::BigSerial,
                CanonicalType::Integer => CanonicalType::Serial,
                other => other,
            };
        }

        let computed = if extra_upper.contains("GENERATED") && !gen_expr.trim().is_empty() {
            Some(ComputedColumnIr {
                expression: gen_expr,
                persisted: !extra_upper.contains("VIRTUAL"),
                dialect_expressions: BTreeMap::new(),
            })
        } else {
            None
        };

        let server_default = if computed.is_some() {
            None
        } else {
            parse_reflected_default(dflt.as_deref(), &canonical_type)
        };

        let table = tables.entry(table_name.clone()).or_insert_with(|| TableIr {
            name: table_name,
            ownership: TableOwnership::Core,
            columns: Vec::new(),
            primary_key: PrimaryKeyIr::default(),
            foreign_keys: Vec::new(),
            uniques: Vec::new(),
            checks: Vec::new(),
            indexes: Vec::new(),
            comment: None,
            confidence: ConfidenceLevel::High,
        });

        table.columns.push(ColumnIr {
            name: col_name,
            ordinal: usize::try_from((pos - 1).max(0)).unwrap_or(0),
            dialect_types: BTreeMap::from([(DatabaseKind::Mysql, raw_ty)]),
            canonical_type,
            nullable: is_nullable.eq_ignore_ascii_case("YES"),
            autoincrement: autoinc,
            server_default,
            computed,
            comment: if comment.is_empty() { None } else { Some(comment) },
            confidence: ConfidenceLevel::High,
        });
    }

    // Primary Keys & Unique Constraints
    let key_rows = sqlx::query(
        "SELECT tc.table_name, tc.constraint_name, tc.constraint_type, kcu.column_name \
         FROM information_schema.table_constraints tc \
         JOIN information_schema.key_column_usage kcu \
           ON tc.constraint_schema = kcu.constraint_schema \
          AND tc.table_name = kcu.table_name \
          AND tc.constraint_name = kcu.constraint_name \
         WHERE tc.table_schema = DATABASE() \
           AND tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE') \
         ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position",
    )
    .fetch_all(pool)
    .await?;

    let mut uq_groups: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for row in key_rows {
        let tname: String = row.get(0);
        let cname: String = row.get(1);
        let ctype: String = row.get(2);
        let col: String = row.get(3);
        let Some(table) = tables.get_mut(&tname) else {
            continue;
        };
        if ctype == "PRIMARY KEY" {
            table.primary_key.columns.push(col);
            if table.primary_key.name.is_none() {
                table.primary_key.name = Some(format!("pk_{tname}"));
            }
        } else {
            uq_groups.entry((tname, cname)).or_default().push(col);
        }
    }
    for ((tname, cname), cols) in uq_groups {
        if let Some(table) = tables.get_mut(&tname) {
            table.uniques.push(UniqueIr {
                name: Some(cname),
                dialect_names: BTreeMap::new(),
                columns: cols,
            });
        }
    }

    // Foreign Keys
    let fk_rows = sqlx::query(
        "SELECT kcu.table_name, kcu.constraint_name, kcu.column_name, \
         kcu.referenced_table_name, kcu.referenced_column_name, rc.delete_rule, rc.update_rule \
         FROM information_schema.key_column_usage kcu \
         JOIN information_schema.referential_constraints rc \
           ON kcu.constraint_schema = rc.constraint_schema \
          AND kcu.table_name = rc.table_name \
          AND kcu.constraint_name = rc.constraint_name \
         WHERE kcu.table_schema = DATABASE() \
           AND kcu.referenced_table_name IS NOT NULL \
         ORDER BY kcu.table_name, kcu.constraint_name, kcu.ordinal_position",
    )
    .fetch_all(pool)
    .await?;

    struct MysqlFkEntry {
        col: String,
        ref_table: String,
        ref_col: String,
        on_delete: String,
        on_update: String,
    }
    let mut fk_groups: BTreeMap<(String, String), Vec<MysqlFkEntry>> = BTreeMap::new();
    for row in fk_rows {
        let tname: String = row.get(0);
        let cname: String = row.get(1);
        let entry = MysqlFkEntry {
            col: row.get(2),
            ref_table: row.get(3),
            ref_col: row.get(4),
            on_delete: row.get(5),
            on_update: row.get(6),
        };
        fk_groups.entry((tname, cname)).or_default().push(entry);
    }
    for ((tname, cname), items) in fk_groups {
        if let Some(table) = tables.get_mut(&tname) {
            table.foreign_keys.push(ForeignKeyIr {
                name: Some(cname),
                dialect_names: BTreeMap::new(),
                columns: items.iter().map(|i| i.col.clone()).collect(),
                ref_table: items[0].ref_table.clone(),
                ref_columns: items.iter().map(|i| i.ref_col.clone()).collect(),
                on_delete: ReferentialAction::from_sql_str(&items[0].on_delete),
                on_update: ReferentialAction::from_sql_str(&items[0].on_update),
                defer_on_create: false,
            });
        }
    }

    // Check Constraints (MySQL 8.0.16+)
    if let Ok(ck_rows) = sqlx::query(
        "SELECT tc.table_name, tc.constraint_name, cc.check_clause \
         FROM information_schema.table_constraints tc \
         JOIN information_schema.check_constraints cc \
           ON tc.constraint_schema = cc.constraint_schema \
          AND tc.constraint_name = cc.constraint_name \
         WHERE tc.table_schema = DATABASE() AND tc.constraint_type = 'CHECK' \
         ORDER BY tc.table_name, tc.constraint_name",
    )
    .fetch_all(pool)
    .await
    {
        for row in ck_rows {
            let tname: String = row.get(0);
            let cname: String = row.get(1);
            let clause: String = row.get(2);
            if let Some(table) = tables.get_mut(&tname) {
                table.checks.push(CheckIr {
                    name: Some(cname),
                    dialect_names: BTreeMap::new(),
                    expression: clause,
                    dialect_expressions: BTreeMap::new(),
                });
            }
        }
    }

    // Indexes
    let idx_rows = sqlx::query(
        "SELECT table_name, index_name, CAST(non_unique AS SIGNED) AS non_uniq, \
         column_name, expression \
         FROM information_schema.statistics \
         WHERE table_schema = DATABASE() AND index_name <> 'PRIMARY' \
         ORDER BY table_name, index_name, seq_in_index",
    )
    .fetch_all(pool)
    .await?;

    let mut idx_groups: BTreeMap<(String, String), (bool, Vec<String>)> = BTreeMap::new();
    for row in idx_rows {
        let tname: String = row.get(0);
        let idx_name: String = row.get(1);
        let non_uniq: i64 = row.get(2);
        let col_opt: Option<String> = row.get(3);
        let expr_opt: Option<String> = row.get(4);
        let Some(item) = col_opt.or(expr_opt) else {
            continue;
        };
        idx_groups
            .entry((tname, idx_name))
            .or_insert_with(|| (non_uniq == 0, Vec::new()))
            .1
            .push(item);
    }
    for ((tname, idx_name), (unique, exprs)) in idx_groups {
        if let Some(table) = tables.get_mut(&tname) {
            let backs_unique = table
                .uniques
                .iter()
                .any(|u| u.name.as_deref() == Some(idx_name.as_str()));
            if !backs_unique {
                table.indexes.push(IndexIr {
                    name: idx_name,
                    dialect_names: BTreeMap::new(),
                    unique,
                    expressions: exprs,
                    dialect_clauses: BTreeMap::new(),
                    where_clause: None,
                });
            }
        }
    }

    Ok(tables)
}

async fn introspect_postgres(pool: &sqlx::PgPool) -> Result<BTreeMap<String, TableIr>> {
    let mut tables: BTreeMap<String, TableIr> = BTreeMap::new();

    let col_rows = sqlx::query(
        "SELECT c.table_name::text, c.column_name::text, c.ordinal_position::bigint, \
         c.data_type::text, c.udt_name::text, c.character_maximum_length::bigint, \
         c.numeric_precision::bigint, c.numeric_scale::bigint, \
         c.is_nullable::text, c.column_default::text, \
         c.is_generated::text, c.generation_expression::text, \
         pg_catalog.col_description(cls.oid, a.attnum) AS col_comment \
         FROM information_schema.columns c \
         JOIN pg_catalog.pg_namespace ns ON ns.nspname = c.table_schema \
         JOIN pg_catalog.pg_class cls ON cls.relnamespace = ns.oid AND cls.relname = c.table_name \
         JOIN pg_catalog.pg_attribute a ON a.attrelid = cls.oid AND a.attname = c.column_name \
         WHERE c.table_schema = 'public' AND cls.relkind IN ('r', 'p') \
         ORDER BY c.table_name, c.ordinal_position",
    )
    .fetch_all(pool)
    .await?;

    for row in col_rows {
        let table_name: String = row.get(0);
        if table_name == "alembic_version" {
            continue;
        }
        let col_name: String = row.get(1);
        let pos: i64 = row.get(2);
        let data_type: String = row.get(3);
        let udt_name: String = row.get(4);
        let char_len: Option<i64> = row.get(5);
        let num_prec: Option<i64> = row.get(6);
        let num_scale: Option<i64> = row.get(7);
        let is_nullable: String = row.get(8);
        let col_default: Option<String> = row.get(9);
        let is_gen: String = row.get(10);
        let gen_expr: Option<String> = row.get(11);
        let comment: Option<String> = row.get(12);

        let is_serial = col_default
            .as_deref()
            .is_some_and(|d| d.contains("nextval("));
        let mut canonical_type = map_pg_type(&data_type, &udt_name, char_len, num_prec, num_scale);
        if is_serial {
            canonical_type = match canonical_type {
                CanonicalType::BigInt => CanonicalType::BigSerial,
                CanonicalType::Integer => CanonicalType::Serial,
                other => other,
            };
        }

        let computed = if is_gen.eq_ignore_ascii_case("ALWAYS") {
            gen_expr.map(|expr| ComputedColumnIr {
                expression: expr,
                persisted: true,
                dialect_expressions: BTreeMap::new(),
            })
        } else {
            None
        };

        let server_default = if is_serial || computed.is_some() {
            None
        } else {
            parse_reflected_default(col_default.as_deref(), &canonical_type)
        };

        let table = tables.entry(table_name.clone()).or_insert_with(|| TableIr {
            name: table_name,
            ownership: TableOwnership::Core,
            columns: Vec::new(),
            primary_key: PrimaryKeyIr::default(),
            foreign_keys: Vec::new(),
            uniques: Vec::new(),
            checks: Vec::new(),
            indexes: Vec::new(),
            comment: None,
            confidence: ConfidenceLevel::High,
        });

        table.columns.push(ColumnIr {
            name: col_name,
            ordinal: usize::try_from((pos - 1).max(0)).unwrap_or(0),
            dialect_types: BTreeMap::from([(
                DatabaseKind::Postgresql,
                canonical_type.ddl_type(DatabaseKind::Postgresql),
            )]),
            canonical_type,
            nullable: is_nullable.eq_ignore_ascii_case("YES"),
            autoincrement: is_serial,
            server_default,
            computed,
            comment,
            confidence: ConfidenceLevel::High,
        });
    }

    // Constraints via pg_constraint
    let con_rows = sqlx::query(
        "SELECT cls.relname::text AS table_name, c.conname::text, c.contype::text, \
         pg_catalog.pg_get_constraintdef(c.oid, true)::text AS def, \
         COALESCE(rcls.relname::text, '') AS ref_table, \
         c.confdeltype::text, c.confupdtype::text, \
         ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord) \
               JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum \
               ORDER BY k.ord) AS cols, \
         ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord) \
               JOIN pg_catalog.pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum \
               ORDER BY k.ord) AS ref_cols \
         FROM pg_catalog.pg_constraint c \
         JOIN pg_catalog.pg_class cls ON cls.oid = c.conrelid \
         JOIN pg_catalog.pg_namespace ns ON ns.oid = cls.relnamespace \
         LEFT JOIN pg_catalog.pg_class rcls ON rcls.oid = c.confrelid \
         WHERE ns.nspname = 'public' AND c.contype IN ('p', 'f', 'u', 'c') \
         ORDER BY cls.relname, c.conname",
    )
    .fetch_all(pool)
    .await?;

    for row in con_rows {
        let tname: String = row.get(0);
        let cname: String = row.get(1);
        let contype: String = row.get(2);
        let def: String = row.get(3);
        let ref_table: String = row.get(4);
        let deltype: String = row.try_get::<Option<String>, _>(5)?.unwrap_or_default();
        let updtype: String = row.try_get::<Option<String>, _>(6)?.unwrap_or_default();
        let cols: Vec<String> = row.get(7);
        let ref_cols: Vec<String> = row.get(8);

        let Some(table) = tables.get_mut(&tname) else {
            continue;
        };
        match contype.as_str() {
            "p" => {
                table.primary_key = PrimaryKeyIr {
                    name: Some(cname),
                    dialect_names: BTreeMap::new(),
                    columns: cols,
                };
            }
            "u" => {
                table.uniques.push(UniqueIr {
                    name: Some(cname),
                    dialect_names: BTreeMap::new(),
                    columns: cols,
                });
            }
            "c" => {
                let expr = extract_paren_inner(def.strip_prefix("CHECK").unwrap_or(&def))
                    .unwrap_or(def);
                table.checks.push(CheckIr {
                    name: Some(cname),
                    dialect_names: BTreeMap::new(),
                    expression: expr,
                    dialect_expressions: BTreeMap::new(),
                });
            }
            "f" => {
                table.foreign_keys.push(ForeignKeyIr {
                    name: Some(cname),
                    dialect_names: BTreeMap::new(),
                    columns: cols,
                    ref_table,
                    ref_columns: ref_cols,
                    on_delete: pg_fk_action(&deltype),
                    on_update: pg_fk_action(&updtype),
                    defer_on_create: false,
                });
            }
            _ => {}
        }
    }

    // Standalone indexes (excluding constraint-backing indexes)
    let idx_rows = sqlx::query(
        "SELECT cls.relname::text AS table_name, icls.relname::text AS index_name, \
         i.indisunique, pg_catalog.pg_get_indexdef(i.indexrelid)::text AS indexdef \
         FROM pg_catalog.pg_index i \
         JOIN pg_catalog.pg_class cls ON cls.oid = i.indrelid \
         JOIN pg_catalog.pg_namespace ns ON ns.oid = cls.relnamespace \
         JOIN pg_catalog.pg_class icls ON icls.oid = i.indexrelid \
         WHERE ns.nspname = 'public' \
           AND NOT i.indisprimary \
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conindid = i.indexrelid) \
         ORDER BY cls.relname, icls.relname",
    )
    .fetch_all(pool)
    .await?;

    for row in idx_rows {
        let tname: String = row.get(0);
        let idx_name: String = row.get(1);
        let unique: bool = row.get(2);
        let indexdef: String = row.get(3);
        if let Some(table) = tables.get_mut(&tname) {
            let (exprs, where_clause) = parse_sqlite_index_sql(&indexdef);
            table.indexes.push(IndexIr {
                name: idx_name,
                dialect_names: BTreeMap::new(),
                unique,
                expressions: exprs,
                dialect_clauses: BTreeMap::new(),
                where_clause,
            });
        }
    }

    Ok(tables)
}

fn pg_fk_action(code: &str) -> Option<ReferentialAction> {
    match code {
        "r" => Some(ReferentialAction::Restrict),
        "c" => Some(ReferentialAction::Cascade),
        "n" => Some(ReferentialAction::SetNull),
        "d" => Some(ReferentialAction::SetDefault),
        _ => None,
    }
}

fn map_pg_type(
    data_type: &str,
    udt_name: &str,
    char_len: Option<i64>,
    num_prec: Option<i64>,
    num_scale: Option<i64>,
) -> CanonicalType {
    match udt_name {
        "int2" => CanonicalType::SmallInt,
        "int4" => CanonicalType::Integer,
        "int8" => CanonicalType::BigInt,
        "float4" => CanonicalType::Float,
        "float8" => CanonicalType::Double,
        "bool" => CanonicalType::Boolean,
        "uuid" => CanonicalType::Uuid,
        "json" => CanonicalType::Json,
        "jsonb" => CanonicalType::Jsonb,
        "bytea" => CanonicalType::Blob,
        "text" => CanonicalType::Text,
        "varchar" => CanonicalType::Varchar {
            length: char_len.and_then(|v| u32::try_from(v).ok()),
        },
        "bpchar" => CanonicalType::Char {
            length: char_len.and_then(|v| u32::try_from(v).ok()),
        },
        "numeric" => CanonicalType::Numeric {
            precision: num_prec.and_then(|v| u16::try_from(v).ok()),
            scale: num_scale.and_then(|v| u16::try_from(v).ok()),
        },
        "date" => CanonicalType::Date,
        "timestamp" => CanonicalType::DateTime { timezone: false },
        "timestamptz" => CanonicalType::DateTime { timezone: true },
        "time" => CanonicalType::Time { timezone: false },
        "timetz" => CanonicalType::Time { timezone: true },
        _ => CanonicalType::Custom {
            raw: data_type.to_ascii_uppercase(),
        },
    }
}

pub fn parse_sql_type_name(raw_ty: &str, kind: DatabaseKind) -> CanonicalType {
    let trimmed = raw_ty.trim();
    let upper = trimmed.to_ascii_uppercase();

    let (base, params) = if let Some(pos) = upper.find('(') {
        let base_part = upper[..pos].trim();
        let inner = upper[pos + 1..].trim_end_matches(')').trim();
        (base_part, Some(inner))
    } else {
        (upper.as_str(), None)
    };

    let parse_len = || params.and_then(|p| p.trim().parse::<u32>().ok());
    let parse_two = || {
        params.and_then(|p| {
            let mut it = p.split(',').map(|s| s.trim().parse::<u16>().ok());
            Some((it.next()??, it.next().flatten()))
        })
    };

    match base {
        "VARCHAR" | "CHARACTER VARYING" => CanonicalType::Varchar {
            length: parse_len(),
        },
        "CHAR" | "CHARACTER" => CanonicalType::Char {
            length: parse_len(),
        },
        "TEXT" => CanonicalType::Text,
        "MEDIUMTEXT" => CanonicalType::MediumText,
        "LONGTEXT" => CanonicalType::LongText,
        "TINYINT" if params == Some("1") && kind == DatabaseKind::Mysql => CanonicalType::Boolean,
        "SMALLINT" => CanonicalType::SmallInt,
        "INT" | "INTEGER" | "MEDIUMINT" => CanonicalType::Integer,
        "BIGINT" => CanonicalType::BigInt,
        "FLOAT" | "REAL" => CanonicalType::Float,
        "DOUBLE" | "DOUBLE PRECISION" => CanonicalType::Double,
        "NUMERIC" | "DECIMAL" => {
            if let Some((p, s)) = parse_two() {
                CanonicalType::Numeric {
                    precision: Some(p),
                    scale: s,
                }
            } else {
                CanonicalType::Numeric {
                    precision: parse_len().and_then(|v| u16::try_from(v).ok()),
                    scale: None,
                }
            }
        }
        "BOOL" | "BOOLEAN" => CanonicalType::Boolean,
        "UUID" => CanonicalType::Uuid,
        "JSON" => CanonicalType::Json,
        "JSONB" => CanonicalType::Jsonb,
        "BLOB" | "LONGBLOB" | "MEDIUMBLOB" | "BYTEA" => CanonicalType::Blob,
        "BINARY" => CanonicalType::FixedBinary {
            length: parse_len(),
        },
        "VARBINARY" => CanonicalType::VarBinary {
            length: parse_len(),
        },
        "DATETIME" | "TIMESTAMP" | "TIMESTAMP WITHOUT TIME ZONE" => CanonicalType::DateTime {
            timezone: false,
        },
        "TIMESTAMPTZ" | "TIMESTAMP WITH TIME ZONE" => CanonicalType::DateTime { timezone: true },
        "DATE" => CanonicalType::Date,
        "TIME" | "TIME WITHOUT TIME ZONE" => CanonicalType::Time { timezone: false },
        "TIMETZ" | "TIME WITH TIME ZONE" => CanonicalType::Time { timezone: true },
        "ENUM" => {
            let vals = params
                .map(|p| {
                    p.split(',')
                        .map(|s| s.trim().trim_matches('\'').to_string())
                        .collect()
                })
                .unwrap_or_default();
            CanonicalType::Enum {
                name: None,
                values: vals,
            }
        }
        _ => CanonicalType::Custom {
            raw: trimmed.to_string(),
        },
    }
}

fn parse_reflected_default(
    raw: Option<&str>,
    col_type: &CanonicalType,
) -> Option<ServerDefaultIr> {
    let text = raw?.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("NULL") {
        return None;
    }
    // Strip Postgres `::type` casts like `'pending'::character varying`.
    let stripped_pg = if let Some((val, _cast)) = text.rsplit_once("::") {
        val.trim()
    } else {
        text
    };
    let unwrapped = extract_paren_inner(stripped_pg).unwrap_or_else(|| stripped_pg.to_string());
    let lower = unwrapped.to_ascii_lowercase();

    if matches!(col_type, CanonicalType::Boolean) {
        if matches!(lower.as_str(), "0" | "false" | "'0'") {
            return Some(ServerDefaultIr::Boolean { value: false });
        }
        if matches!(lower.as_str(), "1" | "true" | "'1'") {
            return Some(ServerDefaultIr::Boolean { value: true });
        }
    }
    if lower == "false" {
        return Some(ServerDefaultIr::Boolean { value: false });
    }
    if lower == "true" {
        return Some(ServerDefaultIr::Boolean { value: true });
    }
    if matches!(
        lower.as_str(),
        "current_timestamp" | "current_timestamp()" | "now()"
    ) {
        return Some(ServerDefaultIr::CurrentTimestamp);
    }
    if let Ok(n) = unwrapped.parse::<i64>() {
        return Some(ServerDefaultIr::Integer { value: n });
    }
    if unwrapped.starts_with('\'') && unwrapped.ends_with('\'') && unwrapped.len() >= 2 {
        return Some(ServerDefaultIr::String {
            value: unwrapped[1..unwrapped.len() - 1].replace("''", "'"),
        });
    }
    Some(ServerDefaultIr::Expression {
        raw: unwrapped,
        dialect_expressions: BTreeMap::new(),
    })
}

fn split_top_level_sql_items(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut start = 0usize;
    let mut prev = '\0';
    for (idx, ch) in input.char_indices() {
        match ch {
            '\'' if !in_double && prev != '\'' => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '(' if !in_single && !in_double => depth += 1,
            ')' if !in_single && !in_double => depth = depth.saturating_sub(1),
            ',' if depth == 0 && !in_single && !in_double => {
                out.push(input[start..idx].to_string());
                start = idx + 1;
            }
            _ => {}
        }
        prev = ch;
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        out.push(input[start..].to_string());
    }
    out
}

fn split_ident_and_rest(input: &str) -> Option<(String, String)> {
    let s = input.trim_start();
    if let Some(after_q) = s.strip_prefix('"') {
        let end = after_q.find('"')?;
        return Some((after_q[..end].to_string(), after_q[end + 1..].trim().to_string()));
    }
    if let Some(after_q) = s.strip_prefix('`') {
        let end = after_q.find('`')?;
        return Some((after_q[..end].to_string(), after_q[end + 1..].trim().to_string()));
    }
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some((s[..end].to_string(), s[end..].trim().to_string()))
}

fn extract_paren_inner(s: &str) -> Option<String> {
    let t = s.trim();
    let open = t.find('(')?;
    let mut depth = 0usize;
    let mut in_single = false;
    for (offset, ch) in t[open..].char_indices() {
        match ch {
            '\'' => in_single = !in_single,
            '(' if !in_single => depth += 1,
            ')' if !in_single => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(t[open + 1..open + offset].trim().to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn split_ident_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|part| {
            part.trim()
                .trim_matches('"')
                .trim_matches('`')
                .to_string()
        })
        .filter(|c| !c.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;
    use crate::db::schema::ddl::create_head_schema;

    #[tokio::test]
    async fn sqlite_live_introspection_matches_builtin_head_tables() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("live_test.db");
        let opts = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .foreign_keys(true);
        let sqlite_pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .expect("connect sqlite");
        let pool = DbPool::Sqlite(sqlite_pool);
        create_head_schema(&pool, true)
            .await
            .expect("create head schema");

        let ir = introspect_live_schema_ir(&pool, true, None)
            .await
            .expect("introspect live sqlite");
        assert_eq!(ir.core_table_names().len(), 35);
        assert_eq!(ir.extension_table_names(), BTreeSet::from(["user_oidc_credentials".to_string()]));

        let nodes = &ir.tables["nodes"];
        assert!(nodes.column("active_name").unwrap().computed.is_some());
        assert_eq!(nodes.checks.len(), 1);
        assert_eq!(nodes.uniques.len(), 1);
        assert!(nodes
            .indexes
            .iter()
            .any(|idx| idx.name == "ix_nodes_parent_status_lower_name_id"
                && idx.expressions == vec!["parent_id", "status", "lower(name)", "id"]));
    }
}
