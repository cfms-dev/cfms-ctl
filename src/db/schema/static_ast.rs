//! Dependency-free static Python AST analysis powered by `ruff_python_parser`.
//!
//! Provides two capabilities without executing any Python interpreter:
//! 1. Alembic revision DAG resolution & data DML detection across `alembic/versions/*.py`.
//! 2. Two-pass static SQLAlchemy 2.0 ORM scanning (constants/enums, PEP 810 `lazy import`,
//!    Mixin inheritance, `Mapped[...]` + `ForeignKey` type inference, `.with_variant()`,
//!    `Computed(...)`, and `__table_args__`) with explicit `ConfidenceLevel::Low` blind-spot reporting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use ruff_python_ast::{
    self as ast, Expr, ModModule, Operator, Stmt, UnaryOp,
};
use ruff_python_parser::parse_module;

use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::schema::ir::{
    CanonicalType, CheckIr, ColumnIr, ComputedColumnIr, ConfidenceLevel, ExtractionSource,
    ForeignKeyIr, IndexIr, PrimaryKeyIr, ReferentialAction, SchemaIr, ServerDefaultIr, TableIr,
    TableOwnership, UniqueIr,
};

/// Parsed metadata for a single `alembic/versions/*.py` migration script.
#[derive(Debug, Clone)]
pub struct AlembicScriptMeta {
    pub revision: String,
    pub down_revisions: Vec<String>,
    pub file_path: PathBuf,
    pub has_data_dml: bool,
    pub dml_reasons: Vec<String>,
}

/// Complete parsed Alembic version DAG from `alembic/versions/`.
#[derive(Debug, Clone)]
pub struct AlembicDirectoryAnalysis {
    pub scripts: BTreeMap<String, AlembicScriptMeta>,
    pub heads: Vec<String>,
    pub single_head: Option<String>,
    pub warnings: Vec<String>,
}

/// Pending migration chain evaluation between a live DB revision and codebase head.
#[derive(Debug, Clone)]
pub struct PendingAlembicAnalysis {
    pub heads: Vec<String>,
    pub single_head: Option<String>,
    pub pending_revisions: Vec<String>,
    pub dml_revisions: Vec<(String, Vec<String>)>,
    pub has_data_dml: bool,
    pub target_reachable_from_current: bool,
}

impl AlembicDirectoryAnalysis {
    /// Walk reachable revisions between `current_revision` and `single_head` in application order.
    #[must_use]
    pub fn pending_since(&self, current_revision: Option<&str>) -> PendingAlembicAnalysis {
        let Some(head) = &self.single_head else {
            return PendingAlembicAnalysis {
                heads: self.heads.clone(),
                single_head: None,
                pending_revisions: Vec::new(),
                dml_revisions: Vec::new(),
                has_data_dml: false,
                target_reachable_from_current: false,
            };
        };

        let Some(curr) = current_revision else {
            return PendingAlembicAnalysis {
                heads: self.heads.clone(),
                single_head: Some(head.clone()),
                pending_revisions: Vec::new(),
                dml_revisions: Vec::new(),
                has_data_dml: false,
                target_reachable_from_current: false,
            };
        };

        if curr == head {
            return PendingAlembicAnalysis {
                heads: self.heads.clone(),
                single_head: Some(head.clone()),
                pending_revisions: Vec::new(),
                dml_revisions: Vec::new(),
                has_data_dml: false,
                target_reachable_from_current: true,
            };
        }

        // Traverse backwards from head until curr (supports branching/merging graphs).
        let mut reachable_from_head = Vec::new();
        let mut visited = BTreeSet::new();
        let mut stack = vec![head.clone()];
        let mut found_current = false;

        while let Some(rev) = stack.pop() {
            if rev == curr {
                found_current = true;
                continue;
            }
            if !visited.insert(rev.clone()) {
                continue;
            }
            if let Some(script) = self.scripts.get(&rev) {
                reachable_from_head.push(rev.clone());
                for parent in &script.down_revisions {
                    stack.push(parent.clone());
                }
            }
        }

        if !found_current {
            return PendingAlembicAnalysis {
                heads: self.heads.clone(),
                single_head: Some(head.clone()),
                pending_revisions: Vec::new(),
                dml_revisions: Vec::new(),
                has_data_dml: false,
                target_reachable_from_current: false,
            };
        }

        // Reverse topological order so parents precede children.
        let mut ordered = Vec::with_capacity(reachable_from_head.len());
        let pending_set: BTreeSet<String> = reachable_from_head.into_iter().collect();
        let mut placed = BTreeSet::new();
        while ordered.len() < pending_set.len() {
            let mut progressed = false;
            for rev in &pending_set {
                if placed.contains(rev) {
                    continue;
                }
                let parents_satisfied = self.scripts.get(rev).is_none_or(|s| {
                    s.down_revisions
                        .iter()
                        .all(|p| !pending_set.contains(p) || placed.contains(p))
                });
                if parents_satisfied {
                    ordered.push(rev.clone());
                    placed.insert(rev.clone());
                    progressed = true;
                }
            }
            if !progressed {
                for rev in &pending_set {
                    if placed.insert(rev.clone()) {
                        ordered.push(rev.clone());
                    }
                }
            }
        }

        let mut dml_revisions = Vec::new();
        for rev in &ordered {
            if let Some(meta) = self.scripts.get(rev)
                && meta.has_data_dml
            {
                dml_revisions.push((rev.clone(), meta.dml_reasons.clone()));
            }
        }
        let has_data_dml = !dml_revisions.is_empty();

        PendingAlembicAnalysis {
            heads: self.heads.clone(),
            single_head: Some(head.clone()),
            pending_revisions: ordered,
            dml_revisions,
            has_data_dml,
            target_reachable_from_current: true,
        }
    }
}

/// Validate that `source` parses cleanly as Python (supporting Python 3.15 syntax via Ruff).
pub fn parse_python_syntax_check(source: &str) -> Result<()> {
    parse_module(source)
        .map(|_| ())
        .map_err(|e| CfmsError::Database(format!("Python syntax validation failed: {e}")))
}

/// Parse all scripts inside `<alembic>/versions/` to build the version DAG and detect data DML.
pub fn analyze_alembic_directory(versions_dir: &Path) -> Result<AlembicDirectoryAnalysis> {
    let mut scripts = BTreeMap::new();
    let mut warnings = Vec::new();

    if !versions_dir.is_dir() {
        return Ok(AlembicDirectoryAnalysis {
            scripts,
            heads: Vec::new(),
            single_head: None,
            warnings: vec![format!(
                "Alembic versions directory not found: {}",
                versions_dir.display()
            )],
        });
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(versions_dir)?
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .filter(|p| {
            p.is_file()
                && p.extension().is_some_and(|ext| ext == "py")
                && p.file_name().and_then(|n| n.to_str()) != Some("__init__.py")
        })
        .collect();
    entries.sort();

    for path in entries {
        let src = std::fs::read_to_string(&path)?;
        let parsed = match parse_module(&src) {
            Ok(p) => p,
            Err(err) => {
                warnings.push(format!(
                    "Failed to parse Alembic script {}: {err}",
                    path.display()
                ));
                continue;
            }
        };
        if let Some(meta) = parse_alembic_script(&path, parsed.syntax()) {
            scripts.insert(meta.revision.clone(), meta);
        }
    }

    let mut referenced_as_parent = BTreeSet::new();
    for meta in scripts.values() {
        for parent in &meta.down_revisions {
            referenced_as_parent.insert(parent.clone());
        }
    }

    let heads: Vec<String> = scripts
        .keys()
        .filter(|rev| !referenced_as_parent.contains(*rev))
        .cloned()
        .collect();
    let single_head = if heads.len() == 1 {
        Some(heads[0].clone())
    } else {
        None
    };

    if heads.len() > 1 {
        warnings.push(format!(
            "Multiple Alembic heads detected: {}",
            heads.join(", ")
        ));
    }

    Ok(AlembicDirectoryAnalysis {
        scripts,
        heads,
        single_head,
        warnings,
    })
}

fn parse_alembic_script(path: &Path, module: &ModModule) -> Option<AlembicScriptMeta> {
    let mut revision: Option<String> = None;
    let mut down_revisions: Vec<String> = Vec::new();
    let mut dml_reasons: Vec<String> = Vec::new();

    for stmt in &module.body {
        match stmt {
            Stmt::Assign(assign) if assign.targets.len() == 1 => {
                if let Some(name) = expr_ident(&assign.targets[0]) {
                    match name {
                        "revision" => revision = eval_string_expr(&assign.value),
                        "down_revision" => down_revisions = eval_string_list_expr(&assign.value),
                        _ => {}
                    }
                }
            }
            Stmt::AnnAssign(ann) => {
                if let Some(name) = expr_ident(&ann.target)
                    && let Some(val) = &ann.value
                {
                    match name {
                        "revision" => revision = eval_string_expr(val),
                        "down_revision" => down_revisions = eval_string_list_expr(val),
                        _ => {}
                    }
                }
            }
            Stmt::FunctionDef(func) if func.name.as_str() == "upgrade" => {
                scan_stmts_for_dml(&func.body, &mut dml_reasons);
            }
            _ => {}
        }
    }

    revision.map(|rev| {
        dml_reasons.sort();
        dml_reasons.dedup();
        AlembicScriptMeta {
            revision: rev,
            down_revisions,
            file_path: path.to_path_buf(),
            has_data_dml: !dml_reasons.is_empty(),
            dml_reasons,
        }
    })
}

fn scan_stmts_for_dml(stmts: &[Stmt], reasons: &mut Vec<String>) {
    for stmt in stmts {
        match stmt {
            Stmt::Expr(e) => scan_expr_for_dml(&e.value, reasons),
            Stmt::Assign(a) => scan_expr_for_dml(&a.value, reasons),
            Stmt::AnnAssign(a) => {
                if let Some(v) = &a.value {
                    scan_expr_for_dml(v, reasons);
                }
            }
            Stmt::AugAssign(a) => scan_expr_for_dml(&a.value, reasons),
            Stmt::Return(r) => {
                if let Some(v) = &r.value {
                    scan_expr_for_dml(v, reasons);
                }
            }
            Stmt::If(s) => {
                scan_expr_for_dml(&s.test, reasons);
                scan_stmts_for_dml(&s.body, reasons);
                for clause in &s.elif_else_clauses {
                    if let Some(test) = &clause.test {
                        scan_expr_for_dml(test, reasons);
                    }
                    scan_stmts_for_dml(&clause.body, reasons);
                }
            }
            Stmt::For(s) => {
                scan_expr_for_dml(&s.iter, reasons);
                scan_stmts_for_dml(&s.body, reasons);
                scan_stmts_for_dml(&s.orelse, reasons);
            }
            Stmt::While(s) => {
                scan_expr_for_dml(&s.test, reasons);
                scan_stmts_for_dml(&s.body, reasons);
                scan_stmts_for_dml(&s.orelse, reasons);
            }
            Stmt::With(s) => {
                for item in &s.items {
                    scan_expr_for_dml(&item.context_expr, reasons);
                }
                scan_stmts_for_dml(&s.body, reasons);
            }
            Stmt::Try(s) => {
                scan_stmts_for_dml(&s.body, reasons);
                for h in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    scan_stmts_for_dml(&eh.body, reasons);
                }
                scan_stmts_for_dml(&s.orelse, reasons);
                scan_stmts_for_dml(&s.finalbody, reasons);
            }
            Stmt::FunctionDef(f) => scan_stmts_for_dml(&f.body, reasons),
            _ => {}
        }
    }
}

fn scan_expr_for_dml(expr: &Expr, reasons: &mut Vec<String>) {
    match expr {
        Expr::Call(call) => {
            if let Some(dotted) = expr_dotted_name(&call.func) {
                match dotted.as_str() {
                    "op.execute" | "batch_op.execute" => {
                        reasons.push(format!("{dotted}(...)"));
                    }
                    "op.bulk_insert" => reasons.push("op.bulk_insert(...)".to_string()),
                    "op.get_bind" => reasons.push("op.get_bind()".to_string()),
                    "sa.insert" | "insert" | "sa.update" | "update" | "sa.delete" | "delete" => {
                        reasons.push(format!("{dotted}(...)"));
                    }
                    "Session" | "sa.orm.Session" | "orm.Session" => {
                        reasons.push("SQLAlchemy Session data operations".to_string());
                    }
                    s if s.ends_with(".execute")
                        || s.ends_with(".bulk_insert")
                        || s.ends_with(".commit")
                        || s.ends_with(".add_all") =>
                    {
                        reasons.push(format!("{s}(...)"));
                    }
                    _ => {}
                }
            }
            scan_expr_for_dml(&call.func, reasons);
            for arg in &call.arguments.args {
                scan_expr_for_dml(arg, reasons);
            }
            for kw in &call.arguments.keywords {
                scan_expr_for_dml(&kw.value, reasons);
            }
        }
        Expr::Attribute(a) => scan_expr_for_dml(&a.value, reasons),
        Expr::List(l) => l.elts.iter().for_each(|e| scan_expr_for_dml(e, reasons)),
        Expr::Tuple(t) => t.elts.iter().for_each(|e| scan_expr_for_dml(e, reasons)),
        Expr::Dict(d) => d.items.iter().for_each(|item| {
            if let Some(k) = &item.key {
                scan_expr_for_dml(k, reasons);
            }
            scan_expr_for_dml(&item.value, reasons);
        }),
        Expr::BinOp(b) => {
            scan_expr_for_dml(&b.left, reasons);
            scan_expr_for_dml(&b.right, reasons);
        }
        _ => {}
    }
}

/// Static scalar value resolved during Pass 1 constant & enum extraction.
#[derive(Debug, Clone)]
enum StaticScalar {
    Int(i64),
    Str(String),
    Bool(bool),
}

/// Extracted raw column pending Pass 2b ForeignKey type propagation.
#[derive(Debug, Clone)]
struct RawColumn {
    name: String,
    ordinal: usize,
    canonical_type: Option<CanonicalType>,
    annotated_type: Option<CanonicalType>,
    fk_ref: Option<(String, String)>,
    nullable: Option<bool>,
    is_pk: bool,
    autoincrement: Option<bool>,
    server_default: Option<ServerDefaultIr>,
    computed: Option<ComputedColumnIr>,
    comment: Option<String>,
    confidence: ConfidenceLevel,
}

/// Collected SQLAlchemy model/mixin class AST record.
struct ClassRecord {
    name: String,
    bases: Vec<String>,
    tablename: Option<String>,
    is_abstract: bool,
    ownership: TableOwnership,
    file_path: PathBuf,
    body: Vec<Stmt>,
}

/// Extract a [`SchemaIr`] purely from Python source files via two-pass `ruff_python_parser` AST scanning.
pub fn extract_static_schema_ir(
    paths: &WorkspacePaths,
    include_extensions: bool,
) -> Result<SchemaIr> {
    let mut warnings = Vec::new();
    let schema_revision = paths
        .discover_alembic_paths()
        .and_then(|ap| analyze_alembic_directory(&ap.versions_dir).ok())
        .and_then(|analysis| {
            warnings.extend(analysis.warnings);
            analysis.single_head
        });

    let mut ir = SchemaIr::new(ExtractionSource::StaticAst, schema_revision);
    let mut files = collect_model_source_files(paths, include_extensions);
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut env: HashMap<String, StaticScalar> = HashMap::new();
    let mut classes: HashMap<String, ClassRecord> = HashMap::new();
    let mut class_order: Vec<String> = Vec::new();

    // Pass 1: constants, Enums, Mixins, and model ClassDefs.
    for (file_path, ownership) in &files {
        let src = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(err) => {
                warnings.push(format!("Cannot read {}: {err}", file_path.display()));
                continue;
            }
        };
        let parsed = match parse_module(&src) {
            Ok(m) => m,
            Err(err) => {
                warnings.push(format!(
                    "Syntax error in {} (skipped): {err}",
                    file_path.display()
                ));
                continue;
            }
        };
        collect_pass1(
            parsed.syntax(),
            file_path,
            ownership,
            &mut env,
            &mut classes,
            &mut class_order,
        );
    }

    // Pass 2: resolve table classes with Mixin linearization.
    let mut pending_tables: BTreeMap<String, (Vec<RawColumn>, TableIr)> = BTreeMap::new();
    for class_name in &class_order {
        let Some(rec) = classes.get(class_name) else {
            continue;
        };
        let Some(tablename) = &rec.tablename else {
            continue;
        };
        if rec.is_abstract {
            continue;
        }
        let mut class_chain = Vec::new();
        let mut seen = BTreeSet::new();
        resolve_mro(class_name, &classes, &mut seen, &mut class_chain);

        let (raw_cols, table_ir) = build_table_from_chain(
            tablename,
            &rec.ownership,
            &class_chain,
            &classes,
            &env,
            &mut warnings,
        );
        pending_tables.insert(tablename.clone(), (raw_cols, table_ir));
    }

    // Pass 2b: finalize column types using FK targets / annotation fallback / PK autoincrement.
    let resolved_col_types = resolve_fk_target_types(&pending_tables);
    for (table_name, (raw_cols, mut table_ir)) in pending_tables {
        let pk_count = table_ir.primary_key.columns.len();
        for rc in raw_cols {
            let mut ty = rc
                .canonical_type
                .clone()
                .or_else(|| {
                    rc.fk_ref
                        .as_ref()
                        .and_then(|(rt, rcol)| resolved_col_types.get(&(rt.clone(), rcol.clone())).cloned())
                })
                .or(rc.annotated_type.clone())
                .unwrap_or_else(|| {
                    warnings.push(format!(
                        "Static AST could not infer column type for {table_name}.{}; defaulting to TEXT",
                        rc.name
                    ));
                    CanonicalType::Text
                });

            let is_single_pk = pk_count == 1 && rc.is_pk;
            let autoinc = is_single_pk
                && rc.autoincrement.unwrap_or_else(|| rc.fk_ref.is_none())
                && ty.is_integer_like();

            if autoinc {
                ty = match ty {
                    CanonicalType::Integer => CanonicalType::Serial,
                    CanonicalType::BigInt | CanonicalType::SqliteIntElseBigInt => {
                        CanonicalType::BigSerial
                    }
                    other => other,
                };
            }

            let nullable = rc
                .nullable
                .unwrap_or_else(|| !rc.is_pk && rc.computed.is_some());

            table_ir.columns.push(ColumnIr {
                name: rc.name,
                ordinal: rc.ordinal,
                canonical_type: ty,
                dialect_types: BTreeMap::new(),
                nullable,
                autoincrement: autoinc,
                server_default: rc.server_default,
                computed: rc.computed,
                comment: rc.comment,
                confidence: rc.confidence,
            });
        }
        table_ir.sort_columns_by_ordinal();
        ir.tables.insert(table_name, table_ir);
    }

    ir.warnings = warnings;
    Ok(ir)
}

fn collect_model_source_files(
    paths: &WorkspacePaths,
    include_extensions: bool,
) -> Vec<(PathBuf, TableOwnership)> {
    let mut files = Vec::new();
    let constants = paths
        .server_root
        .join("include")
        .join("config")
        .join("constants.py");
    if constants.is_file() {
        files.push((constants, TableOwnership::Core));
    }

    let db_dir = paths.server_root.join("include").join("database");
    if db_dir.is_dir() {
        collect_py_files_recursive(&db_dir, &TableOwnership::Core, &mut files);
    }

    if include_extensions && paths.extensions_root.is_dir()
        && let Ok(entries) = std::fs::read_dir(&paths.extensions_root)
    {
        for entry in entries.flatten() {
            let ext_dir = entry.path();
            if !ext_dir.is_dir() {
                continue;
            }
            let Some(ext_name) = ext_dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if ext_name.starts_with("__") || ext_name.starts_with('.') {
                continue;
            }
            let owner = TableOwnership::Extension(ext_name.to_string());
            collect_py_files_recursive(&ext_dir, &owner, &mut files);
        }
    }
    files
}

fn collect_py_files_recursive(
    dir: &Path,
    ownership: &TableOwnership,
    out: &mut Vec<(PathBuf, TableOwnership)>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "__pycache__" | "migrations" | "alembic" | "tests") {
                continue;
            }
            collect_py_files_recursive(&p, ownership, out);
        } else if p.extension().is_some_and(|e| e == "py") {
            out.push((p, ownership.clone()));
        }
    }
}

fn collect_pass1(
    module: &ModModule,
    file_path: &Path,
    ownership: &TableOwnership,
    env: &mut HashMap<String, StaticScalar>,
    classes: &mut HashMap<String, ClassRecord>,
    class_order: &mut Vec<String>,
) {
    for stmt in &module.body {
        match stmt {
            Stmt::Assign(a) if a.targets.len() == 1 => {
                if let Some(name) = expr_ident(&a.targets[0])
                    && let Some(val) = eval_scalar(&a.value, env)
                {
                    env.insert(name.to_string(), val);
                }
            }
            Stmt::AnnAssign(a) => {
                if let Some(name) = expr_ident(&a.target)
                    && let Some(val_expr) = &a.value
                    && let Some(val) = eval_scalar(val_expr, env)
                {
                    env.insert(name.to_string(), val);
                }
            }
            Stmt::ClassDef(cls) => {
                let bases = cls
                    .arguments
                    .as_ref()
                    .map(|args| {
                        args.args
                            .iter()
                            .filter_map(|e| expr_ident(e).or_else(|| expr_dotted_last(e)))
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let is_enum = bases
                    .iter()
                    .any(|b| matches!(b.as_str(), "Enum" | "IntEnum" | "StrEnum"));
                if is_enum {
                    collect_enum_members(&cls.name, &cls.body, env);
                    continue;
                }

                let mut tablename = None;
                let mut is_abstract = false;
                for body_stmt in &cls.body {
                    match body_stmt {
                        Stmt::Assign(a) if a.targets.len() == 1 => {
                            match expr_ident(&a.targets[0]) {
                                Some("__tablename__") => tablename = eval_string_expr(&a.value),
                                Some("__abstract__") => {
                                    if matches!(a.value.as_ref(), Expr::BooleanLiteral(b) if b.value) {
                                        is_abstract = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                        Stmt::AnnAssign(a) => {
                            if let Some(name) = expr_ident(&a.target)
                                && let Some(v) = &a.value
                            {
                                match name {
                                    "__tablename__" => tablename = eval_string_expr(v),
                                    "__abstract__" => {
                                        if matches!(v.as_ref(), Expr::BooleanLiteral(b) if b.value) {
                                            is_abstract = true;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }

                let cls_name = cls.name.to_string();
                if !classes.contains_key(&cls_name) {
                    class_order.push(cls_name.clone());
                }
                classes.insert(
                    cls_name.clone(),
                    ClassRecord {
                        name: cls_name,
                        bases,
                        tablename,
                        is_abstract,
                        ownership: ownership.clone(),
                        file_path: file_path.to_path_buf(),
                        body: cls.body.to_vec(),
                    },
                );
            }
            _ => {}
        }
    }
}

fn collect_enum_members(
    enum_name: &ast::Identifier,
    body: &[Stmt],
    env: &mut HashMap<String, StaticScalar>,
) {
    for stmt in body {
        let (target, value) = match stmt {
            Stmt::Assign(a) if a.targets.len() == 1 => (&a.targets[0], Some(a.value.as_ref())),
            Stmt::AnnAssign(a) => (a.target.as_ref(), a.value.as_deref()),
            _ => continue,
        };
        let Some(member) = expr_ident(target) else {
            continue;
        };
        let Some(val_expr) = value else {
            continue;
        };
        if let Some(val) = eval_scalar(val_expr, env) {
            env.insert(format!("{enum_name}.{member}"), val.clone());
            env.insert(format!("{enum_name}.{member}.value"), val);
        }
    }
}

fn resolve_mro<'a>(
    class_name: &'a str,
    classes: &'a HashMap<String, ClassRecord>,
    seen: &mut BTreeSet<&'a str>,
    out: &mut Vec<&'a ClassRecord>,
) {
    if !seen.insert(class_name) {
        return;
    }
    let Some(rec) = classes.get(class_name) else {
        return;
    };
    for base in &rec.bases {
        resolve_mro(base, classes, seen, out);
    }
    out.push(rec);
}

fn build_table_from_chain(
    table_name: &str,
    ownership: &TableOwnership,
    chain: &[&ClassRecord],
    _classes: &HashMap<String, ClassRecord>,
    env: &HashMap<String, StaticScalar>,
    warnings: &mut Vec<String>,
) -> (Vec<RawColumn>, TableIr) {
    let mut raw_cols: Vec<RawColumn> = Vec::new();
    let mut pk_cols: Vec<String> = Vec::new();
    let mut foreign_keys: Vec<ForeignKeyIr> = Vec::new();
    let mut uniques: Vec<UniqueIr> = Vec::new();
    let mut checks: Vec<CheckIr> = Vec::new();
    let mut indexes: Vec<IndexIr> = Vec::new();
    let mut table_comment: Option<String> = None;
    let mut table_confidence = ConfidenceLevel::High;

    // Preserve Mixin inheritance field ordering (leaf class or base mixins in declaration order).
    let mut col_positions: HashMap<String, usize> = HashMap::new();

    for rec in chain {
        for stmt in &rec.body {
            match stmt {
                Stmt::FunctionDef(func) => {
                    let has_declared_attr = func.decorator_list.iter().any(|dec| {
                        expr_dotted_name(&dec.expression)
                            .is_some_and(|n| n.contains("declared_attr"))
                    });
                    if has_declared_attr {
                        table_confidence = ConfidenceLevel::Low;
                        warnings.push(format!(
                            "Static AST: @declared_attr on {}.{} ({}) cannot be evaluated statically",
                            rec.name,
                            func.name,
                            rec.file_path.display()
                        ));
                    }
                }
                Stmt::Expr(e) => {
                    if let Expr::Call(call) = e.value.as_ref()
                        && expr_dotted_name(&call.func).is_some_and(|n| n == "setattr")
                    {
                        table_confidence = ConfidenceLevel::Low;
                        warnings.push(format!(
                            "Static AST: dynamic setattr() in {} ({})",
                            rec.name,
                            rec.file_path.display()
                        ));
                    }
                }
                Stmt::Assign(a) if a.targets.len() == 1 => {
                    let Some(attr_name) = expr_ident(&a.targets[0]) else {
                        continue;
                    };
                    if attr_name == "__table_args__" {
                        parse_table_args(
                            table_name,
                            &a.value,
                            env,
                            &mut uniques,
                            &mut checks,
                            &mut indexes,
                            &mut foreign_keys,
                            &mut table_comment,
                        );
                        continue;
                    }
                    if attr_name.starts_with("__") {
                        continue;
                    }
                    if let Some(call) = unwrap_column_call(&a.value) {
                        let ordinal = raw_cols.len();
                        let col = parse_column_call(
                            attr_name,
                            ordinal,
                            None,
                            Some(call),
                            table_name,
                            env,
                            &mut pk_cols,
                            &mut foreign_keys,
                            &mut uniques,
                            &mut indexes,
                            warnings,
                        );
                        insert_or_override_col(&mut raw_cols, &mut col_positions, col);
                    }
                }
                Stmt::AnnAssign(a) => {
                    let Some(attr_name) = expr_ident(&a.target) else {
                        continue;
                    };
                    if attr_name == "__table_args__" {
                        if let Some(v) = &a.value {
                            parse_table_args(
                                table_name,
                                v,
                                env,
                                &mut uniques,
                                &mut checks,
                                &mut indexes,
                                &mut foreign_keys,
                                &mut table_comment,
                            );
                        }
                        continue;
                    }
                    if attr_name.starts_with("__") {
                        continue;
                    }
                    if is_classvar_or_relationship(&a.annotation, a.value.as_deref()) {
                        continue;
                    }
                    let (ann_type, ann_nullable) = parse_mapped_annotation(&a.annotation);
                    let call_opt = a.value.as_deref().and_then(unwrap_column_call);
                    if call_opt.is_none() && !is_mapped_annotation(&a.annotation) {
                        continue;
                    }
                    let ordinal = raw_cols.len();
                    let mut col = parse_column_call(
                        attr_name,
                        ordinal,
                        ann_type,
                        call_opt,
                        table_name,
                        env,
                        &mut pk_cols,
                        &mut foreign_keys,
                        &mut uniques,
                        &mut indexes,
                        warnings,
                    );
                    if col.nullable.is_none() {
                        col.nullable = Some(ann_nullable);
                    }
                    insert_or_override_col(&mut raw_cols, &mut col_positions, col);
                }
                _ => {}
            }
        }
    }

    // Re-number ordinals compactly in appearance order.
    for (idx, col) in raw_cols.iter_mut().enumerate() {
        col.ordinal = idx;
    }

    let table_ir = TableIr {
        name: table_name.to_string(),
        ownership: ownership.clone(),
        columns: Vec::new(),
        primary_key: PrimaryKeyIr {
            name: Some(format!("pk_{table_name}")),
            dialect_names: BTreeMap::new(),
            columns: pk_cols,
        },
        foreign_keys,
        uniques,
        checks,
        indexes,
        comment: table_comment,
        confidence: table_confidence,
    };
    (raw_cols, table_ir)
}

fn insert_or_override_col(
    raw_cols: &mut Vec<RawColumn>,
    positions: &mut HashMap<String, usize>,
    mut col: RawColumn,
) {
    if let Some(&pos) = positions.get(&col.name) {
        col.ordinal = pos;
        raw_cols[pos] = col;
    } else {
        let pos = raw_cols.len();
        col.ordinal = pos;
        positions.insert(col.name.clone(), pos);
        raw_cols.push(col);
    }
}

fn is_classvar_or_relationship(annotation: &Expr, value: Option<&Expr>) -> bool {
    if let Expr::Subscript(sub) = annotation
        && expr_dotted_last(&sub.value).is_some_and(|id| id == "ClassVar")
    {
        return true;
    }
    if let Some(Expr::Call(call)) = value
        && expr_dotted_last(&call.func).is_some_and(|n| matches!(n, "relationship" | "deferred" | "column_property"))
    {
        return matches!(expr_dotted_last(&call.func), Some("relationship"));
    }
    false
}

fn is_mapped_annotation(expr: &Expr) -> bool {
    matches!(expr, Expr::Subscript(sub) if expr_dotted_last(&sub.value) == Some("Mapped"))
}

fn parse_mapped_annotation(expr: &Expr) -> (Option<CanonicalType>, bool) {
    let inner = match expr {
        Expr::Subscript(sub) if expr_dotted_last(&sub.value) == Some("Mapped") => sub.slice.as_ref(),
        other => other,
    };
    unwrap_optional_annotation(inner)
}

fn unwrap_optional_annotation(expr: &Expr) -> (Option<CanonicalType>, bool) {
    match expr {
        Expr::BinOp(bin) if matches!(bin.op, Operator::BitOr) => {
            if matches!(bin.right.as_ref(), Expr::NoneLiteral(_)) {
                return (python_type_to_canonical(&bin.left), true);
            }
            if matches!(bin.left.as_ref(), Expr::NoneLiteral(_)) {
                return (python_type_to_canonical(&bin.right), true);
            }
            (None, false)
        }
        Expr::Subscript(sub) if expr_dotted_last(&sub.value) == Some("Optional") => {
            (python_type_to_canonical(&sub.slice), true)
        }
        other => (python_type_to_canonical(other), false),
    }
}

fn python_type_to_canonical(expr: &Expr) -> Option<CanonicalType> {
    let name = expr_dotted_name(expr)?;
    match name.as_str() {
        "str" => Some(CanonicalType::Text),
        "int" => Some(CanonicalType::Integer),
        "float" => Some(CanonicalType::Double),
        "bool" => Some(CanonicalType::Boolean),
        "bytes" => Some(CanonicalType::Blob),
        "dict" => Some(CanonicalType::Json),
        "uuid.UUID" | "UUID" => Some(CanonicalType::Uuid),
        "datetime.datetime" | "datetime" => Some(CanonicalType::DateTime { timezone: false }),
        "datetime.date" | "date" => Some(CanonicalType::Date),
        "datetime.time" | "time" => Some(CanonicalType::Time { timezone: false }),
        "Decimal" | "decimal.Decimal" => Some(CanonicalType::Numeric {
            precision: None,
            scale: None,
        }),
        _ => None,
    }
}

fn unwrap_column_call(expr: &Expr) -> Option<&ast::ExprCall> {
    let Expr::Call(call) = expr else {
        return None;
    };
    match expr_dotted_last(&call.func) {
        Some("mapped_column" | "Column") => Some(call),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_column_call(
    attr_name: &str,
    ordinal: usize,
    annotated_type: Option<CanonicalType>,
    call_opt: Option<&ast::ExprCall>,
    table_name: &str,
    env: &HashMap<String, StaticScalar>,
    pk_cols: &mut Vec<String>,
    foreign_keys: &mut Vec<ForeignKeyIr>,
    uniques: &mut Vec<UniqueIr>,
    indexes: &mut Vec<IndexIr>,
    warnings: &mut Vec<String>,
) -> RawColumn {
    let mut col_name = attr_name.to_string();
    let mut explicit_type: Option<CanonicalType> = None;
    let mut fk_ref: Option<(String, String)> = None;
    let mut nullable: Option<bool> = None;
    let mut is_pk = false;
    let mut autoincrement: Option<bool> = None;
    let mut server_default: Option<ServerDefaultIr> = None;
    let mut computed: Option<ComputedColumnIr> = None;
    let mut comment: Option<String> = None;
    let mut col_confidence = ConfidenceLevel::High;
    let mut index_flag = false;
    let mut unique_flag = false;

    if let Some(call) = call_opt {
        for (idx, arg) in call.arguments.args.iter().enumerate() {
            if idx == 0
                && let Some(explicit_sql_name) = eval_string_expr(arg)
            {
                col_name = explicit_sql_name;
                continue;
            }
            if let Some(fk) = parse_foreign_key_expr(arg, &col_name, table_name) {
                fk_ref = Some((fk.ref_table.clone(), fk.ref_columns[0].clone()));
                foreign_keys.push(fk);
                continue;
            }
            if let Some(ct) = parse_sqlalchemy_type_expr(arg, env) {
                explicit_type = Some(ct);
            } else if is_computed_call(arg) {
                computed = parse_computed_call(arg, env);
            }
        }

        for kw in &call.arguments.keywords {
            let Some(kname) = kw.arg.as_ref().map(|id| id.as_str()) else {
                col_confidence = ConfidenceLevel::Low;
                warnings.push(format!(
                    "Static AST: **kwargs expansion in column {table_name}.{col_name} cannot be evaluated statically"
                ));
                continue;
            };
            match kname {
                "name" => {
                    if let Some(n) = eval_string_expr(&kw.value) {
                        col_name = n;
                    }
                }
                "primary_key" => {
                    is_pk = eval_bool_expr(&kw.value).unwrap_or(false);
                }
                "nullable" => nullable = eval_bool_expr(&kw.value),
                "autoincrement" => autoincrement = eval_bool_expr(&kw.value),
                "unique" => unique_flag = eval_bool_expr(&kw.value).unwrap_or(false),
                "index" => index_flag = eval_bool_expr(&kw.value).unwrap_or(false),
                "comment" => comment = eval_string_expr(&kw.value),
                "server_default" => {
                    server_default = parse_server_default_expr(&kw.value);
                }
                _ => {}
            }
        }
    }

    // Repair FK constraint column names if keyword `name=...` changed it.
    if col_name != attr_name {
        for fk in foreign_keys.iter_mut() {
            if fk.columns == [attr_name] {
                fk.columns = vec![col_name.clone()];
            }
        }
    }
    if is_pk {
        pk_cols.push(col_name.clone());
        nullable = Some(false);
    }
    if unique_flag {
        uniques.push(UniqueIr {
            name: Some(format!("uq_{table_name}_{col_name}")),
            dialect_names: BTreeMap::new(),
            columns: vec![col_name.clone()],
        });
    }
    if index_flag {
        indexes.push(IndexIr {
            name: format!("ix_{table_name}_{col_name}"),
            dialect_names: BTreeMap::new(),
            unique: false,
            expressions: vec![col_name.clone()],
            dialect_clauses: BTreeMap::new(),
            where_clause: None,
        });
    }

    RawColumn {
        name: col_name,
        ordinal,
        canonical_type: explicit_type,
        annotated_type,
        fk_ref,
        nullable,
        is_pk,
        autoincrement,
        server_default,
        computed,
        comment,
        confidence: col_confidence,
    }
}

fn parse_foreign_key_expr(expr: &Expr, col_name: &str, table_name: &str) -> Option<ForeignKeyIr> {
    let Expr::Call(call) = expr else {
        return None;
    };
    if expr_dotted_last(&call.func) != Some("ForeignKey") {
        return None;
    }
    let target = call.arguments.args.first().and_then(eval_string_expr)?;
    let (ref_table, ref_col) = target.split_once('.')?;

    let mut fk_name = None;
    let mut on_delete = None;
    let mut on_update = None;
    for kw in &call.arguments.keywords {
        match kw.arg.as_ref().map(|id| id.as_str()) {
            Some("name") => fk_name = eval_string_expr(&kw.value),
            Some("ondelete") => {
                on_delete = eval_string_expr(&kw.value).and_then(|s| ReferentialAction::from_sql_str(&s));
            }
            Some("onupdate") => {
                on_update = eval_string_expr(&kw.value).and_then(|s| ReferentialAction::from_sql_str(&s));
            }
            _ => {}
        }
    }

    Some(ForeignKeyIr {
        name: fk_name.or_else(|| Some(format!("fk_{table_name}_{col_name}_{ref_table}"))),
        dialect_names: BTreeMap::new(),
        columns: vec![col_name.to_string()],
        ref_table: ref_table.to_string(),
        ref_columns: vec![ref_col.to_string()],
        on_delete,
        on_update,
        defer_on_create: false,
    })
}

fn parse_sqlalchemy_type_expr(
    expr: &Expr,
    env: &HashMap<String, StaticScalar>,
) -> Option<CanonicalType> {
    // Handle `.with_variant(variant_type, dialect_name)` chain recursively.
    if let Expr::Call(call) = expr
        && let Expr::Attribute(attr) = call.func.as_ref()
        && attr.attr.as_str() == "with_variant"
    {
        let base = parse_sqlalchemy_type_expr(&attr.value, env)?;
        let variant_ty = call.arguments.args.first().and_then(|v| {
            parse_sqlalchemy_type_expr(v, env).or_else(|| class_ref_type_name(v))
        });
        let dialect = call.arguments.args.get(1).and_then(eval_string_expr);
        return match (base, variant_ty, dialect.as_deref()) {
            (CanonicalType::BigInt, Some(CanonicalType::Integer), Some("sqlite")) => {
                Some(CanonicalType::SqliteIntElseBigInt)
            }
            (CanonicalType::Text, Some(CanonicalType::LongText), Some("mysql")) => {
                Some(CanonicalType::LongText)
            }
            (CanonicalType::Text, Some(CanonicalType::MediumText), Some("mysql")) => {
                Some(CanonicalType::MediumText)
            }
            (
                CanonicalType::VarBinary { length },
                Some(CanonicalType::FixedBinary { length: flen }),
                Some("mysql"),
            ) => Some(CanonicalType::FixedBinary {
                length: flen.or(length),
            }),
            (
                CanonicalType::Blob,
                Some(CanonicalType::FixedBinary { length: flen }),
                Some("mysql"),
            ) => Some(CanonicalType::FixedBinary { length: flen }),
            (CanonicalType::Json, Some(CanonicalType::Jsonb), Some("postgresql")) => {
                Some(CanonicalType::Jsonb)
            }
            (b, _, _) => Some(b),
        };
    }

    if let Some(class_ty) = class_ref_type_name(expr) {
        return Some(class_ty);
    }

    let Expr::Call(call) = expr else {
        return None;
    };
    let name = expr_dotted_last(&call.func)?;
    let arg0_int = call
        .arguments
        .args
        .first()
        .and_then(|e| eval_int_expr(e, env));
    let kw_len = kwarg_expr(&call.arguments, "length").and_then(|e| eval_int_expr(e, env));
    let length = kw_len.or(arg0_int).and_then(|v| u32::try_from(v).ok());

    match name {
        "String" | "VARCHAR" => Some(CanonicalType::Varchar { length }),
        "CHAR" => Some(CanonicalType::Char { length }),
        "Text" | "TEXT" => Some(CanonicalType::Text),
        "MEDIUMTEXT" => Some(CanonicalType::MediumText),
        "LONGTEXT" => Some(CanonicalType::LongText),
        "SmallInteger" | "SMALLINT" => Some(CanonicalType::SmallInt),
        "Integer" | "INTEGER" | "INT" => Some(CanonicalType::Integer),
        "BigInteger" | "BIGINT" => Some(CanonicalType::BigInt),
        "Float" | "FLOAT" => {
            let prec = arg0_int
                .or_else(|| kwarg_expr(&call.arguments, "precision").and_then(|e| eval_int_expr(e, env)));
            if prec.is_some_and(|p| p > 24) {
                Some(CanonicalType::Double)
            } else {
                Some(CanonicalType::Float)
            }
        }
        "Double" | "DOUBLE" | "DOUBLE_PRECISION" => Some(CanonicalType::Double),
        "Numeric" | "NUMERIC" | "DECIMAL" => {
            let p = kwarg_expr(&call.arguments, "precision")
                .or_else(|| call.arguments.args.first())
                .and_then(|e| eval_int_expr(e, env))
                .and_then(|v| u16::try_from(v).ok());
            let s = kwarg_expr(&call.arguments, "scale")
                .or_else(|| call.arguments.args.get(1))
                .and_then(|e| eval_int_expr(e, env))
                .and_then(|v| u16::try_from(v).ok());
            Some(CanonicalType::Numeric {
                precision: p,
                scale: s,
            })
        }
        "Boolean" | "BOOLEAN" => Some(CanonicalType::Boolean),
        "Uuid" | "UUID" => Some(CanonicalType::Uuid),
        "JSON" => Some(CanonicalType::Json),
        "JSONB" => Some(CanonicalType::Jsonb),
        "LargeBinary" | "BLOB" | "BYTEA" => {
            if let Some(len) = length {
                Some(CanonicalType::VarBinary { length: Some(len) })
            } else {
                Some(CanonicalType::Blob)
            }
        }
        "BINARY" => Some(CanonicalType::FixedBinary { length }),
        "VARBINARY" => Some(CanonicalType::VarBinary { length }),
        "DateTime" | "DATETIME" => {
            let tz = kwarg_expr(&call.arguments, "timezone")
                .and_then(eval_bool_expr)
                .unwrap_or(false);
            Some(CanonicalType::DateTime { timezone: tz })
        }
        "Date" | "DATE" => Some(CanonicalType::Date),
        "Time" | "TIME" => {
            let tz = kwarg_expr(&call.arguments, "timezone")
                .and_then(eval_bool_expr)
                .unwrap_or(false);
            Some(CanonicalType::Time { timezone: tz })
        }
        "Enum" => {
            let mut values = Vec::new();
            for arg in &call.arguments.args {
                if let Some(s) = eval_string_expr(arg) {
                    values.push(s);
                }
            }
            let enum_name = kwarg_expr(&call.arguments, "name").and_then(eval_string_expr);
            Some(CanonicalType::Enum {
                name: enum_name,
                values,
            })
        }
        _ => None,
    }
}

fn class_ref_type_name(expr: &Expr) -> Option<CanonicalType> {
    let name = expr_dotted_last(expr)?;
    match name {
        "Integer" | "INTEGER" => Some(CanonicalType::Integer),
        "SmallInteger" | "SMALLINT" => Some(CanonicalType::SmallInt),
        "BigInteger" | "BIGINT" => Some(CanonicalType::BigInt),
        "Text" | "TEXT" => Some(CanonicalType::Text),
        "LONGTEXT" => Some(CanonicalType::LongText),
        "MEDIUMTEXT" => Some(CanonicalType::MediumText),
        "String" => Some(CanonicalType::Varchar { length: None }),
        "Boolean" | "BOOLEAN" => Some(CanonicalType::Boolean),
        "Uuid" | "UUID" => Some(CanonicalType::Uuid),
        "JSON" => Some(CanonicalType::Json),
        "JSONB" => Some(CanonicalType::Jsonb),
        "LargeBinary" | "BLOB" => Some(CanonicalType::Blob),
        "Float" => Some(CanonicalType::Float),
        "Double" => Some(CanonicalType::Double),
        "Date" => Some(CanonicalType::Date),
        "DateTime" => Some(CanonicalType::DateTime { timezone: false }),
        "Time" => Some(CanonicalType::Time { timezone: false }),
        _ => None,
    }
}

fn is_computed_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(c) if expr_dotted_last(&c.func) == Some("Computed"))
}

fn parse_computed_call(expr: &Expr, env: &HashMap<String, StaticScalar>) -> Option<ComputedColumnIr> {
    let Expr::Call(call) = expr else {
        return None;
    };
    let arg0 = call.arguments.args.first()?;
    let raw_sql = match arg0 {
        Expr::Call(inner) if expr_dotted_last(&inner.func) == Some("text") => {
            inner.arguments.args.first().and_then(|e| eval_sql_template_expr(e, env))?
        }
        other => eval_sql_template_expr(other, env)?,
    };
    let persisted = kwarg_expr(&call.arguments, "persisted")
        .and_then(eval_bool_expr)
        .unwrap_or(true);
    Some(ComputedColumnIr {
        expression: raw_sql,
        persisted,
        dialect_expressions: BTreeMap::new(),
    })
}

fn parse_server_default_expr(expr: &Expr) -> Option<ServerDefaultIr> {
    match expr {
        Expr::StringLiteral(s) => {
            let v = s.value.to_str();
            parse_default_text(v)
        }
        Expr::Call(call) => {
            let fn_name = expr_dotted_last(&call.func)?;
            match fn_name {
                "false" => Some(ServerDefaultIr::Boolean { value: false }),
                "true" => Some(ServerDefaultIr::Boolean { value: true }),
                "text" => {
                    let inner = call.arguments.args.first().and_then(eval_string_expr)?;
                    parse_default_text(&inner)
                }
                "now" | "current_timestamp" => Some(ServerDefaultIr::CurrentTimestamp),
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_default_text(raw: &str) -> Option<ServerDefaultIr> {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
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
    if let Ok(n) = t.parse::<i64>() {
        return Some(ServerDefaultIr::Integer { value: n });
    }
    if t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2 {
        return Some(ServerDefaultIr::String {
            value: t[1..t.len() - 1].replace("''", "'"),
        });
    }
    Some(ServerDefaultIr::Expression {
        raw: t.to_string(),
        dialect_expressions: BTreeMap::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_table_args(
    table_name: &str,
    expr: &Expr,
    env: &HashMap<String, StaticScalar>,
    uniques: &mut Vec<UniqueIr>,
    checks: &mut Vec<CheckIr>,
    indexes: &mut Vec<IndexIr>,
    foreign_keys: &mut Vec<ForeignKeyIr>,
    table_comment: &mut Option<String>,
) {
    let items: &[Expr] = match expr {
        Expr::Tuple(t) => &t.elts,
        Expr::List(l) => &l.elts,
        Expr::Dict(d) => {
            for item in &d.items {
                if let Some(k) = item.key.as_ref().and_then(eval_string_expr)
                    && k == "comment"
                {
                    *table_comment = eval_string_expr(&item.value);
                }
            }
            return;
        }
        _ => return,
    };

    for item in items {
        if let Expr::Dict(d) = item {
            for entry in &d.items {
                if let Some(k) = entry.key.as_ref().and_then(eval_string_expr)
                    && k == "comment"
                {
                    *table_comment = eval_string_expr(&entry.value);
                }
            }
            continue;
        }
        let Expr::Call(call) = item else {
            continue;
        };
        let Some(kind_name) = expr_dotted_last(&call.func) else {
            continue;
        };
        match kind_name {
            "UniqueConstraint" => {
                let mut cols = Vec::new();
                for arg in &call.arguments.args {
                    if let Some(s) = eval_string_expr(arg) {
                        cols.push(s);
                    }
                }
                let explicit_name = kwarg_expr(&call.arguments, "name").and_then(eval_string_expr);
                let col0 = cols.first().map_or("col", String::as_str);
                let name = explicit_name.unwrap_or_else(|| format!("uq_{table_name}_{col0}"));
                uniques.push(UniqueIr {
                    name: Some(name),
                    dialect_names: BTreeMap::new(),
                    columns: cols,
                });
            }
            "CheckConstraint" => {
                let sql_expr = call
                    .arguments
                    .args
                    .first()
                    .and_then(|e| eval_sql_template_expr(e, env))
                    .unwrap_or_default();
                let explicit_name = kwarg_expr(&call.arguments, "name").and_then(eval_string_expr);
                if !sql_expr.is_empty() {
                    checks.push(CheckIr {
                        name: explicit_name,
                        dialect_names: BTreeMap::new(),
                        expression: sql_expr,
                        dialect_expressions: BTreeMap::new(),
                    });
                }
            }
            "Index" => {
                if let Some(idx_name) = call.arguments.args.first().and_then(eval_string_expr) {
                    let unique = kwarg_expr(&call.arguments, "unique")
                        .and_then(eval_bool_expr)
                        .unwrap_or(false);
                    let mut exprs = Vec::new();
                    for arg in call.arguments.args.iter().skip(1) {
                        if let Some(s) = eval_string_expr(arg) {
                            exprs.push(s);
                        } else if let Some(rendered) = render_index_expr(arg) {
                            exprs.push(rendered);
                        }
                    }
                    indexes.push(IndexIr {
                        name: idx_name,
                        dialect_names: BTreeMap::new(),
                        unique,
                        expressions: exprs,
                        dialect_clauses: BTreeMap::new(),
                        where_clause: None,
                    });
                }
            }
            "ForeignKeyConstraint" => {
                if let (Some(cols_expr), Some(ref_expr)) =
                    (call.arguments.args.first(), call.arguments.args.get(1))
                {
                    let cols = eval_string_list_expr(cols_expr);
                    let refs = eval_string_list_expr(ref_expr);
                    if let Some((ref_table, _)) = refs.first().and_then(|r| r.split_once('.')) {
                        let ref_cols = refs
                            .iter()
                            .filter_map(|r| r.split_once('.').map(|(_, c)| c.to_string()))
                            .collect();
                        let explicit_name =
                            kwarg_expr(&call.arguments, "name").and_then(eval_string_expr);
                        let on_delete = kwarg_expr(&call.arguments, "ondelete")
                            .and_then(eval_string_expr)
                            .and_then(|s| ReferentialAction::from_sql_str(&s));
                        foreign_keys.push(ForeignKeyIr {
                            name: explicit_name,
                            dialect_names: BTreeMap::new(),
                            columns: cols,
                            ref_table: ref_table.to_string(),
                            ref_columns: ref_cols,
                            on_delete,
                            on_update: None,
                            defer_on_create: false,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

fn render_index_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Call(call) => {
            if let Some(dotted) = expr_dotted_name(&call.func)
                && let Some(fn_name) = dotted.strip_prefix("func.")
            {
                let args = call
                    .arguments
                    .args
                    .iter()
                    .filter_map(|a| eval_string_expr(a).or_else(|| expr_dotted_last(a).map(ToString::to_string)))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Some(format!("{fn_name}({args})"));
            }
            None
        }
        other => expr_dotted_last(other).map(ToString::to_string),
    }
}

fn resolve_fk_target_types(
    tables: &BTreeMap<String, (Vec<RawColumn>, TableIr)>,
) -> HashMap<(String, String), CanonicalType> {
    let mut map = HashMap::new();
    for (tname, (cols, _)) in tables {
        for col in cols {
            if let Some(ty) = &col.canonical_type {
                map.insert((tname.clone(), col.name.clone()), ty.clone());
            } else if let Some(ty) = &col.annotated_type {
                map.insert((tname.clone(), col.name.clone()), ty.clone());
            }
        }
    }
    // Second hop in case of A.x -> B.y -> C.z foreign key chains.
    for _ in 0..3 {
        for (tname, (cols, _)) in tables {
            for col in cols {
                if !map.contains_key(&(tname.clone(), col.name.clone()))
                    && let Some((rt, rcol)) = &col.fk_ref
                    && let Some(target_ty) = map.get(&(rt.clone(), rcol.clone())).cloned()
                {
                    map.insert((tname.clone(), col.name.clone()), target_ty);
                }
            }
        }
    }
    map
}

fn eval_scalar(expr: &Expr, env: &HashMap<String, StaticScalar>) -> Option<StaticScalar> {
    match expr {
        Expr::StringLiteral(s) => Some(StaticScalar::Str(s.value.to_str().to_string())),
        Expr::BooleanLiteral(b) => Some(StaticScalar::Bool(b.value)),
        Expr::NumberLiteral(n) => match &n.value {
            ast::Number::Int(i) => i.as_i64().map(StaticScalar::Int),
            _ => None,
        },
        Expr::UnaryOp(u) if matches!(u.op, UnaryOp::USub) => {
            if let Some(StaticScalar::Int(v)) = eval_scalar(&u.operand, env) {
                Some(StaticScalar::Int(-v))
            } else {
                None
            }
        }
        Expr::BinOp(b) => match (&b.op, eval_scalar(&b.left, env), eval_scalar(&b.right, env)) {
            (Operator::Add, Some(StaticScalar::Int(l)), Some(StaticScalar::Int(r))) => {
                Some(StaticScalar::Int(l + r))
            }
            (Operator::Sub, Some(StaticScalar::Int(l)), Some(StaticScalar::Int(r))) => {
                Some(StaticScalar::Int(l - r))
            }
            (Operator::Mult, Some(StaticScalar::Int(l)), Some(StaticScalar::Int(r))) => {
                Some(StaticScalar::Int(l * r))
            }
            (Operator::Add, Some(StaticScalar::Str(l)), Some(StaticScalar::Str(r))) => {
                Some(StaticScalar::Str(format!("{l}{r}")))
            }
            _ => None,
        },
        _ => expr_dotted_name(expr).and_then(|name| env.get(&name).cloned()),
    }
}

fn eval_int_expr(expr: &Expr, env: &HashMap<String, StaticScalar>) -> Option<i64> {
    match eval_scalar(expr, env) {
        Some(StaticScalar::Int(i)) => Some(i),
        _ => None,
    }
}

fn eval_string_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        _ => None,
    }
}

fn eval_sql_template_expr(expr: &Expr, env: &HashMap<String, StaticScalar>) -> Option<String> {
    match expr {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        Expr::FString(fs) => {
            let mut out = String::new();
            for part in fs.value.iter() {
                match part {
                    ast::FStringPartRef::Literal(lit) => out.push_str(&lit.value),
                    ast::FStringPartRef::FString(fstr) => {
                        for element in &fstr.elements {
                            match element {
                                ast::InterpolatedStringElement::Literal(lit) => {
                                    out.push_str(&lit.value);
                                }
                                ast::InterpolatedStringElement::Interpolation(interp) => {
                                    match eval_scalar(&interp.expression, env) {
                                        Some(StaticScalar::Int(v)) => out.push_str(&v.to_string()),
                                        Some(StaticScalar::Str(s)) => {
                                            out.push_str(&format!("'{s}'"));
                                        }
                                        Some(StaticScalar::Bool(b)) => {
                                            out.push_str(if b { "true" } else { "false" });
                                        }
                                        None => return None,
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn eval_bool_expr(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(b) => Some(b.value),
        _ => None,
    }
}

fn eval_string_list_expr(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::NoneLiteral(_) => Vec::new(),
        Expr::StringLiteral(s) => vec![s.value.to_str().to_string()],
        Expr::Tuple(t) => t.elts.iter().filter_map(eval_string_expr).collect(),
        Expr::List(l) => l.elts.iter().filter_map(eval_string_expr).collect(),
        _ => Vec::new(),
    }
}

fn kwarg_expr<'a>(args: &'a ast::Arguments, name: &str) -> Option<&'a Expr> {
    args.keywords
        .iter()
        .find(|kw| kw.arg.as_ref().is_some_and(|id| id.as_str() == name))
        .map(|kw| &kw.value)
}

fn expr_ident(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str()),
        _ => None,
    }
}

fn expr_dotted_last(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str()),
        Expr::Attribute(a) => Some(a.attr.as_str()),
        _ => None,
    }
}

fn expr_dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.to_string()),
        Expr::Attribute(a) => {
            let prefix = expr_dotted_name(&a.value)?;
            Some(format!("{prefix}.{}", a.attr))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_ast_handles_python_315_lazy_import_and_implicit_types() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let src = root.join("src");
        let cfg_dir = src.join("include").join("config");
        let models_dir = src.join("include").join("database").join("models");
        std::fs::create_dir_all(&cfg_dir).expect("mkdir config");
        std::fs::create_dir_all(&models_dir).expect("mkdir models");
        std::fs::write(src.join("main.py"), "# entry").expect("write main.py");

        std::fs::write(
            cfg_dir.join("constants.py"),
            "USERNAME_MAX = 256\n",
        )
        .expect("write constants");

        std::fs::write(
            models_dir.join("sample.py"),
            r#"
import uuid
from enum import IntEnum
lazy from datetime import datetime
from sqlalchemy import Computed, ForeignKey, Index, Integer, BigInteger, String, Text, CheckConstraint
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import Mapped, mapped_column

class EntityStatus(IntEnum):
    ACTIVE = 0
    DELETED = 1

class TimestampMixin:
    __abstract__ = True
    created_at: Mapped[float]

class ParentItem(TimestampMixin, Base):
    __tablename__ = "parent_items"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(USERNAME_MAX))
    payload: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), "mysql"))
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    active_name: Mapped[str | None] = mapped_column(
        String(255),
        Computed(f"CASE WHEN status = {EntityStatus.DELETED.value} THEN NULL ELSE name END", persisted=True),
    )

    __table_args__ = (
        CheckConstraint("status >= 0", name="ck_parent_items_status"),
        Index("ix_parent_items_lower_name", func.lower(name)),
    )

class ChildItem(Base):
    __tablename__ = "child_items"
    seq: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    parent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("parent_items.id", ondelete="CASCADE"))
"#,
        )
        .expect("write models");

        let paths = WorkspacePaths::discover(Some(&src), None).expect("discover paths");
        let ir = extract_static_schema_ir(&paths, false).expect("extract static ir");

        let parent = &ir.tables["parent_items"];
        assert_eq!(parent.column("id").unwrap().canonical_type, CanonicalType::Uuid);
        assert_eq!(
            parent.column("name").unwrap().canonical_type,
            CanonicalType::Varchar { length: Some(256) }
        );
        assert_eq!(parent.column("payload").unwrap().canonical_type, CanonicalType::LongText);
        assert!(parent.column("active_name").unwrap().nullable);
        assert_eq!(
            parent
                .column("active_name")
                .unwrap()
                .computed
                .as_ref()
                .unwrap()
                .expression,
            "CASE WHEN status = 1 THEN NULL ELSE name END"
        );
        // Mixin inherited column `created_at`
        assert!(parent.column("created_at").is_some());
        assert_eq!(parent.checks.len(), 1);
        assert_eq!(parent.indexes[0].expressions, vec!["lower(name)"]);

        let child = &ir.tables["child_items"];
        assert_eq!(child.column("seq").unwrap().canonical_type, CanonicalType::BigSerial);
        assert_eq!(child.column("parent_id").unwrap().canonical_type, CanonicalType::Uuid);
    }

    #[test]
    fn static_ast_flags_declared_attr_low_confidence_and_detects_alembic_dml() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let src = root.join("src");
        let models_dir = src.join("include").join("database").join("models");
        let versions_dir = src.join("alembic").join("versions");
        std::fs::create_dir_all(&models_dir).expect("mkdir models");
        std::fs::create_dir_all(&versions_dir).expect("mkdir versions");
        std::fs::write(src.join("main.py"), "# entry").expect("write main.py");
        std::fs::write(src.join("alembic.ini"), "[alembic]\n").expect("write ini");

        std::fs::write(
            models_dir.join("dyn.py"),
            r#"
class DynMixin:
    @declared_attr
    def tenant_id(cls):
        return mapped_column(String(32))

class DynTable(DynMixin, Base):
    __tablename__ = "dyn_tables"
    id: Mapped[int] = mapped_column(primary_key=True)
"#,
        )
        .expect("write dyn");

        std::fs::write(
            versions_dir.join("0001_init.py"),
            "revision = 'rev1'\ndown_revision = None\ndef upgrade():\n    op.create_table('t')\n",
        )
        .expect("write rev1");
        std::fs::write(
            versions_dir.join("0002_backfill.py"),
            "revision: str = 'rev2'\ndown_revision = 'rev1'\ndef upgrade():\n    op.execute('UPDATE t SET a = 1')\n",
        )
        .expect("write rev2");

        let paths = WorkspacePaths::discover(Some(&src), None).expect("discover");
        let ir = extract_static_schema_ir(&paths, false).expect("extract");
        assert_eq!(ir.schema_revision.as_deref(), Some("rev2"));
        assert_eq!(ir.tables["dyn_tables"].confidence, ConfidenceLevel::Low);
        assert!(ir.warnings.iter().any(|w| w.contains("@declared_attr")));

        let analysis = analyze_alembic_directory(&versions_dir).expect("alembic analysis");
        let pending = analysis.pending_since(Some("rev1"));
        assert_eq!(pending.pending_revisions, vec!["rev2".to_string()]);
        assert!(pending.has_data_dml);
        assert_eq!(pending.dml_revisions[0].0, "rev2");
    }
}
