# /// script
# requires-python = ">=3.15"
# dependencies = [
#     "sqlalchemy>=2.0",
#     "alembic",
# ]
# ///

"""Read-only SQLAlchemy MetaData probe for cfms-ctl.

Imports the target `Base.metadata` (and optional extension tables) without
mutating disk state, emitting bytecode, or requiring `config.toml`, then exports
a normalized SchemaIr v1 JSON payload to `--out`.
"""

import argparse
import importlib
import json
import sys
import tomllib
import types
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import MetaData


class LoadExtFn(Protocol):
    def __call__(
        self, metadata: MetaData, path: Path | None = None
    ) -> dict[str, Any]: ...


def _install_cfms_config_stub(server_root: Path, warnings: list[str]) -> None:
    """Stub `include.config.settings` with an in-memory SQLite config when needed."""
    settings_file = server_root / "include" / "config" / "settings.py"
    if not settings_file.is_file():
        return

    config_data: dict[str, Any] = {}
    sample_path = server_root / "config.toml.sample"
    config_path = server_root / "config.toml"
    for candidate in (config_path, sample_path):
        if candidate.is_file():
            try:
                config_data = tomllib.loads(candidate.read_text(encoding="utf-8"))
                break
            except Exception as exc:  # pragma: no cover - defensive
                warnings.append(f"Probe failed to parse {candidate.name}: {exc}")

    config_data["debug"] = False
    db_section = dict(config_data.get("database") or {})
    db_section["type"] = "sqlite"
    db_section["file"] = ":memory:"
    config_data["database"] = db_section

    class _StubGlobalConfig:
        def __init__(self, data: dict[str, Any], path: str) -> None:
            self._data = data
            self._config_path = path

        def reload(self) -> None:
            return None

        def snapshot(self) -> dict[str, Any]:
            return dict(self._data)

        def get(self, key: str, default: Any = None) -> Any:
            return self._data.get(key, default)

        def __getitem__(self, key: str) -> Any:
            return self._data[key]

        def __iter__(self):
            return iter(tuple(self._data))

        def __len__(self) -> int:
            return len(self._data)

        def __contains__(self, key: object) -> bool:
            return key in self._data

    stub_mod = types.ModuleType("include.config.settings")
    stub_mod.GlobalConfig = _StubGlobalConfig  # type: ignore[attr-defined]
    stub_mod.global_config = _StubGlobalConfig(  # type: ignore[attr-defined]
        config_data, str(config_path)
    )
    stub_mod.__all__ = ["GlobalConfig", "global_config"]  # type: ignore[attr-defined]
    sys.modules["include.config.settings"] = stub_mod


def _load_target_object(target: str) -> Any:
    if ":" not in target:
        raise ValueError(f"Expected module:attr target, got {target!r}")
    mod_name, attr_path = target.split(":", 1)
    if mod_name.startswith("include.database."):
        try:
            importlib.import_module("include.database.models")
        except ImportError:
            pass
    module = importlib.import_module(mod_name)
    obj: Any = module
    for part in attr_path.split("."):
        obj = getattr(obj, part)
    return obj


def _extract_alembic_head(server_root: Path) -> str | None:
    alembic_ini = server_root / "alembic.ini"
    if alembic_ini.is_file():
        try:
            from alembic.config import Config
            from alembic.script import ScriptDirectory

            cfg = Config(str(alembic_ini))
            if not cfg.get_main_option("script_location"):
                cfg.set_main_option("script_location", str(server_root / "alembic"))
            script_dir = ScriptDirectory.from_config(cfg)
            heads = script_dir.get_heads()
            if len(heads) == 1:
                return str(heads[0])
        except Exception:
            pass
    return None


def _map_canonical_type(
    col: Any, is_single_pk: bool, dialects: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    import sqlalchemy as sa

    col_type = col.type
    variant_mapping: dict[str, Any] = dict(
        getattr(col_type, "_variant_mapping", {}) or {}
    )
    base_type = variant_mapping.get("_default", col_type)
    while isinstance(base_type, sa.TypeDecorator):
        base_type = base_type.impl

    sqlite_impl = col_type.dialect_impl(dialects["sqlite"])
    mysql_impl = col_type.dialect_impl(dialects["mysql"])
    pg_impl = col_type.dialect_impl(dialects["postgresql"])

    is_autoinc = False
    if is_single_pk and isinstance(base_type, sa.Integer):
        auto_val = col.autoincrement
        table = getattr(col, "table", None)
        if auto_val is True:
            is_autoinc = True
        elif auto_val == "auto":
            if table is not None:
                is_autoinc = getattr(table, "_autoincrement_column", None) is col
            else:
                is_autoinc = (
                    not col.foreign_keys
                    and col.default is None
                    and col.server_default is None
                )

    def _compile_upper(d_name: str) -> str:
        return str(col_type.compile(dialect=dialects[d_name])).strip().upper()

    # Check dialect-variant patterns first.
    if (
        isinstance(base_type, sa.BigInteger)
        and isinstance(sqlite_impl, sa.Integer)
        and not isinstance(sqlite_impl, sa.BigInteger)
    ):
        return (
            {"kind": "big_serial"}
            if is_autoinc
            else {"kind": "sqlite_int_else_big_int"}
        ), is_autoinc

    mysql_impl_name = type(mysql_impl).__name__.upper()
    if isinstance(base_type, sa.Text) and mysql_impl_name in ("LONGTEXT", "MEDIUMTEXT"):
        return {"kind": mysql_impl_name.lower().replace("text", "_text")}, False

    if (
        isinstance(base_type, sa.LargeBinary)
        and "BINARY" in mysql_impl_name
        and "VAR" not in mysql_impl_name
        and "BLOB" not in mysql_impl_name
    ):
        m_upper = _compile_upper("mysql")
        if m_upper.startswith("BINARY("):
            inner = m_upper[len("BINARY(") : -1].strip()
            length = (
                int(inner) if inner.isdigit() else getattr(base_type, "length", None)
            )
            return {"kind": "fixed_binary", "length": length}, False

    pg_impl_name = type(pg_impl).__name__.upper()
    if isinstance(base_type, sa.JSON) and pg_impl_name == "JSONB":
        return {"kind": "jsonb"}, False

    # Base SQLAlchemy types.
    type_name = type(base_type).__name__
    if isinstance(base_type, sa.Uuid) or type_name in ("UUID", "Uuid"):
        return {"kind": "uuid"}, False
    if isinstance(base_type, sa.Enum):
        enums = [str(e) for e in getattr(base_type, "enums", [])]
        return {
            "kind": "enum",
            "name": getattr(base_type, "name", None),
            "values": enums,
        }, False
    if isinstance(base_type, sa.Boolean):
        return {"kind": "boolean"}, False
    if isinstance(base_type, sa.SmallInteger):
        return {"kind": "small_int"}, False
    if isinstance(base_type, sa.BigInteger):
        return (
            {"kind": "big_serial"} if is_autoinc else {"kind": "big_int"}
        ), is_autoinc
    if isinstance(base_type, sa.Integer):
        return ({"kind": "serial"} if is_autoinc else {"kind": "integer"}), is_autoinc
    if type_name == "DOUBLE_PRECISION" or isinstance(
        base_type, getattr(sa, "Double", ())
    ):
        return {"kind": "double"}, False
    if isinstance(base_type, sa.Float):
        prec = getattr(base_type, "precision", None)
        if isinstance(prec, int) and prec > 24:
            return {"kind": "double"}, False
        return {"kind": "float"}, False
    if isinstance(base_type, sa.Numeric):
        return {
            "kind": "numeric",
            "precision": getattr(base_type, "precision", None),
            "scale": getattr(base_type, "scale", None),
        }, False
    if isinstance(base_type, sa.CHAR):
        return {"kind": "char", "length": getattr(base_type, "length", None)}, False
    if isinstance(base_type, sa.Text):
        if "LONGTEXT" in type_name.upper():
            return {"kind": "long_text"}, False
        if "MEDIUMTEXT" in type_name.upper():
            return {"kind": "medium_text"}, False
        return {"kind": "text"}, False
    if isinstance(base_type, sa.String):
        length = getattr(base_type, "length", None)
        if length is None and type_name == "Text":
            return {"kind": "text"}, False
        return {"kind": "varchar", "length": length}, False
    if isinstance(base_type, sa.JSON):
        if "JSONB" in type_name.upper():
            return {"kind": "jsonb"}, False
        return {"kind": "json"}, False
    if isinstance(base_type, sa.LargeBinary):
        if "VARBINARY" in type_name.upper():
            return {
                "kind": "var_binary",
                "length": getattr(base_type, "length", None),
            }, False
        if "BINARY" in type_name.upper() and "LARGE" not in type_name.upper():
            return {
                "kind": "fixed_binary",
                "length": getattr(base_type, "length", None),
            }, False
        length = getattr(base_type, "length", None)
        if length is not None:
            return {"kind": "var_binary", "length": length}, False
        return {"kind": "blob"}, False
    if isinstance(base_type, sa.DateTime):
        return {
            "kind": "date_time",
            "timezone": bool(getattr(base_type, "timezone", False)),
        }, False
    if isinstance(base_type, sa.Date):
        return {"kind": "date"}, False
    if isinstance(base_type, sa.Time):
        return {
            "kind": "time",
            "timezone": bool(getattr(base_type, "timezone", False)),
        }, False

    if not isinstance(base_type, sa.types.TypeEngine):
        return {"kind": "custom", "raw": str(col_type)}, False
    return {"kind": "custom", "raw": _compile_upper("postgresql")}, False


def _extract_server_default(
    col: Any, dialects: dict[str, Any]
) -> dict[str, Any] | None:
    import sqlalchemy as sa

    if (
        col.server_default is None
        or col.computed is not None
        or isinstance(col.server_default, sa.Computed)
    ):
        return None
    arg = getattr(col.server_default, "arg", col.server_default)
    raw = str(getattr(arg, "text", arg)).strip()
    lower = raw.lower()
    if lower in ("false", "0") and "bool" in type(col.type).__name__.lower():
        return {"kind": "boolean", "value": False}
    if lower in ("true", "1") and "bool" in type(col.type).__name__.lower():
        return {"kind": "boolean", "value": True}
    if lower in ("false", "true"):
        return {"kind": "boolean", "value": lower == "true"}
    if lower in ("current_timestamp", "current_timestamp()", "now()"):
        return {"kind": "current_timestamp"}
    if raw.lstrip("+-").isdigit():
        return {"kind": "integer", "value": int(raw)}
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return {"kind": "string", "value": raw[1:-1].replace("''", "'")}

    dialect_exprs: dict[str, str] = {}
    if hasattr(arg, "compile"):
        for d_name, dialect in dialects.items():
            try:
                dialect_exprs[d_name] = _compile_expr(arg, dialect)
            except Exception:
                pass
        raw = dialect_exprs.get("postgresql") or dialect_exprs.get("sqlite") or raw

    return {
        "kind": "expression",
        "raw": raw,
        "dialect_expressions": dialect_exprs,
    }


def _compile_expr(expr: Any, dialect: Any) -> str:
    compiler = dialect.statement_compiler(dialect, None)
    return str(compiler.process(expr, include_table=False, literal_binds=True)).strip()


def _format_constraint_name(constraint: Any, dialect: Any) -> str | None:
    try:
        formatted = dialect.identifier_preparer.format_constraint(constraint)
        if formatted:
            # Strip dialect quotes if SQLAlchemy quoted a mixed-case identifier.
            if (formatted.startswith('"') and formatted.endswith('"')) or (
                formatted.startswith("`") and formatted.endswith("`")
            ):
                return formatted[1:-1]
            return formatted
    except Exception:
        pass
    return getattr(constraint, "name", None)


def _export_table(
    table: Any,
    ownership: str | dict[str, str],
    dialects: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    import sqlalchemy as sa

    pk_cols = [c.name for c in table.primary_key.columns]
    is_single_pk = len(pk_cols) == 1

    columns_ir: list[dict[str, Any]] = []
    for ordinal, col in enumerate(table.columns):
        canonical_type, is_autoinc = _map_canonical_type(
            col, is_single_pk and col.primary_key, dialects
        )
        dialect_types: dict[str, str] = {}
        for d_name, dialect in dialects.items():
            try:
                dialect_types[d_name] = str(col.type.compile(dialect=dialect))
            except Exception as exc:
                warnings.append(
                    f"Failed compiling type for {table.name}.{col.name} ({d_name}): {exc}"
                )

        computed_ir = None
        if getattr(col, "computed", None) is not None:
            comp = col.computed
            dialect_exprs: dict[str, str] = {}
            for d_name, dialect in dialects.items():
                try:
                    dialect_exprs[d_name] = _compile_expr(comp.sqltext, dialect)
                except Exception as exc:
                    warnings.append(
                        f"Failed compiling computed expr for {table.name}.{col.name} ({d_name}): {exc}"
                    )
            base_expr = dialect_exprs.get("sqlite") or next(
                iter(dialect_exprs.values()), str(comp.sqltext)
            )
            computed_ir = {
                "expression": base_expr,
                "persisted": True if comp.persisted is None else bool(comp.persisted),
                "dialect_expressions": {
                    k: v for k, v in dialect_exprs.items() if v != base_expr
                },
            }

        columns_ir.append({
            "name": col.name,
            "ordinal": ordinal,
            "canonical_type": canonical_type,
            "dialect_types": dialect_types,
            "nullable": bool(col.nullable),
            "autoincrement": bool(is_autoinc),
            "server_default": _extract_server_default(col, dialects),
            "computed": computed_ir,
            "comment": col.comment,
            "confidence": "high",
        })

    pk_dialect_names: dict[str, str] = {}
    pk_base_name = _format_constraint_name(table.primary_key, dialects["sqlite"])
    for d_name, dialect in dialects.items():
        if d_name == "sqlite":
            continue
        formatted = _format_constraint_name(table.primary_key, dialect)
        if formatted and formatted != pk_base_name:
            pk_dialect_names[d_name] = formatted

    fks_ir: list[dict[str, Any]] = []
    uniques_ir: list[dict[str, Any]] = []
    checks_ir: list[dict[str, Any]] = []

    def _ref_action(raw: str | None) -> str | None:
        if not raw:
            return None
        upper = raw.strip().upper()
        mapping = {
            "NO ACTION": "no_action",
            "RESTRICT": "restrict",
            "CASCADE": "cascade",
            "SET NULL": "set_null",
            "SET DEFAULT": "set_default",
        }
        return mapping.get(upper)

    for constraint in sorted(
        table.constraints,
        key=lambda c: (type(c).__name__, str(getattr(c, "name", "") or "")),
    ):
        if isinstance(constraint, sa.PrimaryKeyConstraint):
            continue
        base_name = _format_constraint_name(constraint, dialects["sqlite"])
        dialect_names: dict[str, str] = {}
        for d_name, dialect in dialects.items():
            if d_name == "sqlite":
                continue
            formatted = _format_constraint_name(constraint, dialect)
            if formatted and formatted != base_name:
                dialect_names[d_name] = formatted

        if isinstance(constraint, sa.ForeignKeyConstraint):
            elements = list(constraint.elements)
            fks_ir.append({
                "name": base_name,
                "dialect_names": dialect_names,
                "columns": [el.parent.name for el in elements],
                "ref_table": elements[0].column.table.name if elements else "",
                "ref_columns": [el.column.name for el in elements],
                "on_delete": _ref_action(constraint.ondelete),
                "on_update": _ref_action(constraint.onupdate),
                "defer_on_create": False,
            })
        elif isinstance(constraint, sa.UniqueConstraint):
            uniques_ir.append({
                "name": base_name,
                "dialect_names": dialect_names,
                "columns": [c.name for c in constraint.columns],
            })
        elif isinstance(constraint, sa.CheckConstraint):
            d_exprs: dict[str, str] = {}
            for d_name, dialect in dialects.items():
                try:
                    d_exprs[d_name] = _compile_expr(constraint.sqltext, dialect)
                except Exception:
                    pass
            base_expr = d_exprs.get("sqlite") or str(constraint.sqltext)
            checks_ir.append({
                "name": base_name,
                "dialect_names": dialect_names,
                "expression": base_expr,
                "dialect_expressions": {
                    k: v for k, v in d_exprs.items() if v != base_expr
                },
            })

    indexes_ir: list[dict[str, Any]] = []
    for idx in sorted(table.indexes, key=lambda i: str(i.name or "")):
        idx_name = _format_constraint_name(idx, dialects["sqlite"]) or str(idx.name)
        idx_dialect_names: dict[str, str] = {}
        for d_name, dialect in dialects.items():
            if d_name == "sqlite":
                continue
            formatted = _format_constraint_name(idx, dialect)
            if formatted and formatted != idx_name:
                idx_dialect_names[d_name] = formatted

        sqlite_exprs: list[str] = []
        mysql_items: list[str] = []
        for expr in idx.expressions:
            s_expr = _compile_expr(expr, dialects["sqlite"])
            sqlite_exprs.append(s_expr)
            if isinstance(expr, sa.Column):
                mysql_items.append(s_expr)
            else:
                m_expr = _compile_expr(expr, dialects["mysql"])
                mysql_items.append(
                    f"({m_expr})"
                    if "(" in m_expr and not m_expr.startswith("(")
                    else m_expr
                )

        dialect_clauses: dict[str, str] = {}
        sqlite_joined = ", ".join(sqlite_exprs)
        mysql_joined = ", ".join(mysql_items)
        if mysql_joined != sqlite_joined:
            dialect_clauses["mysql"] = mysql_joined

        where_clause = None
        for d_opt in ("sqlite_where", "postgresql_where"):
            opt_val = idx.dialect_options.get(d_opt.split("_")[0], {}).get("where")
            if opt_val is not None:
                where_clause = _compile_expr(opt_val, dialects["sqlite"])
                break

        indexes_ir.append({
            "name": idx_name,
            "dialect_names": idx_dialect_names,
            "unique": bool(idx.unique),
            "expressions": sqlite_exprs,
            "dialect_clauses": dialect_clauses,
            "where_clause": where_clause,
        })

    return {
        "name": table.name,
        "ownership": ownership,
        "columns": columns_ir,
        "primary_key": {
            "name": pk_base_name,
            "dialect_names": pk_dialect_names,
            "columns": pk_cols,
        },
        "foreign_keys": fks_ir,
        "uniques": uniques_ir,
        "checks": checks_ir,
        "indexes": indexes_ir,
        "comment": getattr(table, "comment", None),
        "confidence": "high",
    }


def main(argv: list[str] | None = None) -> int:
    sys.dont_write_bytecode = True

    parser = argparse.ArgumentParser(
        description="Export SQLAlchemy MetaData as SchemaIr v1 JSON"
    )
    parser.add_argument("--server-root", required=True, type=Path)
    parser.add_argument("--target", default="include.database.session:Base")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--no-extensions", action="store_true")
    args = parser.parse_args(argv)

    server_root = args.server_root.resolve()
    if str(server_root) not in sys.path:
        sys.path.insert(0, str(server_root))

    warnings: list[str] = []
    if args.target.startswith("include."):
        _install_cfms_config_stub(server_root, warnings)

    target_obj = _load_target_object(args.target)
    metadata = getattr(target_obj, "metadata", target_obj)

    from sqlalchemy.dialects import mysql, postgresql, sqlite

    dialects = {
        "sqlite": sqlite.dialect(),
        "mysql": mysql.dialect(),
        "postgresql": postgresql.dialect(),
    }

    tables_ir: dict[str, Any] = {}
    for table in metadata.tables.values():
        tables_ir[table.name] = _export_table(table, "core", dialects, warnings)

    if not args.no_extensions:
        try:
            ext_data_mod = importlib.import_module("include.extensions.data")
            load_ext: LoadExtFn | None = getattr(
                ext_data_mod, "load_extension_data", None
            )
            if callable(load_ext):
                declarations = load_ext(metadata, None)
                for ext_name, entry in declarations.items():
                    owner = getattr(entry, "owner", ext_name)
                    ext_table = getattr(entry, "table", None)
                    if ext_table is not None and ext_table.name not in tables_ir:
                        tables_ir[ext_table.name] = _export_table(
                            ext_table,
                            {"extension": str(owner)},
                            dialects,
                            warnings,
                        )
        except ImportError:
            pass
        except Exception as exc:
            warnings.append(f"Extension data discovery warning: {exc}")

    naming_conv = {
        str(k): str(v)
        for k, v in dict(getattr(metadata, "naming_convention", {})).items()
    }
    ir_payload = {
        "ir_version": 1,
        "schema_revision": _extract_alembic_head(server_root),
        "source": "python_probe",
        "naming_convention": naming_conv,
        "tables": dict(sorted(tables_ir.items())),
        "warnings": warnings,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(ir_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
