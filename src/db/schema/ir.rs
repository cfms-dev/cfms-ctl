//! Unified strongly-typed intermediate representation (IR) for database schemas
//! across Python `Base.metadata`, static AST scans, live databases, and built-in fallbacks.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::core::error::{CfmsError, Result};
use crate::db::backend::DatabaseKind;

/// Current IR wire format version.
pub const SCHEMA_IR_VERSION: u32 = 1;

/// Provenance of an extracted `SchemaIr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionSource {
    PythonProbe,
    PrebuiltJson,
    StaticAst,
    LiveDatabase,
    BuiltinFallback,
}

impl std::fmt::Display for ExtractionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::PythonProbe => "python_probe",
            Self::PrebuiltJson => "prebuilt_json",
            Self::StaticAst => "static_ast",
            Self::LiveDatabase => "live_database",
            Self::BuiltinFallback => "builtin_fallback",
        };
        f.write_str(s)
    }
}

/// Ownership classification matching CFMS core metadata vs extension metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TableOwnership {
    #[default]
    Core,
    Extension(String),
}

impl TableOwnership {
    #[must_use]
    pub fn is_extension(&self) -> bool {
        matches!(self, Self::Extension(_))
    }

    #[must_use]
    pub fn owner(&self) -> Option<&str> {
        match self {
            Self::Core => None,
            Self::Extension(owner) => Some(owner.as_str()),
        }
    }
}

/// Confidence score associated with schema extraction (`StaticAst` marks dynamic constructs `Low`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    #[default]
    High,
}

/// Coarse semantic family used by column rename scoring and incompatible type auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeFamily {
    String,
    Integer,
    Float,
    Numeric,
    Boolean,
    Uuid,
    Json,
    Binary,
    Temporal,
    Enum,
    Custom,
}

/// Type evolution relationship between an old column type and a new column type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeCompatibility {
    Exact,
    Widening,
    Narrowing,
    CompatibleCrossFamily,
    Incompatible,
}

impl TypeCompatibility {
    #[must_use]
    pub const fn rename_score(self) -> f64 {
        match self {
            Self::Exact => 1.0,
            Self::Widening => 0.85,
            Self::Narrowing => 0.60,
            Self::CompatibleCrossFamily => 0.40,
            Self::Incompatible => 0.0,
        }
    }
}

/// Normalized semantic column type across SQLAlchemy, SQLite, MySQL, and PostgreSQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalType {
    Varchar {
        length: Option<u32>,
    },
    Char {
        length: Option<u32>,
    },
    Text,
    MediumText,
    LongText,
    SmallInt,
    Integer,
    BigInt,
    /// `BigInteger().with_variant(Integer, "sqlite")`.
    SqliteIntElseBigInt,
    Serial,
    BigSerial,
    Float,
    Double,
    Numeric {
        precision: Option<u16>,
        scale: Option<u16>,
    },
    Boolean,
    Uuid,
    Json,
    Jsonb,
    Blob,
    FixedBinary {
        length: Option<u32>,
    },
    VarBinary {
        length: Option<u32>,
    },
    DateTime {
        #[serde(default)]
        timezone: bool,
    },
    Date,
    Time {
        #[serde(default)]
        timezone: bool,
    },
    Enum {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        values: Vec<String>,
    },
    Custom {
        raw: String,
    },
}

impl CanonicalType {
    #[must_use]
    pub const fn is_serial(&self) -> bool {
        matches!(self, Self::Serial | Self::BigSerial)
    }

    #[must_use]
    pub const fn is_integer_like(&self) -> bool {
        matches!(
            self,
            Self::SmallInt
                | Self::Integer
                | Self::BigInt
                | Self::SqliteIntElseBigInt
                | Self::Serial
                | Self::BigSerial
        )
    }

    #[must_use]
    pub const fn family(&self) -> TypeFamily {
        match self {
            Self::Varchar { .. }
            | Self::Char { .. }
            | Self::Text
            | Self::MediumText
            | Self::LongText => TypeFamily::String,
            Self::SmallInt
            | Self::Integer
            | Self::BigInt
            | Self::SqliteIntElseBigInt
            | Self::Serial
            | Self::BigSerial => TypeFamily::Integer,
            Self::Float | Self::Double => TypeFamily::Float,
            Self::Numeric { .. } => TypeFamily::Numeric,
            Self::Boolean => TypeFamily::Boolean,
            Self::Uuid => TypeFamily::Uuid,
            Self::Json | Self::Jsonb => TypeFamily::Json,
            Self::Blob | Self::FixedBinary { .. } | Self::VarBinary { .. } => TypeFamily::Binary,
            Self::DateTime { .. } | Self::Date | Self::Time { .. } => TypeFamily::Temporal,
            Self::Enum { .. } => TypeFamily::Enum,
            Self::Custom { .. } => TypeFamily::Custom,
        }
    }

    /// Render the exact dialect DDL column type string.
    #[must_use]
    pub fn ddl_type(&self, kind: DatabaseKind) -> String {
        match (self, kind) {
            (Self::Varchar { length: Some(len) }, _) => format!("VARCHAR({len})"),
            (Self::Varchar { length: None }, _) => "TEXT".to_string(),
            (Self::Char { length: Some(len) }, _) => format!("CHAR({len})"),
            (Self::Char { length: None }, _) => "CHAR".to_string(),
            (Self::Text, _) => "TEXT".to_string(),
            (Self::MediumText, DatabaseKind::Mysql) => "MEDIUMTEXT".to_string(),
            (Self::MediumText, DatabaseKind::Sqlite | DatabaseKind::Postgresql) => {
                "TEXT".to_string()
            }
            (Self::LongText, DatabaseKind::Mysql) => "LONGTEXT".to_string(),
            (Self::LongText, DatabaseKind::Sqlite | DatabaseKind::Postgresql) => "TEXT".to_string(),
            (Self::SmallInt, _) => "SMALLINT".to_string(),
            (Self::Integer, _) => "INTEGER".to_string(),
            (Self::BigInt, _) => "BIGINT".to_string(),
            (Self::SqliteIntElseBigInt, DatabaseKind::Sqlite) => "INTEGER".to_string(),
            (Self::SqliteIntElseBigInt, DatabaseKind::Mysql | DatabaseKind::Postgresql) => {
                "BIGINT".to_string()
            }
            (Self::Serial, DatabaseKind::Sqlite) => "INTEGER".to_string(),
            (Self::Serial, DatabaseKind::Mysql) => "INTEGER NOT NULL AUTO_INCREMENT".to_string(),
            (Self::Serial, DatabaseKind::Postgresql) => "SERIAL".to_string(),
            (Self::BigSerial, DatabaseKind::Sqlite) => "INTEGER".to_string(),
            (Self::BigSerial, DatabaseKind::Mysql) => "BIGINT NOT NULL AUTO_INCREMENT".to_string(),
            (Self::BigSerial, DatabaseKind::Postgresql) => "BIGSERIAL".to_string(),
            (Self::Float, DatabaseKind::Postgresql) => "REAL".to_string(),
            (Self::Float, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "FLOAT".to_string(),
            (Self::Double, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "DOUBLE".to_string(),
            (Self::Double, DatabaseKind::Postgresql) => "DOUBLE PRECISION".to_string(),
            (Self::Numeric { precision, scale }, _) => match (precision, scale) {
                (Some(p), Some(s)) => format!("NUMERIC({p}, {s})"),
                (Some(p), None) => format!("NUMERIC({p})"),
                _ => "NUMERIC".to_string(),
            },
            (Self::Boolean, DatabaseKind::Mysql) => "BOOL".to_string(),
            (Self::Boolean, DatabaseKind::Sqlite | DatabaseKind::Postgresql) => {
                "BOOLEAN".to_string()
            }
            (Self::Uuid, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "CHAR(32)".to_string(),
            (Self::Uuid, DatabaseKind::Postgresql) => "UUID".to_string(),
            (Self::Json, _) => "JSON".to_string(),
            (Self::Jsonb, DatabaseKind::Postgresql) => "JSONB".to_string(),
            (Self::Jsonb, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "JSON".to_string(),
            (Self::Blob, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "BLOB".to_string(),
            (Self::Blob, DatabaseKind::Postgresql) => "BYTEA".to_string(),
            (Self::FixedBinary { length }, DatabaseKind::Mysql) => match length {
                Some(len) => format!("BINARY({len})"),
                None => "BLOB".to_string(),
            },
            (Self::FixedBinary { .. }, DatabaseKind::Sqlite) => "BLOB".to_string(),
            (Self::FixedBinary { .. }, DatabaseKind::Postgresql) => "BYTEA".to_string(),
            (Self::VarBinary { length }, DatabaseKind::Mysql) => match length {
                Some(len) => format!("VARBINARY({len})"),
                None => "BLOB".to_string(),
            },
            (Self::VarBinary { .. }, DatabaseKind::Sqlite) => "BLOB".to_string(),
            (Self::VarBinary { .. }, DatabaseKind::Postgresql) => "BYTEA".to_string(),
            (Self::DateTime { timezone }, DatabaseKind::Postgresql) => {
                if *timezone {
                    "TIMESTAMP WITH TIME ZONE".to_string()
                } else {
                    "TIMESTAMP WITHOUT TIME ZONE".to_string()
                }
            }
            (Self::DateTime { .. }, DatabaseKind::Mysql) => "DATETIME".to_string(),
            (Self::DateTime { .. }, DatabaseKind::Sqlite) => "DATETIME".to_string(),
            (Self::Date, _) => "DATE".to_string(),
            (Self::Time { timezone }, DatabaseKind::Postgresql) => {
                if *timezone {
                    "TIME WITH TIME ZONE".to_string()
                } else {
                    "TIME WITHOUT TIME ZONE".to_string()
                }
            }
            (Self::Time { .. }, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "TIME".to_string(),
            (Self::Enum { values, .. }, DatabaseKind::Mysql) if !values.is_empty() => {
                let quoted = values
                    .iter()
                    .map(|v| format!("'{}'", v.replace('\'', "''")))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("ENUM({quoted})")
            }
            (Self::Enum { values, .. }, _) => {
                let max_len = values.iter().map(String::len).max().unwrap_or(64).max(16);
                format!("VARCHAR({max_len})")
            }
            (Self::Custom { raw }, _) => raw.clone(),
        }
    }

    /// Render a SQLAlchemy type expression suitable for Alembic migration templates.
    #[must_use]
    pub fn alembic_type_expr(&self) -> String {
        match self {
            Self::Varchar { length: Some(len) } => format!("sa.String(length={len})"),
            Self::Varchar { length: None } => "sa.String()".to_string(),
            Self::Char { length: Some(len) } => format!("sa.CHAR(length={len})"),
            Self::Char { length: None } => "sa.CHAR()".to_string(),
            Self::Text => "sa.Text()".to_string(),
            Self::MediumText => {
                "sa.Text().with_variant(sa.dialects.mysql.MEDIUMTEXT(), \"mysql\")".to_string()
            }
            Self::LongText => {
                "sa.Text().with_variant(sa.dialects.mysql.LONGTEXT(), \"mysql\")".to_string()
            }
            Self::SmallInt => "sa.SmallInteger()".to_string(),
            Self::Integer | Self::Serial => "sa.Integer()".to_string(),
            Self::BigInt | Self::BigSerial => "sa.BigInteger()".to_string(),
            Self::SqliteIntElseBigInt => {
                "sa.BigInteger().with_variant(sa.Integer(), \"sqlite\")".to_string()
            }
            Self::Float => "sa.Float()".to_string(),
            Self::Double => "sa.Double()".to_string(),
            Self::Numeric { precision, scale } => match (precision, scale) {
                (Some(p), Some(s)) => format!("sa.Numeric(precision={p}, scale={s})"),
                (Some(p), None) => format!("sa.Numeric(precision={p})"),
                _ => "sa.Numeric()".to_string(),
            },
            Self::Boolean => "sa.Boolean()".to_string(),
            Self::Uuid => "sa.Uuid()".to_string(),
            Self::Json => "sa.JSON()".to_string(),
            Self::Jsonb => "sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), \"postgresql\")".to_string(),
            Self::Blob => "sa.LargeBinary()".to_string(),
            Self::FixedBinary { length } => match length {
                Some(len) => format!(
                    "sa.LargeBinary(length={len}).with_variant(sa.dialects.mysql.BINARY({len}), \"mysql\")"
                ),
                None => "sa.LargeBinary()".to_string(),
            },
            Self::VarBinary { length } => match length {
                Some(len) => format!("sa.LargeBinary(length={len})"),
                None => "sa.LargeBinary()".to_string(),
            },
            Self::DateTime { timezone } => {
                if *timezone {
                    "sa.DateTime(timezone=True)".to_string()
                } else {
                    "sa.DateTime()".to_string()
                }
            }
            Self::Date => "sa.Date()".to_string(),
            Self::Time { timezone } => {
                if *timezone {
                    "sa.Time(timezone=True)".to_string()
                } else {
                    "sa.Time()".to_string()
                }
            }
            Self::Enum { name, values } => {
                let vals = values
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Some(name) = name {
                    format!("sa.Enum({vals}, name={name:?})")
                } else {
                    format!("sa.Enum({vals})")
                }
            }
            Self::Custom { raw } => format!("sa.Text()  # custom: {raw}"),
        }
    }

    #[must_use]
    fn capacity_rank(&self) -> Option<(u8, u64)> {
        match self {
            Self::Char { length: Some(l) } | Self::Varchar { length: Some(l) } => {
                Some((1, u64::from(*l)))
            }
            Self::Text | Self::Varchar { length: None } => Some((1, 65_535)),
            Self::MediumText => Some((1, 16_777_215)),
            Self::LongText => Some((1, 4_294_967_295)),
            Self::SmallInt => Some((2, 16)),
            Self::Integer | Self::Serial => Some((2, 32)),
            Self::BigInt | Self::BigSerial | Self::SqliteIntElseBigInt => Some((2, 64)),
            Self::Float => Some((3, 32)),
            Self::Double => Some((3, 64)),
            Self::FixedBinary { length: Some(l) } | Self::VarBinary { length: Some(l) } => {
                Some((4, u64::from(*l)))
            }
            Self::Blob => Some((4, 65_535)),
            _ => None,
        }
    }

    /// Compare two canonical types for compatibility, widening, or narrowing.
    #[must_use]
    pub fn classify_transition(&self, target: &Self) -> TypeCompatibility {
        if self == target {
            return TypeCompatibility::Exact;
        }
        match (self, target) {
            (
                Self::Serial | Self::Integer,
                Self::Serial | Self::Integer,
            )
            | (
                Self::BigSerial | Self::BigInt | Self::SqliteIntElseBigInt,
                Self::BigSerial | Self::BigInt | Self::SqliteIntElseBigInt,
            )
            | (Self::Json, Self::Jsonb) => return TypeCompatibility::Widening,
            (Self::Jsonb, Self::Json) => return TypeCompatibility::Narrowing,
            _ => {}
        }
        if let (Some((g1, r1)), Some((g2, r2))) = (self.capacity_rank(), target.capacity_rank())
            && g1 == g2
        {
            return match r1.cmp(&r2) {
                std::cmp::Ordering::Less => TypeCompatibility::Widening,
                std::cmp::Ordering::Greater => TypeCompatibility::Narrowing,
                std::cmp::Ordering::Equal => {
                    if self.family() == target.family() {
                        TypeCompatibility::Widening
                    } else {
                        TypeCompatibility::CompatibleCrossFamily
                    }
                }
            };
        }
        if let (
            Self::Numeric {
                precision: Some(p1),
                scale: s1,
            },
            Self::Numeric {
                precision: Some(p2),
                scale: s2,
            },
        ) = (self, target)
        {
            let s1 = s1.unwrap_or(0);
            let s2 = s2.unwrap_or(0);
            if p2 >= p1 && s2 >= s1 {
                return TypeCompatibility::Widening;
            }
            return TypeCompatibility::Narrowing;
        }

        let f1 = self.family();
        let f2 = target.family();
        if f1 == f2 {
            return TypeCompatibility::Widening;
        }

        match (self, target) {
            (Self::Char { length: Some(32 | 36) }, Self::Uuid)
            | (Self::Uuid, Self::Char { length: Some(32 | 36) } | Self::Varchar { .. } | Self::Text)
            | (Self::FixedBinary { length: Some(16) }, Self::Uuid)
            | (Self::Uuid, Self::FixedBinary { length: Some(16) })
            | (Self::Text | Self::LongText | Self::Varchar { .. }, Self::Json | Self::Jsonb)
            | (Self::Json | Self::Jsonb, Self::Text | Self::LongText | Self::Varchar { .. })
            | (Self::Integer | Self::SmallInt | Self::BigInt, Self::Float | Self::Double | Self::Numeric { .. })
            | (Self::Date, Self::DateTime { .. })
            | (Self::Enum { .. }, Self::Varchar { .. } | Self::Text)
            | (Self::Varchar { .. }, Self::Enum { .. }) => TypeCompatibility::CompatibleCrossFamily,
            _ => TypeCompatibility::Incompatible,
        }
    }

    /// Return a human-readable narrowing reason when changing `self` -> `target` risks data truncation.
    #[must_use]
    pub fn narrowing_reason(&self, target: &Self) -> Option<String> {
        if self.classify_transition(target) != TypeCompatibility::Narrowing {
            return None;
        }
        Some(format!(
            "Type transition {:?} -> {:?} may truncate or lose precision",
            self.ddl_type(DatabaseKind::Postgresql),
            target.ddl_type(DatabaseKind::Postgresql)
        ))
    }

    /// Semantic equality, optionally normalizing dialect storage aliases (e.g., SQLite `Uuid` == `CHAR(32)`).
    #[must_use]
    pub fn semantic_eq(&self, other: &Self, dialect: Option<DatabaseKind>) -> bool {
        if self == other {
            return true;
        }
        let Some(kind) = dialect else {
            return false;
        };
        let norm = |ty: &Self| -> String {
            match (ty, kind) {
                (Self::Serial | Self::BigSerial | Self::SqliteIntElseBigInt, DatabaseKind::Sqlite) => {
                    "INTEGER".to_string()
                }
                (Self::BigInt | Self::SmallInt, DatabaseKind::Sqlite) => "INTEGER".to_string(),
                (Self::Uuid, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "CHAR(32)".to_string(),
                (Self::Blob | Self::FixedBinary { .. } | Self::VarBinary { .. }, DatabaseKind::Sqlite) => {
                    "BLOB".to_string()
                }
                (Self::Blob | Self::FixedBinary { .. } | Self::VarBinary { .. }, DatabaseKind::Postgresql) => {
                    "BYTEA".to_string()
                }
                (Self::Boolean, DatabaseKind::Mysql | DatabaseKind::Sqlite) => "BOOLEAN".to_string(),
                (Self::DateTime { .. }, DatabaseKind::Sqlite | DatabaseKind::Mysql) => {
                    "DATETIME".to_string()
                }
                (Self::Jsonb, DatabaseKind::Sqlite | DatabaseKind::Mysql) => "JSON".to_string(),
                _ => ty.ddl_type(kind).to_ascii_uppercase(),
            }
        };
        norm(self) == norm(other)
    }
}

/// Normalized server-side column `DEFAULT` value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerDefaultIr {
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
    },
    Number {
        raw: String,
    },
    String {
        value: String,
    },
    CurrentTimestamp,
    Expression {
        raw: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        dialect_expressions: BTreeMap<DatabaseKind, String>,
    },
}

impl ServerDefaultIr {
    /// Render the `DEFAULT ...` clause fragment for the target database dialect.
    #[must_use]
    pub fn render_clause(&self, kind: DatabaseKind) -> String {
        format!("DEFAULT {}", self.render_expr(kind))
    }

    /// Render the expression after `DEFAULT `.
    #[must_use]
    pub fn render_expr(&self, kind: DatabaseKind) -> String {
        match (self, kind) {
            (Self::Boolean { value: false }, DatabaseKind::Sqlite) => "0".to_string(),
            (Self::Boolean { value: true }, DatabaseKind::Sqlite) => "1".to_string(),
            (Self::Boolean { value: false }, DatabaseKind::Mysql | DatabaseKind::Postgresql) => {
                "false".to_string()
            }
            (Self::Boolean { value: true }, DatabaseKind::Mysql | DatabaseKind::Postgresql) => {
                "true".to_string()
            }
            (Self::Integer { value }, _) => value.to_string(),
            (Self::Number { raw }, _) => raw.clone(),
            (Self::String { value }, _) => format!("'{}'", value.replace('\'', "''")),
            (Self::CurrentTimestamp, _) => "CURRENT_TIMESTAMP".to_string(),
            (
                Self::Expression {
                    raw,
                    dialect_expressions,
                },
                k,
            ) => dialect_expressions.get(&k).cloned().unwrap_or_else(|| raw.clone()),
        }
    }

    /// Render Alembic `server_default=...` argument.
    #[must_use]
    pub fn alembic_server_default(&self) -> String {
        match self {
            Self::Boolean { value } => {
                if *value {
                    "sa.text(\"true\")".to_string()
                } else {
                    "sa.text(\"false\")".to_string()
                }
            }
            Self::Integer { value } => format!("sa.text(\"{value}\")"),
            Self::Number { raw } => format!("sa.text({raw:?})"),
            Self::String { value } => {
                let sql_lit = format!("'{}'", value.replace('\'', "''"));
                format!("sa.text({sql_lit:?})")
            }
            Self::CurrentTimestamp => "sa.text(\"CURRENT_TIMESTAMP\")".to_string(),
            Self::Expression { raw, .. } => format!("sa.text({raw:?})"),
        }
    }

    /// Dialect-aware semantic equality (e.g., `0` == `false` for booleans, ignoring outer parens).
    #[must_use]
    pub fn semantic_eq(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }
        fn normalize(d: &ServerDefaultIr) -> String {
            match d {
                ServerDefaultIr::Boolean { value: false } | ServerDefaultIr::Integer { value: 0 } => {
                    "bool_false_or_0".to_string()
                }
                ServerDefaultIr::Boolean { value: true } | ServerDefaultIr::Integer { value: 1 } => {
                    "bool_true_or_1".to_string()
                }
                ServerDefaultIr::Integer { value } => value.to_string(),
                ServerDefaultIr::Number { raw } => raw.trim().to_string(),
                ServerDefaultIr::String { value } => format!("'{}'", value),
                ServerDefaultIr::CurrentTimestamp => "CURRENT_TIMESTAMP".to_string(),
                ServerDefaultIr::Expression { raw, .. } => {
                    let t = raw.trim();
                    let stripped = t
                        .strip_prefix('(')
                        .and_then(|s| s.strip_suffix(')'))
                        .unwrap_or(t)
                        .trim();
                    let lower = stripped.to_ascii_lowercase();
                    if lower == "false" || lower == "0" || lower == "(0)" {
                        "bool_false_or_0".to_string()
                    } else if lower == "true" || lower == "1" || lower == "(1)" {
                        "bool_true_or_1".to_string()
                    } else if lower == "current_timestamp" || lower == "current_timestamp()" || lower == "now()" {
                        "CURRENT_TIMESTAMP".to_string()
                    } else {
                        stripped.to_string()
                    }
                }
            }
        }
        normalize(self) == normalize(other)
    }
}

/// Generated/computed column expression metadata (`GENERATED ALWAYS AS (...) STORED|VIRTUAL`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputedColumnIr {
    pub expression: String,
    #[serde(default = "default_true")]
    pub persisted: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_expressions: BTreeMap<DatabaseKind, String>,
}

impl ComputedColumnIr {
    #[must_use]
    pub fn expr_for(&self, kind: DatabaseKind) -> &str {
        self.dialect_expressions
            .get(&kind)
            .map(String::as_str)
            .unwrap_or(&self.expression)
    }

    #[must_use]
    pub fn storage_keyword(&self) -> &'static str {
        if self.persisted { "STORED" } else { "VIRTUAL" }
    }
}

const fn default_true() -> bool {
    true
}

/// Declarative column IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnIr {
    pub name: String,
    pub ordinal: usize,
    pub canonical_type: CanonicalType,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_types: BTreeMap<DatabaseKind, String>,
    pub nullable: bool,
    #[serde(default)]
    pub autoincrement: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_default: Option<ServerDefaultIr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed: Option<ComputedColumnIr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default)]
    pub confidence: ConfidenceLevel,
}

impl ColumnIr {
    /// Render dialect SQL type string for this column.
    #[must_use]
    pub fn render_ddl_type(&self, kind: DatabaseKind) -> String {
        if let CanonicalType::Custom { .. } = &self.canonical_type
            && let Some(explicit) = self.dialect_types.get(&kind)
        {
            return explicit.clone();
        }
        self.canonical_type.ddl_type(kind)
    }

    /// Compile the column definition fragment inside `CREATE TABLE` or `ADD COLUMN`.
    #[must_use]
    pub fn compile_definition_sql(&self, kind: DatabaseKind) -> String {
        let mut clause = format!("{} ", quote_ident_if_needed(&self.name, kind));
        if let Some(computed) = &self.computed {
            clause.push_str(&self.render_ddl_type(kind));
            clause.push_str(" GENERATED ALWAYS AS (");
            clause.push_str(computed.expr_for(kind));
            clause.push_str(") ");
            clause.push_str(computed.storage_keyword());
        } else if kind == DatabaseKind::Mysql && self.canonical_type.is_serial() {
            clause.push_str(&self.render_ddl_type(kind));
        } else {
            clause.push_str(&self.render_ddl_type(kind));
            match kind {
                DatabaseKind::Mysql => {
                    if !self.nullable {
                        clause.push_str(" NOT NULL");
                    }
                    if let Some(def) = &self.server_default {
                        clause.push(' ');
                        clause.push_str(&def.render_clause(kind));
                    }
                }
                DatabaseKind::Sqlite | DatabaseKind::Postgresql => {
                    if let Some(def) = &self.server_default {
                        clause.push(' ');
                        clause.push_str(&def.render_clause(kind));
                    }
                    if !self.nullable {
                        clause.push_str(" NOT NULL");
                    }
                }
            }
        }
        if kind == DatabaseKind::Mysql
            && let Some(comment) = &self.comment
        {
            let escaped = comment.replace('\'', "''");
            clause.push_str(&format!(" COMMENT '{escaped}'"));
        }
        clause
    }
}

/// Primary key constraint IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrimaryKeyIr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_names: BTreeMap<DatabaseKind, String>,
    pub columns: Vec<String>,
}

impl PrimaryKeyIr {
    #[must_use]
    pub fn effective_name(&self, table_name: &str, kind: DatabaseKind) -> String {
        self.dialect_names
            .get(&kind)
            .cloned()
            .or_else(|| self.name.clone())
            .unwrap_or_else(|| format!("pk_{table_name}"))
    }
}

/// Referential action on foreign key delete / update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReferentialAction {
    #[default]
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

impl ReferentialAction {
    #[must_use]
    pub const fn on_delete_sql(self) -> &'static str {
        match self {
            Self::NoAction => "",
            Self::Restrict => " ON DELETE RESTRICT",
            Self::Cascade => " ON DELETE CASCADE",
            Self::SetNull => " ON DELETE SET NULL",
            Self::SetDefault => " ON DELETE SET DEFAULT",
        }
    }

    #[must_use]
    pub const fn on_update_sql(self) -> &'static str {
        match self {
            Self::NoAction => "",
            Self::Restrict => " ON UPDATE RESTRICT",
            Self::Cascade => " ON UPDATE CASCADE",
            Self::SetNull => " ON UPDATE SET NULL",
            Self::SetDefault => " ON UPDATE SET DEFAULT",
        }
    }

    #[must_use]
    pub const fn alembic_str(self) -> Option<&'static str> {
        match self {
            Self::NoAction => None,
            Self::Restrict => Some("RESTRICT"),
            Self::Cascade => Some("CASCADE"),
            Self::SetNull => Some("SET NULL"),
            Self::SetDefault => Some("SET DEFAULT"),
        }
    }

    #[must_use]
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "" | "NO ACTION" => None,
            "RESTRICT" => Some(Self::Restrict),
            "CASCADE" => Some(Self::Cascade),
            "SET NULL" => Some(Self::SetNull),
            "SET DEFAULT" => Some(Self::SetDefault),
            _ => None,
        }
    }
}

/// Foreign key constraint IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKeyIr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_names: BTreeMap<DatabaseKind, String>,
    pub columns: Vec<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_delete: Option<ReferentialAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_update: Option<ReferentialAction>,
    #[serde(default)]
    pub defer_on_create: bool,
}

impl ForeignKeyIr {
    #[must_use]
    pub fn effective_name(&self, table_name: &str, kind: DatabaseKind) -> String {
        if let Some(n) = self.dialect_names.get(&kind) {
            return n.clone();
        }
        if let Some(n) = &self.name {
            return n.clone();
        }
        let col0 = self.columns.first().map_or("col", String::as_str);
        format!("fk_{}_{}_{}", table_name, col0, self.ref_table)
    }

    /// Structural signature used for comparing foreign keys across naming conventions.
    #[must_use]
    pub fn structural_signature(&self) -> (Vec<String>, String, Vec<String>, Option<ReferentialAction>) {
        let normalized_on_delete = match self.on_delete {
            Some(ReferentialAction::NoAction | ReferentialAction::Restrict) | None => None,
            other => other,
        };
        (
            self.columns.clone(),
            self.ref_table.clone(),
            self.ref_columns.clone(),
            normalized_on_delete,
        )
    }

    #[must_use]
    pub fn constraint_sql(&self, table_name: &str, kind: DatabaseKind) -> String {
        let name = self.effective_name(table_name, kind);
        let cols = self
            .columns
            .iter()
            .map(|c| quote_ident_if_needed(c, kind))
            .collect::<Vec<_>>()
            .join(", ");
        let ref_cols = self
            .ref_columns
            .iter()
            .map(|c| quote_ident_if_needed(c, kind))
            .collect::<Vec<_>>()
            .join(", ");
        let on_del = self.on_delete.map_or("", ReferentialAction::on_delete_sql);
        let on_upd = self.on_update.map_or("", ReferentialAction::on_update_sql);
        format!(
            "CONSTRAINT {} FOREIGN KEY({}) REFERENCES {} ({}){}{}",
            quote_ident_if_needed(&name, kind),
            cols,
            quote_ident_if_needed(&self.ref_table, kind),
            ref_cols,
            on_del,
            on_upd
        )
    }
}

/// Unique constraint IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniqueIr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_names: BTreeMap<DatabaseKind, String>,
    pub columns: Vec<String>,
}

impl UniqueIr {
    #[must_use]
    pub fn effective_name(&self, table_name: &str, kind: DatabaseKind) -> String {
        if let Some(n) = self.dialect_names.get(&kind) {
            return n.clone();
        }
        if let Some(n) = &self.name {
            return n.clone();
        }
        let col0 = self.columns.first().map_or("col", String::as_str);
        format!("uq_{table_name}_{col0}")
    }
}

/// Check constraint IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckIr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_names: BTreeMap<DatabaseKind, String>,
    pub expression: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_expressions: BTreeMap<DatabaseKind, String>,
}

impl CheckIr {
    #[must_use]
    pub fn effective_name(&self, table_name: &str, kind: DatabaseKind) -> String {
        if let Some(n) = self.dialect_names.get(&kind) {
            return n.clone();
        }
        if let Some(n) = &self.name {
            return n.clone();
        }
        format!("ck_{table_name}")
    }

    #[must_use]
    pub fn expr_for(&self, kind: DatabaseKind) -> &str {
        self.dialect_expressions
            .get(&kind)
            .map(String::as_str)
            .unwrap_or(&self.expression)
    }
}

/// Index IR (supporting simple columns, composite indexes, and dialect functional expressions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexIr {
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_names: BTreeMap<DatabaseKind, String>,
    #[serde(default)]
    pub unique: bool,
    pub expressions: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dialect_clauses: BTreeMap<DatabaseKind, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub where_clause: Option<String>,
}

impl IndexIr {
    #[must_use]
    pub fn effective_name(&self, kind: DatabaseKind) -> &str {
        self.dialect_names
            .get(&kind)
            .map(String::as_str)
            .unwrap_or(&self.name)
    }

    /// Format the column / expression list inside `ON table (...)`.
    #[must_use]
    pub fn clause_for(&self, kind: DatabaseKind) -> String {
        if let Some(explicit) = self.dialect_clauses.get(&kind) {
            return explicit.clone();
        }
        self.expressions
            .iter()
            .map(|expr| {
                let t = expr.trim();
                if kind == DatabaseKind::Mysql && t.contains('(') && !t.starts_with('(') {
                    format!("({t})")
                } else {
                    t.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[must_use]
    pub fn create_sql(&self, kind: DatabaseKind, table_name: &str) -> String {
        let prefix = if self.unique {
            "CREATE UNIQUE INDEX"
        } else {
            "CREATE INDEX"
        };
        let base = format!(
            "{prefix} {} ON {} ({})",
            quote_ident_if_needed(self.effective_name(kind), kind),
            quote_ident_if_needed(table_name, kind),
            self.clause_for(kind)
        );
        match (&self.where_clause, kind) {
            (Some(w), DatabaseKind::Sqlite | DatabaseKind::Postgresql) if !w.trim().is_empty() => {
                format!("{base} WHERE {w}")
            }
            _ => base,
        }
    }
}

/// Complete declarative table IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableIr {
    pub name: String,
    #[serde(default)]
    pub ownership: TableOwnership,
    pub columns: Vec<ColumnIr>,
    #[serde(default)]
    pub primary_key: PrimaryKeyIr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub foreign_keys: Vec<ForeignKeyIr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uniques: Vec<UniqueIr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckIr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indexes: Vec<IndexIr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default)]
    pub confidence: ConfidenceLevel,
}

impl TableIr {
    /// Columns that can be selected and inserted directly (excludes generated computed columns).
    pub fn data_columns(&self) -> impl Iterator<Item = &ColumnIr> {
        self.columns.iter().filter(|col| col.computed.is_none())
    }

    #[must_use]
    pub fn column(&self, name: &str) -> Option<&ColumnIr> {
        self.columns.iter().find(|c| c.name == name)
    }

    /// Ensure columns are ordered deterministically by declaration `ordinal` (then `name`).
    pub fn sort_columns_by_ordinal(&mut self) {
        self.columns
            .sort_by(|a, b| a.ordinal.cmp(&b.ordinal).then_with(|| a.name.cmp(&b.name)));
    }

    /// Compile `CREATE TABLE` DDL for `kind`.
    ///
    /// When `deferred_fk_names` is `Some(set)`, foreign keys whose `effective_name` (in `kind`)
    /// is in `set` are omitted from inline creation on MySQL/PostgreSQL so they can be added in
    /// the post-creation `ALTER TABLE` phase.
    #[must_use]
    pub fn compile_create_table(
        &self,
        kind: DatabaseKind,
        deferred_fk_names: Option<&BTreeSet<String>>,
    ) -> String {
        let mut items = Vec::with_capacity(self.columns.len() + 8);
        for col in &self.columns {
            items.push(format!("\t{}", col.compile_definition_sql(kind)));
        }

        if !self.primary_key.columns.is_empty() {
            let pk_name = self.primary_key.effective_name(&self.name, kind);
            let pk_cols = self
                .primary_key
                .columns
                .iter()
                .map(|c| quote_ident_if_needed(c, kind))
                .collect::<Vec<_>>()
                .join(", ");
            items.push(format!(
                "\tCONSTRAINT {} PRIMARY KEY ({pk_cols})",
                quote_ident_if_needed(&pk_name, kind)
            ));
        }

        for ck in &self.checks {
            let ck_name = ck.effective_name(&self.name, kind);
            items.push(format!(
                "\tCONSTRAINT {} CHECK ({})",
                quote_ident_if_needed(&ck_name, kind),
                ck.expr_for(kind)
            ));
        }

        for uq in &self.uniques {
            let uq_name = uq.effective_name(&self.name, kind);
            let cols = uq
                .columns
                .iter()
                .map(|c| quote_ident_if_needed(c, kind))
                .collect::<Vec<_>>()
                .join(", ");
            items.push(format!(
                "\tCONSTRAINT {} UNIQUE ({cols})",
                quote_ident_if_needed(&uq_name, kind)
            ));
        }

        for fk in &self.foreign_keys {
            let fk_name = fk.effective_name(&self.name, kind);
            let is_deferred = if kind == DatabaseKind::Sqlite {
                false
            } else if let Some(set) = deferred_fk_names {
                set.contains(&fk_name)
            } else {
                fk.defer_on_create
            };
            if !is_deferred {
                items.push(format!("\t{}", fk.constraint_sql(&self.name, kind)));
            }
        }

        format!(
            "CREATE TABLE {} (\n{}\n)",
            quote_ident_if_needed(&self.name, kind),
            items.join(", \n")
        )
    }

    /// Compile index creation SQL statements (and PostgreSQL column comments) for `self`.
    #[must_use]
    pub fn compile_create_indexes(&self, kind: DatabaseKind) -> Vec<String> {
        let mut stmts: Vec<String> = self
            .indexes
            .iter()
            .map(|idx| idx.create_sql(kind, &self.name))
            .collect();
        if kind == DatabaseKind::Postgresql {
            for col in &self.columns {
                if let Some(comment) = &col.comment {
                    let escaped = comment.replace('\'', "''");
                    stmts.push(format!(
                        "COMMENT ON COLUMN {}.{} IS '{escaped}'",
                        quote_ident_if_needed(&self.name, kind),
                        quote_ident_if_needed(&col.name, kind)
                    ));
                }
            }
        }
        stmts
    }

    /// Compile deferred `ALTER TABLE ... ADD CONSTRAINT` statements (MySQL / PostgreSQL only).
    #[must_use]
    pub fn compile_deferred_foreign_keys(
        &self,
        kind: DatabaseKind,
        deferred_fk_names: Option<&BTreeSet<String>>,
    ) -> Vec<String> {
        if kind == DatabaseKind::Sqlite {
            return Vec::new();
        }
        self.foreign_keys
            .iter()
            .filter(|fk| {
                if let Some(set) = deferred_fk_names {
                    set.contains(&fk.effective_name(&self.name, kind))
                } else {
                    fk.defer_on_create
                }
            })
            .map(|fk| {
                format!(
                    "ALTER TABLE {} ADD {}",
                    quote_ident_if_needed(&self.name, kind),
                    fk.constraint_sql(&self.name, kind)
                )
            })
            .collect()
    }
}

/// Complete extracted schema IR for a target codebase, pre-exported JSON, or live database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaIr {
    pub ir_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_revision: Option<String>,
    pub source: ExtractionSource,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub naming_convention: BTreeMap<String, String>,
    pub tables: BTreeMap<String, TableIr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl SchemaIr {
    /// Standard CFMS SQLAlchemy `MetaData(naming_convention=...)`.
    #[must_use]
    pub fn default_cfms_naming_convention() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("ix".to_string(), "ix_%(column_0_label)s".to_string()),
            ("uq".to_string(), "uq_%(table_name)s_%(column_0_name)s".to_string()),
            ("ck".to_string(), "ck_%(table_name)s_%(column_0_name)s".to_string()),
            (
                "fk".to_string(),
                "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s".to_string(),
            ),
            ("pk".to_string(), "pk_%(table_name)s".to_string()),
        ])
    }

    #[must_use]
    pub fn new(source: ExtractionSource, schema_revision: Option<String>) -> Self {
        Self {
            ir_version: SCHEMA_IR_VERSION,
            schema_revision,
            source,
            naming_convention: Self::default_cfms_naming_convention(),
            tables: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub fn core_table_names(&self) -> BTreeSet<String> {
        self.tables
            .values()
            .filter(|t| !t.ownership.is_extension())
            .map(|t| t.name.clone())
            .collect()
    }

    #[must_use]
    pub fn extension_table_names(&self) -> BTreeSet<String> {
        self.tables
            .values()
            .filter(|t| t.ownership.is_extension())
            .map(|t| t.name.clone())
            .collect()
    }

    /// Return a cloned `SchemaIr` excluding extension tables when `include_extensions` is `false`.
    #[must_use]
    pub fn with_extensions(&self, include_extensions: bool) -> Self {
        if include_extensions {
            return self.clone();
        }
        let mut cloned = self.clone();
        cloned.tables.retain(|_, t| !t.ownership.is_extension());
        cloned
    }

    pub fn to_pretty_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CfmsError::Database(format!("Failed to serialize SchemaIr: {e}")))
    }

    pub fn from_json_str(raw: &str) -> Result<Self> {
        let ir: Self = serde_json::from_str(raw)
            .map_err(|e| CfmsError::Database(format!("Failed to parse SchemaIr JSON: {e}")))?;
        if ir.ir_version != SCHEMA_IR_VERSION {
            return Err(CfmsError::Database(format!(
                "Unsupported schema IR version {} (expected {SCHEMA_IR_VERSION})",
                ir.ir_version
            )));
        }
        Ok(ir)
    }
}

/// Quote SQL identifiers only when required (reserved keywords or non-identifier characters),
/// keeping canonical snake_case identifiers unquoted for clean dialect SQL.
#[must_use]
pub fn quote_ident_if_needed(ident: &str, kind: DatabaseKind) -> Cow<'_, str> {
    if !needs_quoting(ident) {
        return Cow::Borrowed(ident);
    }
    match kind {
        DatabaseKind::Mysql => Cow::Owned(format!("`{}`", ident.replace('`', "``"))),
        DatabaseKind::Sqlite | DatabaseKind::Postgresql => {
            Cow::Owned(format!("\"{}\"", ident.replace('"', "\"\"")))
        }
    }
}

fn needs_quoting(ident: &str) -> bool {
    let mut chars = ident.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return true;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return true;
    }
    matches!(
        ident.to_ascii_lowercase().as_str(),
        "all"
            | "alter"
            | "and"
            | "as"
            | "asc"
            | "between"
            | "by"
            | "case"
            | "check"
            | "column"
            | "constraint"
            | "create"
            | "default"
            | "delete"
            | "desc"
            | "distinct"
            | "drop"
            | "else"
            | "end"
            | "exists"
            | "false"
            | "foreign"
            | "from"
            | "full"
            | "group"
            | "having"
            | "in"
            | "index"
            | "inner"
            | "insert"
            | "into"
            | "is"
            | "join"
            | "key"
            | "left"
            | "like"
            | "limit"
            | "not"
            | "null"
            | "offset"
            | "on"
            | "or"
            | "order"
            | "outer"
            | "primary"
            | "references"
            | "right"
            | "select"
            | "set"
            | "table"
            | "then"
            | "to"
            | "true"
            | "union"
            | "unique"
            | "update"
            | "user"
            | "using"
            | "values"
            | "when"
            | "where"
    )
}
