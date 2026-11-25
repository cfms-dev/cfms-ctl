//! Dialect-accurate declarative DDL and schema metadata for SQLite, MySQL, and PostgreSQL.
//!
//! Matches SQLAlchemy `Base.metadata` (`create_all`) and `user_oidc_credentials`
//! column types, constraint names, generated columns, and functional indexes.

use std::collections::BTreeMap;

use sqlx::Acquire;
use crate::core::error::Result;
use crate::db::backend::{DatabaseKind, DbPool};
use crate::db::schema::ir::{
    CanonicalType, CheckIr, ColumnIr, ComputedColumnIr, ConfidenceLevel, ExtractionSource,
    ForeignKeyIr, IndexIr, PrimaryKeyIr, ReferentialAction, SchemaIr, ServerDefaultIr, TableIr,
    TableOwnership, UniqueIr,
};
use crate::db::schema::registry::{KNOWN_EXTENSION_TABLES, LATEST_SCHEMA_REVISION};

/// Canonical column semantic data type across SQLite, MySQL, and PostgreSQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Varchar(u16),
    Text,
    LongText,
    SmallInt,
    Integer,
    BigInt,
    SqliteIntElseBigInt,
    Serial,
    BigSerial,
    Double,
    Boolean,
    Uuid,
    Json,
    Blob,
    FixedBinary32,
}

impl From<ColumnType> for CanonicalType {
    fn from(ct: ColumnType) -> Self {
        match ct {
            ColumnType::Varchar(len) => Self::Varchar {
                length: Some(u32::from(len)),
            },
            ColumnType::Text => Self::Text,
            ColumnType::LongText => Self::LongText,
            ColumnType::SmallInt => Self::SmallInt,
            ColumnType::Integer => Self::Integer,
            ColumnType::BigInt => Self::BigInt,
            ColumnType::SqliteIntElseBigInt => Self::SqliteIntElseBigInt,
            ColumnType::Serial => Self::Serial,
            ColumnType::BigSerial => Self::BigSerial,
            ColumnType::Double => Self::Double,
            ColumnType::Boolean => Self::Boolean,
            ColumnType::Uuid => Self::Uuid,
            ColumnType::Json => Self::Json,
            ColumnType::Blob => Self::Blob,
            ColumnType::FixedBinary32 => Self::FixedBinary { length: Some(32) },
        }
    }
}

impl ColumnType {
    /// Render the exact dialect DDL column type.
    #[must_use]
    pub fn ddl_type(self, kind: DatabaseKind) -> String {
        CanonicalType::from(self).ddl_type(kind)
    }

    #[must_use]
    pub const fn is_serial(self) -> bool {
        matches!(self, Self::Serial | Self::BigSerial)
    }
}

/// Optional dialect-specific SQL fragments for column metadata.
#[derive(Debug, Clone, Copy)]
pub enum DefaultClause {
    None,
    BooleanFalse,
}

impl DefaultClause {
    #[must_use]
    pub const fn render(self, kind: DatabaseKind) -> Option<&'static str> {
        match (self, kind) {
            (Self::None, _) => None,
            (Self::BooleanFalse, DatabaseKind::Sqlite) => Some("DEFAULT 0"),
            (Self::BooleanFalse, DatabaseKind::Mysql | DatabaseKind::Postgresql) => {
                Some("DEFAULT false")
            }
        }
    }
}

/// Column definition within a declarative schema table.
#[derive(Debug, Clone, Copy)]
pub struct ColumnDef {
    pub name: &'static str,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub default: DefaultClause,
    pub generated_expr: Option<&'static str>,
    pub comment: Option<&'static str>,
}

impl ColumnDef {
    const fn req(name: &'static str, col_type: ColumnType) -> Self {
        Self {
            name,
            col_type,
            nullable: false,
            default: DefaultClause::None,
            generated_expr: None,
            comment: None,
        }
    }

    const fn opt(name: &'static str, col_type: ColumnType) -> Self {
        Self {
            name,
            col_type,
            nullable: true,
            default: DefaultClause::None,
            generated_expr: None,
            comment: None,
        }
    }

    const fn default_false(name: &'static str) -> Self {
        Self {
            name,
            col_type: ColumnType::Boolean,
            nullable: false,
            default: DefaultClause::BooleanFalse,
            generated_expr: None,
            comment: None,
        }
    }

    const fn generated_stored(name: &'static str, col_type: ColumnType, expr: &'static str) -> Self {
        Self {
            name,
            col_type,
            nullable: true,
            default: DefaultClause::None,
            generated_expr: Some(expr),
            comment: None,
        }
    }

    const fn with_comment(mut self, comment: &'static str) -> Self {
        self.comment = Some(comment);
        self
    }
}

/// Foreign key referential action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnDelete {
    Restrict,
    Cascade,
    SetNull,
}

/// Foreign key constraint definition.
#[derive(Debug, Clone, Copy)]
pub struct ForeignKeyDef {
    pub name_sqlite: &'static str,
    pub name_mysql: &'static str,
    pub name_postgres: &'static str,
    pub column: &'static str,
    pub ref_table: &'static str,
    pub ref_column: &'static str,
    pub on_delete: OnDelete,
    /// Cyclic/alter FK emitted inline on SQLite, but deferred via `ALTER TABLE` on MySQL & PostgreSQL.
    pub cyclic_alter: bool,
}

impl ForeignKeyDef {
    const fn simple(
        name: &'static str,
        column: &'static str,
        ref_table: &'static str,
        ref_column: &'static str,
        on_delete: OnDelete,
    ) -> Self {
        Self {
            name_sqlite: name,
            name_mysql: name,
            name_postgres: name,
            column,
            ref_table,
            ref_column,
            on_delete,
            cyclic_alter: false,
        }
    }

    const fn cyclic(
        name: &'static str,
        column: &'static str,
        ref_table: &'static str,
        ref_column: &'static str,
        on_delete: OnDelete,
    ) -> Self {
        Self {
            name_sqlite: name,
            name_mysql: name,
            name_postgres: name,
            column,
            ref_table,
            ref_column,
            on_delete,
            cyclic_alter: true,
        }
    }
}

/// Unique constraint definition.
#[derive(Debug, Clone, Copy)]
pub struct UniqueDef {
    pub name: &'static str,
    pub columns: &'static [&'static str],
}

/// Check constraint definition.
#[derive(Debug, Clone, Copy)]
pub struct CheckDef {
    pub name: &'static str,
    pub expr: &'static str,
}

/// Index definition (with optional MySQL parenthesized functional expression variant).
#[derive(Debug, Clone, Copy)]
pub struct IndexDef {
    pub name: &'static str,
    pub unique: bool,
    pub cols_sqlite_pg: &'static str,
    pub cols_mysql: &'static str,
}

impl IndexDef {
    const fn normal(name: &'static str, cols: &'static str) -> Self {
        Self {
            name,
            unique: false,
            cols_sqlite_pg: cols,
            cols_mysql: cols,
        }
    }

    const fn unique_idx(name: &'static str, cols: &'static str) -> Self {
        Self {
            name,
            unique: true,
            cols_sqlite_pg: cols,
            cols_mysql: cols,
        }
    }

    const fn functional(
        name: &'static str,
        cols_sqlite_pg: &'static str,
        cols_mysql: &'static str,
    ) -> Self {
        Self {
            name,
            unique: false,
            cols_sqlite_pg,
            cols_mysql,
        }
    }
}

/// Complete declarative definition of a CFMS application/extension table.
#[derive(Debug, Clone, Copy)]
pub struct TableDef {
    pub name: &'static str,
    pub pk_name: &'static str,
    pub pk_columns: &'static [&'static str],
    pub columns: &'static [ColumnDef],
    pub checks: &'static [CheckDef],
    pub uniques: &'static [UniqueDef],
    pub foreign_keys: &'static [ForeignKeyDef],
    pub indexes: &'static [IndexDef],
}

impl TableDef {
    /// Columns that can be selected & inserted directly (excludes generated computed columns).
    pub fn data_columns(&self) -> impl Iterator<Item = &'static ColumnDef> {
        self.columns
            .iter()
            .filter(|col| col.generated_expr.is_none())
    }

    /// Convert this static `TableDef` into an owned `TableIr`.
    #[must_use]
    pub fn to_ir(&self, ownership: TableOwnership) -> TableIr {
        let columns = self
            .columns
            .iter()
            .enumerate()
            .map(|(ordinal, col)| ColumnIr {
                name: col.name.to_string(),
                ordinal,
                canonical_type: CanonicalType::from(col.col_type),
                dialect_types: BTreeMap::new(),
                nullable: col.nullable,
                autoincrement: col.col_type.is_serial(),
                server_default: match col.default {
                    DefaultClause::None => None,
                    DefaultClause::BooleanFalse => Some(ServerDefaultIr::Boolean { value: false }),
                },
                computed: col.generated_expr.map(|expr| ComputedColumnIr {
                    expression: expr.to_string(),
                    persisted: true,
                    dialect_expressions: BTreeMap::new(),
                }),
                comment: col.comment.map(ToString::to_string),
                confidence: ConfidenceLevel::High,
            })
            .collect();

        let foreign_keys = self
            .foreign_keys
            .iter()
            .map(|fk| {
                let mut dialect_names = BTreeMap::new();
                if fk.name_mysql != fk.name_sqlite {
                    dialect_names.insert(DatabaseKind::Mysql, fk.name_mysql.to_string());
                }
                if fk.name_postgres != fk.name_sqlite {
                    dialect_names.insert(DatabaseKind::Postgresql, fk.name_postgres.to_string());
                }
                ForeignKeyIr {
                    name: Some(fk.name_sqlite.to_string()),
                    dialect_names,
                    columns: vec![fk.column.to_string()],
                    ref_table: fk.ref_table.to_string(),
                    ref_columns: vec![fk.ref_column.to_string()],
                    on_delete: match fk.on_delete {
                        OnDelete::Restrict => None,
                        OnDelete::Cascade => Some(ReferentialAction::Cascade),
                        OnDelete::SetNull => Some(ReferentialAction::SetNull),
                    },
                    on_update: None,
                    defer_on_create: fk.cyclic_alter,
                }
            })
            .collect();

        let uniques = self
            .uniques
            .iter()
            .map(|uq| UniqueIr {
                name: Some(uq.name.to_string()),
                dialect_names: BTreeMap::new(),
                columns: uq.columns.iter().map(|s| (*s).to_string()).collect(),
            })
            .collect();

        let checks = self
            .checks
            .iter()
            .map(|ck| CheckIr {
                name: Some(ck.name.to_string()),
                dialect_names: BTreeMap::new(),
                expression: ck.expr.to_string(),
                dialect_expressions: BTreeMap::new(),
            })
            .collect();

        let indexes = self
            .indexes
            .iter()
            .map(|idx| {
                let mut dialect_clauses = BTreeMap::new();
                if idx.cols_mysql != idx.cols_sqlite_pg {
                    dialect_clauses.insert(DatabaseKind::Mysql, idx.cols_mysql.to_string());
                }
                IndexIr {
                    name: idx.name.to_string(),
                    dialect_names: BTreeMap::new(),
                    unique: idx.unique,
                    expressions: split_top_level_commas(idx.cols_sqlite_pg),
                    dialect_clauses,
                    where_clause: None,
                }
            })
            .collect();

        TableIr {
            name: self.name.to_string(),
            ownership,
            columns,
            primary_key: PrimaryKeyIr {
                name: Some(self.pk_name.to_string()),
                dialect_names: BTreeMap::new(),
                columns: self.pk_columns.iter().map(|s| (*s).to_string()).collect(),
            },
            foreign_keys,
            uniques,
            checks,
            indexes,
            comment: None,
            confidence: ConfidenceLevel::High,
        }
    }

    /// Compile `CREATE TABLE` SQL for the given dialect (inline cyclic FKs only on SQLite).
    #[must_use]
    pub fn compile_create_table(&self, kind: DatabaseKind) -> String {
        self.to_ir(TableOwnership::Core)
            .compile_create_table(kind, None)
    }

    /// Compile index creation SQL statements for the table.
    #[must_use]
    pub fn compile_create_indexes(&self, kind: DatabaseKind) -> Vec<String> {
        self.to_ir(TableOwnership::Core)
            .compile_create_indexes(kind)
    }

    /// Compile deferred cyclic `ALTER TABLE ... ADD CONSTRAINT` statements (MySQL / PostgreSQL only).
    #[must_use]
    pub fn compile_deferred_foreign_keys(&self, kind: DatabaseKind) -> Vec<String> {
        self.to_ir(TableOwnership::Core)
            .compile_deferred_foreign_keys(kind, None)
    }
}

fn split_top_level_commas(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let piece = input[start..idx].trim();
                if !piece.is_empty() {
                    parts.push(piece.to_string());
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        parts.push(tail.to_string());
    }
    parts
}

/// Declarative definitions of all 40 core tables in topological dependency order.
pub const CORE_TABLES: &[TableDef] = &[
    TableDef {
        name: "files",
        pk_name: "pk_files",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(255)),
            ColumnDef::opt("sha256", ColumnType::Varchar(64)),
            ColumnDef::req("path", ColumnType::Text),
            ColumnDef::opt("size", ColumnType::BigInt),
            ColumnDef::req("created_time", ColumnType::Double),
            ColumnDef::req("active", ColumnType::Boolean),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[IndexDef::normal(
            "ix_files_sha256_active_created_time_id",
            "sha256, active, created_time, id",
        )],
    },
    TableDef {
        name: "comments",
        pk_name: "pk_comments",
        pk_columns: &["comment_id"],
        columns: &[
            ColumnDef::req("comment_id", ColumnType::BigSerial),
            ColumnDef::req("digest_version", ColumnType::SmallInt),
            ColumnDef::req("content_digest", ColumnType::FixedBinary32),
            ColumnDef::req("comment_text", ColumnType::Text),
            ColumnDef::opt("comment_data", ColumnType::Json),
        ],
        checks: &[],
        uniques: &[UniqueDef {
            name: "uq_comments_content_digest",
            columns: &["digest_version", "content_digest"],
        }],
        foreign_keys: &[],
        indexes: &[],
    },
    TableDef {
        name: "users",
        pk_name: "pk_users",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Uuid),
            ColumnDef::req("username", ColumnType::Varchar(256)),
            ColumnDef::opt("nickname", ColumnType::Varchar(255)),
            ColumnDef::opt("avatar_id", ColumnType::Varchar(255)),
            ColumnDef::opt("last_login", ColumnType::Double),
            ColumnDef::req("created_time", ColumnType::Double),
            ColumnDef::req("status", ColumnType::Integer),
            ColumnDef::opt("status_comment_id", ColumnType::SqliteIntElseBigInt),
            ColumnDef::req("secret_key", ColumnType::Varchar(64)),
            ColumnDef::opt("preference_dek_id", ColumnType::Varchar(64)),
        ],
        checks: &[CheckDef {
            name: "ck_users_secret_key_nonempty",
            expr: "length(secret_key) > 0",
        }],
        uniques: &[UniqueDef {
            name: "uq_users_preference_dek_id",
            columns: &["preference_dek_id"],
        }],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_users_avatar_id_files",
                "avatar_id",
                "files",
                "id",
                OnDelete::Restrict,
            ),
            ForeignKeyDef::simple(
                "fk_users_status_comment_id_comments",
                "status_comment_id",
                "comments",
                "comment_id",
                OnDelete::SetNull,
            ),
            ForeignKeyDef::cyclic(
                "fk_users_preference_dek_id",
                "preference_dek_id",
                "keyrings",
                "id",
                OnDelete::SetNull,
            ),
        ],
        indexes: &[
            IndexDef::normal("ix_users_avatar_id", "avatar_id"),
            IndexDef::unique_idx("ix_users_username", "username"),
        ],
    },
    TableDef {
        name: "user_passwords",
        pk_name: "pk_user_passwords",
        pk_columns: &["user_id"],
        columns: &[
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("credential_id", ColumnType::Varchar(32)),
            ColumnDef::req("pass_hash", ColumnType::Text),
            ColumnDef::req("passwd_last_modified", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[UniqueDef {
            name: "uq_user_passwords_credential_id",
            columns: &["credential_id"],
        }],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_user_passwords_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[],
    },
    TableDef {
        name: "user_totp_credentials",
        pk_name: "pk_user_totp_credentials",
        pk_columns: &["user_id"],
        columns: &[
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("credential_id", ColumnType::Varchar(32)),
            ColumnDef::req("secret", ColumnType::Varchar(32)),
            ColumnDef::req("enabled", ColumnType::Boolean),
            ColumnDef::opt("backup_codes", ColumnType::Text),
            ColumnDef::req("created_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[UniqueDef {
            name: "uq_user_totp_credentials_credential_id",
            columns: &["credential_id"],
        }],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_user_totp_credentials_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[],
    },
    TableDef {
        name: "user_auth_public_keys",
        pk_name: "pk_user_auth_public_keys",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(32)),
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("public_key_der", ColumnType::Blob),
            ColumnDef::req("fingerprint", ColumnType::FixedBinary32),
            ColumnDef::opt("label", ColumnType::Varchar(255)),
            ColumnDef::req("created_time", ColumnType::Double),
            ColumnDef::opt("last_used_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[UniqueDef {
            name: "uq_user_auth_public_keys_user_fingerprint",
            columns: &["user_id", "fingerprint"],
        }],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_user_auth_public_keys_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal(
            "ix_user_auth_public_keys_fingerprint",
            "fingerprint",
        )],
    },
    TableDef {
        name: "user_auth_policies",
        pk_name: "pk_user_auth_policies",
        pk_columns: &["user_id", "purpose"],
        columns: &[
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("purpose", ColumnType::Varchar(16)),
            ColumnDef::req("revision", ColumnType::Integer),
            ColumnDef::req("chains", ColumnType::Json),
        ],
        checks: &[
            CheckDef {
                name: "ck_auth_policy_purpose",
                expr: "purpose IN ('login', 'mfa', 'escalation')",
            },
            CheckDef {
                name: "ck_auth_policy_revision",
                expr: "revision > 0",
            },
        ],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_user_auth_policies_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[],
    },
    TableDef {
        name: "user_groups",
        pk_name: "pk_user_groups",
        pk_columns: &["group_name"],
        columns: &[
            ColumnDef::req("group_name", ColumnType::Varchar(255)),
            ColumnDef::opt("group_display_name", ColumnType::Varchar(128)),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[],
    },
    TableDef {
        name: "group_permissions",
        pk_name: "pk_group_permissions",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Serial),
            ColumnDef::req("group_name", ColumnType::Varchar(255)),
            ColumnDef::req("permission", ColumnType::Varchar(255)),
            ColumnDef::req("granted", ColumnType::Boolean),
            ColumnDef::req("start_time", ColumnType::Double),
            ColumnDef::opt("end_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_group_permissions_group_name_user_groups",
            "group_name",
            "user_groups",
            "group_name",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal("ix_group_permissions_end_time_id", "end_time, id")],
    },
    TableDef {
        name: "user_memberships",
        pk_name: "pk_user_memberships",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Serial),
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("group_name", ColumnType::Varchar(255)),
            ColumnDef::req("start_time", ColumnType::Double),
            ColumnDef::opt("end_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_user_memberships_user_id_users",
                "user_id",
                "users",
                "id",
                OnDelete::Cascade,
            ),
            ForeignKeyDef::simple(
                "fk_user_memberships_group_name_user_groups",
                "group_name",
                "user_groups",
                "group_name",
                OnDelete::Cascade,
            ),
        ],
        indexes: &[],
    },
    TableDef {
        name: "user_permissions",
        pk_name: "pk_user_permissions",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Serial),
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("permission", ColumnType::Varchar(255)),
            ColumnDef::req("granted", ColumnType::Boolean),
            ColumnDef::req("start_time", ColumnType::Double),
            ColumnDef::opt("end_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_user_permissions_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal("ix_user_permissions_end_time_id", "end_time, id")],
    },
    TableDef {
        name: "keyrings",
        pk_name: "pk_keyrings",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(64)),
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("content", ColumnType::Text),
            ColumnDef::opt("label", ColumnType::Varchar(255)),
            ColumnDef::req("created_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_keyrings_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal("ix_keyrings_user_id", "user_id")],
    },
    TableDef {
        name: "nodes",
        pk_name: "pk_nodes",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(255)),
            ColumnDef::req("type", ColumnType::Varchar(16)),
            ColumnDef::req("name", ColumnType::Varchar(255)),
            ColumnDef::opt("parent_id", ColumnType::Varchar(255)),
            ColumnDef::generated_stored(
                "active_name",
                ColumnType::Varchar(255),
                "CASE WHEN status = 1 THEN NULL ELSE name END",
            ),
            ColumnDef::req("inherit", ColumnType::Boolean),
            ColumnDef::req("status", ColumnType::Integer),
            ColumnDef::opt("status_operation_id", ColumnType::Varchar(255)),
        ],
        checks: &[CheckDef {
            name: "ck_nodes_root_parent",
            expr: "id = '/' AND parent_id IS NULL AND type = 'directory' OR id != '/' AND parent_id IS NOT NULL",
        }],
        uniques: &[UniqueDef {
            name: "uq_nodes_active_parent_name",
            columns: &["parent_id", "active_name"],
        }],
        foreign_keys: &[ForeignKeyDef::cyclic(
            "fk_nodes_parent_id_folders",
            "parent_id",
            "folders",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[
            IndexDef::normal("ix_nodes_name", "name"),
            IndexDef::functional(
                "ix_nodes_parent_status_lower_name_id",
                "parent_id, status, lower(name), id",
                "parent_id, status, (lower(name)), id",
            ),
            IndexDef::functional(
                "ix_nodes_status_lower_name_id",
                "status, lower(name), id",
                "status, (lower(name)), id",
            ),
            IndexDef::normal("ix_nodes_status_operation_id", "status_operation_id"),
            IndexDef::normal("ix_nodes_type", "type"),
        ],
    },
    TableDef {
        name: "folders",
        pk_name: "pk_folders",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(255)),
            ColumnDef::req("created_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_folders_id_nodes",
            "id",
            "nodes",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[],
    },
    TableDef {
        name: "documents",
        pk_name: "pk_documents",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(255)),
            ColumnDef::req("created_time", ColumnType::Double),
            ColumnDef::opt("current_revision_id", ColumnType::Varchar(64)),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_documents_id_nodes",
                "id",
                "nodes",
                "id",
                OnDelete::Cascade,
            ),
            ForeignKeyDef::cyclic(
                "fk_documents_current_revision_id_document_revisions",
                "current_revision_id",
                "document_revisions",
                "id",
                OnDelete::SetNull,
            ),
        ],
        indexes: &[IndexDef::normal(
            "ix_documents_current_revision_id",
            "current_revision_id",
        )],
    },
    TableDef {
        name: "document_revisions",
        pk_name: "pk_document_revisions",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(64)),
            ColumnDef::req("document_id", ColumnType::Varchar(255)),
            ColumnDef::req("file_id", ColumnType::Varchar(255)),
            ColumnDef::req("created_time", ColumnType::Double),
            ColumnDef::opt("parent_revision_id", ColumnType::Varchar(64)),
            ColumnDef::req("status", ColumnType::Integer),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_document_revisions_document_id_documents",
                "document_id",
                "documents",
                "id",
                OnDelete::Restrict,
            ),
            ForeignKeyDef::simple(
                "fk_document_revisions_file_id_files",
                "file_id",
                "files",
                "id",
                OnDelete::Restrict,
            ),
            ForeignKeyDef::simple(
                "fk_document_revisions_parent_revision_id_document_revisions",
                "parent_revision_id",
                "document_revisions",
                "id",
                OnDelete::SetNull,
            ),
        ],
        indexes: &[
            IndexDef::normal(
                "ix_document_revisions_document_created_id",
                "document_id, created_time, id",
            ),
            IndexDef::normal("ix_document_revisions_file_id", "file_id"),
            IndexDef::normal(
                "ix_document_revisions_parent_revision_id",
                "parent_revision_id",
            ),
        ],
    },
    TableDef {
        name: "document_metadata",
        pk_name: "pk_document_metadata",
        pk_columns: &["document_id"],
        columns: &[
            ColumnDef::req("document_id", ColumnType::Varchar(255)),
            ColumnDef::opt("creator_id", ColumnType::Uuid),
            ColumnDef::opt("last_modified_by_id", ColumnType::Uuid),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_document_metadata_document_id_documents",
                "document_id",
                "documents",
                "id",
                OnDelete::Cascade,
            ),
            ForeignKeyDef::simple(
                "fk_document_metadata_creator_id_users",
                "creator_id",
                "users",
                "id",
                OnDelete::SetNull,
            ),
            ForeignKeyDef::simple(
                "fk_document_metadata_last_modified_by_id_users",
                "last_modified_by_id",
                "users",
                "id",
                OnDelete::SetNull,
            ),
        ],
        indexes: &[
            IndexDef::normal("ix_document_metadata_creator_id", "creator_id"),
            IndexDef::normal(
                "ix_document_metadata_last_modified_by_id",
                "last_modified_by_id",
            ),
        ],
    },
    TableDef {
        name: "document_metadata_tags",
        pk_name: "pk_document_metadata_tags",
        pk_columns: &["document_id", "tag"],
        columns: &[
            ColumnDef::req("document_id", ColumnType::Varchar(255)),
            ColumnDef::req("tag", ColumnType::Varchar(255)),
            ColumnDef::req("position", ColumnType::Integer),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_document_metadata_tags_document_id_document_metadata",
            "document_id",
            "document_metadata",
            "document_id",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal("ix_document_metadata_tags_tag", "tag")],
    },
    TableDef {
        name: "dacl_rules",
        pk_name: "pk_dacl_rules",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::BigSerial),
            ColumnDef::req("node_id", ColumnType::Varchar(255)),
            ColumnDef::req("effect", ColumnType::Varchar(8)),
            ColumnDef::req("permission_mask", ColumnType::BigInt),
            ColumnDef::req("scope", ColumnType::Varchar(8)),
            ColumnDef::opt("valid_from", ColumnType::BigInt),
            ColumnDef::opt("valid_until", ColumnType::BigInt),
            ColumnDef::opt("remark", ColumnType::Text),
        ],
        checks: &[
            CheckDef {
                name: "ck_dacl_rules_effect",
                expr: "effect IN ('allow', 'deny')",
            },
            CheckDef {
                name: "ck_dacl_rules_permission_mask",
                expr: "permission_mask > 0",
            },
            CheckDef {
                name: "ck_dacl_rules_scope",
                expr: "scope IN ('self', 'dirs', 'docs', 'all')",
            },
            CheckDef {
                name: "ck_dacl_rules_valid_window",
                expr: "valid_from IS NULL OR valid_until IS NULL OR valid_from < valid_until",
            },
        ],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_dacl_rules_node_id_nodes",
            "node_id",
            "nodes",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[
            IndexDef::normal(
                "ix_dacl_rules_node_effect_scope",
                "node_id, effect, scope",
            ),
            IndexDef::normal("ix_dacl_rules_validity", "node_id, valid_from, valid_until"),
        ],
    },
    TableDef {
        name: "dacl_rule_clauses",
        pk_name: "pk_dacl_rule_clauses",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::BigSerial),
            ColumnDef::req("rule_id", ColumnType::SqliteIntElseBigInt),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_dacl_rule_clauses_rule_id_dacl_rules",
            "rule_id",
            "dacl_rules",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal(
            "ix_dacl_rule_clauses_rule_id",
            "rule_id",
        )],
    },
    TableDef {
        name: "dacl_rule_atoms",
        pk_name: "pk_dacl_rule_atoms",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::BigSerial),
            ColumnDef::req("clause_id", ColumnType::SqliteIntElseBigInt),
            ColumnDef::req("predicate_kind", ColumnType::Varchar(16)),
            ColumnDef::req("predicate_value", ColumnType::Varchar(255)),
            ColumnDef::req("is_negated", ColumnType::Boolean),
        ],
        checks: &[CheckDef {
            name: "ck_dacl_rule_atoms_kind",
            expr: "predicate_kind IN ('user', 'group', 'perm')",
        }],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_dacl_rule_atoms_clause_id_dacl_rule_clauses",
            "clause_id",
            "dacl_rule_clauses",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[
            IndexDef::normal("ix_dacl_rule_atoms_clause_id", "clause_id"),
            IndexDef::normal(
                "ix_dacl_rule_atoms_principal",
                "predicate_kind, predicate_value",
            ),
        ],
    },
    TableDef {
        name: "audit_entries",
        pk_name: "pk_audit_entries",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(255)),
            ColumnDef::req("action", ColumnType::Varchar(255)),
            ColumnDef::opt("user_id", ColumnType::Uuid),
            ColumnDef::opt("target", ColumnType::Varchar(255)),
            ColumnDef::opt("data", ColumnType::Json),
            ColumnDef::req("result", ColumnType::Integer),
            ColumnDef::opt("remote_address", ColumnType::Varchar(64)),
            ColumnDef::req("logged_time", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_audit_entries_user_id_users",
            "user_id",
            "users",
            "id",
            OnDelete::SetNull,
        )],
        indexes: &[IndexDef::normal("ix_audit_entries_logged_time", "logged_time")],
    },
    TableDef {
        name: "banned_subnets",
        pk_name: "pk_banned_subnets",
        pk_columns: &["subnet"],
        columns: &[
            ColumnDef::req("subnet", ColumnType::Varchar(128)),
            ColumnDef::opt("reason_comment_id", ColumnType::SqliteIntElseBigInt),
            ColumnDef::req("created_at", ColumnType::Double),
            ColumnDef::req("starts_at", ColumnType::Double),
            ColumnDef::opt("expires_at", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_banned_subnets_reason_comment_id_comments",
            "reason_comment_id",
            "comments",
            "comment_id",
            OnDelete::SetNull,
        )],
        indexes: &[],
    },
    TableDef {
        name: "account_throttles",
        pk_name: "pk_account_throttles",
        pk_columns: &["username", "factor"],
        columns: &[
            ColumnDef::req("username", ColumnType::Varchar(256)),
            ColumnDef::req("factor", ColumnType::Varchar(16)),
            ColumnDef::req("failed_attempts", ColumnType::Integer),
            ColumnDef::req("last_attempt", ColumnType::Double),
            ColumnDef::opt("locked_until", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[IndexDef::normal(
            "ix_account_throttles_last_attempt",
            "last_attempt",
        )],
    },
    TableDef {
        name: "file_tasks",
        pk_name: "pk_file_tasks",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(255)),
            ColumnDef::req("file_id", ColumnType::Varchar(255)),
            ColumnDef::req("status", ColumnType::Integer),
            ColumnDef::req("mode", ColumnType::Integer).with_comment("0: download, 1: upload"),
            ColumnDef::req("start_time", ColumnType::Double),
            ColumnDef::opt("end_time", ColumnType::Double),
            ColumnDef::opt("issued_by_id", ColumnType::Uuid),
            ColumnDef::opt("encryption_key", ColumnType::Varchar(256)),
            ColumnDef::opt("chunk_size", ColumnType::Integer),
            ColumnDef::opt("upload_file_size", ColumnType::BigInt),
            ColumnDef::opt("upload_sha256", ColumnType::Varchar(64)),
            ColumnDef::opt("upload_session_id", ColumnType::Text),
            ColumnDef::opt("upload_checkpoint_size", ColumnType::BigInt),
            ColumnDef::opt("upload_checkpoint_data", ColumnType::Text),
        ],
        checks: &[CheckDef {
            name: "ck_file_tasks_status_value",
            expr: "status IN (0, 1, 2, 3, 4)",
        }],
        uniques: &[],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_file_tasks_file_id_files",
                "file_id",
                "files",
                "id",
                OnDelete::Cascade,
            ),
            ForeignKeyDef::simple(
                "fk_file_tasks_issued_by_id_users",
                "issued_by_id",
                "users",
                "id",
                OnDelete::SetNull,
            ),
        ],
        indexes: &[
            IndexDef::normal("ix_file_tasks_mode_status_end_time", "mode, status, end_time"),
            IndexDef::normal("ix_file_tasks_file_id_mode_status", "file_id, mode, status"),
        ],
    },
    TableDef {
        name: "login_throttles",
        pk_name: "pk_login_throttles",
        pk_columns: &["username", "ip_address"],
        columns: &[
            ColumnDef::req("username", ColumnType::Varchar(255)),
            ColumnDef::req("ip_address", ColumnType::Varchar(45)),
            ColumnDef::req("failed_attempts", ColumnType::Integer),
            ColumnDef::req("window_started_at", ColumnType::Double),
            ColumnDef::req("last_attempt", ColumnType::Double),
            ColumnDef::opt("locked_until", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[
            IndexDef::normal("ix_login_throttles_ip_address", "ip_address"),
            IndexDef::normal("ix_login_throttles_last_attempt", "last_attempt"),
        ],
    },
    TableDef {
        name: "rate_limit_buckets",
        pk_name: "pk_rate_limit_buckets",
        pk_columns: &["namespace", "scope", "identity"],
        columns: &[
            ColumnDef::req("namespace", ColumnType::Varchar(64)),
            ColumnDef::req("scope", ColumnType::Varchar(16)),
            ColumnDef::req("identity", ColumnType::Varchar(256)),
            ColumnDef::req("tokens", ColumnType::Double),
            ColumnDef::req("last_refill_at", ColumnType::Double),
            ColumnDef::req("denial_count", ColumnType::Integer),
            ColumnDef::opt("last_denied_at", ColumnType::Double),
            ColumnDef::req("last_attempt", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[IndexDef::normal(
            "ix_rate_limit_buckets_last_attempt",
            "last_attempt",
        )],
    },
    TableDef {
        name: "risk_ip_accounts",
        pk_name: "pk_risk_ip_accounts",
        pk_columns: &["namespace", "ip_address", "user_id"],
        columns: &[
            ColumnDef::req("namespace", ColumnType::Varchar(64)),
            ColumnDef::req("ip_address", ColumnType::Varchar(45)),
            ColumnDef::req("user_id", ColumnType::Uuid),
            ColumnDef::req("last_attempt", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[IndexDef::normal(
            "ix_risk_ip_accounts_last_attempt",
            "last_attempt",
        )],
    },
    TableDef {
        name: "system_states",
        pk_name: "pk_system_states",
        pk_columns: &["owner", "state_key"],
        columns: &[
            ColumnDef::req("owner", ColumnType::Varchar(255)),
            ColumnDef::req("state_key", ColumnType::Varchar(128)),
            ColumnDef::req("schema_version", ColumnType::Integer),
            ColumnDef::req("revision", ColumnType::BigInt),
            ColumnDef::req("payload", ColumnType::Json),
            ColumnDef::req("updated_at", ColumnType::Double),
        ],
        checks: &[
            CheckDef {
                name: "ck_system_states_schema_version_positive",
                expr: "schema_version > 0",
            },
            CheckDef {
                name: "ck_system_states_revision_positive",
                expr: "revision > 0",
            },
        ],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[],
    },
    TableDef {
        name: "options",
        pk_name: "pk_options",
        pk_columns: &["namespace", "option_key"],
        columns: &[
            ColumnDef::req("namespace", ColumnType::Varchar(111)),
            ColumnDef::req("owner", ColumnType::Varchar(255)),
            ColumnDef::req("option_key", ColumnType::Varchar(128)),
            ColumnDef::req("schema_version", ColumnType::Integer),
            ColumnDef::req("revision", ColumnType::BigInt),
            ColumnDef::req("value_type", ColumnType::Varchar(8)),
            ColumnDef::req("option_value", ColumnType::LongText),
            ColumnDef::req("updated_at", ColumnType::Double),
        ],
        checks: &[
            CheckDef {
                name: "ck_options_schema_version_positive",
                expr: "schema_version > 0",
            },
            CheckDef {
                name: "ck_options_revision_positive",
                expr: "revision > 0",
            },
            CheckDef {
                name: "ck_options_value_type",
                expr: "value_type IN ('str', 'int', 'float', 'bool', 'null', 'json')",
            },
        ],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[IndexDef::normal("ix_options_owner", "owner")],
    },
    TableDef {
        name: "traffic_throttles",
        pk_name: "pk_traffic_throttles",
        pk_columns: &["ip_address"],
        columns: &[
            ColumnDef::req("ip_address", ColumnType::Varchar(45)),
            ColumnDef::req("failed_attempts", ColumnType::Integer),
            ColumnDef::req("window_started_at", ColumnType::Double),
            ColumnDef::req("last_attempt", ColumnType::Double),
            ColumnDef::opt("locked_until", ColumnType::Double),
        ],
        checks: &[],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[IndexDef::normal(
            "ix_traffic_throttles_last_attempt",
            "last_attempt",
        )],
    },
    TableDef {
        name: "file_deduplication_tasks",
        pk_name: "pk_file_deduplication_tasks",
        pk_columns: &["file_id"],
        columns: &[
            ColumnDef::req("file_id", ColumnType::Varchar(255)),
            ColumnDef::req("phase", ColumnType::Integer),
            ColumnDef::req("available_at", ColumnType::Double),
            ColumnDef::opt("lease_owner", ColumnType::Varchar(64)),
            ColumnDef::opt("lease_expires_at", ColumnType::Double),
            ColumnDef::req("attempts", ColumnType::Integer),
            ColumnDef::opt("last_error", ColumnType::Text),
            ColumnDef::req("created_time", ColumnType::Double),
        ],
        checks: &[CheckDef {
            name: "ck_file_deduplication_tasks_phase_value",
            expr: "phase IN (0, 1)",
        }],
        uniques: &[],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_file_deduplication_tasks_file_id_files",
            "file_id",
            "files",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[IndexDef::normal(
            "ix_file_deduplication_tasks_available_lease",
            "available_at, lease_expires_at",
        )],
    },
    TableDef {
        name: "schedules",
        pk_name: "pk_schedules",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(32)),
            ColumnDef::req("task_name", ColumnType::Varchar(255)),
            ColumnDef::req("task_contract_version", ColumnType::Integer),
            ColumnDef::req("payload", ColumnType::Json),
            ColumnDef::req("trigger_type", ColumnType::Varchar(16)),
            ColumnDef::req("trigger_data", ColumnType::Json),
            ColumnDef::req("timezone", ColumnType::Varchar(255)),
            ColumnDef::default_false("system_managed"),
            ColumnDef::req("enabled", ColumnType::Boolean),
            ColumnDef::req("status", ColumnType::Varchar(16)),
            ColumnDef::req("revision", ColumnType::BigInt),
            ColumnDef::opt("next_run_at", ColumnType::Double),
            ColumnDef::opt("active_execution_id", ColumnType::Varchar(64)),
            ColumnDef::opt("pending_scheduled_for", ColumnType::Double),
            ColumnDef::opt("created_by", ColumnType::Uuid),
            ColumnDef::req("created_at", ColumnType::Double),
            ColumnDef::opt("updated_by", ColumnType::Uuid),
            ColumnDef::req("updated_at", ColumnType::Double),
            ColumnDef::opt("deleted_at", ColumnType::Double),
        ],
        checks: &[
            CheckDef {
                name: "ck_schedules_revision_positive",
                expr: "revision > 0",
            },
            CheckDef {
                name: "ck_schedules_task_contract_version_positive",
                expr: "task_contract_version > 0",
            },
            CheckDef {
                name: "ck_schedules_trigger_type",
                expr: "trigger_type IN ('cron', 'date', 'interval')",
            },
            CheckDef {
                name: "ck_schedules_status",
                expr: "status IN ('active', 'completed', 'failed', 'deleted')",
            },
        ],
        uniques: &[],
        foreign_keys: &[
            ForeignKeyDef::simple(
                "fk_schedules_created_by_users",
                "created_by",
                "users",
                "id",
                OnDelete::SetNull,
            ),
            ForeignKeyDef::simple(
                "fk_schedules_updated_by_users",
                "updated_by",
                "users",
                "id",
                OnDelete::SetNull,
            ),
        ],
        indexes: &[IndexDef::normal("ix_schedules_due", "enabled, status, next_run_at")],
    },
    TableDef {
        name: "schedule_executions",
        pk_name: "pk_schedule_executions",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Varchar(64)),
            ColumnDef::req("schedule_id", ColumnType::Varchar(32)),
            ColumnDef::req("task_name", ColumnType::Varchar(255)),
            ColumnDef::req("task_contract_version", ColumnType::Integer),
            ColumnDef::req("payload", ColumnType::Json),
            ColumnDef::req("provider_generation", ColumnType::BigInt),
            ColumnDef::req("scheduled_for", ColumnType::Double),
            ColumnDef::req("state", ColumnType::Varchar(16)),
            ColumnDef::req("dispatch_state", ColumnType::Varchar(16)),
            ColumnDef::req("attempt", ColumnType::Integer),
            ColumnDef::opt("retry_at", ColumnType::Double),
            ColumnDef::opt("dispatched_at", ColumnType::Double),
            ColumnDef::opt("lease_owner", ColumnType::Varchar(64)),
            ColumnDef::opt("lease_expires_at", ColumnType::Double),
            ColumnDef::opt("started_at", ColumnType::Double),
            ColumnDef::opt("completed_at", ColumnType::Double),
            ColumnDef::opt("result", ColumnType::Json),
            ColumnDef::opt("error", ColumnType::Varchar(1024)),
            ColumnDef::req("created_at", ColumnType::Double),
        ],
        checks: &[
            CheckDef {
                name: "ck_schedule_executions_attempt",
                expr: "attempt >= 0",
            },
            CheckDef {
                name: "ck_schedule_executions_state",
                expr: "state IN ('pending', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled')",
            },
            CheckDef {
                name: "ck_schedule_executions_dispatch_state",
                expr: "dispatch_state IN ('pending', 'sent')",
            },
        ],
        uniques: &[UniqueDef {
            name: "uq_schedule_executions_occurrence",
            columns: &["schedule_id", "scheduled_for"],
        }],
        foreign_keys: &[ForeignKeyDef::simple(
            "fk_schedule_executions_schedule_id_schedules",
            "schedule_id",
            "schedules",
            "id",
            OnDelete::Cascade,
        )],
        indexes: &[
            IndexDef::normal("ix_schedule_executions_schedule_id", "schedule_id"),
            IndexDef::normal(
                "ix_schedule_executions_claim",
                "state, dispatch_state, retry_at, lease_expires_at",
            ),
        ],
    },
    TableDef {
        name: "scheduling_runtime_state",
        pk_name: "pk_scheduling_runtime_state",
        pk_columns: &["id"],
        columns: &[
            ColumnDef::req("id", ColumnType::Integer),
            ColumnDef::req("provider", ColumnType::Varchar(16)),
            ColumnDef::opt("redis_namespace", ColumnType::Varchar(63)),
            ColumnDef::req("generation", ColumnType::BigInt),
            ColumnDef::req("schema_version", ColumnType::Integer),
            ColumnDef::req("updated_at", ColumnType::Double),
        ],
        checks: &[
            CheckDef {
                name: "ck_scheduling_runtime_state_singleton",
                expr: "id = 1",
            },
            CheckDef {
                name: "ck_scheduling_generation_positive",
                expr: "generation > 0",
            },
            CheckDef {
                name: "ck_scheduling_runtime_provider",
                expr: "provider IN ('local', 'redis')",
            },
        ],
        uniques: &[],
        foreign_keys: &[],
        indexes: &[],
    },
];

/// Declarative definition for built-in extension table `user_oidc_credentials`.
pub const USER_OIDC_CREDENTIALS_TABLE: TableDef = TableDef {
    name: "user_oidc_credentials",
    pk_name: "pk_user_oidc_credentials",
    pk_columns: &["id"],
    columns: &[
        ColumnDef::req("id", ColumnType::Varchar(32)),
        ColumnDef::req("user_id", ColumnType::Uuid),
        ColumnDef::req("issuer", ColumnType::Text),
        ColumnDef::req("subject", ColumnType::Text),
        ColumnDef::req("identity_digest", ColumnType::FixedBinary32),
    ],
    checks: &[],
    uniques: &[UniqueDef {
        name: "uq_user_oidc_credentials_identity_digest",
        columns: &["identity_digest"],
    }],
    foreign_keys: &[ForeignKeyDef::simple(
        "fk_user_oidc_credentials_user_id_users",
        "user_id",
        "users",
        "id",
        OnDelete::Cascade,
    )],
    indexes: &[IndexDef::normal(
        "ix_user_oidc_credentials_user_id",
        "user_id",
    )],
};

/// Look up declarative definition for any known core or built-in extension table.
#[must_use]
pub fn table_def(name: &str) -> Option<&'static TableDef> {
    if name == USER_OIDC_CREDENTIALS_TABLE.name {
        return Some(&USER_OIDC_CREDENTIALS_TABLE);
    }
    CORE_TABLES.iter().find(|t| t.name == name)
}

/// Export the built-in 0.14.x schema contract as a unified [`SchemaIr`].
#[must_use]
pub fn builtin_schema_ir(include_oidc_extension: bool) -> SchemaIr {
    let mut ir = SchemaIr::new(
        ExtractionSource::BuiltinFallback,
        Some(LATEST_SCHEMA_REVISION.to_string()),
    );
    for table in CORE_TABLES {
        ir.tables
            .insert(table.name.to_string(), table.to_ir(TableOwnership::Core));
    }
    if include_oidc_extension {
        ir.tables.insert(
            USER_OIDC_CREDENTIALS_TABLE.name.to_string(),
            USER_OIDC_CREDENTIALS_TABLE.to_ir(TableOwnership::Extension("oidc_sso".to_string())),
        );
    }
    ir
}

/// Ordered list of active tables (40 core + requested known extensions).
#[must_use]
pub fn ordered_tables_for(extension_tables: &[String]) -> Vec<&'static TableDef> {
    let include_oidc = extension_tables
        .iter()
        .any(|t| t == USER_OIDC_CREDENTIALS_TABLE.name);
    let mut tables = Vec::with_capacity(CORE_TABLES.len() + usize::from(include_oidc));
    for table in CORE_TABLES {
        tables.push(table);
        if include_oidc && table.name == "users" {
            tables.push(&USER_OIDC_CREDENTIALS_TABLE);
        }
    }
    tables
}

/// Compile ordered DDL statements (`CREATE TABLE`, `CREATE INDEX`, and deferred `ALTER TABLE` FKs)
/// to create the latest head schema on `kind`.
#[must_use]
pub fn compile_head_schema_statements(
    kind: DatabaseKind,
    include_oidc_extension: bool,
) -> Vec<String> {
    let ext = if include_oidc_extension {
        vec![KNOWN_EXTENSION_TABLES[0].to_string()]
    } else {
        Vec::new()
    };
    let tables = ordered_tables_for(&ext);
    let mut stmts = Vec::new();
    for table in &tables {
        stmts.push(table.compile_create_table(kind));
        stmts.extend(table.compile_create_indexes(kind));
    }
    for table in &tables {
        stmts.extend(table.compile_deferred_foreign_keys(kind));
    }
    stmts
}

/// Execute DDL statements atomically (SQLite/PostgreSQL) or sequentially on a single connection (MySQL).
pub async fn execute_ddl_statements(pool: &DbPool, statements: &[String]) -> Result<()> {
    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            for sql in statements {
                sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
        DbPool::Mysql(p) => {
            let mut conn = p.acquire().await?;
            for sql in statements {
                sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                    .execute(&mut *conn)
                    .await?;
            }
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            for sql in statements {
                sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
    }
    Ok(())
}

/// Ensure `alembic_version` exists and records exactly `revision`.
pub async fn set_alembic_version(pool: &DbPool, revision: &str) -> Result<()> {
    let create_sql = "CREATE TABLE IF NOT EXISTS alembic_version (\n\
        \tversion_num VARCHAR(32) NOT NULL, \n\
        \tCONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)\n\
    )";
    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            sqlx::query(create_sql).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM alembic_version")
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO alembic_version (version_num) VALUES (?)")
                .bind(revision)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        DbPool::Mysql(p) => {
            let mut conn = p.acquire().await?;
            sqlx::query(create_sql).execute(&mut *conn).await?;
            let mut tx = conn.begin().await?;
            sqlx::query("DELETE FROM alembic_version")
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO alembic_version (version_num) VALUES (?)")
                .bind(revision)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            sqlx::query(create_sql).execute(&mut *tx).await?;
            sqlx::query("DELETE FROM alembic_version")
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO alembic_version (version_num) VALUES ($1)")
                .bind(revision)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
    }
    Ok(())
}

/// Create the full CFMS head schema (35 core tables + optional `user_oidc_credentials`).
pub async fn create_head_schema(pool: &DbPool, include_oidc_extension: bool) -> Result<()> {
    let stmts = compile_head_schema_statements(pool.kind(), include_oidc_extension);
    execute_ddl_statements(pool, &stmts).await
}

/// Cleanly drop `alembic_version` and any created application tables on a failed migration target.
pub async fn drop_all_cfms_tables(pool: &DbPool, existing_tables: &[String]) -> Result<()> {
    let mut ordered_drops: Vec<String> = Vec::new();
    for table in CORE_TABLES.iter().rev() {
        if existing_tables.iter().any(|t| t == table.name) {
            ordered_drops.push(table.name.to_string());
        }
    }
    for ext in KNOWN_EXTENSION_TABLES {
        if existing_tables.iter().any(|t| t == ext) {
            ordered_drops.push((*ext).to_string());
        }
    }
    for name in existing_tables {
        if !ordered_drops.contains(name) {
            ordered_drops.push(name.clone());
        }
    }
    if !ordered_drops.iter().any(|t| t == "alembic_version") {
        ordered_drops.push("alembic_version".to_string());
    }

    match pool {
        DbPool::Sqlite(p) => {
            let mut conn = p.acquire().await?;
            sqlx::query("PRAGMA foreign_keys = OFF")
                .execute(&mut *conn)
                .await?;
            let drop_res: Result<()> = async {
                for name in &ordered_drops {
                    let sql = format!("DROP TABLE IF EXISTS \"{}\"", name.replace('"', "\"\""));
                    sqlx::query(sqlx::AssertSqlSafe(sql))
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            }
            .await;
            let _ = sqlx::query("PRAGMA foreign_keys = ON")
                .execute(&mut *conn)
                .await;
            drop_res?;
        }
        DbPool::Mysql(p) => {
            let mut conn = p.acquire().await?;
            sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
                .execute(&mut *conn)
                .await?;
            let drop_res: Result<()> = async {
                for name in &ordered_drops {
                    let sql = format!("DROP TABLE IF EXISTS `{}`", name.replace('`', "``"));
                    sqlx::query(sqlx::AssertSqlSafe(sql))
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            }
            .await;
            let _ = sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
                .execute(&mut *conn)
                .await;
            drop_res?;
        }
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            for name in &ordered_drops {
                let sql = format!(
                    "DROP TABLE IF EXISTS \"{}\" CASCADE",
                    name.replace('"', "\"\"")
                );
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::registry::APPLICATION_TABLE_NAMES;

    #[test]
    fn core_tables_match_application_table_names_count_and_order() {
        let names: Vec<&str> = CORE_TABLES.iter().map(|t| t.name).collect();
        assert_eq!(names.len(), 35);
        assert_eq!(names.as_slice(), APPLICATION_TABLE_NAMES);
    }

    #[test]
    fn dialect_ddl_compiles_key_differences_accurately() {
        let users = table_def("users").expect("users def");
        let sqlite_users = users.compile_create_table(DatabaseKind::Sqlite);
        let mysql_users = users.compile_create_table(DatabaseKind::Mysql);
        let pg_users = users.compile_create_table(DatabaseKind::Postgresql);

        assert!(sqlite_users.contains("id CHAR(32) NOT NULL"));
        assert!(sqlite_users.contains("status_comment_id INTEGER"));
        assert!(sqlite_users.contains("fk_users_preference_dek_id"));

        assert!(mysql_users.contains("id CHAR(32) NOT NULL"));
        assert!(mysql_users.contains("status_comment_id BIGINT"));
        assert!(!mysql_users.contains("fk_users_preference_dek_id"));
        assert_eq!(users.compile_deferred_foreign_keys(DatabaseKind::Mysql).len(), 1);

        assert!(pg_users.contains("id UUID NOT NULL"));
        assert!(pg_users.contains("status_comment_id BIGINT"));
        assert!(!pg_users.contains("fk_users_preference_dek_id"));
        assert_eq!(
            users.compile_deferred_foreign_keys(DatabaseKind::Postgresql).len(),
            1
        );

        let nodes = table_def("nodes").expect("nodes def");
        let sqlite_idx = nodes.compile_create_indexes(DatabaseKind::Sqlite);
        let mysql_idx = nodes.compile_create_indexes(DatabaseKind::Mysql);
        assert!(
            sqlite_idx
                .iter()
                .any(|s| s.contains("(parent_id, status, lower(name), id)"))
        );
        assert!(
            mysql_idx
                .iter()
                .any(|s| s.contains("(parent_id, status, (lower(name)), id)"))
        );

        let options = table_def("options").expect("options def");
        assert!(
            options
                .compile_create_table(DatabaseKind::Mysql)
                .contains("option_value LONGTEXT NOT NULL")
        );
        assert!(
            options
                .compile_create_table(DatabaseKind::Postgresql)
                .contains("option_value TEXT NOT NULL")
        );

        let comments = table_def("comments").expect("comments def");
        assert!(
            comments
                .compile_create_table(DatabaseKind::Mysql)
                .contains("content_digest BINARY(32) NOT NULL")
        );
        assert!(
            comments
                .compile_create_table(DatabaseKind::Postgresql)
                .contains("comment_id BIGSERIAL NOT NULL")
        );

        let dacl_rules = table_def("dacl_rules").expect("dacl_rules def");
        let pg_dacl = dacl_rules.compile_create_table(DatabaseKind::Postgresql);
        assert!(pg_dacl.contains("id BIGSERIAL NOT NULL"));
        assert!(pg_dacl.contains("ck_dacl_rules_effect"));
        assert!(pg_dacl.contains("ck_dacl_rules_valid_window"));
        let mysql_dacl = dacl_rules.compile_create_table(DatabaseKind::Mysql);
        assert!(mysql_dacl.contains("id BIGINT NOT NULL AUTO_INCREMENT"));
        let sqlite_dacl = dacl_rules.compile_create_table(DatabaseKind::Sqlite);
        assert!(sqlite_dacl.contains("id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT") || sqlite_dacl.contains("id INTEGER NOT NULL"));

        let dacl_clauses = table_def("dacl_rule_clauses").expect("dacl_rule_clauses def");
        assert!(
            dacl_clauses
                .compile_create_table(DatabaseKind::Sqlite)
                .contains("rule_id INTEGER NOT NULL")
        );
        assert!(
            dacl_clauses
                .compile_create_table(DatabaseKind::Postgresql)
                .contains("rule_id BIGINT NOT NULL")
        );
    }

    #[test]
    fn builtin_schema_ir_round_trips_and_matches_table_def_ddl() {
        let ir = builtin_schema_ir(true);
        assert_eq!(ir.core_table_names().len(), 35);
        assert_eq!(ir.extension_table_names().len(), 1);
        assert_eq!(
            ir.schema_revision.as_deref(),
            Some(LATEST_SCHEMA_REVISION)
        );

        let json = ir.to_pretty_json().expect("serialize ir");
        let parsed = SchemaIr::from_json_str(&json).expect("deserialize ir");
        assert_eq!(parsed, ir);

        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Mysql,
            DatabaseKind::Postgresql,
        ] {
            for table in CORE_TABLES {
                let expected = table.compile_create_table(kind);
                let actual = ir.tables[table.name].compile_create_table(kind, None);
                assert_eq!(actual, expected, "table {} ({kind})", table.name);
            }
        }
    }
}
