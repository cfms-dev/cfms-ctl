//! Declarative schema contracts for CFMS 0.14.x+ databases.

/// Latest known core Alembic revision head for CFMS 0.14.0 (`e952c02c1454`).
pub const LATEST_SCHEMA_REVISION: &str = "e952c02c1454";

/// Root Alembic revision from which retained CFMS 0.14.x linear migrations originate.
pub const ROOT_SCHEMA_REVISION: &str = "fe8863687aa4";

/// Metadata describing a single revision in the CFMS linear Alembic schema chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRevisionInfo {
    pub id: &'static str,
    pub down_revision: Option<&'static str>,
    pub description: &'static str,
}

/// Ordered linear chain of CFMS Alembic revisions from `fe8863687aa4` to `e952c02c1454`.
pub const SCHEMA_REVISIONS: &[SchemaRevisionInfo] = &[
    SchemaRevisionInfo {
        id: "fe8863687aa4",
        down_revision: None,
        description: "enforce node name uniqueness",
    },
    SchemaRevisionInfo {
        id: "b4b3061f385c",
        down_revision: Some("fe8863687aa4"),
        description: "grant server diagnostics permission",
    },
    SchemaRevisionInfo {
        id: "76f1c7621e23",
        down_revision: Some("b4b3061f385c"),
        description: "add user block reasons",
    },
    SchemaRevisionInfo {
        id: "f239d439f893",
        down_revision: Some("76f1c7621e23"),
        description: "index permission entry expiry",
    },
    SchemaRevisionInfo {
        id: "170e0a16133e",
        down_revision: Some("f239d439f893"),
        description: "make node namespace compatible with mysql",
    },
    SchemaRevisionInfo {
        id: "7bddfba0d8aa",
        down_revision: Some("170e0a16133e"),
        description: "preserve float precision across databases",
    },
    SchemaRevisionInfo {
        id: "ab7efda19079",
        down_revision: Some("7bddfba0d8aa"),
        description: "add scheduling infrastructure",
    },
    SchemaRevisionInfo {
        id: "8c130010a943",
        down_revision: Some("ab7efda19079"),
        description: "grant scheduling permissions",
    },
    SchemaRevisionInfo {
        id: "39084f380eaa",
        down_revision: Some("8c130010a943"),
        description: "add system-managed schedules",
    },
    SchemaRevisionInfo {
        id: "adc1283fb393",
        down_revision: Some("39084f380eaa"),
        description: "add scheduling redis namespace",
    },
    SchemaRevisionInfo {
        id: "6dba0956fa9d",
        down_revision: Some("adc1283fb393"),
        description: "add scheduling dispatch timestamps",
    },
    SchemaRevisionInfo {
        id: "3c496a214a87",
        down_revision: Some("6dba0956fa9d"),
        description: "snapshot scheduled execution contracts",
    },
    SchemaRevisionInfo {
        id: "0460356a5ba6",
        down_revision: Some("3c496a214a87"),
        description: "index document revision lookups",
    },
    SchemaRevisionInfo {
        id: "5ad5aca75635",
        down_revision: Some("0460356a5ba6"),
        description: "decouple user credentials",
    },
    SchemaRevisionInfo {
        id: "d252e662fc05",
        down_revision: Some("5ad5aca75635"),
        description: "bind accounts and references to immutable user IDs",
    },
    SchemaRevisionInfo {
        id: "b2ea9cac8462",
        down_revision: Some("d252e662fc05"),
        description: "separate registered credentials from authentication purpose policies",
    },
    SchemaRevisionInfo {
        id: "3815ba18197b",
        down_revision: Some("b2ea9cac8462"),
        description: "require independent user signing keys",
    },
    SchemaRevisionInfo {
        id: "03197fed3401",
        down_revision: Some("3815ba18197b"),
        description: "rename nickname permissions",
    },
    SchemaRevisionInfo {
        id: "16c86712512a",
        down_revision: Some("03197fed3401"),
        description: "add namespaced persistent options",
    },
    SchemaRevisionInfo {
        id: "e952c02c1454",
        down_revision: Some("16c86712512a"),
        description: "grant setting permissions",
    },
];

/// Return true if `revision` is part of the known CFMS schema history.
#[must_use]
pub fn is_known_revision(revision: &str) -> bool {
    SCHEMA_REVISIONS.iter().any(|rev| rev.id == revision)
}

/// Return the ordered slice of revisions to execute after `current_revision` to reach HEAD,
/// or `None` if `current_revision` is unknown.
#[must_use]
pub fn revisions_after(current_revision: &str) -> Option<&'static [SchemaRevisionInfo]> {
    let idx = SCHEMA_REVISIONS
        .iter()
        .position(|rev| rev.id == current_revision)?;
    Some(&SCHEMA_REVISIONS[idx + 1..])
}

/// Built-in optional extension tables supported natively by `cfms-ctl`.
pub const KNOWN_EXTENSION_TABLES: &[&str] = &["user_oidc_credentials"];

/// Canonical application tables in topological dependency order (CFMS 0.14.x+).
pub const APPLICATION_TABLE_NAMES: &[&str] = &[
    "files",
    "comments",
    "users",
    "user_passwords",
    "user_totp_credentials",
    "user_auth_public_keys",
    "user_auth_policies",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "nodes",
    "folders",
    "documents",
    "document_revisions",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "compiled_access_rule_sets",
    "compiled_access_rules",
    "compiled_access_rule_groups",
    "compiled_access_rule_memberships",
    "compiled_access_rule_rights",
    "audit_entries",
    "userblock_entries",
    "userblock_sub_entries",
    "banned_subnets",
    "account_throttles",
    "file_tasks",
    "login_throttles",
    "rate_limit_buckets",
    "risk_ip_accounts",
    "system_states",
    "options",
    "traffic_throttles",
    "file_deduplication_tasks",
    "schedules",
    "schedule_executions",
    "scheduling_runtime_state",
];

/// Columns backed by auto-increment / PostgreSQL `SERIAL` or `BIGSERIAL` sequences.
pub const SERIAL_IDENTITY_COLUMNS: &[(&str, &str)] = &[
    ("comments", "comment_id"),
    ("object_access_entries", "id"),
    ("group_permissions", "id"),
    ("compiled_access_rules", "id"),
    ("user_permissions", "id"),
    ("user_memberships", "id"),
    ("userblock_sub_entries", "id"),
    ("compiled_access_rule_rights", "id"),
    ("compiled_access_rule_memberships", "id"),
];

/// Columns that participate in cyclic or self-referential foreign keys and must be
/// inserted as `NULL` first during cross-database transfer or backup restoration.
pub const DEFERRED_COLUMNS: &[(&str, &[&str])] = &[
    ("users", &["preference_dek_id"]),
    ("documents", &["current_revision_id"]),
    ("document_revisions", &["parent_revision_id"]),
    ("nodes", &["access_rule_set_id"]),
];

/// Order in which deferred foreign-key columns are populated after base rows exist.
pub const DEFERRED_UPDATE_ORDER: &[(&str, &str, &[&str])] = &[
    ("users", "id", &["preference_dek_id"]),
    ("document_revisions", "id", &["parent_revision_id"]),
    ("documents", "id", &["current_revision_id"]),
    ("nodes", "id", &["access_rule_set_id"]),
];
