//! Declarative schema contracts for CFMS 0.14.0+ databases.

/// Latest known core Alembic revision head (`a66108639ed7`, CEP-0002 CACL DACL).
pub const LATEST_SCHEMA_REVISION: &str = "a66108639ed7";

/// Baseline Alembic revision from which retained CFMS native migrations originate (CFMS 0.14.0).
pub const ROOT_SCHEMA_REVISION: &str = "e952c02c1454";

/// Metadata describing a single revision in the CFMS linear Alembic schema chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRevisionInfo {
    pub id: &'static str,
    pub down_revision: Option<&'static str>,
    pub description: &'static str,
}

/// Ordered linear chain of supported CFMS Alembic revisions from `e952c02c1454` (0.14.0) to `a66108639ed7`.
pub const SCHEMA_REVISIONS: &[SchemaRevisionInfo] = &[
    SchemaRevisionInfo {
        id: "e952c02c1454",
        down_revision: None,
        description: "CFMS 0.14.0 baseline (grant setting permissions)",
    },
    SchemaRevisionInfo {
        id: "a66108639ed7",
        down_revision: Some("e952c02c1454"),
        description: "migrate to cacl dacl",
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

/// Canonical application tables in topological dependency order (CEP-0002 CACL HEAD).
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
    "dacl_rules",
    "dacl_rule_clauses",
    "dacl_rule_atoms",
    "audit_entries",
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
    ("group_permissions", "id"),
    ("user_permissions", "id"),
    ("user_memberships", "id"),
    ("dacl_rules", "id"),
    ("dacl_rule_clauses", "id"),
    ("dacl_rule_atoms", "id"),
];

/// Columns that participate in cyclic or self-referential foreign keys and must be
/// inserted as `NULL` first during cross-database transfer or backup restoration.
pub const DEFERRED_COLUMNS: &[(&str, &[&str])] = &[
    ("users", &["preference_dek_id"]),
    ("documents", &["current_revision_id"]),
    ("document_revisions", &["parent_revision_id"]),
];

/// Order in which deferred foreign-key columns are populated after base rows exist.
pub const DEFERRED_UPDATE_ORDER: &[(&str, &str, &[&str])] = &[
    ("users", "id", &["preference_dek_id"]),
    ("document_revisions", "id", &["parent_revision_id"]),
    ("documents", "id", &["current_revision_id"]),
];
