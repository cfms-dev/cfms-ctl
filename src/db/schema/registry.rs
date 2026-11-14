//! Declarative schema contracts for CFMS 0.14.x+ databases.

/// Latest known core Alembic revision head for CFMS 0.14.0 (`e952c02c1454`).
pub const LATEST_SCHEMA_REVISION: &str = "e952c02c1454";

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
