//! Backup component dependency closure, 40-table CFMS domain partitioning,
//! extension table discovery, and partial-export SQL filter construction.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use crate::cli::backup::BackupComponentArg;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::backend::DbPool;
use crate::db::schema::SchemaInspector;
use crate::db::schema::graph::infer_transfer_metadata;
use crate::db::schema::ir::{SchemaIr, TableOwnership};
use crate::db::transfer::{TransferTable, active_schema_subset, quote_ident, validate_oidc_table};
use crate::ops::backup::stream::{ExtensionTableBackupSpec, TableColumnSpec, TableSchemaSpec};

/// Logical CFMS backup components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackupComponent {
    Accounts,
    Documents,
    Audit,
    BannedSubnets,
    Configuration,
}

impl BackupComponent {
    pub const ALL: [Self; 5] = [
        Self::Accounts,
        Self::Documents,
        Self::Audit,
        Self::BannedSubnets,
        Self::Configuration,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Documents => "documents",
            Self::Audit => "audit",
            Self::BannedSubnets => "banned_subnets",
            Self::Configuration => "configuration",
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Accounts => {
                "Users, credentials, groups, permissions, keyrings, userblocks, schedules & extensions"
            }
            Self::Documents => {
                "Nodes, folders, documents, revisions, metadata, ACLs & rules (requires: accounts)"
            }
            Self::Audit => "Audit log entries (requires: accounts)",
            Self::BannedSubnets => "Banned IP subnets & linked reason comments",
            Self::Configuration => {
                "Database options & security secrets (`security.pepper`, `server.secret_key`)"
            }
        }
    }

    #[must_use]
    pub const fn dependencies(self) -> &'static [Self] {
        match self {
            Self::Documents | Self::Audit => &[Self::Accounts],
            Self::Accounts | Self::BannedSubnets | Self::Configuration => &[],
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "accounts" => Ok(Self::Accounts),
            "documents" => Ok(Self::Documents),
            "audit" => Ok(Self::Audit),
            "banned_subnets" => Ok(Self::BannedSubnets),
            "configuration" => Ok(Self::Configuration),
            other => Err(CfmsError::ArchiveIntegrity(format!(
                "Unknown backup component '{other}'"
            ))),
        }
    }
}

impl From<BackupComponentArg> for BackupComponent {
    fn from(arg: BackupComponentArg) -> Self {
        match arg {
            BackupComponentArg::Accounts => Self::Accounts,
            BackupComponentArg::Documents => Self::Documents,
            BackupComponentArg::Audit => Self::Audit,
            BackupComponentArg::BannedSubnets => Self::BannedSubnets,
            BackupComponentArg::Configuration => Self::Configuration,
        }
    }
}

/// Core runtime/ephemeral tables excluded from logical CFMS backups.
pub const EXCLUDED_RUNTIME_TABLES: &[&str] = &[
    "account_throttles",
    "file_tasks",
    "file_deduplication_tasks",
    "login_throttles",
    "rate_limit_buckets",
    "risk_ip_accounts",
    "schedule_executions",
    "scheduling_runtime_state",
    "system_states",
    "traffic_throttles",
];

pub const ACCOUNTS_TABLES: &[&str] = &[
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
    "userblock_entries",
    "userblock_sub_entries",
    "schedules",
];

pub const DOCUMENTS_TABLES: &[&str] = &[
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
];

pub const AUDIT_TABLES: &[&str] = &["audit_entries"];
pub const BANNED_SUBNETS_TABLES: &[&str] = &["banned_subnets"];
pub const CONFIGURATION_TABLES: &[&str] = &["options"];

/// Resolved dependency-closed selection of components.
#[derive(Debug, Clone)]
pub struct ComponentSelection {
    pub selected: Vec<BackupComponent>,
    pub auto_added: Vec<BackupComponent>,
}

impl ComponentSelection {
    /// Resolve dependency closure for user-requested components (preserving canonical order).
    pub fn resolve(requested: &[BackupComponent]) -> Result<Self> {
        if requested.is_empty() {
            return Err(CfmsError::InvalidArgument(
                "At least one backup component must be selected".to_string(),
            ));
        }
        let requested_set: BTreeSet<BackupComponent> = requested.iter().copied().collect();
        let mut closed = requested_set.clone();
        for comp in requested {
            for &dep in comp.dependencies() {
                closed.insert(dep);
            }
        }
        let selected: Vec<BackupComponent> = BackupComponent::ALL
            .into_iter()
            .filter(|c| closed.contains(c))
            .collect();
        let auto_added: Vec<BackupComponent> = selected
            .iter()
            .copied()
            .filter(|c| !requested_set.contains(c))
            .collect();
        Ok(Self {
            selected,
            auto_added,
        })
    }

    #[must_use]
    pub fn all() -> Self {
        Self {
            selected: BackupComponent::ALL.to_vec(),
            auto_added: Vec::new(),
        }
    }

    #[must_use]
    pub fn contains(&self, comp: BackupComponent) -> bool {
        self.selected.contains(&comp)
    }

    #[must_use]
    pub fn component_names(&self) -> Vec<String> {
        self.selected
            .iter()
            .map(|c| c.as_str().to_string())
            .collect()
    }
}

/// Validate a string component list read from an archive manifest (including dependency closure).
pub fn parse_and_validate_manifest_components(names: &[String]) -> Result<Vec<BackupComponent>> {
    if names.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive has an empty component list".to_string(),
        ));
    }
    let mut parsed = Vec::with_capacity(names.len());
    let mut seen = BTreeSet::new();
    for raw in names {
        let comp = BackupComponent::from_name(raw)?;
        if !seen.insert(comp) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive has duplicate component '{raw}'"
            )));
        }
        parsed.push(comp);
    }
    for &comp in &parsed {
        for &dep in comp.dependencies() {
            if !seen.contains(&dep) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Archive component '{}' requires '{}' which is missing from manifest",
                    comp.as_str(),
                    dep.as_str()
                )));
            }
        }
    }
    Ok(parsed)
}

/// Compute the exact set of core + extension table names expected for a component selection.
#[must_use]
pub fn expected_tables_for(
    components: &[BackupComponent],
    extension_tables: &[ExtensionTableBackupSpec],
) -> BTreeSet<String> {
    let comp_set: BTreeSet<BackupComponent> = components.iter().copied().collect();
    let mut tables = BTreeSet::new();

    if comp_set.contains(&BackupComponent::Accounts) {
        tables.extend(ACCOUNTS_TABLES.iter().map(|s| (*s).to_string()));
    }
    if comp_set.contains(&BackupComponent::Documents) {
        tables.extend(DOCUMENTS_TABLES.iter().map(|s| (*s).to_string()));
    }
    if comp_set.contains(&BackupComponent::Audit) {
        tables.extend(AUDIT_TABLES.iter().map(|s| (*s).to_string()));
    }
    if comp_set.contains(&BackupComponent::BannedSubnets) {
        tables.extend(BANNED_SUBNETS_TABLES.iter().map(|s| (*s).to_string()));
    }
    if comp_set.contains(&BackupComponent::Configuration) {
        tables.extend(CONFIGURATION_TABLES.iter().map(|s| (*s).to_string()));
    }

    if comp_set.contains(&BackupComponent::Accounts)
        || comp_set.contains(&BackupComponent::BannedSubnets)
    {
        tables.insert("comments".to_string());
    }
    if comp_set.contains(&BackupComponent::Accounts)
        || comp_set.contains(&BackupComponent::Documents)
    {
        tables.insert("files".to_string());
    }

    for ext in extension_tables {
        if let Ok(comp) = BackupComponent::from_name(&ext.backup_component)
            && comp_set.contains(&comp)
        {
            tables.insert(ext.table_name.clone());
        }
    }

    tables
}

/// Discover extension table ownership & backup component mappings for active extension tables.
pub fn resolve_extension_specs(
    ir: &SchemaIr,
    active_extensions: &[String],
    paths: Option<&WorkspacePaths>,
) -> Result<Vec<ExtensionTableBackupSpec>> {
    let mut specs = Vec::new();
    for ext_table_name in active_extensions {
        let Some(table_ir) = ir.tables.get(ext_table_name) else {
            return Err(CfmsError::Extension(format!(
                "Extension table '{ext_table_name}' is missing from resolved SchemaIr"
            )));
        };
        let owner = match &table_ir.ownership {
            TableOwnership::Extension(owner) => owner.clone(),
            TableOwnership::Core => {
                return Err(CfmsError::Extension(format!(
                    "Table '{ext_table_name}' is marked Core instead of Extension"
                )));
            }
        };

        let backup_component = if ext_table_name == "user_oidc_credentials" {
            "accounts".to_string()
        } else if let Some(comp) =
            read_extension_manifest_backup_component(paths, &owner).transpose()?
        {
            comp
        } else {
            infer_extension_component_from_fks(table_ir)
        };

        specs.push(ExtensionTableBackupSpec {
            table_name: ext_table_name.clone(),
            owner,
            backup_component,
        });
    }
    Ok(specs)
}

fn read_extension_manifest_backup_component(
    paths: Option<&WorkspacePaths>,
    owner: &str,
) -> Option<Result<String>> {
    let paths = paths?;
    let manifest_path = paths.extensions_root.join(owner).join("manifest.toml");
    if !manifest_path.is_file() {
        return None;
    }
    let raw = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => return Some(Err(CfmsError::Io(e))),
    };
    let parsed: toml::Value = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return Some(Err(CfmsError::Extension(format!(
                "Malformed manifest '{}': {e}",
                manifest_path.display()
            ))));
        }
    };
    let comp_str = parsed
        .get("backup")
        .and_then(|b| b.get("component"))
        .and_then(|v| v.as_str())?;
    match BackupComponent::from_name(comp_str) {
        Ok(comp) => Some(Ok(comp.as_str().to_string())),
        Err(e) => Some(Err(e)),
    }
}

fn infer_extension_component_from_fks(table: &crate::db::schema::ir::TableIr) -> String {
    for fk in &table.foreign_keys {
        match fk.ref_table.as_str() {
            "nodes" | "folders" | "documents" | "document_revisions" => {
                return "documents".to_string();
            }
            "audit_entries" => return "audit".to_string(),
            "banned_subnets" => return "banned_subnets".to_string(),
            "options" => return "configuration".to_string(),
            _ => {}
        }
    }
    "accounts".to_string()
}

/// Inspect the source database before exporting: verify revision at HEAD, zero schema drift,
/// zero unknown extra tables, and valid `user_oidc_credentials` digest invariants if present.
pub(crate) async fn prepare_source_export_plan(
    source: &DbPool,
    base_ir: &SchemaIr,
    paths: Option<&WorkspacePaths>,
    selection: &ComponentSelection,
) -> Result<SourceExportPlan> {
    let expected_revision = base_ir
        .schema_revision
        .as_deref()
        .ok_or_else(|| CfmsError::SchemaDrift("Resolved SchemaIr has no schema_revision".to_string()))?;

    let report = SchemaInspector::inspect_against_ir(source, base_ir).await?;
    let source_revision = match report.current_revision.as_deref() {
        Some(rev) if rev == expected_revision => rev.to_string(),
        Some(rev) => {
            return Err(CfmsError::SchemaDrift(format!(
                "Source database revision is '{rev}', expected HEAD '{expected_revision}'. Run `cfms-ctl database upgrade` first."
            )));
        }
        None => {
            return Err(CfmsError::SchemaDrift(
                "Source database has no Alembic revision stamped. Run `cfms-ctl database upgrade` first."
                    .to_string(),
            ));
        }
    };

    if !report.missing_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database is missing required CFMS tables: {}",
            report.missing_tables.join(", ")
        )));
    }
    if !report.column_mismatches.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database has column drift against expected schema: {}",
            report.column_mismatches.join("; ")
        )));
    }

    let (known_extensions, unknown_extra) = report.partition_extra_tables();
    if !unknown_extra.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Source database contains unsupported/unregistered extra tables: {}",
            unknown_extra.join(", ")
        )));
    }

    if known_extensions.iter().any(|t| t == "user_oidc_credentials") {
        validate_oidc_table(source).await?;
    }

    let extension_specs = resolve_extension_specs(base_ir, &known_extensions, paths)?;
    let selected_extension_specs: Vec<ExtensionTableBackupSpec> = extension_specs
        .into_iter()
        .filter(|ext| {
            BackupComponent::from_name(&ext.backup_component)
                .is_ok_and(|c| selection.contains(c))
        })
        .collect();
    let selected_ext_names: Vec<String> = selected_extension_specs
        .iter()
        .map(|e| e.table_name.clone())
        .collect();

    let wanted_tables = expected_tables_for(&selection.selected, &selected_extension_specs);
    let active_full_ir = active_schema_subset(base_ir, &selected_ext_names);
    let mut export_ir = SchemaIr::new(active_full_ir.source, Some(source_revision.clone()));
    for (name, table) in active_full_ir.tables {
        if wanted_tables.contains(&name) {
            export_ir.tables.insert(name, table);
        }
    }

    let (_, mut deferred_cols, ordered_names) =
        infer_transfer_metadata(&export_ir, source.kind());
    let use_node_hierarchy = wanted_tables.contains("nodes")
        && wanted_tables.contains("folders")
        && wanted_tables.contains("documents")
        && export_ir
            .tables
            .get("nodes")
            .is_some_and(|n| n.column("parent_id").is_some());
    if use_node_hierarchy && let Some(node_def) = deferred_cols.get_mut("nodes") {
        node_def.retain(|col| col != "parent_id");
    }

    let transfer_tables: BTreeMap<String, TransferTable> = export_ir
        .tables
        .iter()
        .map(|(name, t)| (name.clone(), TransferTable::from_ir(t)))
        .collect();

    let table_specs: BTreeMap<String, TableSchemaSpec> = transfer_tables
        .iter()
        .map(|(name, t)| {
            let cols = t.data_columns().map(TableColumnSpec::from).collect();
            (
                name.clone(),
                TableSchemaSpec {
                    columns: cols,
                    pk_columns: t.pk_columns.clone(),
                },
            )
        })
        .collect();

    Ok(SourceExportPlan {
        schema_revision: source_revision,
        extension_tables: selected_extension_specs,
        table_order: ordered_names,
        table_specs,
        transfer_tables,
        export_ir,
        use_node_hierarchy,
    })
}

/// Complete validated plan produced before opening the streaming export pipeline.
pub(crate) struct SourceExportPlan {
    pub schema_revision: String,
    pub extension_tables: Vec<ExtensionTableBackupSpec>,
    pub table_order: Vec<String>,
    pub table_specs: BTreeMap<String, TableSchemaSpec>,
    pub transfer_tables: BTreeMap<String, TransferTable>,
    pub export_ir: SchemaIr,
    pub use_node_hierarchy: bool,
}

/// Optional partial-export `WHERE` predicate for a table given selected components.
#[must_use]
pub fn partial_export_where_clause(
    table_name: &str,
    components: &[BackupComponent],
) -> Option<&'static str> {
    let has_accounts = components.contains(&BackupComponent::Accounts);
    let has_documents = components.contains(&BackupComponent::Documents);
    let has_banned_subnets = components.contains(&BackupComponent::BannedSubnets);

    match table_name {
        "comments" => match (has_accounts, has_banned_subnets) {
            (true, true) => None,
            (true, false) => Some(
                "comment_id IN (\
                    SELECT status_comment_id FROM users WHERE status_comment_id IS NOT NULL \
                    UNION \
                    SELECT reason_comment_id FROM userblock_entries WHERE reason_comment_id IS NOT NULL\
                )",
            ),
            (false, true) => Some(
                "comment_id IN (\
                    SELECT reason_comment_id FROM banned_subnets WHERE reason_comment_id IS NOT NULL\
                )",
            ),
            (false, false) => None,
        },
        "files" => match (has_accounts, has_documents) {
            (true, true) => None,
            (true, false) => {
                Some("id IN (SELECT avatar_id FROM users WHERE avatar_id IS NOT NULL)")
            }
            (false, true) => {
                Some("id IN (SELECT file_id FROM document_revisions WHERE file_id IS NOT NULL)")
            }
            (false, false) => None,
        },
        "object_access_entries" => Some("target_type IN ('document', 'directory')"),
        "compiled_access_rule_sets" => Some(
            "EXISTS (SELECT 1 FROM nodes n WHERE n.access_rule_set_id = compiled_access_rule_sets.id AND compiled_access_rule_sets.node_id = n.id) \
             AND EXISTS (SELECT 1 FROM compiled_access_rules r WHERE r.rule_set_id = compiled_access_rule_sets.id)",
        ),
        "compiled_access_rules" => Some(
            "rule_set_id IN (\
                SELECT s.id FROM compiled_access_rule_sets s \
                JOIN nodes n ON n.access_rule_set_id = s.id AND s.node_id = n.id \
                WHERE EXISTS (SELECT 1 FROM compiled_access_rules r2 WHERE r2.rule_set_id = s.id)\
            )",
        ),
        "compiled_access_rule_groups" => Some(
            "rule_id IN (\
                SELECT r.id FROM compiled_access_rules r \
                JOIN compiled_access_rule_sets s ON r.rule_set_id = s.id \
                JOIN nodes n ON n.access_rule_set_id = s.id AND s.node_id = n.id\
            )",
        ),
        "compiled_access_rule_memberships" | "compiled_access_rule_rights" => Some(
            "group_id IN (\
                SELECT g.id FROM compiled_access_rule_groups g \
                JOIN compiled_access_rules r ON g.rule_id = r.id \
                JOIN compiled_access_rule_sets s ON r.rule_set_id = s.id \
                JOIN nodes n ON n.access_rule_set_id = s.id AND s.node_id = n.id\
            )",
        ),
        _ => None,
    }
}

/// Query the set of active `compiled_access_rule_set` IDs actually bound to their matching `nodes`.
pub async fn fetch_active_rule_set_ids(pool: &DbPool) -> Result<HashSet<String>> {
    let kind = pool.kind();
    let sql = format!(
        "SELECT s.{id} FROM {sets} s \
         JOIN {nodes} n ON n.{ars_id} = s.{id} AND s.{node_id} = n.{id} \
         WHERE EXISTS (SELECT 1 FROM {rules} r WHERE r.{rule_set_id} = s.{id})",
        id = quote_ident(kind, "id"),
        sets = quote_ident(kind, "compiled_access_rule_sets"),
        nodes = quote_ident(kind, "nodes"),
        ars_id = quote_ident(kind, "access_rule_set_id"),
        node_id = quote_ident(kind, "node_id"),
        rules = quote_ident(kind, "compiled_access_rules"),
        rule_set_id = quote_ident(kind, "rule_set_id"),
    );
    let rows: Vec<String> = match pool {
        DbPool::Sqlite(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?,
        DbPool::Mysql(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?,
        DbPool::Postgres(p) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_all(p).await?,
    };
    Ok(rows.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::registry::APPLICATION_TABLE_NAMES;

    #[test]
    fn all_40_core_tables_are_explicitly_partitioned_without_gaps_or_overlaps() {
        let backed_up = expected_tables_for(&BackupComponent::ALL, &[]);
        assert_eq!(backed_up.len(), 30);

        let excluded: BTreeSet<String> = EXCLUDED_RUNTIME_TABLES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(excluded.len(), 10);

        assert!(backed_up.is_disjoint(&excluded));

        let mut combined = backed_up;
        combined.extend(excluded);
        let expected_all: BTreeSet<String> = APPLICATION_TABLE_NAMES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(combined, expected_all);
    }

    #[test]
    fn component_dependencies_auto_close_cleanly() {
        let sel = ComponentSelection::resolve(&[BackupComponent::Documents]).unwrap();
        assert_eq!(
            sel.selected,
            vec![BackupComponent::Accounts, BackupComponent::Documents]
        );
        assert_eq!(sel.auto_added, vec![BackupComponent::Accounts]);

        assert!(
            parse_and_validate_manifest_components(&["documents".to_string()]).is_err()
        );
        assert!(
            parse_and_validate_manifest_components(&[
                "accounts".to_string(),
                "accounts".to_string()
            ])
            .is_err()
        );
    }
}