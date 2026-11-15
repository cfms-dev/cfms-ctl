//! Graph-based dependency planning for `cfms-ctl extension enable` and `disable`.
//!
//! Computes an immutable selection plan once against a loaded `ConfigDocument` and
//! `ExtensionCatalog`, validates compatibility and schema constraints before any
//! disk write, and preserves existing `[extensions].enabled` ordering and TOML comments.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use serde::Serialize;
use crate::core::{CfmsError, ConfigDocument, Result, WorkspacePaths};
use crate::ops::extension::catalog::{
    BUILTIN_EXTENSION_ID, CatalogDiagnostic, ExtensionCatalog, InstalledExtension,
    MAX_EXTENSION_SCAN_ENTRIES, RETIRED_EXTENSION_IDS, RESERVED_EXTENSION_IDS, StagingMarker,
    UninstallTarget, declared_data_module, declared_option_namespaces, ensure_not_retired,
    read_enabled_config, validate_extension_identifier,
};
use crate::ops::extension::package::VerifiedExtensionPackage;
use crate::ops::extension::version::{
    DetectedServerVersion, check_server_compatibility, discover_server_version,
    parse_pep440_version,
};

/// Planned `config.toml` update computed in a single pass before confirmation/write.
#[derive(Debug, Clone)]
pub struct ExtensionTogglePlan {
    pub action: ToggleAction,
    pub targets: Vec<String>,
    pub changed: bool,
    pub previous_enabled: Vec<String>,
    pub next_enabled: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub cascade_dependents: Vec<String>,
    pub already_in_desired_state: Vec<String>,
    pub removed_uninstalled: Vec<String>,
    pub reordered_existing: bool,
    pub server_version: DetectedServerVersion,
    pub warnings: Vec<String>,
    pub candidate_doc: ConfigDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToggleAction {
    Enable,
    Disable,
}

impl ToggleAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
        }
    }
}

/// Plan `cfms-ctl extension enable <IDENTIFIER>...` in memory without modifying disk.
pub fn plan_enable(
    catalog: &ExtensionCatalog,
    config_doc: &ConfigDocument,
    paths: &WorkspacePaths,
    raw_targets: &[String],
    schema_path: Option<&Path>,
) -> Result<ExtensionTogglePlan> {
    let targets = normalize_targets(raw_targets)?;
    for id in &targets {
        if id == BUILTIN_EXTENSION_ID {
            return Err(CfmsError::Extension(
                "Extension 'builtin' is always enabled and cannot be modified".to_string(),
            ));
        }
        ensure_not_retired(id)?;
        ensure_usable_extension(catalog, id, None)?;
    }

    let prev_state = read_enabled_config(config_doc, false)?;
    let previous_enabled = prev_state.entries;

    // Fail safely when the target workspace server version cannot be determined.
    let server = discover_server_version(paths)?;

    // Check currently installed built-in extension compatibility when present on disk.
    if let Some(builtin_ext) = catalog.extensions.get(BUILTIN_EXTENSION_ID) {
        check_extension_server_compat(builtin_ext, &server)?;
    }

    let prev_set: BTreeSet<String> = previous_enabled.iter().cloned().collect();
    let target_set: BTreeSet<String> = targets.iter().cloned().collect();

    // Traverse both newly requested targets and existing enabled entries so dependencies,
    // version constraints, cycles, and compatibility are verified for the entire active set.
    let mut visited = BTreeSet::new();
    let mut dfs_target_postorder = Vec::new();
    let mut active_closure = BTreeSet::new();
    let mut visit_state: HashMap<String, DfsMark> = HashMap::new();
    let mut dfs_stack: Vec<String> = Vec::new();

    for root in &previous_enabled {
        resolve_dependency_dfs(
            root,
            catalog,
            &server,
            &prev_set,
            false,
            &mut visit_state,
            &mut dfs_stack,
            &mut visited,
            &mut active_closure,
            None,
        )?;
    }
    for root in &targets {
        resolve_dependency_dfs(
            root,
            catalog,
            &server,
            &prev_set,
            true,
            &mut visit_state,
            &mut dfs_stack,
            &mut visited,
            &mut active_closure,
            Some(&mut dfs_target_postorder),
        )?;
    }

    let mut warnings = Vec::new();
    check_scoped_staging_markers(
        &catalog.staging_markers,
        &active_closure,
        &target_set,
        &mut warnings,
        true,
    )?;

    // Build priority order: keep existing entries in their original positions first, then
    // append newly introduced extensions/dependencies in dependency-first DFS order.
    let mut needed_priority: Vec<String> = previous_enabled
        .iter()
        .filter(|id| id.as_str() != BUILTIN_EXTENSION_ID)
        .cloned()
        .collect();
    for id in active_closure {
        if id != BUILTIN_EXTENSION_ID && !prev_set.contains(&id) && !dfs_target_postorder.contains(&id)
        {
            needed_priority.push(id);
        }
    }
    for id in dfs_target_postorder {
        if id != BUILTIN_EXTENSION_ID && !prev_set.contains(&id) {
            needed_priority.push(id);
        }
    }

    let next_enabled = topo_sort_preserving_priority(catalog, &needed_priority);
    let added: Vec<String> = next_enabled
        .iter()
        .filter(|id| !prev_set.contains(*id))
        .cloned()
        .collect();
    let already_in_desired_state: Vec<String> = targets
        .iter()
        .filter(|id| prev_set.contains(*id))
        .cloned()
        .collect();
    let changed = next_enabled != previous_enabled;
    let reordered_existing = changed && added.is_empty();

    let mut candidate_doc = config_doc.clone();
    if changed {
        let schema_warnings = candidate_doc.set_extensions_enabled(&next_enabled, schema_path)?;
        warnings.extend(schema_warnings);
    } else if schema_path.is_some() {
        let schema_warnings = candidate_doc.validate_with_schema(schema_path)?;
        warnings.extend(schema_warnings);
    }

    Ok(ExtensionTogglePlan {
        action: ToggleAction::Enable,
        targets,
        changed,
        previous_enabled,
        next_enabled,
        added,
        removed: Vec::new(),
        cascade_dependents: Vec::new(),
        already_in_desired_state,
        removed_uninstalled: Vec::new(),
        reordered_existing,
        server_version: server,
        warnings,
        candidate_doc,
    })
}

/// Plan `cfms-ctl extension disable <IDENTIFIER>...` in memory without modifying disk.
///
/// Unlike legacy tooling, any identifier present in `[extensions].enabled` (including
/// retired or missing-on-disk extensions) can be cleanly disabled even when sibling
/// extensions have broken manifests.
pub fn plan_disable(
    catalog: &ExtensionCatalog,
    config_doc: &ConfigDocument,
    paths: &WorkspacePaths,
    raw_targets: &[String],
    schema_path: Option<&Path>,
) -> Result<ExtensionTogglePlan> {
    let targets = normalize_targets(raw_targets)?;
    for id in &targets {
        if id == BUILTIN_EXTENSION_ID {
            return Err(CfmsError::Extension(
                "Extension 'builtin' is always enabled and cannot be disabled".to_string(),
            ));
        }
    }

    let prev_state = read_enabled_config(config_doc, true)?;
    let previous_enabled = prev_state.entries;
    let prev_set: BTreeSet<String> = previous_enabled.iter().cloned().collect();
    let target_set: BTreeSet<String> = targets.iter().cloned().collect();

    let mut removed_uninstalled = Vec::new();
    let mut already_in_desired_state = Vec::new();
    for id in &targets {
        if prev_set.contains(id) {
            if !catalog.extensions.contains_key(id) {
                removed_uninstalled.push(id.clone());
            }
        } else if catalog.extensions.contains_key(id)
            || catalog.conflicted_identifiers.contains_key(id)
            || catalog.diagnostic_for(id).is_some()
        {
            already_in_desired_state.push(id.clone());
        } else {
            return Err(CfmsError::Extension(format!(
                "Extension '{id}' is not installed under '{}' and is not enabled in '{}'",
                catalog.extensions_root.display(),
                paths.config_path.display()
            )));
        }
    }

    let mut warnings = Vec::new();
    check_scoped_staging_markers(
        &catalog.staging_markers,
        &target_set,
        &target_set,
        &mut warnings,
        false,
    )?;

    // Build reverse dependency graph and compute transitive closure of dependents to disable.
    let (next_enabled, removed, cascade_dependents) =
        compute_disable_closure(catalog, &previous_enabled, &target_set, &mut warnings);

    let changed = next_enabled != previous_enabled;
    let mut candidate_doc = config_doc.clone();
    if changed {
        let schema_warnings = candidate_doc.set_extensions_enabled(&next_enabled, schema_path)?;
        warnings.extend(schema_warnings);
    } else if schema_path.is_some() {
        let schema_warnings = candidate_doc.validate_with_schema(schema_path)?;
        warnings.extend(schema_warnings);
    }

    let detected_server = discover_server_version(paths)?;

    Ok(ExtensionTogglePlan {
        action: ToggleAction::Disable,
        targets,
        changed,
        previous_enabled,
        next_enabled,
        added: Vec::new(),
        removed,
        cascade_dependents,
        already_in_desired_state,
        removed_uninstalled,
        reordered_existing: false,
        server_version: detected_server,
        warnings,
        candidate_doc,
    })
}

/// Planned local package installation computed before extracting files to disk.
#[derive(Debug, Clone)]
pub struct ExtensionInstallPlan {
    pub identifier: String,
    pub display_name: String,
    pub version: String,
    pub target_directory: PathBuf,
    pub package_sha256: String,
    pub server_version: DetectedServerVersion,
    pub warnings: Vec<String>,
}

/// Planned third-party extension upgrade computed before swapping directories or updating config.
#[derive(Debug, Clone)]
pub struct ExtensionUpgradePlan {
    pub identifier: String,
    pub display_name: String,
    pub previous_version: String,
    pub version: String,
    pub target_directory: PathBuf,
    pub package_sha256: String,
    pub was_enabled: bool,
    pub next_enabled: Vec<String>,
    pub auto_enabled: Vec<String>,
    pub config_changed: bool,
    pub candidate_doc: ConfigDocument,
    pub server_version: DetectedServerVersion,
    pub warnings: Vec<String>,
}

/// Resolved extension module specification for isolated Python hook execution.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionLoadEntry {
    pub identifier: String,
    pub directory: PathBuf,
    pub entrypoint: PathBuf,
    pub option_namespaces: Vec<String>,
}

/// Planned extension uninstallation (healthy or broken directory) computed before mutation.
#[derive(Debug, Clone)]
pub struct ExtensionUninstallPlan {
    pub identifier: String,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub target_directory: PathBuf,
    pub entrypoint_path: PathBuf,
    pub broken_target: bool,
    pub data_module: Option<String>,
    pub option_namespaces: Vec<String>,
    pub load_closure: Vec<ExtensionLoadEntry>,
    pub dependency_error: Option<String>,
    pub purge_data: bool,
    pub disabled_extensions: Vec<String>,
    pub cascade_dependents: Vec<String>,
    pub config_changed: bool,
    pub candidate_doc: ConfigDocument,
    pub warnings: Vec<String>,
}

/// Planned target metadata, fault-isolated dependency closure, and blockers for `extension purge-data`.
#[derive(Debug, Clone)]
pub struct ExtensionPurgeDataPlan {
    pub identifier: String,
    pub installed: bool,
    pub broken_target: bool,
    pub retired_identifier: bool,
    pub currently_enabled: bool,
    pub blockers: Vec<String>,
    pub options_only: bool,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub target_directory: Option<PathBuf>,
    pub entrypoint_path: Option<PathBuf>,
    pub data_module: Option<String>,
    pub option_namespaces: Vec<String>,
    pub load_closure: Vec<ExtensionLoadEntry>,
    pub dependency_error: Option<String>,
    pub warnings: Vec<String>,
}

/// Plan `cfms-ctl extension install <PACKAGE>` against the catalog, release ownership, and config.
pub fn plan_install(
    package: &VerifiedExtensionPackage,
    catalog: &ExtensionCatalog,
    config_doc: &ConfigDocument,
    paths: &WorkspacePaths,
    managed_extensions: &BTreeSet<String>,
) -> Result<ExtensionInstallPlan> {
    let manifest = &package.manifest;
    let id = &manifest.identifier;
    validate_extension_identifier(id)?;
    ensure_not_retired(id)?;

    if id == BUILTIN_EXTENSION_ID
        || RESERVED_EXTENSION_IDS.contains(&id.as_str())
        || managed_extensions.contains(id)
    {
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' is managed by the CFMS server release and cannot be installed separately"
        )));
    }

    if let Some(dirs) = catalog.conflicted_identifiers.get(id) {
        let joined = dirs
            .iter()
            .map(|p| format!("'{}'", p.display()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' already has conflicting installations on disk: {joined}"
        )));
    }
    if let Some(existing) = catalog.extensions.get(id) {
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' (version {}) is already installed at '{}'; use `cfms-ctl extension upgrade` instead",
            existing.raw.extension.version,
            existing.directory.display()
        )));
    }
    if let Some(diag) = catalog.diagnostic_for(id) {
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' has an existing broken directory at '{}' ({}); uninstall or remove it before installing",
            diag.directory.display(),
            diag.message
        )));
    }

    if let Some(collision) = catalog
        .root_entry_names_lower
        .get(&id.to_ascii_lowercase())
    {
        return Err(CfmsError::Extension(format!(
            "Cannot install extension '{id}': conflicting entry '{}' already exists under '{}'",
            collision.display(),
            catalog.extensions_root.display()
        )));
    }

    if catalog.root_entry_count >= MAX_EXTENSION_SCAN_ENTRIES {
        return Err(CfmsError::Extension(format!(
            "Extension directory '{}' already has {MAX_EXTENSION_SCAN_ENTRIES} entries",
            catalog.extensions_root.display()
        )));
    }

    let mut warnings = Vec::new();
    let target_set = BTreeSet::from([id.clone()]);
    check_scoped_staging_markers(
        &catalog.staging_markers,
        &target_set,
        &target_set,
        &mut warnings,
        true,
    )?;

    if let Ok(enabled_state) = read_enabled_config(config_doc, true)
        && enabled_state.entries.iter().any(|entry| entry == id)
    {
        warnings.push(format!(
            "Extension '{id}' is already listed in '{}' [extensions].enabled; verify compatibility and re-run `cfms-ctl extension enable {id}` or restart cautiously",
            paths.config_path.display()
        ));
    }

    let server_version = discover_server_version(paths)?;
    collect_manifest_advisories(
        manifest,
        catalog,
        &server_version,
        &mut warnings,
    );

    Ok(ExtensionInstallPlan {
        identifier: id.clone(),
        display_name: manifest.display_name.clone(),
        version: manifest.raw.extension.version.clone(),
        target_directory: catalog.extensions_root.join(id),
        package_sha256: package.package_sha256.clone(),
        server_version,
        warnings,
    })
}

/// Plan `cfms-ctl extension upgrade <PACKAGE>` against the installed catalog, enabled graph,
/// server compatibility, and existing dependents.
pub fn plan_upgrade(
    package: &VerifiedExtensionPackage,
    catalog: &ExtensionCatalog,
    config_doc: &ConfigDocument,
    paths: &WorkspacePaths,
    managed_extensions: &BTreeSet<String>,
    schema_path: Option<&Path>,
) -> Result<ExtensionUpgradePlan> {
    let new_manifest = &package.manifest;
    let id = &new_manifest.identifier;
    validate_extension_identifier(id)?;
    ensure_not_retired(id)?;

    if id == BUILTIN_EXTENSION_ID
        || RESERVED_EXTENSION_IDS.contains(&id.as_str())
        || managed_extensions.contains(id)
    {
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' is managed by the CFMS server release and cannot be upgraded via package install; upgrade the CFMS server deployment instead"
        )));
    }

    if let Some(dirs) = catalog.conflicted_identifiers.get(id) {
        let joined = dirs
            .iter()
            .map(|p| format!("'{}'", p.display()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' has duplicate definitions in {joined}; resolve duplicates before upgrading"
        )));
    }

    let installed = match catalog.extensions.get(id) {
        Some(ext) => ext,
        None => {
            if let Some(diag) = catalog.diagnostic_for(id) {
                return Err(CfmsError::Extension(format!(
                    "Installed extension '{id}' at '{}' is broken ({}) and cannot be version-compared; uninstall it first and run `install` instead",
                    diag.directory.display(),
                    diag.message
                )));
            }
            return Err(CfmsError::Extension(format!(
                "Extension '{id}' is not installed under '{}'; use `cfms-ctl extension install` instead",
                catalog.extensions_root.display()
            )));
        }
    };

    let old_ver_str = &installed.raw.extension.version;
    let new_ver_str = &new_manifest.raw.extension.version;
    let old_pep440 = installed
        .pep440_version
        .clone()
        .or_else(|| parse_pep440_version(old_ver_str).ok())
        .ok_or_else(|| {
            CfmsError::Extension(format!(
                "Installed extension '{id}' version '{old_ver_str}' is not valid PEP 440; cannot verify upgrade ordering"
            ))
        })?;
    let new_pep440 = new_manifest
        .pep440_version
        .clone()
        .or_else(|| parse_pep440_version(new_ver_str).ok())
        .ok_or_else(|| {
            CfmsError::Extension(format!(
                "Package extension '{id}' version '{new_ver_str}' is not valid PEP 440"
            ))
        })?;

    if new_pep440 <= old_pep440 {
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' upgrade requires a strictly newer version than installed '{old_ver_str}' (package is '{new_ver_str}')"
        )));
    }

    let enabled_state = read_enabled_config(config_doc, true)?;
    let previous_enabled = enabled_state.entries;
    let prev_set: BTreeSet<String> = previous_enabled.iter().cloned().collect();
    let was_enabled = prev_set.contains(id);

    let mut warnings = Vec::new();

    // Reverse-dependent constraint verification: never silently break currently enabled dependents.
    for (sib_id, sib_ext) in &catalog.extensions {
        if sib_id == id {
            continue;
        }
        if let Some(parsed_dep) = sib_ext.dependencies.get(id)
            && !parsed_dep.constraint.matches(&new_pep440)
        {
            if prev_set.contains(sib_id) {
                return Err(CfmsError::Extension(format!(
                    "Cannot upgrade '{id}' to '{new_ver_str}': enabled extension '{sib_id}' requires '{id}' {}",
                    parsed_dep.constraint.requirement_summary()
                )));
            }
            warnings.push(format!(
                "Disabled extension '{sib_id}' requires '{id}' {}, which will not match upgraded version '{new_ver_str}'",
                parsed_dep.constraint.requirement_summary()
            ));
        }
    }

    // Simulate the upgraded catalog to validate dependency closure and server compatibility.
    let mut future_catalog = catalog.clone();
    future_catalog
        .extensions
        .insert(id.clone(), new_manifest.clone());

    let server_version = discover_server_version(paths)?;
    let mut next_enabled = previous_enabled.clone();
    let mut auto_enabled = Vec::new();

    if was_enabled {
        let mut closure_targets = Vec::new();
        let mut visited = BTreeSet::new();
        let mut active_closure = BTreeSet::new();
        let mut visit_state: HashMap<String, DfsMark> = HashMap::new();
        let mut dfs_stack = Vec::new();

        resolve_dependency_dfs(
            id,
            &future_catalog,
            &server_version,
            &prev_set,
            true,
            &mut visit_state,
            &mut dfs_stack,
            &mut visited,
            &mut active_closure,
            Some(&mut closure_targets),
        )?;

        let newly_added: Vec<String> = closure_targets
            .into_iter()
            .filter(|dep| !prev_set.contains(dep))
            .collect();

        if !newly_added.is_empty() {
            let mut priority_order = previous_enabled.clone();
            priority_order.extend(newly_added);
            next_enabled = topo_sort_preserving_priority(&future_catalog, &priority_order);
            auto_enabled = next_enabled
                .iter()
                .filter(|item| !prev_set.contains(*item))
                .cloned()
                .collect();
        }
    } else {
        collect_manifest_advisories(
            new_manifest,
            &future_catalog,
            &server_version,
            &mut warnings,
        );
    }

    let direct_set = BTreeSet::from([id.clone()]);
    let mut affected_set = direct_set.clone();
    affected_set.extend(auto_enabled.iter().cloned());
    check_scoped_staging_markers(
        &catalog.staging_markers,
        &affected_set,
        &direct_set,
        &mut warnings,
        true,
    )?;

    let config_changed = next_enabled != previous_enabled;
    let mut candidate_doc = config_doc.clone();
    if config_changed {
        let schema_warnings = candidate_doc.set_extensions_enabled(&next_enabled, schema_path)?;
        warnings.extend(schema_warnings);
    }

    Ok(ExtensionUpgradePlan {
        identifier: id.clone(),
        display_name: new_manifest.display_name.clone(),
        previous_version: old_ver_str.clone(),
        version: new_ver_str.clone(),
        target_directory: installed.directory.clone(),
        package_sha256: package.package_sha256.clone(),
        was_enabled,
        next_enabled,
        auto_enabled,
        config_changed,
        candidate_doc,
        server_version,
        warnings,
    })
}

/// Plan `cfms-ctl extension uninstall <IDENTIFIER>` (supporting broken diagnostic targets).
pub fn plan_uninstall(
    identifier: &str,
    purge_data: bool,
    catalog: &ExtensionCatalog,
    config_doc: &ConfigDocument,
    managed_extensions: &BTreeSet<String>,
    schema_path: Option<&Path>,
) -> Result<ExtensionUninstallPlan> {
    validate_extension_identifier(identifier)?;

    if identifier == BUILTIN_EXTENSION_ID
        || RESERVED_EXTENSION_IDS.contains(&identifier)
        || managed_extensions.contains(identifier)
    {
        return Err(CfmsError::Extension(format!(
            "Extension '{identifier}' is managed by the CFMS server release and cannot be uninstalled"
        )));
    }

    let resolved = catalog.resolve_uninstall_target(identifier)?;
    let (
        target_directory,
        entrypoint_path,
        display_name,
        version,
        broken_target,
        data_module,
        option_namespaces,
        load_closure,
        dependency_error,
    ) = match resolved {
        UninstallTarget::Installed(ext) => {
            let (closure, dep_err) = match resolve_target_load_closure(catalog, identifier) {
                Ok(entries) => (entries, None),
                Err(err) => (Vec::new(), Some(err)),
            };
            (
                ext.directory.clone(),
                ext.entrypoint.clone(),
                Some(ext.display_name.clone()),
                Some(ext.raw.extension.version.clone()),
                false,
                declared_data_module(&ext.raw).map(ToString::to_string),
                declared_option_namespaces(&ext.raw),
                closure,
                dep_err,
            )
        }
        UninstallTarget::Broken(diag) => (
            diag.directory.clone(),
            diag.directory.join(crate::ops::extension::catalog::ENTRYPOINT_FILENAME),
            None,
            None,
            true,
            None,
            Vec::new(),
            Vec::new(),
            None,
        ),
    };

    let enabled_state = read_enabled_config(config_doc, true)?;
    let previous_enabled = enabled_state.entries;
    let target_set = BTreeSet::from([identifier.to_string()]);
    let mut warnings = Vec::new();
    if broken_target {
        warnings.push(format!(
            "Target extension directory '{}' failed normal manifest/entrypoint loading; proceeding with cleanup uninstall",
            target_directory.display()
        ));
    }

    let (next_enabled, disabled_extensions, cascade_dependents) =
        compute_disable_closure(catalog, &previous_enabled, &target_set, &mut warnings);

    let mut affected_set = target_set.clone();
    affected_set.extend(disabled_extensions.iter().cloned());
    check_scoped_staging_markers(
        &catalog.staging_markers,
        &affected_set,
        &target_set,
        &mut warnings,
        true,
    )?;

    let config_changed = next_enabled != previous_enabled;
    let mut candidate_doc = config_doc.clone();
    if config_changed {
        let schema_warnings = candidate_doc.set_extensions_enabled(&next_enabled, schema_path)?;
        warnings.extend(schema_warnings);
    }

    Ok(ExtensionUninstallPlan {
        identifier: identifier.to_string(),
        display_name,
        version,
        target_directory,
        entrypoint_path,
        broken_target,
        data_module,
        option_namespaces,
        load_closure,
        dependency_error,
        purge_data,
        disabled_extensions,
        cascade_dependents,
        config_changed,
        candidate_doc,
        warnings,
    })
}

/// Plan `cfms-ctl extension purge-data <IDENTIFIER>` without acquiring locks or importing Python code.
pub fn plan_purge_data(
    identifier: &str,
    options_only: bool,
    dry_run: bool,
    catalog: &ExtensionCatalog,
    config_doc: &ConfigDocument,
    paths: &WorkspacePaths,
) -> Result<ExtensionPurgeDataPlan> {
    if identifier == BUILTIN_EXTENSION_ID || RESERVED_EXTENSION_IDS.contains(&identifier) {
        return Err(CfmsError::Extension(format!(
            "Built-in/core data owned by '{identifier}' cannot be purged as extension data"
        )));
    }
    validate_extension_identifier(identifier)?;
    let server_version = discover_server_version(paths)?;

    let retired_identifier = RETIRED_EXTENSION_IDS.contains(&identifier);
    let enabled_state = read_enabled_config(config_doc, true)?;
    let currently_enabled = enabled_state.entries.iter().any(|entry| entry == identifier);
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    if currently_enabled {
        let msg = format!(
            "Extension '{identifier}' is currently enabled in config.toml; run `cfms-ctl extension disable {identifier}` before applying purge-data"
        );
        if !dry_run {
            return Err(CfmsError::Extension(msg));
        }
        blockers.push(msg.clone());
        warnings.push(msg);
    }

    let mut installed = false;
    let mut broken_target = false;
    let mut display_name = None;
    let mut version = None;
    let mut target_directory = None;
    let mut entrypoint_path = None;
    let mut data_module = None;
    let mut option_namespaces = Vec::new();
    let mut load_closure = Vec::new();
    let mut dependency_error = None;

    if let Some(conflict_dirs) = catalog.conflicted_identifiers.get(identifier) {
        let joined = conflict_dirs
            .iter()
            .map(|p| format!("'{}'", p.display()))
            .collect::<Vec<_>>()
            .join(", ");
        if !options_only {
            return Err(CfmsError::Extension(format!(
                "Extension '{identifier}' has duplicate definitions in {joined}; resolve the conflict or pass --options-only to clean options and system states"
            )));
        }
        broken_target = true;
        warnings.push(format!(
            "Extension '{identifier}' has duplicate definitions in {joined}; skipping code and custom data tables under --options-only"
        ));
    } else if let Some(ext) = catalog.extensions.get(identifier) {
        installed = true;
        display_name = Some(ext.display_name.clone());
        version = Some(ext.raw.extension.version.clone());
        target_directory = Some(ext.directory.clone());
        entrypoint_path = Some(ext.entrypoint.clone());
        data_module = declared_data_module(&ext.raw).map(ToString::to_string);
        option_namespaces = declared_option_namespaces(&ext.raw);

        collect_manifest_advisories(ext, catalog, &server_version, &mut warnings);

        if !options_only {
            match resolve_target_load_closure(catalog, identifier) {
                Ok(entries) => load_closure = entries,
                Err(err) => {
                    warnings.push(format!(
                        "Dependency closure for '{identifier}' could not be resolved ({err}); Python `ext_purge_data` hooks cannot run without fixing dependencies or passing --options-only"
                    ));
                    dependency_error = Some(err);
                }
            }
        }
    } else if let Some(diag) = catalog.diagnostic_for(identifier) {
        if !options_only {
            return Err(CfmsError::Extension(format!(
                "Extension '{identifier}' at '{}' is broken ({}); repair it or pass --options-only to purge owned options and system states without executing extension code",
                diag.directory.display(),
                diag.message
            )));
        }
        broken_target = true;
        warnings.push(format!(
            "Extension directory '{}' failed manifest/entrypoint checks ({}); skipping code and custom data tables under --options-only",
            diag.directory.display(),
            diag.message
        ));
    } else {
        if !options_only {
            return Err(CfmsError::Extension(format!(
                "Extension '{identifier}' is not installed under '{}'; pass --options-only to remove orphaned options and system states",
                paths.extensions_root.display()
            )));
        }
        if retired_identifier {
            warnings.push(format!(
                "Target '{identifier}' is a retired extension identifier; cleaning orphaned options and system states only"
            ));
        } else {
            warnings.push(format!(
                "Extension '{identifier}' is not installed on disk; cleaning orphaned options and system states only"
            ));
        }
    }

    let target_set = BTreeSet::from([identifier.to_string()]);
    if dry_run && !options_only {
        if let Err(err) = check_scoped_staging_markers(
            &catalog.staging_markers,
            &target_set,
            &target_set,
            &mut warnings,
            true,
        ) {
            let msg = err.to_string();
            blockers.push(msg.clone());
            warnings.push(msg);
        }
    } else {
        check_scoped_staging_markers(
            &catalog.staging_markers,
            &target_set,
            &target_set,
            &mut warnings,
            !options_only,
        )?;
    }

    Ok(ExtensionPurgeDataPlan {
        identifier: identifier.to_string(),
        installed,
        broken_target,
        retired_identifier,
        currently_enabled,
        blockers,
        options_only,
        display_name,
        version,
        target_directory,
        entrypoint_path,
        data_module,
        option_namespaces,
        load_closure,
        dependency_error,
        warnings,
    })
}

/// Resolve the topological (`dependencies -> target`) load closure for `target_id` without
/// aborting on unrelated broken sibling extensions or server version constraints.
fn resolve_target_load_closure(
    catalog: &ExtensionCatalog,
    target_id: &str,
) -> std::result::Result<Vec<ExtensionLoadEntry>, String> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Visiting,
        Visited,
    }

    fn visit(
        id: &str,
        catalog: &ExtensionCatalog,
        states: &mut HashMap<String, State>,
        stack: &mut Vec<String>,
        out: &mut Vec<ExtensionLoadEntry>,
    ) -> std::result::Result<(), String> {
        if let Some(state) = states.get(id) {
            return match state {
                State::Visited => Ok(()),
                State::Visiting => {
                    let pos = stack.iter().position(|item| item == id).unwrap_or(0);
                    let mut cycle = stack[pos..].to_vec();
                    cycle.push(id.to_string());
                    Err(format!("dependency cycle detected: {}", cycle.join(" -> ")))
                }
            };
        }

        if let Some(dirs) = catalog.conflicted_identifiers.get(id) {
            let joined = dirs
                .iter()
                .map(|p| format!("'{}'", p.display()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "dependency '{id}' has duplicate conflicting definitions in {joined}"
            ));
        }

        let Some(ext) = catalog.extensions.get(id) else {
            if let Some(diag) = catalog.diagnostic_for(id) {
                return Err(format!(
                    "dependency '{id}' at '{}' is broken ({})",
                    diag.directory.display(),
                    diag.message
                ));
            }
            return Err(format!("required dependency '{id}' is not installed"));
        };

        states.insert(id.to_string(), State::Visiting);
        stack.push(id.to_string());
        for dep_id in ext.dependencies.keys() {
            visit(dep_id, catalog, states, stack, out)?;
        }
        stack.pop();
        states.insert(id.to_string(), State::Visited);

        out.push(ExtensionLoadEntry {
            identifier: ext.identifier.clone(),
            directory: ext.directory.clone(),
            entrypoint: ext.entrypoint.clone(),
            option_namespaces: declared_option_namespaces(&ext.raw),
        });
        Ok(())
    }

    let mut states = HashMap::new();
    let mut stack = Vec::new();
    let mut out = Vec::new();
    visit(target_id, catalog, &mut states, &mut stack, &mut out)?;
    Ok(out)
}

fn collect_manifest_advisories(
    ext: &InstalledExtension,
    catalog: &ExtensionCatalog,
    server: &DetectedServerVersion,
    warnings: &mut Vec<String>,
) {
    if let Err(reason) = check_server_compatibility(
        &server.version,
        ext.minimum_server_version.as_ref(),
        ext.maximum_server_version.as_ref(),
    ) {
        warnings.push(format!("Server compatibility notice: '{}' {reason}", ext.identifier));
    }

    for (dep_id, parsed_dep) in &ext.dependencies {
        if let Some(dep_ext) = catalog.extensions.get(dep_id) {
            if let Some(dep_ver) = dep_ext.pep440_version.as_ref() {
                if !parsed_dep.constraint.matches(dep_ver) {
                    warnings.push(format!(
                        "Dependency notice: '{}' requires '{dep_id}' {}, installed is '{}'",
                        ext.identifier,
                        parsed_dep.constraint.requirement_summary(),
                        dep_ext.raw.extension.version
                    ));
                }
            } else {
                warnings.push(format!(
                    "Dependency notice: installed '{dep_id}' has non-PEP-440 version '{}'",
                    dep_ext.raw.extension.version
                ));
            }
        } else {
            warnings.push(format!(
                "Dependency notice: '{}' requires '{dep_id}' {}, which is not currently installed",
                ext.identifier,
                parsed_dep.constraint.requirement_summary()
            ));
        }
    }
}

fn compute_disable_closure(
    catalog: &ExtensionCatalog,
    previous_enabled: &[String],
    target_set: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let prev_set: BTreeSet<String> = previous_enabled.iter().cloned().collect();
    let mut reverse_deps: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for enabled_id in previous_enabled {
        if let Some(ext) = catalog.extensions.get(enabled_id) {
            for dep_id in ext.dependencies.keys() {
                if prev_set.contains(dep_id) {
                    reverse_deps
                        .entry(dep_id.clone())
                        .or_default()
                        .push(enabled_id.clone());
                }
            }
        } else if !target_set.contains(enabled_id) {
            let reason = if let Some(diag) = catalog.diagnostic_for(enabled_id) {
                diag.message.clone()
            } else {
                "extension directory is missing from disk".to_string()
            };
            warnings.push(format!(
                "Enabled extension '{enabled_id}' could not be loaded ({reason}); its reverse dependencies were not checked"
            ));
        }
    }

    let mut remove_set = BTreeSet::new();
    let mut queue = VecDeque::new();
    for id in target_set {
        if prev_set.contains(id) && remove_set.insert(id.clone()) {
            queue.push_back(id.clone());
        }
    }
    while let Some(current) = queue.pop_front() {
        if let Some(dependents) = reverse_deps.get(&current) {
            for dep in dependents {
                if remove_set.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    let next_enabled: Vec<String> = previous_enabled
        .iter()
        .filter(|id| !remove_set.contains(*id))
        .cloned()
        .collect();
    let removed: Vec<String> = previous_enabled
        .iter()
        .filter(|id| remove_set.contains(*id))
        .cloned()
        .collect();
    let cascade_dependents: Vec<String> = removed
        .iter()
        .filter(|id| !target_set.contains(*id))
        .cloned()
        .collect();

    (next_enabled, removed, cascade_dependents)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DfsMark {
    Visiting,
    Visited,
}

fn normalize_targets(raw_targets: &[String]) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::with_capacity(raw_targets.len());
    for raw in raw_targets {
        validate_extension_identifier(raw)?;
        if seen.insert(raw.clone()) {
            ordered.push(raw.clone());
        }
    }
    if ordered.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "At least one extension identifier is required".to_string(),
        ));
    }
    Ok(ordered)
}

fn ensure_usable_extension<'a>(
    catalog: &'a ExtensionCatalog,
    id: &str,
    context_note: Option<&str>,
) -> Result<&'a InstalledExtension> {
    let suffix = context_note.map_or_else(String::new, |note| format!(" ({note})"));
    if let Some(dirs) = catalog.conflicted_identifiers.get(id) {
        let joined = dirs
            .iter()
            .map(|p| format!("'{}'", p.display()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' has duplicate definitions in {joined}{suffix}"
        )));
    }
    if let Some(ext) = catalog.extensions.get(id) {
        return Ok(ext);
    }
    if let Some(CatalogDiagnostic { message, .. }) = catalog.diagnostic_for(id) {
        return Err(CfmsError::Extension(format!(
            "Extension '{id}' cannot be loaded: {message}{suffix}"
        )));
    }
    Err(CfmsError::Extension(format!(
        "Extension '{id}' is not installed under '{}'{suffix}",
        catalog.extensions_root.display()
    )))
}

fn check_extension_server_compat(
    ext: &InstalledExtension,
    server: &DetectedServerVersion,
) -> Result<()> {
    check_server_compatibility(
        &server.version,
        ext.minimum_server_version.as_ref(),
        ext.maximum_server_version.as_ref(),
    )
    .map_err(|reason| CfmsError::Extension(format!("Extension '{}' {reason}", ext.identifier)))
}

#[allow(clippy::too_many_arguments)]
fn resolve_dependency_dfs(
    id: &str,
    catalog: &ExtensionCatalog,
    server: &DetectedServerVersion,
    prev_set: &BTreeSet<String>,
    record_target_postorder: bool,
    visit_state: &mut HashMap<String, DfsMark>,
    dfs_stack: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
    active_closure: &mut BTreeSet<String>,
    mut target_postorder: Option<&mut Vec<String>>,
) -> Result<()> {
    match visit_state.get(id).copied() {
        Some(DfsMark::Visited) => {
            if record_target_postorder && !visited.contains(id) {
                visited.insert(id.to_string());
                if let Some(out) = target_postorder.as_deref_mut() {
                    out.push(id.to_string());
                }
            }
            return Ok(());
        }
        Some(DfsMark::Visiting) => {
            let start = dfs_stack.iter().position(|n| n == id).unwrap_or(0);
            let mut chain: Vec<&str> = dfs_stack[start..].iter().map(String::as_str).collect();
            chain.push(id);
            return Err(CfmsError::Extension(format!(
                "Cyclic extension dependency detected: {}",
                chain.join(" -> ")
            )));
        }
        None => {}
    }

    let context_note = if prev_set.contains(id) {
        Some(format!(
            "currently enabled in config.toml; run `cfms-ctl extension disable {id}` first to remove it"
        ))
    } else {
        None
    };
    let ext = ensure_usable_extension(catalog, id, context_note.as_deref())?;
    check_extension_server_compat(ext, server)?;

    visit_state.insert(id.to_string(), DfsMark::Visiting);
    dfs_stack.push(id.to_string());
    active_closure.insert(id.to_string());

    for (dep_id, parsed_dep) in &ext.dependencies {
        let missing_context = format!("required by '{id}'");
        let dep_ext = ensure_usable_extension(catalog, dep_id, Some(&missing_context))?;

        let Some(installed_dep_ver) = dep_ext.pep440_version.as_ref() else {
            return Err(CfmsError::Extension(format!(
                "Extension '{dep_id}' version '{}' is not comparable as PEP 440 as required by '{id}'",
                dep_ext.raw.extension.version
            )));
        };
        if !parsed_dep.constraint.matches(installed_dep_ver) {
            return Err(CfmsError::Extension(format!(
                "Extension '{id}' requires '{dep_id}' {}; installed version is {}",
                parsed_dep.constraint.requirement_summary(),
                dep_ext.raw.extension.version
            )));
        }

        resolve_dependency_dfs(
            dep_id,
            catalog,
            server,
            prev_set,
            record_target_postorder,
            visit_state,
            dfs_stack,
            visited,
            active_closure,
            target_postorder.as_deref_mut(),
        )?;
    }

    dfs_stack.pop();
    visit_state.insert(id.to_string(), DfsMark::Visited);
    if record_target_postorder && visited.insert(id.to_string())
        && let Some(out) = target_postorder
    {
        out.push(id.to_string());
    }
    Ok(())
}

/// Topologically sort `priority_order` (`dep` before `dependent`) while keeping
/// unrelated entries in their original relative positions via min-heap tie-breaking.
fn topo_sort_preserving_priority(
    catalog: &ExtensionCatalog,
    priority_order: &[String],
) -> Vec<String> {
    let index_of: HashMap<&str, usize> = priority_order
        .iter()
        .enumerate()
        .map(|(idx, id)| (id.as_str(), idx))
        .collect();
    let n = priority_order.len();
    let mut indegree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (u_idx, id) in priority_order.iter().enumerate() {
        if let Some(ext) = catalog.extensions.get(id) {
            for dep_id in ext.dependencies.keys() {
                if let Some(&dep_idx) = index_of.get(dep_id.as_str()) {
                    dependents[dep_idx].push(u_idx);
                    indegree[u_idx] += 1;
                }
            }
        }
    }

    let mut ready = BinaryHeap::new();
    for (idx, &deg) in indegree.iter().enumerate() {
        if deg == 0 {
            ready.push(Reverse(idx));
        }
    }

    let mut ordered = Vec::with_capacity(n);
    while let Some(Reverse(idx)) = ready.pop() {
        ordered.push(priority_order[idx].clone());
        for &dep_of in &dependents[idx] {
            indegree[dep_of] -= 1;
            if indegree[dep_of] == 0 {
                ready.push(Reverse(dep_of));
            }
        }
    }

    ordered
}

pub(crate) fn check_scoped_staging_markers(
    markers: &[StagingMarker],
    affected_ids: &BTreeSet<String>,
    direct_targets: &BTreeSet<String>,
    warnings: &mut Vec<String>,
    block_on_match: bool,
) -> Result<()> {
    for marker in markers {
        match &marker.target_identifier {
            Some(target_id) if affected_ids.contains(target_id) && block_on_match => {
                return Err(CfmsError::Extension(format!(
                    "Unfinished extension transaction '{}' affects '{target_id}' at '{}'",
                    marker.name,
                    marker.path.display()
                )));
            }
            Some(target_id) => {
                warnings.push(format!(
                    "Ignoring unrelated staging artifact '{}' (for '{target_id}') at '{}'",
                    marker.name,
                    marker.path.display()
                ));
            }
            None => {
                if block_on_match && direct_targets.iter().any(|t| marker.name.contains(t)) {
                    return Err(CfmsError::Extension(format!(
                        "Unfinished extension staging artifact '{}' at '{}' may affect requested target",
                        marker.name,
                        marker.path.display()
                    )));
                }
                warnings.push(format!(
                    "Found unidentified residual staging artifact '{}' at '{}'",
                    marker.name,
                    marker.path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::extension::catalog::discover_catalog;

    fn write_manifest_ext(root: &Path, id: &str, body: &str) {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).expect("mkdir ext");
        std::fs::write(dir.join("manifest.toml"), body).expect("write manifest");
        std::fs::write(dir.join("_extension.py"), "# runtime hook").expect("write entry");
    }

    fn setup_workspace(server_version: &str, config_toml: &str) -> (tempfile::TempDir, WorkspacePaths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let cfg_dir = src.join("include").join("config");
        let ext_dir = src.join("include").join("extensions");
        std::fs::create_dir_all(&cfg_dir).expect("cfg dir");
        std::fs::create_dir_all(&ext_dir).expect("ext dir");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            cfg_dir.join("constants.py"),
            format!("CORE_VERSION = Version(\"{server_version}\")\n"),
        )
        .expect("constants.py");
        std::fs::write(src.join("config.toml"), config_toml).expect("config.toml");

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        (dir, paths)
    }

    #[test]
    fn enable_resolves_transitive_dependencies_in_load_order() {
        let (_dir, paths) = setup_workspace("0.14.0", "[extensions]\nenabled = []\n");
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "builtin",
            "manifest_version = 2\n[extension]\nidentifier = \"builtin\"\nname = \"Built-in\"\nversion = \"0.14.0\"\nauthors = [\"CFMS\"]\nlicense = \"GPL\"\n",
        );
        write_manifest_ext(
            ext_root,
            "base_auth",
            "manifest_version = 3\n[extension]\nidentifier = \"base_auth\"\nname = \"Base Auth\"\nversion = \"1.2.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\nbuiltin = \"0.14.0\"\n",
        );
        write_manifest_ext(
            ext_root,
            "http_api",
            "manifest_version = 3\n[extension]\nidentifier = \"http_api\"\nname = \"HTTP API\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[compatibility]\nminimum_server_version = \"0.10.0\"\n[dependencies.extensions]\nbase_auth = \">=1.0.0,<2.0\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");

        let plan = plan_enable(&catalog, &doc, &paths, &["http_api".to_string()], None)
            .expect("plan");
        assert!(plan.changed);
        assert_eq!(plan.next_enabled, vec!["base_auth", "http_api"]);
        assert_eq!(plan.added, vec!["base_auth", "http_api"]);
    }

    #[test]
    fn enable_heals_dependency_order_when_consumer_preexisted() {
        let (_dir, paths) = setup_workspace(
            "0.14.0",
            "[extensions]\nenabled = [\"other_ext\", \"consumer\"]\n",
        );
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "other_ext",
            "manifest_version = 2\n[extension]\nidentifier = \"other_ext\"\nname = \"Other\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "core_dep",
            "manifest_version = 3\n[extension]\nidentifier = \"core_dep\"\nname = \"Core Dep\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "consumer",
            "manifest_version = 3\n[extension]\nidentifier = \"consumer\"\nname = \"Consumer\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\ncore_dep = \"1.0.0\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");

        let plan = plan_enable(&catalog, &doc, &paths, &["core_dep".to_string()], None)
            .expect("plan");
        assert_eq!(plan.next_enabled, vec!["other_ext", "core_dep", "consumer"]);
    }

    #[test]
    fn enable_detects_cycles_version_mismatch_and_missing_server_version() {
        let (dir, paths) = setup_workspace("0.10.0", "[extensions]\nenabled = []\n");
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "ext_a",
            "manifest_version = 3\n[extension]\nidentifier = \"ext_a\"\nname = \"A\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\next_b = \"1.0.0\"\n",
        );
        write_manifest_ext(
            ext_root,
            "ext_b",
            "manifest_version = 3\n[extension]\nidentifier = \"ext_b\"\nname = \"B\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\next_a = \"1.0.0\"\n",
        );
        write_manifest_ext(
            ext_root,
            "too_new",
            "manifest_version = 2\n[extension]\nidentifier = \"too_new\"\nname = \"New\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[compatibility]\nminimum_server_version = \"0.14.0\"\n",
        );
        write_manifest_ext(
            ext_root,
            "too_old_server",
            "manifest_version = 2\n[extension]\nidentifier = \"too_old_server\"\nname = \"Legacy\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[compatibility]\nmaximum_server_version = \"0.9.0\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");

        let cycle_err = plan_enable(&catalog, &doc, &paths, &["ext_a".to_string()], None)
            .expect_err("cycle rejected");
        assert!(cycle_err.to_string().contains("ext_a -> ext_b -> ext_a"));

        let min_err = plan_enable(&catalog, &doc, &paths, &["too_new".to_string()], None)
            .expect_err("min server version rejected");
        assert!(min_err.to_string().contains("0.14.0 or newer"));

        let max_err = plan_enable(
            &catalog,
            &doc,
            &paths,
            &["too_old_server".to_string()],
            None,
        )
        .expect_err("max server version rejected");
        assert!(max_err.to_string().contains("up to 0.9.0"));

        // Deleting constants.py with no other version files fails strictly!
        std::fs::remove_file(dir.path().join("src/include/config/constants.py"))
            .expect("rm constants");
        let unknown_ver_err =
            plan_enable(&catalog, &doc, &paths, &["too_new".to_string()], None)
                .expect_err("unknown server version fails safe");
        let err_msg = unknown_ver_err.to_string();
        assert!(err_msg.contains("Unable to determine target CFMS server version"));
        assert!(!err_msg.contains("--server-version"));
    }

    #[test]
    fn disable_cascades_dependents_and_allows_removing_missing_or_retired_entries() {
        let (_dir, paths) = setup_workspace(
            "0.14.0",
            "[extensions]\nenabled = [\"keep_me\", \"deleted_ext\", \"scheduling\", \"dep\", \"consumer\", \"broken_sibling\"]\n",
        );
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "keep_me",
            "manifest_version = 2\n[extension]\nidentifier = \"keep_me\"\nname = \"Keep\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "dep",
            "manifest_version = 3\n[extension]\nidentifier = \"dep\"\nname = \"Dep\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "consumer",
            "manifest_version = 3\n[extension]\nidentifier = \"consumer\"\nname = \"Consumer\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\ndep = \"1.0.0\"\n",
        );
        // Broken sibling missing _extension.py should emit warning, not block disable!
        let broken_dir = ext_root.join("broken_sibling");
        std::fs::create_dir_all(&broken_dir).expect("broken dir");
        std::fs::write(
            broken_dir.join("manifest.toml"),
            "manifest_version = 2\n[extension]\nidentifier = \"broken_sibling\"\nname = \"Broken\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        )
        .expect("broken manifest");

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");

        let plan = plan_disable(
            &catalog,
            &doc,
            &paths,
            &[
                "dep".to_string(),
                "deleted_ext".to_string(),
                "scheduling".to_string(),
            ],
            None,
        )
        .expect("resilient disable");

        assert!(plan.changed);
        assert_eq!(plan.next_enabled, vec!["keep_me", "broken_sibling"]);
        assert_eq!(plan.cascade_dependents, vec!["consumer"]);
        assert_eq!(plan.removed_uninstalled, vec!["deleted_ext", "scheduling"]);
        assert!(!plan.warnings.is_empty());
    }

    #[test]
    fn enable_checks_pep440_dependency_bounds_and_scoped_staging_markers() {
        let (_dir, paths) = setup_workspace("0.14.0", "[extensions]\nenabled = []\n");
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "dep_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"dep_ext\"\nname = \"Dep\"\nversion = \"0.9.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "consumer_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"consumer_ext\"\nname = \"Consumer\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\ndep_ext = \">=1.0.0\"\n",
        );
        write_manifest_ext(
            ext_root,
            "clean_ext",
            "manifest_version = 2\n[extension]\nidentifier = \"clean_ext\"\nname = \"Clean\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        // Unfinished staging artifact targeting `other_pkg`
        let stage_dir = ext_root.join(".cfms-extension-stage-deadbeef");
        std::fs::create_dir_all(&stage_dir).expect("stage dir");
        std::fs::write(
            stage_dir.join("manifest.toml"),
            "manifest_version = 2\n[extension]\nidentifier = \"clean_ext\"\nname = \"Clean\"\nversion = \"1.1.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        )
        .expect("stage manifest");

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");

        let ver_err = plan_enable(
            &catalog,
            &doc,
            &paths,
            &["consumer_ext".to_string()],
            None,
        )
        .expect_err("dep version mismatch");
        assert!(ver_err.to_string().contains(">=1.0.0"));

        // Staging artifact targeting `clean_ext` blocks enabling `clean_ext`...
        let stage_err = plan_enable(
            &catalog,
            &doc,
            &paths,
            &["clean_ext".to_string()],
            None,
        )
        .expect_err("scoped staging blocks target");
        assert!(stage_err.to_string().contains("Unfinished extension transaction"));

        // ...but does NOT block enabling an unrelated healthy extension `dep_ext`.
        let unrelated_plan =
            plan_enable(&catalog, &doc, &paths, &["dep_ext".to_string()], None)
                .expect("unrelated enable succeeds with warning");
        assert!(
            unrelated_plan
                .warnings
                .iter()
                .any(|w| w.contains("Ignoring unrelated staging artifact"))
        );
    }

    #[test]
    fn upgrade_blocks_breaking_enabled_dependents_and_enforces_server_max_version() {
        let (_dir, paths) = setup_workspace("0.15.0", "[extensions]\nenabled = [\"dep_ext\", \"app_ext\"]\n");
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "dep_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"dep_ext\"\nname = \"Dep\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "app_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"app_ext\"\nname = \"App\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\ndep_ext = \">=1.0.0,<2.0.0\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");
        let managed = BTreeSet::from(["builtin".to_string()]);

        let dep_v2_manifest = crate::ops::extension::catalog::parse_extension_manifest_str(
            "manifest_version = 3\n[extension]\nidentifier = \"dep_ext\"\nname = \"Dep\"\nversion = \"2.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            Path::new("pkg/manifest.toml"),
            Path::new("pkg"),
            Path::new("pkg/_extension.py"),
        )
        .expect("parse v2");
        let dep_v2_pkg = VerifiedExtensionPackage {
            package_path: PathBuf::from("dep-2.0.0.zip"),
            package_sha256: "a".repeat(64),
            manifest: dep_v2_manifest,
            member_count: 2,
            declared_uncompressed_bytes: 64,
        };

        let break_err = plan_upgrade(&dep_v2_pkg, &catalog, &doc, &paths, &managed, None)
            .expect_err("upgrading dep_ext to 2.0.0 breaks enabled app_ext");
        assert!(break_err.to_string().contains("app_ext"));

        let max_ver_manifest = crate::ops::extension::catalog::parse_extension_manifest_str(
            "manifest_version = 3\n[extension]\nidentifier = \"app_ext\"\nname = \"App\"\nversion = \"2.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[compatibility]\nmaximum_server_version = \"0.14.9\"\n",
            Path::new("pkg/manifest.toml"),
            Path::new("pkg"),
            Path::new("pkg/_extension.py"),
        )
        .expect("parse app v2");
        let max_ver_pkg = VerifiedExtensionPackage {
            package_path: PathBuf::from("app-2.0.0.zip"),
            package_sha256: "b".repeat(64),
            manifest: max_ver_manifest,
            member_count: 2,
            declared_uncompressed_bytes: 64,
        };

        let compat_err = plan_upgrade(&max_ver_pkg, &catalog, &doc, &paths, &managed, None)
            .expect_err("server 0.15.0 exceeds maximum_server_version 0.14.9");
        assert!(compat_err.to_string().contains("0.14.9"));
    }

    #[test]
    fn uninstall_resolves_broken_diagnostics_and_blocks_managed_extensions() {
        let (dir, paths) = setup_workspace("0.14.0", "[extensions]\nenabled = [\"broken_ext\"]\n");
        let ext_root = &paths.extensions_root;

        // Create broken directory missing `_extension.py` but with valid manifest identifier hint.
        let broken_dir = ext_root.join("broken_dir_on_disk");
        std::fs::create_dir_all(&broken_dir).expect("mkdir broken");
        std::fs::write(
            broken_dir.join("manifest.toml"),
            "manifest_version = 2\n[extension]\nidentifier = \"broken_ext\"\nname = \"Broken\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        )
        .expect("write manifest");
        std::fs::write(
            dir.path().join("release-manifest.json"),
            r#"{"version":"0.14.0","managed_extensions":["oidc_sso"]}"#,
        )
        .expect("write release manifest");
        write_manifest_ext(
            ext_root,
            "oidc_sso",
            "manifest_version = 2\n[extension]\nidentifier = \"oidc_sso\"\nname = \"OIDC\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");
        let managed = crate::ops::extension::catalog::read_managed_extensions(&paths).expect("managed");
        assert!(managed.contains("oidc_sso"));

        let managed_err = plan_uninstall("oidc_sso", false, &catalog, &doc, &managed, None)
            .expect_err("managed extension cannot be uninstalled");
        assert!(managed_err.to_string().contains("managed"));

        let uninstall_plan = plan_uninstall("broken_ext", false, &catalog, &doc, &managed, None)
            .expect("broken target uninstall planned");
        assert!(uninstall_plan.broken_target);
        assert_eq!(uninstall_plan.target_directory, broken_dir);
        assert!(uninstall_plan.config_changed);
        assert_eq!(uninstall_plan.disabled_extensions, vec!["broken_ext"]);
    }

    #[test]
    fn purge_data_blocks_core_and_handles_enabled_dry_run_vs_managed_disabled() {
        let (dir, paths) = setup_workspace("0.14.0", "[extensions]\nenabled = [\"oidc_sso\"]\n");
        let ext_root = &paths.extensions_root;

        std::fs::write(
            dir.path().join("release-manifest.json"),
            r#"{"version":"0.14.0","managed_extensions":["oidc_sso"]}"#,
        )
        .expect("write release manifest");
        write_manifest_ext(
            ext_root,
            "oidc_sso",
            "manifest_version = 3\noption_namespaces = [\"oidc_sso\"]\n[extension]\nidentifier = \"oidc_sso\"\nname = \"OIDC SSO\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[data]\nmodule = \"models.py\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let enabled_doc = ConfigDocument::load(&paths.config_path).expect("enabled config");

        for reserved in ["core", "builtin"] {
            let err = plan_purge_data(reserved, false, true, &catalog, &enabled_doc, &paths)
                .expect_err("core/builtin rejected");
            assert!(err.to_string().contains("core") || err.to_string().contains("built-in"));
        }

        // Enabled target rejects mutating execution...
        let enabled_err =
            plan_purge_data("oidc_sso", false, false, &catalog, &enabled_doc, &paths)
                .expect_err("enabled target cannot purge");
        assert!(enabled_err.to_string().contains("enabled"));
        assert!(enabled_err.to_string().contains("disable"));

        // ...but allows read-only --dry-run preview with blocker + warning populated.
        let dry_plan = plan_purge_data("oidc_sso", false, true, &catalog, &enabled_doc, &paths)
            .expect("dry-run allowed while enabled");
        assert!(dry_plan.currently_enabled);
        assert!(!dry_plan.blockers.is_empty());
        assert!(
            dry_plan
                .blockers
                .iter()
                .any(|b| b.contains("currently enabled"))
        );
        assert!(
            dry_plan
                .warnings
                .iter()
                .any(|w| w.contains("currently enabled"))
        );
        assert_eq!(dry_plan.option_namespaces, vec!["oidc_sso"]);
        assert_eq!(dry_plan.data_module.as_deref(), Some("models.py"));

        // Managed extensions remain purgeable once disabled!
        std::fs::write(&paths.config_path, "[extensions]\nenabled = []\n").expect("disable oidc");
        let disabled_doc = ConfigDocument::load(&paths.config_path).expect("disabled config");
        let purge_plan =
            plan_purge_data("oidc_sso", false, false, &catalog, &disabled_doc, &paths)
                .expect("disabled managed extension can be purged");
        assert!(!purge_plan.currently_enabled);
        assert!(purge_plan.blockers.is_empty());
        assert_eq!(purge_plan.load_closure.len(), 1);
        assert_eq!(purge_plan.load_closure[0].identifier, "oidc_sso");
    }

    #[test]
    fn purge_data_isolates_broken_siblings_and_recovers_orphans_with_options_only() {
        let (dir, paths) = setup_workspace("0.14.0", "[extensions]\nenabled = []\n");
        let ext_root = &paths.extensions_root;

        write_manifest_ext(
            ext_root,
            "dep_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"dep_ext\"\nname = \"Dep\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );
        write_manifest_ext(
            ext_root,
            "app_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"app_ext\"\nname = \"App\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\ndep_ext = \">=1.0.0\"\n[compatibility]\nminimum_server_version = \"99.0.0\"\n",
        );

        // Unrelated broken sibling + broken target directory (missing `_extension.py`).
        let broken_sibling = ext_root.join("broken_sibling");
        std::fs::create_dir_all(&broken_sibling).expect("mkdir sibling");
        std::fs::write(broken_sibling.join("manifest.toml"), "not valid toml = [")
            .expect("write corrupt manifest");

        let broken_target = ext_root.join("broken_target");
        std::fs::create_dir_all(&broken_target).expect("mkdir broken_target");
        std::fs::write(
            broken_target.join("manifest.toml"),
            "manifest_version = 2\n[extension]\nidentifier = \"broken_target\"\nname = \"Broken\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        )
        .expect("write broken target manifest");

        // Healthy target ignores broken siblings and treats server version bounds as advisory warnings.
        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");

        let app_plan = plan_purge_data("app_ext", false, false, &catalog, &doc, &paths)
            .expect("healthy target ignores broken sibling and server version bounds");
        let closure_ids: Vec<&str> = app_plan
            .load_closure
            .iter()
            .map(|e| e.identifier.as_str())
            .collect();
        assert_eq!(closure_ids, vec!["dep_ext", "app_ext"]);
        assert!(app_plan.dependency_error.is_none());
        assert!(
            app_plan
                .warnings
                .iter()
                .any(|w| w.contains("Server compatibility notice"))
        );

        // Broken, retired, and uninstalled targets fail without --options-only...
        assert!(plan_purge_data("broken_target", false, false, &catalog, &doc, &paths).is_err());
        assert!(plan_purge_data("scheduling", false, false, &catalog, &doc, &paths).is_err());
        assert!(plan_purge_data("ghost_ext", false, false, &catalog, &doc, &paths).is_err());

        // ...and succeed with --options-only.
        let broken_plan = plan_purge_data("broken_target", true, false, &catalog, &doc, &paths)
            .expect("broken target --options-only");
        assert!(broken_plan.broken_target);
        assert!(broken_plan.blockers.is_empty());

        let retired_plan = plan_purge_data("scheduling", true, false, &catalog, &doc, &paths)
            .expect("retired target --options-only");
        assert!(retired_plan.retired_identifier);
        assert!(!retired_plan.installed);

        let ghost_plan = plan_purge_data("ghost_ext", true, false, &catalog, &doc, &paths)
            .expect("uninstalled target --options-only");
        assert!(!ghost_plan.retired_identifier);
        assert!(!ghost_plan.installed);

        // Removing constants.py leaves no detectable server version -> purge-data refuses to run.
        std::fs::remove_file(dir.path().join("src/include/config/constants.py"))
            .expect("rm constants");
        let missing_ver_err = plan_purge_data("app_ext", false, false, &catalog, &doc, &paths)
            .expect_err("purge-data rejects missing server version");
        assert!(
            missing_ver_err
                .to_string()
                .contains("Unable to determine target CFMS server version")
        );
        assert!(plan_purge_data("broken_target", true, false, &catalog, &doc, &paths).is_err());
    }

    #[test]
    fn install_upgrade_and_disable_fail_when_server_version_cannot_be_determined() {
        let (dir, paths) = setup_workspace("0.14.0", "[extensions]\nenabled = [\"app_ext\"]\n");
        let ext_root = &paths.extensions_root;
        write_manifest_ext(
            ext_root,
            "app_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"app_ext\"\nname = \"App\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );

        let catalog = discover_catalog(ext_root).expect("catalog");
        let doc = ConfigDocument::load(&paths.config_path).expect("config");
        let managed = BTreeSet::from(["builtin".to_string()]);

        let new_pkg_manifest = crate::ops::extension::catalog::parse_extension_manifest_str(
            "manifest_version = 3\n[extension]\nidentifier = \"fresh_ext\"\nname = \"Fresh\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            Path::new("pkg/manifest.toml"),
            Path::new("pkg"),
            Path::new("pkg/_extension.py"),
        )
        .expect("parse fresh");
        let fresh_pkg = VerifiedExtensionPackage {
            package_path: PathBuf::from("fresh-1.0.0.zip"),
            package_sha256: "a".repeat(64),
            manifest: new_pkg_manifest,
            member_count: 2,
            declared_uncompressed_bytes: 64,
        };

        let upgrade_manifest = crate::ops::extension::catalog::parse_extension_manifest_str(
            "manifest_version = 3\n[extension]\nidentifier = \"app_ext\"\nname = \"App\"\nversion = \"2.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            Path::new("pkg/manifest.toml"),
            Path::new("pkg"),
            Path::new("pkg/_extension.py"),
        )
        .expect("parse upgrade");
        let upgrade_pkg = VerifiedExtensionPackage {
            package_path: PathBuf::from("app-2.0.0.zip"),
            package_sha256: "b".repeat(64),
            manifest: upgrade_manifest,
            member_count: 2,
            declared_uncompressed_bytes: 64,
        };

        std::fs::remove_file(dir.path().join("src/include/config/constants.py"))
            .expect("rm constants");

        assert!(plan_install(&fresh_pkg, &catalog, &doc, &paths, &managed).is_err());
        assert!(plan_upgrade(&upgrade_pkg, &catalog, &doc, &paths, &managed, None).is_err());
        assert!(plan_disable(&catalog, &doc, &paths, &["app_ext".to_string()], None).is_err());
    }
}
