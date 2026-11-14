//! Graph-based dependency planning for `cfms-ctl extension enable` and `disable`.
//!
//! Computes an immutable selection plan once against a loaded `ConfigDocument` and
//! `ExtensionCatalog`, validates compatibility and schema constraints before any
//! disk write, and preserves existing `[extensions].enabled` ordering and TOML comments.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, VecDeque};
use std::path::Path;
use crate::core::{CfmsError, ConfigDocument, Result, WorkspacePaths};
use crate::ops::extension::catalog::{
    BUILTIN_EXTENSION_ID, CatalogDiagnostic, ExtensionCatalog, InstalledExtension,
    StagingMarker, ensure_not_retired, read_enabled_config, validate_extension_identifier,
};
use crate::ops::extension::version::{
    DetectedServerVersion, check_server_compatibility, discover_server_version,
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
    pub server_version: Option<DetectedServerVersion>,
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
    server_version_override: Option<&str>,
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
    let server = discover_server_version(paths, server_version_override)?.ok_or_else(|| {
        CfmsError::Extension(
            "Unable to determine target CFMS server version from release-manifest.json, include/config/constants.py, or pyproject.toml; pass --server-version <VERSION> to specify it explicitly"
                .to_string(),
        )
    })?;

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
        server_version: Some(server),
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

    // Build reverse dependency graph over readable manifests for currently enabled entries.
    let mut reverse_deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for enabled_id in &previous_enabled {
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

    // Collect targets + transitive enabled dependents.
    let mut remove_set = BTreeSet::new();
    let mut queue = VecDeque::new();
    for id in &targets {
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

    let changed = next_enabled != previous_enabled;
    let mut candidate_doc = config_doc.clone();
    if changed {
        let schema_warnings = candidate_doc.set_extensions_enabled(&next_enabled, schema_path)?;
        warnings.extend(schema_warnings);
    } else if schema_path.is_some() {
        let schema_warnings = candidate_doc.validate_with_schema(schema_path)?;
        warnings.extend(schema_warnings);
    }

    let detected_server = discover_server_version(paths, None).ok().flatten();

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

fn check_scoped_staging_markers(
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

        let plan = plan_enable(&catalog, &doc, &paths, &["http_api".to_string()], None, None)
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

        let plan = plan_enable(&catalog, &doc, &paths, &["core_dep".to_string()], None, None)
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

        let cycle_err = plan_enable(&catalog, &doc, &paths, &["ext_a".to_string()], None, None)
            .expect_err("cycle rejected");
        assert!(cycle_err.to_string().contains("ext_a -> ext_b -> ext_a"));

        let min_err = plan_enable(&catalog, &doc, &paths, &["too_new".to_string()], None, None)
            .expect_err("min server version rejected");
        assert!(min_err.to_string().contains("0.14.0 or newer"));

        let max_err = plan_enable(
            &catalog,
            &doc,
            &paths,
            &["too_old_server".to_string()],
            None,
            None,
        )
        .expect_err("max server version rejected");
        assert!(max_err.to_string().contains("up to 0.9.0"));

        // Overriding --server-version works, while deleting constants.py fails safe!
        assert!(
            plan_enable(
                &catalog,
                &doc,
                &paths,
                &["too_new".to_string()],
                Some("0.14.0"),
                None
            )
            .is_ok()
        );
        std::fs::remove_file(dir.path().join("src/include/config/constants.py"))
            .expect("rm constants");
        let unknown_ver_err =
            plan_enable(&catalog, &doc, &paths, &["too_new".to_string()], None, None)
                .expect_err("unknown server version fails safe");
        assert!(unknown_ver_err.to_string().contains("--server-version"));
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
            None,
        )
        .expect_err("scoped staging blocks target");
        assert!(stage_err.to_string().contains("Unfinished extension transaction"));

        // ...but does NOT block enabling an unrelated healthy extension `dep_ext`.
        let unrelated_plan =
            plan_enable(&catalog, &doc, &paths, &["dep_ext".to_string()], None, None)
                .expect("unrelated enable succeeds with warning");
        assert!(
            unrelated_plan
                .warnings
                .iter()
                .any(|w| w.contains("Ignoring unrelated staging artifact"))
        );
    }
}
