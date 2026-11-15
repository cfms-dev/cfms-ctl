//! `cfms-ctl extension`: Open-world `manifest.toml` (v2/v3+) inspection and lifecycle
//! management for built-in and third-party CFMS server extensions.

pub mod catalog;
pub mod package;
pub mod planner;
pub mod purge;
pub mod version;

use std::collections::{BTreeMap, BTreeSet};
use comfy_table::{Cell, Color};
use serde::Serialize;
use crate::cli::extension::{
    ExtensionCommand, ExtensionDisableArgs, ExtensionEnableArgs, ExtensionIdentifierArgs,
    ExtensionPackageArgs, ExtensionPurgeDataArgs, ExtensionUninstallArgs,
};
use crate::core::atomic::atomic_write;
use crate::core::{CfmsError, Result, RuntimeLock, WorkspacePaths};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort, styled_table};
use catalog::{
    CatalogDiagnostic, ExtensionCatalog, InstalledExtension, discover_catalog, read_enabled_config,
    read_managed_extensions, validate_extension_identifier,
};
use package::{
    ActiveUninstallRollback, ActiveUpgradeRollback, OpenedExtensionPackage, TRUSTED_CODE_NOTICE,
    commit_install_directory,
};
use planner::{
    ExtensionTogglePlan, plan_disable, plan_enable, plan_install, plan_uninstall, plan_upgrade,
};
use purge::{ExtensionPurgeSummary, execute_extension_purge, preview_extension_purge};
use version::{CfmsServerVersion, check_server_compatibility, discover_server_version};

pub use catalog::{
    ExtensionCompatibility, ExtensionDependencies, ExtensionMeta, RawExtensionManifest,
};

/// Summary of an installed extension returned by `extension list` and `extension info`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionSummary {
    pub identifier: String,
    pub display_name: String,
    pub version: String,
    pub manifest_version: Option<u32>,
    pub license: String,
    pub builtin: bool,
    pub enabled: bool,
    pub description: String,
    pub minimum_server_version: Option<String>,
    pub maximum_server_version: Option<String>,
    pub compatible: Option<bool>,
    pub dependencies: BTreeMap<String, String>,
    pub issues: Vec<String>,
    pub path: String,
}

/// Report for `cfms-ctl extension list`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionListReport {
    pub extensions_root: String,
    pub server_version: Option<String>,
    pub extensions: Vec<ExtensionSummary>,
    pub missing_enabled: Vec<String>,
    pub diagnostics: Vec<CatalogDiagnostic>,
}

/// Report for `cfms-ctl extension enable` and `cfms-ctl extension disable`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionToggleReport {
    pub action: String,
    pub targets: Vec<String>,
    pub dry_run: bool,
    pub changed: bool,
    pub applied: bool,
    pub config_path: String,
    pub backup_path: Option<String>,
    pub server_version: Option<String>,
    pub server_version_source: Option<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub cascade_dependents: Vec<String>,
    pub already_in_desired_state: Vec<String>,
    pub removed_uninstalled: Vec<String>,
    pub reordered_existing: bool,
    pub previous_enabled: Vec<String>,
    pub enabled: Vec<String>,
    pub restart_required: bool,
    pub warnings: Vec<String>,
}

/// Report for `cfms-ctl extension install`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionInstallReport {
    pub identifier: String,
    pub display_name: String,
    pub version: String,
    pub directory: String,
    pub package_path: String,
    pub package_sha256: String,
    pub enabled: bool,
    pub dry_run: bool,
    pub applied: bool,
    pub restart_required: bool,
    pub trusted_code_notice: String,
    pub warnings: Vec<String>,
}

/// Report for `cfms-ctl extension upgrade`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionUpgradeReport {
    pub identifier: String,
    pub display_name: String,
    pub previous_version: String,
    pub version: String,
    pub directory: String,
    pub package_path: String,
    pub package_sha256: String,
    pub was_enabled: bool,
    pub enabled: Vec<String>,
    pub auto_enabled: Vec<String>,
    pub config_changed: bool,
    pub backup_path: Option<String>,
    pub dry_run: bool,
    pub applied: bool,
    pub restart_required: bool,
    pub trusted_code_notice: String,
    pub warnings: Vec<String>,
}

/// Report for `cfms-ctl extension uninstall`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionUninstallReport {
    pub identifier: String,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub directory: String,
    pub broken_target: bool,
    pub purge_data: bool,
    pub purge_summary: Option<ExtensionPurgeSummary>,
    pub disabled_extensions: Vec<String>,
    pub cascade_dependents: Vec<String>,
    pub config_changed: bool,
    pub backup_path: Option<String>,
    pub dry_run: bool,
    pub applied: bool,
    pub restart_required: bool,
    pub warnings: Vec<String>,
}

impl CommandReport for ExtensionListReport {
    fn render_human(&self, ui: &UiConsole) {
        ui.print_section(&format!("Installed Extensions ({})", self.extensions_root));
        if let Some(ver) = &self.server_version {
            println!("Detected Server Version: {ver}");
        } else {
            ui.print_warning(
                "Target server version could not be detected; compatibility is reported as unknown.",
            );
        }

        if self.extensions.is_empty() {
            println!("No valid extensions installed.");
        } else {
            let mut table = styled_table(&[
                "Identifier",
                "Name",
                "Version",
                "Manifest",
                "Type",
                "Enabled",
                "Compat",
                "Dependencies",
                "Issues",
            ]);
            for ext in &self.extensions {
                let deps = if ext.dependencies.is_empty() {
                    "-".to_string()
                } else {
                    ext.dependencies
                        .iter()
                        .map(|(k, v)| format!("{k} ({v})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let (compat_label, compat_color) = match ext.compatible {
                    Some(true) => ("ok", Color::Green),
                    Some(false) => ("incompatible", Color::Red),
                    None => ("unknown", Color::Yellow),
                };
                let issues_text = if ext.issues.is_empty() {
                    "-".to_string()
                } else {
                    ext.issues.join("; ")
                };
                table.add_row(vec![
                    Cell::new(&ext.identifier).fg(Color::Cyan),
                    Cell::new(&ext.display_name),
                    Cell::new(&ext.version),
                    Cell::new(
                        ext.manifest_version
                            .map_or_else(|| "?".to_string(), |v| format!("v{v}")),
                    ),
                    Cell::new(if ext.builtin { "builtin" } else { "extension" }),
                    Cell::new(if ext.enabled { "yes" } else { "no" }).fg(if ext.enabled {
                        Color::Green
                    } else {
                        Color::DarkGrey
                    }),
                    Cell::new(compat_label).fg(compat_color),
                    Cell::new(deps),
                    Cell::new(issues_text).fg(if ext.issues.is_empty() {
                        Color::DarkGrey
                    } else {
                        Color::Yellow
                    }),
                ]);
            }
            println!("{table}");
        }

        for missing in &self.missing_enabled {
            ui.print_warning(&format!(
                "Enabled identifier '{missing}' in config.toml is missing or invalid on disk."
            ));
        }
        for diag in &self.diagnostics {
            ui.print_warning(&format!(
                "Invalid extension directory '{}': {}",
                diag.directory.display(),
                diag.message
            ));
        }
    }
}

impl CommandReport for ExtensionSummary {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new(format!("Extension: {}", self.identifier));
        table
            .row("Identifier", self.identifier.clone())
            .row("Name", self.display_name.clone())
            .row("Version", self.version.clone())
            .row(
                "Manifest Version",
                self.manifest_version
                    .map_or_else(|| "unknown".to_string(), |v| v.to_string()),
            )
            .row("License", self.license.clone())
            .row("Built-in", self.builtin.to_string())
            .row("Active / Enabled", self.enabled.to_string())
            .row(
                "Server Compatibility",
                match self.compatible {
                    Some(true) => "compatible".to_string(),
                    Some(false) => "incompatible".to_string(),
                    None => "unknown".to_string(),
                },
            )
            .row("Description", self.description.clone())
            .row(
                "Min Server Version",
                self.minimum_server_version
                    .clone()
                    .unwrap_or_else(|| "(none)".to_string()),
            )
            .row(
                "Max Server Version",
                self.maximum_server_version
                    .clone()
                    .unwrap_or_else(|| "(none)".to_string()),
            )
            .row(
                "Extension Dependencies",
                if self.dependencies.is_empty() {
                    "(none)".to_string()
                } else {
                    self.dependencies
                        .iter()
                        .map(|(k, v)| format!("{k} ({v})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            )
            .row("Directory", self.path.clone());
        table.print();
        for issue in &self.issues {
            ui.print_warning(issue);
        }
    }
}

impl CommandReport for ExtensionToggleReport {
    fn render_human(&self, ui: &UiConsole) {
        let title = match self.action.as_str() {
            "enable" => "Extension Enable Plan",
            "disable" => "Extension Disable Plan",
            _ => "Extension Configuration Update",
        };
        let mut table = KeyValueTable::new(title);
        table
            .row("Action", self.action.clone())
            .row("Requested Targets", self.targets.join(", "))
            .row("Configuration File", self.config_path.clone())
            .row("Dry Run", self.dry_run.to_string())
            .row("Changed", self.changed.to_string())
            .row("Applied", self.applied.to_string());

        if let Some(ver) = &self.server_version {
            let formatted = self
                .server_version_source
                .as_ref()
                .map_or_else(|| ver.clone(), |src| format!("{ver} ({src})"));
            table.row("Server Version", formatted);
        }

        if !self.added.is_empty() {
            table.row("Added Extensions", self.added.join(", "));
        }
        if !self.removed.is_empty() {
            table.row("Removed Extensions", self.removed.join(", "));
        }
        if !self.cascade_dependents.is_empty() {
            table.row("Cascade Dependents", self.cascade_dependents.join(", "));
        }
        if !self.removed_uninstalled.is_empty() {
            table.row(
                "Removed Missing/Retired",
                self.removed_uninstalled.join(", "),
            );
        }
        if self.reordered_existing {
            table.row("Load Order Normalized", "true".to_string());
        }
        if !self.already_in_desired_state.is_empty() {
            table.row(
                if self.action == "enable" {
                    "Already Enabled"
                } else {
                    "Already Disabled"
                },
                self.already_in_desired_state.join(", "),
            );
        }

        table
            .row("Previous Enabled", format_enabled_list(&self.previous_enabled))
            .row("Resulting Enabled", format_enabled_list(&self.enabled))
            .row(
                "Backup Created",
                self.backup_path
                    .clone()
                    .unwrap_or_else(|| "(none)".to_string()),
            );
        table.print();
        println!();

        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if !self.changed {
            ui.print_success("No changes needed; extensions.enabled already matches the target state.");
        } else if !self.applied {
            ui.print_warning(if self.dry_run {
                "Dry-run mode active: config.toml was not modified."
            } else {
                "Preview shown above; confirmation required before modifying config.toml."
            });
        } else {
            ui.print_success(&format!("Updated '{}' successfully.", self.config_path));
            if self.restart_required {
                ui.print_warning(
                    "CFMS server appears to be running (server.lock is held). Restart the server for extension changes to take effect.",
                );
            }
        }
    }
}

impl CommandReport for ExtensionInstallReport {
    fn render_human(&self, ui: &UiConsole) {
        ui.print_section(&format!("Install Extension ({})", self.identifier));
        let mut kv = KeyValueTable::new("Extension Install");
        kv.row("Identifier", &self.identifier)
            .row("Display Name", &self.display_name)
            .row("Version", &self.version)
            .row("Package", &self.package_path)
            .row("Package SHA-256", &self.package_sha256)
            .row("Target Directory", &self.directory)
            .row("Enabled By Default", if self.enabled { "yes" } else { "no" })
            .row("Dry Run", if self.dry_run { "yes" } else { "no" })
            .row("Applied", if self.applied { "yes" } else { "no" });
        kv.print();

        println!("Notice: {}", self.trusted_code_notice);
        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.applied {
            ui.print_success(&format!(
                "Installed extension '{}' ({}) into '{}' (disabled). Enable with `cfms-ctl extension enable {}`.",
                self.identifier, self.version, self.directory, self.identifier
            ));
            if self.restart_required {
                ui.print_warning(
                    "CFMS server appears to be running (server.lock is held). Restart the server after enabling.",
                );
            }
        } else if self.dry_run {
            ui.print_warning("Dry-run mode active: no files were extracted.");
        }
    }
}

impl CommandReport for ExtensionUpgradeReport {
    fn render_human(&self, ui: &UiConsole) {
        ui.print_section(&format!("Upgrade Extension ({})", self.identifier));
        let mut kv = KeyValueTable::new("Extension Upgrade");
        kv.row("Identifier", &self.identifier)
            .row("Display Name", &self.display_name)
            .row(
                "Version Change",
                format!("{} -> {}", self.previous_version, self.version),
            )
            .row("Directory", &self.directory)
            .row("Package", &self.package_path)
            .row("Package SHA-256", &self.package_sha256)
            .row("Currently Enabled", if self.was_enabled { "yes" } else { "no" })
            .row("Auto-Enabled Dependencies", format_enabled_list(&self.auto_enabled))
            .row("Resulting Enabled List", format_enabled_list(&self.enabled))
            .row("Config Changed", if self.config_changed { "yes" } else { "no" })
            .row("Backup Path", self.backup_path.as_deref().unwrap_or("(none)"))
            .row("Dry Run", if self.dry_run { "yes" } else { "no" })
            .row("Applied", if self.applied { "yes" } else { "no" });
        kv.print();

        println!("Notice: {}", self.trusted_code_notice);
        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.applied {
            ui.print_success(&format!(
                "Upgraded extension '{}' from {} to {} at '{}'.",
                self.identifier, self.previous_version, self.version, self.directory
            ));
            if self.restart_required {
                ui.print_warning(
                    "CFMS server appears to be running (server.lock is held). Restart the server for upgraded code to take effect.",
                );
            }
        } else if self.dry_run {
            ui.print_warning("Dry-run mode active: no files or config were modified.");
        }
    }
}

impl CommandReport for ExtensionUninstallReport {
    fn render_human(&self, ui: &UiConsole) {
        ui.print_section(&format!("Uninstall Extension ({})", self.identifier));
        let mut kv = KeyValueTable::new("Extension Uninstall");
        kv.row("Identifier", &self.identifier)
            .row(
                "Display Name",
                self.display_name.as_deref().unwrap_or("(unavailable - broken extension)"),
            )
            .row(
                "Installed Version",
                self.version.as_deref().unwrap_or("(unavailable)"),
            )
            .row("Directory", &self.directory)
            .row("Broken Target", if self.broken_target { "yes" } else { "no" })
            .row(
                "Disabled Extensions",
                format_enabled_list(&self.disabled_extensions),
            )
            .row(
                "Cascade Disabled Dependents",
                format_enabled_list(&self.cascade_dependents),
            )
            .row("Config Changed", if self.config_changed { "yes" } else { "no" })
            .row("Backup Path", self.backup_path.as_deref().unwrap_or("(none)"))
            .row("Purge Data", if self.purge_data { "yes" } else { "no" });
        if let Some(purge) = &self.purge_summary {
            kv.row("Option Rows", purge.option_entries_deleted.to_string())
                .row("State Rows", purge.state_entries_deleted.to_string())
                .row(
                    "Python Hook Executed",
                    if purge.python_hook_executed { "yes" } else { "no" },
                );
        }
        kv.row("Dry Run", if self.dry_run { "yes" } else { "no" })
            .row("Applied", if self.applied { "yes" } else { "no" });
        kv.print();

        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.applied {
            ui.print_success(&format!(
                "Uninstalled extension '{}' from '{}'.",
                self.identifier, self.directory
            ));
            if self.restart_required {
                ui.print_warning(
                    "CFMS server appears to be running (server.lock is held). Restart the server to unload removed extension code.",
                );
            }
        } else if self.dry_run {
            ui.print_warning("Dry-run mode active: no files, config, or database data were modified.");
        }
    }
}

pub async fn handle(ctx: &AppContext, cmd: ExtensionCommand) -> Result<()> {
    match cmd {
        ExtensionCommand::List => handle_list(ctx),
        ExtensionCommand::Info(args) => handle_info(ctx, args),
        ExtensionCommand::Enable(args) => handle_enable(ctx, args),
        ExtensionCommand::Disable(args) => handle_disable(ctx, args),
        ExtensionCommand::Install(args) => handle_install(ctx, args),
        ExtensionCommand::Upgrade(args) => handle_upgrade(ctx, args),
        ExtensionCommand::Uninstall(args) => handle_uninstall(ctx, args).await,
        ExtensionCommand::PurgeData(_args) => {
            Err(CfmsError::NotImplementedYet("extension purge-data"))
        }
    }
}

fn handle_list(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let config_doc = ctx.load_config(&paths)?;
    let enabled_state = read_enabled_config(&config_doc, true)?;
    let enabled_set: BTreeSet<String> = enabled_state.entries.iter().cloned().collect();
    let catalog = discover_catalog(&paths.extensions_root)?;
    let server_version = discover_server_version(&paths, None)?
        .map(|detected| detected.version);

    let extensions: Vec<ExtensionSummary> = catalog
        .extensions
        .values()
        .map(|ext| summarize_extension(ext, &catalog, &enabled_set, server_version.as_ref()))
        .collect();

    let missing_enabled: Vec<String> = enabled_state
        .entries
        .into_iter()
        .filter(|id| !catalog.extensions.contains_key(id))
        .collect();

    let report = ExtensionListReport {
        extensions_root: paths.extensions_root.display().to_string(),
        server_version: server_version.map(|v| v.to_string()),
        extensions,
        missing_enabled,
        diagnostics: catalog.diagnostics,
    };
    ctx.ui.render(&report);
    Ok(())
}

fn handle_info(ctx: &AppContext, args: ExtensionIdentifierArgs) -> Result<()> {
    validate_extension_identifier(&args.identifier)?;
    let paths = ctx.resolve_paths()?;
    let config_doc = ctx.load_config(&paths)?;
    let enabled_state = read_enabled_config(&config_doc, true)?;
    let enabled_set: BTreeSet<String> = enabled_state.entries.iter().cloned().collect();
    let catalog = discover_catalog(&paths.extensions_root)?;
    let server_version = discover_server_version(&paths, None)?
        .map(|detected| detected.version);

    if let Some(dirs) = catalog.conflicted_identifiers.get(&args.identifier) {
        let joined = dirs
            .iter()
            .map(|p| format!("'{}'", p.display()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CfmsError::Extension(format!(
            "Extension '{}' has duplicate definitions in {joined}",
            args.identifier
        )));
    }

    let Some(ext) = catalog.extensions.get(&args.identifier) else {
        if let Some(diag) = catalog.diagnostic_for(&args.identifier) {
            return Err(CfmsError::Extension(format!(
                "Extension '{}' is invalid ({}): {}",
                args.identifier,
                diag.directory.display(),
                diag.message
            )));
        }
        return Err(CfmsError::Extension(format!(
            "Extension '{}' is not installed under '{}'",
            args.identifier,
            paths.extensions_root.display()
        )));
    };

    let summary = summarize_extension(ext, &catalog, &enabled_set, server_version.as_ref());
    ctx.ui.render(&summary);
    Ok(())
}

fn handle_enable(ctx: &AppContext, args: ExtensionEnableArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let schema_path = paths.discover_config_schema_path(args.schema.as_deref())?;
    let config_doc = ctx.load_config(&paths)?;
    let catalog = discover_catalog(&paths.extensions_root)?;
    let plan = plan_enable(
        &catalog,
        &config_doc,
        &paths,
        &args.identifiers,
        args.server_version.as_deref(),
        schema_path.as_deref(),
    )?;
    execute_toggle_plan(ctx, &paths, plan, args.dry_run)
}

fn handle_disable(ctx: &AppContext, args: ExtensionDisableArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let schema_path = paths.discover_config_schema_path(args.schema.as_deref())?;
    let config_doc = ctx.load_config(&paths)?;
    let catalog = discover_catalog(&paths.extensions_root)?;
    let plan = plan_disable(
        &catalog,
        &config_doc,
        &paths,
        &args.identifiers,
        schema_path.as_deref(),
    )?;
    execute_toggle_plan(ctx, &paths, plan, args.dry_run)
}

fn execute_toggle_plan(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    plan: ExtensionTogglePlan,
    dry_run: bool,
) -> Result<()> {
    let mut report = ExtensionToggleReport {
        action: plan.action.as_str().to_string(),
        targets: plan.targets.clone(),
        dry_run,
        changed: plan.changed,
        applied: false,
        config_path: paths.config_path.display().to_string(),
        backup_path: None,
        server_version: plan
            .server_version
            .as_ref()
            .map(|s| s.version.as_str().to_string()),
        server_version_source: plan
            .server_version
            .as_ref()
            .map(|s| s.source.label().to_string()),
        added: plan.added,
        removed: plan.removed,
        cascade_dependents: plan.cascade_dependents,
        already_in_desired_state: plan.already_in_desired_state,
        removed_uninstalled: plan.removed_uninstalled,
        reordered_existing: plan.reordered_existing,
        previous_enabled: plan.previous_enabled,
        enabled: plan.next_enabled,
        restart_required: false,
        warnings: plan.warnings,
    };

    if !plan.changed || dry_run {
        ctx.ui.render(&report);
        return Ok(());
    }

    let prompt = format!(
        "Back up '{}' and apply extension {} change?",
        paths.config_path.display(),
        report.action
    );
    if !confirm_or_dry_run(ctx, &report, dry_run, &prompt)? {
        return Ok(());
    }

    let backup_path = plan.candidate_doc.save_with_backup()?;
    report.backup_path = Some(backup_path.display().to_string());
    report.applied = true;
    report.restart_required = RuntimeLock::is_locked(paths);

    ctx.ui.render(&report);
    Ok(())
}

fn confirm_or_dry_run<R: CommandReport>(
    ctx: &AppContext,
    report: &R,
    dry_run: bool,
    prompt: &str,
) -> Result<bool> {
    if dry_run {
        ctx.ui.render(report);
        return Ok(false);
    }

    if ctx.ui.format() == OutputFormat::Json && !ctx.global.yes {
        return Err(CfmsError::InvalidArgument(
            "Refusing interactive confirmation in JSON output mode; pass --yes to apply or --dry-run to preview"
                .to_string(),
        ));
    }

    if ctx.ui.format() == OutputFormat::Human && !ctx.global.yes {
        report.render_human(&ctx.ui);
    }

    confirm_or_abort(prompt, ctx.global.yes)?;
    Ok(true)
}

fn handle_install(ctx: &AppContext, args: ExtensionPackageArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let config_doc = ctx.load_config(&paths)?;
    let catalog = discover_catalog(&paths.extensions_root)?;
    let managed = read_managed_extensions(&paths)?;

    let mut opened = OpenedExtensionPackage::open_and_verify(&args.package, args.sha256.as_deref())?;
    let plan = plan_install(&opened.summary, &catalog, &config_doc, &paths, &managed)?;

    let mut report = ExtensionInstallReport {
        identifier: plan.identifier.clone(),
        display_name: plan.display_name.clone(),
        version: plan.version.clone(),
        directory: plan.target_directory.display().to_string(),
        package_path: args.package.display().to_string(),
        package_sha256: plan.package_sha256.clone(),
        enabled: false,
        dry_run: args.dry_run,
        applied: false,
        restart_required: false,
        trusted_code_notice: TRUSTED_CODE_NOTICE.to_string(),
        warnings: plan.warnings.clone(),
    };

    let prompt = format!(
        "Install extension '{}' ({}) into '{}' (disabled)?",
        report.identifier, report.version, report.directory
    );
    if !confirm_or_dry_run(ctx, &report, args.dry_run, &prompt)? {
        return Ok(());
    }

    let staged = opened.stage_into(&paths.extensions_root)?;
    commit_install_directory(staged, &plan.target_directory)?;
    report.applied = true;
    report.restart_required = RuntimeLock::is_locked(&paths);

    ctx.ui.render(&report);
    Ok(())
}

fn handle_upgrade(ctx: &AppContext, args: ExtensionPackageArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let config_doc = ctx.load_config(&paths)?;
    let catalog = discover_catalog(&paths.extensions_root)?;
    let managed = read_managed_extensions(&paths)?;
    let schema_path = paths.discover_config_schema_path(None)?;

    let mut opened = OpenedExtensionPackage::open_and_verify(&args.package, args.sha256.as_deref())?;
    let plan = plan_upgrade(
        &opened.summary,
        &catalog,
        &config_doc,
        &paths,
        &managed,
        schema_path.as_deref(),
    )?;

    let mut report = ExtensionUpgradeReport {
        identifier: plan.identifier.clone(),
        display_name: plan.display_name.clone(),
        previous_version: plan.previous_version.clone(),
        version: plan.version.clone(),
        directory: plan.target_directory.display().to_string(),
        package_path: args.package.display().to_string(),
        package_sha256: plan.package_sha256.clone(),
        was_enabled: plan.was_enabled,
        enabled: plan.next_enabled.clone(),
        auto_enabled: plan.auto_enabled.clone(),
        config_changed: plan.config_changed,
        backup_path: None,
        dry_run: args.dry_run,
        applied: false,
        restart_required: false,
        trusted_code_notice: TRUSTED_CODE_NOTICE.to_string(),
        warnings: plan.warnings.clone(),
    };

    let prompt = format!(
        "Upgrade extension '{}' from {} to {} at '{}'?",
        report.identifier, report.previous_version, report.version, report.directory
    );
    if !confirm_or_dry_run(ctx, &report, args.dry_run, &prompt)? {
        return Ok(());
    }

    let staged = opened.stage_into(&paths.extensions_root)?;
    let swap = ActiveUpgradeRollback::begin(plan.target_directory.clone(), staged, &plan.identifier)?;
    if plan.config_changed {
        match plan.candidate_doc.save_with_backup() {
            Ok(backup_path) => {
                report.backup_path = Some(backup_path.display().to_string());
            }
            Err(err) => {
                let _ = swap.revert();
                return Err(err);
            }
        }
    }
    if let Some(cleanup_warning) = swap.finish() {
        report.warnings.push(cleanup_warning);
    }

    report.applied = true;
    report.restart_required = RuntimeLock::is_locked(&paths);

    ctx.ui.render(&report);
    Ok(())
}

async fn handle_uninstall(ctx: &AppContext, args: ExtensionUninstallArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let config_doc = ctx.load_config(&paths)?;
    let catalog = discover_catalog(&paths.extensions_root)?;
    let managed = read_managed_extensions(&paths)?;
    let schema_path = paths.discover_config_schema_path(None)?;

    let plan = plan_uninstall(
        &args.identifier,
        args.purge_data,
        &catalog,
        &config_doc,
        &managed,
        schema_path.as_deref(),
    )?;

    let mut warnings = plan.warnings.clone();
    let preview_summary = if args.purge_data && args.dry_run {
        let db_cfg = config_doc.database_config()?;
        let pool = crate::db::backend::DbPool::connect(&db_cfg, &paths).await?;
        let res = preview_extension_purge(
            &pool,
            &plan.identifier,
            &plan.entrypoint_path,
            plan.data_module.as_deref(),
            &mut warnings,
        )
        .await;
        pool.close().await;
        Some(res?)
    } else {
        None
    };

    let mut report = ExtensionUninstallReport {
        identifier: plan.identifier.clone(),
        display_name: plan.display_name.clone(),
        version: plan.version.clone(),
        directory: plan.target_directory.display().to_string(),
        broken_target: plan.broken_target,
        purge_data: plan.purge_data,
        purge_summary: preview_summary,
        disabled_extensions: plan.disabled_extensions.clone(),
        cascade_dependents: plan.cascade_dependents.clone(),
        config_changed: plan.config_changed,
        backup_path: None,
        dry_run: args.dry_run,
        applied: false,
        restart_required: false,
        warnings,
    };

    let prompt = if plan.purge_data {
        format!(
            "Disable '{}', purge all owned database data, and remove '{}'?",
            report.identifier, report.directory
        )
    } else {
        format!(
            "Uninstall extension '{}' from '{}' (retaining database data)?",
            report.identifier, report.directory
        )
    };
    if !confirm_or_dry_run(ctx, &report, args.dry_run, &prompt)? {
        return Ok(());
    }

    if plan.purge_data {
        let _server_lock = ctx.acquire_server_lock(&paths, false)?;
        let db_cfg = config_doc.database_config()?;

        if plan.config_changed {
            let backup_path = plan.candidate_doc.save_with_backup()?;
            report.backup_path = Some(backup_path.display().to_string());
        }

        let purge_res = execute_extension_purge(
            &paths,
            &db_cfg,
            &plan.identifier,
            &plan.entrypoint_path,
            plan.data_module.as_deref(),
            &mut report.warnings,
        )
        .await;

        let summary = match purge_res {
            Ok(s) => s,
            Err(err) => {
                if plan.config_changed {
                    let _ = atomic_write(config_doc.path(), config_doc.raw_source().as_bytes());
                }
                return Err(err);
            }
        };
        report.purge_summary = Some(summary);

        let rb = ActiveUninstallRollback::begin(plan.target_directory.clone(), &plan.identifier)
            .map_err(|err| {
                CfmsError::Extension(format!(
                    "Database data was purged and config updated, but directory removal failed: {err}"
                ))
            })?;
        if let Some(cleanup_warning) = rb.finish() {
            report.warnings.push(cleanup_warning);
        }
        report.applied = true;
        report.restart_required = false;
    } else {
        let rb = ActiveUninstallRollback::begin(plan.target_directory.clone(), &plan.identifier)?;
        if plan.config_changed {
            match plan.candidate_doc.save_with_backup() {
                Ok(backup_path) => {
                    report.backup_path = Some(backup_path.display().to_string());
                }
                Err(err) => {
                    let _ = rb.revert();
                    return Err(err);
                }
            }
        }
        if let Some(cleanup_warning) = rb.finish() {
            report.warnings.push(cleanup_warning);
        }
        report.applied = true;
        report.restart_required = RuntimeLock::is_locked(&paths);
    }

    ctx.ui.render(&report);
    Ok(())
}

fn summarize_extension(
    ext: &InstalledExtension,
    catalog: &ExtensionCatalog,
    enabled_set: &BTreeSet<String>,
    server_version: Option<&CfmsServerVersion>,
) -> ExtensionSummary {
    let active = ext.builtin || enabled_set.contains(&ext.identifier);
    let mut issues = Vec::new();

    for (dep_id, parsed_dep) in &ext.dependencies {
        if let Some(dep_ext) = catalog.extensions.get(dep_id) {
            if let Some(dep_ver) = dep_ext.pep440_version.as_ref() {
                if !parsed_dep.constraint.matches(dep_ver) {
                    issues.push(format!(
                        "dependency '{dep_id}' requires {}; installed is {}",
                        parsed_dep.constraint.requirement_summary(),
                        dep_ext.raw.extension.version
                    ));
                }
            } else {
                issues.push(format!(
                    "dependency '{dep_id}' has non-PEP-440 version '{}'",
                    dep_ext.raw.extension.version
                ));
            }
            if active && !dep_ext.builtin && !enabled_set.contains(dep_id) {
                issues.push(format!("dependency '{dep_id}' is not enabled"));
            }
        } else {
            issues.push(format!("dependency '{dep_id}' is not installed"));
        }
    }

    let compatible = if let Some(ver) = server_version {
        match check_server_compatibility(
            ver,
            ext.minimum_server_version.as_ref(),
            ext.maximum_server_version.as_ref(),
        ) {
            Ok(()) => Some(true),
            Err(msg) => {
                issues.push(msg);
                Some(false)
            }
        }
    } else {
        None
    };

    ExtensionSummary {
        identifier: ext.identifier.clone(),
        display_name: ext.display_name.clone(),
        version: ext.raw.extension.version.clone(),
        manifest_version: Some(ext.manifest_version),
        license: ext.raw.extension.license.clone(),
        builtin: ext.builtin,
        enabled: active,
        description: ext.raw.extension.description.clone(),
        minimum_server_version: ext.raw.compatibility.minimum_server_version.clone(),
        maximum_server_version: ext.raw.compatibility.maximum_server_version.clone(),
        compatible,
        dependencies: ext
            .dependencies
            .iter()
            .map(|(k, v)| (k.clone(), v.raw_requirement.clone()))
            .collect(),
        issues,
        path: ext.directory.display().to_string(),
    }
}

fn format_enabled_list(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

#[allow(dead_code)]
type _UnusedArgs = ExtensionPurgeDataArgs;

#[cfg(test)]
mod tests {
    use std::path::Path;
    use super::*;
    use crate::cli::GlobalOpts;
    use crate::core::ConfigDocument;

    fn test_ctx(root: &Path, format: OutputFormat, yes: bool) -> AppContext {
        AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output: format,
                yes,
                verbose: false,
            },
            UiConsole::new(format),
        )
    }

    fn write_ext(ext_root: &Path, id: &str, manifest: &str) {
        let dir = ext_root.join(id);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("manifest.toml"), manifest).expect("write manifest");
        std::fs::write(dir.join("_extension.py"), "# hook").expect("write entrypoint");
    }

    fn setup_workspace(config_content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let cfg_dir = src.join("include").join("config");
        let ext_dir = src.join("include").join("extensions");
        std::fs::create_dir_all(&cfg_dir).expect("cfg dir");
        std::fs::create_dir_all(&ext_dir).expect("ext dir");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            cfg_dir.join("constants.py"),
            "CORE_VERSION = Version(\"0.14.0\")\n",
        )
        .expect("constants.py");
        std::fs::write(src.join("config.toml"), config_content).expect("config.toml");

        write_ext(
            &ext_dir,
            "builtin",
            "manifest_version = 2\n[extension]\nidentifier = \"builtin\"\nname = \"Built-in\"\nversion = \"0.14.0\"\nauthors = [\"CFMS Contributors\"]\nlicense = \"GPL-3.0-or-later\"\n[compatibility]\nminimum_server_version = \"0.14.0\"\n",
        );
        write_ext(
            &ext_dir,
            "oidc_sso",
            "manifest_version = 2\n[extension]\nidentifier = \"oidc_sso\"\nname = \"OIDC SSO\"\nversion = \"1.0.0\"\nauthors = [\"CFMS Contributors\"]\nlicense = \"GPL-3.0-or-later\"\n[compatibility]\nminimum_server_version = \"0.5.1\"\n",
        );
        write_ext(
            &ext_dir,
            "http_api",
            "manifest_version = 3\n[extension]\nidentifier = \"http_api\"\nname = \"HTTP API\"\nversion = \"1.0.0\"\nauthors = [\"CFMS Contributors\"]\nlicense = \"GPL-3.0-or-later\"\n[compatibility]\nminimum_server_version = \"0.7.0\"\n[dependencies.extensions]\nbuiltin = \"0.14.0\"\noidc_sso = \"1.0.0\"\n",
        );
        dir
    }

    #[tokio::test]
    async fn enable_dry_run_does_not_write_and_json_requires_yes_on_mutation() {
        let original_cfg = "[extensions]\n# Keep comments\nenabled = [] # note\n";
        let dir = setup_workspace(original_cfg);
        let cfg_path = dir.path().join("src").join("config.toml");

        // 1. Dry-run succeeds even in JSON output mode without --yes, touching nothing
        let json_ctx = test_ctx(dir.path(), OutputFormat::Json, false);
        handle(
            &json_ctx,
            ExtensionCommand::Enable(ExtensionEnableArgs {
                identifiers: vec!["http_api".to_string()],
                dry_run: true,
                server_version: None,
                schema: None,
            }),
        )
        .await
        .expect("dry-run should succeed without --yes");
        assert_eq!(
            std::fs::read_to_string(&cfg_path).expect("read"),
            original_cfg
        );

        // 2. Non-dry-run mutation in JSON mode without --yes aborts cleanly without prompting
        let err = handle(
            &json_ctx,
            ExtensionCommand::Enable(ExtensionEnableArgs {
                identifiers: vec!["http_api".to_string()],
                dry_run: false,
                server_version: None,
                schema: None,
            }),
        )
        .await
        .expect_err("mutating json mode without --yes should abort");
        assert!(err.to_string().contains("--yes"));
    }

    #[tokio::test]
    async fn end_to_end_enable_backup_and_disable_cascade() {
        let dir = setup_workspace("[extensions]\n# keep me\nenabled = []\n");
        let cfg_path = dir.path().join("src").join("config.toml");
        let ctx = test_ctx(dir.path(), OutputFormat::Human, true);

        // Enable http_api -> enables oidc_sso before http_api, skipping implicit builtin
        handle(
            &ctx,
            ExtensionCommand::Enable(ExtensionEnableArgs {
                identifiers: vec!["http_api".to_string()],
                dry_run: false,
                server_version: None,
                schema: None,
            }),
        )
        .await
        .expect("enable succeeds");

        let updated = std::fs::read_to_string(&cfg_path).expect("read config");
        assert!(updated.contains("# keep me"));
        assert!(updated.contains("\"oidc_sso\", \"http_api\""));

        let backup_count = std::fs::read_dir(dir.path().join("src"))
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("config.toml.backup-"))
            })
            .count();
        assert_eq!(backup_count, 1);

        // Disable oidc_sso -> cascades to http_api cleanly
        handle(
            &ctx,
            ExtensionCommand::Disable(ExtensionDisableArgs {
                identifiers: vec!["oidc_sso".to_string()],
                dry_run: false,
                schema: None,
            }),
        )
        .await
        .expect("disable cascades cleanly");

        let disabled_cfg = crate::core::ConfigDocument::load(&cfg_path).expect("reload");
        assert_eq!(
            disabled_cfg.extensions_enabled_raw().expect("read enabled"),
            Some(vec![])
        );
    }

    #[tokio::test]
    async fn handle_list_and_info_fail_on_corrupt_config_not_silently() {
        let dir = setup_workspace("[extensions]\nenabled = \"not_an_array\"\n");
        let ctx = test_ctx(dir.path(), OutputFormat::Human, true);

        assert!(handle(&ctx, ExtensionCommand::List).await.is_err());
        assert!(
            handle(
                &ctx,
                ExtensionCommand::Info(ExtensionIdentifierArgs {
                    identifier: "oidc_sso".to_string()
                })
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn enable_sets_restart_required_when_server_locked_and_is_idempotent() {
        let dir = setup_workspace("debug = false\n# no [extensions] section initially\n");
        let cfg_path = dir.path().join("src").join("config.toml");
        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let ctx = test_ctx(dir.path(), OutputFormat::Human, true);

        // Simulate running server via server.lock
        let _lock = RuntimeLock::acquire(&paths, false).expect("acquire server lock");

        let catalog = discover_catalog(&paths.extensions_root).expect("catalog");
        let doc = ctx.load_config(&paths).expect("load");
        let plan = plan_enable(&catalog, &doc, &paths, &["oidc_sso".to_string()], None, None)
            .expect("enable plan");
        assert!(plan.changed);
        let backup = plan.candidate_doc.save_with_backup().expect("save");
        assert!(backup.is_file());
        assert!(RuntimeLock::is_locked(&paths));

        // Second enable on already-enabled target is idempotent and writes no extra backup
        let backups_before = std::fs::read_dir(dir.path().join("src"))
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("config.toml.backup-"))
            })
            .count();

        handle(
            &ctx,
            ExtensionCommand::Enable(ExtensionEnableArgs {
                identifiers: vec!["oidc_sso".to_string()],
                dry_run: false,
                server_version: None,
                schema: None,
            }),
        )
        .await
        .expect("idempotent enable");

        // Typo on disable errors cleanly instead of silent no-op
        let typo_err = handle(
            &ctx,
            ExtensionCommand::Disable(ExtensionDisableArgs {
                identifiers: vec!["typo_extension".to_string()],
                dry_run: false,
                schema: None,
            }),
        )
        .await
        .expect_err("typo must error");
        assert!(typo_err.to_string().contains("not installed"));

        // Re-check backups count unchanged by idempotent run
        let backups_after = std::fs::read_dir(dir.path().join("src"))
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("config.toml.backup-"))
            })
            .count();
        assert_eq!(backups_before, backups_after);
        assert!(
            std::fs::read_to_string(&cfg_path)
                .expect("read")
                .contains("# no [extensions] section initially")
        );
    }

    #[tokio::test]
    async fn enable_validates_external_config_schema_before_writing() {
        let dir = setup_workspace(
            "[security]\npepper = \"abc\"\n[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n[extensions]\nenabled = []\n",
        );
        let schema_path = dir.path().join("src").join("config.schema.json");
        std::fs::write(
            &schema_path,
            r#"{
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "extensions": {
                        "type": "object",
                        "properties": {
                            "enabled": {
                                "type": "array",
                                "maxItems": 1
                            }
                        }
                    }
                }
            }"#,
        )
        .expect("write schema");

        let cfg_path = dir.path().join("src").join("config.toml");
        let original = std::fs::read_to_string(&cfg_path).expect("read");
        let ctx = test_ctx(dir.path(), OutputFormat::Human, true);

        // Enabling `http_api` adds ["oidc_sso", "http_api"] (2 items) which violates maxItems: 1
        let err = handle(
            &ctx,
            ExtensionCommand::Enable(ExtensionEnableArgs {
                identifiers: vec!["http_api".to_string()],
                dry_run: false,
                server_version: None,
                schema: Some(schema_path),
            }),
        )
        .await
        .expect_err("schema validation failure aborts before write");
        let msg = err.to_string();
        assert!(msg.contains("Schema validation failed"), "unexpected error: {msg}");
        assert!(msg.contains("extensions.enabled"), "unexpected error: {msg}");
        assert_eq!(std::fs::read_to_string(&cfg_path).expect("read"), original);
    }

    fn write_test_zip(pkg_path: &Path, manifest: &str, extra_files: &[(&str, &[u8])]) {
        use std::io::Write;
        use zip::CompressionMethod;
        use zip::ZipWriter;
        use zip::write::SimpleFileOptions;

        let file = std::fs::File::create(pkg_path).expect("create zip");
        let mut writer = ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("manifest.toml", opts).expect("start manifest");
        writer.write_all(manifest.as_bytes()).expect("write manifest");
        writer.start_file("_extension.py", opts).expect("start entry");
        writer.write_all(b"# extension entrypoint\n").expect("write entry");
        for (name, content) in extra_files {
            writer.start_file(*name, opts).expect("start extra");
            writer.write_all(content).expect("write extra");
        }
        writer.finish().expect("finish zip");
    }

    #[tokio::test]
    async fn install_upgrade_and_uninstall_full_lifecycle_including_topo_deps_and_broken_cleanup() {
        let dir = setup_workspace(
            "# keep header comment\n[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n\n[extensions]\nenabled = []\n",
        );
        let ext_root = dir.path().join("src").join("include").join("extensions");

        // Leave an unrelated broken sibling to ensure fault isolation across install/upgrade/uninstall.
        std::fs::create_dir_all(ext_root.join("unrelated_broken")).expect("mkdir broken sibling");
        std::fs::write(
            ext_root.join("unrelated_broken").join("manifest.toml"),
            "invalid = [",
        )
        .expect("write broken sibling");

        // Mark `oidc_sso` as managed by release-manifest.json so install rejects it even if absent on disk.
        std::fs::write(
            dir.path().join("release-manifest.json"),
            r#"{"version":"0.14.0","managed_extensions":["oidc_sso"]}"#,
        )
        .expect("release-manifest");

        let pkgs_dir = dir.path().join("packages");
        std::fs::create_dir_all(&pkgs_dir).expect("pkgs dir");

        let managed_pkg = pkgs_dir.join("oidc_sso.zip");
        write_test_zip(
            &managed_pkg,
            "manifest_version = 3\n[extension]\nidentifier = \"oidc_sso\"\nname = \"OIDC\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            &[],
        );
        let json_yes_ctx = test_ctx(dir.path(), OutputFormat::Json, true);
        let managed_err = handle(
            &json_yes_ctx,
            ExtensionCommand::Install(ExtensionPackageArgs {
                package: managed_pkg,
                sha256: None,
                dry_run: false,
            }),
        )
        .await
        .expect_err("managed extension install blocked");
        assert!(managed_err.to_string().contains("managed by the CFMS server release"));

        // Install `dep_ext` 1.0.0 with --dry-run first, then real install with --sha256.
        let dep_pkg = pkgs_dir.join("dep_ext-1.0.0.zip");
        write_test_zip(
            &dep_pkg,
            "manifest_version = 3\n[extension]\nidentifier = \"dep_ext\"\nname = \"Dep\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
            &[],
        );

        let json_no_ctx = test_ctx(dir.path(), OutputFormat::Json, false);
        handle(
            &json_no_ctx,
            ExtensionCommand::Install(ExtensionPackageArgs {
                package: dep_pkg.clone(),
                sha256: None,
                dry_run: true,
            }),
        )
        .await
        .expect("dry-run succeeds without --yes in json mode");
        assert!(!ext_root.join("dep_ext").exists());

        let refused = handle(
            &json_no_ctx,
            ExtensionCommand::Install(ExtensionPackageArgs {
                package: dep_pkg.clone(),
                sha256: None,
                dry_run: false,
            }),
        )
        .await
        .expect_err("mutating json mode without --yes refuses");
        assert!(refused.to_string().contains("--yes"));

        let opened_dep = OpenedExtensionPackage::open_and_verify(&dep_pkg, None).expect("hash dep");
        let dep_sha = opened_dep.summary.package_sha256.clone();
        drop(opened_dep);

        handle(
            &json_yes_ctx,
            ExtensionCommand::Install(ExtensionPackageArgs {
                package: dep_pkg,
                sha256: Some(dep_sha),
                dry_run: false,
            }),
        )
        .await
        .expect("install dep_ext");
        assert!(ext_root.join("dep_ext").join("manifest.toml").is_file());

        // Install `consumer_ext` 1.0.0 into a custom directory name to test directory preservation across upgrade.
        let custom_dir = ext_root.join("consumer_custom_folder");
        std::fs::create_dir_all(&custom_dir).expect("mkdir custom");
        std::fs::write(
            custom_dir.join("manifest.toml"),
            "manifest_version = 3\n[extension]\nidentifier = \"consumer_ext\"\nname = \"Consumer\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        )
        .expect("manifest");
        std::fs::write(custom_dir.join("_extension.py"), "# v1\n").expect("entry");
        let mut ro_perms = std::fs::metadata(custom_dir.join("_extension.py"))
            .unwrap()
            .permissions();
        ro_perms.set_readonly(true);
        std::fs::set_permissions(custom_dir.join("_extension.py"), ro_perms).expect("set ro");

        // Enable consumer_ext.
        handle(
            &json_yes_ctx,
            ExtensionCommand::Enable(ExtensionEnableArgs {
                identifiers: vec!["consumer_ext".to_string()],
                dry_run: false,
                server_version: None,
                schema: None,
            }),
        )
        .await
        .expect("enable consumer_ext");

        // Upgrade consumer_ext -> 2.0.0 adding dependency on `dep_ext >=1.0.0`.
        let consumer_v2 = pkgs_dir.join("consumer-2.0.0.zip");
        write_test_zip(
            &consumer_v2,
            "manifest_version = 3\n[extension]\nidentifier = \"consumer_ext\"\nname = \"Consumer\"\nversion = \"2.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n[dependencies.extensions]\ndep_ext = \">=1.0.0\"\n",
            &[("extra/new_file.py", b"hello = True\n")],
        );

        // Same version upgrade fails cleanly; v2 succeeds cleanly preserving `consumer_custom_folder` & placing `dep_ext` BEFORE `consumer_ext`.
        handle(
            &json_yes_ctx,
            ExtensionCommand::Upgrade(ExtensionPackageArgs {
                package: consumer_v2.clone(),
                sha256: None,
                dry_run: false,
            }),
        )
        .await
        .expect("upgrade consumer_ext to 2.0.0");
        assert!(custom_dir.join("extra").join("new_file.py").is_file());
        assert!(!ext_root.join("consumer_ext").exists());

        let doc = ConfigDocument::load(&dir.path().join("src").join("config.toml")).expect("reload");
        assert_eq!(
            doc.extensions_enabled_raw().expect("enabled"),
            Some(vec!["dep_ext".to_string(), "consumer_ext".to_string()])
        );
        assert!(doc.raw_source().contains("# keep header comment"));

        // Re-running upgrade with the same 2.0.0 package fails strictly.
        let same_ver_err = handle(
            &json_yes_ctx,
            ExtensionCommand::Upgrade(ExtensionPackageArgs {
                package: consumer_v2,
                sha256: None,
                dry_run: false,
            }),
        )
        .await
        .expect_err("reinstall/same version upgrade rejected");
        assert!(same_ver_err.to_string().contains("strictly newer version"));

        // Uninstall `dep_ext` cascades to disable `consumer_ext`, cleans config, and deletes `dep_ext`.
        handle(
            &json_yes_ctx,
            ExtensionCommand::Uninstall(ExtensionUninstallArgs {
                identifier: "dep_ext".to_string(),
                purge_data: false,
                dry_run: false,
            }),
        )
        .await
        .expect("uninstall dep_ext");
        assert!(!ext_root.join("dep_ext").exists());
        let doc_after_uninstall =
            ConfigDocument::load(&dir.path().join("src").join("config.toml")).expect("reload");
        assert_eq!(
            doc_after_uninstall.extensions_enabled_raw().expect("enabled"),
            Some(Vec::<String>::new())
        );

        // Clean up broken sibling via uninstall by directory name!
        handle(
            &json_yes_ctx,
            ExtensionCommand::Uninstall(ExtensionUninstallArgs {
                identifier: "unrelated_broken".to_string(),
                purge_data: false,
                dry_run: false,
            }),
        )
        .await
        .expect("uninstall broken sibling directory");
        assert!(!ext_root.join("unrelated_broken").exists());
    }

    #[tokio::test]
    async fn uninstall_with_purge_data_respects_server_lock_and_rolls_back_config_on_db_error() {
        use crate::db::schema::ddl::create_head_schema;
        use sqlx::Row;

        let dir = setup_workspace(
            "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n\n[extensions]\nenabled = [\"sample_ext\"]\n",
        );
        let ext_root = dir.path().join("src").join("include").join("extensions");
        write_ext(
            &ext_root,
            "sample_ext",
            "manifest_version = 3\n[extension]\nidentifier = \"sample_ext\"\nname = \"Sample\"\nversion = \"1.0.0\"\nauthors = [\"CFMS\"]\nlicense = \"MIT\"\n",
        );

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let db_cfg = ConfigDocument::load(&paths.config_path)
            .expect("cfg")
            .database_config()
            .expect("db");

        // Note: database has NO tables yet, so purge fails cleanly and MUST roll back `config.toml`!
        let ctx = test_ctx(dir.path(), OutputFormat::Json, true);
        let before_cfg = std::fs::read_to_string(&paths.config_path).expect("read before");
        let db_err = handle(
            &ctx,
            ExtensionCommand::Uninstall(ExtensionUninstallArgs {
                identifier: "sample_ext".to_string(),
                purge_data: true,
                dry_run: false,
            }),
        )
        .await
        .expect_err("missing tables triggers rollback");
        assert!(!db_err.to_string().is_empty());
        assert_eq!(
            std::fs::read_to_string(&paths.config_path).expect("restored config"),
            before_cfg
        );
        assert!(ext_root.join("sample_ext").exists());

        // Initialize DB tables and insert extension-owned rows.
        let pool = crate::db::backend::DbPool::connect(&db_cfg, &paths)
            .await
            .expect("connect");
        create_head_schema(&pool, false).await.expect("schema");
        let crate::db::backend::DbPool::Sqlite(ref sp) = pool else {
            panic!("sqlite");
        };
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('ext.sample', 'sample_ext', 'k', 1, 1, 'str', '\"v\"', 1.0)",
        )
        .execute(sp)
        .await
        .expect("insert option");
        pool.close().await;

        // Running `uninstall --purge-data` while `server.lock` is held fails cleanly without touching DB or dir!
        let server_lock = RuntimeLock::acquire(&paths, false).expect("hold server lock");
        let locked_err = handle(
            &ctx,
            ExtensionCommand::Uninstall(ExtensionUninstallArgs {
                identifier: "sample_ext".to_string(),
                purge_data: true,
                dry_run: false,
            }),
        )
        .await
        .expect_err("purge-data rejected while server holds lock");
        assert!(locked_err.to_string().contains("lock"));
        drop(server_lock);

        // Once server is stopped, --dry-run previews without deleting, then real purge deletes everything cleanly.
        handle(
            &ctx,
            ExtensionCommand::Uninstall(ExtensionUninstallArgs {
                identifier: "sample_ext".to_string(),
                purge_data: true,
                dry_run: true,
            }),
        )
        .await
        .expect("dry-run purge succeeds");
        assert!(ext_root.join("sample_ext").exists());

        handle(
            &ctx,
            ExtensionCommand::Uninstall(ExtensionUninstallArgs {
                identifier: "sample_ext".to_string(),
                purge_data: true,
                dry_run: false,
            }),
        )
        .await
        .expect("purge uninstall succeeds");
        assert!(!ext_root.join("sample_ext").exists());

        let verify_pool = crate::db::backend::DbPool::connect(&db_cfg, &paths)
            .await
            .expect("reconnect");
        let crate::db::backend::DbPool::Sqlite(ref sp2) = verify_pool else {
            panic!("sqlite");
        };
        let opt_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM options WHERE owner = 'sample_ext'")
            .fetch_one(sp2)
            .await
            .expect("count");
        assert_eq!(opt_count, 0);
        let audit = sqlx::query("SELECT action, target FROM audit_entries")
            .fetch_one(sp2)
            .await
            .expect("audit");
        assert_eq!(audit.get::<String, _>("action"), "purge_extension_data");
        assert_eq!(audit.get::<String, _>("target"), "sample_ext");
        verify_pool.close().await;
    }
}
