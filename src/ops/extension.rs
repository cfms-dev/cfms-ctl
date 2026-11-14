//! `cfms-ctl extension`: Open-world `manifest.toml` (v2/v3+) inspection and lifecycle
//! management for built-in and third-party CFMS server extensions.

use std::collections::BTreeMap;
use std::path::Path;
use comfy_table::{Cell, Color};
use serde::{Deserialize, Serialize};
use crate::cli::extension::{
    ExtensionCommand, ExtensionIdentifierArgs, ExtensionPackageArgs, ExtensionPurgeDataArgs,
    ExtensionUninstallArgs,
};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole, styled_table};

/// Open-world representation of `[extension]` inside `manifest.toml`.
/// Unknown fields introduced by newer CFMS versions are captured in `extra`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionMeta {
    #[serde(default)]
    pub identifier: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Open-world representation of `[compatibility]` inside `manifest.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionCompatibility {
    #[serde(default)]
    pub minimum_server_version: Option<String>,
    #[serde(default)]
    pub maximum_server_version: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Open-world representation of `[dependencies]` inside `manifest.toml` (Manifest v3+).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionDependencies {
    #[serde(default)]
    pub extensions: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// Open-world representation of an extension's `manifest.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RawExtensionManifest {
    #[serde(default)]
    pub manifest_version: Option<u32>,
    #[serde(default)]
    pub extension: ExtensionMeta,
    #[serde(default)]
    pub compatibility: ExtensionCompatibility,
    #[serde(default)]
    pub dependencies: ExtensionDependencies,
    #[serde(flatten)]
    pub extra_sections: BTreeMap<String, toml::Value>,
}

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
    pub dependencies: BTreeMap<String, String>,
    pub path: String,
}

/// Report for `cfms-ctl extension list`.
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionListReport {
    pub extensions_root: String,
    pub extensions: Vec<ExtensionSummary>,
}

impl CommandReport for ExtensionListReport {
    fn render_human(&self, ui: &UiConsole) {
        ui.print_section(&format!("Installed Extensions ({})", self.extensions_root));
        if self.extensions.is_empty() {
            println!("No extensions installed.");
            return;
        }
        let mut table = styled_table(&[
            "Identifier",
            "Name",
            "Version",
            "Manifest",
            "Type",
            "Enabled",
            "Min Server",
            "Dependencies",
        ]);
        for ext in &self.extensions {
            let deps = if ext.dependencies.is_empty() {
                "-".to_string()
            } else {
                ext.dependencies
                    .iter()
                    .map(|(k, v)| format!("{k}>={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
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
                Cell::new(ext.minimum_server_version.as_deref().unwrap_or("*")),
                Cell::new(deps),
            ]);
        }
        println!("{table}");
    }
}

impl CommandReport for ExtensionSummary {
    fn render_human(&self, _ui: &UiConsole) {
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
            .row("Description", self.description.clone())
            .row(
                "Min Server Version",
                self.minimum_server_version
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
                        .map(|(k, v)| format!("{k} >= {v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            )
            .row("Directory", self.path.clone());
        table.print();
    }
}

pub async fn handle(ctx: &AppContext, cmd: ExtensionCommand) -> Result<()> {
    match cmd {
        ExtensionCommand::List => handle_list(ctx),
        ExtensionCommand::Info(args) => handle_info(ctx, args),
        ExtensionCommand::Install(_args) => Err(CfmsError::NotImplementedYet("extension install")),
        ExtensionCommand::Upgrade(_args) => Err(CfmsError::NotImplementedYet("extension upgrade")),
        ExtensionCommand::Enable(_args) => Err(CfmsError::NotImplementedYet("extension enable")),
        ExtensionCommand::Disable(_args) => Err(CfmsError::NotImplementedYet("extension disable")),
        ExtensionCommand::Uninstall(_args) => {
            Err(CfmsError::NotImplementedYet("extension uninstall"))
        }
        ExtensionCommand::PurgeData(_args) => {
            Err(CfmsError::NotImplementedYet("extension purge-data"))
        }
    }
}

fn discover_installed_extensions(
    extensions_root: &Path,
    enabled_list: &[String],
) -> Result<Vec<ExtensionSummary>> {
    let mut items = Vec::new();
    if !extensions_root.is_dir() {
        return Ok(items);
    }

    for entry in std::fs::read_dir(extensions_root)? {
        let entry = entry?;
        let dir_path = entry.path();
        if !dir_path.is_dir() {
            continue;
        }
        let manifest_path = dir_path.join("manifest.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&manifest_path)?;
        let parsed: RawExtensionManifest = toml::from_str(&raw).map_err(|e| {
            CfmsError::Extension(format!(
                "Invalid extension manifest '{}': {e}",
                manifest_path.display()
            ))
        })?;
        let identifier = if parsed.extension.identifier.is_empty() {
            entry.file_name().to_string_lossy().to_string()
        } else {
            parsed.extension.identifier.clone()
        };
        let display_name = if parsed.extension.name.is_empty() {
            identifier.clone()
        } else {
            parsed.extension.name.clone()
        };
        let builtin = identifier == "builtin";
        let enabled = builtin || enabled_list.iter().any(|e| e == &identifier);

        items.push(ExtensionSummary {
            identifier,
            display_name,
            version: parsed.extension.version,
            manifest_version: parsed.manifest_version,
            license: parsed.extension.license,
            builtin,
            enabled,
            description: parsed.extension.description,
            minimum_server_version: parsed.compatibility.minimum_server_version,
            dependencies: parsed.dependencies.extensions,
            path: dir_path.display().to_string(),
        });
    }

    items.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    Ok(items)
}

fn handle_list(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let enabled_list = ctx
        .load_config(&paths)
        .and_then(|d| d.summary())
        .map(|s| s.enabled_extensions)
        .unwrap_or_default();

    let extensions = discover_installed_extensions(&paths.extensions_root, &enabled_list)?;
    let report = ExtensionListReport {
        extensions_root: paths.extensions_root.display().to_string(),
        extensions,
    };
    ctx.ui.render(&report);
    Ok(())
}

fn handle_info(ctx: &AppContext, args: ExtensionIdentifierArgs) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let enabled_list = ctx
        .load_config(&paths)
        .and_then(|d| d.summary())
        .map(|s| s.enabled_extensions)
        .unwrap_or_default();

    let extensions = discover_installed_extensions(&paths.extensions_root, &enabled_list)?;
    let Some(found) = extensions
        .into_iter()
        .find(|e| e.identifier == args.identifier)
    else {
        return Err(CfmsError::Extension(format!(
            "Extension '{}' is not installed under '{}'",
            args.identifier,
            paths.extensions_root.display()
        )));
    };
    ctx.ui.render(&found);
    Ok(())
}

#[allow(dead_code)]
type _UnusedArgs = (
    ExtensionPackageArgs,
    ExtensionUninstallArgs,
    ExtensionPurgeDataArgs,
);
