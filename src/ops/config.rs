//! `cfms-ctl config`: Lossless `config.toml` template synchronization, `security.pepper`
//! generation, and database-backed `options` CRUD with optimistic concurrency.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use comfy_table::{Cell, Color};
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use toml_edit::{Item, Table, TableLike, Value as TomlValue, value};
use crate::cli::config::{
    ConfigCommand, ConfigMigrateOptionsArgs, ConfigSyncTemplateArgs, OptionsCommand,
};
use crate::core::migration::{
    ConfigMigrationsManifest, apply_toml_migrations, get_dotted_item, has_dotted_path,
    load_config_migrations, remove_dotted_and_prune,
};
use crate::core::schema::normalize_and_precheck_value;
use crate::core::{CfmsError, ConfigDocument, Result, WorkspacePaths};
use crate::db::{
    DbPool, OptionUpdateInput, OptionsSchemaRegistry, ResolvedOptionRecord, encode_option_value,
    fetch_stored_options, get_option, list_options, reset_option,
    validate_namespace_values_with_schema, validate_option_key, validate_option_namespace,
    write_options_batch, write_options_batches,
};
use crate::ops::AppContext;
use crate::ui::{
    CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort, styled_table,
};

const MAX_JSON_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;

/// Report returned by `cfms-ctl config fill-pepper`.
#[derive(Debug, Clone, Serialize)]
pub struct PepperFillReport {
    pub config_path: String,
    pub backup_path: Option<String>,
    pub updated: bool,
}

impl CommandReport for PepperFillReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new("Security Pepper Initialization");
        table
            .row("Configuration File", self.config_path.clone())
            .row("Updated", self.updated.to_string())
            .row(
                "Backup Created",
                self.backup_path
                    .clone()
                    .unwrap_or_else(|| "(no changes written)".to_string()),
            );
        table.print();
        if self.updated {
            ui.print_success("Generated and saved a new 32-byte hex security.pepper.");
        } else {
            ui.print_success("security.pepper is already configured; no changes needed.");
        }
    }
}

/// Report returned by `cfms-ctl config sync-template`.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigSyncReport {
    pub config_path: String,
    pub template_path: String,
    pub check_only: bool,
    pub changed: bool,
    pub migrations_applied: Vec<String>,
    pub added_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub warnings: Vec<String>,
    pub backup_path: Option<String>,
}

impl CommandReport for ConfigSyncReport {
    fn render_human(&self, ui: &UiConsole) {
        if !self.added_paths.is_empty()
            || !self.removed_paths.is_empty()
            || !self.preserved_paths.is_empty()
            || !self.migrations_applied.is_empty()
        {
            ui.print_section("Configuration Template Sync");
            let mut table = styled_table(&["Change", "Configuration Path"]);
            for rule in &self.migrations_applied {
                table.add_row(vec![Cell::new("Migrate").fg(Color::Yellow), Cell::new(rule)]);
            }
            for path in &self.added_paths {
                table.add_row(vec![Cell::new("Add").fg(Color::Green), Cell::new(path)]);
            }
            for path in &self.removed_paths {
                table.add_row(vec![Cell::new("Remove").fg(Color::Red), Cell::new(path)]);
            }
            for path in &self.preserved_paths {
                table.add_row(vec![
                    Cell::new("Preserve").fg(Color::Cyan),
                    Cell::new(path),
                ]);
            }
            println!("{table}");
        }

        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.check_only {
            if !self.changed {
                ui.print_success("config.toml is synchronized with the template.");
            }
            return;
        }

        if let Some(backup) = &self.backup_path {
            ui.print_success(&format!(
                "Synchronized {}. Backup: {backup}",
                self.config_path
            ));
        } else if !self.changed {
            ui.print_success("config.toml is already synchronized with the template.");
        }
    }
}

/// Single action entry planned or executed by `cfms-ctl config migrate-options`.
#[derive(Debug, Clone, Serialize)]
pub struct OptionMigrationActionItem {
    pub target: String,
    pub action: String,
    pub detail: String,
}

/// Report returned by `cfms-ctl config migrate-options`.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigMigrateOptionsReport {
    pub config_path: String,
    pub migrations_path: Option<String>,
    pub check_only: bool,
    pub changed: bool,
    pub discard_legacy: bool,
    pub toml_migrations_applied: Vec<String>,
    pub items: Vec<OptionMigrationActionItem>,
    pub warnings: Vec<String>,
    pub backup_path: Option<String>,
}

impl CommandReport for ConfigMigrateOptionsReport {
    fn render_human(&self, ui: &UiConsole) {
        if !self.toml_migrations_applied.is_empty() || !self.items.is_empty() {
            ui.print_section("Legacy Options Migration");
            let mut table = styled_table(&["Action", "Target", "Detail"]);
            for rule_id in &self.toml_migrations_applied {
                table.add_row(vec![
                    Cell::new("Migrate TOML").fg(Color::Yellow),
                    Cell::new(rule_id),
                    Cell::new("Normalized legacy config.toml path"),
                ]);
            }
            for item in &self.items {
                let color = match item.action.as_str() {
                    "Import" => Color::Green,
                    "Already imported" => Color::Cyan,
                    "Discard legacy" => Color::Yellow,
                    "Remove obsolete (ignored)" | "Remove empty section" => Color::Red,
                    _ => Color::White,
                };
                table.add_row(vec![
                    Cell::new(&item.action).fg(color),
                    Cell::new(&item.target),
                    Cell::new(&item.detail),
                ]);
            }
            println!("{table}");
        }

        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        if self.check_only {
            if !self.changed {
                ui.print_success("No legacy options or obsolete keys require migration.");
            }
            return;
        }

        if let Some(backup) = &self.backup_path {
            ui.print_success(&format!(
                "Migrated legacy options from {}. Backup: {backup}",
                self.config_path
            ));
        } else if !self.changed {
            ui.print_success("No legacy options or obsolete keys require migration.");
        } else {
            ui.print_success(&format!(
                "Committed legacy option imports from {}.",
                self.config_path
            ));
        }
    }
}

/// Report returned by `cfms-ctl config options list`.
#[derive(Debug, Clone, Serialize)]
pub struct OptionsListReport {
    pub namespace_filter: Option<String>,
    pub options: Vec<ResolvedOptionRecord>,
}

impl CommandReport for OptionsListReport {
    fn render_human(&self, ui: &UiConsole) {
        let title = match &self.namespace_filter {
            Some(ns) => format!("Database Configuration Settings ({ns})"),
            None => "Database Configuration Settings".to_string(),
        };
        ui.print_section(&title);
        if self.options.is_empty() {
            println!("No options found.");
            return;
        }
        let mut table = styled_table(&[
            "Namespace",
            "Owner",
            "Key",
            "Schema",
            "Revision",
            "Source",
            "Value",
        ]);
        for item in &self.options {
            let source = if item.revision > 0 {
                "Database"
            } else {
                "Default"
            };
            let formatted_value =
                serde_json::to_string(&item.value).unwrap_or_else(|_| "null".to_string());
            table.add_row(vec![
                Cell::new(&item.namespace).fg(Color::Cyan),
                Cell::new(&item.owner),
                Cell::new(&item.option_key).fg(Color::Green),
                Cell::new(item.schema_version.to_string()),
                Cell::new(item.revision.to_string()),
                Cell::new(source),
                Cell::new(formatted_value),
            ]);
        }
        println!("{table}");
    }
}

/// Report returned by `cfms-ctl config options get`, `set`, and `reset`.
#[derive(Debug, Clone, Serialize)]
pub struct OptionItemReport {
    #[serde(flatten)]
    pub option: ResolvedOptionRecord,
}

impl CommandReport for OptionItemReport {
    fn render_human(&self, _ui: &UiConsole) {
        let item = &self.option;
        let mut table = KeyValueTable::new(format!(
            "Option: {}/{}",
            item.namespace, item.option_key
        ));
        let val_pretty =
            serde_json::to_string(&item.value).unwrap_or_else(|_| "null".to_string());
        table
            .row("Namespace", item.namespace.clone())
            .row("Owner", item.owner.clone())
            .row("Option Key", item.option_key.clone())
            .row("Schema Version", item.schema_version.to_string())
            .row("Revision", item.revision.to_string())
            .row(
                "Source",
                if item.revision > 0 {
                    "Database".to_string()
                } else {
                    "Default".to_string()
                },
            )
            .row("Value (JSON)", val_pretty)
            .row(
                "Updated At",
                item.updated_at
                    .map_or_else(|| "(default / never persisted)".to_string(), |t| format!("{t:.6}")),
            );
        table.print();
    }
}

/// Report returned by `cfms-ctl config options set-many`.
#[derive(Debug, Clone, Serialize)]
pub struct OptionsBatchReport {
    pub namespace: String,
    pub updated: BTreeMap<String, ResolvedOptionRecord>,
}

impl CommandReport for OptionsBatchReport {
    fn render_human(&self, ui: &UiConsole) {
        ui.print_section(&format!(
            "Updated Options in Namespace '{}'",
            self.namespace
        ));
        let mut table = styled_table(&["Key", "Owner", "Schema", "New Revision", "Value"]);
        for item in self.updated.values() {
            let formatted_value =
                serde_json::to_string(&item.value).unwrap_or_else(|_| "null".to_string());
            table.add_row(vec![
                Cell::new(&item.option_key).fg(Color::Green),
                Cell::new(&item.owner),
                Cell::new(item.schema_version.to_string()),
                Cell::new(item.revision.to_string()).fg(Color::Cyan),
                Cell::new(formatted_value),
            ]);
        }
        println!("{table}");
        ui.print_success(&format!(
            "Atomically updated {} option(s) in '{}'.",
            self.updated.len(),
            self.namespace
        ));
    }
}

pub async fn handle(ctx: &AppContext, cmd: ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::FillPepper => handle_fill_pepper(ctx),
        ConfigCommand::SyncTemplate(args) => handle_sync_template(ctx, args),
        ConfigCommand::MigrateOptions(args) => handle_migrate_options(ctx, args).await,
        ConfigCommand::Options(sub) => handle_options(ctx, sub).await,
    }
}

async fn handle_migrate_options(ctx: &AppContext, args: ConfigMigrateOptionsArgs) -> Result<()> {
    if args.check && ctx.global.yes {
        return Err(CfmsError::InvalidArgument(
            "--check cannot be combined with --yes".to_string(),
        ));
    }

    let paths = ctx.resolve_paths()?;
    let _lock = if args.check {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let registry = load_options_registry_with_override(
        &paths,
        args.schema.as_deref(),
        None,
    )?;
    let migrations_path = paths.discover_config_migrations_path(args.migrations.as_deref())?;
    let explicit_config_schema = args.config_schema.is_some();
    let config_schema_path = paths.discover_config_schema_path(args.config_schema.as_deref())?;
    let template_path = paths
        .config_template_path
        .is_file()
        .then_some(paths.config_template_path.as_path());

    let pool = ctx.connect_db(&paths).await?;
    let tables = pool.list_tables().await?;
    if !tables.iter().any(|t| t == "options") {
        return Err(CfmsError::Database(
            "Database table 'options' does not exist yet; run database migrations first (e.g. `cfms-ctl database upgrade`)."
                .to_string(),
        ));
    }

    let preview = execute_options_migration(OptionsMigrationRequest {
        paths: &paths,
        pool: Some(&pool),
        registry: &registry,
        migrations_path: migrations_path.as_deref(),
        config_schema_path: config_schema_path.as_deref(),
        template_path,
        override_doc: None,
        strict_config_schema: explicit_config_schema,
        dry_run: true,
        discard_legacy: args.discard_legacy,
    })
    .await?;

    if args.check {
        if preview.changed {
            if ctx.ui.format() == OutputFormat::Human {
                preview.render_human(&ctx.ui);
            }
            return Err(CfmsError::Config(format!(
                "config.toml still has {} legacy option/obsolete migration item(s) pending",
                preview.items.len() + preview.toml_migrations_applied.len()
            )));
        }
        ctx.ui.render(&preview);
        return Ok(());
    }

    if !preview.changed {
        ctx.ui.render(&preview);
        return Ok(());
    }

    if ctx.ui.format() == OutputFormat::Human {
        preview.render_human(&ctx.ui);
    }

    confirm_or_abort(
        "Import legacy options into the database, back up config.toml, and clean up migrated keys?",
        ctx.global.yes,
    )?;

    let applied = execute_options_migration(OptionsMigrationRequest {
        paths: &paths,
        pool: Some(&pool),
        registry: &registry,
        migrations_path: migrations_path.as_deref(),
        config_schema_path: config_schema_path.as_deref(),
        template_path,
        override_doc: None,
        strict_config_schema: explicit_config_schema,
        dry_run: false,
        discard_legacy: args.discard_legacy,
    })
    .await?;

    ctx.ui.render(&applied);
    Ok(())
}

fn handle_fill_pepper(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let mut doc = ctx.load_config(&paths)?;

    if let Some(sec_item) = doc.document().get("security")
        && !sec_item.is_table_like()
    {
        return Err(CfmsError::Config(
            "Configuration section 'security' must be a table".to_string(),
        ));
    }

    let summary = doc.summary()?;

    if summary.has_pepper {
        let report = PepperFillReport {
            config_path: paths.config_path.display().to_string(),
            backup_path: None,
            updated: false,
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    let mut random_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);
    let pepper_hex = hex::encode(random_bytes);

    let root = doc.document_mut();
    if !root.contains_key("security") {
        root.insert("security", Item::Table(Table::new()));
    }
    let Some(sec_table) = root["security"].as_table_like_mut() else {
        return Err(CfmsError::Config(
            "Configuration section 'security' must be a table".to_string(),
        ));
    };

    if let Some(existing_pepper) = sec_table.get_mut("pepper")
        && let Some(val_mut) = existing_pepper.as_value_mut()
    {
        let existing_decor = val_mut.decor().clone();
        *val_mut = TomlValue::from(pepper_hex);
        *val_mut.decor_mut() = existing_decor;
    } else {
        sec_table.insert("pepper", value(pepper_hex));
    }

    let backup_path = doc.save_with_backup()?;
    let report = PepperFillReport {
        config_path: paths.config_path.display().to_string(),
        backup_path: Some(backup_path.display().to_string()),
        updated: true,
    };
    ctx.ui.render(&report);
    Ok(())
}

fn handle_sync_template(ctx: &AppContext, args: ConfigSyncTemplateArgs) -> Result<()> {
    if args.check && ctx.global.yes {
        return Err(CfmsError::InvalidArgument(
            "--check cannot be combined with --yes".to_string(),
        ));
    }
    if args.prune && !args.remove.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "--prune cannot be combined with --remove".to_string(),
        ));
    }

    let paths = ctx.resolve_paths()?;
    let template_path = match &args.template {
        Some(explicit) => paths.resolve_file_override(explicit),
        None => paths.config_template_path.clone(),
    };

    if !template_path.is_file() {
        return Err(CfmsError::Config(format!(
            "Configuration template not found: '{}'",
            template_path.display()
        )));
    }

    let schema_path = paths.discover_config_schema_path(args.schema.as_deref())?;
    let migrations_path = paths.discover_config_migrations_path(args.migrations.as_deref())?;

    let mut current_doc = ctx.load_config(&paths)?;
    let template_doc = ConfigDocument::load(&template_path)?;
    let plan = current_doc.sync_with_template_and_migrations(
        &template_doc,
        &args.remove,
        args.prune,
        schema_path.as_deref(),
        migrations_path.as_deref(),
        false,
    )?;

    let mut report = ConfigSyncReport {
        config_path: plan.config_path.display().to_string(),
        template_path: plan.template_path.display().to_string(),
        check_only: args.check,
        changed: plan.changed,
        migrations_applied: plan.migrations_applied,
        added_paths: plan.added_paths,
        removed_paths: plan.removed_paths,
        preserved_paths: plan.preserved_paths,
        warnings: plan.warnings,
        backup_path: None,
    };

    if args.check {
        if report.changed {
            if ctx.ui.format() == OutputFormat::Human {
                report.render_human(&ctx.ui);
            }
            return Err(CfmsError::Config(format!(
                "config.toml is out of sync with template ({} to add, {} to remove)",
                report.added_paths.len(),
                report.removed_paths.len()
            )));
        }
        ctx.ui.render(&report);
        return Ok(());
    }

    if !report.changed {
        ctx.ui.render(&report);
        return Ok(());
    }

    if ctx.ui.format() == OutputFormat::Human && !ctx.global.yes {
        // Show the diff preview before asking for interactive confirmation
        let mut preview = report.clone();
        preview.check_only = true;
        preview.render_human(&ctx.ui);
    }

    confirm_or_abort(
        "Back up config.toml and apply these configuration changes?",
        ctx.global.yes,
    )?;

    let backup_path = current_doc.save_with_backup()?;
    report.backup_path = Some(backup_path.display().to_string());
    ctx.ui.render(&report);
    Ok(())
}

async fn handle_options(ctx: &AppContext, cmd: OptionsCommand) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    match cmd {
        OptionsCommand::List(args) => {
            let registry = OptionsSchemaRegistry::from_workspace(&paths, args.schema.as_deref())?;
            let pool = ctx.connect_db(&paths).await?;
            let options = list_options(&pool, &registry, args.namespace.as_deref()).await?;
            let report = OptionsListReport {
                namespace_filter: args.namespace,
                options,
            };
            ctx.ui.render(&report);
            Ok(())
        }
        OptionsCommand::Get(args) => {
            let registry = OptionsSchemaRegistry::from_workspace(&paths, args.schema.as_deref())?;
            let pool = ctx.connect_db(&paths).await?;
            let option = get_option(&pool, &registry, &args.namespace, &args.option_key).await?;
            ctx.ui.render(&OptionItemReport { option });
            Ok(())
        }
        OptionsCommand::Set(args) => {
            let registry = OptionsSchemaRegistry::from_workspace(&paths, args.schema.as_deref())?;
            let value = read_single_option_json(&args.payload_file)?;
            let pool = ctx.connect_db(&paths).await?;
            let mut updates = BTreeMap::new();
            updates.insert(
                args.option_key.clone(),
                OptionUpdateInput {
                    value,
                    expected_revision: args.expected_revision,
                },
            );
            let mut updated =
                write_options_batch(&pool, &registry, &args.namespace, updates).await?;
            let option = updated.remove(&args.option_key).ok_or_else(|| {
                CfmsError::Database(format!(
                    "Failed to retrieve updated option {}/{}",
                    args.namespace, args.option_key
                ))
            })?;
            ctx.ui.render(&OptionItemReport { option });
            Ok(())
        }
        OptionsCommand::SetMany(args) => {
            let registry = OptionsSchemaRegistry::from_workspace(&paths, args.schema.as_deref())?;
            let updates = read_many_options_json(&args.payload_file)?;
            let pool = ctx.connect_db(&paths).await?;
            let updated =
                write_options_batch(&pool, &registry, &args.namespace, updates).await?;
            let report = OptionsBatchReport {
                namespace: args.namespace,
                updated,
            };
            ctx.ui.render(&report);
            Ok(())
        }
        OptionsCommand::Reset(args) => {
            let registry = OptionsSchemaRegistry::from_workspace(&paths, args.schema.as_deref())?;
            let pool = ctx.connect_db(&paths).await?;
            let option = reset_option(
                &pool,
                &registry,
                &args.namespace,
                &args.option_key,
                args.expected_revision,
            )
            .await?;
            ctx.ui.render(&OptionItemReport { option });
            Ok(())
        }
    }
}

fn read_json_payload_text(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to read options JSON file '{}': {e}",
            path.display()
        ))
    })?;
    if metadata.len() > MAX_JSON_PAYLOAD_BYTES {
        return Err(CfmsError::Config(format!(
            "Options JSON file '{}' exceeds the 16 MiB limit",
            path.display()
        )));
    }
    std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to read options JSON file '{}': {e}",
            path.display()
        ))
    })
}

/// Read and parse a single-option JSON value from `path`.
pub fn read_single_option_json(path: &Path) -> Result<Value> {
    let raw = read_json_payload_text(path)?;
    serde_json::from_str::<Value>(&raw).map_err(|e| {
        CfmsError::Config(format!(
            "Unable to parse options JSON in '{}': {e}",
            path.display()
        ))
    })
}

/// Parse a `set-many` JSON payload strictly (`{ "<option_key>": { "value": ..., "expected_revision": <u64> } }`).
pub fn parse_set_many_payload(raw_json: &str) -> Result<BTreeMap<String, OptionUpdateInput>> {
    let root: Value = serde_json::from_str(raw_json)
        .map_err(|e| CfmsError::Config(format!("Invalid options update JSON: {e}")))?;
    let Some(obj) = root.as_object() else {
        return Err(CfmsError::Config(
            "Invalid options update JSON: top-level value must be a JSON object".to_string(),
        ));
    };
    if obj.is_empty() {
        return Err(CfmsError::Config(
            "Options update JSON must contain at least one setting".to_string(),
        ));
    }

    let mut updates = BTreeMap::new();
    for (key, entry_val) in obj {
        validate_option_key(key)?;
        let Some(entry_obj) = entry_val.as_object() else {
            return Err(CfmsError::Config(format!(
                "Invalid options update JSON at '{key}': entry must be an object"
            )));
        };
        for field_name in entry_obj.keys() {
            if field_name != "value" && field_name != "expected_revision" {
                return Err(CfmsError::Config(format!(
                    "Invalid options update JSON at '{key}.{field_name}': Extra inputs are not permitted"
                )));
            }
        }
        let Some(value) = entry_obj.get("value") else {
            return Err(CfmsError::Config(format!(
                "Invalid options update JSON at '{key}.value': Field required"
            )));
        };
        let Some(rev_val) = entry_obj.get("expected_revision") else {
            return Err(CfmsError::Config(format!(
                "Invalid options update JSON at '{key}.expected_revision': Field required"
            )));
        };
        let Value::Number(rev_num) = rev_val else {
            return Err(CfmsError::Config(format!(
                "Invalid options update JSON at '{key}.expected_revision': Input should be a valid non-negative integer"
            )));
        };
        let rev_str = rev_num.to_string();
        let Ok(expected_revision) = rev_str.parse::<u64>() else {
            return Err(CfmsError::Config(format!(
                "Invalid options update JSON at '{key}.expected_revision': Input should be a valid non-negative integer"
            )));
        };
        updates.insert(
            key.clone(),
            OptionUpdateInput {
                value: value.clone(),
                expected_revision,
            },
        );
    }

    Ok(updates)
}

/// Read and parse a `set-many` JSON file from `path`.
pub fn read_many_options_json(path: &Path) -> Result<BTreeMap<String, OptionUpdateInput>> {
    let raw = read_json_payload_text(path)?;
    parse_set_many_payload(&raw)
}

pub(crate) struct OptionsMigrationRequest<'a> {
    pub paths: &'a WorkspacePaths,
    pub pool: Option<&'a DbPool>,
    pub registry: &'a OptionsSchemaRegistry,
    pub migrations_path: Option<&'a Path>,
    pub config_schema_path: Option<&'a Path>,
    pub template_path: Option<&'a Path>,
    pub override_doc: Option<ConfigDocument>,
    pub strict_config_schema: bool,
    pub dry_run: bool,
    pub discard_legacy: bool,
}

#[derive(Default)]
struct ExtractedNamespaceBucket {
    owner: String,
    raw_values: BTreeMap<String, Value>,
    toml_paths_to_remove: Vec<String>,
    empty_sections: Vec<String>,
}

/// Resolve an `OptionsSchemaRegistry` accepting either a core `options.schema.json` file or a schemas directory.
pub(crate) fn load_options_registry_with_override(
    paths: &WorkspacePaths,
    explicit_schema: Option<&Path>,
    explicit_extensions_root: Option<&Path>,
) -> Result<OptionsSchemaRegistry> {
    let mut inferred_extensions_root: Option<PathBuf> =
        explicit_extensions_root.map(Path::to_path_buf);

    let core_schema = match explicit_schema {
        Some(raw_override) => {
            let resolved = paths.resolve_file_override(raw_override);
            if resolved.is_dir() {
                let candidate = resolved.join("options.schema.json");
                let nested = resolved.join("src").join("include").join("schemas").join("options.schema.json");
                let picked = if candidate.is_file() {
                    candidate
                } else if nested.is_file() {
                    if inferred_extensions_root.is_none() {
                        let ext_dir = resolved.join("src").join("include").join("extensions");
                        if ext_dir.is_dir() {
                            inferred_extensions_root = Some(ext_dir);
                        }
                    }
                    nested
                } else {
                    return Err(CfmsError::Config(format!(
                        "Options schema file 'options.schema.json' not found under directory '{}'",
                        resolved.display()
                    )));
                };
                if inferred_extensions_root.is_none() {
                    let sibling_ext = resolved.join("extensions");
                    let parent_ext = resolved.parent().map(|p| p.join("extensions"));
                    if sibling_ext.is_dir() {
                        inferred_extensions_root = Some(sibling_ext);
                    } else if let Some(ext_dir) = parent_ext
                        && ext_dir.is_dir()
                    {
                        inferred_extensions_root = Some(ext_dir);
                    }
                }
                Some(picked)
            } else {
                paths.discover_options_schema_path(Some(raw_override))?
            }
        }
        None => paths.discover_options_schema_path(None)?,
    };

    let ext_dir = inferred_extensions_root.unwrap_or_else(|| paths.extensions_root.clone());
    OptionsSchemaRegistry::load(core_schema.as_deref(), Some(ext_dir.as_path()))
}

pub(crate) async fn execute_options_migration(
    req: OptionsMigrationRequest<'_>,
) -> Result<ConfigMigrateOptionsReport> {
    let config_doc = match req.override_doc {
        Some(doc) => doc,
        None => ConfigDocument::load(&req.paths.config_path)?,
    };
    let Some(migrations_path) = req.migrations_path else {
        return Ok(ConfigMigrateOptionsReport {
            config_path: req.paths.config_path.display().to_string(),
            migrations_path: None,
            check_only: req.dry_run,
            changed: false,
            discard_legacy: req.discard_legacy,
            toml_migrations_applied: Vec::new(),
            items: Vec::new(),
            warnings: vec![
                "No config.migrations.json found; skipping legacy option migration.".to_string(),
            ],
            backup_path: None,
        });
    };

    let manifest = load_config_migrations(migrations_path)?;
    let template_doc = match req.template_path {
        Some(path) if path.is_file() => Some(ConfigDocument::load(path)?),
        _ => None,
    };

    let mut working_doc = config_doc.document().clone();
    let toml_outcome = apply_toml_migrations(
        &mut working_doc,
        &manifest,
        template_doc.as_ref().map(ConfigDocument::document),
    )?;

    let mut warnings = Vec::new();
    let mut seen_warnings = BTreeSet::new();
    for w in toml_outcome.warnings {
        if seen_warnings.insert(w.clone()) {
            warnings.push(w);
        }
    }

    let stored_options = match req.pool {
        Some(pool) => fetch_stored_options(pool, None).await?,
        None => BTreeMap::new(),
    };

    let (ns_order, buckets) = collect_option_buckets(working_doc.as_table(), &manifest)?;

    let mut pending_batches: Vec<(String, BTreeMap<String, OptionUpdateInput>)> = Vec::new();
    let mut items: Vec<OptionMigrationActionItem> = Vec::new();
    let mut all_toml_removals: Vec<String> = Vec::new();

    for ns in ns_order {
        let Some(bucket) = buckets.get(&ns) else {
            continue;
        };
        validate_option_namespace(&ns)?;

        for empty_sec in &bucket.empty_sections {
            all_toml_removals.push(empty_sec.clone());
            if bucket.raw_values.is_empty() {
                items.push(OptionMigrationActionItem {
                    target: empty_sec.clone(),
                    action: "Remove empty section".to_string(),
                    detail: format!("Empty legacy table mapped to {ns}"),
                });
            }
        }

        if bucket.raw_values.is_empty() {
            continue;
        }

        let ns_spec = req.registry.get_namespace(&ns);
        if ns_spec.is_none() && req.registry.has_core_schema() {
            return Err(CfmsError::Config(format!(
                "Cannot resolve option declarations for '{ns}' (owner '{}')",
                bucket.owner
            )));
        }

        let allow_additional = ns_spec
            .and_then(|s| s.raw_schema.get("additionalProperties"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut namespace_imports = BTreeMap::new();
        let mut effective_namespace_values: BTreeMap<String, Value> = stored_options
            .iter()
            .filter(|((stored_ns, _), _)| stored_ns == &ns)
            .map(|((_, k), rec)| (k.clone(), rec.value.clone()))
            .collect();

        for (key, raw_val) in &bucket.raw_values {
            validate_option_key(key)?;
            let normalized = if let Some(spec) = ns_spec
                && spec.has_detailed_schema
            {
                if let Some(prop_spec) = spec.properties.get(key) {
                    let norm =
                        normalize_and_precheck_value(key, &prop_spec.raw_property_schema, raw_val)?;
                    let _ = encode_option_value(&norm)?;
                    norm
                } else if allow_additional {
                    let _ = encode_option_value(raw_val)?;
                    raw_val.clone()
                } else {
                    return Err(CfmsError::Config(format!(
                        "No option definition for {ns}/{key}"
                    )));
                }
            } else {
                let _ = encode_option_value(raw_val)?;
                raw_val.clone()
            };

            match stored_options.get(&(ns.clone(), key.clone())) {
                None => {
                    effective_namespace_values.insert(key.clone(), normalized.clone());
                    namespace_imports.insert(
                        key.clone(),
                        OptionUpdateInput {
                            value: normalized,
                            expected_revision: 0,
                        },
                    );
                    items.push(OptionMigrationActionItem {
                        target: format!("{ns}/{key}"),
                        action: "Import".to_string(),
                        detail: "Legacy config.toml value (revision 0 -> 1)".to_string(),
                    });
                }
                Some(db_rec) => {
                    if db_rec.value == normalized {
                        items.push(OptionMigrationActionItem {
                            target: format!("{ns}/{key}"),
                            action: "Already imported".to_string(),
                            detail: format!(
                                "DB revision {} already matches config.toml",
                                db_rec.revision
                            ),
                        });
                    } else if req.discard_legacy {
                        items.push(OptionMigrationActionItem {
                            target: format!("{ns}/{key}"),
                            action: "Discard legacy".to_string(),
                            detail: format!(
                                "Keep authoritative DB revision {}; discard differing legacy TOML value",
                                db_rec.revision
                            ),
                        });
                    } else {
                        return Err(CfmsError::OptionConflict(format!(
                            "Option conflict for {ns}/{key}: database has authoritative revision {} \
                             with a different value than legacy config.toml; resolve manually or re-run with --discard-legacy",
                            db_rec.revision
                        )));
                    }
                }
            }
        }

        if let Some(spec) = ns_spec
            && spec.has_detailed_schema
            && !namespace_imports.is_empty()
        {
            let validated_map =
                validate_namespace_values_with_schema(spec, &effective_namespace_values)?;
            for (key, input) in &mut namespace_imports {
                if let Some(validated_val) = validated_map.get(key) {
                    input.value = validated_val.clone();
                }
            }
        }

        if !namespace_imports.is_empty() {
            pending_batches.push((ns.clone(), namespace_imports));
        }

        all_toml_removals.extend(bucket.toml_paths_to_remove.iter().cloned());
    }

    for rule in &manifest.obsolete_paths {
        if has_dotted_path(working_doc.as_table(), &rule.path) {
            all_toml_removals.push(rule.path.clone());
            if let Some(w) = &rule.warning
                && seen_warnings.insert(w.clone())
            {
                warnings.push(w.clone());
            }
            items.push(OptionMigrationActionItem {
                target: rule.path.clone(),
                action: "Remove obsolete (ignored)".to_string(),
                detail: rule
                    .warning
                    .clone()
                    .unwrap_or_else(|| "Obsolete key with no replacement".to_string()),
            });
        }
    }

    let mut cleaned_doc = working_doc;
    for path in &all_toml_removals {
        remove_dotted_and_prune(cleaned_doc.as_table_mut(), path, true);
    }

    let toml_changed = cleaned_doc.to_string() != config_doc.raw_source();
    let changed = !pending_batches.is_empty()
        || !items.is_empty()
        || !toml_outcome.applied_rule_ids.is_empty()
        || toml_changed;

    let mut preview_doc = config_doc.clone();
    *preview_doc.document_mut() = cleaned_doc.clone();
    match preview_doc.validate_with_schema(req.config_schema_path) {
        Ok(schema_warnings) => {
            for w in schema_warnings {
                if seen_warnings.insert(w.clone()) {
                    warnings.push(w);
                }
            }
        }
        Err(err) => {
            let unsynced_template = !req.strict_config_schema
                && template_doc.as_ref().is_some_and(|tpl| {
                    has_missing_template_paths(cleaned_doc.as_table(), tpl.document().as_table())
                });
            if unsynced_template {
                let warn = format!(
                    "Cleaned config.toml does not yet satisfy config.schema.json; run `cfms-ctl config sync-template` to merge new template keys ({err})"
                );
                if seen_warnings.insert(warn.clone()) {
                    warnings.push(warn);
                }
            } else {
                return Err(err);
            }
        }
    }

    let mut backup_path = None;
    if !req.dry_run {
        if !pending_batches.is_empty() {
            let pool = req.pool.ok_or_else(|| {
                CfmsError::Database(
                    "Database connection is required to commit legacy option imports".to_string(),
                )
            })?;
            write_options_batches(pool, req.registry, &pending_batches, "cfms_ctl_migration")
                .await?;
        }
        if toml_changed {
            let saved_backup = preview_doc.save_with_backup()?;
            backup_path = Some(saved_backup.display().to_string());
        }
    }

    Ok(ConfigMigrateOptionsReport {
        config_path: req.paths.config_path.display().to_string(),
        migrations_path: Some(migrations_path.display().to_string()),
        check_only: req.dry_run,
        changed,
        discard_legacy: req.discard_legacy,
        toml_migrations_applied: toml_outcome.applied_rule_ids,
        items,
        warnings,
        backup_path,
    })
}

fn collect_option_buckets(
    root: &dyn TableLike,
    manifest: &ConfigMigrationsManifest,
) -> Result<(Vec<String>, BTreeMap<String, ExtractedNamespaceBucket>)> {
    let obsolete_set: BTreeSet<&str> = manifest
        .obsolete_paths
        .iter()
        .map(|r| r.path.as_str())
        .collect();
    let mut order: Vec<String> = Vec::new();
    let mut buckets: BTreeMap<String, ExtractedNamespaceBucket> = BTreeMap::new();

    for group in &manifest.options_migrations {
        let Some(item) = get_dotted_item(root, &group.toml_path) else {
            continue;
        };
        if item.is_none() {
            continue;
        }
        let tbl = item.as_table_like().ok_or_else(|| {
            CfmsError::Config(format!(
                "Legacy option section '{}' in config.toml must be a table",
                group.toml_path
            ))
        })?;

        if !buckets.contains_key(&group.namespace) {
            order.push(group.namespace.clone());
        }
        let bucket = buckets
            .entry(group.namespace.clone())
            .or_insert_with(|| ExtractedNamespaceBucket {
                owner: group.owner.clone(),
                ..Default::default()
            });

        match &group.keys {
            Some(keys) => {
                for key in keys {
                    if let Some(val_item) = tbl.get(key)
                        && !val_item.is_none()
                    {
                        let json_val = toml_item_to_json(val_item)?;
                        bucket.raw_values.insert(key.clone(), json_val);
                        bucket
                            .toml_paths_to_remove
                            .push(format!("{}.{key}", group.toml_path));
                    }
                }
            }
            None => {
                let mut extracted_any = false;
                for (key, val_item) in tbl.iter() {
                    if val_item.is_none() {
                        continue;
                    }
                    let full_key = format!("{}.{key}", group.toml_path);
                    if obsolete_set.contains(full_key.as_str()) {
                        continue;
                    }
                    let json_val = toml_item_to_json(val_item)?;
                    bucket.raw_values.insert(key.to_string(), json_val);
                    extracted_any = true;
                }
                bucket.toml_paths_to_remove.push(group.toml_path.clone());
                if !extracted_any {
                    bucket.empty_sections.push(group.toml_path.clone());
                }
            }
        }
    }

    Ok((order, buckets))
}

fn toml_item_to_json(item: &Item) -> Result<Value> {
    match item {
        Item::Value(v) => toml_value_to_json(v),
        Item::Table(t) => toml_table_like_to_json(t),
        Item::ArrayOfTables(aot) => {
            let mut arr = Vec::with_capacity(aot.len());
            for t in aot {
                arr.push(toml_table_like_to_json(t)?);
            }
            Ok(Value::Array(arr))
        }
        Item::None => Ok(Value::Null),
    }
}

fn toml_table_like_to_json(table: &dyn TableLike) -> Result<Value> {
    let mut map = serde_json::Map::new();
    for (k, v) in table.iter() {
        if !v.is_none() {
            map.insert(k.to_string(), toml_item_to_json(v)?);
        }
    }
    Ok(Value::Object(map))
}

fn toml_value_to_json(val: &TomlValue) -> Result<Value> {
    match val {
        TomlValue::String(s) => Ok(Value::String(s.value().clone())),
        TomlValue::Integer(i) => Ok(Value::Number((*i.value()).into())),
        TomlValue::Float(f) => serde_json::Number::from_f64(*f.value())
            .map(Value::Number)
            .ok_or_else(|| {
                CfmsError::Config("Non-finite floating point number in config.toml".to_string())
            }),
        TomlValue::Boolean(b) => Ok(Value::Bool(*b.value())),
        TomlValue::Datetime(dt) => Ok(Value::String(dt.value().to_string())),
        TomlValue::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for elem in arr {
                out.push(toml_value_to_json(elem)?);
            }
            Ok(Value::Array(out))
        }
        TomlValue::InlineTable(it) => toml_table_like_to_json(it),
    }
}

fn has_missing_template_paths(current: &dyn TableLike, template: &dyn TableLike) -> bool {
    for (key, tpl_item) in template.iter() {
        if tpl_item.is_none() {
            continue;
        }
        let Some(cur_item) = current.get(key) else {
            return true;
        };
        if cur_item.is_none() {
            return true;
        }
        if let (Some(cur_tbl), Some(tpl_tbl)) =
            (cur_item.as_table_like(), tpl_item.as_table_like())
            && has_missing_template_paths(cur_tbl, tpl_tbl)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_set_many_payload_strict_validation() {
        let valid = r#"{
            "min_length": {"value": 10, "expected_revision": 0},
            "require_symbol": {"value": true, "expected_revision": 2}
        }"#;
        let parsed = parse_set_many_payload(valid).expect("valid set-many payload");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["min_length"].value, json!(10));
        assert_eq!(parsed["min_length"].expected_revision, 0);
        assert_eq!(parsed["require_symbol"].value, json!(true));
        assert_eq!(parsed["require_symbol"].expected_revision, 2);

        // Reject empty map
        assert!(parse_set_many_payload("{}").is_err());

        // Reject extra fields
        let extra = r#"{"min_length": {"value": 10, "expected_revision": 0, "extra": 1}}"#;
        assert!(
            parse_set_many_payload(extra)
                .unwrap_err()
                .to_string()
                .contains("Extra inputs are not permitted")
        );

        // Reject float or negative expected_revision
        for bad_rev in ["1.5", "-1", "\"0\"", "true"] {
            let payload = format!(
                r#"{{"min_length": {{"value": 10, "expected_revision": {bad_rev}}}}}"#
            );
            assert!(parse_set_many_payload(&payload).is_err());
        }
    }

    #[tokio::test]
    async fn test_migrate_options_sync_reject_check_conflict_discard_and_audit() {
        use sqlx::Row;
        use crate::cli::GlobalOpts;
        use crate::db::schema::create_head_schema;
        use crate::db::write_options_batch;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let src_dir = root.join("src");
        let schemas_dir = src_dir.join("include").join("schemas");
        let ext_dir = src_dir.join("include").join("extensions");
        std::fs::create_dir_all(&schemas_dir).unwrap();
        std::fs::create_dir_all(ext_dir.join("oidc_sso")).unwrap();

        let template_toml = r#"[database]
type = "sqlite"
name = "cfms.db"

[security]
pepper = ""

[server]
secret_key = ""

[extensions]
enabled = []
"#;
        std::fs::write(src_dir.join("config.toml.sample"), template_toml).unwrap();

        let config_schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": true,
            "properties": {
                "database": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "type": { "type": "string", "enum": ["sqlite", "mysql", "postgresql"] },
                        "name": { "type": "string", "minLength": 1 }
                    },
                    "required": ["type", "name"]
                },
                "security": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "pepper": { "type": "string" }
                    },
                    "required": ["pepper"]
                },
                "server": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "secret_key": { "type": "string" }
                    },
                    "required": ["secret_key"]
                },
                "extensions": {
                    "type": "object",
                    "additionalProperties": true,
                    "properties": {
                        "enabled": { "type": "array", "items": { "type": "string" } }
                    }
                }
            },
            "required": ["database", "security", "server"]
        });
        std::fs::write(
            schemas_dir.join("config.schema.json"),
            serde_json::to_vec_pretty(&config_schema).unwrap(),
        )
        .unwrap();

        let options_schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "security.password": {
                    "type": "object",
                    "x-cfms-owner": "core",
                    "x-cfms-schema-version": 1,
                    "additionalProperties": false,
                    "properties": {
                        "passwd_min_len": { "type": "integer", "minimum": 1, "default": 8 },
                        "passwd_rules": {
                            "type": "array",
                            "items": { "type": "string", "x-format": "regex" },
                            "default": []
                        },
                        "passwd_min_passed_count": { "type": "integer", "minimum": 0, "default": 0 }
                    }
                },
                "document.upload.creation_risk_control": {
                    "type": "object",
                    "x-cfms-owner": "core",
                    "x-cfms-schema-version": 1,
                    "additionalProperties": false,
                    "properties": {
                        "refill_period_seconds": { "type": "integer", "minimum": 1, "default": 60 },
                        "account_refill_tokens": { "type": "integer", "minimum": 1, "default": 10 },
                        "account_capacity": { "type": "integer", "minimum": 1, "default": 10 }
                    },
                    "x-invariants": [
                        {
                            "rule": "order",
                            "lower": "account_refill_tokens",
                            "upper": "account_capacity",
                            "allow_equal": true,
                            "message": "account_refill_tokens cannot exceed account_capacity"
                        }
                    ]
                }
            }
        });
        std::fs::write(
            schemas_dir.join("options.schema.json"),
            serde_json::to_vec_pretty(&options_schema).unwrap(),
        )
        .unwrap();

        let oidc_schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "ext.oidc_sso": {
                    "type": "object",
                    "x-cfms-owner": "oidc_sso",
                    "x-cfms-schema-version": 1,
                    "additionalProperties": false,
                    "properties": {
                        "issuer": { "type": "string", "minLength": 1, "x-normalize": "trim" }
                    }
                }
            }
        });
        std::fs::write(
            ext_dir.join("oidc_sso").join("options.schema.json"),
            serde_json::to_vec_pretty(&oidc_schema).unwrap(),
        )
        .unwrap();

        let migrations_json = serde_json::json!({
            "format_version": 1,
            "toml_migrations": [
                {
                    "id": "database_db_name_to_name",
                    "description": "Rename database.db_name to database.name",
                    "ops": [
                        { "op": "rename_or_move", "from": "database.db_name", "to": "database.name" },
                        { "op": "remove", "path": "database.db_name" }
                    ]
                },
                {
                    "id": "sso_oidc_to_extensions",
                    "description": "Move sso.oidc under extensions.oidc_sso",
                    "ops": [
                        { "op": "move_table_entries", "from_table": "sso.oidc", "to_table": "extensions.oidc_sso", "exclude": ["enabled"] },
                        { "op": "append_if_true", "from_flag": "sso.oidc.enabled", "to_array": "extensions.enabled", "value": "oidc_sso" },
                        { "op": "remove", "path": "sso.oidc" },
                        { "op": "remove", "path": "sso" }
                    ]
                },
                {
                    "id": "document_upload_creation_rate_to_risk_control",
                    "description": "Convert creation_rate_*",
                    "ops": [
                        { "op": "copy_positive_int", "from": "document.upload.creation_rate_window_seconds", "to": "document.upload.creation_risk_control.refill_period_seconds" },
                        { "op": "copy_positive_int", "from": "document.upload.creation_rate_per_user", "to": "document.upload.creation_risk_control.account_refill_tokens" },
                        { "op": "copy_scaled_int", "from": "document.upload.creation_rate_per_user", "to": "document.upload.creation_risk_control.account_capacity", "div_ceil": 3, "min_from_path": "document.upload.creation_risk_control.account_capacity", "default_min": 10 },
                        { "op": "remove", "path": "document.upload.creation_rate_window_seconds" },
                        { "op": "remove", "path": "document.upload.creation_rate_per_user" }
                    ]
                },
                {
                    "id": "security_passwd_must_contain_to_rules",
                    "description": "Convert passwd_must_contain to passwd_rules",
                    "ops": [
                        { "op": "char_groups_to_regex_list", "from": "security.passwd_must_contain", "to_rules": "security.passwd_rules", "to_count": "security.passwd_min_passed_count" },
                        { "op": "remove", "path": "security.passwd_must_contain" }
                    ]
                }
            ],
            "options_migrations": [
                {
                    "toml_path": "security",
                    "namespace": "security.password",
                    "owner": "core",
                    "keys": ["passwd_min_len", "passwd_rules", "passwd_min_passed_count"]
                },
                {
                    "toml_path": "document.upload.creation_risk_control",
                    "namespace": "document.upload.creation_risk_control",
                    "owner": "core"
                },
                {
                    "toml_path": "extensions.oidc_sso",
                    "namespace": "ext.oidc_sso",
                    "owner": "oidc_sso"
                }
            ],
            "obsolete_paths": [
                { "path": "document.allow_name_duplicate", "action": "warn_and_ignore", "warning": "document.allow_name_duplicate is obsolete" }
            ]
        });
        std::fs::write(
            schemas_dir.join("config.migrations.json"),
            serde_json::to_vec_pretty(&migrations_json).unwrap(),
        )
        .unwrap();

        let legacy_toml = r#"# Operator header comment
[database]
type = "sqlite"
# Legacy db_name
db_name = "legacy.db"

[security]
# Keep pepper comment
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
passwd_min_len = 8
passwd_must_contain = ["AB", "01"]

[sso.oidc]
enabled = true
issuer = "  https://idp.example.com  "

[document]
allow_name_duplicate = true

[document.upload]
creation_rate_window_seconds = 120
creation_rate_per_user = 6

[extensions]
enabled = []

[custom]
keep_me = true
"#;
        std::fs::write(src_dir.join("config.toml"), legacy_toml).unwrap();

        let paths = WorkspacePaths::discover(Some(root), None).unwrap();
        let ctx = AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output: OutputFormat::Json,
                yes: true,
                verbose: false,
            },
            UiConsole::new(OutputFormat::Json),
        );

        let pool = ctx.connect_db(&paths).await.unwrap();
        create_head_schema(&pool, false).await.unwrap();

        // 1. Standalone sync-template must reject when legacy options / obsolete keys remain
        let sync_err = handle_sync_template(
            &ctx,
            ConfigSyncTemplateArgs {
                check: false,
                remove: Vec::new(),
                prune: false,
                template: None,
                schema: None,
                migrations: None,
            },
        )
        .unwrap_err();
        assert!(sync_err.to_string().contains("migrate-options"), "err={sync_err}");
        assert_eq!(std::fs::read_to_string(&paths.config_path).unwrap(), legacy_toml);

        // 2. migrate-options --check must fail with pending items and leave DB + config untouched
        let check_ctx = AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output: OutputFormat::Json,
                yes: false,
                verbose: false,
            },
            UiConsole::new(OutputFormat::Json),
        );
        let check_err = handle_migrate_options(
            &check_ctx,
            ConfigMigrateOptionsArgs {
                check: true,
                discard_legacy: false,
                schema: None,
                migrations: None,
                config_schema: None,
            },
        )
        .await
        .unwrap_err();
        assert!(check_err.to_string().contains("pending"), "check_err={check_err}");
        assert!(fetch_stored_options(&pool, None).await.unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&paths.config_path).unwrap(), legacy_toml);

        // 3. Seed conflicting DB option revision=1 and ensure non-discard mode errors cleanly & atomically
        let registry = OptionsSchemaRegistry::from_workspace(&paths, None).unwrap();
        let mut seed_updates = BTreeMap::new();
        seed_updates.insert(
            "passwd_min_len".to_string(),
            OptionUpdateInput {
                value: json!(16),
                expected_revision: 0,
            },
        );
        write_options_batch(&pool, &registry, "security.password", seed_updates)
            .await
            .unwrap();

        let conflict_err = handle_migrate_options(
            &ctx,
            ConfigMigrateOptionsArgs {
                check: false,
                discard_legacy: false,
                schema: None,
                migrations: None,
                config_schema: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(conflict_err, CfmsError::OptionConflict(_)));
        // Atomicity: other options must NOT have been committed on conflict
        let stored_after_conflict = fetch_stored_options(&pool, None).await.unwrap();
        assert_eq!(stored_after_conflict.len(), 1);

        // 4. Invalid regex in config.toml should fail strict options.schema validation
        let mut bad_regex_toml = legacy_toml.replace("passwd_must_contain = [\"AB\", \"01\"]", "passwd_rules = [\"[unclosed\"]\npasswd_min_passed_count = 1");
        std::fs::write(&paths.config_path, &bad_regex_toml).unwrap();
        let regex_err = handle_migrate_options(
            &ctx,
            ConfigMigrateOptionsArgs {
                check: false,
                discard_legacy: true,
                schema: None,
                migrations: None,
                config_schema: None,
            },
        )
        .await
        .unwrap_err();
        assert!(regex_err.to_string().contains("Invalid regular expression"), "regex_err={regex_err}");

        // Restore valid legacy TOML and apply with --discard-legacy
        bad_regex_toml.clear();
        let _ = bad_regex_toml;
        std::fs::write(&paths.config_path, legacy_toml).unwrap();
        handle_migrate_options(
            &ctx,
            ConfigMigrateOptionsArgs {
                check: false,
                discard_legacy: true,
                schema: None,
                migrations: None,
                config_schema: None,
            },
        )
        .await
        .unwrap();

        let stored = fetch_stored_options(&pool, None).await.unwrap();
        // Conflicting DB row kept at 16 (revision=1)
        assert_eq!(stored[&("security.password".to_string(), "passwd_min_len".to_string())].value, json!(16));
        assert_eq!(stored[&("security.password".to_string(), "passwd_min_len".to_string())].revision, 1);
        // Non-conflicting options imported at revision=1 with normalization
        assert_eq!(
            stored[&("security.password".to_string(), "passwd_rules".to_string())].value,
            json!(["(?:A|B)", "(?:0|1)"])
        );
        assert_eq!(
            stored[&("security.password".to_string(), "passwd_min_passed_count".to_string())].value,
            json!(2)
        );
        assert_eq!(
            stored[&("document.upload.creation_risk_control".to_string(), "refill_period_seconds".to_string())].value,
            json!(120)
        );
        assert_eq!(
            stored[&("document.upload.creation_risk_control".to_string(), "account_refill_tokens".to_string())].value,
            json!(6)
        );
        assert_eq!(
            stored[&("document.upload.creation_risk_control".to_string(), "account_capacity".to_string())].value,
            json!(10) // ceil(6/3)=2 floored to default_min=10, and satisfies order invariant 6 <= 10
        );
        assert_eq!(
            stored[&("ext.oidc_sso".to_string(), "issuer".to_string())].value,
            json!("https://idp.example.com")
        );

        let DbPool::Sqlite(ref sq) = pool else { unreachable!() };
        let audit_rows = sqlx::query("SELECT data FROM audit_entries WHERE action = 'update_options'")
            .fetch_all(sq)
            .await
            .unwrap();
        assert!(audit_rows.iter().any(|r| {
            let data: Value = serde_json::from_str(r.get::<String, _>(0).as_str()).unwrap();
            data["source"] == json!("cfms_ctl_migration")
        }));

        // Verify cleaned config.toml preserves comments, pepper, custom section, enabled extension, and server section added by sync-template
        let after_mig = std::fs::read_to_string(&paths.config_path).unwrap();
        assert!(after_mig.contains("# Operator header comment"));
        assert!(after_mig.contains("# Keep pepper comment"));
        assert!(after_mig.contains("keep_me = true"));
        assert!(after_mig.contains("name = \"legacy.db\""));
        assert!(!after_mig.contains("db_name"));
        assert!(!after_mig.contains("passwd_must_contain"));
        assert!(!after_mig.contains("passwd_rules"));
        assert!(!after_mig.contains("allow_name_duplicate"));
        assert!(!after_mig.contains("creation_rate_"));
        assert!(!after_mig.contains("[sso"));

        // 5. sync-template now succeeds (merges missing [server]) and becomes idempotent
        handle_sync_template(
            &ctx,
            ConfigSyncTemplateArgs {
                check: false,
                remove: Vec::new(),
                prune: false,
                template: None,
                schema: None,
                migrations: None,
            },
        )
        .unwrap();

        handle_sync_template(
            &check_ctx,
            ConfigSyncTemplateArgs {
                check: true,
                remove: Vec::new(),
                prune: false,
                template: None,
                schema: None,
                migrations: None,
            },
        )
        .unwrap();

        handle_migrate_options(
            &check_ctx,
            ConfigMigrateOptionsArgs {
                check: true,
                discard_legacy: false,
                schema: None,
                migrations: None,
                config_schema: None,
            },
        )
        .await
        .unwrap();
    }
}
