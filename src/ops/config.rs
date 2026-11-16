//! `cfms-ctl config`: Lossless `config.toml` template synchronization, `security.pepper`
//! generation, and database-backed `options` CRUD with optimistic concurrency.

use std::collections::BTreeMap;
use std::path::Path;
use comfy_table::{Cell, Color};
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use toml_edit::{Item, Table, Value as TomlValue, value};
use crate::cli::config::{ConfigCommand, ConfigSyncTemplateArgs, OptionsCommand};
use crate::core::{
    CfmsError, ConfigDocument, CoreConfigContract, RenamedPathRecord, Result,
};
use crate::db::{
    OptionUpdateInput, OptionsSchemaRegistry, ResolvedOptionRecord, get_option, list_options,
    reset_option, validate_option_key, write_options_batch,
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
    pub contract_source: Option<String>,
    pub check_only: bool,
    pub changed: bool,
    pub renamed_paths: Vec<RenamedPathRecord>,
    pub added_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub preserved_unknown_core_paths: Vec<String>,
    pub warnings: Vec<String>,
    pub backup_path: Option<String>,
}

impl CommandReport for ConfigSyncReport {
    fn render_human(&self, ui: &UiConsole) {
        if !self.renamed_paths.is_empty()
            || !self.added_paths.is_empty()
            || !self.removed_paths.is_empty()
            || !self.preserved_paths.is_empty()
        {
            ui.print_section("Configuration Template Sync");
            let mut table = styled_table(&["Change", "Configuration Path"]);
            for r in &self.renamed_paths {
                table.add_row(vec![
                    Cell::new("Rename").fg(Color::Yellow),
                    Cell::new(format!("{} -> {}", r.from, r.to)),
                ]);
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
        ConfigCommand::Options(sub) => handle_options(ctx, sub).await,
    }
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

    let contract = CoreConfigContract::from_workspace(&paths, args.contract.as_deref())?;
    let contract_source = contract.as_ref().map(|(_, s)| s.clone());

    let mut current_doc = ctx.load_config(&paths)?;
    let template_doc = ConfigDocument::load(&template_path)?;
    let plan = current_doc.sync_with_contract(
        &template_doc,
        &args.remove,
        args.prune,
        contract.as_ref().map(|(c, _)| c),
    )?;

    let mut report = ConfigSyncReport {
        config_path: plan.config_path.display().to_string(),
        template_path: plan.template_path.display().to_string(),
        contract_source,
        check_only: args.check,
        changed: plan.changed,
        renamed_paths: plan.renamed_paths,
        added_paths: plan.added_paths,
        removed_paths: plan.removed_paths,
        preserved_paths: plan.preserved_paths,
        preserved_unknown_core_paths: plan.preserved_unknown_core_paths,
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
            let registry =
                OptionsSchemaRegistry::from_workspace(&paths, args.contract.as_deref())?;
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
            let registry =
                OptionsSchemaRegistry::from_workspace(&paths, args.contract.as_deref())?;
            let pool = ctx.connect_db(&paths).await?;
            let option = get_option(&pool, &registry, &args.namespace, &args.option_key).await?;
            ctx.ui.render(&OptionItemReport { option });
            Ok(())
        }
        OptionsCommand::Set(args) => {
            let registry =
                OptionsSchemaRegistry::from_workspace(&paths, args.contract.as_deref())?;
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
            let registry =
                OptionsSchemaRegistry::from_workspace(&paths, args.contract.as_deref())?;
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
            let registry =
                OptionsSchemaRegistry::from_workspace(&paths, args.contract.as_deref())?;
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
    async fn test_sync_template_with_release_manifest_contract_and_options_core_boundary() {
        use crate::cli::GlobalOpts;
        use crate::cli::config::{OptionsGetArgs, OptionsListArgs, OptionsSetArgs};
        use crate::core::{CORE_CONFIG_CONTRACT_VERSION, DRAFT_2020_12_DIALECT, WorkspacePaths};
        use crate::db::schema::create_head_schema;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();

        let template_toml = r#"[database]
type = "sqlite"
name = "cfms.db"

[security]
pepper = ""

[server]
port = 5104
secret_key = ""

[extensions]
enabled = []
"#;
        std::fs::write(src_dir.join("config.toml.sample"), template_toml).unwrap();

        let contract = CoreConfigContract {
            contract_version: CORE_CONFIG_CONTRACT_VERSION.to_string(),
            core_version: "0.14.0".to_string(),
            schema_dialect: DRAFT_2020_12_DIALECT.to_string(),
            toml: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "required": ["database", "security", "server", "extensions"],
                "properties": {
                    "database": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["type"],
                        "properties": {
                            "type": { "type": "string", "enum": ["sqlite", "mysql", "postgresql"] },
                            "name": {
                                "type": "string",
                                "minLength": 1,
                                "x-renamed-from": ["database.db_name"]
                            }
                        }
                    },
                    "security": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["pepper"],
                        "properties": {
                            "pepper": { "type": "string" }
                        }
                    },
                    "server": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["secret_key"],
                        "properties": {
                            "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                            "secret_key": { "type": "string" }
                        }
                    },
                    "extensions": {
                        "type": "object",
                        "additionalProperties": { "type": "object" },
                        "required": ["enabled"],
                        "x-unmanaged-subtables": true,
                        "properties": {
                            "enabled": { "type": "array", "items": { "type": "string" } }
                        }
                    }
                }
            }),
            options: json!({
                "$schema": DRAFT_2020_12_DIALECT,
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "security.password": {
                        "type": "object",
                        "x-owner": "core",
                        "additionalProperties": false,
                        "properties": {
                            "passwd_min_length": {
                                "type": "integer",
                                "minimum": 1,
                                "default": 8,
                                "x-schema-version": 1
                            }
                        }
                    }
                }
            }),
        };

        let manifest_json = json!({
            "format_version": 1,
            "product": "cfms-on-websocket",
            "version": "0.14.0",
            "requires_python": ">=3.14",
            "managed_extensions": ["builtin", "oidc_sso"],
            "files": {},
            "core_config_contract": contract
        });
        std::fs::write(
            root.join("release-manifest.json"),
            serde_json::to_vec_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let initial_toml = r#"# Operator header comment
[database]
type = "sqlite"
db_name = "legacy.db"

[security]
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[extensions]
enabled = ["oidc_sso"]

[extensions.oidc_sso]
issuer = "https://idp.example.com"
client_id = "cfms-web"
"#;
        std::fs::write(src_dir.join("config.toml"), initial_toml).unwrap();

        let paths = WorkspacePaths::discover(Some(root), None).unwrap();
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
        let apply_ctx = AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output: OutputFormat::Json,
                yes: true,
                verbose: false,
            },
            UiConsole::new(OutputFormat::Json),
        );

        // 1. `--check` detects missing template sections + x-renamed-from rename without writing
        let check_err = handle_sync_template(
            &check_ctx,
            ConfigSyncTemplateArgs {
                template: None,
                contract: None,
                check: true,
                remove: Vec::new(),
                prune: false,
            },
        )
        .unwrap_err();
        assert!(check_err.to_string().contains("out of sync"));
        assert_eq!(std::fs::read_to_string(&paths.config_path).unwrap(), initial_toml);

        // 2. Apply renames `database.db_name -> database.name`, merges [server], preserves `[extensions.oidc_sso]`
        handle_sync_template(
            &apply_ctx,
            ConfigSyncTemplateArgs {
                template: None,
                contract: None,
                check: false,
                remove: Vec::new(),
                prune: false,
            },
        )
        .unwrap();
        let synced = std::fs::read_to_string(&paths.config_path).unwrap();
        assert!(synced.contains("# Operator header comment"));
        assert!(synced.contains("name = \"legacy.db\""));
        assert!(!synced.contains("db_name"));
        assert!(synced.contains("[server]"));
        assert!(synced.contains("[extensions.oidc_sso]"));
        assert!(synced.contains("issuer = \"https://idp.example.com\""));

        // 3. Re-running `--check` is idempotent
        handle_sync_template(
            &check_ctx,
            ConfigSyncTemplateArgs {
                template: None,
                contract: None,
                check: true,
                remove: Vec::new(),
                prune: false,
            },
        )
        .unwrap();

        // 4. `config options` reads both core defaults & stored extension rows, allows core writes, rejects extension writes
        let pool = apply_ctx.connect_db(&paths).await.unwrap();
        create_head_schema(&pool, false).await.unwrap();
        let crate::db::DbPool::Sqlite(ref sq) = pool else { unreachable!() };
        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('identity.oidc', 'oidc_sso', 'issuer', 1, 1, 'str', 'https://idp.example.com', 10.0)",
        )
        .execute(sq)
        .await
        .unwrap();

        handle_options(
            &apply_ctx,
            OptionsCommand::List(OptionsListArgs {
                namespace: None,
                contract: None,
            }),
        )
        .await
        .unwrap();

        handle_options(
            &apply_ctx,
            OptionsCommand::Get(OptionsGetArgs {
                namespace: "identity.oidc".to_string(),
                option_key: "issuer".to_string(),
                contract: None,
            }),
        )
        .await
        .unwrap();

        let payload_core = root.join("core_opt.json");
        std::fs::write(&payload_core, "12").unwrap();
        handle_options(
            &apply_ctx,
            OptionsCommand::Set(OptionsSetArgs {
                namespace: "security.password".to_string(),
                option_key: "passwd_min_length".to_string(),
                payload_file: payload_core,
                expected_revision: 0,
                contract: None,
            }),
        )
        .await
        .unwrap();

        let payload_ext = root.join("ext_opt.json");
        std::fs::write(&payload_ext, "\"https://other.example.com\"").unwrap();
        let ext_set_err = handle_options(
            &apply_ctx,
            OptionsCommand::Set(OptionsSetArgs {
                namespace: "identity.oidc".to_string(),
                option_key: "issuer".to_string(),
                payload_file: payload_ext,
                expected_revision: 1,
                contract: None,
            }),
        )
        .await
        .unwrap_err();
        assert!(ext_set_err.to_string().contains("core_config_contract"));
    }
}
