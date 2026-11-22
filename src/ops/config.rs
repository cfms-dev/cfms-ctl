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
use crate::core::{CfmsError, ConfigDocument, ConfigMergeConflict, Result};
use crate::db::{
    OptionUpdateInput, ResolvedOptionRecord, get_option, list_options, validate_option_key,
    write_options_batch,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_template_path: Option<String>,
    pub check_only: bool,
    pub changed: bool,
    pub added_paths: Vec<String>,
    pub updated_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub conflicts: Vec<ConfigMergeConflict>,
    pub warnings: Vec<String>,
    pub backup_path: Option<String>,
}

impl CommandReport for ConfigSyncReport {
    fn render_human(&self, ui: &UiConsole) {
        if !self.added_paths.is_empty()
            || !self.updated_paths.is_empty()
            || !self.removed_paths.is_empty()
            || !self.preserved_paths.is_empty()
            || !self.conflicts.is_empty()
        {
            ui.print_section("Configuration Template Sync");
            let mut table = styled_table(&["Change", "Configuration Path"]);
            for path in &self.added_paths {
                table.add_row(vec![Cell::new("Add").fg(Color::Green), Cell::new(path)]);
            }
            for path in &self.updated_paths {
                table.add_row(vec![Cell::new("Update").fg(Color::Yellow), Cell::new(path)]);
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
            for conflict in &self.conflicts {
                table.add_row(vec![
                    Cell::new("Conflict").fg(Color::Magenta),
                    Cell::new(format!("{} ({})", conflict.path, conflict.kind)),
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

    let mut current_doc = ctx.load_config(&paths)?;
    let template_doc = ConfigDocument::load(&template_path)?;
    let plan = if let Some(explicit_base) = &args.base {
        let base_path = paths.resolve_file_override(explicit_base);
        if !base_path.is_file() {
            return Err(CfmsError::Config(format!(
                "Base configuration template not found: '{}'",
                base_path.display()
            )));
        }
        let base_doc = ConfigDocument::load(&base_path)?;
        current_doc.merge_three_way(&base_doc, &template_doc, &args.remove, args.prune)?
    } else {
        current_doc.sync_with_template(&template_doc, &args.remove, args.prune)?
    };

    let mut report = ConfigSyncReport {
        config_path: plan.config_path.display().to_string(),
        template_path: plan.template_path.display().to_string(),
        base_template_path: plan.base_template_path.map(|p| p.display().to_string()),
        check_only: args.check,
        changed: plan.changed,
        added_paths: plan.added_paths,
        updated_paths: plan.updated_paths,
        removed_paths: plan.removed_paths,
        preserved_paths: plan.preserved_paths,
        conflicts: plan.conflicts,
        warnings: plan.warnings,
        backup_path: None,
    };

    if args.check {
        if report.changed {
            if ctx.ui.format() == OutputFormat::Human {
                report.render_human(&ctx.ui);
            }
            return Err(CfmsError::Config(format!(
                "config.toml is out of sync with template ({} to add, {} to update, {} to remove)",
                report.added_paths.len(),
                report.updated_paths.len(),
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
            let pool = ctx.connect_db(&paths).await?;
            let options = list_options(&pool, args.namespace.as_deref()).await?;
            let report = OptionsListReport {
                namespace_filter: args.namespace,
                options,
            };
            ctx.ui.render(&report);
            Ok(())
        }
        OptionsCommand::Get(args) => {
            let pool = ctx.connect_db(&paths).await?;
            let option = get_option(&pool, &args.namespace, &args.option_key).await?;
            ctx.ui.render(&OptionItemReport { option });
            Ok(())
        }
        OptionsCommand::Set(args) => {
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
            let mut updated = write_options_batch(&pool, &args.namespace, updates).await?;
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
            let updates = read_many_options_json(&args.payload_file)?;
            let pool = ctx.connect_db(&paths).await?;
            let updated = write_options_batch(&pool, &args.namespace, updates).await?;
            let report = OptionsBatchReport {
                namespace: args.namespace,
                updated,
            };
            ctx.ui.render(&report);
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
    async fn test_sync_template_three_way_and_schemaless_options() {
        use crate::cli::GlobalOpts;
        use crate::cli::config::{OptionsGetArgs, OptionsListArgs, OptionsSetArgs};
        use crate::core::WorkspacePaths;
        use crate::db::schema::create_head_schema;

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let src_dir = root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();

        let base_toml = r#"[database]
type = "sqlite"
file = "cfms.db"

[security]
pepper = ""

[server]
port = 5104
secret_key = ""
deprecated_flag = false

[extensions]
enabled = []
"#;
        let new_template_toml = r#"[database]
type = "sqlite"
file = "cfms.db"

[security]
pepper = ""

[server]
port = 5105
secret_key = ""
# New timeout
timeout = 30

[extensions]
enabled = []
"#;
        let base_path = root.join("old.config.toml.sample");
        std::fs::write(&base_path, base_toml).unwrap();
        std::fs::write(src_dir.join("config.toml.sample"), new_template_toml).unwrap();

        let initial_toml = r#"# Operator header comment
[database]
type = "sqlite"
file = "prod.db"

[security]
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[server]
port = 5104
secret_key = "operator-secret"
deprecated_flag = false

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

        // 1. `--check --base` detects pending 3-way merge changes without modifying disk
        let check_err = handle_sync_template(
            &check_ctx,
            ConfigSyncTemplateArgs {
                template: None,
                base: Some(base_path.clone()),
                check: true,
                remove: Vec::new(),
                prune: false,
            },
        )
        .unwrap_err();
        assert!(check_err.to_string().contains("out of sync"));
        assert_eq!(std::fs::read_to_string(&paths.config_path).unwrap(), initial_toml);

        // 2. Apply 3-way merge: updates unmodified port 5104 -> 5105, adds timeout = 30,
        // removes unmodified deprecated_flag, preserves custom db file, secrets & `[extensions.oidc_sso]`.
        handle_sync_template(
            &apply_ctx,
            ConfigSyncTemplateArgs {
                template: None,
                base: Some(base_path.clone()),
                check: false,
                remove: Vec::new(),
                prune: false,
            },
        )
        .unwrap();
        let synced = std::fs::read_to_string(&paths.config_path).unwrap();
        assert!(synced.contains("# Operator header comment"));
        assert!(synced.contains("file = \"prod.db\""));
        assert!(synced.contains("port = 5105"));
        assert!(synced.contains("timeout = 30"));
        assert!(!synced.contains("deprecated_flag"));
        assert!(synced.contains("[extensions.oidc_sso]"));
        assert!(synced.contains("issuer = \"https://idp.example.com\""));

        // 3. Re-running `--check` (2-way) is idempotent
        handle_sync_template(
            &check_ctx,
            ConfigSyncTemplateArgs {
                template: None,
                base: None,
                check: true,
                remove: Vec::new(),
                prune: false,
            },
        )
        .unwrap();

        // 4. Schema-less `config options` reads and writes options directly
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
            OptionsCommand::List(OptionsListArgs { namespace: None }),
        )
        .await
        .unwrap();

        handle_options(
            &apply_ctx,
            OptionsCommand::Get(OptionsGetArgs {
                namespace: "identity.oidc".to_string(),
                option_key: "issuer".to_string(),
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
            }),
        )
        .await
        .unwrap();

        let stored = get_option(&pool, "security.password", "passwd_min_length")
            .await
            .unwrap();
        assert_eq!(stored.value, json!(12));
        assert_eq!(stored.revision, 1);
    }
}
