//! `cfms-ctl config`: Lossless `config.toml` template synchronization, `security.pepper`
//! generation, and database-backed `options` CRUD with optimistic concurrency.

use rand::RngCore;
use serde::Serialize;
use toml_edit::{Item, Table, value};
use crate::cli::config::{
    ConfigCommand, ConfigSyncTemplateArgs, OptionsCommand, OptionsGetArgs, OptionsListArgs,
    OptionsResetArgs, OptionsSetArgs, OptionsSetManyArgs,
};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

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

pub async fn handle(ctx: &AppContext, cmd: ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::FillPepper => handle_fill_pepper(ctx),
        ConfigCommand::SyncTemplate(_args) => {
            Err(CfmsError::NotImplementedYet("config sync-template"))
        }
        ConfigCommand::Options(sub) => handle_options(ctx, sub).await,
    }
}

fn handle_fill_pepper(ctx: &AppContext) -> Result<()> {
    let paths = ctx.resolve_paths()?;
    let mut doc = ctx.load_config(&paths)?;
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
    rand::thread_rng().fill_bytes(&mut random_bytes);
    let pepper_hex = hex::encode(random_bytes);

    let root = doc.document_mut();
    if !root.contains_key("security") {
        root.insert("security", Item::Table(Table::new()));
    }
    if let Some(sec_table) = root["security"].as_table_like_mut() {
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

async fn handle_options(_ctx: &AppContext, cmd: OptionsCommand) -> Result<()> {
    match cmd {
        OptionsCommand::List(_args) => Err(CfmsError::NotImplementedYet("config options list")),
        OptionsCommand::Get(_args) => Err(CfmsError::NotImplementedYet("config options get")),
        OptionsCommand::Set(_args) => Err(CfmsError::NotImplementedYet("config options set")),
        OptionsCommand::SetMany(_args) => {
            Err(CfmsError::NotImplementedYet("config options set-many"))
        }
        OptionsCommand::Reset(_args) => Err(CfmsError::NotImplementedYet("config options reset")),
    }
}

#[allow(dead_code)]
type _UnusedArgs = (
    ConfigSyncTemplateArgs,
    OptionsListArgs,
    OptionsGetArgs,
    OptionsSetArgs,
    OptionsSetManyArgs,
    OptionsResetArgs,
);
