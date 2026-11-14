//! `cfms-ctl permission`: Expired permission record purging and default group
//! permission synchronization (`user`, `sysop`).

use serde::Serialize;
use crate::cli::permission::{
    PermissionCommand, PermissionPurgeExpiredArgs, PermissionSyncDefaultsArgs,
};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Report for `cfms-ctl permission purge-expired`.
#[derive(Debug, Clone, Serialize)]
pub struct PermissionPurgeReport {
    pub dry_run: bool,
    pub cutoff_timestamp: f64,
    pub purged_count: u64,
}

impl CommandReport for PermissionPurgeReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("Expired Permission Purge");
        table
            .row("Dry Run", self.dry_run.to_string())
            .row("Cutoff Timestamp", format!("{:.3}", self.cutoff_timestamp))
            .row("Eligible / Purged Records", self.purged_count.to_string());
        table.print();
    }
}

/// Report for `cfms-ctl permission sync-defaults`.
#[derive(Debug, Clone, Serialize)]
pub struct PermissionSyncReport {
    pub dry_run: bool,
    pub groups: Vec<String>,
    pub inserted_count: u64,
}

impl CommandReport for PermissionSyncReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("Default Group Permission Sync");
        table
            .row("Dry Run", self.dry_run.to_string())
            .row("Target Groups", self.groups.join(", "))
            .row("Missing / Inserted Grants", self.inserted_count.to_string());
        table.print();
    }
}

pub async fn handle(_ctx: &AppContext, cmd: PermissionCommand) -> Result<()> {
    match cmd {
        PermissionCommand::PurgeExpired(_args) => {
            Err(CfmsError::NotImplementedYet("permission purge-expired"))
        }
        PermissionCommand::SyncDefaults(_args) => {
            Err(CfmsError::NotImplementedYet("permission sync-defaults"))
        }
    }
}

#[allow(dead_code)]
type _UnusedArgs = (PermissionPurgeExpiredArgs, PermissionSyncDefaultsArgs);
