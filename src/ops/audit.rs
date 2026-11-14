//! `cfms-ctl audit`: Audit log inspection, JSONL export, and archive-before-delete purging.

use std::collections::BTreeMap;
use serde::Serialize;
use crate::cli::audit::{AuditCommand, AuditExportArgs, AuditFilterArgs, AuditPurgeArgs};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Report for `cfms-ctl audit inspect`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditInspectReport {
    pub matched_entries: u64,
    pub by_action: BTreeMap<String, u64>,
    pub by_result: BTreeMap<i32, u64>,
}

impl CommandReport for AuditInspectReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("Audit Log Inspection");
        table
            .row("Matched Entries", self.matched_entries.to_string())
            .row("Distinct Actions", self.by_action.len().to_string())
            .row("Distinct Result Codes", self.by_result.len().to_string());
        table.print();
    }
}

/// Report for `cfms-ctl audit export` and `cfms-ctl audit purge`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditArchiveReport {
    pub dry_run: bool,
    pub archive_path: Option<String>,
    pub exported_entries: u64,
    pub purged_entries: u64,
}

impl CommandReport for AuditArchiveReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("Audit Log Archive / Purge");
        table
            .row("Dry Run", self.dry_run.to_string())
            .row(
                "Archive Path",
                self.archive_path
                    .clone()
                    .unwrap_or_else(|| "(none)".to_string()),
            )
            .row("Exported Entries", self.exported_entries.to_string())
            .row("Purged Entries", self.purged_entries.to_string());
        table.print();
    }
}

pub async fn handle(_ctx: &AppContext, cmd: AuditCommand) -> Result<()> {
    match cmd {
        AuditCommand::Inspect(_args) => Err(CfmsError::NotImplementedYet("audit inspect")),
        AuditCommand::Export(_args) => Err(CfmsError::NotImplementedYet("audit export")),
        AuditCommand::Purge(_args) => Err(CfmsError::NotImplementedYet("audit purge")),
    }
}

#[allow(dead_code)]
type _UnusedArgs = (AuditFilterArgs, AuditExportArgs, AuditPurgeArgs);
