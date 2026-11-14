//! `cfms-ctl backup`: Encrypted CFMS Format v2 (`CFMSBAK\x00`) backup inspection,
//! verification, export, and import.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::cli::backup::{
    BackupCommand, BackupExportArgs, BackupImportArgs, BackupInfoArgs, BackupVerifyArgs,
};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Magic header prefix for CFMS Encrypted Backup Format v2 (`CFMSBAK\0`).
pub const BACKUP_V2_MAGIC: &[u8; 8] = b"CFMSBAK\0";
const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// Unencrypted outer header stored at the start of a `.confbak` Format v2 file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeaderReport {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub format_version: u32,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub server_version: String,
    #[serde(default)]
    pub schema_revision: String,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub cipher: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl CommandReport for BackupHeaderReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("CFMS Backup Archive Info (Format v2)");
        table
            .row("Archive Path", self.path.clone())
            .row("File Size (bytes)", self.file_size.to_string())
            .row("Format Version", self.format_version.to_string())
            .row("Created At", self.created_at.clone())
            .row("Server Version", self.server_version.clone())
            .row("Schema Revision", self.schema_revision.clone())
            .row("Cipher", self.cipher.clone())
            .row(
                "Included Components",
                if self.components.is_empty() {
                    "(none)".to_string()
                } else {
                    self.components.join(", ")
                },
            );
        table.print();
    }
}

pub async fn handle(ctx: &AppContext, cmd: BackupCommand) -> Result<()> {
    match cmd {
        BackupCommand::Info(args) => handle_info(ctx, args),
        BackupCommand::Export(_args) => Err(CfmsError::NotImplementedYet("backup export")),
        BackupCommand::Import(_args) => Err(CfmsError::NotImplementedYet("backup import")),
        BackupCommand::Verify(_args) => Err(CfmsError::NotImplementedYet("backup verify")),
    }
}

fn handle_info(ctx: &AppContext, args: BackupInfoArgs) -> Result<()> {
    let report = read_backup_v2_header(&args.backup_path)?;
    ctx.ui.render(&report);
    Ok(())
}

/// Parse the unencrypted outer header of a CFMS Format v2 `.confbak` archive.
pub fn read_backup_v2_header(path: &Path) -> Result<BackupHeaderReport> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        CfmsError::Backup(format!("Unable to open backup '{}': {e}", path.display()))
    })?;
    let mut file = std::fs::File::open(path)?;

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).map_err(|_| {
        CfmsError::Backup(format!(
            "File '{}' is too short to be a CFMS v2 backup",
            path.display()
        ))
    })?;
    if &magic != BACKUP_V2_MAGIC {
        return Err(CfmsError::Backup(format!(
            "File '{}' does not have the CFMS Format v2 magic header (pre-0.14 v1 backups are not supported)",
            path.display()
        )));
    }

    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let header_len = u32::from_be_bytes(len_bytes) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(CfmsError::Backup(format!(
            "Invalid backup header length ({header_len} bytes) in '{}'",
            path.display()
        )));
    }

    let mut header_buf = vec![0u8; header_len];
    file.read_exact(&mut header_buf)?;
    let mut report: BackupHeaderReport = serde_json::from_slice(&header_buf).map_err(|e| {
        CfmsError::Backup(format!(
            "Malformed JSON header in backup '{}': {e}",
            path.display()
        ))
    })?;
    report.path = path.display().to_string();
    report.file_size = metadata.len();
    Ok(report)
}

#[allow(dead_code)]
type _UnusedArgs = (BackupExportArgs, BackupImportArgs, BackupVerifyArgs);
