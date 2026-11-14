//! `cfms-ctl user`: Password resets (Argon2id + HMAC-SHA256 pepper),
//! signing secret rotation, and TOTP credential clearing.

use serde::Serialize;
use crate::cli::user::{UserClearTotpArgs, UserCommand, UserResetPasswordArgs};
use crate::core::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Report for `cfms-ctl user reset-password`.
#[derive(Debug, Clone, Serialize)]
pub struct PasswordResetReport {
    pub username: String,
    pub generated_password: Option<String>,
    pub dek_access_preserved: bool,
}

impl CommandReport for PasswordResetReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("User Password Reset");
        table
            .row("Username", self.username.clone())
            .row(
                "Generated Password",
                self.generated_password
                    .clone()
                    .unwrap_or_else(|| "(explicitly supplied)".to_string()),
            )
            .row("DEK Access Preserved", self.dek_access_preserved.to_string());
        table.print();
    }
}

/// Report for `cfms-ctl user rotate-secrets`.
#[derive(Debug, Clone, Serialize)]
pub struct RotateSecretsReport {
    pub rotated_users: u64,
}

impl CommandReport for RotateSecretsReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("User Token Secret Rotation");
        table.row("Rotated User Accounts", self.rotated_users.to_string());
        table.print();
    }
}

/// Report for `cfms-ctl user clear-totp`.
#[derive(Debug, Clone, Serialize)]
pub struct ClearTotpReport {
    pub target_scope: String,
    pub cleared_credentials: u64,
    pub updated_policies: u64,
}

impl CommandReport for ClearTotpReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("User TOTP Reset");
        table
            .row("Target Scope", self.target_scope.clone())
            .row("Cleared TOTP Credentials", self.cleared_credentials.to_string())
            .row("Updated Auth Policies", self.updated_policies.to_string());
        table.print();
    }
}

pub async fn handle(_ctx: &AppContext, cmd: UserCommand) -> Result<()> {
    match cmd {
        UserCommand::ResetPassword(_args) => {
            Err(CfmsError::NotImplementedYet("user reset-password"))
        }
        UserCommand::RotateSecrets => Err(CfmsError::NotImplementedYet("user rotate-secrets")),
        UserCommand::ClearTotp(_args) => Err(CfmsError::NotImplementedYet("user clear-totp")),
    }
}

#[allow(dead_code)]
type _UnusedArgs = (UserResetPasswordArgs, UserClearTotpArgs);
