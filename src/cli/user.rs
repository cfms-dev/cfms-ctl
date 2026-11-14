//! CLI arguments for `cfms-ctl user`.

use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum UserCommand {
    /// Reset a user's password (generates a secure random password if `--password` is omitted).
    ResetPassword(UserResetPasswordArgs),

    /// Rotate all user signing keys (`secret_key`) and invalidate all active tokens.
    RotateSecrets,

    /// Clear TOTP credential and MFA policy references for one user or all users.
    ClearTotp(UserClearTotpArgs),
}

#[derive(Debug, Clone, Args)]
pub struct UserResetPasswordArgs {
    /// Username of the account whose password should be reset.
    #[arg(value_name = "USERNAME")]
    pub username: String,

    /// Explicit new password (a random 16-char password is generated when omitted).
    #[arg(long = "password", value_name = "NEW_PASSWORD")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct UserClearTotpArgs {
    /// Username whose TOTP state should be cleared.
    #[arg(
        value_name = "USERNAME",
        conflicts_with = "all_users",
        required_unless_present = "all_users"
    )]
    pub username: Option<String>,

    /// Clear TOTP state for every user in the database.
    #[arg(long = "all", conflicts_with = "username", required_unless_present = "username")]
    pub all_users: bool,
}
