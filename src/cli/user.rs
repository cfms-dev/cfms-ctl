//! CLI arguments for `cfms-ctl user`.

use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum UserCommand {
    /// Reset a user's password (generates a compliant CSPRNG password when input flags are omitted).
    ResetPassword(UserResetPasswordArgs),

    /// Rotate token signing keys (`secret_key`) and invalidate active tokens.
    RotateSecrets(UserRotateSecretsArgs),

    /// Clear TOTP credential and prune MFA/escalation policy references for one user or all users.
    ClearTotp(UserClearTotpArgs),
}

#[derive(Debug, Clone, Args)]
pub struct UserResetPasswordArgs {
    /// Username of the account whose password should be reset.
    #[arg(value_name = "USERNAME")]
    pub username: String,

    /// Explicit new password (discouraged: leaks in shell history/ps; prefer `--password-stdin` or `--prompt-password`).
    #[arg(long = "password", value_name = "NEW_PASSWORD", group = "password_source")]
    pub password: Option<String>,

    /// Read the new password from standard input (trimmed of trailing newline).
    #[arg(long = "password-stdin", group = "password_source")]
    pub password_stdin: bool,

    /// Prompt interactively for a masked password with confirmation.
    #[arg(long = "prompt-password", group = "password_source")]
    pub prompt_password: bool,

    /// Keep password valid immediately without forcing a password change at next login (`passwd_last_modified = now`).
    #[arg(long = "no-force-change")]
    pub no_force_change: bool,

    /// Do not add a `password` login chain into `user_auth_policies` when absent.
    #[arg(long = "no-ensure-login-policy")]
    pub no_ensure_login_policy: bool,

    /// Validate target user, password policy, and auth policies without acquiring locks or mutating the database.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Args)]
pub struct UserRotateSecretsArgs {
    /// Optional target username (rotates every user in the database when omitted).
    #[arg(value_name = "USERNAME")]
    pub username: Option<String>,

    /// Preview impacted account count without acquiring locks or rotating keys.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
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

    /// Clear TOTP state for every user in the database with TOTP credentials or policy entries.
    #[arg(long = "all", conflicts_with = "username", required_unless_present = "username")]
    pub all_users: bool,

    /// Also rotate `secret_key` for affected users to invalidate existing active tokens.
    #[arg(long = "revoke-sessions")]
    pub revoke_sessions: bool,

    /// Preview affected credentials and policy updates without acquiring locks or mutating the database.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use crate::cli::{Cli, Commands};
    use super::*;

    #[test]
    fn user_cli_parses_all_variants_and_rejects_conflicts() {
        let cli = Cli::try_parse_from([
            "cfms-ctl",
            "user",
            "reset-password",
            "alice",
            "--password-stdin",
            "--no-force-change",
            "--dry-run",
        ])
        .expect("parse reset-password");
        match cli.command {
            Commands::User(UserCommand::ResetPassword(args)) => {
                assert_eq!(args.username, "alice");
                assert!(args.password_stdin);
                assert!(args.no_force_change);
                assert!(args.dry_run);
                assert!(args.password.is_none());
                assert!(!args.prompt_password);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // Reject conflicting password sources
        assert!(
            Cli::try_parse_from([
                "cfms-ctl",
                "user",
                "reset-password",
                "alice",
                "--password",
                "Secret123!",
                "--password-stdin",
            ])
            .is_err()
        );

        let rotate_all = Cli::try_parse_from(["cfms-ctl", "user", "rotate-secrets"])
            .expect("parse rotate-secrets all");
        match rotate_all.command {
            Commands::User(UserCommand::RotateSecrets(args)) => {
                assert!(args.username.is_none());
                assert!(!args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let rotate_one =
            Cli::try_parse_from(["cfms-ctl", "user", "rotate-secrets", "bob", "--dry-run"])
                .expect("parse rotate-secrets user");
        match rotate_one.command {
            Commands::User(UserCommand::RotateSecrets(args)) => {
                assert_eq!(args.username.as_deref(), Some("bob"));
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let clear = Cli::try_parse_from([
            "cfms-ctl",
            "user",
            "clear-totp",
            "alice",
            "--revoke-sessions",
            "--dry-run",
        ])
        .expect("parse clear-totp");
        match clear.command {
            Commands::User(UserCommand::ClearTotp(args)) => {
                assert_eq!(args.username.as_deref(), Some("alice"));
                assert!(!args.all_users);
                assert!(args.revoke_sessions);
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
