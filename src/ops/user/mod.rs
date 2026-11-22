//! User account maintenance operations: `reset-password`, `rotate-secrets`, and `clear-totp`.

pub mod auth_policy;
pub mod db;
pub mod password;

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cli::user::{
    UserClearTotpArgs, UserCommand, UserResetPasswordArgs, UserRotateSecretsArgs,
};
use crate::core::config::ConfigDocument;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::DbPool;
use crate::ops::AppContext;
use crate::ops::user::auth_policy::{
    AuthPurpose, PolicyMutation, PolicyRow, RegisteredCredential, apply_mutations_preview,
    ensure_authentication_available, ensure_password_in_login_policy, prune_method_from_policies,
};
use crate::ops::user::db::{
    DbExec, DbTx, OidcRow, PasswordRow, PublicKeyRow, SchemaPreflight, TotpRow, UserRow,
    apply_policy_mutations, count_target_users, delete_totp_credentials_by_users,
    fetch_all_user_ids, fetch_oidc_by_users, fetch_passwords_by_users, fetch_policies_by_users,
    fetch_public_keys_by_users, fetch_totp_candidate_user_ids, fetch_totps_by_users,
    fetch_user_by_username, fetch_users_by_ids, group_policies_by_user, insert_audit_entry,
    now_unix_seconds, preflight_user_schema, update_user_secrets_chunked,
    upsert_user_password,
};
use crate::ops::user::password::{
    PasswordPolicyConfig, generate_random_hex, hash_password_argon2id,
    read_explicit_password_input,
};
use crate::ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort};

const MAX_USERNAME_LEN: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct PasswordResetReport {
    pub username: String,
    pub user_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_password: Option<String>,
    pub credential_created: bool,
    pub login_policy_updated: bool,
    pub force_change_on_login: bool,
    pub sessions_revoked: bool,
    pub audit_logged: bool,
    pub dry_run: bool,
}

impl CommandReport for PasswordResetReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut kv = KeyValueTable::new(if self.dry_run {
            "User Password Reset (Dry Run)"
        } else {
            "User Password Reset"
        });
        kv.row("Username", &self.username);
        kv.row("User Status", &self.user_status);
        kv.row("Mode", if self.dry_run { "dry-run" } else { "applied" });
        kv.row(
            "Password Credential",
            if self.credential_created {
                "created"
            } else {
                "updated"
            },
        );
        kv.row(
            "Login Auth Policy",
            if self.login_policy_updated {
                "updated"
            } else {
                "unchanged"
            },
        );
        kv.row(
            "Force Change on Login",
            if self.force_change_on_login {
                "yes"
            } else {
                "no"
            },
        );
        kv.row(
            "Sessions Revoked",
            if self.sessions_revoked { "yes" } else { "no" },
        );
        kv.row("Audit Logged", if self.audit_logged { "yes" } else { "no" });
        if let Some(pwd) = &self.generated_password {
            kv.row("Generated Password", pwd);
        }
        kv.print();

        if self.user_status != "ACTIVE" {
            ui.print_warning(&format!(
                "Account '{}' is currently {}. Password was reset, but login remains blocked until the account is enabled.",
                self.username, self.user_status
            ));
        }
        if self.generated_password.is_some() {
            ui.print_success(
                "Store the generated password securely; it is shown only once and is not written to audit logs.",
            );
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RotateSecretsReport {
    pub scope: String,
    pub rotated_users: u64,
    pub audit_logged: bool,
    pub dry_run: bool,
}

impl CommandReport for RotateSecretsReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut kv = KeyValueTable::new(if self.dry_run {
            "Rotate User Secrets (Dry Run)"
        } else {
            "Rotate User Secrets"
        });
        kv.row("Scope", &self.scope);
        kv.row("Mode", if self.dry_run { "dry-run" } else { "applied" });
        kv.row("Rotated Users", self.rotated_users.to_string());
        kv.row("Audit Logged", if self.audit_logged { "yes" } else { "no" });
        kv.print();

        if !self.dry_run && self.rotated_users > 0 {
            ui.print_success(
                "All previously issued session tokens for rotated accounts are now invalidated.",
            );
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClearTotpReport {
    pub scope: String,
    pub affected_users: u64,
    pub unchanged_users: u64,
    pub cleared_credentials: u64,
    pub updated_policies: u64,
    pub sessions_revoked: u64,
    pub revoke_sessions: bool,
    pub audit_logged: bool,
    pub dry_run: bool,
}

impl CommandReport for ClearTotpReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut kv = KeyValueTable::new(if self.dry_run {
            "Clear TOTP (Dry Run)"
        } else {
            "Clear TOTP"
        });
        kv.row("Scope", &self.scope);
        kv.row("Mode", if self.dry_run { "dry-run" } else { "applied" });
        kv.row("Affected Users", self.affected_users.to_string());
        kv.row("Unchanged Users", self.unchanged_users.to_string());
        kv.row("Cleared Credentials", self.cleared_credentials.to_string());
        kv.row("Updated Policies", self.updated_policies.to_string());
        kv.row(
            "Session Revocation",
            if self.revoke_sessions {
                "requested"
            } else {
                "preserved (default)"
            },
        );
        kv.row("Sessions Revoked", self.sessions_revoked.to_string());
        kv.row("Audit Logged", if self.audit_logged { "yes" } else { "no" });
        kv.print();
    }
}

/// Dispatch `cfms-ctl user <subcommand>`.
pub async fn handle(ctx: &AppContext, cmd: UserCommand) -> Result<()> {
    match cmd {
        UserCommand::ResetPassword(args) => reset_password(ctx, args).await,
        UserCommand::RotateSecrets(args) => rotate_secrets(ctx, args).await,
        UserCommand::ClearTotp(args) => clear_totp(ctx, args).await,
    }
}

async fn reset_password(ctx: &AppContext, args: UserResetPasswordArgs) -> Result<()> {
    validate_username(&args.username)?;
    let paths = ctx.resolve_paths()?;
    let config = ctx.load_config(&paths)?;
    let pool = ctx.connect_db(&paths).await?;
    let _preflight = preflight_user_schema(&pool).await?;

    let _lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let report = reset_password_with_context(&paths, &config, &pool, args, &ctx.ui).await?;
    ctx.ui.render(&report);
    Ok(())
}

async fn rotate_secrets(ctx: &AppContext, args: UserRotateSecretsArgs) -> Result<()> {
    if let Some(u) = &args.username {
        validate_username(u)?;
    }

    let paths = ctx.resolve_paths()?;
    let _config = ctx.load_config(&paths)?;
    let pool = ctx.connect_db(&paths).await?;
    let _preflight = preflight_user_schema(&pool).await?;

    let _lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    if !args.dry_run && args.username.is_none() {
        confirm_destructive(
            &ctx.ui,
            "Rotate secret keys for ALL users? This will invalidate every active session.",
            ctx.global.yes,
        )?;
    }

    let report = rotate_secrets_with_context(&pool, args).await?;
    ctx.ui.render(&report);
    Ok(())
}

async fn clear_totp(ctx: &AppContext, args: UserClearTotpArgs) -> Result<()> {
    validate_clear_totp_args(&args)?;

    let paths = ctx.resolve_paths()?;
    let config = ctx.load_config(&paths)?;
    let pool = ctx.connect_db(&paths).await?;
    let _preflight = preflight_user_schema(&pool).await?;

    let _lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    if !args.dry_run && args.all_users {
        let prompt = if args.revoke_sessions {
            "Clear TOTP credentials and policies for ALL affected users, and revoke their sessions?"
        } else {
            "Clear TOTP credentials and policies for ALL affected users (active sessions preserved)?"
        };
        confirm_destructive(&ctx.ui, prompt, ctx.global.yes)?;
    }

    let report = clear_totp_with_context(&config, &pool, args).await?;
    ctx.ui.render(&report);
    Ok(())
}

fn confirm_destructive(ui: &UiConsole, prompt: &str, yes: bool) -> Result<()> {
    if !yes && ui.format() == OutputFormat::Json {
        return Err(CfmsError::InvalidArgument(
            "Refusing interactive confirmation in JSON output mode; pass --yes to apply or --dry-run to preview"
                .to_string(),
        ));
    }
    confirm_or_abort(prompt, yes)
}

pub async fn reset_password_with_context(
    _paths: &WorkspacePaths,
    config: &ConfigDocument,
    pool: &DbPool,
    args: UserResetPasswordArgs,
    ui: &UiConsole,
) -> Result<PasswordResetReport> {
    validate_username(&args.username)?;
    let preflight = preflight_user_schema(pool).await?;
    let active_oidc_issuer = config.oidc_sso_issuer();
    let policy_cfg = PasswordPolicyConfig::load(pool).await?;
    policy_cfg.ensure_consistent()?;

    let explicit_password = read_explicit_password_input(&args, ui).await?;
    if let Some(pw) = &explicit_password {
        policy_cfg.validate(pw)?;
    }

    // Fast read-only pre-check before any heavy Argon2id hashing.
    let pre_user = fetch_user_by_username(&mut DbExec::Pool(pool), &args.username)
        .await?
        .ok_or_else(|| {
            CfmsError::InvalidArgument(format!("User '{}' does not exist", args.username))
        })?;

    if args.dry_run {
        let mut exec = DbExec::Pool(pool);
        let state = load_single_user_auth_state(
            &mut exec,
            &preflight,
            &pre_user,
            active_oidc_issuer.as_deref(),
            true,
        )
        .await?;
        let cred_id = state
            .password_cred_id
            .clone()
            .unwrap_or_else(|| "<new-password-credential>".to_string());
        let credential_created = state.password_cred_id.is_none();

        let (login_policy_updated, next_policies) = compute_reset_login_policy(
            &state.policies,
            &cred_id,
            args.no_ensure_login_policy,
        );
        let mut next_creds = state.credentials;
        if credential_created {
            next_creds.push(RegisteredCredential {
                method: "password".to_string(),
                credential_id: cred_id,
                active: true,
                key_identity: None,
            });
        }
        verify_reset_reachability(
            &pre_user.username,
            &next_policies,
            &next_creds,
            args.no_ensure_login_policy,
            ui,
        )?;

        return Ok(PasswordResetReport {
            username: pre_user.username,
            user_status: user_status_label(pre_user.status).to_string(),
            generated_password: None,
            credential_created,
            login_policy_updated,
            force_change_on_login: !args.no_force_change,
            sessions_revoked: false,
            audit_logged: false,
            dry_run: true,
        });
    }

    let (generated_plain, pw_to_hash) = match explicit_password {
        Some(pw) => (None, pw),
        None => {
            let generated = policy_cfg.generate_compliant()?;
            let copy = Zeroizing::new(generated.as_str().to_string());
            (Some(generated), copy)
        }
    };

    // Perform heavy Argon2id hashing before opening the SQLite write transaction.
    let pass_hash = hash_password_argon2id(pw_to_hash).await?;

    let mut tx = DbTx::begin(pool).await?;
    let locked_user = fetch_user_by_username(&mut DbExec::Tx(&mut tx), &args.username)
        .await?
        .ok_or_else(|| {
            CfmsError::InvalidArgument(format!("User '{}' does not exist", args.username))
        })?;

    let state = {
        let mut exec = DbExec::Tx(&mut tx);
        load_single_user_auth_state(
            &mut exec,
            &preflight,
            &locked_user,
            active_oidc_issuer.as_deref(),
            true,
        )
        .await?
    };

    let (cred_id, credential_created) = match &state.password_cred_id {
        Some(existing_id) => (existing_id.clone(), false),
        None => (generate_random_hex(16).as_str().to_string(), true),
    };

    let passwd_last_modified = if args.no_force_change {
        now_unix_seconds()
    } else {
        0.0
    };

    upsert_user_password(
        &mut tx,
        locked_user.id,
        &cred_id,
        &pass_hash,
        passwd_last_modified,
        credential_created,
    )
    .await?;

    let new_secret = generate_random_hex(32);
    update_user_secrets_chunked(&mut tx, &[(locked_user.id, new_secret.as_str().to_string())])
        .await?;

    let (login_mutation, next_policies) = if args.no_ensure_login_policy {
        (None, state.policies)
    } else {
        let m = ensure_password_in_login_policy(state.policies.get(&AuthPurpose::Login), &cred_id);
        let preview = match &m {
            Some(mut_item) => apply_mutations_preview(&state.policies, std::slice::from_ref(mut_item)),
            None => state.policies,
        };
        (m, preview)
    };

    let login_policy_updated = if let Some(m) = login_mutation {
        apply_policy_mutations(&mut tx, locked_user.id, &[m]).await? > 0
    } else {
        false
    };

    let mut next_creds = state.credentials;
    if credential_created {
        next_creds.push(RegisteredCredential {
            method: "password".to_string(),
            credential_id: cred_id,
            active: true,
            key_identity: None,
        });
    }

    verify_reset_reachability(
        &locked_user.username,
        &next_policies,
        &next_creds,
        args.no_ensure_login_policy,
        ui,
    )?;

    let user_status = user_status_label(locked_user.status).to_string();
    let audit_data = serde_json::json!({
        "credential_created": credential_created,
        "force_change_on_login": !args.no_force_change,
        "login_policy_updated": login_policy_updated,
        "sessions_revoked": true,
        "user_status": user_status,
    });
    insert_audit_entry(&mut tx, "reset_user_password", &locked_user.username, &audit_data).await?;

    tx.commit().await?;

    Ok(PasswordResetReport {
        username: locked_user.username,
        user_status,
        generated_password: generated_plain.map(|z| z.as_str().to_string()),
        credential_created,
        login_policy_updated,
        force_change_on_login: !args.no_force_change,
        sessions_revoked: true,
        audit_logged: true,
        dry_run: false,
    })
}

pub async fn rotate_secrets_with_context(
    pool: &DbPool,
    args: UserRotateSecretsArgs,
) -> Result<RotateSecretsReport> {
    if let Some(u) = &args.username {
        validate_username(u)?;
    }
    let _preflight = preflight_user_schema(pool).await?;

    let scope = match &args.username {
        Some(u) => format!("user:{u}"),
        None => "all".to_string(),
    };

    if args.dry_run {
        let count = match &args.username {
            Some(u) => {
                fetch_user_by_username(&mut DbExec::Pool(pool), u)
                    .await?
                    .ok_or_else(|| {
                        CfmsError::InvalidArgument(format!("User '{u}' does not exist"))
                    })?;
                1
            }
            None => count_target_users(pool, None).await?,
        };
        return Ok(RotateSecretsReport {
            scope,
            rotated_users: count,
            audit_logged: false,
            dry_run: true,
        });
    }

    let mut tx = DbTx::begin(pool).await?;
    let targets: Vec<(Uuid, String)> = match &args.username {
        Some(u) => {
            let user = fetch_user_by_username(&mut DbExec::Tx(&mut tx), u)
                .await?
                .ok_or_else(|| {
                    CfmsError::InvalidArgument(format!("User '{u}' does not exist"))
                })?;
            vec![(user.id, user.username)]
        }
        None => fetch_all_user_ids(&mut DbExec::Tx(&mut tx)).await?,
    };

    if targets.is_empty() {
        tx.commit().await?;
        return Ok(RotateSecretsReport {
            scope,
            rotated_users: 0,
            audit_logged: false,
            dry_run: false,
        });
    }

    let updates: Vec<(Uuid, String)> = targets
        .iter()
        .map(|(id, _)| {
            let secret = generate_random_hex(32);
            (*id, secret.as_str().to_string())
        })
        .collect();

    let rotated_users = update_user_secrets_chunked(&mut tx, &updates).await?;
    let audit_target = args.username.as_deref().unwrap_or("*");
    let audit_data = serde_json::json!({
        "scope": scope,
        "rotated_users": rotated_users,
    });
    insert_audit_entry(&mut tx, "rotate_user_secrets", audit_target, &audit_data).await?;

    tx.commit().await?;

    Ok(RotateSecretsReport {
        scope,
        rotated_users,
        audit_logged: true,
        dry_run: false,
    })
}

pub async fn clear_totp_with_context(
    config: &ConfigDocument,
    pool: &DbPool,
    args: UserClearTotpArgs,
) -> Result<ClearTotpReport> {
    validate_clear_totp_args(&args)?;
    let preflight = preflight_user_schema(pool).await?;
    let active_oidc_issuer = config.oidc_sso_issuer();

    let scope = match &args.username {
        Some(u) => format!("user:{u}"),
        None => "all".to_string(),
    };

    if args.dry_run {
        let mut exec = DbExec::Pool(pool);
        let plan = plan_clear_totp(
            &mut exec,
            &preflight,
            args.username.as_deref(),
            active_oidc_issuer.as_deref(),
        )
        .await?;
        return Ok(ClearTotpReport {
            scope,
            affected_users: plan.affected.len() as u64,
            unchanged_users: plan.unchanged_users,
            cleared_credentials: plan.cleared_credentials,
            updated_policies: plan.updated_policies,
            sessions_revoked: 0,
            revoke_sessions: args.revoke_sessions,
            audit_logged: false,
            dry_run: true,
        });
    }

    let mut tx = DbTx::begin(pool).await?;
    let plan = {
        let mut exec = DbExec::Tx(&mut tx);
        plan_clear_totp(
            &mut exec,
            &preflight,
            args.username.as_deref(),
            active_oidc_issuer.as_deref(),
        )
        .await?
    };

    let affected_users = plan.affected.len() as u64;
    if affected_users == 0 {
        tx.commit().await?;
        return Ok(ClearTotpReport {
            scope,
            affected_users: 0,
            unchanged_users: plan.unchanged_users,
            cleared_credentials: 0,
            updated_policies: 0,
            sessions_revoked: 0,
            revoke_sessions: args.revoke_sessions,
            audit_logged: false,
            dry_run: false,
        });
    }

    let cred_user_ids: Vec<Uuid> = plan
        .affected
        .iter()
        .filter(|u| u.has_totp_credential)
        .map(|u| u.user_id)
        .collect();
    let cleared_credentials = delete_totp_credentials_by_users(&mut tx, &cred_user_ids).await?;

    let mut updated_policies = 0u64;
    for item in &plan.affected {
        if !item.policy_mutations.is_empty() {
            updated_policies +=
                apply_policy_mutations(&mut tx, item.user_id, &item.policy_mutations).await?;
        }
    }

    let sessions_revoked = if args.revoke_sessions {
        let updates: Vec<(Uuid, String)> = plan
            .affected
            .iter()
            .map(|u| (u.user_id, generate_random_hex(32).as_str().to_string()))
            .collect();
        update_user_secrets_chunked(&mut tx, &updates).await?
    } else {
        0
    };

    let audit_target = args.username.as_deref().unwrap_or("*");
    let audit_data = serde_json::json!({
        "scope": scope,
        "affected_users": affected_users,
        "unchanged_users": plan.unchanged_users,
        "cleared_credentials": cleared_credentials,
        "updated_policies": updated_policies,
        "sessions_revoked": sessions_revoked,
        "revoke_sessions": args.revoke_sessions,
    });
    insert_audit_entry(&mut tx, "clear_user_totp", audit_target, &audit_data).await?;

    tx.commit().await?;

    Ok(ClearTotpReport {
        scope,
        affected_users,
        unchanged_users: plan.unchanged_users,
        cleared_credentials,
        updated_policies,
        sessions_revoked,
        revoke_sessions: args.revoke_sessions,
        audit_logged: true,
        dry_run: false,
    })
}

struct SingleUserAuthState {
    password_cred_id: Option<String>,
    policies: BTreeMap<AuthPurpose, PolicyRow>,
    credentials: Vec<RegisteredCredential>,
}

async fn load_single_user_auth_state(
    exec: &mut DbExec<'_>,
    preflight: &SchemaPreflight,
    user: &UserRow,
    active_oidc_issuer: Option<&str>,
    include_totp: bool,
) -> Result<SingleUserAuthState> {
    let ids = [user.id];
    let passwords = fetch_passwords_by_users(exec, &ids).await?;
    let totps = if include_totp {
        fetch_totps_by_users(exec, &ids).await?
    } else {
        Vec::new()
    };
    let public_keys = fetch_public_keys_by_users(exec, &ids).await?;
    let oidcs = load_oidc_by_users_if_present(exec, preflight, &ids).await?;
    let policy_rows = fetch_policies_by_users(exec, &ids).await?;

    let password_cred_id = passwords.first().map(|p| p.credential_id.clone());
    let policies = group_policies_by_user(policy_rows)
        .remove(&user.id)
        .unwrap_or_default();
    let credentials = build_registered_credentials(
        passwords.first(),
        totps.first(),
        &public_keys,
        &oidcs,
        active_oidc_issuer,
    );

    Ok(SingleUserAuthState {
        password_cred_id,
        policies,
        credentials,
    })
}

struct ClearTotpUserPlan {
    user_id: Uuid,
    has_totp_credential: bool,
    policy_mutations: Vec<PolicyMutation>,
}

struct ClearTotpPlan {
    affected: Vec<ClearTotpUserPlan>,
    unchanged_users: u64,
    cleared_credentials: u64,
    updated_policies: u64,
}

async fn plan_clear_totp(
    exec: &mut DbExec<'_>,
    preflight: &SchemaPreflight,
    target_username: Option<&str>,
    active_oidc_issuer: Option<&str>,
) -> Result<ClearTotpPlan> {
    let users: Vec<UserRow> = match target_username {
        Some(u) => {
            let row = fetch_user_by_username(exec, u).await?.ok_or_else(|| {
                CfmsError::InvalidArgument(format!("User '{u}' does not exist"))
            })?;
            vec![row]
        }
        None => {
            let candidate_ids = fetch_totp_candidate_user_ids(exec).await?;
            if candidate_ids.is_empty() {
                return Ok(ClearTotpPlan {
                    affected: Vec::new(),
                    unchanged_users: 0,
                    cleared_credentials: 0,
                    updated_policies: 0,
                });
            }
            fetch_users_by_ids(exec, &candidate_ids).await?
        }
    };

    let user_ids: Vec<Uuid> = users.iter().map(|u| u.id).collect();
    let passwords = fetch_passwords_by_users(exec, &user_ids).await?;
    let totps = fetch_totps_by_users(exec, &user_ids).await?;
    let public_keys = fetch_public_keys_by_users(exec, &user_ids).await?;
    let oidcs = load_oidc_by_users_if_present(exec, preflight, &user_ids).await?;
    let mut policies_map = group_policies_by_user(fetch_policies_by_users(exec, &user_ids).await?);

    let pw_by_user: HashMap<Uuid, PasswordRow> =
        passwords.into_iter().map(|p| (p.user_id, p)).collect();
    let totp_by_user: HashMap<Uuid, TotpRow> =
        totps.into_iter().map(|t| (t.user_id, t)).collect();
    let mut pk_by_user: HashMap<Uuid, Vec<PublicKeyRow>> = HashMap::new();
    for pk in public_keys {
        pk_by_user.entry(pk.user_id).or_default().push(pk);
    }
    let mut oidc_by_user: HashMap<Uuid, Vec<OidcRow>> = HashMap::new();
    for oidc in oidcs {
        oidc_by_user.entry(oidc.user_id).or_default().push(oidc);
    }

    let mut affected = Vec::new();
    let mut unchanged_users = 0u64;
    let mut cleared_credentials = 0u64;
    let mut updated_policies = 0u64;

    for user in users {
        let user_policies = policies_map.remove(&user.id).unwrap_or_default();
        let has_totp_credential = totp_by_user.contains_key(&user.id);
        let has_totp_policy_ref = user_policies.values().any(|policy| {
            policy
                .chains
                .iter()
                .any(|chain| chain.iter().any(|step| step.method == "totp"))
        });

        if !has_totp_credential && !has_totp_policy_ref {
            unchanged_users += 1;
            continue;
        }

        let remaining_creds = build_registered_credentials(
            pw_by_user.get(&user.id),
            None, // TOTP removed
            pk_by_user.get(&user.id).map(Vec::as_slice).unwrap_or(&[]),
            oidc_by_user.get(&user.id).map(Vec::as_slice).unwrap_or(&[]),
            active_oidc_issuer,
        );

        let mutations = prune_method_from_policies(&user_policies, "totp", None, &remaining_creds);
        let preview_policies = apply_mutations_preview(&user_policies, &mutations);

        if let Err(code) = ensure_authentication_available(&preview_policies, &remaining_creds) {
            return Err(CfmsError::InvalidArgument(format_auth_block_reason(
                &user.username,
                code,
                "clear TOTP",
            )));
        }

        if has_totp_credential {
            cleared_credentials += 1;
        }
        updated_policies += mutations.len() as u64;

        affected.push(ClearTotpUserPlan {
            user_id: user.id,
            has_totp_credential,
            policy_mutations: mutations,
        });
    }

    Ok(ClearTotpPlan {
        affected,
        unchanged_users,
        cleared_credentials,
        updated_policies,
    })
}

async fn load_oidc_by_users_if_present(
    exec: &mut DbExec<'_>,
    preflight: &SchemaPreflight,
    user_ids: &[Uuid],
) -> Result<Vec<OidcRow>> {
    if preflight.has_oidc_table {
        fetch_oidc_by_users(exec, user_ids).await
    } else {
        Ok(Vec::new())
    }
}

fn build_registered_credentials(
    password: Option<&PasswordRow>,
    totp: Option<&TotpRow>,
    public_keys: &[PublicKeyRow],
    oidc: &[OidcRow],
    active_oidc_issuer: Option<&str>,
) -> Vec<RegisteredCredential> {
    let mut creds = Vec::new();
    if let Some(pw) = password {
        creds.push(RegisteredCredential {
            method: "password".to_string(),
            credential_id: pw.credential_id.clone(),
            active: true,
            key_identity: None,
        });
    }
    if let Some(t) = totp {
        creds.push(RegisteredCredential {
            method: "totp".to_string(),
            credential_id: t.credential_id.clone(),
            active: t.enabled,
            key_identity: None,
        });
    }
    for pk in public_keys {
        creds.push(RegisteredCredential {
            method: "publickey".to_string(),
            credential_id: pk.id.clone(),
            active: true,
            key_identity: Some(pk.fingerprint_hex.clone()),
        });
    }
    for row in oidc {
        let active = active_oidc_issuer.is_some_and(|cfg_iss| cfg_iss == row.issuer);
        creds.push(RegisteredCredential {
            method: "oidc".to_string(),
            credential_id: row.id.clone(),
            active,
            key_identity: None,
        });
    }
    creds
}

fn compute_reset_login_policy(
    policies: &BTreeMap<AuthPurpose, PolicyRow>,
    password_cred_id: &str,
    no_ensure_login_policy: bool,
) -> (bool, BTreeMap<AuthPurpose, PolicyRow>) {
    if no_ensure_login_policy {
        return (false, policies.clone());
    }
    match ensure_password_in_login_policy(policies.get(&AuthPurpose::Login), password_cred_id) {
        Some(m) => (
            true,
            apply_mutations_preview(policies, std::slice::from_ref(&m)),
        ),
        None => (false, policies.clone()),
    }
}

fn verify_reset_reachability(
    username: &str,
    policies: &BTreeMap<AuthPurpose, PolicyRow>,
    credentials: &[RegisteredCredential],
    warn_only: bool,
    ui: &UiConsole,
) -> Result<()> {
    match ensure_authentication_available(policies, credentials) {
        Ok(()) => Ok(()),
        Err(code) if warn_only => {
            ui.print_warning(&format!(
                "{} (`--no-ensure-login-policy` skipped policy update).",
                format_auth_block_reason(username, code, "reach login after password reset")
            ));
            Ok(())
        }
        Err(code) => Err(CfmsError::InvalidArgument(format_auth_block_reason(
            username,
            code,
            "reset password",
        ))),
    }
}

fn format_auth_block_reason(username: &str, code: &str, operation: &str) -> String {
    match code {
        "login_unavailable" => format!(
            "Cannot {operation} for user '{username}': resulting authentication policies leave no reachable login factor compatible with configured MFA rules"
        ),
        "escalation_unavailable" => format!(
            "Cannot {operation} for user '{username}': resulting authentication policies leave privilege escalation with no completable factor"
        ),
        other => format!(
            "Cannot {operation} for user '{username}': authentication policy invariant failed ({other})"
        ),
    }
}

fn validate_username(username: &str) -> Result<()> {
    if username.trim().is_empty() {
        return Err(CfmsError::InvalidArgument(
            "Username must not be empty".to_string(),
        ));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(CfmsError::InvalidArgument(format!(
            "Username exceeds maximum length of {MAX_USERNAME_LEN} bytes"
        )));
    }
    if username.chars().any(char::is_control) {
        return Err(CfmsError::InvalidArgument(
            "Username must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn validate_clear_totp_args(args: &UserClearTotpArgs) -> Result<()> {
    match (&args.username, args.all_users) {
        (Some(u), false) => validate_username(u),
        (None, true) => Ok(()),
        _ => Err(CfmsError::InvalidArgument(
            "Specify either <USERNAME> or `--all` for `user clear-totp`".to_string(),
        )),
    }
}

const fn user_status_label(status: i32) -> &'static str {
    if status == 0 { "ACTIVE" } else { "DISABLED" }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use argon2::password_hash::phc::PasswordHash;
    use argon2::{Argon2, PasswordVerifier};
    use sqlx::Row;

    use super::*;
    use crate::cli::GlobalOpts;
    use crate::core::RuntimeLock;
    use crate::db::backend::DatabaseKind;
    use crate::db::schema::LATEST_SCHEMA_REVISION;
    use crate::db::schema::ddl::{
        USER_OIDC_CREDENTIALS_TABLE, create_head_schema, execute_ddl_statements,
        set_alembic_version,
    };

    struct TestEnv {
        _dir: tempfile::TempDir,
        paths: WorkspacePaths,
        config: ConfigDocument,
        pool: DbPool,
        root: std::path::PathBuf,
    }

    async fn setup_test_env(extra_toml: &str) -> TestEnv {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let cfg_dir = src.join("include").join("config");
        std::fs::create_dir_all(&cfg_dir).expect("cfg dir");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            cfg_dir.join("constants.py"),
            "CORE_VERSION = Version(\"0.14.0\")\n",
        )
        .expect("constants.py");

        let config_toml = format!("[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n{extra_toml}");
        std::fs::write(src.join("config.toml"), config_toml).expect("config.toml");

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
        let config = ConfigDocument::load(&paths.config_path).expect("load config");
        let db_cfg = config.database_config().expect("db config");
        let pool = DbPool::connect(&db_cfg, &paths).await.expect("connect sqlite");
        create_head_schema(&pool, false).await.expect("head schema");
        set_alembic_version(&pool, LATEST_SCHEMA_REVISION)
            .await
            .expect("alembic version");

        TestEnv {
            root: dir.path().to_path_buf(),
            _dir: dir,
            paths,
            config,
            pool,
        }
    }

    fn ctx_for(root: &Path, yes: bool) -> AppContext {
        AppContext::new(
            GlobalOpts {
                root: Some(root.to_path_buf()),
                config: None,
                output: OutputFormat::Json,
                yes,
                verbose: false,
            },
            UiConsole::new(OutputFormat::Json),
        )
    }

    fn sqlite_pool(pool: &DbPool) -> &sqlx::SqlitePool {
        match pool {
            DbPool::Sqlite(p) => p,
            _ => panic!("expected sqlite pool"),
        }
    }

    async fn insert_user(pool: &DbPool, username: &str, status: i32, secret_key: &str) -> Uuid {
        let uid = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, nickname, created_time, status, secret_key) VALUES (?, ?, ?, 1.0, ?, ?)",
        )
        .bind(uid.simple().to_string())
        .bind(username)
        .bind(username)
        .bind(status)
        .bind(secret_key)
        .execute(sqlite_pool(pool))
        .await
        .expect("insert user");
        uid
    }

    async fn insert_password(
        pool: &DbPool,
        user_id: Uuid,
        cred_id: &str,
        pass_hash: &str,
        last_mod: f64,
    ) {
        sqlx::query(
            "INSERT INTO user_passwords (user_id, credential_id, pass_hash, passwd_last_modified) VALUES (?, ?, ?, ?)",
        )
        .bind(user_id.simple().to_string())
        .bind(cred_id)
        .bind(pass_hash)
        .bind(last_mod)
        .execute(sqlite_pool(pool))
        .await
        .expect("insert password");
    }

    async fn insert_totp(pool: &DbPool, user_id: Uuid, cred_id: &str, enabled: bool) {
        sqlx::query(
            "INSERT INTO user_totp_credentials (user_id, credential_id, secret, enabled, backup_codes, created_time) VALUES (?, ?, 'JBSWY3DPEHPK3PXP', ?, NULL, 1.0)",
        )
        .bind(user_id.simple().to_string())
        .bind(cred_id)
        .bind(enabled)
        .execute(sqlite_pool(pool))
        .await
        .expect("insert totp");
    }

    async fn insert_public_key(pool: &DbPool, id: &str, user_id: Uuid, fp: &[u8]) {
        sqlx::query(
            "INSERT INTO user_auth_public_keys (id, user_id, public_key_der, fingerprint, label, created_time, last_used_time) VALUES (?, ?, X'01', ?, 'k', 1.0, NULL)",
        )
        .bind(id)
        .bind(user_id.simple().to_string())
        .bind(fp)
        .execute(sqlite_pool(pool))
        .await
        .expect("insert public key");
    }

    async fn insert_policy(
        pool: &DbPool,
        user_id: Uuid,
        purpose: &str,
        revision: i32,
        chains_json: serde_json::Value,
    ) {
        sqlx::query(
            "INSERT INTO user_auth_policies (user_id, purpose, revision, chains) VALUES (?, ?, ?, ?)",
        )
        .bind(user_id.simple().to_string())
        .bind(purpose)
        .bind(revision)
        .bind(chains_json.to_string())
        .execute(sqlite_pool(pool))
        .await
        .expect("insert policy");
    }

    async fn create_oidc_table_and_insert(pool: &DbPool, id: &str, user_id: Uuid, issuer: &str) {
        let ddl = vec![USER_OIDC_CREDENTIALS_TABLE.compile_create_table(DatabaseKind::Sqlite)];
        execute_ddl_statements(pool, &ddl)
            .await
            .expect("create oidc table");
        sqlx::query(
            "INSERT INTO user_oidc_credentials (id, user_id, issuer, subject, identity_digest) VALUES (?, ?, ?, 'sub-1', ?)",
        )
        .bind(id)
        .bind(user_id.simple().to_string())
        .bind(issuer)
        .bind(vec![1u8; 32])
        .execute(sqlite_pool(pool))
        .await
        .expect("insert oidc");
    }

    #[tokio::test]
    async fn reset_password_updates_existing_preserves_cred_id_revokes_sessions_and_audits() {
        let env = setup_test_env("").await;
        let old_secret = "a".repeat(64);
        let uid = insert_user(&env.pool, "alice", 0, &old_secret).await;
        insert_password(&env.pool, uid, "cred_alice_1", "$argon2id$old", 1234.0).await;
        insert_policy(
            &env.pool,
            uid,
            "login",
            1,
            serde_json::json!([[{"method": "password", "credential_ids": ["cred_alice_1"]}]]),
        )
        .await;

        let ui = UiConsole::new(OutputFormat::Json);
        let report = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "alice".to_string(),
                password: None,
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: false,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect("reset password");

        assert_eq!(report.username, "alice");
        assert_eq!(report.user_status, "ACTIVE");
        assert!(!report.credential_created);
        assert!(!report.login_policy_updated);
        assert!(report.force_change_on_login);
        assert!(report.sessions_revoked);
        assert!(report.audit_logged);
        assert!(!report.dry_run);
        let plain = report.generated_password.expect("generated password");

        let pw_row = sqlx::query(
            "SELECT credential_id, pass_hash, passwd_last_modified FROM user_passwords WHERE user_id = ?",
        )
        .bind(uid.simple().to_string())
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("fetch pw");
        assert_eq!(pw_row.get::<String, _>("credential_id"), "cred_alice_1");
        assert_eq!(pw_row.get::<f64, _>("passwd_last_modified"), 0.0);
        let hash_str: String = pw_row.get("pass_hash");
        let parsed = PasswordHash::new(&hash_str).expect("phc");
        Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .expect("verify generated password");

        let user_row = sqlx::query("SELECT secret_key FROM users WHERE id = ?")
            .bind(uid.simple().to_string())
            .fetch_one(sqlite_pool(&env.pool))
            .await
            .expect("fetch user");
        let new_secret: String = user_row.get("secret_key");
        assert_ne!(new_secret, old_secret);
        assert_eq!(new_secret.len(), 64);

        let audit_row = sqlx::query(
            "SELECT action, user_id, target, data, result FROM audit_entries",
        )
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("audit");
        assert_eq!(audit_row.get::<String, _>("action"), "reset_user_password");
        assert_eq!(audit_row.get::<Option<String>, _>("user_id"), None);
        assert_eq!(audit_row.get::<String, _>("target"), "alice");
        assert_eq!(audit_row.get::<i32, _>("result"), 0);
        let data_str: String = audit_row.get("data");
        assert!(!data_str.contains(&plain));
        assert!(!data_str.contains(&hash_str));
    }

    #[tokio::test]
    async fn reset_password_creates_credential_and_login_policy_for_passwordless_user() {
        let env = setup_test_env("").await;
        let bob = insert_user(&env.pool, "bob", 0, &"b".repeat(64)).await;
        insert_public_key(&env.pool, "pk_bob", bob, b"\xaa\xbb").await;
        insert_policy(
            &env.pool,
            bob,
            "login",
            2,
            serde_json::json!([[{"method": "publickey", "credential_ids": ["pk_bob"]}]]),
        )
        .await;

        let ui = UiConsole::new(OutputFormat::Json);
        let bob_report = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "bob".to_string(),
                password: Some("ValidPass99!".to_string()),
                password_stdin: false,
                prompt_password: false,
                no_force_change: true,
                no_ensure_login_policy: false,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect("reset bob");

        assert!(bob_report.generated_password.is_none());
        assert!(bob_report.credential_created);
        assert!(bob_report.login_policy_updated);
        assert!(!bob_report.force_change_on_login);

        let pw_row = sqlx::query(
            "SELECT credential_id, passwd_last_modified FROM user_passwords WHERE user_id = ?",
        )
        .bind(bob.simple().to_string())
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("bob pw");
        let bob_cid: String = pw_row.get("credential_id");
        assert_eq!(bob_cid.len(), 32);
        assert!(pw_row.get::<f64, _>("passwd_last_modified") > 0.0);

        let pol_row = sqlx::query(
            "SELECT revision, chains FROM user_auth_policies WHERE user_id = ? AND purpose = 'login'",
        )
        .bind(bob.simple().to_string())
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("bob login policy");
        assert_eq!(pol_row.get::<i32, _>("revision"), 3);
        let chains: serde_json::Value =
            serde_json::from_str(&pol_row.get::<String, _>("chains")).expect("json");
        assert_eq!(
            chains,
            serde_json::json!([
                [{"method": "publickey", "credential_ids": ["pk_bob"]}],
                [{"method": "password", "credential_ids": [bob_cid]}]
            ])
        );

        // --no-ensure-login-policy skips policy creation, and --dry-run touches nothing
        let carol = insert_user(&env.pool, "carol", 0, &"c".repeat(64)).await;
        let carol_report = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "carol".to_string(),
                password: Some("ValidPass99!".to_string()),
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: true,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect("carol opt-out");
        assert!(carol_report.credential_created);
        assert!(!carol_report.login_policy_updated);
        let carol_pol_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_auth_policies WHERE user_id = ?",
        )
        .bind(carol.simple().to_string())
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("cnt");
        assert_eq!(carol_pol_count, 0);

        let dry = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "bob".to_string(),
                password: Some("AnotherPass99!".to_string()),
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: false,
                dry_run: true,
            },
            &ui,
        )
        .await
        .expect("dry run");
        assert!(dry.dry_run);
        assert!(!dry.sessions_revoked);
        assert!(!dry.audit_logged);
    }

    #[tokio::test]
    async fn reset_password_enforces_db_policy_rejects_empty_weak_missing_and_allows_disabled() {
        let env = setup_test_env("").await;
        let _disabled = insert_user(&env.pool, "disabled_u", 1, &"d".repeat(64)).await;

        sqlx::query(
            "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('security.password', 'core', 'passwd_min_length', 1, 1, 'int', '20', 1.0)",
        )
        .execute(sqlite_pool(&env.pool))
        .await
        .expect("insert option");

        let ui = UiConsole::new(OutputFormat::Json);

        let empty_err = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "disabled_u".to_string(),
                password: Some(String::new()),
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: false,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect_err("empty password rejected");
        assert!(matches!(empty_err, CfmsError::InvalidArgument(_)));

        let weak_err = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "disabled_u".to_string(),
                password: Some("ShortValid1!".to_string()),
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: false,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect_err("short under DB option rejected");
        assert!(matches!(weak_err, CfmsError::InvalidArgument(_)));

        let missing_err = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "missing".to_string(),
                password: None,
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: false,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect_err("missing user rejected");
        assert!(matches!(missing_err, CfmsError::InvalidArgument(_)));

        let ok = reset_password_with_context(
            &env.paths,
            &env.config,
            &env.pool,
            UserResetPasswordArgs {
                username: "disabled_u".to_string(),
                password: None,
                password_stdin: false,
                prompt_password: false,
                no_force_change: false,
                no_ensure_login_policy: false,
                dry_run: false,
            },
            &ui,
        )
        .await
        .expect("disabled user allowed");
        assert_eq!(ok.user_status, "DISABLED");
        assert!(ok.generated_password.as_ref().expect("gen").len() >= 20);
    }

    #[tokio::test]
    async fn rotate_secrets_handles_empty_single_user_fleet_over_250_and_dry_run() {
        let env = setup_test_env("").await;
        let empty = rotate_secrets_with_context(
            &env.pool,
            UserRotateSecretsArgs {
                username: None,
                dry_run: false,
            },
        )
        .await
        .expect("empty rotate");
        assert_eq!(empty.rotated_users, 0);
        assert!(!empty.audit_logged);

        let initial_secret = "0".repeat(64);
        for i in 0..260 {
            insert_user(&env.pool, &format!("user_{i:03}"), 0, &initial_secret).await;
        }

        let dry = rotate_secrets_with_context(
            &env.pool,
            UserRotateSecretsArgs {
                username: Some("user_001".to_string()),
                dry_run: true,
            },
        )
        .await
        .expect("dry single");
        assert!(dry.dry_run);
        assert_eq!(dry.rotated_users, 1);

        let single = rotate_secrets_with_context(
            &env.pool,
            UserRotateSecretsArgs {
                username: Some("user_001".to_string()),
                dry_run: false,
            },
        )
        .await
        .expect("single rotate");
        assert_eq!(single.rotated_users, 1);
        assert!(single.audit_logged);

        let single_secret: String =
            sqlx::query_scalar("SELECT secret_key FROM users WHERE username = 'user_001'")
                .fetch_one(sqlite_pool(&env.pool))
                .await
                .expect("u1");
        assert_ne!(single_secret, initial_secret);

        let fleet = rotate_secrets_with_context(
            &env.pool,
            UserRotateSecretsArgs {
                username: None,
                dry_run: false,
            },
        )
        .await
        .expect("fleet rotate");
        assert_eq!(fleet.rotated_users, 260);
        assert!(fleet.audit_logged);

        let rows = sqlx::query("SELECT secret_key FROM users")
            .fetch_all(sqlite_pool(&env.pool))
            .await
            .expect("all secrets");
        let unique: HashSet<String> = rows
            .into_iter()
            .map(|r| r.get::<String, _>("secret_key"))
            .collect();
        assert_eq!(unique.len(), 260);
        assert!(!unique.contains(&initial_secret));
        assert!(!unique.contains(&single_secret));
        assert!(unique.iter().all(|s| s.len() == 64));
    }

    #[tokio::test]
    async fn clear_totp_handles_noop_orphans_sessions_oidc_and_atomic_rollback() {
        let env = setup_test_env("[extensions.oidc_sso]\nissuer = \"https://idp.example.com/\"\n").await;

        let noop_u = insert_user(&env.pool, "noop_u", 0, &"1".repeat(64)).await;
        insert_password(&env.pool, noop_u, "pw_noop", "$argon2id$x", 1.0).await;
        insert_policy(
            &env.pool,
            noop_u,
            "login",
            1,
            serde_json::json!([[{"method": "password", "credential_ids": ["pw_noop"]}]]),
        )
        .await;

        let noop_res = clear_totp_with_context(
            &env.config,
            &env.pool,
            UserClearTotpArgs {
                username: Some("noop_u".to_string()),
                all_users: false,
                revoke_sessions: false,
                dry_run: false,
            },
        )
        .await
        .expect("noop clear");
        assert_eq!(noop_res.affected_users, 0);
        assert_eq!(noop_res.unchanged_users, 1);
        assert_eq!(noop_res.cleared_credentials, 0);
        assert_eq!(noop_res.updated_policies, 0);
        assert!(!noop_res.audit_logged);

        // User alice: TOTP credential + MFA + Escalation, default preserves session secret_key
        let alice_sec = "2".repeat(64);
        let alice = insert_user(&env.pool, "alice", 0, &alice_sec).await;
        insert_password(&env.pool, alice, "pw_a", "$argon2id$a", 1.0).await;
        insert_totp(&env.pool, alice, "totp_a", true).await;
        insert_policy(
            &env.pool,
            alice,
            "login",
            1,
            serde_json::json!([[{"method": "password", "credential_ids": ["pw_a"]}]]),
        )
        .await;
        insert_policy(
            &env.pool,
            alice,
            "mfa",
            1,
            serde_json::json!([[{"method": "totp", "credential_ids": ["totp_a"]}]]),
        )
        .await;
        insert_policy(
            &env.pool,
            alice,
            "escalation",
            1,
            serde_json::json!([
                [{"method": "totp", "credential_ids": ["totp_a"]}],
                [{"method": "password", "credential_ids": ["pw_a"]}]
            ]),
        )
        .await;

        // Dry run leaves TOTP intact
        let alice_dry = clear_totp_with_context(
            &env.config,
            &env.pool,
            UserClearTotpArgs {
                username: Some("alice".to_string()),
                all_users: false,
                revoke_sessions: true,
                dry_run: true,
            },
        )
        .await
        .expect("dry run");
        assert_eq!(alice_dry.cleared_credentials, 1);
        assert_eq!(alice_dry.updated_policies, 2);
        assert_eq!(alice_dry.sessions_revoked, 0);

        let alice_res = clear_totp_with_context(
            &env.config,
            &env.pool,
            UserClearTotpArgs {
                username: Some("alice".to_string()),
                all_users: false,
                revoke_sessions: false,
                dry_run: false,
            },
        )
        .await
        .expect("clear alice");
        assert_eq!(alice_res.cleared_credentials, 1);
        assert_eq!(alice_res.updated_policies, 2);
        assert_eq!(alice_res.sessions_revoked, 0);
        assert!(alice_res.audit_logged);

        let sec_after: String =
            sqlx::query_scalar("SELECT secret_key FROM users WHERE id = ?")
                .bind(alice.simple().to_string())
                .fetch_one(sqlite_pool(&env.pool))
                .await
                .expect("alice secret");
        assert_eq!(sec_after, alice_sec);

        let mfa_row = sqlx::query(
            "SELECT revision, chains FROM user_auth_policies WHERE user_id = ? AND purpose = 'mfa'",
        )
        .bind(alice.simple().to_string())
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("mfa kept");
        assert_eq!(mfa_row.get::<i32, _>("revision"), 2);
        assert_eq!(mfa_row.get::<String, _>("chains"), "[]");

        // Orphaned totp policy + --revoke-sessions rotates secret_key
        let orphan_sec = "3".repeat(64);
        let orphan = insert_user(&env.pool, "orphan", 0, &orphan_sec).await;
        insert_password(&env.pool, orphan, "pw_o", "$argon2id$o", 1.0).await;
        insert_policy(
            &env.pool,
            orphan,
            "login",
            1,
            serde_json::json!([[{"method": "password", "credential_ids": ["pw_o"]}]]),
        )
        .await;
        insert_policy(
            &env.pool,
            orphan,
            "mfa",
            1,
            serde_json::json!([[{"method": "totp", "credential_ids": ["stale_totp"]}]]),
        )
        .await;

        let orphan_res = clear_totp_with_context(
            &env.config,
            &env.pool,
            UserClearTotpArgs {
                username: Some("orphan".to_string()),
                all_users: false,
                revoke_sessions: true,
                dry_run: false,
            },
        )
        .await
        .expect("clear orphan");
        assert_eq!(orphan_res.affected_users, 1);
        assert_eq!(orphan_res.cleared_credentials, 0);
        assert_eq!(orphan_res.updated_policies, 1);
        assert_eq!(orphan_res.sessions_revoked, 1);

        let orphan_sec_after: String =
            sqlx::query_scalar("SELECT secret_key FROM users WHERE id = ?")
                .bind(orphan.simple().to_string())
                .fetch_one(sqlite_pool(&env.pool))
                .await
                .expect("orphan sec");
        assert_ne!(orphan_sec_after, orphan_sec);

        // --all atomic rollback + active OIDC issuer verification
        let oidc_ok = insert_user(&env.pool, "oidc_ok", 0, &"4".repeat(64)).await;
        insert_totp(&env.pool, oidc_ok, "totp_oidc", true).await;
        create_oidc_table_and_insert(&env.pool, "oidc_1", oidc_ok, "https://idp.example.com").await;
        insert_policy(
            &env.pool,
            oidc_ok,
            "login",
            1,
            serde_json::json!([[{"method": "oidc", "credential_ids": ["oidc_1"]}]]),
        )
        .await;
        insert_policy(
            &env.pool,
            oidc_ok,
            "mfa",
            1,
            serde_json::json!([[{"method": "totp", "credential_ids": ["totp_oidc"]}]]),
        )
        .await;

        let blocked = insert_user(&env.pool, "blocked_u", 0, &"5".repeat(64)).await;
        insert_totp(&env.pool, blocked, "totp_blk", true).await;
        insert_public_key(&env.pool, "pk_blk", blocked, b"\x01\x02").await;
        insert_policy(
            &env.pool,
            blocked,
            "login",
            1,
            serde_json::json!([[{"method": "publickey", "credential_ids": ["pk_blk"]}]]),
        )
        .await;
        insert_policy(
            &env.pool,
            blocked,
            "mfa",
            1,
            serde_json::json!([
                [{"method": "publickey", "credential_ids": ["pk_blk"]}],
                [{"method": "totp", "credential_ids": ["totp_blk"]}]
            ]),
        )
        .await;

        let rollback_err = clear_totp_with_context(
            &env.config,
            &env.pool,
            UserClearTotpArgs {
                username: None,
                all_users: true,
                revoke_sessions: false,
                dry_run: false,
            },
        )
        .await
        .expect_err("all must roll back cleanly");
        assert!(rollback_err.to_string().contains("blocked_u"));

        let oidc_totp_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_totp_credentials WHERE user_id = ?",
        )
        .bind(oidc_ok.simple().to_string())
        .fetch_one(sqlite_pool(&env.pool))
        .await
        .expect("oidc totp preserved");
        assert_eq!(oidc_totp_count, 1);

        // Remove blocked_u totp conflict via clearing only oidc_ok -> active OIDC issuer succeeds!
        let oidc_clear = clear_totp_with_context(
            &env.config,
            &env.pool,
            UserClearTotpArgs {
                username: Some("oidc_ok".to_string()),
                all_users: false,
                revoke_sessions: false,
                dry_run: false,
            },
        )
        .await
        .expect("active oidc issuer satisfies login after totp clear");
        assert_eq!(oidc_clear.cleared_credentials, 1);
    }

    #[tokio::test]
    async fn handle_enforces_runtime_lock_unfinished_tx_confirm_and_schema_drift() {
        let env = setup_test_env("").await;
        insert_user(&env.pool, "alice", 0, &"a".repeat(64)).await;

        let ctx_no_yes = ctx_for(&env.root, false);
        let ctx_yes = ctx_for(&env.root, true);

        // Fleet confirm_destructive without --yes aborts cleanly in JSON mode
        let abort_err = handle(
            &ctx_no_yes,
            UserCommand::RotateSecrets(UserRotateSecretsArgs {
                username: None,
                dry_run: false,
            }),
        )
        .await
        .expect_err("unconfirmed fleet rotate aborts");
        assert!(abort_err.to_string().contains("--yes"));

        let clear_abort_err = handle(
            &ctx_no_yes,
            UserCommand::ClearTotp(UserClearTotpArgs {
                username: None,
                all_users: true,
                revoke_sessions: false,
                dry_run: false,
            }),
        )
        .await
        .expect_err("unconfirmed clear-totp --all aborts");
        assert!(clear_abort_err.to_string().contains("--yes"));

        // Held server.lock blocks live mutations, allows --dry-run
        {
            let _server_lock = RuntimeLock::acquire(&env.paths, false).expect("lock");
            let lock_err = handle(
                &ctx_yes,
                UserCommand::ResetPassword(UserResetPasswordArgs {
                    username: "alice".to_string(),
                    password: Some("ValidPass99!".to_string()),
                    password_stdin: false,
                    prompt_password: false,
                    no_force_change: false,
                    no_ensure_login_policy: false,
                    dry_run: false,
                }),
            )
            .await
            .expect_err("runtime lock rejects mutation");
            assert!(matches!(lock_err, CfmsError::RuntimeLocked { .. }));

            handle(
                &ctx_yes,
                UserCommand::ResetPassword(UserResetPasswordArgs {
                    username: "alice".to_string(),
                    password: Some("ValidPass99!".to_string()),
                    password_stdin: false,
                    prompt_password: false,
                    no_force_change: false,
                    no_ensure_login_policy: false,
                    dry_run: true,
                }),
            )
            .await
            .expect("dry-run bypasses server lock");
        }

        // Pending transaction.json blocks mutations with UnfinishedTransaction
        let tx_marker = env.paths.transaction_path();
        if let Some(parent) = tx_marker.parent() {
            std::fs::create_dir_all(parent).expect("create tx parent dir");
        }
        std::fs::write(&tx_marker, "{}").expect("write tx marker");
        let tx_err = handle(
            &ctx_yes,
            UserCommand::ClearTotp(UserClearTotpArgs {
                username: Some("alice".to_string()),
                all_users: false,
                revoke_sessions: false,
                dry_run: false,
            }),
        )
        .await
        .expect_err("transaction marker rejects mutation");
        assert!(matches!(tx_err, CfmsError::UnfinishedTransaction { .. }));
        std::fs::remove_file(&tx_marker).expect("remove tx marker");

        // Stale alembic_version triggers SchemaDrift before mutations
        set_alembic_version(&env.pool, "fe8863687aa4")
            .await
            .expect("stale revision");
        let drift_err = handle(
            &ctx_yes,
            UserCommand::RotateSecrets(UserRotateSecretsArgs {
                username: Some("alice".to_string()),
                dry_run: false,
            }),
        )
        .await
        .expect_err("stale revision fails");
        assert!(matches!(drift_err, CfmsError::SchemaDrift(_)));
    }
}
