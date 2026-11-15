use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sqlx::Row;

use cfms_ctl::cli::GlobalOpts;
use cfms_ctl::cli::config::{
    ConfigCommand, ConfigMigrateOptionsArgs, ConfigSyncTemplateArgs,
};
use cfms_ctl::core::{CfmsError, ConfigDocument, WorkspacePaths};
use cfms_ctl::db::schema::create_head_schema;
use cfms_ctl::db::{
    DbPool, OptionUpdateInput, OptionsSchemaRegistry, fetch_stored_options, write_options_batch,
};
use cfms_ctl::ops::AppContext;
use cfms_ctl::ops::config;
use cfms_ctl::ui::{OutputFormat, UiConsole};

fn sibling_server_repo() -> Option<PathBuf> {
    let candidate = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cfms_on_websocket");
    if candidate
        .join("src/include/schemas/config.migrations.json")
        .is_file()
        && candidate
            .join("src/include/schemas/config.schema.json")
            .is_file()
        && candidate
            .join("src/include/schemas/options.schema.json")
            .is_file()
        && candidate.join("src/config.toml.sample").is_file()
    {
        Some(candidate)
    } else {
        None
    }
}

fn copy_real_server_schemas(server_repo: &Path, deploy_root: &Path) {
    let dst_src = deploy_root.join("src");
    let dst_schemas = dst_src.join("include").join("schemas");
    let dst_ext = dst_src.join("include").join("extensions");
    fs::create_dir_all(&dst_schemas).unwrap();
    fs::create_dir_all(&dst_ext).unwrap();

    fs::copy(
        server_repo.join("src/config.toml.sample"),
        dst_src.join("config.toml.sample"),
    )
    .unwrap();

    for name in ["config.schema.json", "options.schema.json", "config.migrations.json"] {
        fs::copy(
            server_repo.join("src/include/schemas").join(name),
            dst_schemas.join(name),
        )
        .unwrap();
    }

    let src_ext = server_repo.join("src/include/extensions");
    for entry in fs::read_dir(&src_ext).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let target_ext = dst_ext.join(entry.file_name());
        fs::create_dir_all(&target_ext).unwrap();
        for fname in ["manifest.toml", "options.schema.json"] {
            let f = path.join(fname);
            if f.is_file() {
                fs::copy(&f, target_ext.join(fname)).unwrap();
            }
        }
    }
}

fn make_ctx(root: &Path, yes: bool) -> AppContext {
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

#[tokio::test]
async fn real_server_schemas_and_migrations_parity_e2e() {
    let Some(server_repo) = sibling_server_repo() else {
        // Optional cross-repo check when `../cfms_on_websocket` is checked out alongside this CLI.
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    copy_real_server_schemas(&server_repo, root);

    let legacy_toml = r#"# CFMS v0.13 operator config
[server]
host = "127.0.0.1"
port = 5104
file_chunk_size = 2097152
name = "Legacy CFMS Instance"

[database]
type = "sqlite"
file = "parity.db"
# Legacy v0.13 key
db_name = "parity_pg"

[storage]
type = "local"
local_path = "content"

[security]
# Keep operator pepper comment
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
passwd_min_length = 10
passwd_must_contain = ["AB", ["0", "1"], "!@"]
require_passwd_enforcement_changes = false

[security.auth_throttle]
enabled = true
account_failure_threshold = 6

[sso.oidc]
enabled = true
issuer = "https://idp.parity.example.com"
client_id = "cfms-client"
client_secret = "secret-value"
username_claim = "email"
auto_provision = true
default_groups = ["users", "sso"]

[extensions.brute_force_lockdown]
failure_threshold = 25

[document]
allow_name_duplicate = true

[document.upload]
creation_rate_window_seconds = 90
creation_rate_per_user = 21

[extensions]
enabled = []

[custom_operator]
keep = "untouched"
"#;
    fs::write(root.join("src/config.toml"), legacy_toml).unwrap();

    let paths = WorkspacePaths::discover(Some(root), None).unwrap();
    let ctx_yes = make_ctx(root, true);
    let ctx_check = make_ctx(root, false);

    let pool = ctx_yes.connect_db(&paths).await.unwrap();
    create_head_schema(&pool, false).await.unwrap();

    // 1. `config sync-template` must reject before `migrate-options` clears legacy option keys.
    let err = config::handle(
        &ctx_yes,
        ConfigCommand::SyncTemplate(ConfigSyncTemplateArgs {
            check: false,
            remove: Vec::new(),
            prune: false,
            template: None,
            schema: None,
            migrations: None,
        }),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("migrate-options"),
        "expected migrate-options guidance, got: {err}"
    );
    assert_eq!(fs::read_to_string(&paths.config_path).unwrap(), legacy_toml);

    // 2. `migrate-options --check` reports pending items and keeps DB & disk clean.
    let err = config::handle(
        &ctx_check,
        ConfigCommand::MigrateOptions(ConfigMigrateOptionsArgs {
            check: true,
            discard_legacy: false,
            schema: None,
            migrations: None,
            config_schema: None,
        }),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("pending"), "unexpected: {err}");
    assert!(fetch_stored_options(&pool, None).await.unwrap().is_empty());

    // 3. Authoritative DB option conflicts fail without `--discard-legacy`.
    let registry = OptionsSchemaRegistry::from_workspace(&paths, None).unwrap();
    let mut seed = BTreeMap::new();
    seed.insert(
        "passwd_min_length".to_string(),
        OptionUpdateInput {
            value: serde_json::json!(14),
            expected_revision: 0,
        },
    );
    write_options_batch(&pool, &registry, "security.password", seed)
        .await
        .unwrap();

    let err = config::handle(
        &ctx_yes,
        ConfigCommand::MigrateOptions(ConfigMigrateOptionsArgs {
            check: false,
            discard_legacy: false,
            schema: None,
            migrations: None,
            config_schema: None,
        }),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CfmsError::OptionConflict(_)), "got: {err}");
    assert_eq!(fetch_stored_options(&pool, None).await.unwrap().len(), 1);

    // 4. `migrate-options --discard-legacy` imports all remaining legacy options atomically and cleans config.toml.
    config::handle(
        &ctx_yes,
        ConfigCommand::MigrateOptions(ConfigMigrateOptionsArgs {
            check: false,
            discard_legacy: true,
            schema: None,
            migrations: None,
            config_schema: None,
        }),
    )
    .await
    .unwrap();

    let stored = fetch_stored_options(&pool, None).await.unwrap();
    assert_eq!(
        stored[&("server".to_string(), "name".to_string())].value,
        serde_json::json!("Legacy CFMS Instance")
    );
    assert_eq!(
        stored[&("security.password".to_string(), "passwd_min_length".to_string())].value,
        serde_json::json!(14)
    );
    assert_eq!(
        stored[&("security.password".to_string(), "passwd_rules".to_string())].value,
        serde_json::json!(["(?:A|B)", "(?:0|1)", "(?:!|@)"])
    );
    assert_eq!(
        stored[&(
            "security.password".to_string(),
            "passwd_min_passed_count".to_string()
        )]
            .value,
        serde_json::json!(3)
    );
    assert_eq!(
        stored[&(
            "security.auth_throttle".to_string(),
            "account_failure_threshold".to_string()
        )]
            .value,
        serde_json::json!(6)
    );
    assert_eq!(
        stored[&(
            "document.upload.creation_risk_control".to_string(),
            "refill_period_seconds".to_string()
        )]
            .value,
        serde_json::json!(90)
    );
    assert_eq!(
        stored[&(
            "document.upload.creation_risk_control".to_string(),
            "account_capacity".to_string()
        )]
            .value,
        serde_json::json!(10)
    );
    assert_eq!(
        stored[&(
            "security.brute_force_lockdown".to_string(),
            "failure_threshold".to_string()
        )]
            .value,
        serde_json::json!(25)
    );
    assert_eq!(
        stored[&("identity.oidc".to_string(), "username_claim".to_string())].value,
        serde_json::json!("email")
    );
    assert_eq!(
        stored[&("identity.oidc".to_string(), "auto_provision".to_string())].value,
        serde_json::json!(true)
    );
    assert_eq!(
        stored[&("identity.oidc".to_string(), "default_groups".to_string())].value,
        serde_json::json!(["users", "sso"])
    );

    let DbPool::Sqlite(ref sq) = pool else {
        unreachable!()
    };
    let sources: Vec<String> = sqlx::query("SELECT data FROM audit_entries WHERE action = 'update_options'")
        .fetch_all(sq)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.get::<String, _>(0))
        .collect();
    assert!(sources.iter().any(|raw| {
        let parsed: Value = serde_json::from_str(raw).unwrap();
        parsed["source"] == serde_json::json!("cfms_ctl_migration")
    }));

    // 5. `sync-template` merges remaining real v0.14 sample sections and passes real `config.schema.json`.
    config::handle(
        &ctx_yes,
        ConfigCommand::SyncTemplate(ConfigSyncTemplateArgs {
            check: false,
            remove: Vec::new(),
            prune: false,
            template: None,
            schema: None,
            migrations: None,
        }),
    )
    .await
    .unwrap();

    let final_doc = ConfigDocument::load(&paths.config_path).unwrap();
    let schema_path = paths.discover_config_schema_path(None).unwrap().unwrap();
    final_doc.validate_with_schema(Some(&schema_path)).unwrap();

    let final_text = fs::read_to_string(&paths.config_path).unwrap();
    assert!(final_text.contains("# CFMS v0.13 operator config"));
    assert!(final_text.contains("# Keep operator pepper comment"));
    assert!(final_text.contains("keep = \"untouched\""));
    assert!(final_text.contains("issuer = \"https://idp.parity.example.com\""));
    assert!(final_text.contains("enabled = [\"oidc_sso\"]"));
    assert!(!final_text.contains("db_name"));
    assert!(!final_text.contains("[sso"));
    assert!(!final_text.contains("username_claim"));
    assert!(!final_text.contains("passwd_must_contain"));
    assert!(!final_text.contains("allow_name_duplicate"));
    assert!(!final_text.contains("creation_rate_"));

    // 6. Both `sync-template --check` and `migrate-options --check` are idempotent no-ops now.
    config::handle(
        &ctx_check,
        ConfigCommand::SyncTemplate(ConfigSyncTemplateArgs {
            check: true,
            remove: Vec::new(),
            prune: false,
            template: None,
            schema: None,
            migrations: None,
        }),
    )
    .await
    .unwrap();
    config::handle(
        &ctx_check,
        ConfigCommand::MigrateOptions(ConfigMigrateOptionsArgs {
            check: true,
            discard_legacy: false,
            schema: None,
            migrations: None,
            config_schema: None,
        }),
    )
    .await
    .unwrap();
}
