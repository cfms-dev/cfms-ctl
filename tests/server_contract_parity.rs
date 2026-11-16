use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use cfms_ctl::cli::GlobalOpts;
use cfms_ctl::cli::config::ConfigSyncTemplateArgs;
use cfms_ctl::core::{
    CORE_CONFIG_CONTRACT_VERSION, ConfigDocument, CoreConfigContract, DRAFT_2020_12_DIALECT,
    WorkspacePaths,
};
use cfms_ctl::db::schema::create_head_schema;
use cfms_ctl::db::{
    DbPool, OptionUpdateInput, OptionsSchemaRegistry, get_option, list_options,
    write_options_batch,
};
use cfms_ctl::ops::AppContext;
use cfms_ctl::ops::config;
use cfms_ctl::ops::deployment::ReleaseManifest;
use cfms_ctl::ui::{OutputFormat, UiConsole};

fn sibling_server_repo() -> Option<PathBuf> {
    let candidate = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cfms_on_websocket");
    if candidate.join("src/include/config/contract.py").is_file()
        && candidate.join("src/config.toml.sample").is_file()
    {
        Some(candidate)
    } else {
        None
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
async fn real_server_core_config_contract_parity_e2e() {
    let Some(server_repo) = sibling_server_repo() else {
        // Optional cross-repo check when `../cfms_on_websocket` is checked out alongside this CLI.
        return;
    };

    // 1. Server repository no longer ships standalone `.schema.json` or `.migrations.json` files.
    assert!(!server_repo.join("src/include/schemas").exists());

    // 2. Live Python reflection extracts a valid v1.0 Draft 2020-12 core configuration contract.
    let repo_paths = WorkspacePaths::from_code_dir(&server_repo.join("src")).unwrap();
    let (contract, source_desc) = CoreConfigContract::from_workspace(&repo_paths, None)
        .expect("reflect core_config_contract")
        .expect("contract present in cfms_on_websocket");
    assert_eq!(contract.contract_version, CORE_CONFIG_CONTRACT_VERSION);
    assert_eq!(contract.schema_dialect, DRAFT_2020_12_DIALECT);
    assert!(
        source_desc.contains("include.config.contract"),
        "expected python reflection source, got: {source_desc}"
    );

    // 3. `src/config.toml.sample` validates strictly against `contract.toml`, surfacing only non-blocking warnings.
    let sample_doc = ConfigDocument::load(&server_repo.join("src/config.toml.sample")).unwrap();
    let sample_warnings = sample_doc
        .validate_with_contract(Some(&contract))
        .expect("sample config must satisfy live contract.toml");
    assert!(
        sample_warnings.iter().any(|w| w.contains("pepper")),
        "expected security.pepper non-empty warning, got: {sample_warnings:?}"
    );

    // 4. `OptionsSchemaRegistry::from_contract` exposes all core namespaces and excludes extensions.
    let registry = OptionsSchemaRegistry::from_contract(&contract).unwrap();
    assert!(registry.has_core_contract());
    for expected_core_ns in [
        "access",
        "document.download.risk_control",
        "document.upload",
        "document.upload.creation_risk_control",
        "identity.permission_retention",
        "maintenance.audit_retention",
        "scheduling",
        "security.auth_throttle",
        "security.password",
        "security.request_rate_control",
        "server",
    ] {
        assert!(
            registry.get_namespace(expected_core_ns).is_some(),
            "missing core namespace {expected_core_ns}"
        );
    }
    assert!(registry.get_namespace("identity.oidc").is_none());
    assert!(registry.get_namespace("security.brute_force_lockdown").is_none());

    // 5. Build a release-manifest workspace embedding `core_config_contract` (zero Python needed).
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::copy(
        server_repo.join("src/config.toml.sample"),
        src_dir.join("config.toml.sample"),
    )
    .unwrap();

    let manifest = ReleaseManifest {
        format_version: 1,
        product: "cfms-on-websocket".to_string(),
        version: contract.core_version.clone(),
        requires_python: ">=3.14".to_string(),
        managed_extensions: vec!["builtin".to_string(), "oidc_sso".to_string()],
        files: BTreeMap::new(),
        core_config_contract: Some(contract.clone()),
    };
    fs::write(
        root.join("release-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // 6. Test `config sync-template` against real `config.toml.sample` + embedded contract:
    //    - Renames `database.db_name -> database.name` via `x-renamed-from`
    //    - Preserves removed core key with warning (without failing additionalProperties: false)
    //    - Leaves `[extensions.<id>]` subtables completely untouched (`x-unmanaged-subtables`)
    let legacy_toml = r#"# Operator header comment
[server]
host = "  127.0.0.1  "
port = 5104
file_chunk_size = 1048576
secret_key = "deploy-secret"
deprecated_core_flag = true

[security]
pepper = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[database]
type = "sqlite"
db_name = "parity_legacy.db"

[extensions]
enabled = ["oidc_sso"]

[extensions.oidc_sso]
issuer = "https://idp.example.com"
client_id = "cfms"

[extensions.custom_plugin]
endpoint = "https://custom.local"
nested = { timeout = 30 }
"#;
    fs::write(src_dir.join("config.toml"), legacy_toml).unwrap();

    let paths = WorkspacePaths::discover(Some(root), None).unwrap();
    let (loaded_contract, loaded_src) = CoreConfigContract::from_workspace(&paths, None)
        .unwrap()
        .expect("manifest contract");
    assert!(loaded_src.contains("release-manifest.json"));
    assert_eq!(loaded_contract, contract);

    let ctx = make_ctx(root, true);
    config::handle(
        &ctx,
        cfms_ctl::cli::config::ConfigCommand::SyncTemplate(ConfigSyncTemplateArgs {
            template: None,
            contract: None,
            check: false,
            remove: Vec::new(),
            prune: false,
        }),
    )
    .await
    .expect("sync-template with preserve-and-warn");

    let synced_raw = fs::read_to_string(&paths.config_path).unwrap();
    assert!(synced_raw.contains("# Operator header comment"));
    assert!(synced_raw.contains("name = \"parity_legacy.db\""));
    assert!(!synced_raw.contains("db_name"));
    assert!(synced_raw.contains("deprecated_core_flag = true"));
    assert!(synced_raw.contains("[extensions.oidc_sso]"));
    assert!(synced_raw.contains("[extensions.custom_plugin]"));
    assert!(synced_raw.contains("endpoint = \"https://custom.local\""));

    // Prune cleans unknown core keys while preserving all unmanaged extension subtables cleanly
    config::handle(
        &ctx,
        cfms_ctl::cli::config::ConfigCommand::SyncTemplate(ConfigSyncTemplateArgs {
            template: None,
            contract: None,
            check: false,
            remove: Vec::new(),
            prune: true,
        }),
    )
    .await
    .expect("sync-template --prune");
    let pruned_raw = fs::read_to_string(&paths.config_path).unwrap();
    assert!(!pruned_raw.contains("deprecated_core_flag"));
    assert!(pruned_raw.contains("[extensions.oidc_sso]"));
    assert!(pruned_raw.contains("[extensions.custom_plugin]"));

    let final_doc = ConfigDocument::load(&paths.config_path).unwrap();
    final_doc
        .validate_with_contract(Some(&loaded_contract))
        .expect("pruned config passes strict contract validation");

    // 7. Verify DB options enforcement against real contract (core invariants + trim + extension boundary).
    let pool = ctx.connect_db(&paths).await.unwrap();
    create_head_schema(&pool, false).await.unwrap();
    let DbPool::Sqlite(ref sq) = pool else {
        unreachable!()
    };
    sqlx::query(
        "INSERT INTO options (namespace, owner, option_key, schema_version, revision, value_type, option_value, updated_at) VALUES ('identity.oidc', 'oidc_sso', 'issuer', 1, 1, 'str', 'https://idp.example.com', 10.0)",
    )
    .execute(sq)
    .await
    .unwrap();

    // Reads return stored extension rows alongside core contract defaults
    let listed = list_options(&pool, &registry, None).await.unwrap();
    assert!(listed.iter().any(|r| r.namespace == "identity.oidc" && r.option_key == "issuer"));
    assert!(listed.iter().any(|r| r.namespace == "security.password" && r.option_key == "passwd_min_length"));
    assert_eq!(
        get_option(&pool, &registry, "identity.oidc", "issuer")
            .await
            .unwrap()
            .value,
        json!("https://idp.example.com")
    );

    // Core regex / invariant validation works against live contract schemas
    let mut bad_regex = BTreeMap::new();
    bad_regex.insert(
        "passwd_rules".to_string(),
        OptionUpdateInput {
            value: json!(["[unclosed"]),
            expected_revision: 0,
        },
    );
    assert!(
        write_options_batch(&pool, &registry, "security.password", bad_regex)
            .await
            .is_err()
    );

    let mut trim_map = BTreeMap::new();
    trim_map.insert(
        "action_costs".to_string(),
        OptionUpdateInput {
            value: json!({ "  upload  ": 5 }),
            expected_revision: 0,
        },
    );
    let written_rate =
        write_options_batch(&pool, &registry, "security.request_rate_control", trim_map)
            .await
            .expect("x-normalize-keys trims key cleanly");
    assert_eq!(written_rate["action_costs"].value, json!({ "upload": 5 }));

    // Writes to extension namespaces are rejected cleanly when core_config_contract is active
    let mut ext_write = BTreeMap::new();
    ext_write.insert(
        "issuer".to_string(),
        OptionUpdateInput {
            value: json!("https://other.example.com"),
            expected_revision: 1,
        },
    );
    let ext_err = write_options_batch(&pool, &registry, "identity.oidc", ext_write)
        .await
        .expect_err("non-core option write rejected");
    assert!(ext_err.to_string().contains("core_config_contract"));
}
