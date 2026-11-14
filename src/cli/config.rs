//! CLI arguments for `cfms-ctl config` and `cfms-ctl config options`.

use std::path::PathBuf;
use clap::{Args, Subcommand};

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigCommand {
    /// Losslessly merge new template settings from `config.toml.sample` into `config.toml`.
    SyncTemplate(ConfigSyncTemplateArgs),

    /// Generate and store a 32-byte hex `security.pepper` in `config.toml` when missing.
    FillPepper,

    /// Read and update namespaced database-backed business settings (`options` table).
    #[command(subcommand)]
    Options(OptionsCommand),
}

#[derive(Debug, Clone, Args)]
pub struct ConfigSyncTemplateArgs {
    /// Configuration template to merge into `config.toml` (defaults to `config.toml.sample`).
    #[arg(long = "template", value_name = "FILE")]
    pub template: Option<PathBuf>,

    /// Optional JSON Schema file to validate the merged configuration against (defaults to workspace `config.schema.json` if present).
    #[arg(long = "schema", value_name = "SCHEMA_FILE")]
    pub schema: Option<PathBuf>,

    /// Report whether synchronization is needed without modifying `config.toml` (exits 1 if dirty).
    #[arg(long = "check")]
    pub check: bool,

    /// Remove specific template-external dotted configuration paths (may be repeated).
    #[arg(long = "remove", value_name = "DOTTED_PATH", conflicts_with = "prune")]
    pub remove: Vec<String>,

    /// Remove all template-external configuration paths not present in the template.
    #[arg(long = "prune", conflicts_with = "remove")]
    pub prune: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum OptionsCommand {
    /// List stored database settings (optionally filtered by namespace).
    List(OptionsListArgs),

    /// Read a single stored setting and its revision without loading extension code.
    Get(OptionsGetArgs),

    /// Set a single option value from a JSON file using optimistic concurrency (`--expected-revision`).
    Set(OptionsSetArgs),

    /// Atomically update multiple keys in a namespace from a JSON file.
    SetMany(OptionsSetManyArgs),

    /// Reset a setting to its default value using its expected revision.
    Reset(OptionsResetArgs),
}

#[derive(Debug, Clone, Args)]
pub struct OptionsListArgs {
    /// Filter options by namespace (e.g. `security.password`).
    #[arg(long = "namespace")]
    pub namespace: Option<String>,

    /// Optional JSON Schema file for option definitions (defaults to workspace `options.schema.json` if present).
    #[arg(long = "schema", value_name = "SCHEMA_FILE")]
    pub schema: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct OptionsGetArgs {
    /// Option namespace (e.g. `server`).
    pub namespace: String,
    /// Option key (e.g. `name`).
    pub option_key: String,
    /// Optional JSON Schema file for option definitions (defaults to workspace `options.schema.json` if present).
    #[arg(long = "schema", value_name = "SCHEMA_FILE")]
    pub schema: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct OptionsSetArgs {
    /// Option namespace.
    pub namespace: String,
    /// Option key.
    pub option_key: String,
    /// Path to JSON file containing the new value.
    #[arg(value_name = "PAYLOAD_FILE")]
    pub payload_file: PathBuf,
    /// Expected current revision (0 creates a new entry).
    #[arg(long = "expected-revision")]
    pub expected_revision: u64,
    /// Optional JSON Schema file for option definitions (defaults to workspace `options.schema.json` if present).
    #[arg(long = "schema", value_name = "SCHEMA_FILE")]
    pub schema: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct OptionsSetManyArgs {
    /// Option namespace.
    pub namespace: String,
    /// Path to JSON file mapping `option_key -> { value, expected_revision }`.
    #[arg(value_name = "PAYLOAD_FILE")]
    pub payload_file: PathBuf,
    /// Optional JSON Schema file for option definitions (defaults to workspace `options.schema.json` if present).
    #[arg(long = "schema", value_name = "SCHEMA_FILE")]
    pub schema: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct OptionsResetArgs {
    /// Option namespace.
    pub namespace: String,
    /// Option key.
    pub option_key: String,
    /// Expected current revision.
    #[arg(long = "expected-revision")]
    pub expected_revision: u64,
    /// Optional JSON Schema file for option definitions (defaults to workspace `options.schema.json` if present).
    #[arg(long = "schema", value_name = "SCHEMA_FILE")]
    pub schema: Option<PathBuf>,
}
