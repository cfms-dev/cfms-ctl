//! Domain operation orchestrators and structured command reports.

pub mod audit;
pub mod backup;
pub mod config;
pub mod database;
pub mod deployment;
pub mod doctor;
pub mod extension;
pub mod permission;
pub mod user;

use crate::cli::{Cli, Commands, GlobalOpts};
use crate::core::{ConfigDocument, Result, RuntimeLock, ServerLockGuard, WorkspacePaths};
use crate::db::DbPool;
use crate::ui::UiConsole;

/// Execution context passed into domain operation handlers.
#[derive(Debug, Clone)]
pub struct AppContext {
    pub global: GlobalOpts,
    pub ui: UiConsole,
}

impl AppContext {
    #[must_use]
    pub const fn new(global: GlobalOpts, ui: UiConsole) -> Self {
        Self { global, ui }
    }

    /// Resolve workspace paths on demand without mutating process working directory.
    pub fn resolve_paths(&self) -> Result<WorkspacePaths> {
        WorkspacePaths::discover(self.global.root.as_deref(), self.global.config.as_deref())
    }

    /// Load `config.toml` from the resolved workspace using tolerant `toml_edit` parsing.
    pub fn load_config(&self, paths: &WorkspacePaths) -> Result<ConfigDocument> {
        ConfigDocument::load(&paths.config_path)
    }

    /// Connect to the configured database backend (`sqlite`, `mysql`, or `postgresql`).
    pub async fn connect_db(&self, paths: &WorkspacePaths) -> Result<DbPool> {
        let doc = self.load_config(paths)?;
        let db_cfg = doc.database_config()?;
        DbPool::connect(&db_cfg, paths).await
    }

    /// Acquire the exclusive stopped-server maintenance lock (`src/.maintenance/server.lock`).
    pub fn acquire_server_lock(
        &self,
        paths: &WorkspacePaths,
        allow_unfinished_deployment: bool,
    ) -> Result<ServerLockGuard> {
        RuntimeLock::acquire(paths, allow_unfinished_deployment)
    }
}

/// Top-level command dispatcher.
pub async fn execute(cli: Cli, ui: &UiConsole) -> Result<()> {
    let ctx = AppContext::new(cli.global, ui.clone());

    match cli.command {
        Commands::Doctor(args) => doctor::handle(&ctx, args).await,
        Commands::Deployment(cmd) => deployment::handle(&ctx, cmd).await,
        Commands::Database(cmd) => database::handle(&ctx, cmd).await,
        Commands::Backup(cmd) => backup::handle(&ctx, cmd).await,
        Commands::Config(cmd) => config::handle(&ctx, cmd).await,
        Commands::Extension(cmd) => extension::handle(&ctx, cmd).await,
        Commands::User(cmd) => user::handle(&ctx, cmd).await,
        Commands::Permission(cmd) => permission::handle(&ctx, cmd).await,
        Commands::Audit(cmd) => audit::handle(&ctx, cmd).await,
    }
}
