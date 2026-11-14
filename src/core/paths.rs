//! Side-effect-free path resolution for CFMS deployments and server roots.
//!
//! Unlike the legacy Python `enter_server_root()` which mutated process state
//! via `os.chdir()`, `WorkspacePaths` resolves canonical paths purely as data.

use std::path::{Path, PathBuf};
use serde::Serialize;
use crate::core::error::{CfmsError, Result};

/// Resolved directory layout for a target CFMS installation.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspacePaths {
    /// Top-level deployment / repository root (contains `pyproject.toml` or `release-manifest.json`).
    pub project_root: PathBuf,
    /// Server runtime root (`<project_root>/src`), containing `main.py` and `config.toml`.
    pub server_root: PathBuf,
    /// Maintenance state directory (`<server_root>/.maintenance`).
    pub maintenance_root: PathBuf,
    /// Active `config.toml` path.
    pub config_path: PathBuf,
    /// Sample configuration template path (`<server_root>/config.toml.sample`).
    pub config_template_path: PathBuf,
    /// Installed server extensions directory (`<server_root>/include/extensions`).
    pub extensions_root: PathBuf,
    /// Active release manifest path (`<project_root>/release-manifest.json`).
    pub release_manifest_path: PathBuf,
}

impl WorkspacePaths {
    /// Locate a CFMS installation starting from `start_dir` (or current directory)
    /// and optionally overriding `config_override`.
    pub fn discover(
        root_override: Option<&Path>,
        config_override: Option<&Path>,
    ) -> Result<Self> {
        let start = match root_override {
            Some(path) => Self::canonicalize_clean(path),
            None => Self::canonicalize_clean(&std::env::current_dir()?),
        };

        for ancestor in start.ancestors() {
            // Case 1: `ancestor` is `<project_root>` containing `src/main.py` or `src/.maintenance/transaction.json`
            let candidate_src = ancestor.join("src");
            if Self::is_server_root(&candidate_src) {
                return Ok(Self::from_roots(
                    ancestor.to_path_buf(),
                    candidate_src,
                    config_override,
                ));
            }

            // Case 2: `ancestor` is directly `<server_root>` (`src/`)
            if Self::is_server_root(ancestor) {
                let project_root = ancestor
                    .parent()
                    .map_or_else(|| ancestor.to_path_buf(), Path::to_path_buf);
                return Ok(Self::from_roots(
                    project_root,
                    ancestor.to_path_buf(),
                    config_override,
                ));
            }
        }

        Err(CfmsError::WorkspaceNotFound(start))
    }

    fn is_server_root(candidate: &Path) -> bool {
        candidate.join("main.py").is_file()
            || candidate.join("config.toml").is_file()
            || candidate.join("config.toml.sample").is_file()
            || candidate
                .join(".maintenance")
                .join("transaction.json")
                .is_file()
    }

    fn canonicalize_clean(path: &Path) -> PathBuf {
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        #[cfg(windows)]
        {
            if let Some(s) = canonical.to_str()
                && let Some(stripped) = s.strip_prefix(r"\\?\")
                && !stripped.starts_with(r"UNC\")
            {
                return PathBuf::from(stripped);
            }
        }
        canonical
    }

    fn from_roots(
        project_root: PathBuf,
        server_root: PathBuf,
        config_override: Option<&Path>,
    ) -> Self {
        let maintenance_root = server_root.join(".maintenance");
        let config_path = config_override.map_or_else(
            || server_root.join("config.toml"),
            |p| {
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    server_root.join(p)
                }
            },
        );
        let config_template_path = server_root.join("config.toml.sample");
        let extensions_root = server_root.join("include").join("extensions");
        let release_manifest_path = project_root.join("release-manifest.json");

        Self {
            project_root,
            server_root,
            maintenance_root,
            config_path,
            config_template_path,
            extensions_root,
            release_manifest_path,
        }
    }

    /// Path to `src/.maintenance/server.lock`.
    #[must_use]
    pub fn server_lock_path(&self) -> PathBuf {
        self.maintenance_root.join("server.lock")
    }

    /// Path to `src/.maintenance/transaction.json`.
    #[must_use]
    pub fn transaction_path(&self) -> PathBuf {
        self.maintenance_root.join("transaction.json")
    }

    /// Resolve a database file path relative to `server_root` (matching CFMS server semantics).
    #[must_use]
    pub fn resolve_sqlite_path(&self, raw_file: &str) -> PathBuf {
        let path = Path::new(raw_file);
        if raw_file == ":memory:" || path.is_absolute() {
            path.to_path_buf()
        } else {
            self.server_root.join(path)
        }
    }

    /// Resolve an explicit file path override, checking `server_root` for relative paths if needed.
    #[must_use]
    pub fn resolve_file_override(&self, explicit: &Path) -> PathBuf {
        if explicit.is_absolute() || explicit.is_file() {
            explicit.to_path_buf()
        } else {
            let candidate_in_server = self.server_root.join(explicit);
            if candidate_in_server.is_file() {
                candidate_in_server
            } else {
                explicit.to_path_buf()
            }
        }
    }

    /// Discover the external `config.schema.json` file in the workspace or validate an explicit override.
    pub fn discover_config_schema_path(
        &self,
        override_path: Option<&Path>,
    ) -> Result<Option<PathBuf>> {
        if let Some(explicit) = override_path {
            let resolved = self.resolve_file_override(explicit);
            if !resolved.is_file() {
                return Err(CfmsError::Config(format!(
                    "Configuration schema file not found: '{}'",
                    resolved.display()
                )));
            }
            return Ok(Some(resolved));
        }

        let candidates = [
            self.server_root.join("config.schema.json"),
            self.server_root
                .join("include")
                .join("schemas")
                .join("config.schema.json"),
            self.project_root.join("schemas").join("config.schema.json"),
        ];
        Ok(candidates.into_iter().find(|p| p.is_file()))
    }

    /// Discover the external `options.schema.json` file in the workspace or validate an explicit override.
    pub fn discover_options_schema_path(
        &self,
        override_path: Option<&Path>,
    ) -> Result<Option<PathBuf>> {
        if let Some(explicit) = override_path {
            let resolved = self.resolve_file_override(explicit);
            if !resolved.is_file() {
                return Err(CfmsError::Config(format!(
                    "Options schema file not found: '{}'",
                    resolved.display()
                )));
            }
            return Ok(Some(resolved));
        }

        let candidates = [
            self.server_root.join("options.schema.json"),
            self.server_root
                .join("include")
                .join("schemas")
                .join("options.schema.json"),
            self.project_root
                .join("schemas")
                .join("options.schema.json"),
        ];
        Ok(candidates.into_iter().find(|p| p.is_file()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_from_project_root_and_src() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("src");
        std::fs::create_dir_all(&src).expect("create src");
        std::fs::write(src.join("main.py"), "# cfms").expect("write main.py");
        std::fs::write(src.join("config.toml"), "[database]\ntype = \"sqlite\"\nfile = \"app.db\"\n")
            .expect("write config.toml");

        let from_root = WorkspacePaths::discover(Some(temp.path()), None).expect("discover root");
        assert_eq!(
            from_root.server_root,
            WorkspacePaths::canonicalize_clean(&src)
        );

        let from_src = WorkspacePaths::discover(Some(&src), None).expect("discover src");
        assert_eq!(from_src.project_root, from_root.project_root);
        assert_eq!(
            from_src.resolve_sqlite_path("app.db"),
            from_src.server_root.join("app.db")
        );
    }
}
