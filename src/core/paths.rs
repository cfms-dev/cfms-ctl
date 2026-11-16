//! Side-effect-free path resolution for CFMS deployments and server roots.
//!
//! Unlike the legacy Python `enter_server_root()` which mutated process state
//! via `os.chdir()`, `WorkspacePaths` resolves canonical paths purely as data.

use std::path::{Path, PathBuf};
use serde::Serialize;
use crate::core::error::{CfmsError, Result};

/// Located Alembic configuration and script directories in a CFMS server root.
#[derive(Debug, Clone, Serialize)]
pub struct AlembicPaths {
    pub ini_path: PathBuf,
    pub script_location: PathBuf,
    pub versions_dir: PathBuf,
}

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

    /// Construct a temporary [`WorkspacePaths`] rooted at a specific source or project checkout
    /// directory (used for comparing arbitrary `--from`/`--to` directories without requiring `config.toml`).
    pub fn from_code_dir(dir: &Path) -> Result<Self> {
        if !dir.is_dir() {
            return Err(CfmsError::WorkspaceNotFound(dir.to_path_buf()));
        }
        let clean = Self::canonicalize_clean(dir);
        let candidate_src = clean.join("src");
        if candidate_src.is_dir()
            && (Self::is_server_root(&candidate_src) || clean.join("pyproject.toml").is_file())
        {
            return Ok(Self::from_roots(clean, candidate_src, None));
        }
        let project_root = if clean.file_name().is_some_and(|n| n == "src") {
            clean.parent().map_or_else(|| clean.clone(), Path::to_path_buf)
        } else {
            clean.clone()
        };
        Ok(Self::from_roots(project_root, clean, None))
    }

    /// Construct [`WorkspacePaths`] for an explicit target `project_root` (even before CFMS files exist,
    /// such as during `cfms-ctl deployment install`).
    #[must_use]
    pub fn for_target_project_root(project_root: &Path, config_override: Option<&Path>) -> Self {
        let clean = Self::canonicalize_clean(project_root);
        let server_root = clean.join("src");
        Self::from_roots(clean, server_root, config_override)
    }

    fn is_server_root(candidate: &Path) -> bool {
        candidate.join("main.py").is_file()
            || candidate.join("config.toml").is_file()
            || candidate.join("config.toml.sample").is_file()
            || candidate.join("include").join("database").is_dir()
            || candidate.join("schema.ir.json").is_file()
            || candidate.join("alembic.ini").is_file()
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

    /// Ordered candidate locations checked when discovering named external schema/IR files.
    #[must_use]
    pub fn named_schema_candidates(&self, filename: &str) -> [PathBuf; 3] {
        [
            self.server_root.join(filename),
            self.server_root
                .join("include")
                .join("schemas")
                .join(filename),
            self.project_root.join("schemas").join(filename),
        ]
    }

    fn discover_named_schema_file(
        &self,
        filename: &str,
        label: &str,
        override_path: Option<&Path>,
    ) -> Result<Option<PathBuf>> {
        if let Some(explicit) = override_path {
            let resolved = self.resolve_file_override(explicit);
            if !resolved.is_file() {
                return Err(CfmsError::Config(format!(
                    "{label} file not found: '{}'",
                    resolved.display()
                )));
            }
            return Ok(Some(resolved));
        }

        Ok(self
            .named_schema_candidates(filename)
            .into_iter()
            .find(|p| p.is_file()))
    }

    /// Discover a pre-exported `schema.ir.json` file in the workspace or validate an explicit override.
    pub fn discover_schema_ir_path(
        &self,
        override_path: Option<&Path>,
    ) -> Result<Option<PathBuf>> {
        self.discover_named_schema_file("schema.ir.json", "Schema IR", override_path)
    }

    /// Discover Alembic configuration (`alembic.ini`) and `alembic/versions/` directory if present.
    #[must_use]
    pub fn discover_alembic_paths(&self) -> Option<AlembicPaths> {
        let roots = [&self.server_root, &self.project_root];
        for root in roots {
            let ini_path = root.join("alembic.ini");
            let script_location = root.join("alembic");
            let versions_dir = script_location.join("versions");
            if versions_dir.is_dir() && (ini_path.is_file() || script_location.join("env.py").is_file()) {
                return Some(AlembicPaths {
                    ini_path,
                    script_location,
                    versions_dir,
                });
            }
        }
        None
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

    #[test]
    fn discover_schema_ir_alembic_and_from_code_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("src");
        let alembic_versions = src.join("alembic").join("versions");
        let include_schemas = src.join("include").join("schemas");
        std::fs::create_dir_all(&alembic_versions).unwrap();
        std::fs::create_dir_all(&include_schemas).unwrap();
        std::fs::write(src.join("main.py"), "# cfms").unwrap();
        std::fs::write(src.join("alembic.ini"), "[alembic]\n").unwrap();
        std::fs::write(src.join("alembic").join("env.py"), "# env\n").unwrap();
        std::fs::write(include_schemas.join("schema.ir.json"), "{}").unwrap();

        // Notice `config.toml` is absent: `from_code_dir` still works cleanly.
        let code_paths = WorkspacePaths::from_code_dir(&src).expect("from_code_dir");
        assert_eq!(
            code_paths.server_root,
            WorkspacePaths::canonicalize_clean(&src)
        );
        let ir_path = code_paths
            .discover_schema_ir_path(None)
            .expect("discover ir")
            .expect("some schema.ir.json");
        assert_eq!(ir_path, WorkspacePaths::canonicalize_clean(&include_schemas.join("schema.ir.json")));

        let ap = code_paths.discover_alembic_paths().expect("alembic paths");
        assert_eq!(ap.ini_path, code_paths.server_root.join("alembic.ini"));
        assert_eq!(ap.versions_dir, code_paths.server_root.join("alembic").join("versions"));

        let missing = code_paths.discover_schema_ir_path(Some(Path::new("does-not-exist.json")));
        assert!(missing.is_err());
    }
}
