//! Multi-mode codebase schema IR extractor.
//!
//! Coordinates pre-exported `schema.ir.json` discovery, the read-only Python
//! `Base.metadata` probe (`probes/extract_metadata.py`), and graceful fallback
//! to `static_ast` (`ruff_python_parser`) or the built-in 0.14.x contract.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::schema::ddl::builtin_schema_ir;
use crate::db::schema::ir::{ExtractionSource, SchemaIr};
use crate::db::schema::static_ast::{analyze_alembic_directory, extract_static_schema_ir};

/// Embedded read-only Python SQLAlchemy metadata probe.
pub const EXTRACT_METADATA_PY: &str = include_str!("probes/extract_metadata.py");

/// Default SQLAlchemy metadata entrypoint for CFMS servers.
pub const DEFAULT_MODELS_TARGET: &str = "include.database.session:Base";

const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Source strategy for extracting a [`SchemaIr`] from a codebase or artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ExtractorMode {
    /// Prefer `schema.ir.json` -> Python probe -> `ruff_python_parser` static AST.
    #[default]
    Auto,
    /// Require the Python `Base.metadata` runtime probe.
    Python,
    /// Force dependency-free static Python AST scanning via `ruff_python_parser`.
    Static,
    /// Require a pre-exported `schema.ir.json` artifact.
    Json,
    /// Use the built-in 0.14.x contract embedded in `cfms-ctl`.
    Builtin,
}

impl std::fmt::Display for ExtractorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Auto => "auto",
            Self::Python => "python",
            Self::Static => "static",
            Self::Json => "json",
            Self::Builtin => "builtin",
        };
        f.write_str(s)
    }
}

/// Discovered Python interpreter command candidate.
#[derive(Debug, Clone)]
pub struct PythonCandidate {
    pub program: PathBuf,
    pub prefix_args: Vec<String>,
    pub description: String,
}

/// Locate candidate Python environments suitable for running CFMS scripts or Alembic.
#[must_use]
pub fn discover_python_candidates(paths: &WorkspacePaths) -> Vec<PythonCandidate> {
    let mut candidates = Vec::new();
    let mut seen_programs: Vec<String> = Vec::new();

    let mut push_unique = |program: PathBuf, prefix_args: Vec<String>, description: String| {
        let key = format!("{}|{}", program.display(), prefix_args.join(" "));
        if !seen_programs.contains(&key) {
            seen_programs.push(key);
            candidates.push(PythonCandidate {
                program,
                prefix_args,
                description,
            });
        }
    };

    if let Ok(explicit) = std::env::var("CFMS_PYTHON")
        && !explicit.trim().is_empty()
    {
        let p = PathBuf::from(explicit.trim());
        if p.exists() || !p.is_absolute() {
            push_unique(
                p.clone(),
                Vec::new(),
                format!("CFMS_PYTHON ({})", p.display()),
            );
        }
    }

    for venv_root in [&paths.project_root, &paths.server_root] {
        let py_path = if cfg!(windows) {
            venv_root.join(".venv").join("Scripts").join("python.exe")
        } else {
            venv_root.join(".venv").join("bin").join("python")
        };
        if py_path.is_file() {
            push_unique(
                py_path.clone(),
                Vec::new(),
                format!("workspace venv ({})", py_path.display()),
            );
        }
    }

    let has_uv_project =
        paths.project_root.join("pyproject.toml").is_file() || paths.project_root.join("uv.lock").is_file();
    if has_uv_project {
        push_unique(
            PathBuf::from("uv"),
            vec![
                "run".to_string(),
                "--no-sync".to_string(),
                "--project".to_string(),
                paths.project_root.to_string_lossy().to_string(),
                "python".to_string(),
            ],
            "uv run --no-sync python".to_string(),
        );
    }

    for sys_py in ["python3", "python"] {
        push_unique(
            PathBuf::from(sys_py),
            Vec::new(),
            format!("system `{sys_py}`"),
        );
    }
    #[cfg(windows)]
    push_unique(
        PathBuf::from("py"),
        vec!["-3".to_string()],
        "Windows Python Launcher (`py -3`)".to_string(),
    );

    candidates
}

/// Run the read-only Python `Base.metadata` probe against `paths.server_root`.
pub async fn run_python_probe(
    paths: &WorkspacePaths,
    models_target: Option<&str>,
    include_extensions: bool,
) -> Result<SchemaIr> {
    let target = models_target.unwrap_or(DEFAULT_MODELS_TARGET);
    let candidates = discover_python_candidates(paths);
    if candidates.is_empty() {
        return Err(CfmsError::Database(
            "No Python interpreter candidate found to run metadata probe".to_string(),
        ));
    }

    let script_file = tempfile::Builder::new()
        .prefix("cfms_probe_")
        .suffix(".py")
        .tempfile()?;
    std::fs::write(script_file.path(), EXTRACT_METADATA_PY)?;

    let out_file = tempfile::Builder::new()
        .prefix("cfms_schema_ir_")
        .suffix(".json")
        .tempfile()?;

    let mut errors = Vec::new();
    for cand in &candidates {
        let mut cmd = Command::new(&cand.program);
        cmd.args(&cand.prefix_args);
        cmd.arg("-B")
            .arg(script_file.path())
            .arg("--server-root")
            .arg(&paths.server_root)
            .arg("--target")
            .arg(target)
            .arg("--out")
            .arg(out_file.path());
        if !include_extensions {
            cmd.arg("--no-extensions");
        }
        cmd.env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONUTF8", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                errors.push(format!("{}: spawn failed ({err})", cand.description));
                continue;
            }
        };

        let output = match tokio::time::timeout(PROBE_TIMEOUT, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(err)) => {
                errors.push(format!("{}: execution error ({err})", cand.description));
                continue;
            }
            Err(_) => {
                errors.push(format!(
                    "{}: timed out after {}s",
                    cand.description,
                    PROBE_TIMEOUT.as_secs()
                ));
                continue;
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let snippet: String = stderr.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | ");
            errors.push(format!(
                "{}: exited with {} ({snippet})",
                cand.description, output.status
            ));
            continue;
        }

        let json_text = std::fs::read_to_string(out_file.path())?;
        if json_text.trim().is_empty() {
            errors.push(format!(
                "{}: probe exited 0 but wrote empty IR output",
                cand.description
            ));
            continue;
        }

        let mut ir = SchemaIr::from_json_str(&json_text)?;
        if ir.schema_revision.is_none()
            && let Some(ap) = paths.discover_alembic_paths()
            && let Ok(analysis) = analyze_alembic_directory(&ap.versions_dir)
        {
            ir.schema_revision = analysis.single_head;
        }
        return Ok(ir);
    }

    Err(CfmsError::Database(format!(
        "Python metadata probe failed across all candidates: {}",
        errors.join("; ")
    )))
}

/// Load a pre-exported `schema.ir.json` file from disk.
pub fn load_schema_ir_file(path: &Path, include_extensions: bool) -> Result<SchemaIr> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!(
            "Failed to read Schema IR file '{}': {e}",
            path.display()
        ))
    })?;
    let mut ir = SchemaIr::from_json_str(&raw)?;
    ir.source = ExtractionSource::PrebuiltJson;
    if !include_extensions {
        ir = ir.with_extensions(false);
    }
    Ok(ir)
}

/// Extract a [`SchemaIr`] from `paths` using `mode`, falling back cleanly in `Auto` mode.
pub async fn extract_code_schema_ir(
    paths: &WorkspacePaths,
    mode: ExtractorMode,
    ir_json_override: Option<&Path>,
    models_target: Option<&str>,
    include_extensions: bool,
    fallback_to_builtin_when_empty: bool,
) -> Result<SchemaIr> {
    match mode {
        ExtractorMode::Builtin => Ok(builtin_schema_ir(include_extensions)),
        ExtractorMode::Json => {
            let Some(json_path) = paths.discover_schema_ir_path(ir_json_override)? else {
                return Err(CfmsError::Config(
                    "No schema.ir.json found in workspace (pass --ir or deploy schema.ir.json)"
                        .to_string(),
                ));
            };
            load_schema_ir_file(&json_path, include_extensions)
        }
        ExtractorMode::Python => run_python_probe(paths, models_target, include_extensions).await,
        ExtractorMode::Static => extract_static_schema_ir(paths, include_extensions),
        ExtractorMode::Auto => {
            if let Some(json_path) = paths.discover_schema_ir_path(ir_json_override)? {
                let mut ir = load_schema_ir_file(&json_path, include_extensions)?;
                if ir.schema_revision.is_none()
                    && let Some(ap) = paths.discover_alembic_paths()
                    && let Ok(analysis) = analyze_alembic_directory(&ap.versions_dir)
                {
                    ir.schema_revision = analysis.single_head;
                }
                return Ok(ir);
            }

            match run_python_probe(paths, models_target, include_extensions).await {
                Ok(ir) => Ok(ir),
                Err(probe_err) => {
                    let mut ir = extract_static_schema_ir(paths, include_extensions)?;
                    if ir.tables.is_empty() && fallback_to_builtin_when_empty {
                        let mut builtin = builtin_schema_ir(include_extensions);
                        builtin.warnings.push(format!(
                            "No workspace ORM models found and Python probe unavailable ({probe_err}); using built-in 0.14.x schema contract"
                        ));
                        return Ok(builtin);
                    }
                    ir.warnings.insert(
                        0,
                        format!(
                            "Python probe unavailable ({probe_err}); fell back to static ruff_python_parser AST scan"
                        ),
                    );
                    Ok(ir)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ddl::builtin_schema_ir;
    use crate::db::schema::diff::{DiffOptions, SchemaOp, diff_schemas};

    #[tokio::test]
    async fn cfms_on_websocket_probe_and_static_ast_parity_if_present() {
        let code_dir = std::path::Path::new(r"D:\projects\cfms_on_websocket\src");
        if !code_dir.is_dir() {
            return;
        }
        let paths = WorkspacePaths::from_code_dir(code_dir).expect("from_code_dir");

        // 1. Dependency-free static AST extraction must always discover the full CFMS model set.
        let static_ir =
            extract_code_schema_ir(&paths, ExtractorMode::Static, None, None, true, false)
                .await
                .expect("static AST extraction");
        assert!(
            static_ir.tables.len() >= 40,
            "expected >=40 tables from static AST scan, got {}",
            static_ir.tables.len()
        );
        assert_eq!(static_ir.schema_revision.as_deref(), Some("e952c02c1454"));

        // 2. If a working Python environment is present, verify live Base.metadata probe parity
        // against built-in 0.14.x contract without writing into the reference repository.
        if let Ok(probe_ir) =
            extract_code_schema_ir(&paths, ExtractorMode::Python, None, None, true, false).await
        {
            assert_eq!(probe_ir.schema_revision.as_deref(), Some("e952c02c1454"));
            let builtin = builtin_schema_ir(true);
            let plan = diff_schemas(
                &builtin,
                &probe_ir,
                &DiffOptions {
                    dialect: None,
                    include_extensions: false,
                    ..Default::default()
                },
            );
            let unexpected_core_drops: Vec<String> = plan
                .operations
                .iter()
                .filter_map(|op| match op {
                    SchemaOp::DropTable { table, .. } => {
                        Some(format!("drop table {}: {op:?}", table.name))
                    }
                    SchemaOp::DropColumn { table, column, .. } => {
                        Some(format!("drop column {table}.{}: {op:?}", column.name))
                    }
                    _ => None,
                })
                .collect();
            assert!(
                unexpected_core_drops.is_empty(),
                "probe vs builtin had unexpected table/column drops: {unexpected_core_drops:?}"
            );
        }
    }
}
