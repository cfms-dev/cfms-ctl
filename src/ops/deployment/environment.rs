//! Target Python compatibility verification (`pep440_rs`) and `uv` environment synchronization.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::core::{CfmsError, Result, WorkspacePaths};
use crate::db::schema::probe::discover_python_candidates;

use super::manifest::python_version_satisfies;
use super::models::DeploymentSettings;
use super::repository::{requirements_lock_path, validate_requirements_lock_file};

const UV_TIMEOUT: Duration = Duration::from_secs(300);
const PY_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct ResolvedEnvPlan {
    pub extras: Vec<String>,
    pub extras_changed: bool,
    pub extras_added: Vec<String>,
    pub extras_removed: Vec<String>,
    pub effective_requirements_lock: Option<PathBuf>,
    pub skip_env: bool,
}

/// Resolve effective `extras` and `requirements.lock` changes cleanly without mutating persisted state yet.
pub fn plan_environment_options(
    paths: &WorkspacePaths,
    current_settings: &DeploymentSettings,
    cli_extras: &[String],
    clear_extras: bool,
    cli_requirements_lock: Option<&Path>,
    clear_requirements_lock: bool,
    skip_env: bool,
) -> Result<ResolvedEnvPlan> {
    let resolved_extras: Vec<String> = if clear_extras {
        Vec::new()
    } else if !cli_extras.is_empty() {
        let mut set = BTreeSet::new();
        for extra in cli_extras {
            let trimmed = extra.trim();
            if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
                return Err(CfmsError::InvalidArgument(format!(
                    "Invalid --extra value '{extra}'"
                )));
            }
            set.insert(trimmed.to_string());
        }
        set.into_iter().collect()
    } else {
        current_settings.extras.clone()
    };

    let old_set: BTreeSet<&str> = current_settings.extras.iter().map(String::as_str).collect();
    let new_set: BTreeSet<&str> = resolved_extras.iter().map(String::as_str).collect();
    let extras_added: Vec<String> = new_set
        .difference(&old_set)
        .map(|s| (*s).to_string())
        .collect();
    let extras_removed: Vec<String> = old_set
        .difference(&new_set)
        .map(|s| (*s).to_string())
        .collect();
    let extras_changed = !extras_added.is_empty() || !extras_removed.is_empty();

    let effective_requirements_lock = if clear_requirements_lock {
        None
    } else if let Some(explicit) = cli_requirements_lock {
        validate_requirements_lock_file(explicit)?;
        Some(explicit.to_path_buf())
    } else {
        let persisted = requirements_lock_path(paths);
        if persisted.is_file() {
            validate_requirements_lock_file(&persisted)?;
            Some(persisted)
        } else {
            None
        }
    };

    Ok(ResolvedEnvPlan {
        extras: resolved_extras,
        extras_changed,
        extras_added,
        extras_removed,
        effective_requirements_lock,
        skip_env,
    })
}

/// Discover `uv` binary path (`CFMS_UV` env override or `uv` on `PATH`).
#[must_use]
pub fn resolve_uv_program() -> PathBuf {
    if let Ok(explicit) = std::env::var("CFMS_UV")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit.trim());
    }
    PathBuf::from("uv")
}

/// Probe the target deployment's Python version and check PEP 440 `requires_python` compatibility.
///
/// Unlike legacy Python tooling which checked the CLI's own host interpreter, this inspects the
/// target server `.venv` / `CFMS_PYTHON` / `uv python find` interpreter.
pub async fn check_target_python_compatibility(
    paths: &WorkspacePaths,
    requires_python: &str,
) -> Result<Option<String>> {
    let candidates = discover_python_candidates(paths);
    for candidate in candidates {
        let mut cmd = Command::new(&candidate.program);
        for arg in &candidate.prefix_args {
            cmd.arg(arg);
        }
        cmd.arg("-B")
            .arg("-c")
            .arg("import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Ok(Ok(child_out)) =
            tokio::time::timeout(PY_PROBE_TIMEOUT, cmd.output()).await
            && child_out.status.success()
        {
            let version_str = String::from_utf8_lossy(&child_out.stdout).trim().to_string();
            if !version_str.is_empty() {
                if !python_version_satisfies(requires_python, &version_str)? {
                    return Err(CfmsError::Deployment(format!(
                        "Target Python {} ({}) does not satisfy release requirement `requires-python = {}`",
                        version_str, candidate.description, requires_python
                    )));
                }
                return Ok(Some(version_str));
            }
        }
    }
    Ok(None)
}

/// Locate the project's virtual environment Python binary after `uv sync`.
#[must_use]
pub fn project_venv_python(paths: &WorkspacePaths) -> PathBuf {
    if cfg!(windows) {
        paths.project_root.join(".venv").join("Scripts").join("python.exe")
    } else {
        paths.project_root.join(".venv").join("bin").join("python")
    }
}

/// Synchronize `.venv` with `pyproject.toml` + `uv.lock` (`--locked --no-dev`) and install any
/// hash-locked extension dependencies from `requirements.lock`.
pub async fn sync_python_environment(
    paths: &WorkspacePaths,
    plan: &ResolvedEnvPlan,
) -> Result<()> {
    if plan.skip_env {
        return Ok(());
    }

    let uv_prog = resolve_uv_program();
    let mut args = vec![
        "sync".to_string(),
        "--project".to_string(),
        paths.project_root.display().to_string(),
        "--locked".to_string(),
        "--no-dev".to_string(),
    ];
    for extra in &plan.extras {
        args.push("--extra".to_string());
        args.push(extra.clone());
    }

    run_uv_command(&uv_prog, &paths.project_root, &args, "uv sync").await?;

    if let Some(ref lock_path) = plan.effective_requirements_lock {
        let content = fs::read_to_string(lock_path)?;
        if !content.trim().is_empty() {
            let venv_python = if project_venv_python(paths).is_file() {
                project_venv_python(paths)
            } else if let Some(first) = discover_python_candidates(paths).into_iter().next() {
                first.program
            } else {
                return Err(CfmsError::Deployment(format!(
                    "Cannot install requirements.lock '{}': target `.venv` Python binary missing after `uv sync`",
                    lock_path.display()
                )));
            };

            let pip_args = vec![
                "pip".to_string(),
                "install".to_string(),
                "--python".to_string(),
                venv_python.display().to_string(),
                "--requirements".to_string(),
                lock_path.display().to_string(),
                "--require-hashes".to_string(),
                "--strict".to_string(),
            ];
            run_uv_command(&uv_prog, &paths.project_root, &pip_args, "uv pip install").await?;
        }
    }

    Ok(())
}

async fn run_uv_command(
    uv_prog: &Path,
    cwd: &Path,
    args: &[String],
    label: &str,
) -> Result<()> {
    let mut cmd = Command::new(uv_prog);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn().map_err(|err| {
        CfmsError::Deployment(format!(
            "Failed to invoke `{label}` via '{}': {err}. Ensure `uv` is installed or pass `--skip-env`.",
            uv_prog.display()
        ))
    })?;

    let output = tokio::time::timeout(UV_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| CfmsError::Deployment(format!("`{label}` timed out after {}s", UV_TIMEOUT.as_secs())))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(CfmsError::Deployment(format!(
            "`{label}` failed with exit status {}: {}{}",
            output.status,
            stderr,
            if stdout.is_empty() {
                String::new()
            } else {
                format!(" | stdout: {stdout}")
            }
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use super::*;

    #[test]
    fn resolves_extras_diff_and_clear_flags() {
        let tmp = TempDir::new().unwrap();
        let paths = WorkspacePaths::for_target_project_root(tmp.path(), None);
        let saved = DeploymentSettings {
            format_version: 1,
            extras: vec!["mysql".to_string(), "redis".to_string()],
        };

        // Omitting CLI extras reuses saved settings cleanly.
        let reused = plan_environment_options(&paths, &saved, &[], false, None, false, false).unwrap();
        assert_eq!(reused.extras, vec!["mysql", "redis"]);
        assert!(!reused.extras_changed);

        // Passing --extra replaces saved extras cleanly and computes exact diff.
        let replaced = plan_environment_options(
            &paths,
            &saved,
            &["postgres".to_string(), "redis".to_string()],
            false,
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(replaced.extras, vec!["postgres", "redis"]);
        assert!(replaced.extras_changed);
        assert_eq!(replaced.extras_added, vec!["postgres"]);
        assert_eq!(replaced.extras_removed, vec!["mysql"]);

        // Clearing extras produces empty set cleanly.
        let cleared = plan_environment_options(&paths, &saved, &[], true, None, false, false).unwrap();
        assert!(cleared.extras.is_empty());
        assert_eq!(cleared.extras_removed, vec!["mysql", "redis"]);
    }
}
