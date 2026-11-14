//! Version parsing and compatibility evaluation for CFMS servers and extensions.
//!
//! Server compatibility (`[compatibility].minimum_server_version` /
//! `maximum_server_version`) uses the CFMS server version grammar
//! (`major.minor.patch[.build][_alpha|_beta|_rc|_release[num]]`), while extension
//! package versions and `[dependencies.extensions]` constraints use PEP 440 via `pep440_rs`.

use std::cmp::Ordering;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;
use pep440_rs::{Version as Pep440Version, VersionSpecifiers as Pep440Specifiers};
use regex::Regex;
use ruff_python_ast::{Expr, Stmt};
use ruff_python_parser::parse_module;
use serde::Serialize;
use crate::core::{CfmsError, Result, WorkspacePaths};

/// Release stage ordering matching CFMS `src/include/config/version.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionStage {
    Alpha = 0,
    Beta = 1,
    Rc = 2,
    Release = 3,
}

/// Parsed CFMS server version (`major.minor.patch[.build][_type[num]]`).
#[derive(Debug, Clone)]
pub struct CfmsServerVersion {
    original: String,
    major: u64,
    minor: u64,
    patch: u64,
    build: u64,
    stage: VersionStage,
    stage_num: u64,
}

impl CfmsServerVersion {
    /// Parse a CFMS version string such as `"0.14.0"` or `"0.4.1.260811_alpha"`.
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let captures = server_version_regex()
            .captures(trimmed)
            .ok_or_else(|| CfmsError::Extension(format!("Invalid CFMS server version '{raw}'")))?;

        let major = parse_u64(&captures[1], raw)?;
        let minor = parse_u64(&captures[2], raw)?;
        let patch = parse_u64(&captures[3], raw)?;
        let build = captures
            .get(4)
            .map_or(Ok(0), |m| parse_u64(m.as_str(), raw))?;

        let stage = match captures
            .get(5)
            .map(|m| m.as_str().to_ascii_lowercase())
            .as_deref()
        {
            None | Some("release") => VersionStage::Release,
            Some("alpha") => VersionStage::Alpha,
            Some("beta") => VersionStage::Beta,
            Some("rc") => VersionStage::Rc,
            Some(_) => {
                return Err(CfmsError::Extension(format!(
                    "Invalid CFMS server version '{raw}'"
                )));
            }
        };

        let stage_num = match captures.get(6) {
            Some(m) if !m.as_str().is_empty() => parse_u64(m.as_str(), raw)?,
            _ => 0,
        };

        Ok(Self {
            original: trimmed.to_string(),
            major,
            minor,
            patch,
            build,
            stage,
            stage_num,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    const fn cmp_key(&self) -> (u64, u64, u64, u64, VersionStage, u64) {
        (
            self.major,
            self.minor,
            self.patch,
            self.build,
            self.stage,
            self.stage_num,
        )
    }
}

impl PartialEq for CfmsServerVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_key() == other.cmp_key()
    }
}

impl Eq for CfmsServerVersion {}

impl PartialOrd for CfmsServerVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CfmsServerVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_key().cmp(&other.cmp_key())
    }
}

impl fmt::Display for CfmsServerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

/// Origin from which the target CFMS server version was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerVersionSource {
    CliOverride,
    ReleaseManifest,
    ConstantsAst,
    PyprojectToml,
}

impl ServerVersionSource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CliOverride => "--server-version",
            Self::ReleaseManifest => "release-manifest.json",
            Self::ConstantsAst => "include/config/constants.py",
            Self::PyprojectToml => "pyproject.toml",
        }
    }
}

/// Detected target CFMS server version paired with its discovery source.
#[derive(Debug, Clone)]
pub struct DetectedServerVersion {
    pub version: CfmsServerVersion,
    pub source: ServerVersionSource,
}

/// Discover the target CFMS server version without importing or running Python code.
///
/// Precedence:
/// 1. Explicit `cli_override` (`--server-version`)
/// 2. `<project_root>/release-manifest.json` (`"version"`)
/// 3. `<server_root>/include/config/constants.py` (`CORE_VERSION` via `ruff_python_parser`)
/// 4. `<project_root>/pyproject.toml` (`[project].version`)
pub fn discover_server_version(
    paths: &WorkspacePaths,
    cli_override: Option<&str>,
) -> Result<Option<DetectedServerVersion>> {
    if let Some(raw) = cli_override {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CfmsError::InvalidArgument(
                "--server-version cannot be empty".to_string(),
            ));
        }
        let version = CfmsServerVersion::parse(trimmed).map_err(|e| {
            CfmsError::InvalidArgument(format!("Invalid --server-version '{raw}': {e}"))
        })?;
        return Ok(Some(DetectedServerVersion {
            version,
            source: ServerVersionSource::CliOverride,
        }));
    }

    if let Some(version) = read_release_manifest_version(&paths.release_manifest_path)? {
        return Ok(Some(DetectedServerVersion {
            version,
            source: ServerVersionSource::ReleaseManifest,
        }));
    }

    let constants_path = paths
        .server_root
        .join("include")
        .join("config")
        .join("constants.py");
    if let Some(version) = read_constants_ast_version(&constants_path)? {
        return Ok(Some(DetectedServerVersion {
            version,
            source: ServerVersionSource::ConstantsAst,
        }));
    }

    let pyproject_path = paths.project_root.join("pyproject.toml");
    if let Some(version) = read_pyproject_version(&pyproject_path)? {
        return Ok(Some(DetectedServerVersion {
            version,
            source: ServerVersionSource::PyprojectToml,
        }));
    }

    Ok(None)
}

/// Check whether `server_version` falls within optional `[min, max]` server bounds.
pub fn check_server_compatibility(
    server_version: &CfmsServerVersion,
    minimum: Option<&CfmsServerVersion>,
    maximum: Option<&CfmsServerVersion>,
) -> std::result::Result<(), String> {
    if let Some(min) = minimum
        && server_version < min
    {
        return Err(format!(
            "requires server version {min} or newer; target server version is {server_version}"
        ));
    }
    if let Some(max) = maximum
        && server_version > max
    {
        return Err(format!(
            "supports server version up to {max}; target server version is {server_version}"
        ));
    }
    Ok(())
}

/// Parse a PEP 440 version string cleanly.
pub fn parse_pep440_version(raw: &str) -> Result<Pep440Version> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CfmsError::Extension("Empty PEP 440 version string".to_string()));
    }
    Pep440Version::from_str(trimmed)
        .map_err(|e| CfmsError::Extension(format!("Invalid PEP 440 version '{raw}': {e}")))
}

/// Version constraint declared under `[dependencies.extensions]`.
///
/// CFMS manifests specify bare version strings (e.g. `builtin = "0.14.0"`) meaning
/// minimum compatible version `>= 0.14.0`, and we also accept full PEP 440 specifier
/// sets (e.g. `>=1.0.0,<2.0`).
#[derive(Debug, Clone)]
pub enum DependencyConstraint {
    Minimum {
        raw: String,
        version: Pep440Version,
    },
    Specifiers {
        raw: String,
        specifiers: Pep440Specifiers,
    },
}

impl DependencyConstraint {
    /// Parse either a bare PEP 440 minimum version or a PEP 440 specifier list.
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CfmsError::Extension(
                "Dependency version requirement cannot be empty".to_string(),
            ));
        }

        if let Ok(version) = Pep440Version::from_str(trimmed) {
            return Ok(Self::Minimum {
                raw: trimmed.to_string(),
                version,
            });
        }

        let specifiers = Pep440Specifiers::from_str(trimmed).map_err(|e| {
            CfmsError::Extension(format!(
                "Invalid PEP 440 version requirement '{raw}': {e}"
            ))
        })?;
        if specifiers.is_empty() {
            return Err(CfmsError::Extension(format!(
                "Empty PEP 440 version requirement '{raw}'"
            )));
        }

        Ok(Self::Specifiers {
            raw: trimmed.to_string(),
            specifiers,
        })
    }

    #[must_use]
    pub fn matches(&self, installed: &Pep440Version) -> bool {
        match self {
            Self::Minimum { version, .. } => installed >= version,
            Self::Specifiers { specifiers, .. } => specifiers.contains(installed),
        }
    }

    #[must_use]
    pub fn raw(&self) -> &str {
        match self {
            Self::Minimum { raw, .. } | Self::Specifiers { raw, .. } => raw,
        }
    }

    #[must_use]
    pub fn requirement_summary(&self) -> String {
        match self {
            Self::Minimum { raw, .. } => format!("{raw} or newer"),
            Self::Specifiers { raw, .. } => format!("matching '{raw}'"),
        }
    }
}

fn server_version_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:_([a-zA-Z]+)(\d*))?$")
            .expect("valid CFMS version regex")
    })
}

fn parse_u64(digits: &str, full_input: &str) -> Result<u64> {
    digits.parse::<u64>().map_err(|_| {
        CfmsError::Extension(format!(
            "Numeric component overflow in CFMS server version '{full_input}'"
        ))
    })
}

fn read_release_manifest_version(path: &Path) -> Result<Option<CfmsServerVersion>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!("Unable to read '{}': {e}", path.display()))
    })?;
    let json: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        CfmsError::Config(format!("Invalid JSON in '{}': {e}", path.display()))
    })?;
    let Some(version_val) = json.get("version").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let trimmed = version_val.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    CfmsServerVersion::parse(trimmed)
        .map(Some)
        .map_err(|e| CfmsError::Config(format!("Invalid version in '{}': {e}", path.display())))
}

fn read_constants_ast_version(path: &Path) -> Result<Option<CfmsServerVersion>> {
    if !path.is_file() {
        return Ok(None);
    }
    let src = std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!("Unable to read '{}': {e}", path.display()))
    })?;
    let parsed = parse_module(&src).map_err(|e| {
        CfmsError::Config(format!("Unable to parse '{}': {e}", path.display()))
    })?;

    for stmt in &parsed.syntax().body {
        let value_expr = match stmt {
            Stmt::Assign(assign) if assign.targets.len() == 1 => {
                if is_ident(&assign.targets[0], "CORE_VERSION") {
                    Some(assign.value.as_ref())
                } else {
                    None
                }
            }
            Stmt::AnnAssign(ann) if is_ident(&ann.target, "CORE_VERSION") => {
                ann.value.as_deref()
            }
            _ => None,
        };

        if let Some(expr) = value_expr
            && let Some(raw_ver) = extract_core_version_literal(expr)
        {
            return CfmsServerVersion::parse(&raw_ver).map(Some).map_err(|e| {
                CfmsError::Config(format!(
                    "Invalid CORE_VERSION in '{}': {e}",
                    path.display()
                ))
            });
        }
    }

    Ok(None)
}

fn read_pyproject_version(path: &Path) -> Result<Option<CfmsServerVersion>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CfmsError::Config(format!("Unable to read '{}': {e}", path.display()))
    })?;
    let doc = raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
        CfmsError::Config(format!("Invalid TOML in '{}': {e}", path.display()))
    })?;
    let Some(version_str) = doc
        .get("project")
        .and_then(|p| p.as_table_like())
        .and_then(|t| t.get("version"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };
    let trimmed = version_str.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    CfmsServerVersion::parse(trimmed)
        .map(Some)
        .map_err(|e| CfmsError::Config(format!("Invalid project.version in '{}': {e}", path.display())))
}

fn is_ident(expr: &Expr, expected: &str) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == expected)
}

fn extract_core_version_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        Expr::Call(call) => {
            let is_version_ctor = match call.func.as_ref() {
                Expr::Name(name) => name.id.as_str() == "Version",
                Expr::Attribute(attr) => attr.attr.as_str() == "Version",
                _ => false,
            };
            if !is_version_ctor || call.arguments.args.len() != 1 || !call.arguments.keywords.is_empty() {
                return None;
            }
            match &call.arguments.args[0] {
                Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfms_server_version_ordering_matches_server_spec() {
        let alpha = CfmsServerVersion::parse("0.4.1.260811_alpha").expect("alpha");
        let beta = CfmsServerVersion::parse("0.4.1.260811_beta").expect("beta");
        let rc = CfmsServerVersion::parse("0.4.1.260811_rc1").expect("rc1");
        let release_plain = CfmsServerVersion::parse("0.4.1.260811").expect("plain");
        let release_explicit = CfmsServerVersion::parse("0.4.1.260811_release").expect("release");
        let release_1 = CfmsServerVersion::parse("0.4.1.260811_release1").expect("release1");
        let modern = CfmsServerVersion::parse("0.14.0").expect("modern");

        assert!(alpha < beta);
        assert!(beta < rc);
        assert!(rc < release_plain);
        assert_eq!(release_plain, release_explicit);
        assert!(release_explicit < release_1);
        assert!(release_1 < modern);
        assert!(CfmsServerVersion::parse("0.14").is_err());
        assert!(CfmsServerVersion::parse("0.14.0_nightly").is_err());
        assert!(CfmsServerVersion::parse("0.14.0_").is_err());
    }

    #[test]
    fn discovers_server_version_precedence_and_ast() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        let cfg_dir = src.join("include").join("config");
        std::fs::create_dir_all(&cfg_dir).expect("dirs");
        std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"cfms\"\nversion = \"0.12.0\"\n",
        )
        .expect("pyproject");

        let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");

        // Fallback to pyproject.toml
        let detected = discover_server_version(&paths, None)
            .expect("ok")
            .expect("pyproject");
        assert_eq!(detected.version.as_str(), "0.12.0");
        assert_eq!(detected.source, ServerVersionSource::PyprojectToml);

        // constants.py AST overrides pyproject.toml
        std::fs::write(
            cfg_dir.join("constants.py"),
            "from include.config.version import Version\nCORE_VERSION: Version = Version(\"0.14.0\")\n",
        )
        .expect("constants.py");
        let detected = discover_server_version(&paths, None)
            .expect("ok")
            .expect("constants");
        assert_eq!(detected.version.as_str(), "0.14.0");
        assert_eq!(detected.source, ServerVersionSource::ConstantsAst);

        // release-manifest.json overrides constants.py
        std::fs::write(
            dir.path().join("release-manifest.json"),
            r#"{"version": "0.15.1"}"#,
        )
        .expect("release-manifest");
        let detected = discover_server_version(&paths, None)
            .expect("ok")
            .expect("manifest");
        assert_eq!(detected.version.as_str(), "0.15.1");
        assert_eq!(detected.source, ServerVersionSource::ReleaseManifest);

        // CLI override beats everything
        let detected = discover_server_version(&paths, Some("0.16.0_rc2"))
            .expect("ok")
            .expect("cli");
        assert_eq!(detected.version.as_str(), "0.16.0_rc2");
        assert_eq!(detected.source, ServerVersionSource::CliOverride);
    }

    #[test]
    fn pep440_dependency_constraints_handle_minimum_and_specifiers() {
        let min_req = DependencyConstraint::parse("0.14.0").expect("min");
        let v_ok = parse_pep440_version("0.14.1").expect("v_ok");
        let v_pre = parse_pep440_version("0.14.0a1").expect("v_pre");
        assert!(min_req.matches(&v_ok));
        assert!(!min_req.matches(&v_pre));

        let range_req = DependencyConstraint::parse(">=1.0.0,<2.0").expect("range");
        assert!(range_req.matches(&parse_pep440_version("1.5.2").unwrap()));
        assert!(!range_req.matches(&parse_pep440_version("2.0.0").unwrap()));
        assert!(DependencyConstraint::parse("not_valid!!!").is_err());
    }
}
