//! Manifest parsing, layout verification, path hygiene, and PEP 440 `requires-python` checks.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::str::FromStr;

use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
use sha2::{Digest, Sha256};

use crate::core::{
    CfmsError, Result, WorkspacePaths, is_symlink_or_reparse_point, is_windows_reserved_name,
};
use crate::ops::extension::version::CfmsServerVersion;

use super::models::{
    MAX_MANIFEST_BYTES, OPERATOR_OWNED_PREFIXES, PRESERVED_WORKSPACE_PREFIXES,
    RELEASE_MANIFEST_FORMAT_VERSION, RELEASE_PRODUCT_NAME, REQUIRED_RELEASE_FILES,
    ReleaseManifest, ValidatedManifest,
};

/// Compute lowercase hexadecimal SHA-256 digest of a byte buffer.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Stream a regular file in 64 KiB blocks and return its lowercase SHA-256 hex digest and byte length.
pub fn hash_file_sha256(path: &Path) -> Result<(String, u64)> {
    let meta = fs::symlink_metadata(path)?;
    if is_symlink_or_reparse_point(&meta) {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Refusing to hash symlink or junction file '{}'",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Expected regular file at '{}'",
            path.display()
        )));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Verify that a string is a normalized 64-character lowercase hexadecimal SHA-256 digest.
pub fn validate_sha256_hex(raw: &str, context: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Invalid SHA-256 digest in {context}: expected 64 hex characters, got '{raw}'"
        )));
    }
    Ok(normalized)
}

/// Validate and normalize a manifest member path (POSIX `/` separators, relative, non-operator-owned).
pub fn validate_manifest_rel_path(raw: &str) -> Result<String> {
    if raw.is_empty()
        || raw.contains('\\')
        || raw.contains('\0')
        || raw.starts_with('/')
        || raw.ends_with('/')
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest contains invalid relative path '{raw}'"
        )));
    }

    let mut clean = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.ends_with(' ')
            || seg.ends_with('.')
            || is_windows_reserved_name(seg)
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Manifest contains unsafe path segment '{seg}' in '{raw}'"
            )));
        }
        if seg == "__pycache__" {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Manifest contains forbidden Python bytecode directory in '{raw}'"
            )));
        }
        clean.push(seg);
    }

    if raw.ends_with(".pyc") || raw.ends_with(".pyo") {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest contains forbidden compiled bytecode file '{raw}'"
        )));
    }
    if clean.first().copied() == Some(".git") || clean.first().copied() == Some(".venv") {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest contains forbidden workspace-internal path '{raw}'"
        )));
    }
    for prefix in OPERATOR_OWNED_PREFIXES {
        if raw.starts_with(prefix) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Manifest attempts to manage operator-owned path '{raw}'"
            )));
        }
    }

    Ok(clean.join("/"))
}

/// Parse raw `release-manifest.json` bytes, validate schema/hygiene constraints, and compute `release_id`.
pub fn parse_and_validate_manifest_bytes(
    raw_bytes: &[u8],
    source_desc: &str,
) -> Result<ValidatedManifest> {
    if raw_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest '{source_desc}' exceeds {MAX_MANIFEST_BYTES}-byte limit"
        )));
    }

    let manifest: ReleaseManifest = serde_json::from_slice(raw_bytes).map_err(|err| {
        CfmsError::ArchiveIntegrity(format!("Invalid release manifest '{source_desc}': {err}"))
    })?;

    if manifest.format_version != RELEASE_MANIFEST_FORMAT_VERSION {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Unsupported release manifest format_version {} in '{source_desc}' (expected {RELEASE_MANIFEST_FORMAT_VERSION})",
            manifest.format_version
        )));
    }
    if manifest.product != RELEASE_PRODUCT_NAME {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Unexpected release manifest product '{}' in '{source_desc}' (expected '{RELEASE_PRODUCT_NAME}')",
            manifest.product
        )));
    }
    CfmsServerVersion::parse(&manifest.version).map_err(|err| {
        CfmsError::ArchiveIntegrity(format!(
            "Invalid CFMS server version '{}' in '{source_desc}': {err}",
            manifest.version
        ))
    })?;

    if manifest.requires_python.trim().is_empty() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest '{source_desc}' must declare a non-empty `requires_python` constraint"
        )));
    }
    VersionSpecifiers::from_str(manifest.requires_python.trim()).map_err(|err| {
        CfmsError::ArchiveIntegrity(format!(
            "Invalid `requires_python` specifier '{}' in '{source_desc}': {err}",
            manifest.requires_python
        ))
    })?;

    if !manifest.managed_extensions.iter().any(|ext| ext == "builtin") {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest '{source_desc}' `managed_extensions` must contain 'builtin'"
        )));
    }
    for ext in &manifest.managed_extensions {
        if ext.is_empty() || !ext.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Invalid managed extension identifier '{ext}' in '{source_desc}'"
            )));
        }
    }

    if manifest.files.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest '{source_desc}' contains an empty file list"
        )));
    }

    let mut seen_lower = BTreeSet::new();
    let mut normalized_files = std::collections::BTreeMap::new();
    for (raw_path, raw_hash) in &manifest.files {
        let clean = validate_manifest_rel_path(raw_path)?;
        let lower = clean.to_ascii_lowercase();
        if !seen_lower.insert(lower) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Manifest '{source_desc}' has case-colliding path '{clean}'"
            )));
        }
        let hex = validate_sha256_hex(raw_hash, source_desc)?;
        normalized_files.insert(clean, hex);
    }

    for required in REQUIRED_RELEASE_FILES {
        if !normalized_files.contains_key(*required) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Manifest '{source_desc}' is missing required CFMS file '{required}'"
            )));
        }
    }

    let release_id = sha256_hex(raw_bytes);
    let mut validated_manifest = manifest;
    validated_manifest.files = normalized_files;

    Ok(ValidatedManifest {
        release_id,
        raw_bytes: raw_bytes.to_vec(),
        manifest: validated_manifest,
    })
}

/// Read and validate `<manifest_path>` from disk safely without following symlinks.
pub fn load_manifest_file(manifest_path: &Path) -> Result<ValidatedManifest> {
    let meta = fs::symlink_metadata(manifest_path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            CfmsError::Deployment(format!(
                "Release manifest not found at '{}'",
                manifest_path.display()
            ))
        } else {
            CfmsError::Io(err)
        }
    })?;
    if is_symlink_or_reparse_point(&meta) || !meta.is_file() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release manifest '{}' must be a regular file (not a symlink or directory)",
            manifest_path.display()
        )));
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release manifest '{}' exceeds {MAX_MANIFEST_BYTES}-byte limit",
            manifest_path.display()
        )));
    }
    let bytes = fs::read(manifest_path)?;
    parse_and_validate_manifest_bytes(&bytes, &manifest_path.display().to_string())
}

/// Reject `.git` developer checkouts and obsolete multi-release (`deployment.json`/`shared`/`releases`) trees.
pub fn validate_workspace_layout(paths: &WorkspacePaths, require_manifest: bool) -> Result<()> {
    let project_meta = fs::symlink_metadata(&paths.project_root)?;
    if is_symlink_or_reparse_point(&project_meta) || !project_meta.is_dir() {
        return Err(CfmsError::Deployment(format!(
            "Deployment root '{}' must be a real directory",
            paths.project_root.display()
        )));
    }
    let git_path = paths.project_root.join(".git");
    if fs::symlink_metadata(&git_path).is_ok() {
        return Err(CfmsError::Deployment(format!(
            "Git working tree detected at '{}'; `cfms-ctl deployment` operates only on packaged deployments",
            paths.project_root.display()
        )));
    }
    for legacy_entry in ["deployment.json", "shared", "releases"] {
        if fs::symlink_metadata(paths.project_root.join(legacy_entry)).is_ok() {
            return Err(CfmsError::Deployment(format!(
                "Legacy multi-release directory marker '{}' found under '{}'; flat layout is required",
                legacy_entry,
                paths.project_root.display()
            )));
        }
    }

    if require_manifest && !paths.release_manifest_path.exists() {
        return Err(CfmsError::Deployment(format!(
            "Missing '{}' under '{}'; run `cfms-ctl deployment adopt` if this is a manually unpacked archive",
            super::models::RELEASE_MANIFEST_FILENAME,
            paths.project_root.display()
        )));
    }
    Ok(())
}

/// Return true if a relative POSIX path inside `project_root` is preserved operator/state data
/// that release upgrades and rollbacks must never delete or overwrite directly.
#[must_use]
pub fn is_preserved_workspace_path(
    rel_posix: &str,
    managed_extensions: &BTreeSet<String>,
) -> bool {
    if rel_posix == "src/config.toml"
        || rel_posix.starts_with("src/config.toml.backup-")
        || rel_posix == ".python-version"
    {
        return true;
    }
    for prefix in PRESERVED_WORKSPACE_PREFIXES {
        if rel_posix.starts_with(prefix) || rel_posix == prefix.trim_end_matches('/') {
            return true;
        }
    }
    if let Some(rest) = rel_posix.strip_prefix("src/include/extensions/")
        && let Some(ext_id) = rest.split('/').next()
        && !ext_id.is_empty()
        && !ext_id.starts_with('.')
        && ext_id != "__pycache__"
        && ext_id != "__init__.py"
        && !managed_extensions.contains(ext_id)
    {
        return true;
    }
    false
}

/// Evaluate whether `python_version` (e.g. `"3.15.0"`) satisfies `requires_python` (e.g. `">=3.14"`).
pub fn python_version_satisfies(requires_python: &str, python_version: &str) -> Result<bool> {
    let spec = VersionSpecifiers::from_str(requires_python.trim()).map_err(|err| {
        CfmsError::Deployment(format!(
            "Invalid requires_python specifier '{requires_python}': {err}"
        ))
    })?;
    let ver = Pep440Version::from_str(python_version.trim()).map_err(|err| {
        CfmsError::Deployment(format!(
            "Invalid Python version '{python_version}': {err}"
        ))
    })?;
    Ok(spec.contains(&ver))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use super::*;

    pub(crate) fn minimal_valid_manifest_bytes(version: &str, main_bytes: &[u8]) -> Vec<u8> {
        let mut files = BTreeMap::new();
        for req in REQUIRED_RELEASE_FILES {
            let hash = if *req == "src/main.py" {
                sha256_hex(main_bytes)
            } else {
                sha256_hex(format!("content-for-{req}").as_bytes())
            };
            files.insert((*req).to_string(), hash);
        }
        let manifest = ReleaseManifest {
            format_version: 1,
            product: RELEASE_PRODUCT_NAME.to_string(),
            version: version.to_string(),
            requires_python: ">=3.14".to_string(),
            managed_extensions: vec!["builtin".to_string()],
            files,
        };
        serde_json::to_vec_pretty(&manifest).unwrap()
    }

    #[test]
    fn parses_valid_manifest_and_deterministically_hashes_release_id() {
        let raw = minimal_valid_manifest_bytes("0.15.0", b"print('hi')\n");
        let parsed = parse_and_validate_manifest_bytes(&raw, "test").unwrap();
        assert_eq!(parsed.release_id, sha256_hex(&raw));
        assert_eq!(parsed.manifest.version, "0.15.0");
    }

    #[test]
    fn rejects_operator_owned_and_reserved_paths_in_manifest() {
        for bad in [
            "src/.maintenance/settings.json",
            "src/content/files/blob",
            "src/__pycache__/main.cpython-315.pyc",
            "src/COM1.py",
            "../outside.py",
            ".venv/bin/python",
        ] {
            assert!(validate_manifest_rel_path(bad).is_err(), "expected error for {bad}");
        }
    }

    #[test]
    fn validates_requires_python_with_pep440_rs() {
        assert!(python_version_satisfies(">=3.14", "3.15.0").unwrap());
        assert!(!python_version_satisfies(">=3.14,<3.15", "3.15.1").unwrap());
    }

    #[test]
    fn preserves_third_party_extensions_and_operator_directories() {
        let managed: BTreeSet<String> = ["builtin", "oidc_sso"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert!(is_preserved_workspace_path("src/config.toml", &managed));
        assert!(is_preserved_workspace_path("src/config.toml.backup-2026", &managed));
        assert!(is_preserved_workspace_path("src/include/extensions/custom_ext/_extension.py", &managed));
        assert!(!is_preserved_workspace_path("src/include/extensions/oidc_sso/_extension.py", &managed));
        assert!(!is_preserved_workspace_path("src/include/extensions/builtin/_extension.py", &managed));
    }

    #[test]
    fn rejects_git_checkout_and_legacy_layout() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(tmp.path().join("src/main.py"), "x").unwrap();
        let paths = WorkspacePaths::for_target_project_root(tmp.path(), None);

        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        assert!(validate_workspace_layout(&paths, false).is_err());
        std::fs::remove_dir(tmp.path().join(".git")).unwrap();

        std::fs::write(tmp.path().join("deployment.json"), "{}").unwrap();
        assert!(validate_workspace_layout(&paths, false).is_err());
    }
}
