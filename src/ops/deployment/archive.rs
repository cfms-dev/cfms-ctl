//! Safe archive inspection, checksum verification, and bounded staging extraction
//! for `.zip` and `.tar.gz`/`.tgz` CFMS release bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::{Archive as TarArchive, EntryType};
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::read::ZipArchive;

use crate::core::{
    CfmsError, Result, ensure_safe_directory_chain, is_symlink_or_reparse_point,
    is_windows_reserved_name,
};

use super::manifest::{
    hash_file_sha256, parse_and_validate_manifest_bytes, validate_manifest_rel_path,
    validate_sha256_hex,
};
use super::models::{
    ChecksumVerificationInfo, MAX_ARCHIVE_MEMBERS, MAX_CHECKSUM_BYTES, MAX_PACKAGE_BYTES,
    MAX_UNCOMPRESSED_BYTES, RELEASE_MANIFEST_FILENAME, ValidatedManifest,
};

/// Verified and staged CFMS release extracted under an isolated temporary or maintenance staging directory.
#[derive(Debug)]
pub struct StagedRelease {
    pub archive_path: PathBuf,
    pub checksum: ChecksumVerificationInfo,
    pub manifest: ValidatedManifest,
    pub extracted_dir: PathBuf,
    _temp_guard: Option<TempDir>,
}

/// Parse a `SHA256SUMS.txt` or `<archive>.sha256` file and locate the expected digest for `target_filename`.
pub fn parse_checksum_file_for_asset(
    checksums_path: &Path,
    target_filename: &str,
) -> Result<Option<String>> {
    let meta = fs::symlink_metadata(checksums_path)?;
    if is_symlink_or_reparse_point(&meta) || !meta.is_file() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Checksum file '{}' must be a regular file",
            checksums_path.display()
        )));
    }
    if meta.len() > MAX_CHECKSUM_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Checksum file '{}' exceeds {MAX_CHECKSUM_BYTES}-byte limit",
            checksums_path.display()
        )));
    }

    let raw = fs::read_to_string(checksums_path).map_err(|err| {
        CfmsError::ArchiveIntegrity(format!(
            "Unable to read checksum file '{}' as UTF-8: {err}",
            checksums_path.display()
        ))
    })?;

    let mut non_empty_lines = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        non_empty_lines.push(trimmed);
    }

    if non_empty_lines.len() == 1
        && non_empty_lines[0].len() == 64
        && non_empty_lines[0].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(Some(non_empty_lines[0].to_ascii_lowercase()));
    }

    let mut matched_digest: Option<String> = None;
    for line in non_empty_lines {
        // Handle BSD-style: `SHA256 (filename) = <hex>`
        if let Some(rest) = line.strip_prefix("SHA256 (")
            && let Some((name_part, hex_part)) = rest.split_once(") = ")
        {
            let clean_name = normalize_checksum_target_name(name_part);
            if clean_name == target_filename {
                let hex = validate_sha256_hex(hex_part, &checksums_path.display().to_string())?;
                record_unique_digest(&mut matched_digest, hex, checksums_path, target_filename)?;
            }
            continue;
        }

        // Standard GNU sha256sum lines: `<hex>  <filename>` or `<hex> *<filename>`
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex_token = parts.next().unwrap_or("");
        let rest_token = parts.next().unwrap_or("").trim_start();
        if hex_token.len() == 64 && !rest_token.is_empty() {
            let asset_name = rest_token.strip_prefix('*').unwrap_or(rest_token);
            let clean_name = normalize_checksum_target_name(asset_name);
            if clean_name == target_filename {
                let hex = validate_sha256_hex(hex_token, &checksums_path.display().to_string())?;
                record_unique_digest(&mut matched_digest, hex, checksums_path, target_filename)?;
            }
        }
    }

    Ok(matched_digest)
}

fn normalize_checksum_target_name(raw: &str) -> &str {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed)
}

fn record_unique_digest(
    slot: &mut Option<String>,
    digest: String,
    path: &Path,
    asset: &str,
) -> Result<()> {
    if let Some(existing) = slot
        && existing != &digest
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Conflicting SHA-256 entries for '{asset}' inside '{}'",
            path.display()
        )));
    }
    *slot = Some(digest);
    Ok(())
}

/// Verify package size + SHA-256 digest against optional `--sha256`, `--checksums`, or sibling checksum files.
///
/// When operators provide a local archive without an external checksum file or `--sha256`, this
/// still computes and reports the archive SHA-256 and delegates full integrity enforcement to the
/// internal `release-manifest.json` hash verification during staging.
pub fn verify_package_checksum(
    package_path: &Path,
    explicit_sha256: Option<&str>,
    explicit_checksums: Option<&Path>,
) -> Result<ChecksumVerificationInfo> {
    verify_package_checksum_with_source(package_path, explicit_sha256, None, explicit_checksums)
}

/// Variant of [`verify_package_checksum`] allowing callers (such as online GitHub updates) to
/// supply a custom provenance label when passing an already-verified explicit SHA-256 digest.
pub fn verify_package_checksum_with_source(
    package_path: &Path,
    explicit_sha256: Option<&str>,
    explicit_sha256_source: Option<&str>,
    explicit_checksums: Option<&Path>,
) -> Result<ChecksumVerificationInfo> {
    let meta = fs::symlink_metadata(package_path)?;
    if is_symlink_or_reparse_point(&meta) || !meta.is_file() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release package '{}' must be a regular file",
            package_path.display()
        )));
    }
    if meta.len() > MAX_PACKAGE_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release package '{}' ({} bytes) exceeds the {MAX_PACKAGE_BYTES}-byte limit",
            package_path.display(),
            meta.len()
        )));
    }

    let (actual_sha256, package_bytes) = hash_file_sha256(package_path)?;
    let asset_name = package_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            CfmsError::InvalidArgument(format!(
                "Invalid release package filename '{}'",
                package_path.display()
            ))
        })?;

    if let Some(raw_expected) = explicit_sha256 {
        let expected = validate_sha256_hex(raw_expected, "--sha256")?;
        if actual_sha256 != expected {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "SHA-256 mismatch for '{}': expected {expected}, actual {actual_sha256}",
                package_path.display()
            )));
        }
        return Ok(ChecksumVerificationInfo {
            package_sha256: actual_sha256,
            package_bytes,
            source: explicit_sha256_source.unwrap_or("cli:--sha256").to_string(),
            verified_against_external: true,
        });
    }

    if let Some(checksums_path) = explicit_checksums {
        let expected = parse_checksum_file_for_asset(checksums_path, asset_name)?.ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "No entry for '{asset_name}' found in checksum file '{}'",
                checksums_path.display()
            ))
        })?;
        if actual_sha256 != expected {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "SHA-256 mismatch for '{}' against '{}': expected {expected}, actual {actual_sha256}",
                package_path.display(),
                checksums_path.display()
            )));
        }
        return Ok(ChecksumVerificationInfo {
            package_sha256: actual_sha256,
            package_bytes,
            source: format!("cli:--checksums ({})", checksums_path.display()),
            verified_against_external: true,
        });
    }

    // Best-effort sibling discovery: `<package>.sha256`, then `SHA256SUMS.txt` / `sha256.sum`.
    let sibling_per_file = PathBuf::from(format!("{}.sha256", package_path.display()));
    if sibling_per_file.is_file()
        && let Some(expected) = parse_checksum_file_for_asset(&sibling_per_file, asset_name)?
    {
        if actual_sha256 != expected {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "SHA-256 mismatch for '{}' against sibling '{}': expected {expected}, actual {actual_sha256}",
                package_path.display(),
                sibling_per_file.display()
            )));
        }
        return Ok(ChecksumVerificationInfo {
            package_sha256: actual_sha256,
            package_bytes,
            source: format!("sibling:{}", sibling_per_file.display()),
            verified_against_external: true,
        });
    }

    if let Some(parent) = package_path.parent() {
        for candidate_name in ["SHA256SUMS.txt", "sha256.sum"] {
            let candidate = parent.join(candidate_name);
            if candidate.is_file()
                && let Some(expected) = parse_checksum_file_for_asset(&candidate, asset_name)?
            {
                if actual_sha256 != expected {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "SHA-256 mismatch for '{}' against sibling '{}': expected {expected}, actual {actual_sha256}",
                        package_path.display(),
                        candidate.display()
                    )));
                }
                return Ok(ChecksumVerificationInfo {
                    package_sha256: actual_sha256,
                    package_bytes,
                    source: format!("sibling:{}", candidate.display()),
                    verified_against_external: true,
                });
            }
        }
    }

    Ok(ChecksumVerificationInfo {
        package_sha256: actual_sha256,
        package_bytes,
        source: "internal release-manifest.json (no external archive checksum provided)".to_string(),
        verified_against_external: false,
    })
}

/// Extract and cryptographically verify a `.zip`, `.tar.gz`, or `.tgz` release bundle into an isolated
/// staging directory (inside `staging_parent` if supplied, or a temporary directory if `None`).
pub fn stage_release_archive(
    package_path: &Path,
    explicit_sha256: Option<&str>,
    explicit_checksums: Option<&Path>,
    staging_parent: Option<&Path>,
) -> Result<StagedRelease> {
    stage_release_archive_with_source(
        package_path,
        explicit_sha256,
        None,
        explicit_checksums,
        staging_parent,
    )
}

/// Variant of [`stage_release_archive`] allowing callers to supply a custom checksum source label.
pub fn stage_release_archive_with_source(
    package_path: &Path,
    explicit_sha256: Option<&str>,
    explicit_sha256_source: Option<&str>,
    explicit_checksums: Option<&Path>,
    staging_parent: Option<&Path>,
) -> Result<StagedRelease> {
    let checksum = verify_package_checksum_with_source(
        package_path,
        explicit_sha256,
        explicit_sha256_source,
        explicit_checksums,
    )?;

    let (temp_guard, extracted_dir) = if let Some(parent) = staging_parent {
        fs::create_dir_all(parent)?;
        let meta = fs::symlink_metadata(parent)?;
        if is_symlink_or_reparse_point(&meta) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Staging directory '{}' cannot be a symlink or junction",
                parent.display()
            )));
        }
        let guard = tempfile::Builder::new()
            .prefix(".stage-")
            .tempdir_in(parent)?;
        let release_dir = guard.path().join("release");
        fs::create_dir_all(&release_dir)?;
        (guard, release_dir)
    } else {
        let guard = tempfile::Builder::new().prefix("cfms-stage-").tempdir()?;
        let release_dir = guard.path().join("release");
        fs::create_dir_all(&release_dir)?;
        (guard, release_dir)
    };

    let raw_extracted = match detect_archive_kind(package_path)? {
        ArchiveKind::Zip => extract_zip_raw_entries(package_path, &extracted_dir)?,
        ArchiveKind::TarGz => extract_targz_raw_entries(package_path, &extracted_dir)?,
    };

    normalize_top_level_prefix(&extracted_dir, &raw_extracted)?;
    let validated_manifest = verify_staged_release_tree(&extracted_dir)?;

    Ok(StagedRelease {
        archive_path: package_path.to_path_buf(),
        checksum,
        manifest: validated_manifest,
        extracted_dir,
        _temp_guard: Some(temp_guard),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Zip,
    TarGz,
}

fn detect_archive_kind(path: &Path) -> Result<ArchiveKind> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if name.ends_with(".zip") {
        Ok(ArchiveKind::Zip)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Ok(ArchiveKind::TarGz)
    } else {
        Err(CfmsError::ArchiveIntegrity(format!(
            "Unsupported release archive extension for '{}' (expected .zip, .tar.gz, or .tgz)",
            path.display()
        )))
    }
}

struct ExtractedRawState {
    files_rel: Vec<String>,
    dirs_rel: Vec<String>,
}

fn validate_raw_archive_path(raw: &str, is_dir: bool, package_path: &Path) -> Result<String> {
    let replaced_err = || {
        CfmsError::ArchiveIntegrity(format!(
            "Release archive '{}' contains unsafe member path '{raw}'",
            package_path.display()
        ))
    };
    if raw.is_empty() || raw.contains('\\') || raw.contains('\0') || raw.starts_with('/') {
        return Err(replaced_err());
    }
    if raw.len() >= 2 && raw.as_bytes()[0].is_ascii_alphabetic() && raw.as_bytes()[1] == b':' {
        return Err(replaced_err());
    }
    let trimmed = if is_dir {
        raw.trim_end_matches('/')
    } else {
        if raw.ends_with('/') {
            return Err(replaced_err());
        }
        raw
    };
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    let mut clean = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.ends_with(' ')
            || seg.ends_with('.')
            || is_windows_reserved_name(seg)
        {
            return Err(replaced_err());
        }
        clean.push(seg);
    }
    Ok(clean.join("/"))
}

fn record_path_uniqueness(
    norm: &str,
    is_dir: bool,
    seen_lower: &mut BTreeMap<String, String>,
    dir_lower: &mut BTreeSet<String>,
    file_lower: &mut BTreeSet<String>,
    package_path: &Path,
) -> Result<()> {
    let lower = norm.to_ascii_lowercase();
    if let Some(prev) = seen_lower.get(&lower) {
        if is_dir && dir_lower.contains(&lower) && !file_lower.contains(&lower) {
            return Ok(());
        }
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release archive '{}' has colliding paths '{prev}' and '{norm}'",
            package_path.display()
        )));
    }
    seen_lower.insert(lower.clone(), norm.to_string());

    let mut prefix = String::new();
    let segs: Vec<&str> = lower.split('/').collect();
    for (idx, seg) in segs.iter().enumerate() {
        if idx > 0 {
            prefix.push('/');
        }
        prefix.push_str(seg);
        let is_leaf = idx + 1 == segs.len();
        if !is_leaf || is_dir {
            if file_lower.contains(&prefix) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Release archive '{}' has file/directory conflict at '{norm}'",
                    package_path.display()
                )));
            }
            dir_lower.insert(prefix.clone());
        } else {
            if dir_lower.contains(&prefix) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Release archive '{}' has file/directory conflict at '{norm}'",
                    package_path.display()
                )));
            }
            file_lower.insert(prefix.clone());
        }
    }
    Ok(())
}

fn copy_bounded_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    remaining_budget: &mut u64,
    package_path: &Path,
    member_name: &str,
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut member_bytes = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|err| {
            CfmsError::ArchiveIntegrity(format!(
                "Failed reading archive member '{member_name}' from '{}': {err}",
                package_path.display()
            ))
        })?;
        if n == 0 {
            break;
        }
        let chunk_len = n as u64;
        if chunk_len > *remaining_budget {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Release archive '{}' exceeded {MAX_UNCOMPRESSED_BYTES}-byte uncompressed safety limit",
                package_path.display()
            )));
        }
        *remaining_budget -= chunk_len;
        member_bytes += chunk_len;
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n])?;
    }
    Ok((member_bytes, hex::encode(hasher.finalize())))
}

fn extract_zip_raw_entries(package_path: &Path, dest: &Path) -> Result<ExtractedRawState> {
    let file = File::open(package_path)?;
    let mut archive = ZipArchive::new(BufReader::with_capacity(64 * 1024, file)).map_err(|err| {
        CfmsError::ArchiveIntegrity(format!(
            "Unable to open ZIP archive '{}': {err}",
            package_path.display()
        ))
    })?;

    if archive.len() > MAX_ARCHIVE_MEMBERS {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release archive '{}' contains {} entries, exceeding limit {MAX_ARCHIVE_MEMBERS}",
            package_path.display(),
            archive.len()
        )));
    }

    let mut remaining_budget = MAX_UNCOMPRESSED_BYTES;
    let mut seen_lower = BTreeMap::new();
    let mut dir_lower = BTreeSet::new();
    let mut file_lower = BTreeSet::new();
    let mut files_rel = Vec::new();
    let mut dirs_rel = Vec::new();

    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).map_err(|err| {
            CfmsError::ArchiveIntegrity(format!(
                "Invalid ZIP entry at index {idx} in '{}': {err}",
                package_path.display()
            ))
        })?;

        if entry.encrypted() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Encrypted ZIP entries are forbidden in '{}'",
                package_path.display()
            )));
        }
        if !matches!(entry.compression(), CompressionMethod::Stored | CompressionMethod::Deflated) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unsupported ZIP compression method in '{}'",
                package_path.display()
            )));
        }
        if entry.is_symlink() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Symlink entries are forbidden in release archive '{}'",
                package_path.display()
            )));
        }
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & 0o170000;
            if file_type != 0 && !matches!(file_type, 0o100000 | 0o040000) {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Special UNIX file mode {file_type:#o} forbidden in release archive '{}'",
                    package_path.display()
                )));
            }
        }

        let raw_name = entry
            .name()
            .map_err(|err| {
                CfmsError::ArchiveIntegrity(format!(
                    "Archive '{}' contains invalid member name encoding at #{idx}: {err}",
                    package_path.display()
                ))
            })?
            .into_owned();
        let is_dir = entry.is_dir();
        let norm = validate_raw_archive_path(&raw_name, is_dir, package_path)?;
        if norm.is_empty() {
            continue;
        }
        record_path_uniqueness(
            &norm,
            is_dir,
            &mut seen_lower,
            &mut dir_lower,
            &mut file_lower,
            package_path,
        )?;

        let rel_path = Path::new(&norm);
        if is_dir {
            ensure_safe_directory_chain(dest, rel_path)?;
            dirs_rel.push(norm);
        } else {
            if let Some(parent) = rel_path.parent()
                && !parent.as_os_str().is_empty()
            {
                ensure_safe_directory_chain(dest, parent)?;
            }
            let target = dest.join(rel_path);
            let mut out = OpenOptions::new().write(true).create_new(true).open(&target)?;
            copy_bounded_stream(&mut entry, &mut out, &mut remaining_budget, package_path, &norm)?;
            out.sync_all()?;
            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                let safe_mode = (mode & 0o755) | 0o600;
                fs::set_permissions(&target, fs::Permissions::from_mode(safe_mode))?;
            }
            files_rel.push(norm);
        }
    }

    Ok(ExtractedRawState { files_rel, dirs_rel })
}

fn extract_targz_raw_entries(package_path: &Path, dest: &Path) -> Result<ExtractedRawState> {
    let file = File::open(package_path)?;
    let gz = GzDecoder::new(BufReader::with_capacity(64 * 1024, file));
    let mut archive = TarArchive::new(gz);
    archive.set_ignore_zeros(false);

    let mut remaining_budget = MAX_UNCOMPRESSED_BYTES;
    let mut count = 0usize;
    let mut seen_lower = BTreeMap::new();
    let mut dir_lower = BTreeSet::new();
    let mut file_lower = BTreeSet::new();
    let mut files_rel = Vec::new();
    let mut dirs_rel = Vec::new();

    let entries = archive.entries().map_err(|err| {
        CfmsError::ArchiveIntegrity(format!(
            "Unable to read tar.gz entries in '{}': {err}",
            package_path.display()
        ))
    })?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|err| {
            CfmsError::ArchiveIntegrity(format!(
                "Corrupt tar.gz entry in '{}': {err}",
                package_path.display()
            ))
        })?;
        count += 1;
        if count > MAX_ARCHIVE_MEMBERS {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Release archive '{}' exceeds {MAX_ARCHIVE_MEMBERS}-member limit",
                package_path.display()
            )));
        }

        let etype = entry.header().entry_type();
        let is_dir = match etype {
            EntryType::Directory => true,
            EntryType::Regular | EntryType::Continuous => false,
            _ => {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Unsupported tar entry type '{etype:?}' (symlinks/hardlinks/devices forbidden) in '{}'",
                    package_path.display()
                )));
            }
        };

        let raw_path_cow = entry.path_bytes();
        let raw_name = std::str::from_utf8(&raw_path_cow).map_err(|_| {
            CfmsError::ArchiveIntegrity(format!(
                "Non-UTF-8 member path in '{}'",
                package_path.display()
            ))
        })?;
        let raw_name_owned = raw_name.strip_prefix("./").unwrap_or(raw_name).to_string();
        if raw_name_owned.is_empty() || raw_name_owned == "." {
            continue;
        }
        let norm = validate_raw_archive_path(&raw_name_owned, is_dir, package_path)?;
        if norm.is_empty() {
            continue;
        }
        record_path_uniqueness(
            &norm,
            is_dir,
            &mut seen_lower,
            &mut dir_lower,
            &mut file_lower,
            package_path,
        )?;

        let rel_path = Path::new(&norm);
        if is_dir {
            ensure_safe_directory_chain(dest, rel_path)?;
            dirs_rel.push(norm);
        } else {
            if let Some(parent) = rel_path.parent()
                && !parent.as_os_str().is_empty()
            {
                ensure_safe_directory_chain(dest, parent)?;
            }
            let target = dest.join(rel_path);
            let mut out = OpenOptions::new().write(true).create_new(true).open(&target)?;
            copy_bounded_stream(&mut entry, &mut out, &mut remaining_budget, package_path, &norm)?;
            out.sync_all()?;
            #[cfg(unix)]
            if let Ok(mode) = entry.header().mode() {
                use std::os::unix::fs::PermissionsExt;
                let safe_mode = (mode & 0o755) | 0o600;
                fs::set_permissions(&target, fs::Permissions::from_mode(safe_mode))?;
            }
            files_rel.push(norm);
        }
    }

    Ok(ExtractedRawState { files_rel, dirs_rel })
}

/// If the archive nests its contents under a single top-level directory (`cfms-on-websocket-<ver>/`),
/// unwrap that single root directory cleanly into `dest`.
fn normalize_top_level_prefix(dest: &Path, raw: &ExtractedRawState) -> Result<()> {
    if raw.files_rel.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Release archive contains no files".to_string(),
        ));
    }

    if dest.join(RELEASE_MANIFEST_FILENAME).is_file() {
        return Ok(());
    }

    let first_roots: BTreeSet<&str> = raw
        .files_rel
        .iter()
        .chain(raw.dirs_rel.iter())
        .filter_map(|p| p.split('/').next())
        .collect();

    if first_roots.len() != 1 {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release archive must contain either root '{RELEASE_MANIFEST_FILENAME}' or a single top-level directory"
        )));
    }

    let top_dir_name = *first_roots.iter().next().unwrap();
    let top_dir = dest.join(top_dir_name);
    if !top_dir.join(RELEASE_MANIFEST_FILENAME).is_file() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release archive top-level directory '{top_dir_name}' is missing '{RELEASE_MANIFEST_FILENAME}'"
        )));
    }

    // Move children of `top_dir` cleanly up to `dest` via a unique temp dir to handle name collisions (e.g. `src/src`).
    let temp_top = dest.join(format!(".unwrap-{}", uuid::Uuid::new_v4().simple()));
    fs::rename(&top_dir, &temp_top)?;
    for entry in fs::read_dir(&temp_top)? {
        let entry = entry?;
        let target = dest.join(entry.file_name());
        fs::rename(entry.path(), target)?;
    }
    fs::remove_dir_all(&temp_top)?;
    Ok(())
}

/// Verify that all extracted files inside `release_dir` match `release-manifest.json` 1:1 with zero
/// missing, tampered, or untracked files.
pub fn verify_staged_release_tree(release_dir: &Path) -> Result<ValidatedManifest> {
    let manifest_path = release_dir.join(RELEASE_MANIFEST_FILENAME);
    let raw_bytes = fs::read(&manifest_path).map_err(|_| {
        CfmsError::ArchiveIntegrity(format!(
            "Staged release is missing '{RELEASE_MANIFEST_FILENAME}'"
        ))
    })?;
    let validated =
        parse_and_validate_manifest_bytes(&raw_bytes, &manifest_path.display().to_string())?;

    let actual_files = collect_regular_files_rel(release_dir)?;
    let expected_keys: BTreeSet<&str> = validated
        .manifest
        .files
        .keys()
        .map(String::as_str)
        .collect();
    let actual_keys: BTreeSet<&str> = actual_files
        .iter()
        .map(String::as_str)
        .filter(|p| *p != RELEASE_MANIFEST_FILENAME)
        .collect();

    if actual_keys != expected_keys {
        let missing: Vec<&str> = expected_keys.difference(&actual_keys).copied().collect();
        let extra: Vec<&str> = actual_keys.difference(&expected_keys).copied().collect();
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Staged release files do not match manifest (missing: {:?}, unexpected: {:?})",
            missing, extra
        )));
    }

    for (rel_posix, expected_hash) in &validated.manifest.files {
        validate_manifest_rel_path(rel_posix)?;
        let full = release_dir.join(rel_posix);
        let (actual_hash, _) = hash_file_sha256(&full)?;
        if &actual_hash != expected_hash {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Staged file '{rel_posix}' failed SHA-256 verification: expected {expected_hash}, got {actual_hash}"
            )));
        }
    }

    Ok(validated)
}

pub(crate) fn collect_regular_files_rel(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    collect_recursive(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_recursive(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if is_symlink_or_reparse_point(&meta) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Refusing to traverse symlink or junction '{}'",
                path.display()
            )));
        }
        let rel = path.strip_prefix(base).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!("Path prefix error under '{}': {e}", base.display()))
        })?;
        let rel_posix = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if meta.is_dir() {
            collect_recursive(base, &path, out)?;
        } else if meta.is_file() {
            out.push(rel_posix);
        } else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unsupported non-regular filesystem entry '{}'",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder as TarBuilder;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    use super::*;
    use super::super::manifest::tests::minimal_valid_manifest_bytes;
    use super::super::models::REQUIRED_RELEASE_FILES;

    fn build_sample_entries(version: &str, main_bytes: &[u8]) -> (Vec<(String, Vec<u8>)>, Vec<u8>) {
        let manifest_bytes = minimal_valid_manifest_bytes(version, main_bytes);
        let mut entries = Vec::new();
        for req in REQUIRED_RELEASE_FILES {
            let content = if *req == "src/main.py" {
                main_bytes.to_vec()
            } else {
                format!("content-for-{req}").into_bytes()
            };
            entries.push(((*req).to_string(), content));
        }
        entries.push((RELEASE_MANIFEST_FILENAME.to_string(), manifest_bytes.clone()));
        (entries, manifest_bytes)
    }

    pub(crate) fn write_test_zip(path: &Path, version: &str, main_bytes: &[u8]) -> String {
        let (entries, _) = build_sample_entries(version, main_bytes);
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = SimpleFileOptions::default();
        let prefix = format!("cfms-on-websocket-{version}");
        for (rel, data) in entries {
            zip.start_file(format!("{prefix}/{rel}"), opts).unwrap();
            zip.write_all(&data).unwrap();
        }
        zip.finish().unwrap();
        hash_file_sha256(path).unwrap().0
    }

    pub(crate) fn write_test_targz(path: &Path, version: &str, main_bytes: &[u8]) -> String {
        let (entries, _) = build_sample_entries(version, main_bytes);
        let file = File::create(path).unwrap();
        let gz = GzEncoder::new(file, Compression::default());
        let mut tar = TarBuilder::new(gz);
        let prefix = format!("cfms-on-websocket-{version}");
        for (rel, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, format!("{prefix}/{rel}"), &data[..])
                .unwrap();
        }
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
        hash_file_sha256(path).unwrap().0
    }

    #[test]
    fn stages_zip_without_external_checksum_or_with_sha256sums() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("cfms-on-websocket-0.15.0.zip");
        let sha = write_test_zip(&zip_path, "0.15.0", b"print('v15')\n");

        // No external checksum required: computes package hash & still verifies internal manifest
        let staged_no_ext = stage_release_archive(&zip_path, None, None, None).unwrap();
        assert_eq!(staged_no_ext.checksum.package_sha256, sha);
        assert!(!staged_no_ext.checksum.verified_against_external);
        assert_eq!(staged_no_ext.manifest.manifest.version, "0.15.0");

        // Explicit --sha256 wrong digest still fails closed
        let bad = "0".repeat(64);
        assert!(stage_release_archive(&zip_path, Some(&bad), None, None).is_err());

        // Sibling SHA256SUMS.txt auto-discovered and verified
        let sums = tmp.path().join("SHA256SUMS.txt");
        fs::write(&sums, format!("{sha}  cfms-on-websocket-0.15.0.zip\n")).unwrap();
        let staged_sums = stage_release_archive(&zip_path, None, None, None).unwrap();
        assert!(staged_sums.checksum.verified_against_external);
    }

    #[test]
    fn stages_targz_bundles_natively() {
        let tmp = TempDir::new().unwrap();
        let tgz_path = tmp.path().join("cfms-on-websocket-0.16.0.tar.gz");
        let sha = write_test_targz(&tgz_path, "0.16.0", b"print('v16')\n");
        let staged = stage_release_archive(&tgz_path, Some(&sha), None, None).unwrap();
        assert!(staged.checksum.verified_against_external);
        assert_eq!(staged.manifest.manifest.version, "0.16.0");
        assert!(staged.extracted_dir.join("src/main.py").is_file());
    }

    #[test]
    fn rejects_zipslip_and_symlinks() {
        let tmp = TempDir::new().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        let file = File::create(&zip_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("../escape.py", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"boom").unwrap();
        zip.finish().unwrap();
        assert!(stage_release_archive(&zip_path, None, None, None).is_err());

        let tgz_path = tmp.path().join("evil_sym.tar.gz");
        let file = File::create(&tgz_path).unwrap();
        let gz = GzEncoder::new(file, Compression::default());
        let mut tar = TarBuilder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "top/link", std::io::empty())
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        assert!(stage_release_archive(&tgz_path, None, None, None).is_err());
    }
}
