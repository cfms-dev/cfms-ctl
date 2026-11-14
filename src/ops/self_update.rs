//! Self-update operation backed by GitHub Releases and `cargo-dist` artifacts.

use std::path::PathBuf;
use semver::Version;
use serde::Serialize;
use self_update::{
    Release, ReleaseAsset, UpdateStrategy,
    backends::github::Update,
    cargo_crate_version, get_target,
};
use crate::{
    cli::self_update::SelfUpdateArgs,
    core::error::{CfmsError, Result},
    ops::AppContext,
    ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort},
};

/// Default GitHub repository owner for `cfms-ctl` releases.
pub const DEFAULT_REPO_OWNER: &str = "cfms-dev";
/// Default GitHub repository name for `cfms-ctl` releases.
pub const DEFAULT_REPO_NAME: &str = "cfms-ctl";
/// Binary name distributed by `cargo-dist`.
pub const BIN_NAME: &str = "cfms-ctl";

/// Outcome status of a `self-update` check or installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUpdateStatus {
    UpToDate,
    UpdateAvailable,
    Updated,
}

/// Structured report emitted by `cfms-ctl self-update`.
#[derive(Debug, Clone, Serialize)]
pub struct SelfUpdateReport {
    pub status: SelfUpdateStatus,
    pub check_only: bool,
    pub repository: String,
    pub target: String,
    pub current_version: String,
    pub target_version: String,
    pub release_name: String,
    pub release_date: String,
    pub release_notes_url: Option<String>,
    pub asset_name: Option<String>,
    pub checksum_asset: Option<String>,
    pub install_path: Option<PathBuf>,
}

impl CommandReport for SelfUpdateReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut table = KeyValueTable::new(format!("CFMS-CTL Self-Update ({})", self.repository));
        table
            .row("Current Version", format!("v{}", self.current_version))
            .row("Target Version", format!("v{}", self.target_version))
            .row("Platform Target", &self.target);

        if let Some(asset) = &self.asset_name {
            table.row("Release Asset", asset);
        }
        if let Some(checksum) = &self.checksum_asset {
            table.row("Checksum Source", checksum);
        }
        if let Some(path) = &self.install_path {
            table.row("Install Path", path.display().to_string());
        }
        if let Some(url) = &self.release_notes_url {
            table.row("Release Notes", url);
        }

        let status_label = match self.status {
            SelfUpdateStatus::UpToDate => "UP TO DATE",
            SelfUpdateStatus::UpdateAvailable => "UPDATE AVAILABLE",
            SelfUpdateStatus::Updated => "UPDATED",
        };
        table.row("Status", status_label);
        table.print();
        println!();

        match self.status {
            SelfUpdateStatus::UpToDate => {
                ui.print_success(&format!(
                    "cfms-ctl v{} is already up to date.",
                    self.current_version
                ));
            }
            SelfUpdateStatus::UpdateAvailable => {
                ui.print_warning(&format!(
                    "A newer release (v{}) is available. Run `cfms-ctl self-update` to install it.",
                    self.target_version
                ));
            }
            SelfUpdateStatus::Updated => {
                ui.print_success(&format!(
                    "Successfully updated cfms-ctl from v{} to v{}.",
                    self.current_version, self.target_version
                ));
            }
        }
    }
}

/// Resolve the GitHub `(owner, repo)` coordinates, allowing environment overrides for testing or mirrors.
#[must_use]
pub fn resolve_repo_coordinates() -> (String, String) {
    let owner = std::env::var("CFMS_UPDATE_REPO_OWNER")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_REPO_OWNER.to_owned());
    let name = std::env::var("CFMS_UPDATE_REPO_NAME")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_REPO_NAME.to_owned());
    (owner, name)
}

/// Candidate tag strings to try when a user supplies `--version <VERSION>`.
///
/// If the user passes `0.2.0`, tries `["v0.2.0", "0.2.0"]` because `cargo-dist` tag conventions
/// typically prefix versions with `v`. If the user passes `v0.2.0`, tries `["v0.2.0", "0.2.0"]`.
#[must_use]
pub fn candidate_release_tags(requested: &str) -> Vec<String> {
    let trimmed = requested.trim();
    if let Some(stripped) = trimmed.strip_prefix('v') {
        vec![trimmed.to_owned(), stripped.to_owned()]
    } else {
        vec![format!("v{trimmed}"), trimmed.to_owned()]
    }
}

/// Select the primary downloadable `cargo-dist` archive asset for `bin_name` and `target`.
///
/// Explicitly ignores sidecar files such as `.sha256`, `.sig`, `.asc`, `.pdb`, `.debug`, and `.dSYM`.
#[must_use]
pub fn select_cargo_dist_asset(
    assets: &[ReleaseAsset],
    bin_name: &str,
    target: &str,
) -> Option<ReleaseAsset> {
    let preferred_names = if target.contains("windows") {
        [
            format!("{bin_name}-{target}.zip"),
            format!("{bin_name}-{target}.tar.xz"),
            format!("{bin_name}-{target}.tar.gz"),
        ]
    } else {
        [
            format!("{bin_name}-{target}.tar.xz"),
            format!("{bin_name}-{target}.tar.gz"),
            format!("{bin_name}-{target}.zip"),
        ]
    };

    for expected in &preferred_names {
        if let Some(asset) = assets.iter().find(|a| a.name() == expected) {
            return Some(asset.clone());
        }
    }

    // Fallback: any supported archive containing `target` that is not a checksum or debug symbol file.
    assets
        .iter()
        .find(|a| {
            let name = a.name();
            name.contains(target)
                && (name.ends_with(".tar.xz")
                    || name.ends_with(".tar.gz")
                    || name.ends_with(".zip"))
        })
        .cloned()
}

/// Compute the path of the executable inside a `cargo-dist` archive.
///
/// - `cargo-dist` `.zip` archives place the binary at the archive root (`cfms-ctl.exe` / `cfms-ctl`).
/// - `cargo-dist` `.tar.xz` / `.tar.gz` archives nest the binary inside a `{bin_name}-{target}/`
///   top-level directory (`cfms-ctl-{target}/cfms-ctl`).
#[must_use]
pub fn archive_bin_path_for_asset(
    asset_name: &str,
    bin_name: &str,
    target: &str,
    exe_suffix: &str,
) -> String {
    let raw_bin = format!("{}{exe_suffix}", bin_name.trim_end_matches(exe_suffix));
    if asset_name.ends_with(".zip") {
        raw_bin
    } else {
        format!("{bin_name}-{target}/{raw_bin}")
    }
}

/// Locate the best checksum sidecar asset in the release (`<asset>.sha256` or `sha256.sum`).
#[must_use]
pub fn checksum_asset_for_release(
    assets: &[ReleaseAsset],
    selected_asset_name: &str,
) -> Option<String> {
    let per_asset_sha256 = format!("{selected_asset_name}.sha256");
    if assets.iter().any(|a| a.name() == per_asset_sha256) {
        return Some(per_asset_sha256);
    }
    if assets.iter().any(|a| a.name() == "sha256.sum") {
        return Some("sha256.sum".to_owned());
    }
    None
}

/// Compare two bare SemVer strings and return `true` if `candidate` is strictly newer than `current`.
pub fn is_newer_version(current: &str, candidate: &str) -> Result<bool> {
    let cur = Version::parse(current.trim_start_matches('v')).map_err(|e| {
        CfmsError::SelfUpdate(format!("Invalid current version '{current}': {e}"))
    })?;
    let cand = Version::parse(candidate.trim_start_matches('v')).map_err(|e| {
        CfmsError::SelfUpdate(format!("Invalid release version '{candidate}': {e}"))
    })?;
    Ok(cand > cur)
}

/// Configure a base `self_update` GitHub `UpdateBuilder` for `cfms-ctl`.
fn base_updater_builder(
    owner: &str,
    repo: &str,
    current_version: &str,
    target: &str,
) -> self_update::backends::github::UpdateBuilder {
    let mut builder = Update::configure();
    builder
        .repo_owner(owner)
        .repo_name(repo)
        .bin_name(BIN_NAME)
        .target(target)
        .current_version(current_version)
        .auth_token_from_env()
        .update_strategy(UpdateStrategy::Latest)
        .check_install_path_writable(true);

    if let Ok(api_url) = std::env::var("CFMS_UPDATE_API_BASE_URL") {
        let trimmed = api_url.trim();
        if !trimmed.is_empty() {
            builder.api_base_url(trimmed);
        }
    }

    builder
}

/// Resolve the target [`Release`] and optional pinned tag from GitHub Releases.
async fn fetch_target_release(
    owner: &str,
    repo: &str,
    current_version: &str,
    target: &str,
    requested_version: Option<&str>,
) -> Result<(Release, Option<String>)> {
    let updater = base_updater_builder(owner, repo, current_version, target)
        .build_async()
        .map_err(|e| CfmsError::SelfUpdate(e.to_string()))?;

    if let Some(req_ver) = requested_version {
        let candidates = candidate_release_tags(req_ver);
        let mut last_err = None;
        for tag in candidates {
            match updater.get_release_version_async(&tag).await {
                Ok(release) => return Ok((release, Some(tag))),
                Err(err) => last_err = Some(err),
            }
        }
        let err_msg = last_err.map_or_else(
            || format!("No release matching '{req_ver}' found"),
            |e| e.to_string(),
        );
        Err(CfmsError::SelfUpdate(err_msg))
    } else {
        let releases = updater
            .get_latest_release_async()
            .await
            .map_err(|e| CfmsError::SelfUpdate(e.to_string()))?;
        let release = releases
            .latest()
            .cloned()
            .ok_or_else(|| CfmsError::SelfUpdate("No releases found on GitHub".to_owned()))?;
        Ok((release, None))
    }
}

/// Handle `cfms-ctl self-update`.
pub async fn handle(ctx: &AppContext, args: SelfUpdateArgs) -> Result<()> {
    let (owner, repo) = resolve_repo_coordinates();
    let repository = format!("{owner}/{repo}");
    let current_version = cargo_crate_version!();
    let target = get_target();
    let install_path = std::env::current_exe().ok();

    let (release, pinned_tag) = fetch_target_release(
        &owner,
        &repo,
        current_version,
        target,
        args.version.as_deref(),
    )
    .await?;

    let target_version = release.version().to_owned();
    let selected_asset = select_cargo_dist_asset(release.assets(), BIN_NAME, target);
    let checksum_asset = selected_asset
        .as_ref()
        .and_then(|asset| checksum_asset_for_release(release.assets(), asset.name()));

    let should_update = if args.version.is_some() {
        let cur = Version::parse(current_version.trim_start_matches('v'))
            .map_err(|e| CfmsError::SelfUpdate(e.to_string()))?;
        let tgt = Version::parse(target_version.trim_start_matches('v'))
            .map_err(|e| CfmsError::SelfUpdate(e.to_string()))?;
        cur != tgt
    } else {
        is_newer_version(current_version, &target_version)?
    };

    if !should_update {
        let report = SelfUpdateReport {
            status: SelfUpdateStatus::UpToDate,
            check_only: args.check,
            repository,
            target: target.to_owned(),
            current_version: current_version.to_owned(),
            target_version,
            release_name: release.name().to_owned(),
            release_date: release.date().to_owned(),
            release_notes_url: release.release_notes_url().map(str::to_owned),
            asset_name: selected_asset.as_ref().map(|a| a.name().to_owned()),
            checksum_asset,
            install_path,
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    let asset = selected_asset.ok_or_else(|| {
        CfmsError::SelfUpdate(format!(
            "Release v{target_version} does not contain a compatible archive for target '{target}'"
        ))
    })?;

    if args.check {
        let report = SelfUpdateReport {
            status: SelfUpdateStatus::UpdateAvailable,
            check_only: true,
            repository,
            target: target.to_owned(),
            current_version: current_version.to_owned(),
            target_version,
            release_name: release.name().to_owned(),
            release_date: release.date().to_owned(),
            release_notes_url: release.release_notes_url().map(str::to_owned),
            asset_name: Some(asset.name().to_owned()),
            checksum_asset,
            install_path,
        };
        ctx.ui.render(&report);
        return Ok(());
    }

    confirm_or_abort(
        &format!(
            "Update cfms-ctl from v{current_version} to v{target_version} ({})?",
            asset.name()
        ),
        ctx.global.yes,
    )?;

    let bin_path_in_archive = archive_bin_path_for_asset(
        asset.name(),
        BIN_NAME,
        target,
        std::env::consts::EXE_SUFFIX,
    );
    let expected_asset_name = asset.name().to_owned();

    // When a user explicitly requests a downgrade/reinstall via `--version`, set `current_version`
    // on the inner updater to `0.0.0` so `self_update`'s `bump_is_greater` check allows installing
    // the pinned release tag.
    let effective_current_version = if pinned_tag.is_some()
        && !is_newer_version(current_version, &target_version)?
    {
        "0.0.0"
    } else {
        current_version
    };

    let mut builder = base_updater_builder(&owner, &repo, effective_current_version, target);
    builder
        .unattended()
        .show_download_progress(matches!(ctx.global.output, OutputFormat::Human))
        .bin_path_in_archive(bin_path_in_archive)
        .asset_matcher(move |assets| {
            assets
                .iter()
                .find(|a| a.name() == expected_asset_name)
                .cloned()
        });

    if let Some(ref tag) = pinned_tag {
        builder.release_tag(tag);
    }
    if let Some(ref sum_asset) = checksum_asset {
        builder.checksum_from_asset(sum_asset);
    }

    let updater = builder
        .build_async()
        .map_err(|e| CfmsError::SelfUpdate(e.to_string()))?;

    updater
        .update_extended_async()
        .await
        .map_err(|e| CfmsError::SelfUpdate(e.to_string()))?;

    let report = SelfUpdateReport {
        status: SelfUpdateStatus::Updated,
        check_only: false,
        repository,
        target: target.to_owned(),
        current_version: current_version.to_owned(),
        target_version,
        release_name: release.name().to_owned(),
        release_date: release.date().to_owned(),
        release_notes_url: release.release_notes_url().map(str::to_owned),
        asset_name: Some(asset.name().to_owned()),
        checksum_asset,
        install_path,
    };
    ctx.ui.render(&report);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cargo_dist_assets() -> Vec<ReleaseAsset> {
        vec![
            ReleaseAsset::new(
                "cfms-ctl-installer.sh",
                "https://example.com/cfms-ctl-installer.sh",
            ),
            ReleaseAsset::new(
                "cfms-ctl-installer.ps1",
                "https://example.com/cfms-ctl-installer.ps1",
            ),
            ReleaseAsset::new(
                "cfms-ctl-x86_64-pc-windows-msvc.pdb",
                "https://example.com/cfms-ctl-x86_64-pc-windows-msvc.pdb",
            ),
            ReleaseAsset::new(
                "cfms-ctl-x86_64-pc-windows-msvc.zip.sha256",
                "https://example.com/cfms-ctl-x86_64-pc-windows-msvc.zip.sha256",
            ),
            ReleaseAsset::new(
                "cfms-ctl-x86_64-pc-windows-msvc.zip",
                "https://example.com/cfms-ctl-x86_64-pc-windows-msvc.zip",
            ),
            ReleaseAsset::new(
                "cfms-ctl-x86_64-unknown-linux-gnu.debug",
                "https://example.com/cfms-ctl-x86_64-unknown-linux-gnu.debug",
            ),
            ReleaseAsset::new(
                "cfms-ctl-x86_64-unknown-linux-gnu.tar.xz.sha256",
                "https://example.com/cfms-ctl-x86_64-unknown-linux-gnu.tar.xz.sha256",
            ),
            ReleaseAsset::new(
                "cfms-ctl-x86_64-unknown-linux-gnu.tar.xz",
                "https://example.com/cfms-ctl-x86_64-unknown-linux-gnu.tar.xz",
            ),
            ReleaseAsset::new("sha256.sum", "https://example.com/sha256.sum"),
        ]
    }

    #[test]
    fn selects_windows_zip_skipping_pdb_and_sha256() {
        let assets = sample_cargo_dist_assets();
        let selected = select_cargo_dist_asset(&assets, "cfms-ctl", "x86_64-pc-windows-msvc")
            .expect("windows asset should be found");
        assert_eq!(selected.name(), "cfms-ctl-x86_64-pc-windows-msvc.zip");
    }

    #[test]
    fn selects_linux_tar_xz_skipping_debug_and_sha256() {
        let assets = sample_cargo_dist_assets();
        let selected = select_cargo_dist_asset(&assets, "cfms-ctl", "x86_64-unknown-linux-gnu")
            .expect("linux asset should be found");
        assert_eq!(selected.name(), "cfms-ctl-x86_64-unknown-linux-gnu.tar.xz");
    }

    #[test]
    fn returns_none_for_missing_target() {
        let assets = sample_cargo_dist_assets();
        assert!(select_cargo_dist_asset(&assets, "cfms-ctl", "riscv64gc-unknown-linux-gnu").is_none());
    }

    #[test]
    fn resolves_archive_bin_path_for_zip_and_tar() {
        assert_eq!(
            archive_bin_path_for_asset(
                "cfms-ctl-x86_64-pc-windows-msvc.zip",
                "cfms-ctl",
                "x86_64-pc-windows-msvc",
                ".exe"
            ),
            "cfms-ctl.exe"
        );
        assert_eq!(
            archive_bin_path_for_asset(
                "cfms-ctl-x86_64-unknown-linux-gnu.tar.xz",
                "cfms-ctl",
                "x86_64-unknown-linux-gnu",
                ""
            ),
            "cfms-ctl-x86_64-unknown-linux-gnu/cfms-ctl"
        );
    }

    #[test]
    fn resolves_checksum_asset_preference() {
        let assets = sample_cargo_dist_assets();
        assert_eq!(
            checksum_asset_for_release(&assets, "cfms-ctl-x86_64-pc-windows-msvc.zip").as_deref(),
            Some("cfms-ctl-x86_64-pc-windows-msvc.zip.sha256")
        );
        assert_eq!(
            checksum_asset_for_release(&assets, "cfms-ctl-aarch64-apple-darwin.tar.xz").as_deref(),
            Some("sha256.sum")
        );
    }

    #[test]
    fn candidate_release_tags_handles_prefixed_and_bare_versions() {
        assert_eq!(
            candidate_release_tags("0.2.0"),
            vec!["v0.2.0".to_owned(), "0.2.0".to_owned()]
        );
        assert_eq!(
            candidate_release_tags("v0.2.0"),
            vec!["v0.2.0".to_owned(), "0.2.0".to_owned()]
        );
    }

    #[test]
    fn compares_versions_accurately() {
        assert!(is_newer_version("0.1.0", "0.2.0").unwrap());
        assert!(is_newer_version("v0.1.0", "v0.1.1").unwrap());
        assert!(!is_newer_version("0.2.0", "0.2.0").unwrap());
        assert!(!is_newer_version("0.2.0", "0.1.9").unwrap());
    }
}
