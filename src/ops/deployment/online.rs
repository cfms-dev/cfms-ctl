//! Configurable GitHub Releases client for `cfms-ctl deployment check`, `update`,
//! `install --from-github`, and `adopt --from-github`.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use url::Url;

use crate::cli::deployment::{OnlineReleaseArgs, ReleaseArchiveFormat};
use crate::core::{CfmsError, Result};
use crate::ops::extension::version::CfmsServerVersion;
use crate::ui::OutputFormat;

use super::archive::parse_checksum_file_for_asset;
use super::manifest::validate_sha256_hex;
use super::models::{
    DeploymentCheckReport, GitHubAssetSummary, MAX_CHECKSUM_BYTES, MAX_PACKAGE_BYTES,
};

pub const DEFAULT_DEPLOY_REPO_OWNER: &str = "cfms-dev";
pub const DEFAULT_DEPLOY_REPO_NAME: &str = "cfms_on_websocket";
pub const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";

#[derive(Debug, Clone)]
pub struct OnlineClientConfig {
    pub owner: String,
    pub repo: String,
    pub api_base_url: Url,
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedGitHubRelease {
    pub repository: String,
    pub tag_name: String,
    pub version: String,
    pub prerelease: bool,
    pub release_url: String,
    pub published_at: Option<String>,
    pub asset: GitHubAssetSummary,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct DownloadedGitHubPackage {
    pub release: ResolvedGitHubRelease,
    pub package_path: PathBuf,
    pub sha256: String,
    _temp_dir: TempDir,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    html_url: String,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiAsset {
    name: String,
    size: u64,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

/// Resolve GitHub repository & API coordinates from CLI flags and environment overrides.
pub fn resolve_online_config(repo_override: Option<&str>) -> Result<OnlineClientConfig> {
    let (owner, repo) = if let Some(raw) = repo_override {
        let (o, r) = raw.trim().split_once('/').ok_or_else(|| {
            CfmsError::InvalidArgument(format!(
                "Invalid --repo '{raw}': expected `OWNER/NAME`"
            ))
        })?;
        validate_repo_segment(o, "owner")?;
        validate_repo_segment(r, "name")?;
        (o.to_string(), r.to_string())
    } else {
        let owner = std::env::var("CFMS_DEPLOY_REPO_OWNER")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_DEPLOY_REPO_OWNER.to_string());
        let repo = std::env::var("CFMS_DEPLOY_REPO_NAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_DEPLOY_REPO_NAME.to_string());
        validate_repo_segment(&owner, "owner")?;
        validate_repo_segment(&repo, "name")?;
        (owner, repo)
    };

    let raw_api_base = std::env::var("CFMS_DEPLOY_API_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GITHUB_API_BASE.to_string());
    let api_base_url = parse_safe_url(&raw_api_base, "GitHub API base URL")?;

    let auth_token = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Ok(OnlineClientConfig {
        owner,
        repo,
        api_base_url,
        auth_token,
    })
}

fn validate_repo_segment(seg: &str, label: &str) -> Result<()> {
    if seg.is_empty()
        || seg == "."
        || seg == ".."
        || !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(CfmsError::InvalidArgument(format!(
            "Invalid GitHub repository {label} '{seg}'"
        )));
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(raw) => {
            let trimmed = raw.trim_start_matches('[').trim_end_matches(']');
            trimmed
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        }
        None => false,
    }
}

fn parse_safe_url(raw: &str, context: &str) -> Result<Url> {
    let url = Url::parse(raw.trim()).map_err(|err| {
        CfmsError::Deployment(format!("Invalid URL for {context} ('{raw}'): {err}"))
    })?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_host(&url) => Ok(url),
        other => Err(CfmsError::Deployment(format!(
            "Refusing insecure URL scheme '{other}' for {context}: HTTPS is required"
        ))),
    }
}

fn build_http_client(auth_token: Option<&str>) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static(GITHUB_API_VERSION),
    );
    let ua = format!("cfms-ctl/{}", env!("CARGO_PKG_VERSION"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&ua).map_err(|e| CfmsError::Deployment(e.to_string()))?,
    );
    if let Some(tok) = auth_token {
        let mut auth_val = HeaderValue::from_str(&format!("Bearer {tok}"))
            .map_err(|e| CfmsError::Deployment(format!("Invalid GitHub token header: {e}")))?;
        auth_val.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_val);
    }

    let redirect_policy = Policy::custom(|attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("Too many HTTP redirects");
        }
        let next = attempt.url();
        let prev_https = attempt
            .previous()
            .last()
            .is_some_and(|u| u.scheme() == "https");
        if next.scheme() == "http" && (prev_https || !is_loopback_host(next)) {
            return attempt.error("Refusing insecure HTTP redirect");
        }
        if !matches!(next.scheme(), "https" | "http") {
            return attempt.error("Unsupported redirect scheme");
        }
        attempt.follow()
    });

    reqwest::Client::builder()
        .default_headers(headers)
        .redirect(redirect_policy)
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| CfmsError::Deployment(format!("Failed constructing HTTP client: {e}")))
}

fn candidate_tags(raw_version: &str) -> Vec<String> {
    let trimmed = raw_version.trim();
    let bare = trimmed.trim_start_matches('v');
    if trimmed.starts_with('v') {
        vec![trimmed.to_string(), bare.to_string()]
    } else {
        vec![format!("v{bare}"), bare.to_string()]
    }
}

/// Resolve release metadata from GitHub REST API and verify `SHA256SUMS.txt` + optional asset `digest`.
pub async fn check_github_release(
    online: &OnlineReleaseArgs,
    current_version: Option<&str>,
    require_github_digest: bool,
) -> Result<DeploymentCheckReport> {
    let cfg = resolve_online_config(online.repo.as_deref())?;
    check_github_release_with_config(&cfg, online, current_version, require_github_digest).await
}

pub async fn check_github_release_with_config(
    cfg: &OnlineClientConfig,
    online: &OnlineReleaseArgs,
    current_version: Option<&str>,
    require_github_digest: bool,
) -> Result<DeploymentCheckReport> {
    let resolved = fetch_and_resolve_release_with_config(cfg, online, require_github_digest).await?;
    let update_available = match current_version {
        None => true,
        Some(cur_raw) => {
            let cur = CfmsServerVersion::parse(cur_raw)?;
            let tgt = CfmsServerVersion::parse(&resolved.version)?;
            if tgt < cur {
                return Err(CfmsError::Deployment(format!(
                    "Target GitHub release {} is older than active release {}; downgrading a completed deployment is not supported",
                    resolved.version, cur_raw
                )));
            }
            tgt > cur
        }
    };

    Ok(DeploymentCheckReport {
        repository: resolved.repository,
        current_version: current_version.map(str::to_string),
        target_version: resolved.version,
        tag_name: resolved.tag_name,
        prerelease: resolved.prerelease,
        update_available,
        asset: resolved.asset,
        release_url: resolved.release_url,
        published_at: resolved.published_at,
        warnings: resolved.warnings,
    })
}

pub async fn fetch_and_resolve_release(
    online: &OnlineReleaseArgs,
    require_github_digest: bool,
) -> Result<ResolvedGitHubRelease> {
    let cfg = resolve_online_config(online.repo.as_deref())?;
    fetch_and_resolve_release_with_config(&cfg, online, require_github_digest).await
}

pub async fn fetch_and_resolve_release_with_config(
    cfg: &OnlineClientConfig,
    online: &OnlineReleaseArgs,
    require_github_digest: bool,
) -> Result<ResolvedGitHubRelease> {
    let api_client = build_http_client(cfg.auth_token.as_deref())?;
    // Separate unauthenticated client for asset/CDN downloads so auth headers never leak cross-domain.
    let asset_client = build_http_client(None)?;

    let repository = format!("{}/{}", cfg.owner, cfg.repo);
    let api_rel = fetch_api_release(&api_client, cfg, online).await?;

    if api_rel.draft {
        return Err(CfmsError::Deployment(format!(
            "GitHub release '{}' in '{repository}' is still a draft",
            api_rel.tag_name
        )));
    }
    if api_rel.prerelease && !online.include_prerelease {
        return Err(CfmsError::Deployment(format!(
            "GitHub release '{}' is a prerelease; pass `--include-prerelease` to allow it",
            api_rel.tag_name
        )));
    }

    let bare_version = api_rel.tag_name.trim_start_matches('v').to_string();
    CfmsServerVersion::parse(&bare_version).map_err(|e| {
        CfmsError::Deployment(format!(
            "GitHub release tag '{}' is not a valid CFMS version: {e}",
            api_rel.tag_name
        ))
    })?;

    let selected = select_release_asset(&api_rel.assets, &bare_version, online.format)?;
    if selected.size > MAX_PACKAGE_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Remote release asset '{}' ({} bytes) exceeds {MAX_PACKAGE_BYTES}-byte limit",
            selected.name, selected.size
        )));
    }

    let sums_asset = api_rel
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "GitHub release '{}' is missing required `SHA256SUMS.txt` asset",
                api_rel.tag_name
            ))
        })?;
    if sums_asset.size > MAX_CHECKSUM_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "`SHA256SUMS.txt` asset size ({} bytes) exceeds {MAX_CHECKSUM_BYTES}-byte limit",
            sums_asset.size
        )));
    }

    let sums_url = parse_safe_url(&sums_asset.browser_download_url, "SHA256SUMS.txt")?;
    let sums_bytes = download_bounded_bytes(&asset_client, sums_url, MAX_CHECKSUM_BYTES).await?;
    let temp_dir = tempfile::Builder::new().prefix("cfms-sums-").tempdir()?;
    let sums_file = temp_dir.path().join("SHA256SUMS.txt");
    fs::write(&sums_file, &sums_bytes)?;
    let sums_digest = parse_checksum_file_for_asset(&sums_file, &selected.name)?.ok_or_else(|| {
        CfmsError::ArchiveIntegrity(format!(
            "`SHA256SUMS.txt` in release '{}' contains no digest for '{}'",
            api_rel.tag_name, selected.name
        ))
    })?;

    let mut warnings = Vec::new();
    let api_digest = match selected.digest.as_deref() {
        Some(raw) => {
            let hex_raw = raw.strip_prefix("sha256:").ok_or_else(|| {
                CfmsError::ArchiveIntegrity(format!(
                    "Unsupported GitHub asset digest format '{raw}' for '{}'",
                    selected.name
                ))
            })?;
            let normalized = validate_sha256_hex(hex_raw, "GitHub asset.digest")?;
            if normalized != sums_digest {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Integrity conflict for '{}': GitHub asset digest ({normalized}) disagrees with SHA256SUMS.txt ({sums_digest})",
                    selected.name
                )));
            }
            Some(normalized)
        }
        None => {
            if require_github_digest {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "GitHub asset '{}' did not report a `digest` field and `--require-github-digest` is set",
                    selected.name
                )));
            }
            warnings.push(format!(
                "GitHub API returned `digest: null` for '{}'; relying on SHA256SUMS.txt + release-manifest.json verification",
                selected.name
            ));
            None
        }
    };

    let format_str = if selected.name.ends_with(".zip") {
        "zip"
    } else {
        "tar.gz"
    };
    let download_url =
        parse_safe_url(&selected.browser_download_url, "release archive asset")?.to_string();

    Ok(ResolvedGitHubRelease {
        repository,
        tag_name: api_rel.tag_name,
        version: bare_version,
        prerelease: api_rel.prerelease,
        release_url: api_rel.html_url,
        published_at: api_rel.published_at,
        asset: GitHubAssetSummary {
            name: selected.name.clone(),
            format: format_str.to_string(),
            size: selected.size,
            download_url,
            digest_sha256: api_digest,
            sha256sums_sha256: sums_digest,
        },
        warnings,
    })
}

async fn fetch_api_release(
    client: &reqwest::Client,
    cfg: &OnlineClientConfig,
    online: &OnlineReleaseArgs,
) -> Result<ApiRelease> {
    if let Some(ref version_req) = online.version {
        let mut last_err = None;
        for tag in candidate_tags(version_req) {
            let mut url = cfg.api_base_url.clone();
            url.path_segments_mut()
                .map_err(|()| CfmsError::Deployment("Invalid API base URL".to_string()))?
                .extend(["repos", &cfg.owner, &cfg.repo, "releases", "tags", &tag]);
            let resp = client.get(url).send().await.map_err(|e| {
                CfmsError::Deployment(format!("GitHub API request failed: {e}"))
            })?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                last_err = Some(format!("Release tag '{tag}' not found"));
                continue;
            }
            if !resp.status().is_success() {
                return Err(format_github_http_error(resp).await);
            }
            return resp.json::<ApiRelease>().await.map_err(|e| {
                CfmsError::Deployment(format!("Failed parsing GitHub release JSON: {e}"))
            });
        }
        return Err(CfmsError::Deployment(
            last_err.unwrap_or_else(|| format!("No release matching '{version_req}' found")),
        ));
    }

    if online.include_prerelease {
        let mut url = cfg.api_base_url.clone();
        url.path_segments_mut()
            .map_err(|()| CfmsError::Deployment("Invalid API base URL".to_string()))?
            .extend(["repos", &cfg.owner, &cfg.repo, "releases"]);
        url.query_pairs_mut().append_pair("per_page", "20");
        let resp = client.get(url).send().await.map_err(|e| {
            CfmsError::Deployment(format!("GitHub API request failed: {e}"))
        })?;
        if !resp.status().is_success() {
            return Err(format_github_http_error(resp).await);
        }
        let releases: Vec<ApiRelease> = resp.json().await.map_err(|e| {
            CfmsError::Deployment(format!("Failed parsing GitHub releases JSON: {e}"))
        })?;
        return releases
            .into_iter()
            .find(|r| !r.draft)
            .ok_or_else(|| CfmsError::Deployment("No non-draft GitHub releases found".to_string()));
    }

    let mut url = cfg.api_base_url.clone();
    url.path_segments_mut()
        .map_err(|()| CfmsError::Deployment("Invalid API base URL".to_string()))?
        .extend(["repos", &cfg.owner, &cfg.repo, "releases", "latest"]);
    let resp = client.get(url).send().await.map_err(|e| {
        CfmsError::Deployment(format!("GitHub API request failed: {e}"))
    })?;
    if !resp.status().is_success() {
        return Err(format_github_http_error(resp).await);
    }
    resp.json::<ApiRelease>().await.map_err(|e| {
        CfmsError::Deployment(format!("Failed parsing GitHub latest release JSON: {e}"))
    })
}

async fn format_github_http_error(resp: reqwest::Response) -> CfmsError {
    let status = resp.status();
    let hint = if status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        " (if rate-limited, export `GITHUB_TOKEN` or `GH_TOKEN`)"
    } else {
        ""
    };
    let body = resp.text().await.unwrap_or_default();
    let snippet = body.trim();
    CfmsError::Deployment(format!(
        "GitHub Releases API returned HTTP {status}{hint}{}",
        if snippet.is_empty() {
            String::new()
        } else {
            format!(": {}", &snippet[..snippet.len().min(240)])
        }
    ))
}

fn select_release_asset<'a>(
    assets: &'a [ApiAsset],
    version: &str,
    format: ReleaseArchiveFormat,
) -> Result<&'a ApiAsset> {
    let zip_name = format!("cfms-on-websocket-{version}.zip");
    let tgz_name = format!("cfms-on-websocket-{version}.tar.gz");
    let short_tgz_name = format!("cfms-on-websocket-{version}.tgz");

    let candidates: Vec<&str> = match format {
        ReleaseArchiveFormat::Zip => vec![zip_name.as_str()],
        ReleaseArchiveFormat::TarGz => vec![tgz_name.as_str(), short_tgz_name.as_str()],
        ReleaseArchiveFormat::Auto => {
            if cfg!(windows) {
                vec![zip_name.as_str(), tgz_name.as_str(), short_tgz_name.as_str()]
            } else {
                vec![tgz_name.as_str(), short_tgz_name.as_str(), zip_name.as_str()]
            }
        }
    };

    for expected in &candidates {
        if let Some(found) = assets.iter().find(|a| a.name == *expected) {
            return Ok(found);
        }
    }

    Err(CfmsError::Deployment(format!(
        "Release v{version} does not contain any matching archive asset ({})",
        candidates.join(", ")
    )))
}

async fn download_bounded_bytes(
    client: &reqwest::Client,
    url: Url,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let mut resp = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| CfmsError::Deployment(format!("Download failed for '{url}': {e}")))?;
    if !resp.status().is_success() {
        return Err(CfmsError::Deployment(format!(
            "Failed downloading '{url}': HTTP {}",
            resp.status()
        )));
    }
    if let Some(len) = resp.content_length()
        && len > max_bytes
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Remote payload '{url}' exceeds {max_bytes}-byte limit"
        )));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        CfmsError::Deployment(format!("Stream error downloading '{url}': {e}"))
    })? {
        if (out.len() as u64).saturating_add(chunk.len() as u64) > max_bytes {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Remote payload '{url}' exceeded {max_bytes}-byte streaming limit"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Download a verified GitHub release archive into an isolated temp directory and double-check
/// its SHA-256 digest against `SHA256SUMS.txt` and any non-null GitHub asset digest.
pub async fn download_verified_github_release(
    resolved: ResolvedGitHubRelease,
    ui_format: OutputFormat,
) -> Result<DownloadedGitHubPackage> {
    let client = build_http_client(None)?;
    let url = parse_safe_url(&resolved.asset.download_url, "release archive")?;
    let mut resp = client.get(url.clone()).send().await.map_err(|e| {
        CfmsError::Deployment(format!("Failed downloading release asset: {e}"))
    })?;
    if !resp.status().is_success() {
        return Err(CfmsError::Deployment(format!(
            "Failed downloading '{}': HTTP {}",
            resolved.asset.name,
            resp.status()
        )));
    }

    let expected_size = resp.content_length().unwrap_or(resolved.asset.size);
    if expected_size > MAX_PACKAGE_BYTES {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Release archive exceeds {MAX_PACKAGE_BYTES}-byte limit"
        )));
    }

    let temp_dir = tempfile::Builder::new().prefix("cfms-dl-").tempdir()?;
    let dest_path = temp_dir.path().join(&resolved.asset.name);

    let pb = if ui_format == OutputFormat::Human {
        let bar = ProgressBar::new(expected_size);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:32.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("=> "),
        );
        bar
    } else {
        ProgressBar::with_draw_target(None, ProgressDrawTarget::hidden())
    };

    let mut hasher = Sha256::new();
    let mut total = 0u64;
    {
        let mut writer = BufWriter::with_capacity(64 * 1024, File::create(&dest_path)?);
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            CfmsError::Deployment(format!("Stream error downloading '{}': {e}", resolved.asset.name))
        })? {
            let chunk_len = chunk.len() as u64;
            total = total.checked_add(chunk_len).ok_or_else(|| {
                CfmsError::ArchiveIntegrity("Download byte counter overflow".to_string())
            })?;
            if total > MAX_PACKAGE_BYTES {
                pb.finish_and_clear();
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Downloaded stream exceeded {MAX_PACKAGE_BYTES}-byte safety limit"
                )));
            }
            hasher.update(&chunk);
            writer.write_all(&chunk)?;
            pb.set_position(total);
        }
        writer.flush()?;
    }
    pb.finish_and_clear();

    let actual_sha256 = hex::encode(hasher.finalize());
    if actual_sha256 != resolved.asset.sha256sums_sha256 {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Downloaded '{}' SHA-256 ({actual_sha256}) disagrees with SHA256SUMS.txt ({})",
            resolved.asset.name, resolved.asset.sha256sums_sha256
        )));
    }
    if let Some(ref gh_digest) = resolved.asset.digest_sha256
        && &actual_sha256 != gh_digest
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Downloaded '{}' SHA-256 ({actual_sha256}) disagrees with GitHub asset digest ({gh_digest})",
            resolved.asset.name
        )));
    }

    Ok(DownloadedGitHubPackage {
        release: resolved,
        package_path: dest_path,
        sha256: actual_sha256,
        _temp_dir: temp_dir,
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tempfile::TempDir;

    use super::*;
    use super::super::archive::tests::write_test_targz;

    async fn spawn_mock_github_server(
        asset_name: String,
        asset_bytes: Vec<u8>,
        sums_body: String,
        digest_json: serde_json::Value,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let base_clone = base_url.clone();

        let handle = tokio::spawn(async move {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                let (status, content_type, body): (&str, &str, Vec<u8>) =
                    if path == "/repos/cfms-dev/cfms_on_websocket/releases/latest"
                        || path == "/repos/cfms-dev/cfms_on_websocket/releases/tags/v0.16.0"
                    {
                        let json = serde_json::json!({
                            "tag_name": "v0.16.0",
                            "draft": false,
                            "prerelease": false,
                            "html_url": format!("{base_clone}/releases/v0.16.0"),
                            "published_at": "2026-11-15T12:00:00Z",
                            "assets": [
                                {
                                    "name": asset_name,
                                    "size": asset_bytes.len(),
                                    "browser_download_url": format!("{base_clone}/dl/{asset_name}"),
                                    "digest": digest_json
                                },
                                {
                                    "name": "SHA256SUMS.txt",
                                    "size": sums_body.len(),
                                    "browser_download_url": format!("{base_clone}/dl/SHA256SUMS.txt"),
                                    "digest": null
                                }
                            ]
                        });
                        ("200 OK", "application/json", serde_json::to_vec(&json).unwrap())
                    } else if path == "/dl/SHA256SUMS.txt" {
                        ("200 OK", "text/plain", sums_body.as_bytes().to_vec())
                    } else if path == format!("/dl/{asset_name}") {
                        ("200 OK", "application/octet-stream", asset_bytes.clone())
                    } else {
                        ("404 Not Found", "text/plain", b"not found".to_vec())
                    };

                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            }
        });

        (base_url, handle)
    }

    #[tokio::test]
    async fn check_and_download_handles_targz_and_nullable_digest() {
        let tmp = TempDir::new().unwrap();
        let tgz_path = tmp.path().join("cfms-on-websocket-0.16.0.tar.gz");
        let sha = write_test_targz(&tgz_path, "0.16.0", b"print('v16')\n");
        let bytes = fs::read(&tgz_path).unwrap();
        let sums = format!("{sha}  cfms-on-websocket-0.16.0.tar.gz\n");

        let (mock_url, handle) = spawn_mock_github_server(
            "cfms-on-websocket-0.16.0.tar.gz".to_string(),
            bytes,
            sums,
            serde_json::Value::Null,
        )
        .await;

        let cfg = OnlineClientConfig {
            owner: DEFAULT_DEPLOY_REPO_OWNER.to_string(),
            repo: DEFAULT_DEPLOY_REPO_NAME.to_string(),
            api_base_url: Url::parse(&mock_url).unwrap(),
            auth_token: None,
        };

        let online = OnlineReleaseArgs {
            version: Some("0.16.0".to_string()),
            format: ReleaseArchiveFormat::TarGz,
            include_prerelease: false,
            repo: None,
        };

        // Strict digest mode rejects `digest: null`
        assert!(
            check_github_release_with_config(&cfg, &online, Some("0.15.0"), true)
                .await
                .is_err()
        );

        // Normal mode warns on null digest, relies on SHA256SUMS.txt, and streams verified download
        let report = check_github_release_with_config(&cfg, &online, Some("0.15.0"), false)
            .await
            .unwrap();
        assert!(report.update_available);
        assert_eq!(report.warnings.len(), 1);

        let resolved = fetch_and_resolve_release_with_config(&cfg, &online, false)
            .await
            .unwrap();
        let dl = download_verified_github_release(resolved, OutputFormat::Json).await.unwrap();
        assert_eq!(dl.sha256, sha);
        assert!(dl.package_path.is_file());

        handle.abort();
    }
}
