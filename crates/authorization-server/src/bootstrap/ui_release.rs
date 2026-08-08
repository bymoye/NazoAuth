use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, bail};
use flate2::read::GzDecoder;
use fs2::FileExt as _;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use url::Url;

use crate::config::{ConfigSource, DEFAULT_DATA_DIR};

const DEFAULT_FRONTEND: &str = include_str!("../../../../release/frontend.json");
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FrontendDescriptor {
    schema: u32,
    repository: String,
    version: String,
    commit: String,
    release_identity: String,
    artifact: FrontendArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FrontendArtifact {
    repository: String,
    name: String,
    sha256: String,
    size: u64,
}

pub(super) async fn resolve(config: &ConfigSource) -> anyhow::Result<Option<PathBuf>> {
    if config.optional_string("UI_STATIC_DIR").is_some() {
        let path = config.persistent_path("UI_STATIC_DIR", None)?;
        return Ok(Some(validate_static_directory(&path)?));
    }
    let descriptor: FrontendDescriptor = serde_json::from_str(DEFAULT_FRONTEND)
        .context("embedded frontend descriptor is invalid")?;
    descriptor.validate()?;
    let cache = match config.optional_string("UI_CACHE_DIR") {
        Some(_) => config.persistent_path("UI_CACHE_DIR", None)?,
        None => config
            .persistent_path("DATA_DIR", Some(DEFAULT_DATA_DIR))?
            .join("ui-releases"),
    };
    Ok(Some(ensure_cached(&cache, &descriptor).await?))
}

fn validate_static_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let path = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve UI_STATIC_DIR {}", path.display()))?;
    if !path.join("index.html").is_file() {
        bail!("UI_STATIC_DIR must contain index.html: {}", path.display());
    }
    Ok(path)
}

impl FrontendDescriptor {
    fn validate(&self) -> anyhow::Result<()> {
        let expected_identity = format!(
            "https://github.com/{}/.github/workflows/release.yml@refs/tags/{}",
            self.repository, self.version
        );
        if self.schema != 1
            || self.repository != "nazozero/NazoAuthWeb"
            || !semantic_tag(&self.version)
            || !lower_hex(&self.commit, 40)
            || self.release_identity != expected_identity
            || self.artifact.repository != self.repository
            || self.artifact.name != "nazoauth-web.tar.gz"
            || !lower_hex(&self.artifact.sha256, 64)
            || self.artifact.size == 0
            || self.artifact.size > MAX_ARCHIVE_BYTES
        {
            bail!("embedded frontend descriptor failed policy validation");
        }
        Ok(())
    }

    fn url(&self) -> anyhow::Result<Url> {
        Url::parse(&format!(
            "https://github.com/{}/releases/download/{}/{}",
            self.artifact.repository, self.version, self.artifact.name
        ))
        .context("frontend release URL is invalid")
    }
}

async fn ensure_cached(cache: &Path, descriptor: &FrontendDescriptor) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(cache)
        .with_context(|| format!("failed to create UI cache {}", cache.display()))?;
    let lock_path = cache.join(".lock");
    let _lock = tokio::task::spawn_blocking(move || -> anyhow::Result<File> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.lock_exclusive()?;
        Ok(lock)
    })
    .await
    .context("UI cache lock task failed")??;
    let target = cache.join(&descriptor.artifact.sha256);
    if cached_release_valid(&target, descriptor)? {
        return fs::canonicalize(target).context("failed to resolve cached UI release");
    }
    if target.exists() {
        bail!(
            "cached UI release failed validation and requires operator review: {}",
            target.display()
        );
    }
    let archive = cache.join(format!(".{}.download", descriptor.artifact.sha256));
    if archive.exists() {
        fs::remove_file(&archive)?;
    }
    download(&descriptor.url()?, descriptor, &archive).await?;
    let staging = cache.join(format!(".{}.extract", descriptor.artifact.sha256));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir(&staging)?;
    if let Err(error) = extract(&archive, &staging) {
        let _ = fs::remove_dir_all(&staging);
        let _ = fs::remove_file(&archive);
        return Err(error);
    }
    write_private(
        &staging.join(".nazoauth-ui.json"),
        &serde_json::to_vec(descriptor)?,
    )?;
    make_tree_read_only(&staging)?;
    fs::rename(&staging, &target)?;
    fs::remove_file(&archive)?;
    sync_directory(cache)?;
    fs::canonicalize(target).context("failed to resolve installed UI release")
}

async fn download(url: &Url, descriptor: &FrontendDescriptor, target: &Path) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !allowed_download_url(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    let response = client.get(url.clone()).send().await?.error_for_status()?;
    if !allowed_download_url(response.url()) {
        bail!("frontend download left the approved HTTPS origin set");
    }
    let mut stream = response.bytes_stream();
    let mut file = tokio::fs::File::create(target).await?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size = size
            .checked_add(chunk.len() as u64)
            .context("frontend archive size overflow")?;
        if size > descriptor.artifact.size || size > MAX_ARCHIVE_BYTES {
            bail!("frontend archive exceeds its signed size");
        }
        digest.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    if size != descriptor.artifact.size || hex(&digest.finalize()) != descriptor.artifact.sha256 {
        bail!("frontend archive does not match its signed digest and size");
    }
    Ok(())
}

fn allowed_download_url(url: &Url) -> bool {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.fragment().is_some()
    {
        return false;
    }
    matches!(
        url.host_str(),
        Some("github.com")
            | Some("objects.githubusercontent.com")
            | Some("release-assets.githubusercontent.com")
    )
}

fn extract(archive: &Path, target: &Path) -> anyhow::Result<()> {
    let source = File::open(archive)?;
    let mut archive = tar::Archive::new(GzDecoder::new(source));
    let mut entries = 0_usize;
    let mut expanded = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > MAX_ENTRIES {
            bail!("frontend archive contains too many entries");
        }
        let path = entry.path()?.into_owned();
        if !safe_relative(&path) {
            bail!("frontend archive contains an unsafe path");
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!("frontend archive contains a non-file entry");
        }
        expanded = expanded
            .checked_add(entry.header().size()?)
            .context("frontend expanded size overflow")?;
        if expanded > MAX_EXPANDED_BYTES {
            bail!("frontend archive expands beyond the safety limit");
        }
        entry.unpack_in(target)?;
    }
    if !target.join("index.html").is_file() {
        bail!("frontend archive has no index.html");
    }
    Ok(())
}

fn safe_relative(path: &Path) -> bool {
    let rendered = path.to_string_lossy();
    !path.as_os_str().is_empty()
        && !rendered.contains(['\\', ':'])
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn cached_release_valid(target: &Path, descriptor: &FrontendDescriptor) -> anyhow::Result<bool> {
    if !target.exists() {
        return Ok(false);
    }
    let marker = target.join(".nazoauth-ui.json");
    if !target.join("index.html").is_file() || !marker.is_file() {
        return Ok(false);
    }
    let current: FrontendDescriptor = serde_json::from_slice(&fs::read(marker)?)?;
    Ok(&current == descriptor)
}

fn write_private(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o400);
    }
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)?;
    Ok(())
}

fn make_tree_read_only(root: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            make_tree_read_only(&path)?;
        } else {
            set_read_only(&path, false)?;
        }
    }
    set_read_only(root, true)
}

fn set_read_only(path: &Path, _directory: bool) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if _directory { 0o555 } else { 0o444 }),
        )?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> anyhow::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn semantic_tag(value: &str) -> bool {
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    semver::Version::parse(version).is_ok_and(|parsed| parsed.to_string() == version)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
#[path = "../../tests/unit/ui_release.rs"]
mod tests;
