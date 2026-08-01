use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};

use crate::{
    filesystem::atomic_write,
    filesystem::{PrivateTempDir, sha256},
    model::{Artifact, ReleaseManifest, semantic_tag},
    process::{Process, command_exists},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustState {
    schema: u32,
    version: String,
    backend_commit: String,
    image_oci_digest: String,
    release_identity: String,
}

const COSIGN_IMAGE: &str = "ghcr.io/sigstore/cosign/cosign@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00";

pub(crate) struct VerifiedRelease {
    work: PrivateTempDir,
    pub(crate) manifest: ReleaseManifest,
}

pub(crate) fn enforce_release_trust(
    config: &crate::model::UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    let path = &config.operator.trust_state_file;
    if !path.exists() {
        return Ok(());
    }
    let state: ReleaseTrustState =
        serde_json::from_slice(&fs::read(path)?).context("Release trust state is invalid")?;
    if state.schema != 1 {
        bail!("unsupported Release trust state");
    }
    enforce_release_trust_state(&state, manifest)
}

fn enforce_release_trust_state(
    state: &ReleaseTrustState,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    match compare_versions(&manifest.version, &state.version)? {
        std::cmp::Ordering::Less => bail!(
            "Release anti-downgrade policy rejected {} below trusted {}; use the explicit rollback or break-glass recovery flow",
            manifest.version,
            state.version
        ),
        std::cmp::Ordering::Equal => {
            if manifest.backend_commit != state.backend_commit
                || manifest.image_oci_digest != state.image_oci_digest
                || manifest.release_identity != state.release_identity
            {
                bail!("immutable Release identity changed for an already trusted version");
            }
        }
        std::cmp::Ordering::Greater => {}
    }
    Ok(())
}

pub(crate) fn commit_release_trust(
    config: &crate::model::UpdateConfig,
    manifest: &ReleaseManifest,
) -> anyhow::Result<()> {
    let state = ReleaseTrustState {
        schema: 1,
        version: manifest.version.clone(),
        backend_commit: manifest.backend_commit.clone(),
        image_oci_digest: manifest.image_oci_digest.clone(),
        release_identity: manifest.release_identity.clone(),
    };
    atomic_write(
        &config.operator.trust_state_file,
        &serde_json::to_vec_pretty(&state)?,
        0o600,
    )
}

pub(crate) fn compare_versions(left: &str, right: &str) -> anyhow::Result<std::cmp::Ordering> {
    fn parse(value: &str) -> anyhow::Result<semver::Version> {
        let value = value
            .strip_prefix('v')
            .context("Release version has no v prefix")?;
        semver::Version::parse(value).context("Release version is not semantic")
    }
    Ok(parse(left)?.cmp_precedence(&parse(right)?))
}

impl VerifiedRelease {
    pub(crate) fn fetch(
        repository: &str,
        requested_version: Option<&str>,
        container_engine: Option<&str>,
    ) -> anyhow::Result<Self> {
        let version = resolve_version(repository, requested_version)?;
        let work = PrivateTempDir::new("nazoauth-release")?;
        download(repository, &version, "release-manifest.json", work.path())?;
        download(
            repository,
            &version,
            "release-manifest.json.bundle",
            work.path(),
        )?;
        let identity = format!(
            "https://github.com/{repository}/.github/workflows/release-security.yml@refs/tags/{version}"
        );
        verify_blob(
            work.path(),
            "release-manifest.json.bundle",
            "release-manifest.json",
            &identity,
            container_engine,
        )?;
        let manifest: ReleaseManifest = serde_json::from_slice(
            &fs::read(work.path().join("release-manifest.json"))
                .context("failed to read signed release manifest")?,
        )
        .context("signed release manifest is not valid JSON")?;
        manifest.validate(&version, &identity)?;
        Ok(Self { work, manifest })
    }

    pub(crate) fn artifact(&self, key: &str, repository: &str) -> anyhow::Result<PathBuf> {
        let artifact = self
            .manifest
            .artifacts
            .get(key)
            .with_context(|| format!("release manifest does not contain {key}"))?;
        let path = self.work.path().join(&artifact.name);
        if !path.exists() {
            download(
                repository,
                &self.manifest.version,
                &artifact.name,
                self.work.path(),
            )?;
            verify_artifact(&path, artifact)?;
        }
        Ok(path)
    }
}

fn resolve_version(repository: &str, requested: Option<&str>) -> anyhow::Result<String> {
    if let Some(version) = requested {
        if !semantic_tag(version) {
            bail!("release version is not an immutable semantic tag");
        }
        return Ok(version.to_owned());
    }
    let response = Process::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-H",
            "Accept: application/vnd.github+json",
            &format!("https://api.github.com/repos/{repository}/releases/latest"),
        ])
        .stdout()?;
    let value: serde_json::Value =
        serde_json::from_str(&response).context("GitHub latest release response is invalid")?;
    let version = value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .context("GitHub latest release response has no tag_name")?;
    if !semantic_tag(version) {
        bail!("release version is not an immutable semantic tag");
    }
    Ok(version.to_owned())
}

fn download(repository: &str, version: &str, name: &str, destination: &Path) -> anyhow::Result<()> {
    Process::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--output",
        ])
        .arg(destination.join(name))
        .arg(format!(
            "https://github.com/{repository}/releases/download/{version}/{name}"
        ))
        .run_quiet()
}

fn verify_blob(
    work: &Path,
    bundle: &str,
    blob: &str,
    identity: &str,
    container_engine: Option<&str>,
) -> anyhow::Result<()> {
    if command_exists("cosign") {
        return Process::new("cosign")
            .args(["verify-blob", "--bundle"])
            .arg(work.join(bundle))
            .args([
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ])
            .arg(work.join(blob))
            .run_quiet();
    }
    let engine = container_engine.context("Cosign is required when no container engine exists")?;
    Process::new(engine)
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/work:ro", work.display()))
        .arg(COSIGN_IMAGE)
        .args([
            "verify-blob",
            "--bundle",
            &format!("/work/{bundle}"),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            &format!("/work/{blob}"),
        ])
        .run_quiet()
}

fn verify_artifact(path: &Path, artifact: &Artifact) -> anyhow::Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() != artifact.size {
        bail!("artifact size mismatch: {}", artifact.name);
    }
    if sha256(path)? != artifact.sha256 {
        bail!("artifact digest mismatch: {}", artifact.name);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/release.rs"]
mod tests;
