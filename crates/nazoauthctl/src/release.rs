use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    filesystem::atomic_write,
    filesystem::{PrivateTempDir, sha256},
    model::{Artifact, ReleaseManifest, release_target, semantic_tag},
    process::{Process, command_exists},
};

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
const RELEASE_PREDICATE: &str = "https://nazo.run/attestations/release-manifest/v1";
const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
const MAX_ATTESTATIONS: usize = 20;
const ATTESTATION_PAGE_SIZE: usize = MAX_ATTESTATIONS + 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationResponse {
    attestations: Vec<Attestation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    #[serde(rename = "bundle_url")]
    _bundle_url: String,
    initiator: String,
    repository_id: u64,
    bundle: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    kind: String,
    subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InTotoSubject {
    name: String,
    digest: BTreeMap<String, String>,
}

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
                || manifest.image_oci_digest() != state.image_oci_digest
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
        image_oci_digest: manifest.image_oci_digest().to_owned(),
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
        let target = release_target().context("this platform has no official Release binary")?;
        let suffix = if target.contains("windows") {
            ".exe"
        } else {
            ""
        };
        let updater = format!("nazoauthctl-{target}{suffix}");
        download(repository, &version, &updater, work.path())?;
        let identity = format!(
            "https://github.com/{repository}/.github/workflows/release-security.yml@refs/tags/{version}"
        );
        let manifest = verified_attested_manifest(
            repository,
            &version,
            work.path(),
            &updater,
            &identity,
            container_engine,
        )?;
        manifest.validate(&version, &identity)?;
        Ok(Self { work, manifest })
    }

    pub(crate) fn artifact(&self, key: &str, repository: &str) -> anyhow::Result<PathBuf> {
        let artifact = self
            .manifest
            .artifacts
            .get(key)
            .with_context(|| format!("release manifest does not contain {key}"))?;
        if artifact.repository != repository {
            bail!("release artifact repository does not match controller policy");
        }
        let path = self.work.path().join(&artifact.name);
        if !path.exists() {
            download(
                &artifact.repository,
                &self.manifest.version,
                &artifact.name,
                self.work.path(),
            )?;
            verify_artifact(&path, artifact)?;
        }
        Ok(path)
    }
}

fn verified_attested_manifest(
    repository: &str,
    version: &str,
    work: &Path,
    blob: &str,
    identity: &str,
    container_engine: Option<&str>,
) -> anyhow::Result<ReleaseManifest> {
    let digest = sha256(&work.join(blob))?;
    let response = Process::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "30",
            "--max-filesize",
            "10485760",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            &format!(
                "https://api.github.com/repos/{repository}/attestations/sha256%3A{digest}?per_page={ATTESTATION_PAGE_SIZE}&predicate_type={}",
                urlencoding::encode(RELEASE_PREDICATE)
            ),
        ])
        .stdout()?;
    verified_manifest_from_attestations(
        &response,
        version,
        work,
        blob,
        &digest,
        identity,
        |work, bundle, blob, identity| {
            verify_blob_attestation(work, bundle, blob, identity, container_engine)
        },
    )
}

fn verified_manifest_from_attestations(
    response: &str,
    version: &str,
    work: &Path,
    blob: &str,
    digest: &str,
    identity: &str,
    mut verify_attestation: impl FnMut(&Path, &str, &str, &str) -> anyhow::Result<()>,
) -> anyhow::Result<ReleaseManifest> {
    let response: AttestationResponse =
        serde_json::from_str(response).context("GitHub attestation response is invalid")?;
    if response.attestations.is_empty() || response.attestations.len() > MAX_ATTESTATIONS {
        bail!("GitHub returned no bounded Release attestation set");
    }
    let mut verified: Option<ReleaseManifest> = None;
    for (index, attestation) in response.attestations.into_iter().enumerate() {
        let bundle_name = format!("release-attestation-{index}.json");
        if attestation.repository_id == 0 || attestation.initiator.trim().is_empty() {
            bail!("GitHub returned invalid Release attestation metadata");
        }
        if attestation
            .bundle
            .get("mediaType")
            .and_then(serde_json::Value::as_str)
            != Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
        {
            bail!("GitHub returned an unsupported Sigstore bundle");
        }
        atomic_write(
            &work.join(&bundle_name),
            &serde_json::to_vec(&attestation.bundle)?,
            0o600,
        )?;
        let Some(candidate) = manifest_from_bundle(&attestation.bundle, blob, digest)? else {
            continue;
        };
        if candidate.version != version || candidate.release_identity != identity {
            continue;
        }
        verify_attestation(work, &bundle_name, blob, identity)?;
        candidate.validate(version, identity)?;
        let updater = candidate
            .artifacts
            .get("updater")
            .context("Release attestation has no updater")?;
        if updater.name != blob
            || updater.sha256 != digest
            || updater.size != fs::metadata(work.join(blob))?.len()
        {
            bail!("Release attestation does not bind the downloaded updater");
        }
        accept_verified_manifest(&mut verified, candidate)?;
    }
    verified.context("no verified Release attestation matched the requested target")
}

fn accept_verified_manifest(
    verified: &mut Option<ReleaseManifest>,
    candidate: ReleaseManifest,
) -> anyhow::Result<()> {
    if let Some(existing) = verified {
        if existing == &candidate {
            return Ok(());
        }
        bail!("matching Release attestations contain conflicting predicates");
    }
    *verified = Some(candidate);
    Ok(())
}

fn manifest_from_bundle(
    bundle: &serde_json::Value,
    blob: &str,
    digest: &str,
) -> anyhow::Result<Option<ReleaseManifest>> {
    let payload = bundle
        .get("dsseEnvelope")
        .and_then(|envelope| envelope.get("payload"))
        .and_then(serde_json::Value::as_str)
        .context("Release attestation has no DSSE payload")?;
    let statement: InTotoStatement = serde_json::from_slice(
        &STANDARD
            .decode(payload)
            .context("Release attestation payload is not base64")?,
    )
    .context("Release attestation statement is invalid")?;
    if statement.kind != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != RELEASE_PREDICATE
    {
        return Ok(None);
    }
    if !statement.subject.iter().any(|subject| {
        subject.name == blob
            && subject
                .digest
                .get("sha256")
                .is_some_and(|subject_digest| subject_digest == digest)
    }) {
        bail!("Release attestation subject does not bind the downloaded updater");
    }
    let manifest = serde_json::from_value(statement.predicate)
        .context("Release attestation predicate is not a closed manifest")?;
    Ok(Some(manifest))
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
            "--proto-redir",
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
            "--proto-redir",
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

fn verify_blob_attestation(
    work: &Path,
    bundle: &str,
    blob: &str,
    identity: &str,
    container_engine: Option<&str>,
) -> anyhow::Result<()> {
    if command_exists("cosign") {
        return Process::new("cosign")
            .args(["verify-blob-attestation", "--bundle"])
            .arg(work.join(bundle))
            .args([
                "--type",
                RELEASE_PREDICATE,
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
        .args(containerized_cosign_attestation_arguments(
            work, bundle, blob, identity,
        ))
        .run_quiet()
}

fn containerized_cosign_attestation_arguments(
    work: &Path,
    bundle: &str,
    blob: &str,
    identity: &str,
) -> Vec<String> {
    vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--user".to_owned(),
        "0:0".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--read-only".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--pids-limit".to_owned(),
        "64".to_owned(),
        "--tmpfs".to_owned(),
        "/root/.sigstore:rw,noexec,nosuid,nodev,size=16m".to_owned(),
        "-v".to_owned(),
        format!("{}:/work:ro", work.display()),
        COSIGN_IMAGE.to_owned(),
        "verify-blob-attestation".to_owned(),
        "--bundle".to_owned(),
        format!("/work/{bundle}"),
        "--type".to_owned(),
        RELEASE_PREDICATE.to_owned(),
        "--certificate-identity".to_owned(),
        identity.to_owned(),
        "--certificate-oidc-issuer".to_owned(),
        "https://token.actions.githubusercontent.com".to_owned(),
        format!("/work/{blob}"),
    ]
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
