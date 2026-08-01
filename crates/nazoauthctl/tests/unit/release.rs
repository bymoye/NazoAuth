use super::{
    AttestationResponse, COSIGN_IMAGE, RELEASE_PREDICATE, ReleaseTrustState,
    SIGSTORE_BUNDLE_MEDIA_TYPE, accept_verified_manifest, compare_versions,
    containerized_cosign_attestation_arguments, enforce_release_trust_state, manifest_from_bundle,
};
use crate::model::{
    Artifact, DatabaseRestore, FrontendRelease, OciRelease, ReleaseManifest, Rollback,
    release_target,
};
use base64::Engine as _;
use nazo_operator_protocol::EmbeddedIdentity;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

fn manifest(version: &str) -> ReleaseManifest {
    let target = release_target().unwrap().to_owned();
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let binary = Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name: format!("nazoauth-{target}{suffix}"),
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 4,
        version: version.to_owned(),
        target: target.clone(),
        backend_commit: "b".repeat(40),
        release_identity: format!(
            "https://github.com/nazozero/NazoAuth/.github/workflows/release-security.yml@refs/tags/{version}"
        ),
        embedded: EmbeddedIdentity {
            release: version.to_owned(),
            revision: "b".repeat(40),
            protocol: 1,
            build_id: "build".to_owned(),
        },
        rollback: Rollback {
            artifact: true,
            schema_compatible: true,
            database_restore: DatabaseRestore::Backup,
            irreversible_migration: false,
            minimum_supported_version: "1.0.0".to_owned(),
            migration_floor: "20260731000200".to_owned(),
            rationale: "test recovery policy".to_owned(),
        },
        artifacts: BTreeMap::from([
            ("binary".to_owned(), binary),
            (
                "updater".to_owned(),
                Artifact {
                    repository: "nazozero/NazoAuth".to_owned(),
                    name: format!("nazoauthctl-{target}{suffix}"),
                    sha256: "e".repeat(64),
                    size: 1,
                },
            ),
        ]),
        frontend: FrontendRelease {
            repository: "nazozero/NazoAuthWeb".to_owned(),
            version: "v0.2.0".to_owned(),
            commit: "c".repeat(40),
            release_identity: "https://github.com/nazozero/NazoAuthWeb/.github/workflows/release.yml@refs/tags/v0.2.0".to_owned(),
            artifact: Artifact {
                repository: "nazozero/NazoAuthWeb".to_owned(),
                name: "nazoauth-web.tar.gz".to_owned(),
                sha256: "f".repeat(64),
                size: 1,
            },
        },
        oci: OciRelease {
            repository: "ghcr.io/nazozero/nazoauth".to_owned(),
            index_digest: format!("sha256:{}", "d".repeat(64)),
            platform_manifests: BTreeMap::from([
                (
                    "linux/amd64".to_owned(),
                    format!("sha256:{}", "1".repeat(64)),
                ),
                (
                    "linux/arm64".to_owned(),
                    format!("sha256:{}", "2".repeat(64)),
                ),
            ]),
        },
    }
}

fn state(version: &str) -> ReleaseTrustState {
    let manifest = manifest(version);
    let image_oci_digest = manifest.image_oci_digest().to_owned();
    ReleaseTrustState {
        schema: 1,
        version: manifest.version,
        backend_commit: manifest.backend_commit,
        image_oci_digest,
        release_identity: manifest.release_identity,
    }
}

#[test]
fn github_attestation_response_accepts_current_inline_bundle() {
    let response: AttestationResponse = serde_json::from_value(serde_json::json!({
        "attestations": [{
            "bundle_url": "https://tmaproduction.blob.core.windows.net/example/bundle.json.sn",
            "initiator": "github-actions",
            "repository_id": 123,
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"
            }
        }]
    }))
    .unwrap();

    assert_eq!(response.attestations.len(), 1);
    assert_eq!(
        response.attestations[0]
            .bundle
            .get("mediaType")
            .and_then(serde_json::Value::as_str),
        Some(SIGSTORE_BUNDLE_MEDIA_TYPE)
    );
}

#[test]
fn semantic_precedence_prevents_prerelease_downgrades() {
    assert_eq!(
        compare_versions("v1.0.0-rc.1", "v1.0.0").unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_versions("v1.0.0", "v1.0.0-rc.9").unwrap(),
        Ordering::Greater
    );
    assert_eq!(
        compare_versions("v1.0.0-rc.10", "v1.0.0-rc.2").unwrap(),
        Ordering::Greater
    );
    assert_eq!(
        compare_versions("v1.0.0+build.2", "v1.0.0+build.1").unwrap(),
        Ordering::Equal
    );
    assert!(compare_versions("latest", "v1.0.0").is_err());
}

#[test]
fn trust_state_rejects_downgrade_and_same_version_identity_substitution() {
    let trusted = state("v2.0.0");
    assert!(enforce_release_trust_state(&trusted, &manifest("v1.9.9")).is_err());

    let mut substituted = manifest("v2.0.0");
    substituted.backend_commit = "e".repeat(40);
    assert!(enforce_release_trust_state(&trusted, &substituted).is_err());

    assert!(enforce_release_trust_state(&trusted, &manifest("v2.0.1")).is_ok());
}

#[test]
fn containerized_cosign_policy_can_read_private_staging_without_host_privileges() {
    let args = containerized_cosign_attestation_arguments(
        Path::new("/private/release"),
        "manifest.bundle",
        "manifest.json",
        "https://example.test/release-workflow@refs/tags/v1.0.0",
    );

    assert_eq!(
        args,
        vec![
            "run",
            "--rm",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/root/.sigstore:rw,noexec,nosuid,nodev,size=16m",
            "-v",
            "/private/release:/work:ro",
            COSIGN_IMAGE,
            "verify-blob-attestation",
            "--bundle",
            "/work/manifest.bundle",
            "--type",
            RELEASE_PREDICATE,
            "--certificate-identity",
            "https://example.test/release-workflow@refs/tags/v1.0.0",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "/work/manifest.json",
        ]
    );
}

#[test]
fn release_manifest_validation_is_closed_over_target_frontend_and_oci() {
    let value = manifest("v1.2.3");
    let identity = value.release_identity.clone();
    value.validate("v1.2.3", &identity).unwrap();

    let mut changed = value.clone();
    changed.target = "unsupported-target".to_owned();
    assert!(changed.validate("v1.2.3", &identity).is_err());

    let mut changed = value.clone();
    changed.frontend.artifact.repository = "nazozero/NazoAuth".to_owned();
    assert!(changed.validate("v1.2.3", &identity).is_err());

    let mut changed = value.clone();
    changed.oci.platform_manifests.remove("linux/arm64");
    assert!(changed.validate("v1.2.3", &identity).is_err());

    let mut changed = value;
    changed
        .artifacts
        .insert("unexpected".to_owned(), changed.artifacts["binary"].clone());
    assert!(changed.validate("v1.2.3", &identity).is_err());
}

#[test]
fn repeated_identical_attestations_are_idempotent_but_conflicts_fail() {
    let first = manifest("v1.2.3");
    let mut verified = None;
    accept_verified_manifest(&mut verified, first.clone()).unwrap();
    accept_verified_manifest(&mut verified, first.clone()).unwrap();
    assert_eq!(verified, Some(first.clone()));

    let mut conflict = first;
    conflict.backend_commit = "9".repeat(40);
    assert!(accept_verified_manifest(&mut verified, conflict).is_err());
}

#[test]
fn dsse_statement_must_bind_the_updater_subject_and_custom_predicate() {
    let value = manifest("v1.2.3");
    let updater = &value.artifacts["updater"];
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": updater.name,
            "digest": {"sha256": updater.sha256},
        }],
        "predicateType": RELEASE_PREDICATE,
        "predicate": value,
    });
    let bundle = serde_json::json!({
        "dsseEnvelope": {
            "payload": base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&statement).unwrap()
            )
        }
    });
    assert_eq!(
        manifest_from_bundle(&bundle, &updater.name, &updater.sha256)
            .unwrap()
            .unwrap(),
        value
    );
    assert!(manifest_from_bundle(&bundle, "wrong-updater", &updater.sha256).is_err());
}
