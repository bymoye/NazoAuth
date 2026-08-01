use super::{
    COSIGN_IMAGE, ReleaseTrustState, compare_versions, containerized_cosign_arguments,
    enforce_release_trust_state,
};
use crate::model::{Artifact, DatabaseRestore, ReleaseManifest, Rollback};
use nazo_operator_protocol::EmbeddedIdentity;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

fn manifest(version: &str) -> ReleaseManifest {
    let artifact = Artifact {
        name: "artifact".to_owned(),
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 3,
        version: version.to_owned(),
        backend_commit: "b".repeat(40),
        frontend_commit: "c".repeat(40),
        release_identity: "release-identity".to_owned(),
        image_ref: "example/image:tag".to_owned(),
        image_oci_digest: format!("sha256:{}", "d".repeat(64)),
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
            ("image".to_owned(), artifact.clone()),
            ("ui".to_owned(), artifact.clone()),
            ("binary".to_owned(), artifact.clone()),
            ("bootstrap".to_owned(), artifact.clone()),
            ("updater".to_owned(), artifact.clone()),
            ("updater_sbom".to_owned(), artifact.clone()),
            ("sbom".to_owned(), artifact),
        ]),
    }
}

fn state(version: &str) -> ReleaseTrustState {
    let manifest = manifest(version);
    ReleaseTrustState {
        schema: 1,
        version: manifest.version,
        backend_commit: manifest.backend_commit,
        image_oci_digest: manifest.image_oci_digest,
        release_identity: manifest.release_identity,
    }
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
    let args = containerized_cosign_arguments(
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
            "verify-blob",
            "--bundle",
            "/work/manifest.bundle",
            "--certificate-identity",
            "https://example.test/release-workflow@refs/tags/v1.0.0",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "/work/manifest.json",
        ]
    );
}
