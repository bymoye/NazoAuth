use super::{
    AttestationResponse, COSIGN_IMAGE, RELEASE_PREDICATE, ReleaseTrustState,
    SIGSTORE_BUNDLE_MEDIA_TYPE, VerifiedRelease, accept_verified_manifest, commit_release_trust,
    compare_versions, containerized_cosign_attestation_arguments, enforce_release_trust,
    enforce_release_trust_state, manifest_from_bundle, resolve_version,
    verified_manifest_from_attestations, verify_artifact,
};
use crate::filesystem::{PrivateTempDir, atomic_write, sha256};
use crate::model::{
    Artifact, DatabaseRestore, Dependencies, FrontendRelease, OciRelease, Operator, Postgres,
    ReleaseManifest, Rollback, Runtime, Ui, UpdateConfig, Valkey, release_target,
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

fn bundle(statement: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
        "dsseEnvelope": {
            "payload": base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(statement).unwrap()
            )
        }
    })
}

fn attestation(bundle: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "bundle_url": "https://example.test/bundle.json",
        "initiator": "github-actions",
        "repository_id": 123,
        "bundle": bundle,
    })
}

fn statement(value: &ReleaseManifest, blob: &str, digest: &str) -> serde_json::Value {
    serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": blob,
            "digest": {"sha256": digest},
        }],
        "predicateType": RELEASE_PREDICATE,
        "predicate": value,
    })
}

fn attestation_response(attestations: Vec<serde_json::Value>) -> String {
    serde_json::json!({"attestations": attestations}).to_string()
}

fn prepared_attestation() -> (PrivateTempDir, String, String, ReleaseManifest, String) {
    let work = PrivateTempDir::new("release-attestation-test").unwrap();
    let mut value = manifest("v1.2.3");
    let blob = value.artifacts["updater"].name.clone();
    atomic_write(&work.path().join(&blob), b"x", 0o600).unwrap();
    let digest = sha256(&work.path().join(&blob)).unwrap();
    value.artifacts.get_mut("updater").unwrap().sha256 = digest.clone();
    let identity = value.release_identity.clone();
    (work, blob, digest, value, identity)
}

fn config(work: &PrivateTempDir) -> UpdateConfig {
    let path = |name: &str| work.path().join(name);
    UpdateConfig {
        schema: 2,
        managed_install: true,
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: path("nazoauthctl"),
        backup_root: path("backups"),
        deployment_root: path("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: path("operator/controller.key"),
            controller_public_key: path("operator/controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: path("operator/receipt.key"),
            receipt_public_key: path("operator/receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: path("operator/audit.key"),
            audit_public_key: path("operator/audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: path("operator/break-glass.key"),
            break_glass_public_key: path("operator/break-glass.pub"),
            secret_revision_file: path("operator/secret-revision"),
            state_directory: path("operator-state"),
            audit_directory: path("audit"),
            trust_state_file: path("operator/release-trust.json"),
        },
        dependencies: Dependencies::default(),
        runtime: Runtime {
            engine: "host".to_owned(),
            dependency_engine: String::new(),
            container_name: "nazoauth".to_owned(),
            network: "nazoauth".to_owned(),
            ip_address: String::new(),
            publish_address: String::new(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 1,
            readiness_interval_seconds: 0,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: Vec::new(),
            snapshot_paths: Vec::new(),
            environment: BTreeMap::new(),
            service_name: "nazoauth.service".to_owned(),
            service_user: "nazoauth".to_owned(),
            binary_path: path("nazoauth"),
            binary_releases: path("releases"),
            working_directory: work.path().to_owned(),
        },
        postgres: Postgres {
            container_name: "postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "migrator".to_owned(),
            image: "postgres".to_owned(),
            validation_image: "postgres".to_owned(),
        },
        valkey: Valkey {
            container_name: "valkey".to_owned(),
            image: "valkey".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: path("valkey-password"),
        },
        ui: Ui {
            releases_root: path("ui-releases"),
        },
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
fn github_attestation_response_is_a_closed_schema() {
    for invalid in [
        serde_json::json!({}),
        serde_json::json!({"attestations": [], "unexpected": true}),
        serde_json::json!({"attestations": [{
            "bundle_url": "https://example.test/bundle.json",
            "initiator": "github-actions",
            "repository_id": 123,
        }]}),
        serde_json::json!({"attestations": [{
            "bundle_url": "https://example.test/bundle.json",
            "initiator": "github-actions",
            "repository_id": 123,
            "bundle": {},
            "unexpected": true,
        }]}),
    ] {
        assert!(serde_json::from_value::<AttestationResponse>(invalid).is_err());
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
fn trust_state_binds_every_same_version_release_identity_component() {
    let trusted = state("v2.0.0");
    assert!(enforce_release_trust_state(&trusted, &manifest("v2.0.0")).is_ok());

    let mut substituted = manifest("v2.0.0");
    substituted.oci.index_digest = format!("sha256:{}", "9".repeat(64));
    assert!(enforce_release_trust_state(&trusted, &substituted).is_err());

    let mut substituted = manifest("v2.0.0");
    substituted.release_identity = "https://example.test/substituted".to_owned();
    assert!(enforce_release_trust_state(&trusted, &substituted).is_err());
}

#[test]
fn persisted_release_trust_is_private_closed_and_oci_index_bound() {
    let work = PrivateTempDir::new("release-trust-test").unwrap();
    let config = config(&work);
    let value = manifest("v2.0.0");

    enforce_release_trust(&config, &value).unwrap();
    commit_release_trust(&config, &value).unwrap();
    let persisted: ReleaseTrustState =
        serde_json::from_slice(&std::fs::read(&config.operator.trust_state_file).unwrap()).unwrap();
    assert_eq!(persisted.schema, 1);
    assert_eq!(persisted.version, value.version);
    assert_eq!(persisted.backend_commit, value.backend_commit);
    assert_eq!(persisted.image_oci_digest, value.oci.index_digest);
    assert_eq!(persisted.release_identity, value.release_identity);
    enforce_release_trust(&config, &value).unwrap();

    let mut unsupported = persisted;
    unsupported.schema = 2;
    atomic_write(
        &config.operator.trust_state_file,
        &serde_json::to_vec(&unsupported).unwrap(),
        0o600,
    )
    .unwrap();
    assert!(enforce_release_trust(&config, &value).is_err());

    atomic_write(&config.operator.trust_state_file, b"not-json", 0o600).unwrap();
    assert!(enforce_release_trust(&config, &value).is_err());
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
fn release_manifest_rejects_oci_repository_index_and_platform_digest_substitution() {
    let value = manifest("v1.2.3");
    let identity = value.release_identity.clone();
    let invalid = [
        {
            let mut changed = value.clone();
            changed.oci.repository = "ghcr.io/attacker/nazoauth".to_owned();
            changed
        },
        {
            let mut changed = value.clone();
            changed.oci.index_digest = "sha256:not-a-digest".to_owned();
            changed
        },
        {
            let mut changed = value.clone();
            changed.oci.platform_manifests.insert(
                "linux/amd64".to_owned(),
                format!("sha256:{}", "A".repeat(64)),
            );
            changed
        },
        {
            let mut changed = value.clone();
            changed.oci.platform_manifests.insert(
                "linux/s390x".to_owned(),
                format!("sha256:{}", "3".repeat(64)),
            );
            changed
        },
    ];
    for changed in invalid {
        assert!(changed.validate("v1.2.3", &identity).is_err());
    }

    assert_eq!(value.image_oci_digest(), value.oci.index_digest);
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    assert_eq!(
        value.image_ref().unwrap(),
        format!(
            "{}@{}",
            value.oci.repository, value.oci.platform_manifests["linux/amd64"]
        )
    );
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    assert_eq!(
        value.image_ref().unwrap(),
        format!(
            "{}@{}",
            value.oci.repository, value.oci.platform_manifests["linux/arm64"]
        )
    );
    #[cfg(not(target_os = "linux"))]
    assert!(value.image_ref().is_err());
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

#[test]
fn dsse_statement_parser_fails_closed_for_malformed_or_unrelated_payloads() {
    let value = manifest("v1.2.3");
    let updater = &value.artifacts["updater"];

    assert!(manifest_from_bundle(&serde_json::json!({}), &updater.name, &updater.sha256).is_err());
    assert!(
        manifest_from_bundle(
            &serde_json::json!({"dsseEnvelope": {"payload": "%%%"}}),
            &updater.name,
            &updater.sha256,
        )
        .is_err()
    );
    let invalid_json = serde_json::json!({
        "dsseEnvelope": {
            "payload": base64::engine::general_purpose::STANDARD.encode(b"not-json")
        }
    });
    assert!(manifest_from_bundle(&invalid_json, &updater.name, &updater.sha256).is_err());

    let mut unrelated = statement(&value, &updater.name, &updater.sha256);
    unrelated["_type"] = serde_json::json!("https://in-toto.io/Statement/v0.1");
    assert!(
        manifest_from_bundle(&bundle(&unrelated), &updater.name, &updater.sha256)
            .unwrap()
            .is_none()
    );
    let mut unrelated = statement(&value, &updater.name, &updater.sha256);
    unrelated["predicateType"] = serde_json::json!("https://example.test/other-predicate");
    assert!(
        manifest_from_bundle(&bundle(&unrelated), &updater.name, &updater.sha256)
            .unwrap()
            .is_none()
    );

    for digest in [
        serde_json::json!({"sha256": "0".repeat(64)}),
        serde_json::json!({"sha512": updater.sha256}),
        serde_json::json!({}),
    ] {
        let mut unbound = statement(&value, &updater.name, &updater.sha256);
        unbound["subject"][0]["digest"] = digest;
        assert!(manifest_from_bundle(&bundle(&unbound), &updater.name, &updater.sha256).is_err());
    }

    let mut invalid_predicate = statement(&value, &updater.name, &updater.sha256);
    invalid_predicate["predicate"] = serde_json::json!({"schema": 4});
    assert!(
        manifest_from_bundle(&bundle(&invalid_predicate), &updater.name, &updater.sha256,).is_err()
    );
}

#[test]
fn attestation_set_accepts_only_verified_target_bound_manifests() {
    let (work, blob, digest, value, identity) = prepared_attestation();
    let response = attestation_response(vec![attestation(bundle(&statement(
        &value, &blob, &digest,
    )))]);
    let mut verification_calls = 0;
    let verified = verified_manifest_from_attestations(
        &response,
        "v1.2.3",
        work.path(),
        &blob,
        &digest,
        &identity,
        |path, bundle_name, verified_blob, verified_identity| {
            verification_calls += 1;
            assert!(path.join(bundle_name).is_file());
            assert_eq!(verified_blob, blob);
            assert_eq!(verified_identity, identity);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(verified, value);
    assert_eq!(verification_calls, 1);
}

#[test]
fn attestation_set_rejects_unbounded_invalid_or_unsupported_responses() {
    let (work, blob, digest, value, identity) = prepared_attestation();
    let valid = attestation(bundle(&statement(&value, &blob, &digest)));
    let responses = [
        "not-json".to_owned(),
        serde_json::json!({"attestations": [], "unexpected": true}).to_string(),
        attestation_response(vec![]),
        attestation_response(vec![valid.clone(); 21]),
        attestation_response(vec![serde_json::json!({
            "bundle_url": "https://example.test/bundle.json",
            "initiator": "github-actions",
            "repository_id": 0,
            "bundle": bundle(&statement(&value, &blob, &digest)),
        })]),
        attestation_response(vec![serde_json::json!({
            "bundle_url": "https://example.test/bundle.json",
            "initiator": " ",
            "repository_id": 123,
            "bundle": bundle(&statement(&value, &blob, &digest)),
        })]),
        attestation_response(vec![attestation(serde_json::json!({
            "mediaType": "application/json",
            "dsseEnvelope": {"payload": "ignored"},
        }))]),
    ];

    for response in responses {
        assert!(
            verified_manifest_from_attestations(
                &response,
                "v1.2.3",
                work.path(),
                &blob,
                &digest,
                &identity,
                |_, _, _, _| panic!("invalid responses must not reach signature verification"),
            )
            .is_err()
        );
    }
}

#[test]
fn attestation_set_skips_unrelated_release_claims_before_signature_verification() {
    let (work, blob, digest, value, identity) = prepared_attestation();
    let mut wrong_version = value.clone();
    wrong_version.version = "v9.9.9".to_owned();
    wrong_version.embedded.release = wrong_version.version.clone();
    let mut wrong_identity = value.clone();
    wrong_identity.release_identity = "https://example.test/wrong".to_owned();
    let mut wrong_statement_kind = statement(&value, &blob, &digest);
    wrong_statement_kind["_type"] = serde_json::json!("https://in-toto.io/Statement/v0.1");
    let response = attestation_response(vec![
        attestation(bundle(&statement(&wrong_version, &blob, &digest))),
        attestation(bundle(&statement(&wrong_identity, &blob, &digest))),
        attestation(bundle(&wrong_statement_kind)),
    ]);

    assert!(
        verified_manifest_from_attestations(
            &response,
            "v1.2.3",
            work.path(),
            &blob,
            &digest,
            &identity,
            |_, _, _, _| panic!("unrelated claims must not reach signature verification"),
        )
        .is_err()
    );
}

#[test]
fn attestation_set_propagates_signature_manifest_updater_and_conflict_failures() {
    let (work, blob, digest, value, identity) = prepared_attestation();
    let valid = attestation(bundle(&statement(&value, &blob, &digest)));
    let response = attestation_response(vec![valid.clone()]);
    assert!(
        verified_manifest_from_attestations(
            &response,
            "v1.2.3",
            work.path(),
            &blob,
            &digest,
            &identity,
            |_, _, _, _| anyhow::bail!("signature rejected"),
        )
        .is_err()
    );

    let mut invalid_manifest = value.clone();
    invalid_manifest.schema = 3;
    let response = attestation_response(vec![attestation(bundle(&statement(
        &invalid_manifest,
        &blob,
        &digest,
    )))]);
    assert!(
        verified_manifest_from_attestations(
            &response,
            "v1.2.3",
            work.path(),
            &blob,
            &digest,
            &identity,
            |_, _, _, _| Ok(()),
        )
        .is_err()
    );

    let mut size_substitution = value.clone();
    size_substitution.artifacts.get_mut("updater").unwrap().size = 2;
    let response = attestation_response(vec![attestation(bundle(&statement(
        &size_substitution,
        &blob,
        &digest,
    )))]);
    assert!(
        verified_manifest_from_attestations(
            &response,
            "v1.2.3",
            work.path(),
            &blob,
            &digest,
            &identity,
            |_, _, _, _| Ok(()),
        )
        .is_err()
    );

    let mut digest_substitution = value.clone();
    digest_substitution
        .artifacts
        .get_mut("updater")
        .unwrap()
        .sha256 = "9".repeat(64);
    let response = attestation_response(vec![attestation(bundle(&statement(
        &digest_substitution,
        &blob,
        &digest,
    )))]);
    assert!(
        verified_manifest_from_attestations(
            &response,
            "v1.2.3",
            work.path(),
            &blob,
            &digest,
            &identity,
            |_, _, _, _| Ok(()),
        )
        .is_err()
    );

    let mut conflict = value.clone();
    conflict.rollback.rationale = "different but valid policy".to_owned();
    let response = attestation_response(vec![
        valid,
        attestation(bundle(&statement(&conflict, &blob, &digest))),
    ]);
    assert!(
        verified_manifest_from_attestations(
            &response,
            "v1.2.3",
            work.path(),
            &blob,
            &digest,
            &identity,
            |_, _, _, _| Ok(()),
        )
        .is_err()
    );
}

#[test]
fn requested_versions_and_artifact_bytes_fail_closed() {
    assert_eq!(
        resolve_version("nazozero/NazoAuth", Some("v1.2.3")).unwrap(),
        "v1.2.3"
    );
    assert!(resolve_version("nazozero/NazoAuth", Some("latest")).is_err());

    let work = PrivateTempDir::new("release-artifact-test").unwrap();
    let path = work.path().join("artifact");
    atomic_write(&path, b"x", 0o600).unwrap();
    let mut artifact = Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name: "artifact".to_owned(),
        sha256: sha256(&path).unwrap(),
        size: 1,
    };
    verify_artifact(&path, &artifact).unwrap();
    artifact.size = 2;
    assert!(verify_artifact(&path, &artifact).is_err());
    artifact.size = 1;
    artifact.sha256 = "0".repeat(64);
    assert!(verify_artifact(&path, &artifact).is_err());
    assert!(verify_artifact(&work.path().join("missing"), &artifact).is_err());
}

#[test]
fn verified_release_exposes_only_existing_policy_repository_artifacts() {
    let work = PrivateTempDir::new("verified-release-artifact-test").unwrap();
    let value = manifest("v1.2.3");
    let updater = value.artifacts["updater"].clone();
    atomic_write(&work.path().join(&updater.name), b"x", 0o600).unwrap();
    let release = VerifiedRelease {
        work,
        manifest: value,
    };

    assert!(release.artifact("missing", "nazozero/NazoAuth").is_err());
    assert!(release.artifact("updater", "attacker/NazoAuth").is_err());
    assert_eq!(
        release
            .artifact("updater", "nazozero/NazoAuth")
            .unwrap()
            .file_name()
            .unwrap(),
        updater.name.as_str()
    );
}
