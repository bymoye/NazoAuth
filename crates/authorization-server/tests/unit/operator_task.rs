//! E04/E05 unit coverage for the reworked one-shot operator entry:
//! presentation strictness, Controller Registry admission classification,
//! J1 target identity, config_revision fencing, deployment anchors, the E05
//! resume-ownership table, and dispatch precondition mapping.  Database-backed
//! end-to-end behavior (including crash/failpoint evidence) lives in
//! `tests/operator_task_process.rs`.

use std::{fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::{
    CONTROL_OPERATION_SCHEMA, ControlBuildIdentity, ControlOperation, ControlOperationPayload,
    ControlTarget, MAX_CONTROL_OPERATION_BYTES,
};
use sha2::{Digest as _, Sha256};

use super::*;

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazoauth-operator-task-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn build_identity() -> ControlBuildIdentity {
    ControlBuildIdentity {
        product: "nazauth".to_owned(),
        version: "v9.9.9-test".to_owned(),
        commit: "c".repeat(40),
    }
}

fn operation(operation_id: &str) -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: operation_id.to_owned(),
        // Unpadded base64url SHA-256 shape: exactly 43 characters.
        kid: "kid-controller-test-key-0000000000000000000".to_owned(),
        deployment_id: "deployment-test".to_owned(),
        target: ControlTarget::HostBinary {
            sha256: "a".repeat(64),
            embedded: build_identity(),
        },
        config_revision: "config-revision-1".to_owned(),
        operation: ControlOperationPayload::MigrateApply,
    }
}

/// Fabricate a compact JWS-shaped string whose payload carries `json`.  The
/// presentation stage does not verify signatures (the registry key is not
/// known yet), so arbitrary header/signature segments are fine here.
fn presented(json: &str) -> String {
    format!("e30.{}.c2ln", URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

fn presented_operation(operation: &ControlOperation) -> String {
    let json = serde_json::to_string(operation).unwrap();
    presented(&json)
}

#[test]
fn presentation_rejects_malformed_requests_before_any_authority() {
    let valid = operation("019c8ca2-30a6-7000-8000-00000000a001");
    assert!(admission::present(&presented_operation(&valid)).is_ok());

    // Unknown envelope member.
    let mut extra = serde_json::to_value(&valid).unwrap();
    extra["argv"] = serde_json::json!(["sh", "-c"]);
    assert!(admission::present(&presented(&extra.to_string())).is_err());

    // Wrong schema tag is a protocol change, never a fallback.
    let mut schema = serde_json::to_value(&valid).unwrap();
    schema["schema"] = serde_json::json!(2);
    assert!(admission::present(&presented(&schema.to_string())).is_err());

    // Unknown closed-operation name and unknown typed-payload members are
    // rejected instead of dropped (E01 hand-written enum parsing).
    for body in [
        r#"{"name":"shell-exec"}"#,
        r#"{"name":"migrate-apply","argv":["sh","-c","id"]}"#,
        r#"{"name":"keys-list","tenant_id":"019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90"}"#,
        r#"{"name":"keys-generate-local","alg":"ES256","purposes":["credential"],"quiet":true}"#,
        r#"{"name":"tenant-resource-enumerate","tenant_id":"x","selectors":[]}"#,
    ] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value["operation"] = serde_json::from_str::<serde_json::Value>(body).unwrap();
        assert!(
            admission::present(&presented(&value.to_string())).is_err(),
            "presentation must reject {body}"
        );
    }

    // Unknown members inside tenant resource identities cannot smuggle
    // undeclared parameters either.
    let mut value = serde_json::to_value(&valid).unwrap();
    value["operation"] = serde_json::json!({
        "name": "tenant-resource-apply",
        "tenant_id": "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90",
        "resources": [{
            "kind": "user",
            "resource_id": "user-1",
            "digest": "a".repeat(64),
            "password": "smuggled",
        }],
    });
    assert!(admission::present(&presented(&value.to_string())).is_err());

    // Structural policy violations fail before any authority is consulted.
    let mut bad_id = valid.clone();
    bad_id.operation_id = "not-a-uuid".to_owned();
    assert!(admission::present(&presented_operation(&bad_id)).is_err());

    let mut bad_kid = valid.clone();
    bad_kid.kid = "short-kid".to_owned();
    assert!(admission::present(&presented_operation(&bad_kid)).is_err());

    // Oversized payloads hit the size gate regardless of validity.
    let giant = format!(
        "{{\"schema\":1,\"operation_id\":\"019c8ca2-30a6-7000-8000-00000000a002\",\"kid\":\"{}\",\"deployment_id\":\"d\",\"target\":{{\"kind\":\"host-binary\",\"sha256\":\"{}\",\"embedded\":{{\"product\":\"p\",\"version\":\"v\",\"commit\":\"c\"}}}},\"config_revision\":\"r\",\"operation\":{{\"name\":\"keys-validate\",\"filler\":\"{}\"}}}}",
        "k".repeat(43),
        "a".repeat(64),
        "x".repeat(MAX_CONTROL_OPERATION_BYTES),
    );
    let oversized = presented(&giant);
    assert!(oversized.len() > MAX_CONTROL_OPERATION_BYTES);
    assert!(admission::present(&oversized).is_err());

    // Segment shape and base64url strictness.
    assert!(admission::present("a.b").is_err());
    assert!(admission::present("e30.!!!.c2ln").is_err());
}

#[test]
fn unadmitted_controller_keys_are_classified_from_registry_state() {
    use nazo_postgres::StoredControllerSlot;

    // Unknown kid for this deployment.
    assert_eq!(
        admission::classify_unadmitted_key(None),
        admission::KeyAdmissionFailure::Untrusted
    );

    // A terminally revoked slot can never admit again; it stays distinct
    // from expiry in the rejection taxonomy but refuses identically.
    let slot = StoredControllerSlot {
        deployment_id: "deployment-test".to_owned(),
        controller_id: "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90".to_owned(),
        label: "primary".to_owned(),
        kid: "kid-controller-test-key-0000000000000000000".to_owned(),
        public_key: vec![1; 32],
        slot_index: 0,
        issued_at: chrono::Utc::now() - chrono::Duration::days(40),
        expires_at: chrono::Utc::now() - chrono::Duration::days(10),
        last_used_at: None,
        status: nazo_postgres::ControllerSlotStatus::Revoked,
        revoked_at: Some(chrono::Utc::now() - chrono::Duration::days(1)),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    assert_eq!(
        admission::classify_unadmitted_key(Some(&slot)),
        admission::KeyAdmissionFailure::Untrusted
    );

    // An active slot that failed admission has necessarily aged out of its
    // fixed server-side window.
    let expired = StoredControllerSlot {
        status: nazo_postgres::ControllerSlotStatus::Active,
        revoked_at: None,
        ..slot
    };
    assert_eq!(
        admission::classify_unadmitted_key(Some(&expired)),
        admission::KeyAdmissionFailure::Expired
    );
}

#[test]
fn resume_ownership_table_pins_every_closed_variant() {
    // E05 decision point: which existing ledger makes re-entry safe.
    let cases: Vec<(ControlOperationPayload, bool)> = vec![
        // Diesel __diesel_schema_migrations deduplicates applied migrations.
        (ControlOperationPayload::MigrateApply, true),
        // Read-only operations have no side effect to duplicate.
        (ControlOperationPayload::KeysList, true),
        (ControlOperationPayload::KeysValidate, true),
        // keyset.json dedupes the exact (alg, purposes) registration and an
        // identical external registration respectively.
        (
            ControlOperationPayload::KeysGenerateLocal {
                alg: "ES256".to_owned(),
                purposes: vec!["credential".to_owned()],
            },
            true,
        ),
        (
            ControlOperationPayload::KeysRegisterExternal {
                kid: "external-1".to_owned(),
                alg: "ES256".to_owned(),
                key_ref: "provider:key-1".to_owned(),
                public_jwk_sha256: "a".repeat(64),
            },
            true,
        ),
        // Read-only authoritative state read.
        (
            ControlOperationPayload::TenantResourceEnumerate {
                tenant_id: "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90".to_owned(),
                selectors: Vec::new(),
            },
            true,
        ),
        // Serviced through the shared CAS engine since H07.  Re-entry stays
        // fail closed because this driver writes no `tenant_resource_operations`
        // replay row: an ambiguous crash window cannot prove whether the
        // transaction committed, so it must never be re-run or reported as
        // failed.
        (
            ControlOperationPayload::TenantResourceApply {
                tenant_id: "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90".to_owned(),
                resources: Vec::new(),
            },
            false,
        ),
        (
            ControlOperationPayload::TenantResourceRevoke {
                tenant_id: "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90".to_owned(),
                resources: Vec::new(),
            },
            false,
        ),
    ];
    for (payload, allowed) in cases {
        assert_eq!(execution::resume_allowed(&payload), allowed, "{payload:?}");
    }
}

#[test]
fn mounted_change_set_material_is_a_regular_bounded_file() {
    let directory = temporary_directory();
    let change_set = directory.join("change-set.json");
    fs::write(&change_set, br#"{"schema":1,"resources":[]}"#).unwrap();
    assert_eq!(
        execution::read_regular_bounded_file(&change_set).unwrap(),
        br#"{"schema":1,"resources":[]}"#.to_vec()
    );

    // Symlinks are refused even when they point at valid material.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&change_set, directory.join("link.json")).unwrap();
        assert!(execution::read_regular_bounded_file(&directory.join("link.json")).is_err());
    }

    // Directories and missing files are refused.
    assert!(
        execution::read_regular_bounded_file(&directory)
            .unwrap_err()
            .to_string()
            .contains("regular non-symlink")
    );
    assert!(execution::read_regular_bounded_file(&directory.join("missing.json")).is_err());

    // Oversized material is refused.
    let oversized = directory.join("oversized.json");
    fs::write(&oversized, vec![b'x'; execution::MAX_CHANGE_SET_BYTES + 1]).unwrap();
    assert!(execution::read_regular_bounded_file(&oversized).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn apply_change_sets_are_digest_bound_to_the_signed_identities() {
    use nazo_operator_protocol::TenantResourceIdentity;
    use nazo_operator_protocol::TenantResourceKind;

    let password_payload = serde_json::json!({
        "username": "operator-user",
        "email": "operator-user@example.test",
        "password": "correct horse battery staple",
        "email_verified": true,
    });
    let raw_payload = serde_json::to_vec(&password_payload).unwrap();
    let digest: String = Sha256::digest(&raw_payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-1".to_owned(),
        digest: digest.clone(),
    };
    let manifest = serde_json::json!({
        "schema": 1,
        "resources": [{
            "kind": "user",
            "resource_id": "user-1",
            "payload_base64url": URL_SAFE_NO_PAD.encode(&raw_payload),
        }],
    });
    let raw_manifest = serde_json::to_vec(&manifest).unwrap();

    let prepared =
        execution::prepare_change_set_material(&raw_manifest, std::slice::from_ref(&identity))
            .expect("digest-bound change set");
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].identity, identity);

    // Any drift between the mounted bytes and the signed digests is refused.
    assert!(
        execution::prepare_change_set_material(b"{}", std::slice::from_ref(&identity)).is_err(),
        "an empty manifest cannot satisfy a non-empty signed delta"
    );
    let mut other = manifest.clone();
    other["resources"][0]["payload_base64url"] =
        serde_json::json!(URL_SAFE_NO_PAD.encode(b"drift"));
    assert!(
        execution::prepare_change_set_material(&serde_json::to_vec(&other).unwrap(), &[identity])
            .is_err()
    );
}

#[test]
fn j1_target_identity_binds_operations_to_this_binary() {
    let this = identity::control_build_identity();

    let matching = ControlTarget::HostBinary {
        sha256: "a".repeat(64),
        embedded: this.clone(),
    };
    identity::validate_embedded_target_identity(&matching).unwrap();

    let oci_matching = ControlTarget::OciImage {
        image_digest: format!("sha256:{}", "b".repeat(64)),
        embedded: this.clone(),
    };
    identity::validate_embedded_target_identity(&oci_matching).unwrap();

    let wrong_version = ControlTarget::HostBinary {
        sha256: "a".repeat(64),
        embedded: ControlBuildIdentity {
            version: "other-release".to_owned(),
            ..this.clone()
        },
    };
    assert!(identity::validate_embedded_target_identity(&wrong_version).is_err());

    let wrong_product = ControlTarget::HostBinary {
        sha256: "a".repeat(64),
        embedded: ControlBuildIdentity {
            product: "counterfeit".to_owned(),
            ..this
        },
    };
    assert!(identity::validate_embedded_target_identity(&wrong_product).is_err());
}

#[test]
fn config_revision_fencing_against_the_local_marker_is_constant_time() {
    let directory = temporary_directory();
    let marker = directory.join("config-revision");
    fs::write(&marker, b"config-revision-1\n").unwrap();

    let valid = operation("019c8ca2-30a6-7000-8000-00000000a003");
    identity::validate_config_revision_at(&valid, &marker).unwrap();

    let mut rotated = valid.clone();
    rotated.config_revision = "config-revision-2".to_owned();
    let error = identity::validate_config_revision_at(&rotated, &marker)
        .unwrap_err()
        .to_string();
    assert!(error.contains("revision binding mismatch"), "{error}");

    fs::write(&marker, b"").unwrap();
    assert!(identity::validate_config_revision_at(&valid, &marker).is_err());
    fs::remove_file(&marker).unwrap();
    assert!(identity::validate_config_revision_at(&valid, &marker).is_err());
    fs::remove_dir_all(directory).unwrap();
}

fn write_deployment_fixtures(directory: &std::path::Path) -> PathBuf {
    let config_path = directory.join("server.yaml");
    fs::write(
        &config_path,
        b"DATA_DIR: runtime\nDEPLOYMENT_ID: deployment-test\n",
    )
    .unwrap();
    let identity_path = directory.join("runtime/instance/deployment-id");
    fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
    fs::write(&identity_path, b"deployment-test\n").unwrap();
    config_path
}

#[test]
fn local_deployment_identity_binds_to_every_available_anchor() {
    let directory = temporary_directory();
    let config_path = write_deployment_fixtures(&directory);
    let state_directory = directory.join("state");
    fs::create_dir_all(&state_directory).unwrap();

    // Non-bootstrap operations require the operator-state anchor first.
    let bootstrap = ControlOperationPayload::MigrateApply;
    assert!(
        identity::validate_local_operation_identity_at(
            &bootstrap,
            &config_path,
            None,
            Some(&state_directory)
        )
        .is_ok()
    );
    let expected = identity::validate_local_operation_identity_at(
        &bootstrap,
        &config_path,
        None,
        Some(&state_directory),
    )
    .unwrap();
    assert_eq!(expected, "deployment-test");
    identity::persist_operator_state_identity(&state_directory, &expected).unwrap();

    // Once the anchor exists every operation resolves to it.
    let regular = ControlOperationPayload::KeysValidate;
    assert_eq!(
        identity::validate_local_operation_identity_at(
            &regular,
            &config_path,
            None,
            Some(&state_directory)
        )
        .unwrap(),
        "deployment-test"
    );

    // A signed deployment_id that differs from the local anchor is refused by
    // the caller comparison; simulate the mismatch directly.
    let other = identity::validate_local_operation_identity_at(
        &regular,
        &directory.join("missing.yaml"),
        None,
        Some(&state_directory),
    );
    assert!(other.is_err());

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn local_deployment_identity_rejects_missing_or_conflicting_bootstrap_sources() {
    let directory = temporary_directory();
    let config_path = directory.join("server.yaml");
    let regular = ControlOperationPayload::KeysValidate;

    assert!(
        identity::validate_local_operation_identity_at(
            &regular,
            &config_path,
            None,
            Some(&directory.join("state")),
        )
        .unwrap_err()
        .to_string()
        .contains("failed to read server configuration")
    );

    fs::write(&config_path, b"- not-a-mapping\n").unwrap();
    assert!(
        identity::validate_local_operation_identity_at(
            &regular,
            &config_path,
            None,
            Some(&directory.join("state")),
        )
        .unwrap_err()
        .to_string()
        .contains("top-level key/value mapping")
    );

    fs::write(
        &config_path,
        b"DATA_DIR: runtime\nDEPLOYMENT_ID: deployment-test\n",
    )
    .unwrap();
    let explicit_identity = directory.join("explicit-deployment-id");
    assert!(
        identity::validate_local_operation_identity_at(
            &regular,
            &config_path,
            Some(&explicit_identity),
            Some(&directory.join("state")),
        )
        .unwrap_err()
        .to_string()
        .contains("configured persisted deployment identity is unavailable")
    );

    let persisted_identity = directory.join("runtime/instance/deployment-id");
    fs::create_dir_all(persisted_identity.parent().unwrap()).unwrap();
    fs::write(&persisted_identity, b"deployment-test\n").unwrap();
    let state_directory = directory.join("state");
    fs::create_dir_all(&state_directory).unwrap();
    assert!(
        identity::validate_local_operation_identity_at(
            &regular,
            &config_path,
            None,
            Some(&state_directory)
        )
        .unwrap_err()
        .to_string()
        .contains("operator state deployment identity is unavailable")
    );

    fs::remove_file(&persisted_identity).unwrap();
    fs::write(&config_path, b"DATA_DIR: runtime\n").unwrap();
    let bootstrap = ControlOperationPayload::MigrateApply;
    assert!(
        identity::validate_local_operation_identity_at(&bootstrap, &config_path, None, None)
            .unwrap_err()
            .to_string()
            .contains("no local deployment identity is available")
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn local_deployment_identity_stringifies_yaml_scalars_and_rejects_sequences() {
    let directory = temporary_directory();
    let config_path = directory.join("server.yaml");
    let bootstrap = ControlOperationPayload::MigrateApply;

    // Scalar YAML types are read as strings; the signed deployment_id
    // comparison (caller side) rejects anything that does not match.
    fs::write(&config_path, b"DEPLOYMENT_ID: true\n").unwrap();
    assert_eq!(
        identity::validate_local_operation_identity_at(&bootstrap, &config_path, None, None)
            .unwrap(),
        "true"
    );
    fs::write(&config_path, b"DEPLOYMENT_ID: 42\n").unwrap();
    assert_eq!(
        identity::validate_local_operation_identity_at(&bootstrap, &config_path, None, None)
            .unwrap(),
        "42"
    );
    fs::write(
        &config_path,
        b"DATA_DIR: [runtime]\nDEPLOYMENT_ID: deployment-test\n",
    )
    .unwrap();
    assert!(
        identity::validate_local_operation_identity_at(&bootstrap, &config_path, None, None)
            .unwrap_err()
            .to_string()
            .contains("must be a scalar")
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn operator_state_identity_is_immutable_after_first_publication() {
    let directory = temporary_directory();
    identity::persist_operator_state_identity(&directory, "deployment-test").unwrap();
    identity::persist_operator_state_identity(&directory, "deployment-test").unwrap();
    let error = identity::persist_operator_state_identity(&directory, "deployment-other")
        .unwrap_err()
        .to_string();
    assert!(error.contains("changed unexpectedly"));
    assert_eq!(
        fs::read_to_string(directory.join("deployment-id"))
            .unwrap()
            .trim(),
        "deployment-test"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn mounted_external_jwk_material_is_digest_bound() {
    let directory = temporary_directory();
    let jwk_path = directory.join("public.jwk");
    fs::write(&jwk_path, br#"{"kty":"EC","kid":"external-1"}"#).unwrap();
    let jwk_sha256: String = Sha256::digest(fs::read(&jwk_path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        execution::verify_public_jwk_at(&jwk_sha256, jwk_path.clone()).unwrap(),
        jwk_path
    );
    assert!(execution::verify_public_jwk_at(&"0".repeat(64), jwk_path.clone()).is_err());
    assert!(execution::verify_public_jwk_at(&jwk_sha256, directory.join("missing.jwk")).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn task_lock_acquisition_is_bounded() {
    use std::time::{Duration, Instant};

    let directory = temporary_directory();
    let path = directory.join("task.lock");
    let holder = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    holder.lock_exclusive().unwrap();
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();

    let started = Instant::now();
    let error = acquire_task_lock_with_timeout(contender, Duration::from_millis(20))
        .await
        .expect_err("contended lock must time out");
    assert!(error.to_string().contains("timed out"), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(holder);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn dispatch_maps_precondition_failures_to_engine_errors_without_a_database() {
    let context = execution::ExecutionContext {
        operation_id: "019c8ca2-30a6-7000-8000-000000000005",
        deployment_id: "deployment-test",
        controller_id: "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90",
        kid: "kid-controller-test-key-0000000000000000000",
        request_hash: &"a".repeat(64),
    };
    // Unsupported signing parameters fail inside the existing engine before
    // any durable state changes.
    let generated = execution::execute(
        &ControlOperationPayload::KeysGenerateLocal {
            alg: "unsupported-algorithm".to_owned(),
            purposes: vec!["credential".to_owned()],
        },
        &context,
    )
    .await;
    assert!(generated.is_err());

    let external = execution::execute(
        &ControlOperationPayload::KeysRegisterExternal {
            kid: "external-1".to_owned(),
            alg: "ES256".to_owned(),
            key_ref: "provider:key-1".to_owned(),
            public_jwk_sha256: "a".repeat(64),
        },
        &context,
    )
    .await;
    assert!(external.is_err());

    // The apply delta cannot proceed without its mounted change-set material.
    let apply = execution::execute(
        &ControlOperationPayload::TenantResourceApply {
            tenant_id: "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90".to_owned(),
            resources: Vec::new(),
        },
        &context,
    )
    .await;
    assert!(apply.is_err());

    // Read-only local keyset dispatches map their typed errors without a
    // database connection; their outcome depends on ambient configuration so
    // only the Ok/Err totality is pinned here.
    let _ = execution::execute(&ControlOperationPayload::KeysList, &context).await;
    let _ = execution::execute(&ControlOperationPayload::KeysValidate, &context).await;
}
