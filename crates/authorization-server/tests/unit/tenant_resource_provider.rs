use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use futures_util::future::BoxFuture;
use nazo_operator_protocol::{
    Actor, ActorKind, EmbeddedIdentity, TenantResourceCapability, TenantResourceIdentity,
    TenantResourceOperation, TenantResourceReceipt, TenantResourceTask, TenantResourceTaskPayload,
    canonical_tenant_resource_manifest_sha256, compact_sha256, instance_key_id,
    sign_tenant_resource_capability, sign_tenant_resource_receipt, sign_tenant_resource_task,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::*;

const NOW: i64 = 1_800_000_000;
const DEPLOYMENT: &str = "deployment-a";
const TENANT: &str = "00000000-0000-7000-8000-000000000001";

struct TestSigner {
    key: SigningKey,
    fail_receipt: Arc<AtomicBool>,
}

impl TenantResourceSigner for TestSigner {
    fn sign_capability(
        &self,
        capability: &TenantResourceCapability,
    ) -> Result<String, TenantResourceProviderError> {
        sign_tenant_resource_capability(
            capability,
            &instance_key_id(&self.key.verifying_key()),
            &self.key,
        )
        .map_err(|_| TenantResourceProviderError::Unavailable("test signer failed"))
    }

    fn sign_receipt(
        &self,
        receipt: &TenantResourceReceipt,
    ) -> Result<String, TenantResourceProviderError> {
        if self.fail_receipt.load(Ordering::SeqCst) {
            return Err(TenantResourceProviderError::Unavailable(
                "test receipt signer failed",
            ));
        }
        sign_tenant_resource_receipt(
            receipt,
            &instance_key_id(&self.key.verifying_key()),
            &self.key,
        )
        .map_err(|_| TenantResourceProviderError::Unavailable("test signer failed"))
    }
}

struct TestState {
    snapshot: Arc<Mutex<TenantResourceStateSnapshot>>,
    reads: Arc<AtomicUsize>,
}

impl TenantResourceStateSource for TestState {
    fn current<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<TenantResourceStateSnapshot, TenantResourceExecutorError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let snapshot = self.snapshot.lock().expect("state lock").clone();
        Box::pin(async move { Ok(snapshot) })
    }
}

struct TestExecutor {
    calls: Arc<AtomicUsize>,
    commits: Arc<AtomicUsize>,
    receipt: Arc<Mutex<Option<String>>>,
    result: TenantResourceExecutionResult,
}

impl TenantResourceExecutor for TestExecutor {
    fn replay<'a>(
        &'a self,
        _task: &'a PreparedTenantResourceTask,
    ) -> BoxFuture<'a, Result<Option<String>, TenantResourceExecutorError>> {
        let receipt = self.receipt.lock().expect("receipt lock").clone();
        Box::pin(async move { Ok(receipt) })
    }

    fn execute<'a>(
        &'a self,
        _task: PreparedTenantResourceTask,
        receipt_issuer: &'a dyn TenantResourceReceiptIssuer,
    ) -> BoxFuture<'a, Result<String, TenantResourceExecutorError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let issued = receipt_issuer.issue(self.result.clone());
        let result = match issued {
            Ok(issued) => {
                *self.receipt.lock().expect("receipt lock") = Some(issued.compact.clone());
                self.commits.fetch_add(1, Ordering::SeqCst);
                Ok(issued.compact)
            }
            Err(_) => Err(TenantResourceExecutorError::Unavailable),
        };
        Box::pin(async move { result })
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

struct ProviderFixture {
    provider: TenantResourceProvider,
    calls: Arc<AtomicUsize>,
    commits: Arc<AtomicUsize>,
    snapshot: Arc<Mutex<TenantResourceStateSnapshot>>,
    reads: Arc<AtomicUsize>,
    fail_receipt: Arc<AtomicBool>,
    controller: SigningKey,
    runtime: SigningKey,
}

fn provider() -> ProviderFixture {
    let controller = key(7);
    let runtime = key(9);
    let runtime_key_id = instance_key_id(&runtime.verifying_key());
    let calls = Arc::new(AtomicUsize::new(0));
    let commits = Arc::new(AtomicUsize::new(0));
    let fail_receipt = Arc::new(AtomicBool::new(false));
    let state_reads = Arc::new(AtomicUsize::new(0));
    let state_snapshot = Arc::new(Mutex::new(TenantResourceStateSnapshot {
        revision: 0,
        resource_manifest_sha256: "0".repeat(64),
    }));
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-1".to_owned(),
        digest: user_payload_digest(),
    };
    let executor = Arc::new(TestExecutor {
        calls: calls.clone(),
        commits: commits.clone(),
        receipt: Arc::new(Mutex::new(None)),
        result: TenantResourceExecutionResult {
            revision: 1,
            resources: vec![identity],
            resource_mappings: vec![TenantResourceMapping {
                kind: TenantResourceKind::User,
                resource_id: "user-1".to_owned(),
                public_id: "018f0f79-5f3d-7e44-8000-000000000001".to_owned(),
            }],
            audit_sequence: 1,
            audit_previous_sha256: "0".repeat(64),
        },
    });
    let config = TenantResourceProviderConfig {
        deployment_id: DEPLOYMENT.to_owned(),
        tenant_id: TENANT.to_owned(),
        runtime_instance_id: "runtime-a".to_owned(),
        issuer: format!("runtime:{DEPLOYMENT}"),
        instance_key_id: runtime_key_id,
        runtime_public_key: runtime.verifying_key(),
        embedded: EmbeddedIdentity {
            release: "0.1.0".to_owned(),
            revision: "rev-a".to_owned(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build-a".to_owned(),
        },
        resource_kinds: vec![TenantResourceKind::User],
        actions: vec![TenantResourceOperation::Apply],
    };
    let provider = TenantResourceProvider::new(
        ControllerPublicKey {
            verifying_key: controller.verifying_key(),
            key_id: instance_key_id(&controller.verifying_key()),
        },
        config,
        Arc::new(TestSigner {
            key: runtime.clone(),
            fail_receipt: fail_receipt.clone(),
        }),
        Arc::new(TestState {
            snapshot: state_snapshot.clone(),
            reads: state_reads.clone(),
        }),
        executor,
    )
    .expect("valid provider config");
    ProviderFixture {
        provider,
        calls,
        commits,
        snapshot: state_snapshot,
        reads: state_reads,
        fail_receipt,
        controller,
        runtime,
    }
}

async fn capability(
    provider: &TenantResourceProvider,
    runtime: &SigningKey,
) -> (String, TenantResourceCapability) {
    let response = provider
        .issue_capability(
            TenantResourceCapabilityRequest {
                schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
                nonce: URL_SAFE_NO_PAD.encode([4u8; 32]),
                tenant_id: TENANT.to_owned(),
            },
            NOW,
        )
        .await
        .expect("capability");
    let capability = nazo_operator_protocol::verify_tenant_resource_capability(
        &response.capability_jws,
        &instance_key_id(&runtime.verifying_key()),
        &runtime.verifying_key(),
        NOW,
    )
    .expect("signed capability");
    (response.capability_jws, capability)
}

fn manifest_and_task(
    capability_jws: &str,
    capability: &TenantResourceCapability,
    controller: &SigningKey,
    manifest_json: serde_json::Value,
) -> (String, Vec<u8>) {
    let payload = json!({
        "username": "alice",
        "email": "alice@example.test",
        "password": "password",
        "email_verified": true,
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("payload");
    let payload_digest = hex(&payload_bytes);
    let raw_manifest = if manifest_json.is_null() {
        serde_json::to_vec(&json!({
            "schema": 1,
            "resources": [{
                "kind": "user",
                "resource_id": "user-1",
                "payload_base64url": URL_SAFE_NO_PAD.encode(&payload_bytes),
            }],
        }))
        .expect("manifest")
    } else {
        serde_json::to_vec(&manifest_json).expect("manifest")
    };
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-1".to_owned(),
        digest: payload_digest,
    };
    let resource_manifest_sha256 =
        canonical_tenant_resource_manifest_sha256(std::slice::from_ref(&identity))
            .expect("canonical resource manifest");
    let task = TenantResourceTask {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("controller:{DEPLOYMENT}"),
        aud: format!("runtime:{DEPLOYMENT}"),
        jti: Uuid::now_v7().to_string(),
        iat: NOW - 1,
        nbf: NOW - 1,
        exp: NOW + 30,
        deployment_id: DEPLOYMENT.to_owned(),
        tenant_id: TENANT.to_owned(),
        capability_jti: capability.jti.clone(),
        capability_sha256: compact_sha256(capability_jws),
        actor: Actor {
            kind: ActorKind::Automation,
            id: "ctl".to_owned(),
        },
        expected_revision: capability.revision,
        change_set_id: "change-set-a".to_owned(),
        change_set_sha256: hex(&raw_manifest),
        operation: TenantResourceOperation::Apply,
        payload: TenantResourceTaskPayload::Apply {
            resources: vec![identity],
        },
        resource_manifest_sha256,
        baseline_manifest_sha256: "0".repeat(64),
    };
    let task_jws = sign_tenant_resource_task(
        &task,
        &instance_key_id(&controller.verifying_key()),
        controller,
    )
    .expect("signed task");
    (task_jws, raw_manifest)
}

fn envelope(capability_jws: &str, task_jws: &str, raw_manifest: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "capability_jws": capability_jws,
        "task_jws": task_jws,
        "manifest_base64url": URL_SAFE_NO_PAD.encode(raw_manifest),
    }))
    .expect("envelope")
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn user_payload_digest() -> String {
    hex(&serde_json::to_vec(&json!({
        "username": "alice",
        "email": "alice@example.test",
        "password": "password",
        "email_verified": true,
    }))
    .expect("payload"))
}

#[tokio::test]
async fn valid_apply_calls_executor_once_and_returns_receipt() {
    let ProviderFixture {
        provider,
        calls,
        commits,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let response = provider
        .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
        .await
        .expect("valid operation");
    assert!(!response.receipt_jws.is_empty());
    let replay = provider
        .execute(
            &envelope(&capability_jws, &task_jws, &raw_manifest),
            NOW + 61,
        )
        .await
        .expect("durable replay after request expiry");
    assert_eq!(replay.receipt_jws, response.receipt_jws);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(commits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn receipt_signing_failure_does_not_mark_executor_commit() {
    let ProviderFixture {
        provider,
        calls,
        commits,
        fail_receipt,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    fail_receipt.store(true, Ordering::SeqCst);
    let error = provider
        .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
        .await
        .expect_err("signing failure");
    assert_eq!(
        error.status_code(),
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(commits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn capability_reads_authoritative_state_for_each_request() {
    let ProviderFixture {
        provider,
        snapshot,
        reads,
        runtime,
        ..
    } = provider();
    let (_, first) = capability(&provider, &runtime).await;
    assert_eq!(first.revision, 0);
    assert_eq!(first.resource_manifest_sha256, "0".repeat(64));
    {
        let mut current = snapshot.lock().expect("state lock");
        current.revision = 2;
        current.resource_manifest_sha256 = "a".repeat(64);
    }
    let (_, second) = capability(&provider, &runtime).await;
    assert_eq!(second.revision, 2);
    assert_eq!(second.resource_manifest_sha256, "a".repeat(64));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn wrong_controller_key_is_rejected_before_executor() {
    let ProviderFixture {
        provider,
        calls,
        commits,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &key(8), Value::Null);
    let error = provider
        .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
        .await
        .expect_err("wrong key");
    assert_eq!(
        error.status_code(),
        actix_web::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(commits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_automation_actor_is_forbidden_before_executor() {
    let ProviderFixture {
        provider,
        calls,
        commits,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let task = nazo_operator_protocol::verify_tenant_resource_task(
        &task_jws,
        &instance_key_id(&controller.verifying_key()),
        &controller.verifying_key(),
        NOW,
    )
    .expect("task");
    let mut local_root = task;
    local_root.actor.kind = ActorKind::LocalRoot;
    let local_root_jws = sign_tenant_resource_task(
        &local_root,
        &instance_key_id(&controller.verifying_key()),
        &controller,
    )
    .expect("local root task");
    let error = provider
        .execute(
            &envelope(&capability_jws, &local_root_jws, &raw_manifest),
            NOW,
        )
        .await
        .expect_err("non-automation actor");
    assert_eq!(error.status_code(), actix_web::http::StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(commits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deployment_tenant_and_capability_digest_bindings_fail_closed() {
    let ProviderFixture {
        provider,
        calls,
        commits,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let task = nazo_operator_protocol::verify_tenant_resource_task(
        &task_jws,
        &instance_key_id(&controller.verifying_key()),
        &controller.verifying_key(),
        NOW,
    )
    .expect("task");
    let mut changed = task.clone();
    changed.deployment_id = "deployment-b".to_owned();
    changed.iss = "controller:deployment-b".to_owned();
    changed.aud = "runtime:deployment-b".to_owned();
    let changed_jws = sign_tenant_resource_task(
        &changed,
        &instance_key_id(&controller.verifying_key()),
        &controller,
    )
    .expect("changed task");
    let error = provider
        .execute(&envelope(&capability_jws, &changed_jws, &raw_manifest), NOW)
        .await
        .expect_err("deployment binding");
    assert_eq!(error.status_code(), actix_web::http::StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(commits.load(Ordering::SeqCst), 0);

    let mut wrong_tenant = task.clone();
    wrong_tenant.tenant_id = "00000000-0000-7000-8000-000000000002".to_owned();
    let wrong_tenant_jws = sign_tenant_resource_task(
        &wrong_tenant,
        &instance_key_id(&controller.verifying_key()),
        &controller,
    )
    .expect("changed tenant task");
    let error = provider
        .execute(
            &envelope(&capability_jws, &wrong_tenant_jws, &raw_manifest),
            NOW,
        )
        .await
        .expect_err("tenant binding");
    assert_eq!(error.status_code(), actix_web::http::StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(commits.load(Ordering::SeqCst), 0);

    let mut bad_digest = task;
    bad_digest.capability_sha256 = "f".repeat(64);
    let bad_digest_jws = sign_tenant_resource_task(
        &bad_digest,
        &instance_key_id(&controller.verifying_key()),
        &controller,
    )
    .expect("changed digest task");
    let error = provider
        .execute(
            &envelope(&capability_jws, &bad_digest_jws, &raw_manifest),
            NOW,
        )
        .await
        .expect_err("digest binding");
    assert_eq!(error.status_code(), actix_web::http::StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_capability_manifest_tamper_unknown_field_and_oversize_are_rejected() {
    let ProviderFixture {
        provider,
        calls,
        commits,
        controller,
        runtime,
        ..
    } = provider();
    let (_capability_jws, mut expired_capability) = capability(&provider, &runtime).await;
    expired_capability.issued_at = NOW - 60;
    expired_capability.expires_at = NOW - 1;
    let expired_jws = sign_tenant_resource_capability(
        &expired_capability,
        &instance_key_id(&runtime.verifying_key()),
        &runtime,
    )
    .expect("expired capability");
    let (task_jws, raw_manifest) =
        manifest_and_task(&expired_jws, &expired_capability, &controller, Value::Null);
    let error = provider
        .execute(&envelope(&expired_jws, &task_jws, &raw_manifest), NOW)
        .await
        .expect_err("expired capability");
    assert_eq!(error.status_code(), actix_web::http::StatusCode::FORBIDDEN);

    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let mut tampered = raw_manifest.clone();
    tampered[0] = b' ';
    let error = provider
        .execute(&envelope(&capability_jws, &task_jws, &tampered), NOW)
        .await
        .expect_err("tampered manifest");
    assert_eq!(error.status_code(), actix_web::http::StatusCode::FORBIDDEN);

    let unknown = serde_json::to_vec(&json!({
        "schema": 1,
        "unexpected": true,
        "resources": [],
    }))
    .expect("unknown manifest");
    let (task_jws, _) = manifest_and_task(
        &capability_jws,
        &capability,
        &controller,
        json!({
            "schema": 1,
            "unexpected": true,
            "resources": [],
        }),
    );
    let error = provider
        .execute(&envelope(&capability_jws, &task_jws, &unknown), NOW)
        .await
        .expect_err("unknown manifest field");
    assert_eq!(
        error.status_code(),
        actix_web::http::StatusCode::BAD_REQUEST
    );

    let oversized = vec![b'x'; MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES + 1];
    let error = provider
        .execute(&oversized, NOW)
        .await
        .expect_err("oversized body");
    assert_eq!(
        error.status_code(),
        actix_web::http::StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(commits.load(Ordering::SeqCst), 0);
}

#[test]
fn controller_key_loader_rejects_non_regular_and_derives_kid() {
    let root = std::env::temp_dir().join(format!("nazoauth-tenant-provider-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("temp root");
    let key = key(7);
    let path = root.join("controller.pub");
    fs::write(
        &path,
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    )
    .expect("key");
    let loaded = load_controller_public_key(&path).expect("loaded key");
    assert_eq!(loaded.key_id, instance_key_id(&key.verifying_key()));
    let directory = root.join("directory");
    fs::create_dir(&directory).expect("directory");
    assert_eq!(
        load_controller_public_key(&directory)
            .expect_err("directory")
            .status_code(),
        actix_web::http::StatusCode::FORBIDDEN
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn ordinary_trust_policy_payload_is_public_and_validator_fenced() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let certificate =
        |label: &str| format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n");
    let policy = json!({
        "schema": 1,
        "client_attestation_issuer": "https://issuer.example/attestation",
        "client_attestation_jwks": {"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "client"
        }]},
        "key_attestation_jwks": {"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "holder"
        }]},
        "credential_trust_anchor_pem": format!("{}{}", certificate("MA=="), certificate("MDE=")),
        "wallet_authorization_origins": ["https://wallet.example"]
    });
    let payload = serde_json::to_vec(&policy).expect("policy payload");
    let decoded = decode_payload(TenantResourceKind::Openid4vcTrustPolicy, &payload)
        .expect("ordinary policy");
    assert!(matches!(
        decoded,
        TenantResourcePayload::Openid4vcTrustPolicy(value)
            if value.public_material.schema == 1
    ));
    let mut private = policy;
    private["client_attestation_jwks"]["keys"][0]["d"] = json!("secret");
    let private = serde_json::to_vec(&private).expect("private policy payload");
    assert!(decode_payload(TenantResourceKind::Openid4vcTrustPolicy, &private).is_err());
}

#[actix_web::test]
async fn management_execute_route_enforces_media_type_and_payload_limit() {
    let ProviderFixture { provider, .. } = provider();
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(provider))
            .configure(crate::bootstrap::routes::configure_tenant_resource_management),
    )
    .await;

    let missing_media_type = actix_web::test::TestRequest::post()
        .uri("/management/tenant-resources/execute")
        .set_payload("{}")
        .to_request();
    let response = actix_web::test::call_service(&app, missing_media_type).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);

    let oversized = actix_web::test::TestRequest::post()
        .uri("/management/tenant-resources/execute")
        .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
        .set_payload(vec![b'x'; MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES + 1])
        .to_request();
    let response = actix_web::test::call_service(&app, oversized).await;
    assert_eq!(
        response.status(),
        actix_web::http::StatusCode::PAYLOAD_TOO_LARGE
    );
}
