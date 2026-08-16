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

fn provider_config(runtime: &SigningKey) -> TenantResourceProviderConfig {
    TenantResourceProviderConfig {
        deployment_id: DEPLOYMENT.to_owned(),
        tenant_id: TENANT.to_owned(),
        runtime_instance_id: "runtime-a".to_owned(),
        issuer: format!("runtime:{DEPLOYMENT}"),
        instance_key_id: instance_key_id(&runtime.verifying_key()),
        runtime_public_key: runtime.verifying_key(),
        embedded: EmbeddedIdentity {
            release: "0.1.0".to_owned(),
            revision: "rev-a".to_owned(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build-a".to_owned(),
        },
        resource_kinds: vec![TenantResourceKind::User],
        actions: vec![TenantResourceOperation::Apply],
    }
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
    let config = provider_config(&runtime);
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

fn apply_task_and_manifest() -> (TenantResourceTask, Vec<u8>) {
    let payload = serde_json::to_vec(&json!({
        "username": "alice",
        "email": "alice@example.test",
        "password": "password",
        "email_verified": true,
    }))
    .expect("payload");
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-1".to_owned(),
        digest: hex(&payload),
    };
    let raw = serde_json::to_vec(&json!({
        "schema": 1,
        "resources": [{
            "kind": "user",
            "resource_id": "user-1",
            "payload_base64url": URL_SAFE_NO_PAD.encode(&payload),
        }],
    }))
    .expect("manifest");
    let task = TenantResourceTask {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("controller:{DEPLOYMENT}"),
        aud: format!("runtime:{DEPLOYMENT}"),
        jti: "task-a".to_owned(),
        iat: NOW - 1,
        nbf: NOW - 1,
        exp: NOW + 30,
        deployment_id: DEPLOYMENT.to_owned(),
        tenant_id: TENANT.to_owned(),
        capability_jti: "capability-a".to_owned(),
        capability_sha256: "a".repeat(64),
        actor: Actor {
            kind: ActorKind::Automation,
            id: "ctl".to_owned(),
        },
        expected_revision: 0,
        change_set_id: "change-set-a".to_owned(),
        change_set_sha256: hex(&raw),
        operation: TenantResourceOperation::Apply,
        payload: TenantResourceTaskPayload::Apply {
            resources: vec![identity.clone()],
        },
        baseline_manifest_sha256: "0".repeat(64),
        resource_manifest_sha256: canonical_tenant_resource_manifest_sha256(&[identity])
            .expect("canonical manifest"),
    };
    (task, raw)
}

struct ErrorState(TenantResourceExecutorError);

impl TenantResourceStateSource for ErrorState {
    fn current<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<TenantResourceStateSnapshot, TenantResourceExecutorError>> {
        let error = self.0.clone();
        Box::pin(async move { Err(error) })
    }
}

enum StubExecutorMode {
    ReplayError(TenantResourceExecutorError),
    ReplayReceipt(String),
    ExecuteError(TenantResourceExecutorError),
    ExecuteReceipt(String),
}

struct StubExecutor(StubExecutorMode);

impl TenantResourceExecutor for StubExecutor {
    fn replay<'a>(
        &'a self,
        _task: &'a PreparedTenantResourceTask,
    ) -> BoxFuture<'a, Result<Option<String>, TenantResourceExecutorError>> {
        let result = match &self.0 {
            StubExecutorMode::ReplayError(error) => Err(error.clone()),
            StubExecutorMode::ReplayReceipt(compact) => Ok(Some(compact.clone())),
            StubExecutorMode::ExecuteError(_) | StubExecutorMode::ExecuteReceipt(_) => Ok(None),
        };
        Box::pin(async move { result })
    }

    fn execute<'a>(
        &'a self,
        _task: PreparedTenantResourceTask,
        _receipt_issuer: &'a dyn TenantResourceReceiptIssuer,
    ) -> BoxFuture<'a, Result<String, TenantResourceExecutorError>> {
        let result = match &self.0 {
            StubExecutorMode::ExecuteError(error) => Err(error.clone()),
            StubExecutorMode::ExecuteReceipt(compact) => Ok(compact.clone()),
            StubExecutorMode::ReplayError(_) | StubExecutorMode::ReplayReceipt(_) => {
                Err(TenantResourceExecutorError::Unavailable)
            }
        };
        Box::pin(async move { result })
    }
}

struct InvalidSigner;

impl TenantResourceSigner for InvalidSigner {
    fn sign_capability(
        &self,
        _capability: &TenantResourceCapability,
    ) -> Result<String, TenantResourceProviderError> {
        Ok("not-a-compact-jws".to_owned())
    }

    fn sign_receipt(
        &self,
        _receipt: &TenantResourceReceipt,
    ) -> Result<String, TenantResourceProviderError> {
        Ok("not-a-compact-jws".to_owned())
    }
}

struct InvalidReceiptSigner(SigningKey);

impl TenantResourceSigner for InvalidReceiptSigner {
    fn sign_capability(
        &self,
        capability: &TenantResourceCapability,
    ) -> Result<String, TenantResourceProviderError> {
        sign_tenant_resource_capability(
            capability,
            &instance_key_id(&self.0.verifying_key()),
            &self.0,
        )
        .map_err(|_| TenantResourceProviderError::Unavailable("test signer failed"))
    }

    fn sign_receipt(
        &self,
        _receipt: &TenantResourceReceipt,
    ) -> Result<String, TenantResourceProviderError> {
        Ok("not-a-compact-jws".to_owned())
    }
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

#[actix_web::test]
async fn provider_error_contract_and_internal_error_mapping_are_stable() {
    let cases = [
        (
            TenantResourceProviderError::BadRequest("bad"),
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "bad",
        ),
        (
            TenantResourceProviderError::Unauthorized("unsigned"),
            actix_web::http::StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "unsigned",
        ),
        (
            TenantResourceProviderError::Forbidden("denied"),
            actix_web::http::StatusCode::FORBIDDEN,
            "policy_denied",
            "denied",
        ),
        (
            TenantResourceProviderError::Conflict("stale"),
            actix_web::http::StatusCode::CONFLICT,
            "revision_conflict",
            "stale",
        ),
        (
            TenantResourceProviderError::TooLarge,
            actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "request too large",
        ),
        (
            TenantResourceProviderError::Unavailable("offline"),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
            "provider_unavailable",
            "offline",
        ),
    ];
    for (error, status, code, message) in cases {
        assert_eq!(error.status_code(), status);
        assert_eq!(error.stable_code(), code);
        assert_eq!(error.to_string(), message);
        let response = error.into_http_response();
        assert_eq!(response.status(), status);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("error body");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"],
            code
        );
    }

    for (protocol, status) in [
        (
            nazo_operator_protocol::ProtocolError::TooLarge,
            actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            nazo_operator_protocol::ProtocolError::SegmentCount,
            actix_web::http::StatusCode::BAD_REQUEST,
        ),
        (
            nazo_operator_protocol::ProtocolError::Base64,
            actix_web::http::StatusCode::BAD_REQUEST,
        ),
        (
            nazo_operator_protocol::ProtocolError::Json,
            actix_web::http::StatusCode::BAD_REQUEST,
        ),
        (
            nazo_operator_protocol::ProtocolError::Header,
            actix_web::http::StatusCode::UNAUTHORIZED,
        ),
        (
            nazo_operator_protocol::ProtocolError::Signature,
            actix_web::http::StatusCode::UNAUTHORIZED,
        ),
        (
            nazo_operator_protocol::ProtocolError::Policy("policy"),
            actix_web::http::StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(map_untrusted_jws_error(protocol).status_code(), status);
    }
    assert!(matches!(
        map_executor_error(TenantResourceExecutorError::Conflict),
        TenantResourceProviderError::Conflict(_)
    ));
    assert!(matches!(
        map_executor_error(TenantResourceExecutorError::Unavailable),
        TenantResourceProviderError::Unavailable(_)
    ));
    assert!(matches!(
        map_executor_error(TenantResourceExecutorError::Rejected),
        TenantResourceProviderError::BadRequest(_)
    ));
}

#[test]
fn provider_configuration_and_apply_manifest_boundaries_fail_closed() {
    let runtime = key(9);
    let valid = provider_config(&runtime);
    validate_provider_config(&valid).expect("valid config");
    let invalid_configs: Vec<TenantResourceProviderConfig> = vec![
        TenantResourceProviderConfig {
            tenant_id: "not-a-uuid".to_owned(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            deployment_id: String::new(),
            issuer: "runtime:".to_owned(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            runtime_instance_id: String::new(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            issuer: "runtime:other".to_owned(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            instance_key_id: "wrong-key".to_owned(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            resource_kinds: Vec::new(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            resource_kinds: vec![TenantResourceKind::User, TenantResourceKind::User],
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            actions: Vec::new(),
            ..valid.clone()
        },
        TenantResourceProviderConfig {
            actions: vec![
                TenantResourceOperation::Apply,
                TenantResourceOperation::Apply,
            ],
            ..valid
        },
    ];
    for invalid in invalid_configs {
        assert!(validate_provider_config(&invalid).is_err());
    }
    assert!(is_lower_sha256(&"a".repeat(64)));
    assert!(!is_lower_sha256(&"A".repeat(64)));
    assert!(!is_lower_sha256(&"a".repeat(63)));

    let (task, raw) = apply_task_and_manifest();
    let encoded = URL_SAFE_NO_PAD.encode(&raw);
    let prepared = prepare_task(&task, Some(&encoded)).expect("valid apply");
    assert_eq!(prepared.resources.len(), 1);
    assert!(matches!(
        prepared.resources[0].payload,
        Some(TenantResourcePayload::User(_))
    ));
    assert!(prepare_task(&task, None).is_err());
    assert!(matches!(
        prepare_task(&task, Some(&"x".repeat(MAX_MANIFEST_BYTES * 2 + 1))),
        Err(TenantResourceProviderError::TooLarge)
    ));
    assert!(prepare_task(&task, Some("%%%")).is_err());
    assert!(prepare_task(&task, Some("")).is_err());
    let oversized = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_MANIFEST_BYTES + 1]);
    assert!(matches!(
        prepare_task(&task, Some(&oversized)),
        Err(TenantResourceProviderError::TooLarge)
    ));

    let mut wrong_digest = task.clone();
    wrong_digest.change_set_sha256 = "f".repeat(64);
    assert!(matches!(
        prepare_task(&wrong_digest, Some(&encoded)),
        Err(TenantResourceProviderError::Forbidden(_))
    ));
    let invalid_json = b"not-json";
    let mut invalid_json_task = task.clone();
    invalid_json_task.change_set_sha256 = hex(invalid_json);
    assert!(
        prepare_task(
            &invalid_json_task,
            Some(&URL_SAFE_NO_PAD.encode(invalid_json))
        )
        .is_err()
    );

    for manifest in [
        json!({"schema": 2, "resources": [{
            "kind": "user", "resource_id": "user-1", "payload_base64url": "AA"
        }]}),
        json!({"schema": 1, "resources": []}),
        json!({"schema": 1, "unknown": true, "resources": []}),
    ] {
        let raw = serde_json::to_vec(&manifest).unwrap();
        let mut changed = task.clone();
        changed.change_set_sha256 = hex(&raw);
        assert!(prepare_task(&changed, Some(&URL_SAFE_NO_PAD.encode(raw))).is_err());
    }

    let user_payload = serde_json::to_vec(&json!({
        "username": "alice", "email": "alice@example.test", "password": "password",
        "email_verified": true
    }))
    .unwrap();
    let resource = |resource_id: &str, payload: &str| json!({"kind": "user", "resource_id": resource_id, "payload_base64url": payload});
    let invalid_manifests = [
        json!({"schema": 1, "resources": [resource("not valid", "AA")]}),
        json!({"schema": 1, "resources": [resource("user-1", "%%%")]}),
        json!({"schema": 1, "resources": [resource("user-1", "")]}),
        json!({"schema": 1, "resources": [
            resource("user-1", &URL_SAFE_NO_PAD.encode(&user_payload)),
            resource("user-1", &URL_SAFE_NO_PAD.encode(&user_payload)),
        ]}),
    ];
    for manifest in invalid_manifests {
        let raw = serde_json::to_vec(&manifest).unwrap();
        let mut changed = task.clone();
        changed.change_set_sha256 = hex(&raw);
        assert!(prepare_task(&changed, Some(&URL_SAFE_NO_PAD.encode(raw))).is_err());
    }
    let huge_payload = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_RESOURCE_PAYLOAD_BYTES + 1]);
    let raw = serde_json::to_vec(&json!({
        "schema": 1, "resources": [resource("user-1", &huge_payload)]
    }))
    .unwrap();
    let mut changed = task.clone();
    changed.change_set_sha256 = hex(&raw);
    assert!(matches!(
        prepare_task(&changed, Some(&URL_SAFE_NO_PAD.encode(raw))),
        Err(TenantResourceProviderError::TooLarge)
    ));

    let unauthorized_payload = serde_json::to_vec(&json!({
        "username": "bob", "email": "bob@example.test", "password": "password",
        "email_verified": false
    }))
    .unwrap();
    let raw = serde_json::to_vec(&json!({
        "schema": 1,
        "resources": [resource("user-2", &URL_SAFE_NO_PAD.encode(&unauthorized_payload))]
    }))
    .unwrap();
    let mut changed = task.clone();
    changed.change_set_sha256 = hex(&raw);
    assert!(matches!(
        prepare_task(&changed, Some(&URL_SAFE_NO_PAD.encode(raw))),
        Err(TenantResourceProviderError::Forbidden(_))
    ));
    let wrong_payload = serde_json::to_vec(&json!({
        "username": "mallory", "email": "alice@example.test", "password": "password",
        "email_verified": true
    }))
    .unwrap();
    let raw = serde_json::to_vec(&json!({
        "schema": 1,
        "resources": [resource("user-1", &URL_SAFE_NO_PAD.encode(&wrong_payload))]
    }))
    .unwrap();
    let mut changed = task.clone();
    changed.change_set_sha256 = hex(&raw);
    assert!(matches!(
        prepare_task(&changed, Some(&URL_SAFE_NO_PAD.encode(raw))),
        Err(TenantResourceProviderError::Forbidden(_))
    ));

    let mut extra_expected = task.clone();
    if let TenantResourceTaskPayload::Apply { resources } = &mut extra_expected.payload {
        resources.push(TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: "user-2".to_owned(),
            digest: "b".repeat(64),
        });
    }
    assert!(matches!(
        prepare_task(&extra_expected, Some(&encoded)),
        Err(TenantResourceProviderError::Forbidden(_))
    ));
    let mut duplicate_expected = task.clone();
    if let TenantResourceTaskPayload::Apply { resources } = &mut duplicate_expected.payload {
        resources.push(resources[0].clone());
    }
    assert!(prepare_task(&duplicate_expected, Some(&encoded)).is_err());
}

#[test]
fn non_apply_tasks_and_payload_decoders_enforce_operation_specific_contracts() {
    let (apply, raw) = apply_task_and_manifest();
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    let enumerate = TenantResourceTask {
        operation: TenantResourceOperation::Enumerate,
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: Vec::new(),
        },
        resource_manifest_sha256: "0".repeat(64),
        ..apply.clone()
    };
    assert!(prepare_task(&enumerate, Some(&encoded)).is_err());
    let prepared = prepare_task(&enumerate, None).expect("enumerate");
    assert!(prepared.resources.is_empty());
    assert!(task_resource_identities(&enumerate).is_err());
    let revoke = TenantResourceTask {
        operation: TenantResourceOperation::Revoke,
        payload: TenantResourceTaskPayload::Revoke {
            resources: match &apply.payload {
                TenantResourceTaskPayload::Apply { resources } => resources.clone(),
                _ => unreachable!(),
            },
        },
        ..apply.clone()
    };
    let prepared = prepare_task(&revoke, None).expect("revoke");
    assert_eq!(prepared.resources.len(), 1);
    assert!(prepared.resources[0].payload.is_none());
    let mismatched = TenantResourceTask {
        operation: TenantResourceOperation::Revoke,
        payload: apply.payload.clone(),
        ..apply
    };
    assert!(prepare_task(&mismatched, None).is_err());

    let malformed = *b"{}x";
    for kind in [
        TenantResourceKind::User,
        TenantResourceKind::OauthClient,
        TenantResourceKind::MtlsTrustAnchor,
        TenantResourceKind::Openid4vcDataset,
        TenantResourceKind::Openid4vcTrustPolicy,
    ] {
        assert!(decode_payload(kind, &malformed).is_err());
    }
    assert!(validate_resource_id("invalid id").is_err());
    assert!(validate_text("", 8).is_err());
    assert!(validate_text("abcdefghi", 8).is_err());
    assert!(validate_text("bad\ntext", 32).is_err());
    assert!(validate_text("valid", 8).is_ok());
}

#[tokio::test]
async fn capability_issuance_maps_identity_state_clock_and_signer_failures() {
    let request = || TenantResourceCapabilityRequest {
        schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
        nonce: URL_SAFE_NO_PAD.encode([8u8; 32]),
        tenant_id: TENANT.to_owned(),
    };
    let ProviderFixture {
        provider: provider_under_test,
        snapshot,
        ..
    } = provider();
    let mut invalid_nonce = request();
    invalid_nonce.nonce = "short".to_owned();
    assert!(matches!(
        provider_under_test
            .issue_capability(invalid_nonce, NOW)
            .await,
        Err(TenantResourceProviderError::BadRequest(_))
    ));
    let mut wrong_tenant = request();
    wrong_tenant.tenant_id = "00000000-0000-7000-8000-000000000002".to_owned();
    assert!(matches!(
        provider_under_test
            .issue_capability(wrong_tenant, NOW)
            .await,
        Err(TenantResourceProviderError::Forbidden(_))
    ));
    snapshot.lock().expect("snapshot").resource_manifest_sha256 = "A".repeat(64);
    assert!(matches!(
        provider_under_test.issue_capability(request(), NOW).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));

    for state_error in [
        TenantResourceExecutorError::Unavailable,
        TenantResourceExecutorError::Conflict,
        TenantResourceExecutorError::Rejected,
    ] {
        let ProviderFixture { mut provider, .. } = provider();
        provider.state = Arc::new(ErrorState(state_error));
        assert!(matches!(
            provider.issue_capability(request(), NOW).await,
            Err(TenantResourceProviderError::Unavailable(_))
        ));
    }
    let ProviderFixture { mut provider, .. } = provider();
    assert!(matches!(
        provider.issue_capability(request(), i64::MAX).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));
    provider.signer = Arc::new(InvalidSigner);
    assert!(matches!(
        provider.issue_capability(request(), NOW).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));
}

#[tokio::test]
async fn execute_maps_executor_failures_and_rejects_invalid_returned_evidence() {
    for executor_error in [
        TenantResourceExecutorError::Conflict,
        TenantResourceExecutorError::Unavailable,
        TenantResourceExecutorError::Rejected,
    ] {
        let ProviderFixture {
            mut provider,
            controller,
            runtime,
            ..
        } = provider();
        let (capability_jws, capability) = capability(&provider, &runtime).await;
        let (task_jws, raw_manifest) =
            manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
        provider.executor = Arc::new(StubExecutor(StubExecutorMode::ReplayError(
            executor_error.clone(),
        )));
        let error = provider
            .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
            .await
            .expect_err("replay error");
        assert_eq!(
            error.status_code(),
            map_executor_error(executor_error).status_code()
        );
    }
    for executor_error in [
        TenantResourceExecutorError::Conflict,
        TenantResourceExecutorError::Unavailable,
        TenantResourceExecutorError::Rejected,
    ] {
        let ProviderFixture {
            mut provider,
            controller,
            runtime,
            ..
        } = provider();
        let (capability_jws, capability) = capability(&provider, &runtime).await;
        let (task_jws, raw_manifest) =
            manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
        provider.executor = Arc::new(StubExecutor(StubExecutorMode::ExecuteError(
            executor_error.clone(),
        )));
        let error = provider
            .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
            .await
            .expect_err("execute error");
        assert_eq!(
            error.status_code(),
            map_executor_error(executor_error).status_code()
        );
    }

    for mode in [
        StubExecutorMode::ReplayReceipt("not-a-jws".to_owned()),
        StubExecutorMode::ExecuteReceipt("not-a-jws".to_owned()),
    ] {
        let ProviderFixture {
            mut provider,
            controller,
            runtime,
            ..
        } = provider();
        let (capability_jws, capability) = capability(&provider, &runtime).await;
        let (task_jws, raw_manifest) =
            manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
        provider.executor = Arc::new(StubExecutor(mode));
        assert!(matches!(
            provider
                .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
                .await,
            Err(TenantResourceProviderError::Unavailable(_))
        ));
    }
}

#[tokio::test]
async fn replayed_receipt_must_rebind_the_exact_task_and_request() {
    let ProviderFixture {
        mut provider,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let mut wrong_deployment_capability = capability.clone();
    wrong_deployment_capability.deployment_id = "deployment-other".to_owned();
    wrong_deployment_capability.issuer = "runtime:deployment-other".to_owned();
    let wrong_deployment_jws = sign_tenant_resource_capability(
        &wrong_deployment_capability,
        &instance_key_id(&runtime.verifying_key()),
        &runtime,
    )
    .unwrap();
    let (wrong_deployment_task, wrong_deployment_manifest) = manifest_and_task(
        &wrong_deployment_jws,
        &wrong_deployment_capability,
        &controller,
        Value::Null,
    );
    assert!(matches!(
        provider
            .execute(
                &envelope(
                    &wrong_deployment_jws,
                    &wrong_deployment_task,
                    &wrong_deployment_manifest,
                ),
                NOW,
            )
            .await,
        Err(TenantResourceProviderError::Forbidden(_))
    ));
    let request = envelope(&capability_jws, &task_jws, &raw_manifest);
    let response = provider
        .execute(&request, NOW)
        .await
        .expect("initial receipt");
    let receipt = nazo_operator_protocol::verify_tenant_resource_receipt_signature(
        &response.receipt_jws,
        &instance_key_id(&runtime.verifying_key()),
        &runtime.verifying_key(),
    )
    .expect("receipt");

    let sign = |receipt: &TenantResourceReceipt| {
        sign_tenant_resource_receipt(
            receipt,
            &instance_key_id(&runtime.verifying_key()),
            &runtime,
        )
        .expect("signed mutated receipt")
    };
    let mut wrong_request = receipt.clone();
    wrong_request.request_sha256 = "f".repeat(64);
    provider.executor = Arc::new(StubExecutor(StubExecutorMode::ReplayReceipt(sign(
        &wrong_request,
    ))));
    assert!(matches!(
        provider.execute(&request, NOW + 61).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));

    let mut wrong_task = receipt;
    wrong_task.change_set_id = "different-change-set".to_owned();
    provider.executor = Arc::new(StubExecutor(StubExecutorMode::ReplayReceipt(sign(
        &wrong_task,
    ))));
    assert!(matches!(
        provider.execute(&request, NOW + 61).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));
}

#[tokio::test]
async fn execute_rejects_malformed_envelopes_runtime_identity_and_expired_tasks() {
    let ProviderFixture {
        provider,
        controller,
        runtime,
        calls,
        ..
    } = provider();
    for invalid in [b"".as_slice(), b"{}", b"not-json"] {
        assert!(matches!(
            provider.execute(invalid, NOW).await,
            Err(TenantResourceProviderError::BadRequest(_))
        ));
    }
    let malformed = serde_json::to_vec(&json!({
        "capability_jws": "bad",
        "task_jws": "bad",
    }))
    .unwrap();
    assert!(provider.execute(&malformed, NOW).await.is_err());

    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let mut changed_capability = capability.clone();
    changed_capability.runtime_instance_id = "runtime-other".to_owned();
    let changed_capability_jws = sign_tenant_resource_capability(
        &changed_capability,
        &instance_key_id(&runtime.verifying_key()),
        &runtime,
    )
    .unwrap();
    let (changed_task_jws, changed_manifest) = manifest_and_task(
        &changed_capability_jws,
        &changed_capability,
        &controller,
        Value::Null,
    );
    assert!(matches!(
        provider
            .execute(
                &envelope(
                    &changed_capability_jws,
                    &changed_task_jws,
                    &changed_manifest,
                ),
                NOW,
            )
            .await,
        Err(TenantResourceProviderError::Forbidden(_))
    ));

    let task = nazo_operator_protocol::verify_tenant_resource_task_signature(
        &task_jws,
        &instance_key_id(&controller.verifying_key()),
        &controller.verifying_key(),
    )
    .unwrap();
    let expired_task = TenantResourceTask {
        iat: NOW - 90,
        nbf: NOW - 90,
        exp: NOW - 30,
        ..task
    };
    let expired_task_jws = sign_tenant_resource_task(
        &expired_task,
        &instance_key_id(&controller.verifying_key()),
        &controller,
    )
    .unwrap();
    assert!(matches!(
        provider
            .execute(
                &envelope(&capability_jws, &expired_task_jws, &raw_manifest),
                NOW,
            )
            .await,
        Err(TenantResourceProviderError::Forbidden(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn receipt_issuer_rejects_old_revisions_bad_signatures_and_capability_drift() {
    let ProviderFixture {
        provider: initial_provider,
        snapshot,
        controller,
        runtime,
        ..
    } = provider();
    {
        let mut state = snapshot.lock().expect("state");
        state.revision = 2;
        state.resource_manifest_sha256 = "0".repeat(64);
    }
    let (initial_capability_jws, initial_capability) =
        capability(&initial_provider, &runtime).await;
    let (task_jws, raw_manifest) = manifest_and_task(
        &initial_capability_jws,
        &initial_capability,
        &controller,
        Value::Null,
    );
    assert!(matches!(
        initial_provider
            .execute(
                &envelope(&initial_capability_jws, &task_jws, &raw_manifest),
                NOW,
            )
            .await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));

    let ProviderFixture {
        mut provider,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    provider.signer = Arc::new(InvalidReceiptSigner(runtime));
    assert!(matches!(
        provider
            .execute(&envelope(&capability_jws, &task_jws, &raw_manifest), NOW)
            .await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));

    let task = nazo_operator_protocol::verify_tenant_resource_task_signature(
        &task_jws,
        &instance_key_id(&controller.verifying_key()),
        &controller.verifying_key(),
    )
    .expect("task");
    let mut unsupported = capability;
    unsupported.resource_kinds = vec![TenantResourceKind::OauthClient];
    let signer = TestSigner {
        key: key(9),
        fail_receipt: Arc::new(AtomicBool::new(false)),
    };
    let capability_digest = compact_sha256(&capability_jws);
    let request_digest = "f".repeat(64);
    let signer_key_id = instance_key_id(&signer.key.verifying_key());
    let signer_verifying_key = signer.key.verifying_key();
    let issuer = BoundReceiptIssuer {
        task: &task,
        capability: &unsupported,
        capability_digest: &capability_digest,
        request_sha256: &request_digest,
        started_at: NOW,
        signer: &signer,
        instance_key_id: &signer_key_id,
        runtime_public_key: &signer_verifying_key,
    };
    assert!(matches!(
        issuer.issue(TenantResourceExecutionResult {
            revision: 1,
            resources: match &task.payload {
                TenantResourceTaskPayload::Apply { resources } => resources.clone(),
                _ => unreachable!(),
            },
            resource_mappings: vec![TenantResourceMapping {
                kind: TenantResourceKind::User,
                resource_id: "user-1".to_owned(),
                public_id: "018f0f79-5f3d-7e44-8000-000000000001".to_owned(),
            }],
            audit_sequence: 1,
            audit_previous_sha256: "0".repeat(64),
        }),
        Err(TenantResourceProviderError::Unavailable(_))
    ));
}

#[tokio::test]
async fn post_execute_receipt_is_revalidated_independently_of_the_executor() {
    let ProviderFixture {
        mut provider,
        controller,
        runtime,
        ..
    } = provider();
    let (capability_jws, capability) = capability(&provider, &runtime).await;
    let (task_jws, raw_manifest) =
        manifest_and_task(&capability_jws, &capability, &controller, Value::Null);
    let request = envelope(&capability_jws, &task_jws, &raw_manifest);
    let response = provider
        .execute(&request, NOW)
        .await
        .expect("valid receipt");
    let receipt = nazo_operator_protocol::verify_tenant_resource_receipt_signature(
        &response.receipt_jws,
        &instance_key_id(&runtime.verifying_key()),
        &runtime.verifying_key(),
    )
    .expect("receipt");
    let sign = |receipt: &TenantResourceReceipt| {
        sign_tenant_resource_receipt(
            receipt,
            &instance_key_id(&runtime.verifying_key()),
            &runtime,
        )
        .expect("mutated receipt")
    };

    let mut wrong_task = receipt.clone();
    wrong_task.change_set_id = "wrong-change-set".to_owned();
    provider.executor = Arc::new(StubExecutor(StubExecutorMode::ExecuteReceipt(sign(
        &wrong_task,
    ))));
    assert!(matches!(
        provider.execute(&request, NOW).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));
    let mut wrong_request = receipt;
    wrong_request.request_sha256 = "f".repeat(64);
    provider.executor = Arc::new(StubExecutor(StubExecutorMode::ExecuteReceipt(sign(
        &wrong_request,
    ))));
    assert!(matches!(
        provider.execute(&request, NOW).await,
        Err(TenantResourceProviderError::Unavailable(_))
    ));
}

#[actix_web::test]
async fn management_endpoints_return_stable_success_and_error_responses() {
    let ProviderFixture { provider, .. } = provider();
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(provider))
            .configure(crate::bootstrap::routes::configure_tenant_resource_management),
    )
    .await;
    let capability_request = actix_web::test::TestRequest::post()
        .uri("/management/tenant-resources/capability")
        .set_json(json!({
            "schema": nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
            "nonce": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "tenant_id": TENANT,
        }))
        .to_request();
    let response = actix_web::test::call_service(&app, capability_request).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);

    let denied_request = actix_web::test::TestRequest::post()
        .uri("/management/tenant-resources/capability")
        .set_json(json!({
            "schema": nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
            "nonce": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "tenant_id": "00000000-0000-7000-8000-000000000002",
        }))
        .to_request();
    let response = actix_web::test::call_service(&app, denied_request).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);

    let malformed_execute = actix_web::test::TestRequest::post()
        .uri("/management/tenant-resources/execute")
        .insert_header((
            actix_web::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        ))
        .set_payload("{}")
        .to_request();
    let response = actix_web::test::call_service(&app, malformed_execute).await;
    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
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
    let missing = root.join("missing.pub");
    assert!(matches!(
        load_controller_public_key(&missing),
        Err(TenantResourceProviderError::Unavailable(_))
    ));
    let directory = root.join("directory");
    fs::create_dir(&directory).expect("directory");
    assert_eq!(
        load_controller_public_key(&directory)
            .expect_err("directory")
            .status_code(),
        actix_web::http::StatusCode::FORBIDDEN
    );
    let oversized = root.join("oversized.pub");
    fs::write(&oversized, vec![b'a'; 4097]).expect("oversized key");
    assert!(matches!(
        load_controller_public_key(&oversized),
        Err(TenantResourceProviderError::TooLarge)
    ));
    let invalid_utf8 = root.join("invalid-utf8.pub");
    fs::write(&invalid_utf8, [0xff, 0xfe]).expect("invalid UTF-8 key");
    assert!(matches!(
        load_controller_public_key(&invalid_utf8),
        Err(TenantResourceProviderError::Unavailable(_))
    ));
    let invalid_base64 = root.join("invalid-base64.pub");
    fs::write(&invalid_base64, "%%%").expect("invalid base64 key");
    assert!(matches!(
        load_controller_public_key(&invalid_base64),
        Err(TenantResourceProviderError::Forbidden(_))
    ));
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

#[test]
fn ordinary_resource_payloads_are_typed_bounded_and_dependency_fenced() {
    let user = serde_json::to_vec(&json!({
        "username": "ordinary-user",
        "email": "ordinary-user@example.test",
        "password": "correct horse battery staple",
        "email_verified": true,
        "profile": {"display_name": "Ordinary User"}
    }))
    .unwrap();
    assert!(matches!(
        decode_payload(TenantResourceKind::User, &user).unwrap(),
        TenantResourcePayload::User(value)
            if value.username == "ordinary-user"
                && value.email_verified
                && value.profile == Some(json!({"display_name": "Ordinary User"}))
    ));
    for invalid in [
        json!({
            "username": "",
            "email": "ordinary-user@example.test",
            "password": "secret",
            "email_verified": false
        }),
        json!({
            "username": "ordinary-user",
            "email": "ordinary-user@example.test",
            "password": "x".repeat(MAX_PASSWORD_BYTES + 1),
            "email_verified": false
        }),
        json!({
            "username": "ordinary-user",
            "email": "ordinary-user@example.test",
            "password": "secret",
            "email_verified": false,
            "profile": {"large": "x".repeat(MAX_PROFILE_BYTES + 1)}
        }),
    ] {
        assert!(
            decode_payload(
                TenantResourceKind::User,
                &serde_json::to_vec(&invalid).unwrap(),
            )
            .is_err()
        );
    }

    let oauth = serde_json::to_vec(&json!({
        "request": {
            "client_name": "ordinary-client",
            "client_type": "confidential",
            "redirect_uris": ["https://client.example/callback"],
            "scopes": ["openid"],
            "allowed_audiences": ["resource://default"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks": null
        },
        "supplied_secret": "0123456789abcdef0123456789abcdef",
        "trust_policy_resource_id": "wallet-policy"
    }))
    .unwrap();
    assert!(matches!(
        decode_payload(TenantResourceKind::OauthClient, &oauth).unwrap(),
        TenantResourcePayload::OauthClient(value)
            if value.request.client_name == "ordinary-client"
                && value.supplied_secret.as_deref()
                    == Some("0123456789abcdef0123456789abcdef")
                && value.trust_policy_resource_id.as_deref() == Some("wallet-policy")
    ));
    let invalid_oauth = serde_json::to_vec(&json!({
        "request": {
            "client_name": "ordinary-client",
            "client_type": "public",
            "redirect_uris": [],
            "scopes": [],
            "allowed_audiences": [],
            "grant_types": [],
            "token_endpoint_auth_method": "none",
            "jwks": null
        },
        "supplied_secret": "x".repeat(MAX_CLIENT_SECRET_BYTES + 1),
        "trust_policy_resource_id": "wallet-policy"
    }))
    .unwrap();
    assert!(decode_payload(TenantResourceKind::OauthClient, &invalid_oauth).is_err());

    let mtls = serde_json::to_vec(&json!({
        "client_resource_id": "ordinary-client",
        "certificate_pem": "-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n"
    }))
    .unwrap();
    assert!(matches!(
        decode_payload(TenantResourceKind::MtlsTrustAnchor, &mtls).unwrap(),
        TenantResourcePayload::MtlsTrustAnchor(value)
            if value.client_resource_id == "ordinary-client"
    ));
    assert!(
        decode_payload(
            TenantResourceKind::MtlsTrustAnchor,
            &serde_json::to_vec(&json!({
                "client_resource_id": "ordinary-client",
                "certificate_pem": "not-a-certificate"
            }))
            .unwrap(),
        )
        .is_err()
    );

    let dataset = serde_json::to_vec(&json!({
        "user_resource_id": "ordinary-user",
        "configuration_id": "pid-sd-jwt",
        "claims": {"given_name": "Nazo"}
    }))
    .unwrap();
    assert!(matches!(
        decode_payload(TenantResourceKind::Openid4vcDataset, &dataset).unwrap(),
        TenantResourcePayload::Openid4vcDataset(value)
            if value.user_resource_id == "ordinary-user"
                && value.configuration_id == "pid-sd-jwt"
                && value.claims == json!({"given_name": "Nazo"})
    ));
    for invalid in [
        json!({
            "user_resource_id": "ordinary-user",
            "configuration_id": "pid-sd-jwt",
            "claims": ["not", "an", "object"]
        }),
        json!({
            "user_resource_id": "ordinary-user",
            "configuration_id": "pid-sd-jwt",
            "claims": {"large": "x".repeat(MAX_DATASET_CLAIMS_BYTES + 1)}
        }),
    ] {
        assert!(
            decode_payload(
                TenantResourceKind::Openid4vcDataset,
                &serde_json::to_vec(&invalid).unwrap(),
            )
            .is_err()
        );
    }
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
