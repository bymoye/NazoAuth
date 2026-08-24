//! Tenant-scoped machine resource management.
//!
//! This module authenticates a controller, binds a task to a freshly signed
//! runtime capability, validates an optional resource manifest, and hands the
//! prepared operation to a focused executor.  The executor owns persistence;
//! this module owns only the wire and trust boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read as _,
    path::Path,
    sync::Arc,
};

use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use futures_util::future::BoxFuture;
use nazo_auth::CreateClientRequest;
use nazo_operator_protocol::{
    ActorKind, EmbeddedIdentity, Openid4vcTrustPolicy, ProtocolError, TenantResourceCapability,
    TenantResourceIdentity, TenantResourceKind, TenantResourceMapping, TenantResourceOperation,
    TenantResourceOutcome, TenantResourceReceipt, TenantResourceTask, TenantResourceTaskPayload,
    compact_sha256, instance_key_id, validate_discovery_request, validate_openid4vc_trust_policy,
    validate_tenant_resource_capability, validate_tenant_resource_capability_binding,
    validate_tenant_resource_capability_request_binding, validate_tenant_resource_receipt_binding,
    validate_tenant_resource_receipt_capability_binding_at,
    validate_tenant_resource_receipt_capability_binding_with_digest,
    validate_tenant_resource_receipt_request_binding,
    validate_tenant_resource_task_capability_binding_at,
    validate_tenant_resource_task_capability_binding_with_digest,
    validate_tenant_resource_task_deployment_binding, verify_tenant_resource_capability,
    verify_tenant_resource_capability_signature, verify_tenant_resource_receipt,
    verify_tenant_resource_receipt_signature, verify_tenant_resource_task_signature,
    verify_tenant_resource_task_window,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// Environment/configuration name for the pinned controller public key.
pub const TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE: &str =
    "TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE";

/// Maximum encoded JSON body accepted by the execute endpoint.
pub const MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES: usize = 4 * 1024 * 1024;

const APPLY_MANIFEST_SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESOURCE_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_RESOURCE_PAYLOAD_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_USERNAME_BYTES: usize = 150;
const MAX_EMAIL_BYTES: usize = 254;
const MAX_PASSWORD_BYTES: usize = 512;
const MAX_CLIENT_SECRET_BYTES: usize = 512;
const MAX_CONFIGURATION_ID_BYTES: usize = 255;
const MAX_PROFILE_BYTES: usize = 128 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
const MAX_DATASET_CLAIMS_BYTES: usize = 256 * 1024;
const RECEIPT_LIFETIME_SECONDS: i64 = 60;

/// A controller public key loaded from a privileged, pinned regular file.
#[derive(Clone, Debug)]
pub struct ControllerPublicKey {
    pub verifying_key: VerifyingKey,
    pub key_id: String,
}

/// Load a base64url (unpadded) Ed25519 public key from a regular file.
///
/// Symlinks, directories, device files, and keys of any size other than 32
/// bytes are rejected.  A missing file is reported to the caller; the caller
/// decides whether that means this optional provider is disabled.
pub fn load_controller_public_key(
    path: &Path,
) -> Result<ControllerPublicKey, TenantResourceProviderError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| {
        TenantResourceProviderError::Unavailable("controller public key is unavailable")
    })?;
    if !path_metadata.file_type().is_file() {
        return Err(TenantResourceProviderError::Forbidden(
            "controller public key must be a regular file",
        ));
    }
    let file = File::open(path).map_err(|_| {
        TenantResourceProviderError::Unavailable("controller public key cannot be read")
    })?;
    let metadata = file.metadata().map_err(|_| {
        TenantResourceProviderError::Unavailable("controller public key cannot be inspected")
    })?;
    if !metadata.file_type().is_file() {
        return Err(TenantResourceProviderError::Forbidden(
            "controller public key must be a regular file",
        ));
    }
    if metadata.len() > 4096 {
        return Err(TenantResourceProviderError::TooLarge);
    }
    let mut encoded = String::new();
    file.take(4097).read_to_string(&mut encoded).map_err(|_| {
        TenantResourceProviderError::Unavailable("controller public key cannot be read")
    })?;
    if encoded.len() > 4096 {
        return Err(TenantResourceProviderError::TooLarge);
    }
    let encoded = encoded.trim();
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TenantResourceProviderError::Forbidden("controller public key is invalid"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| TenantResourceProviderError::Forbidden("controller public key is invalid"))?;
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| TenantResourceProviderError::Forbidden("controller public key is invalid"))?;
    let key_id = instance_key_id(&verifying_key);
    Ok(ControllerPublicKey {
        verifying_key,
        key_id,
    })
}

/// Request for a tenant capability.  The nonce uses exactly the same strict
/// validation as the deployment control-discovery endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceCapabilityRequest {
    pub schema: u32,
    pub nonce: String,
    pub tenant_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceCapabilityResponse {
    pub capability_jws: String,
}

/// Signed request envelope accepted by the machine execute endpoint.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceExecuteEnvelope {
    pub capability_jws: String,
    pub task_jws: String,
    #[serde(default)]
    pub manifest_base64url: Option<String>,
}

/// Runtime identity and capability snapshot used to issue capabilities.
#[derive(Clone)]
pub struct TenantResourceProviderConfig {
    pub deployment_id: String,
    pub tenant_id: String,
    pub runtime_instance_id: String,
    pub issuer: String,
    pub instance_key_id: String,
    pub runtime_public_key: VerifyingKey,
    pub embedded: EmbeddedIdentity,
    pub resource_kinds: Vec<TenantResourceKind>,
    pub actions: Vec<TenantResourceOperation>,
}

/// Authoritative state observed for each issued capability.  This cannot be a
/// startup snapshot: a successful mutation advances both values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceStateSnapshot {
    pub revision: u64,
    pub resource_manifest_sha256: String,
}

pub trait TenantResourceStateSource: Send + Sync {
    fn current<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<TenantResourceStateSnapshot, TenantResourceExecutorError>>;
}

/// Signing boundary supplied by `ControlDiscoveryEndpoint` and the runtime
/// identity owner.  Keeping it as a trait avoids exposing the endpoint's
/// private signing key to this provider.
pub trait TenantResourceSigner: Send + Sync {
    fn sign_capability(
        &self,
        capability: &TenantResourceCapability,
    ) -> Result<String, TenantResourceProviderError>;

    fn sign_receipt(
        &self,
        receipt: &TenantResourceReceipt,
    ) -> Result<String, TenantResourceProviderError>;
}

/// Typed, already validated resource payload handed to the persistence layer.
#[derive(Clone)]
pub enum TenantResourcePayload {
    User(UserResourcePayload),
    OauthClient(Box<OauthClientResourcePayload>),
    MtlsTrustAnchor(MtlsTrustAnchorResourcePayload),
    Openid4vcDataset(Openid4vcDatasetResourcePayload),
    Openid4vcTrustPolicy(Box<Openid4vcTrustPolicyResourcePayload>),
}

#[derive(Clone)]
pub struct UserResourcePayload {
    pub username: String,
    pub email: String,
    pub password: String,
    pub email_verified: bool,
    pub profile: Option<Value>,
}

#[derive(Clone)]
pub struct OauthClientResourcePayload {
    pub request: CreateClientRequest,
    pub supplied_secret: Option<String>,
    pub trust_policy_resource_id: Option<String>,
}

#[derive(Clone)]
pub struct MtlsTrustAnchorResourcePayload {
    pub client_resource_id: String,
    pub certificate_pem: String,
}

#[derive(Clone)]
pub struct Openid4vcDatasetResourcePayload {
    pub user_resource_id: String,
    pub configuration_id: String,
    pub claims: Value,
}

#[derive(Clone)]
pub struct Openid4vcTrustPolicyResourcePayload {
    pub public_material: Openid4vcTrustPolicy,
}

#[derive(Clone)]
pub struct PreparedTenantResource {
    pub identity: TenantResourceIdentity,
    /// Revoke/enumerate carry no desired payload.  Apply always carries one.
    pub payload: Option<TenantResourcePayload>,
}

#[derive(Clone)]
pub struct PreparedTenantResourceTask {
    pub task: TenantResourceTask,
    /// SHA-256 of the exact execute-envelope bytes accepted by the provider.
    pub request_sha256: String,
    pub resources: Vec<PreparedTenantResource>,
}

#[derive(Clone, Debug)]
pub struct TenantResourceExecutionResult {
    pub revision: u64,
    pub resources: Vec<TenantResourceIdentity>,
    /// Public identifiers assigned by the authoritative resource services.
    /// Only successful Apply operations may populate this collection.
    pub resource_mappings: Vec<TenantResourceMapping>,
    pub audit_sequence: u64,
    pub audit_previous_sha256: String,
}

pub struct IssuedTenantResourceReceipt {
    pub receipt: TenantResourceReceipt,
    pub compact: String,
}

/// Signs the final receipt inside the executor's caller-owned database
/// transaction.  A signing failure therefore rolls resource, audit, and
/// operation evidence back together.
pub trait TenantResourceReceiptIssuer: Send + Sync {
    fn issue(
        &self,
        result: TenantResourceExecutionResult,
    ) -> Result<IssuedTenantResourceReceipt, TenantResourceProviderError>;
}

#[derive(Clone, Debug)]
pub enum TenantResourceExecutorError {
    Conflict,
    Unavailable,
    Rejected,
}

/// Focused persistence boundary.  The provider never writes users, clients,
/// trust anchors, or credential datasets itself.
pub trait TenantResourceExecutor: Send + Sync {
    fn replay<'a>(
        &'a self,
        task: &'a PreparedTenantResourceTask,
    ) -> BoxFuture<'a, Result<Option<String>, TenantResourceExecutorError>>;

    fn execute<'a>(
        &'a self,
        task: PreparedTenantResourceTask,
        receipt_issuer: &'a dyn TenantResourceReceiptIssuer,
    ) -> BoxFuture<'a, Result<String, TenantResourceExecutorError>>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceExecutionResponse {
    pub receipt_jws: String,
}

#[derive(Debug)]
pub enum TenantResourceProviderError {
    BadRequest(&'static str),
    Unauthorized(&'static str),
    Forbidden(&'static str),
    Conflict(&'static str),
    TooLarge,
    Unavailable(&'static str),
}

impl std::fmt::Display for TenantResourceProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BadRequest(message)
            | Self::Unauthorized(message)
            | Self::Forbidden(message)
            | Self::Conflict(message)
            | Self::Unavailable(message) => message,
            Self::TooLarge => "request too large",
        })
    }
}

impl std::error::Error for TenantResourceProviderError {}

impl TenantResourceProviderError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "invalid_request",
            Self::Unauthorized(_) => "invalid_signature",
            Self::Forbidden(_) => "policy_denied",
            Self::Conflict(_) => "revision_conflict",
            Self::TooLarge => "request_too_large",
            Self::Unavailable(_) => "provider_unavailable",
        }
    }

    pub fn into_http_response(self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": self.stable_code(),
        }))
    }
}

fn map_untrusted_jws_error(error: ProtocolError) -> TenantResourceProviderError {
    match error {
        ProtocolError::TooLarge => TenantResourceProviderError::TooLarge,
        ProtocolError::SegmentCount | ProtocolError::Base64 | ProtocolError::Json => {
            TenantResourceProviderError::BadRequest("malformed signed evidence")
        }
        ProtocolError::Header | ProtocolError::Signature => {
            TenantResourceProviderError::Unauthorized("invalid signed evidence")
        }
        ProtocolError::Policy(_) => {
            TenantResourceProviderError::BadRequest("signed evidence violates protocol policy")
        }
    }
}

pub struct TenantResourceProvider {
    controller: ControllerPublicKey,
    config: TenantResourceProviderConfig,
    signer: Arc<dyn TenantResourceSigner>,
    state: Arc<dyn TenantResourceStateSource>,
    executor: Arc<dyn TenantResourceExecutor>,
}

impl TenantResourceProvider {
    pub fn new(
        controller: ControllerPublicKey,
        config: TenantResourceProviderConfig,
        signer: Arc<dyn TenantResourceSigner>,
        state: Arc<dyn TenantResourceStateSource>,
        executor: Arc<dyn TenantResourceExecutor>,
    ) -> Result<Self, TenantResourceProviderError> {
        validate_provider_config(&config)?;
        Ok(Self {
            controller,
            config,
            signer,
            state,
            executor,
        })
    }

    pub async fn issue_capability(
        &self,
        request: TenantResourceCapabilityRequest,
        now: i64,
    ) -> Result<TenantResourceCapabilityResponse, TenantResourceProviderError> {
        validate_discovery_request(&nazo_operator_protocol::DiscoveryRequest {
            schema: request.schema,
            nonce: request.nonce.clone(),
        })
        .map_err(|_| TenantResourceProviderError::BadRequest("invalid capability nonce"))?;
        if request.tenant_id != self.config.tenant_id {
            return Err(TenantResourceProviderError::Forbidden(
                "capability tenant binding mismatch",
            ));
        }
        let state = self.state.current().await.map_err(|error| match error {
            TenantResourceExecutorError::Unavailable => {
                TenantResourceProviderError::Unavailable("resource state unavailable")
            }
            TenantResourceExecutorError::Conflict | TenantResourceExecutorError::Rejected => {
                TenantResourceProviderError::Unavailable("resource state is inconsistent")
            }
        })?;
        if !is_lower_sha256(&state.resource_manifest_sha256) {
            return Err(TenantResourceProviderError::Unavailable(
                "resource state is inconsistent",
            ));
        }
        let capability = TenantResourceCapability {
            ver: nazo_operator_protocol::PROTOCOL_VERSION,
            capability_version: nazo_operator_protocol::TENANT_RESOURCE_CAPABILITY_VERSION,
            jti: Uuid::now_v7().to_string(),
            nonce: request.nonce.clone(),
            deployment_id: self.config.deployment_id.clone(),
            tenant_id: self.config.tenant_id.clone(),
            runtime_instance_id: self.config.runtime_instance_id.clone(),
            issuer: self.config.issuer.clone(),
            instance_key_id: self.config.instance_key_id.clone(),
            embedded: self.config.embedded.clone(),
            revision: state.revision,
            resource_manifest_sha256: state.resource_manifest_sha256,
            resource_kinds: self.config.resource_kinds.clone(),
            actions: self.config.actions.clone(),
            issued_at: now,
            expires_at: now
                .checked_add(RECEIPT_LIFETIME_SECONDS)
                .ok_or(TenantResourceProviderError::Unavailable("clock overflow"))?,
        };
        validate_tenant_resource_capability_request_binding(
            &capability,
            &self.config.deployment_id,
            &self.config.tenant_id,
            &capability.jti,
            &request.nonce,
        )
        .map_err(|_| TenantResourceProviderError::BadRequest("invalid capability"))?;
        let compact = self.signer.sign_capability(&capability)?;
        verify_tenant_resource_capability(
            &compact,
            &self.config.instance_key_id,
            &self.config.runtime_public_key,
            now,
        )
        .map_err(|_| {
            TenantResourceProviderError::Unavailable("capability signer returned invalid evidence")
        })?;
        Ok(TenantResourceCapabilityResponse {
            capability_jws: compact,
        })
    }

    pub async fn execute(
        &self,
        body: &[u8],
        now: i64,
    ) -> Result<TenantResourceExecutionResponse, TenantResourceProviderError> {
        if body.len() > MAX_TENANT_RESOURCE_EXECUTE_BODY_BYTES {
            return Err(TenantResourceProviderError::TooLarge);
        }
        let envelope: TenantResourceExecuteEnvelope = serde_json::from_slice(body)
            .map_err(|_| TenantResourceProviderError::BadRequest("invalid execute envelope"))?;
        let capability = verify_tenant_resource_capability_signature(
            &envelope.capability_jws,
            &self.config.instance_key_id,
            &self.config.runtime_public_key,
        )
        .map_err(map_untrusted_jws_error)?;
        validate_tenant_resource_capability_binding(
            &capability,
            &self.config.deployment_id,
            &self.config.tenant_id,
        )
        .map_err(|_| {
            TenantResourceProviderError::Forbidden("capability deployment or tenant mismatch")
        })?;
        if capability.runtime_instance_id != self.config.runtime_instance_id
            || capability.instance_key_id != self.config.instance_key_id
        {
            return Err(TenantResourceProviderError::Forbidden(
                "capability runtime identity mismatch",
            ));
        }

        let task = verify_tenant_resource_task_signature(
            &envelope.task_jws,
            &self.controller.key_id,
            &self.controller.verifying_key,
        )
        .map_err(map_untrusted_jws_error)?;
        if task.actor.kind != ActorKind::Automation {
            return Err(TenantResourceProviderError::Forbidden(
                "machine resource tasks require an automation actor",
            ));
        }
        validate_tenant_resource_task_deployment_binding(
            &task,
            &self.config.deployment_id,
            &self.config.tenant_id,
        )
        .map_err(|_| {
            TenantResourceProviderError::Forbidden("task deployment or tenant mismatch")
        })?;
        let capability_digest = compact_sha256(&envelope.capability_jws);
        validate_tenant_resource_task_capability_binding_with_digest(
            &task,
            &capability,
            &capability_digest,
        )
        .map_err(|_| TenantResourceProviderError::Forbidden("task capability binding mismatch"))?;

        let request_sha256 = sha256_hex(body);
        let mut prepared = prepare_task(&task, envelope.manifest_base64url.as_deref())?;
        prepared.request_sha256.clone_from(&request_sha256);
        if let Some(compact) = self
            .executor
            .replay(&prepared)
            .await
            .map_err(map_executor_error)?
        {
            let receipt = verify_tenant_resource_receipt_signature(
                &compact,
                &self.config.instance_key_id,
                &self.config.runtime_public_key,
            )
            .map_err(|_| {
                TenantResourceProviderError::Unavailable(
                    "persisted executor receipt signature is invalid",
                )
            })?;
            validate_tenant_resource_receipt_binding(&task, &receipt).map_err(|_| {
                TenantResourceProviderError::Unavailable(
                    "persisted executor receipt data is invalid",
                )
            })?;
            validate_tenant_resource_receipt_capability_binding_with_digest(
                &receipt,
                &capability,
                &capability_digest,
            )
            .map_err(|_| {
                TenantResourceProviderError::Unavailable(
                    "persisted executor capability binding is invalid",
                )
            })?;
            validate_tenant_resource_receipt_request_binding(&receipt, &request_sha256).map_err(
                |_| {
                    TenantResourceProviderError::Unavailable(
                        "persisted executor request binding is invalid",
                    )
                },
            )?;
            return Ok(TenantResourceExecutionResponse {
                receipt_jws: compact,
            });
        }
        validate_tenant_resource_capability(&capability, now).map_err(|_| {
            TenantResourceProviderError::Forbidden("capability is outside its validity window")
        })?;
        verify_tenant_resource_task_window(&task, now).map_err(|_| {
            TenantResourceProviderError::Forbidden("task is outside its validity window")
        })?;
        validate_tenant_resource_task_capability_binding_at(
            &task,
            &capability,
            &capability_digest,
            now,
        )
        .map_err(|_| TenantResourceProviderError::Forbidden("task capability binding mismatch"))?;
        let started_at = now;
        let receipt_issuer = BoundReceiptIssuer {
            task: &task,
            capability: &capability,
            capability_digest: &capability_digest,
            request_sha256: &request_sha256,
            started_at,
            signer: self.signer.as_ref(),
            instance_key_id: &self.config.instance_key_id,
            runtime_public_key: &self.config.runtime_public_key,
        };
        let compact = self
            .executor
            .execute(prepared, &receipt_issuer)
            .await
            .map_err(map_executor_error)?;
        let completed_at = Utc::now().timestamp().max(started_at);
        let receipt = verify_tenant_resource_receipt(
            &compact,
            &self.config.instance_key_id,
            &self.config.runtime_public_key,
            completed_at,
        )
        .map_err(|_| {
            TenantResourceProviderError::Unavailable("executor returned invalid receipt evidence")
        })?;
        validate_tenant_resource_receipt_binding(&task, &receipt).map_err(|_| {
            TenantResourceProviderError::Unavailable("executor returned invalid receipt data")
        })?;
        validate_tenant_resource_receipt_capability_binding_at(
            &receipt,
            &capability,
            &capability_digest,
            now,
        )
        .map_err(|_| {
            TenantResourceProviderError::Unavailable("executor returned invalid capability data")
        })?;
        validate_tenant_resource_receipt_request_binding(&receipt, &request_sha256).map_err(
            |_| TenantResourceProviderError::Unavailable("receipt request binding failed"),
        )?;
        Ok(TenantResourceExecutionResponse {
            receipt_jws: compact,
        })
    }

    pub async fn execute_http(&self, body: web::Bytes) -> HttpResponse {
        match self.execute(&body, Utc::now().timestamp()).await {
            Ok(response) => HttpResponse::Ok().json(response),
            Err(error) => error.into_http_response(),
        }
    }
}

fn map_executor_error(error: TenantResourceExecutorError) -> TenantResourceProviderError {
    match error {
        TenantResourceExecutorError::Conflict => {
            TenantResourceProviderError::Conflict("resource revision is stale")
        }
        TenantResourceExecutorError::Unavailable => {
            TenantResourceProviderError::Unavailable("resource persistence unavailable")
        }
        TenantResourceExecutorError::Rejected => {
            TenantResourceProviderError::BadRequest("resource operation rejected")
        }
    }
}

pub async fn tenant_resource_capability_endpoint(
    provider: web::Data<TenantResourceProvider>,
    request: web::Json<TenantResourceCapabilityRequest>,
) -> HttpResponse {
    match provider
        .issue_capability(request.into_inner(), Utc::now().timestamp())
        .await
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(error) => error.into_http_response(),
    }
}

pub async fn tenant_resource_execute_endpoint(
    provider: web::Data<TenantResourceProvider>,
    request: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let is_json = request
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return TenantResourceProviderError::BadRequest("execute body must be JSON")
            .into_http_response();
    }
    provider.execute_http(body).await
}

struct BoundReceiptIssuer<'a> {
    task: &'a TenantResourceTask,
    capability: &'a TenantResourceCapability,
    capability_digest: &'a str,
    request_sha256: &'a str,
    started_at: i64,
    signer: &'a dyn TenantResourceSigner,
    instance_key_id: &'a str,
    runtime_public_key: &'a VerifyingKey,
}

impl TenantResourceReceiptIssuer for BoundReceiptIssuer<'_> {
    fn issue(
        &self,
        result: TenantResourceExecutionResult,
    ) -> Result<IssuedTenantResourceReceipt, TenantResourceProviderError> {
        if result.revision < self.task.expected_revision {
            return Err(TenantResourceProviderError::Unavailable(
                "executor returned a revision older than the request",
            ));
        }
        let completed_at = Utc::now().timestamp().max(self.started_at);
        let receipt = TenantResourceReceipt {
            ver: nazo_operator_protocol::PROTOCOL_VERSION,
            iss: format!("runtime:{}", self.task.deployment_id),
            aud: format!("controller:{}", self.task.deployment_id),
            jti: self.task.jti.clone(),
            request_sha256: self.request_sha256.to_owned(),
            deployment_id: self.task.deployment_id.clone(),
            tenant_id: self.task.tenant_id.clone(),
            capability_jti: self.task.capability_jti.clone(),
            capability_sha256: self.task.capability_sha256.clone(),
            actor: self.task.actor.clone(),
            change_set_id: self.task.change_set_id.clone(),
            change_set_sha256: self.task.change_set_sha256.clone(),
            operation: self.task.operation,
            expected_revision: self.task.expected_revision,
            revision: result.revision,
            outcome: TenantResourceOutcome::Succeeded,
            resources: result.resources,
            resource_mappings: result.resource_mappings,
            baseline_manifest_sha256: self.task.baseline_manifest_sha256.clone(),
            resource_manifest_sha256: self.task.resource_manifest_sha256.clone(),
            started_at: self.started_at,
            completed_at,
            exp: completed_at
                .checked_add(RECEIPT_LIFETIME_SECONDS)
                .ok_or(TenantResourceProviderError::Unavailable("clock overflow"))?,
            audit_sequence: result.audit_sequence,
            audit_previous_sha256: result.audit_previous_sha256,
        };
        validate_tenant_resource_receipt_binding(self.task, &receipt)
            .map_err(|_| TenantResourceProviderError::Unavailable("invalid receipt data"))?;
        validate_tenant_resource_receipt_capability_binding_at(
            &receipt,
            self.capability,
            self.capability_digest,
            self.started_at,
        )
        .map_err(|_| TenantResourceProviderError::Unavailable("invalid receipt capability data"))?;
        validate_tenant_resource_receipt_request_binding(&receipt, self.request_sha256).map_err(
            |_| TenantResourceProviderError::Unavailable("invalid receipt request data"),
        )?;
        let compact = self.signer.sign_receipt(&receipt)?;
        verify_tenant_resource_receipt(
            &compact,
            self.instance_key_id,
            self.runtime_public_key,
            completed_at,
        )
        .map_err(|_| {
            TenantResourceProviderError::Unavailable("receipt signer returned invalid evidence")
        })?;
        Ok(IssuedTenantResourceReceipt { receipt, compact })
    }
}

fn validate_provider_config(
    config: &TenantResourceProviderConfig,
) -> Result<(), TenantResourceProviderError> {
    let kinds: BTreeSet<_> = config.resource_kinds.iter().copied().collect();
    let actions: BTreeSet<_> = config.actions.iter().copied().collect();
    let tenant_is_canonical = Uuid::parse_str(&config.tenant_id)
        .map(|tenant| tenant.to_string() == config.tenant_id)
        .unwrap_or(false);
    if !tenant_is_canonical
        || config.deployment_id.is_empty()
        || config.runtime_instance_id.is_empty()
        || config.issuer != format!("runtime:{}", config.deployment_id)
        || config.instance_key_id != instance_key_id(&config.runtime_public_key)
        || config.resource_kinds.is_empty()
        || kinds.len() != config.resource_kinds.len()
        || config.actions.is_empty()
        || actions.len() != config.actions.len()
    {
        return Err(TenantResourceProviderError::BadRequest(
            "invalid provider identity",
        ));
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyManifest {
    schema: u32,
    resources: Vec<ManifestResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestResource {
    kind: TenantResourceKind,
    resource_id: String,
    payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserManifestPayload {
    username: String,
    email: String,
    password: String,
    email_verified: bool,
    #[serde(default)]
    profile: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OauthClientManifestPayload {
    request: CreateClientRequest,
    #[serde(default)]
    supplied_secret: Option<String>,
    #[serde(default)]
    trust_policy_resource_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MtlsTrustAnchorManifestPayload {
    client_resource_id: String,
    certificate_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Openid4vcDatasetManifestPayload {
    user_resource_id: String,
    configuration_id: String,
    claims: Value,
}

fn prepare_task(
    task: &TenantResourceTask,
    encoded_manifest: Option<&str>,
) -> Result<PreparedTenantResourceTask, TenantResourceProviderError> {
    match (&task.operation, encoded_manifest) {
        (TenantResourceOperation::Apply, None) => {
            return Err(TenantResourceProviderError::BadRequest(
                "apply requires a resource manifest",
            ));
        }
        (TenantResourceOperation::Enumerate | TenantResourceOperation::Revoke, Some(_)) => {
            return Err(TenantResourceProviderError::BadRequest(
                "manifest is only valid for apply",
            ));
        }
        _ => {}
    }

    if let TenantResourceOperation::Apply = task.operation {
        let Some(encoded) = encoded_manifest else {
            return Err(TenantResourceProviderError::BadRequest(
                "apply requires a resource manifest",
            ));
        };
        if encoded.len() > MAX_MANIFEST_BYTES.saturating_mul(2) {
            return Err(TenantResourceProviderError::TooLarge);
        }
        let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            TenantResourceProviderError::BadRequest("manifest is not valid base64url")
        })?;
        let prepared = decode_change_set_payloads(
            &raw,
            Some(&task.change_set_sha256),
            &task_resource_identities(task)?,
        )?;
        return Ok(PreparedTenantResourceTask {
            task: task.clone(),
            request_sha256: String::new(),
            resources: prepared,
        });
    }

    let resources = match &task.payload {
        TenantResourceTaskPayload::Revoke { resources } => resources
            .iter()
            .cloned()
            .map(|identity| PreparedTenantResource {
                identity,
                payload: None,
            })
            .collect(),
        TenantResourceTaskPayload::Enumerate { .. } => Vec::new(),
        TenantResourceTaskPayload::Apply { .. } => {
            return Err(TenantResourceProviderError::BadRequest(
                "invalid task payload",
            ));
        }
    };
    Ok(PreparedTenantResourceTask {
        task: task.clone(),
        request_sha256: String::new(),
        resources,
    })
}

/// Shared change-set decoder for both drivers: the HTTP provider execute
/// envelope and the one-shot [`crate::operator_task`] ControlOperation
/// pipeline (H07).  `raw_manifest` carries the decoded Apply-manifest JSON.
/// Every manifest resource must be pre-authorized by the signed identity set
/// (`authorized`), and each per-resource payload must hash exactly to its
/// signed digest — the same material binding as the external public JWK.
pub(crate) fn decode_change_set_payloads(
    raw_manifest: &[u8],
    expected_change_set_sha256: Option<&str>,
    authorized: &BTreeMap<(TenantResourceKind, String), TenantResourceIdentity>,
) -> Result<Vec<PreparedTenantResource>, TenantResourceProviderError> {
    if raw_manifest.is_empty() {
        return Err(TenantResourceProviderError::BadRequest("manifest is empty"));
    }
    if raw_manifest.len() > MAX_MANIFEST_BYTES {
        return Err(TenantResourceProviderError::TooLarge);
    }
    if let Some(expected) = expected_change_set_sha256
        && sha256_hex(raw_manifest) != expected
    {
        return Err(TenantResourceProviderError::Forbidden(
            "change-set digest does not match task",
        ));
    }
    let manifest: ApplyManifest = serde_json::from_slice(raw_manifest)
        .map_err(|_| TenantResourceProviderError::BadRequest("invalid resource manifest"))?;
    if manifest.schema != APPLY_MANIFEST_SCHEMA
        || manifest.resources.is_empty()
        || manifest.resources.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
    {
        return Err(TenantResourceProviderError::BadRequest(
            "unsupported resource manifest",
        ));
    }
    let mut seen_ids = BTreeSet::new();
    let mut seen_kinds = BTreeSet::new();
    let mut payload_total = 0usize;
    let mut prepared = Vec::with_capacity(manifest.resources.len());
    for resource in manifest.resources {
        validate_resource_id(&resource.resource_id)?;
        if !seen_ids.insert(resource.resource_id.clone())
            || !seen_kinds.insert((resource.kind, resource.resource_id.clone()))
        {
            return Err(TenantResourceProviderError::BadRequest(
                "resource identities must be unique",
            ));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&resource.payload_base64url)
            .map_err(|_| {
                TenantResourceProviderError::BadRequest("resource payload is not valid base64url")
            })?;
        if payload.is_empty() || payload.len() > MAX_RESOURCE_PAYLOAD_BYTES {
            return Err(if payload.len() > MAX_RESOURCE_PAYLOAD_BYTES {
                TenantResourceProviderError::TooLarge
            } else {
                TenantResourceProviderError::BadRequest("resource payload is empty")
            });
        }
        payload_total = payload_total
            .checked_add(payload.len())
            .ok_or(TenantResourceProviderError::TooLarge)?;
        if payload_total > MAX_RESOURCE_PAYLOAD_TOTAL_BYTES {
            return Err(TenantResourceProviderError::TooLarge);
        }
        let identity = authorized
            .get(&(resource.kind, resource.resource_id.clone()))
            .ok_or(TenantResourceProviderError::Forbidden(
                "manifest resource is not authorized by task",
            ))?;
        if sha256_hex(&payload) != identity.digest {
            return Err(TenantResourceProviderError::Forbidden(
                "resource payload digest does not match task",
            ));
        }
        let typed = decode_payload(resource.kind, &payload)?;
        prepared.push(PreparedTenantResource {
            identity: identity.clone(),
            payload: Some(typed),
        });
    }
    if prepared.len() != authorized.len() {
        return Err(TenantResourceProviderError::Forbidden(
            "manifest resources do not match task",
        ));
    }
    Ok(prepared)
}

fn task_resource_identities(
    task: &TenantResourceTask,
) -> Result<
    BTreeMap<(TenantResourceKind, String), TenantResourceIdentity>,
    TenantResourceProviderError,
> {
    let resources = match &task.payload {
        TenantResourceTaskPayload::Apply { resources } => resources,
        _ => {
            return Err(TenantResourceProviderError::BadRequest(
                "apply task payload is invalid",
            ));
        }
    };
    let mut expected = BTreeMap::new();
    for resource in resources {
        if expected
            .insert(
                (resource.kind, resource.resource_id.clone()),
                resource.clone(),
            )
            .is_some()
        {
            return Err(TenantResourceProviderError::BadRequest(
                "task resource identities must be unique",
            ));
        }
    }
    Ok(expected)
}

fn decode_payload(
    kind: TenantResourceKind,
    payload: &[u8],
) -> Result<TenantResourcePayload, TenantResourceProviderError> {
    match kind {
        TenantResourceKind::User => {
            let value: UserManifestPayload = serde_json::from_slice(payload)
                .map_err(|_| TenantResourceProviderError::BadRequest("invalid user payload"))?;
            validate_text(&value.username, MAX_USERNAME_BYTES)?;
            validate_text(&value.email, MAX_EMAIL_BYTES)?;
            validate_text(&value.password, MAX_PASSWORD_BYTES)?;
            if let Some(profile) = &value.profile {
                let size = serde_json::to_vec(profile)
                    .map_err(|_| TenantResourceProviderError::BadRequest("invalid user profile"))?
                    .len();
                if size > MAX_PROFILE_BYTES {
                    return Err(TenantResourceProviderError::TooLarge);
                }
            }
            Ok(TenantResourcePayload::User(UserResourcePayload {
                username: value.username,
                email: value.email,
                password: value.password,
                email_verified: value.email_verified,
                profile: value.profile,
            }))
        }
        TenantResourceKind::OauthClient => {
            let value: OauthClientManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceProviderError::BadRequest("invalid oauth client payload")
                })?;
            if let Some(secret) = &value.supplied_secret {
                validate_text(secret, MAX_CLIENT_SECRET_BYTES)?;
            }
            Ok(TenantResourcePayload::OauthClient(Box::new(
                OauthClientResourcePayload {
                    request: value.request,
                    supplied_secret: value.supplied_secret,
                    trust_policy_resource_id: value
                        .trust_policy_resource_id
                        .map(|resource_id| validate_resource_id(&resource_id).map(|()| resource_id))
                        .transpose()?,
                },
            )))
        }
        TenantResourceKind::MtlsTrustAnchor => {
            let value: MtlsTrustAnchorManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceProviderError::BadRequest("invalid mTLS trust anchor payload")
                })?;
            validate_resource_id(&value.client_resource_id)?;
            if value.certificate_pem.len() > MAX_CERTIFICATE_BYTES
                || !value
                    .certificate_pem
                    .contains("-----BEGIN CERTIFICATE-----")
                || !value.certificate_pem.contains("-----END CERTIFICATE-----")
            {
                return Err(TenantResourceProviderError::BadRequest(
                    "invalid mTLS trust anchor certificate",
                ));
            }
            Ok(TenantResourcePayload::MtlsTrustAnchor(
                MtlsTrustAnchorResourcePayload {
                    client_resource_id: value.client_resource_id,
                    certificate_pem: value.certificate_pem,
                },
            ))
        }
        TenantResourceKind::Openid4vcDataset => {
            let value: Openid4vcDatasetManifestPayload =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceProviderError::BadRequest("invalid OpenID4VC dataset payload")
                })?;
            validate_resource_id(&value.user_resource_id)?;
            validate_text(&value.configuration_id, MAX_CONFIGURATION_ID_BYTES)?;
            if !value.claims.is_object() {
                return Err(TenantResourceProviderError::BadRequest(
                    "OpenID4VC dataset claims must be an object",
                ));
            }
            let size = serde_json::to_vec(&value.claims)
                .map_err(|_| TenantResourceProviderError::BadRequest("invalid dataset claims"))?
                .len();
            if size > MAX_DATASET_CLAIMS_BYTES {
                return Err(TenantResourceProviderError::TooLarge);
            }
            Ok(TenantResourcePayload::Openid4vcDataset(
                Openid4vcDatasetResourcePayload {
                    user_resource_id: value.user_resource_id,
                    configuration_id: value.configuration_id,
                    claims: value.claims,
                },
            ))
        }
        TenantResourceKind::Openid4vcTrustPolicy => {
            let public_material: Openid4vcTrustPolicy =
                serde_json::from_slice(payload).map_err(|_| {
                    TenantResourceProviderError::BadRequest(
                        "invalid OpenID4VC trust policy payload",
                    )
                })?;
            validate_openid4vc_trust_policy(&public_material).map_err(|_| {
                TenantResourceProviderError::BadRequest("invalid OpenID4VC trust policy")
            })?;
            Ok(TenantResourcePayload::Openid4vcTrustPolicy(Box::new(
                Openid4vcTrustPolicyResourcePayload { public_material },
            )))
        }
    }
}

fn validate_resource_id(value: &str) -> Result<(), TenantResourceProviderError> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .map_err(|_| TenantResourceProviderError::BadRequest("invalid resource identifier"))
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), TenantResourceProviderError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(TenantResourceProviderError::BadRequest(
            "invalid resource text",
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "../tests/unit/tenant_resource_provider.rs"]
mod tests;
