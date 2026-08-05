//! Closed, non-secret wire protocol for privileged NazoAuth operator tasks.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: u32 = 1;
pub const CONFIG_MANIFEST_VERSION: u32 = 1;
pub const TASK_JWS_TYPE: &str = "nazoauth-operator-task+jwt";
pub const RUNTIME_RECEIPT_JWS_TYPE: &str = "nazoauth-runtime-receipt+jwt";
pub const FINAL_RECEIPT_JWS_TYPE: &str = "nazoauth-operator-receipt+jwt";
pub const TRUST_TRANSITION_JWS_TYPE: &str = "nazoauth-controller-trust-transition+jwt";
pub const MANAGEMENT_EVENT_JWS_TYPE: &str = "nazoauth-management-event+jwt";
pub const CONTROL_DISCOVERY_JWS_TYPE: &str = "nazoauth-control-discovery+jwt";
pub const DEPLOYMENT_STATEMENT_JWS_TYPE: &str = "nazoauth-deployment-statement+jwt";
pub const ADOPTION_RECEIPT_JWS_TYPE: &str = "nazoauth-adoption-receipt+jwt";
pub const CONTROL_DISCOVERY_SCHEMA: u32 = 1;
pub const CONTROL_DISCOVERY_PRODUCT: &str = "nazoauth";
pub const MAX_COMPACT_JWS_BYTES: usize = 64 * 1024;
pub const MAX_TASK_LIFETIME_SECONDS: i64 = 60;
pub const MAX_DISCOVERY_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedHeader {
    pub alg: FixedAlgorithm,
    pub kid: String,
    pub typ: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FixedAlgorithm {
    EdDSA,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEnvelope {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub deployment_id: String,
    pub actor: Actor,
    pub target: TargetExpectation,
    pub embedded: EmbeddedIdentity,
    pub config: ConfigBinding,
    pub operation: TaskOperation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    LocalRoot,
    Automation,
    BreakGlass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TargetExpectation {
    OciImage {
        image_ref: String,
        image_digest: String,
    },
    HostBinary {
        path: String,
        sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedIdentity {
    pub release: String,
    pub revision: String,
    pub protocol: u32,
    pub build_id: String,
}

/// Unauthenticated, bounded challenge for the read-only control discovery endpoint.
///
/// The nonce is 32 random bytes encoded as unpadded base64url.  It provides
/// freshness, not trust; callers still have to bind the returned instance key
/// to runtime evidence and a trusted release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRequest {
    pub schema: u32,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryResponse {
    pub statement: String,
    pub instance_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryStatement {
    pub schema: u32,
    pub product: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub issuer: String,
    pub release: String,
    pub revision: String,
    pub build_id: String,
    pub control_protocol_versions: Vec<u32>,
    pub operator_protocol_versions: Vec<u32>,
    pub instance_key_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Long-lived identity evidence written beside the instance public key.
///
/// This statement deliberately has no freshness claim.  It identifies an
/// offline deployment but never proves that its named artifact is trusted;
/// recovery controllers must independently verify the mounted binary or OCI
/// digest against a cached trusted release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentStatement {
    pub schema: u32,
    pub product: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub issuer: String,
    pub release: String,
    pub revision: String,
    pub build_id: String,
    pub control_protocol_versions: Vec<u32>,
    pub operator_protocol_versions: Vec<u32>,
    pub instance_key_id: String,
    pub issued_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionReceipt {
    pub schema: u32,
    pub deployment_id: String,
    pub issuer: String,
    pub runtime_instances: Vec<AdoptedRuntimeIdentity>,
    pub verified_release: String,
    pub release_manifest_sha256: String,
    pub instance_key_ids: Vec<String>,
    pub resource_references: BTreeMap<String, String>,
    pub capabilities: BTreeMap<String, String>,
    pub recovery_proven: bool,
    pub recovery_evidence: Vec<String>,
    pub plan_sha256: String,
    pub adopted_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedRuntimeIdentity {
    pub runtime_instance_id: String,
    pub backend: String,
    pub object_reference: String,
    pub artifact_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBinding {
    pub manifest_version: u32,
    pub config_sha256: String,
    pub secret_binding: SecretBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretBinding {
    OpaqueRevision { revision: String },
    HmacSha256 { key_id: String, digest: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "name", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TaskOperation {
    MigrateApply,
    ConformanceLeaseCreate {
        profile: String,
        material_sha256: String,
        /// SHA-256 of the per-run dynamic-registration initial-access token.
        ///
        /// The token itself is deliberately never part of the operator
        /// protocol.  This digest is only used to bind a short-lived
        /// conformance lease to the registration guard.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dynamic_registration_initial_access_token_sha256: Option<String>,
        /// SHA-256 of the per-run CIBA automated-decision token.
        ///
        /// The token itself never crosses the operator protocol boundary.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ciba_automated_decision_token_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_material: Option<Openid4vcConformanceTrust>,
        ttl_seconds: u64,
    },
    ConformanceLeaseList,
    ConformanceLeaseRevoke {
        lease_id: String,
    },
    ConformanceLeaseCleanup,
    KeysList,
    KeysValidate,
    KeysGenerateLocal {
        alg: String,
        purposes: Vec<String>,
    },
    KeysRegisterExternal {
        kid: String,
        alg: String,
        key_ref: String,
        public_jwk_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vcConformanceTrust {
    pub schema: u32,
    pub client_attestation_issuer: String,
    pub client_attestation_jwks: serde_json::Value,
    pub key_attestation_jwks: serde_json::Value,
    pub credential_trust_anchor_pem: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceipt {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub request_sha256: String,
    pub deployment_id: String,
    pub actor: Actor,
    pub operation: String,
    pub started_at: i64,
    pub completed_at: i64,
    pub embedded: EmbeddedIdentity,
    pub config: ConfigBinding,
    pub outcome: TaskOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeTargetClaim {
    OciImage {
        image_ref: String,
        image_digest: String,
    },
    HostBinary {
        path: String,
        sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalReceipt {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub request_sha256: String,
    pub deployment_id: String,
    pub actor: Actor,
    pub operation: String,
    pub completed_at: i64,
    pub audit_sequence: u64,
    pub audit_previous_sha256: String,
    pub controller_verified_target: RuntimeTargetClaim,
    pub embedded: EmbeddedIdentity,
    pub config: ConfigBinding,
    pub runtime_receipt_sha256: String,
    pub outcome: TaskOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerTrustTransition {
    pub ver: u32,
    pub deployment_id: String,
    pub issued_at: i64,
    pub authorization: TransitionAuthorization,
    pub previous_key_id: String,
    pub next_key_id: String,
    pub next_public_key_sha256: String,
    pub previous_audit_key_id: String,
    pub next_audit_key_id: String,
    pub next_audit_public_key_sha256: String,
    pub previous_break_glass_key_id: String,
    pub next_break_glass_key_id: String,
    pub next_break_glass_public_key_sha256: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionAuthorization {
    Controller,
    BreakGlass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementAuditEvent {
    pub ver: u32,
    pub deployment_id: String,
    pub sequence: u64,
    pub previous_sha256: String,
    pub request_id: String,
    pub issued_at: i64,
    pub actor: Actor,
    pub operation: String,
    pub release: String,
    pub recovery_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TaskOutcome {
    Succeeded { result: TaskResult },
    Failed { code: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TaskResult {
    Migration {
        applied: bool,
    },
    KeyList {
        keyset_revision: String,
    },
    KeyValidation {
        keyset_revision: String,
    },
    KeyGenerated {
        kid: String,
        keyset_revision: String,
    },
    ExternalKeyRegistered {
        kid: String,
        keyset_revision: String,
    },
    ConformanceLeaseCreated {
        lease: ConformanceLeaseSummary,
    },
    ConformanceLeaseList {
        leases: Vec<ConformanceLeaseSummary>,
    },
    ConformanceLeaseRevoked {
        lease_id: String,
        deactivated_clients: u64,
    },
    ConformanceLeaseCleaned {
        cleaned_leases: u64,
        deleted_clients: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceLeaseSummary {
    pub lease_id: String,
    pub profile: String,
    pub material_sha256: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub cleaned_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalConfigManifest {
    pub version: u32,
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("compact JWS exceeds the maximum size")]
    TooLarge,
    #[error("compact JWS must contain exactly three segments")]
    SegmentCount,
    #[error("compact JWS contains invalid base64url")]
    Base64,
    #[error("compact JWS contains invalid JSON")]
    Json,
    #[error("compact JWS uses an invalid protected header")]
    Header,
    #[error("compact JWS signature is invalid")]
    Signature,
    #[error("task envelope violates protocol policy: {0}")]
    Policy(&'static str),
}

pub fn validate_discovery_request(request: &DiscoveryRequest) -> Result<(), ProtocolError> {
    if request.schema != CONTROL_DISCOVERY_SCHEMA {
        return Err(ProtocolError::Policy(
            "unsupported control discovery schema",
        ));
    }
    validate_discovery_nonce(&request.nonce)
}

pub fn sign_discovery_statement(
    statement: &DiscoveryStatement,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_discovery_statement(statement, statement.issued_at, None)?;
    if statement.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "instance key id does not match signer",
        ));
    }
    sign_compact(statement, key_id, CONTROL_DISCOVERY_JWS_TYPE, key)
}

pub fn verify_discovery_statement(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
    expected_nonce: &str,
    now: i64,
) -> Result<DiscoveryStatement, ProtocolError> {
    validate_discovery_nonce(expected_nonce)?;
    let statement: DiscoveryStatement =
        verify_compact(compact, expected_key_id, CONTROL_DISCOVERY_JWS_TYPE, key)?;
    if statement.instance_key_id != expected_key_id {
        return Err(ProtocolError::Policy(
            "instance key id does not match signer",
        ));
    }
    validate_discovery_statement(&statement, now, Some(expected_nonce))?;
    Ok(statement)
}

pub fn sign_deployment_statement(
    statement: &DeploymentStatement,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_deployment_statement(statement)?;
    if statement.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "instance key id does not match signer",
        ));
    }
    sign_compact(statement, key_id, DEPLOYMENT_STATEMENT_JWS_TYPE, key)
}

pub fn verify_deployment_statement(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<DeploymentStatement, ProtocolError> {
    let statement: DeploymentStatement =
        verify_compact(compact, expected_key_id, DEPLOYMENT_STATEMENT_JWS_TYPE, key)?;
    if statement.instance_key_id != expected_key_id {
        return Err(ProtocolError::Policy(
            "instance key id does not match signer",
        ));
    }
    validate_deployment_statement(&statement)?;
    Ok(statement)
}

pub fn sign_adoption_receipt(
    receipt: &AdoptionReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_adoption_receipt(receipt)?;
    sign_compact(receipt, key_id, ADOPTION_RECEIPT_JWS_TYPE, key)
}

pub fn verify_adoption_receipt(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<AdoptionReceipt, ProtocolError> {
    let receipt = verify_compact(compact, expected_key_id, ADOPTION_RECEIPT_JWS_TYPE, key)?;
    validate_adoption_receipt(&receipt)?;
    Ok(receipt)
}

pub fn encode_instance_public_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

pub fn decode_instance_public_key(encoded: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::Base64)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProtocolError::Policy("invalid instance public key"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ProtocolError::Policy("invalid instance public key"))
}

pub fn instance_key_id(key: &VerifyingKey) -> String {
    format!("instance-{}", &hex_sha256(&key.to_bytes())[..32])
}

pub fn validate_file_identifier_value(value: &str) -> Result<(), ProtocolError> {
    validate_file_identifier(value)
}

pub fn sign_task(
    task: &TaskEnvelope,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_task(task)?;
    verify_task_window(task, task.iat)?;
    sign_compact(task, key_id, TASK_JWS_TYPE, key)
}

pub fn verify_task(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
    now: i64,
) -> Result<TaskEnvelope, ProtocolError> {
    let task = verify_task_signature(compact, expected_key_id, key)?;
    verify_task_window(&task, now)?;
    Ok(task)
}

pub fn verify_task_signature(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<TaskEnvelope, ProtocolError> {
    let task = verify_compact(compact, expected_key_id, TASK_JWS_TYPE, key)?;
    validate_task(&task)?;
    Ok(task)
}

/// Bind a signed task's issuer, audience, and deployment claim to the
/// deployment identity trusted by the local runtime.
///
/// Signature verification only proves that the configured controller signed
/// the envelope.  It does not prove that the envelope was intended for this
/// runtime: a valid controller envelope from another deployment would still
/// verify with a stale or mis-mounted controller key.  The application must
/// obtain `expected_deployment_id` from its local read-only identity/config
/// boundary and call this check before claiming or executing the task.
pub fn validate_task_deployment_binding(
    task: &TaskEnvelope,
    expected_deployment_id: &str,
) -> Result<(), ProtocolError> {
    validate_file_identifier(expected_deployment_id)?;
    if task.deployment_id != expected_deployment_id
        || task.iss != format!("controller:{expected_deployment_id}")
        || task.aud != format!("runtime:{expected_deployment_id}")
    {
        return Err(ProtocolError::Policy(
            "operator task deployment binding mismatch",
        ));
    }
    Ok(())
}

/// Bind a runtime receipt's issuer, audience, and deployment claim to the
/// same deployment identity as its originating task.
pub fn validate_runtime_receipt_deployment_binding(
    receipt: &RuntimeReceipt,
    expected_deployment_id: &str,
) -> Result<(), ProtocolError> {
    validate_file_identifier(expected_deployment_id)?;
    if receipt.deployment_id != expected_deployment_id
        || receipt.iss != format!("runtime:{expected_deployment_id}")
        || receipt.aud != format!("controller:{expected_deployment_id}")
    {
        return Err(ProtocolError::Policy(
            "runtime receipt deployment binding mismatch",
        ));
    }
    Ok(())
}

pub fn verify_task_window(task: &TaskEnvelope, now: i64) -> Result<(), ProtocolError> {
    if now < task.nbf || now > task.exp {
        return Err(ProtocolError::Policy("task is outside its validity window"));
    }
    Ok(())
}

pub fn sign_runtime_receipt(
    receipt: &RuntimeReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    if receipt.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("unsupported receipt version"));
    }
    sign_compact(receipt, key_id, RUNTIME_RECEIPT_JWS_TYPE, key)
}

pub fn verify_runtime_receipt(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<RuntimeReceipt, ProtocolError> {
    let receipt: RuntimeReceipt =
        verify_compact(compact, expected_key_id, RUNTIME_RECEIPT_JWS_TYPE, key)?;
    if receipt.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("unsupported receipt version"));
    }
    Ok(receipt)
}

pub fn sign_final_receipt(
    receipt: &FinalReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_final_receipt(receipt)?;
    sign_compact(receipt, key_id, FINAL_RECEIPT_JWS_TYPE, key)
}

pub fn verify_final_receipt(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<FinalReceipt, ProtocolError> {
    let receipt: FinalReceipt =
        verify_compact(compact, expected_key_id, FINAL_RECEIPT_JWS_TYPE, key)?;
    validate_final_receipt(&receipt)?;
    Ok(receipt)
}

pub fn sign_trust_transition(
    transition: &ControllerTrustTransition,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_transition(transition)?;
    sign_compact(transition, key_id, TRUST_TRANSITION_JWS_TYPE, key)
}

pub fn verify_trust_transition(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<ControllerTrustTransition, ProtocolError> {
    let transition: ControllerTrustTransition =
        verify_compact(compact, expected_key_id, TRUST_TRANSITION_JWS_TYPE, key)?;
    validate_transition(&transition)?;
    Ok(transition)
}

pub fn sign_management_event(
    event: &ManagementAuditEvent,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_management_event(event)?;
    sign_compact(event, key_id, MANAGEMENT_EVENT_JWS_TYPE, key)
}

pub fn verify_management_event(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<ManagementAuditEvent, ProtocolError> {
    let event: ManagementAuditEvent =
        verify_compact(compact, expected_key_id, MANAGEMENT_EVENT_JWS_TYPE, key)?;
    validate_management_event(&event)?;
    Ok(event)
}

pub fn canonical_config_sha256(
    manifest: &CanonicalConfigManifest,
) -> Result<String, ProtocolError> {
    if manifest.version != CONFIG_MANIFEST_VERSION {
        return Err(ProtocolError::Policy("unsupported config manifest version"));
    }
    let bytes = serde_json::to_vec(manifest).map_err(|_| ProtocolError::Json)?;
    Ok(hex_sha256(&bytes))
}

pub fn compact_sha256(compact: &str) -> String {
    hex_sha256(compact.as_bytes())
}

pub fn protected_header(compact: &str) -> Result<ProtectedHeader, ProtocolError> {
    let (protected, _, _) = compact_segments(compact)?;
    decode_protected_header(protected)
}

fn sign_compact<T: Serialize>(
    claims: &T,
    key_id: &str,
    expected_type: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    // The key id becomes a key-store path component for verifiers.  Keep the
    // signing and pre-lookup parsing boundary identical so we never mint a
    // token that a safe verifier cannot look up.
    validate_file_identifier(key_id)?;
    let header = ProtectedHeader {
        alg: FixedAlgorithm::EdDSA,
        kid: key_id.to_owned(),
        typ: expected_type.to_owned(),
    };
    let protected = encode_json(&header)?;
    let payload = encode_json(claims)?;
    let signing_input = format!("{protected}.{payload}");
    let signature = key.sign(signing_input.as_bytes());
    let compact = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(compact)
}

fn verify_compact<T: DeserializeOwned>(
    compact: &str,
    expected_key_id: &str,
    expected_type: &str,
    key: &VerifyingKey,
) -> Result<T, ProtocolError> {
    validate_file_identifier(expected_key_id).map_err(|_| ProtocolError::Header)?;
    let (protected, payload, signature) = compact_segments(compact)?;
    let header = decode_protected_header(protected)?;
    if header.kid != expected_key_id || header.typ != expected_type {
        return Err(ProtocolError::Header);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProtocolError::Base64)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ProtocolError::Signature)?;
    key.verify(format!("{protected}.{payload}").as_bytes(), &signature)
        .map_err(|_| ProtocolError::Signature)?;
    decode_json(payload)
}

fn compact_segments(compact: &str) -> Result<(&str, &str, &str), ProtocolError> {
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut segments = compact.split('.');
    let protected = segments.next().ok_or(ProtocolError::SegmentCount)?;
    let payload = segments.next().ok_or(ProtocolError::SegmentCount)?;
    let signature = segments.next().ok_or(ProtocolError::SegmentCount)?;
    if segments.next().is_some()
        || protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
    {
        return Err(ProtocolError::SegmentCount);
    }
    Ok((protected, payload, signature))
}

fn decode_protected_header(protected: &str) -> Result<ProtectedHeader, ProtocolError> {
    let header: ProtectedHeader = decode_json(protected).map_err(|_| ProtocolError::Header)?;
    if header.alg != FixedAlgorithm::EdDSA
        || validate_file_identifier(&header.kid).is_err()
        || validate_identifier(&header.typ).is_err()
    {
        return Err(ProtocolError::Header);
    }
    Ok(header)
}

fn validate_discovery_statement(
    statement: &DiscoveryStatement,
    now: i64,
    expected_nonce: Option<&str>,
) -> Result<(), ProtocolError> {
    validate_discovery_identity(
        statement.schema,
        &statement.product,
        &statement.deployment_id,
        &statement.runtime_instance_id,
        &statement.issuer,
        &statement.release,
        &statement.revision,
        &statement.build_id,
        &statement.control_protocol_versions,
        &statement.operator_protocol_versions,
        &statement.instance_key_id,
    )?;
    validate_discovery_nonce(&statement.nonce)?;
    if expected_nonce.is_some_and(|expected| statement.nonce != expected) {
        return Err(ProtocolError::Policy("control discovery nonce mismatch"));
    }
    if statement.expires_at < statement.issued_at
        || statement.expires_at - statement.issued_at > MAX_DISCOVERY_LIFETIME_SECONDS
        || now < statement.issued_at
        || now > statement.expires_at
    {
        return Err(ProtocolError::Policy(
            "control discovery statement is outside its validity window",
        ));
    }
    Ok(())
}

fn validate_deployment_statement(statement: &DeploymentStatement) -> Result<(), ProtocolError> {
    validate_discovery_identity(
        statement.schema,
        &statement.product,
        &statement.deployment_id,
        &statement.runtime_instance_id,
        &statement.issuer,
        &statement.release,
        &statement.revision,
        &statement.build_id,
        &statement.control_protocol_versions,
        &statement.operator_protocol_versions,
        &statement.instance_key_id,
    )?;
    if statement.issued_at <= 0 {
        return Err(ProtocolError::Policy(
            "deployment statement has an invalid issuance time",
        ));
    }
    Ok(())
}

fn validate_adoption_receipt(receipt: &AdoptionReceipt) -> Result<(), ProtocolError> {
    if receipt.schema != CONTROL_DISCOVERY_SCHEMA {
        return Err(ProtocolError::Policy("unsupported adoption receipt schema"));
    }
    validate_file_identifier(&receipt.deployment_id)?;
    validate_identifier(&receipt.issuer)?;
    validate_identifier(&receipt.verified_release)?;
    validate_lower_hex(&receipt.release_manifest_sha256, 64)?;
    validate_lower_hex(&receipt.plan_sha256, 64)?;
    if receipt.adopted_at <= 0 || receipt.runtime_instances.is_empty() {
        return Err(ProtocolError::Policy("invalid adoption receipt"));
    }
    if receipt.runtime_instances.len() > 128 || receipt.instance_key_ids.len() > 128 {
        return Err(ProtocolError::Policy(
            "adoption receipt exceeds instance limit",
        ));
    }
    for runtime in &receipt.runtime_instances {
        validate_file_identifier(&runtime.runtime_instance_id)?;
        for value in [
            &runtime.backend,
            &runtime.object_reference,
            &runtime.artifact_identity,
        ] {
            validate_audit_boundary(value)?;
        }
    }
    for key_id in &receipt.instance_key_ids {
        validate_file_identifier(key_id)?;
    }
    if receipt.resource_references.len() > 64 || receipt.capabilities.len() > 16 {
        return Err(ProtocolError::Policy(
            "adoption receipt exceeds policy limit",
        ));
    }
    for (name, value) in receipt
        .resource_references
        .iter()
        .chain(receipt.capabilities.iter())
    {
        validate_identifier(name)?;
        validate_audit_boundary(value)?;
    }
    if receipt.recovery_evidence.len() > 64 {
        return Err(ProtocolError::Policy(
            "adoption receipt exceeds recovery evidence limit",
        ));
    }
    for evidence in &receipt.recovery_evidence {
        validate_audit_boundary(evidence)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_discovery_identity(
    schema: u32,
    product: &str,
    deployment_id: &str,
    runtime_instance_id: &str,
    issuer: &str,
    release: &str,
    revision: &str,
    build_id: &str,
    control_protocol_versions: &[u32],
    operator_protocol_versions: &[u32],
    instance_key_id: &str,
) -> Result<(), ProtocolError> {
    if schema != CONTROL_DISCOVERY_SCHEMA {
        return Err(ProtocolError::Policy(
            "unsupported control discovery schema",
        ));
    }
    if product != CONTROL_DISCOVERY_PRODUCT {
        return Err(ProtocolError::Policy(
            "unexpected control discovery product",
        ));
    }
    validate_file_identifier(deployment_id)?;
    validate_file_identifier(runtime_instance_id)?;
    validate_file_identifier(instance_key_id)?;
    for value in [issuer, release, revision, build_id] {
        validate_identifier(value)?;
    }
    validate_protocol_versions(
        control_protocol_versions,
        CONTROL_DISCOVERY_SCHEMA,
        "unsupported control discovery protocol",
    )?;
    validate_protocol_versions(
        operator_protocol_versions,
        PROTOCOL_VERSION,
        "unsupported operator protocol",
    )
}

fn validate_protocol_versions(
    versions: &[u32],
    required: u32,
    error: &'static str,
) -> Result<(), ProtocolError> {
    if versions.is_empty()
        || versions.len() > 16
        || !versions.windows(2).all(|pair| pair[0] < pair[1])
        || !versions.contains(&required)
    {
        return Err(ProtocolError::Policy(error));
    }
    Ok(())
}

fn validate_discovery_nonce(nonce: &str) -> Result<(), ProtocolError> {
    if nonce.len() != 43 {
        return Err(ProtocolError::Policy(
            "control discovery nonce must encode 32 bytes",
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| ProtocolError::Policy("control discovery nonce is not base64url"))?;
    if bytes.len() != 32 {
        return Err(ProtocolError::Policy(
            "control discovery nonce must encode 32 bytes",
        ));
    }
    Ok(())
}

fn validate_task(task: &TaskEnvelope) -> Result<(), ProtocolError> {
    if task.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("unsupported task version"));
    }
    for value in [&task.iss, &task.aud, &task.actor.id] {
        validate_identifier(value)?;
    }
    validate_file_identifier(&task.jti)?;
    validate_file_identifier(&task.deployment_id)?;
    if task.exp < task.iat || task.exp - task.iat > MAX_TASK_LIFETIME_SECONDS {
        return Err(ProtocolError::Policy("task lifetime exceeds 60 seconds"));
    }
    if task.nbf < task.iat {
        return Err(ProtocolError::Policy(
            "task validity starts before issuance",
        ));
    }
    if task.config.manifest_version != CONFIG_MANIFEST_VERSION {
        return Err(ProtocolError::Policy("unsupported config manifest version"));
    }
    validate_lower_hex(&task.config.config_sha256, 64)?;
    validate_identifier(&task.embedded.build_id)?;
    match &task.target {
        TargetExpectation::OciImage { image_digest, .. } => {
            let digest = image_digest
                .strip_prefix("sha256:")
                .ok_or(ProtocolError::Policy("OCI target must use a sha256 digest"))?;
            validate_lower_hex(digest, 64)?;
        }
        TargetExpectation::HostBinary { sha256, .. } => validate_lower_hex(sha256, 64)?,
    }
    match &task.config.secret_binding {
        SecretBinding::OpaqueRevision { revision } => validate_identifier(revision)?,
        SecretBinding::HmacSha256 { key_id, digest } => {
            validate_identifier(key_id)?;
            validate_lower_hex(digest, 64)?;
        }
    }
    validate_operation(&task.operation)?;
    Ok(())
}

fn validate_final_receipt(receipt: &FinalReceipt) -> Result<(), ProtocolError> {
    if receipt.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("unsupported receipt version"));
    }
    for value in [
        &receipt.iss,
        &receipt.aud,
        &receipt.embedded.build_id,
        &receipt.operation,
        &receipt.actor.id,
    ] {
        validate_identifier(value)?;
    }
    validate_file_identifier(&receipt.jti)?;
    validate_file_identifier(&receipt.deployment_id)?;
    validate_lower_hex(&receipt.request_sha256, 64)?;
    validate_lower_hex(&receipt.runtime_receipt_sha256, 64)?;
    validate_lower_hex(&receipt.audit_previous_sha256, 64)?;
    Ok(())
}

fn validate_operation(operation: &TaskOperation) -> Result<(), ProtocolError> {
    match operation {
        TaskOperation::MigrateApply
        | TaskOperation::ConformanceLeaseList
        | TaskOperation::ConformanceLeaseCleanup
        | TaskOperation::KeysList
        | TaskOperation::KeysValidate => {}
        TaskOperation::ConformanceLeaseCreate {
            profile,
            material_sha256,
            dynamic_registration_initial_access_token_sha256,
            ciba_automated_decision_token_sha256,
            public_material,
            ttl_seconds,
        } => {
            validate_identifier(profile)?;
            if profile.len() > 64 {
                return Err(ProtocolError::Policy(
                    "conformance lease profile exceeds 64 bytes",
                ));
            }
            validate_lower_hex(material_sha256, 64)?;
            if (dynamic_registration_initial_access_token_sha256.is_some()
                || ciba_automated_decision_token_sha256.is_some())
                && profile != "oidc-fapi-ciba"
            {
                return Err(ProtocolError::Policy(
                    "conformance token bindings are only allowed for the oidc-fapi-ciba profile",
                ));
            }
            for digest in [
                dynamic_registration_initial_access_token_sha256,
                ciba_automated_decision_token_sha256,
            ]
            .into_iter()
            .flatten()
            {
                validate_lower_hex(digest, 64)?;
            }
            match (profile.as_str(), public_material) {
                ("openid4vc", Some(material)) => validate_openid4vc_conformance_trust(material)?,
                ("openid4vc", None) => {
                    return Err(ProtocolError::Policy(
                        "openid4vc conformance lease requires public trust material",
                    ));
                }
                (_, Some(_)) => {
                    return Err(ProtocolError::Policy(
                        "public trust material is accepted only by the openid4vc profile",
                    ));
                }
                (_, None) => {}
            }
            if !(60..=86_400).contains(ttl_seconds) {
                return Err(ProtocolError::Policy(
                    "conformance lease ttl must be between 60 and 86400 seconds",
                ));
            }
        }
        TaskOperation::ConformanceLeaseRevoke { lease_id } => {
            validate_file_identifier(lease_id)?;
        }
        TaskOperation::KeysGenerateLocal { alg, purposes } => {
            validate_identifier(alg)?;
            if purposes.is_empty() || purposes.len() > 8 {
                return Err(ProtocolError::Policy("invalid signing purposes"));
            }
            for purpose in purposes {
                validate_identifier(purpose)?;
            }
        }
        TaskOperation::KeysRegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk_sha256,
        } => {
            validate_file_identifier(kid)?;
            validate_identifier(alg)?;
            validate_lower_hex(public_jwk_sha256, 64)?;
            if key_ref.is_empty()
                || key_ref.len() > 512
                || ["//", "@", "?", "#", "="]
                    .iter()
                    .any(|forbidden| key_ref.contains(forbidden))
                || !key_ref.chars().all(|character| {
                    character.is_ascii_alphanumeric() || ".:_/-+".contains(character)
                })
            {
                return Err(ProtocolError::Policy(
                    "external key reference must be a non-secret provider locator",
                ));
            }
        }
    }
    Ok(())
}

fn validate_openid4vc_conformance_trust(
    material: &Openid4vcConformanceTrust,
) -> Result<(), ProtocolError> {
    if material.schema != 1
        || material.client_attestation_issuer.len() > 2048
        || !material.client_attestation_issuer.starts_with("https://")
        || material.credential_trust_anchor_pem.len() > 16 * 1024
        || !material
            .credential_trust_anchor_pem
            .starts_with("-----BEGIN CERTIFICATE-----\n")
        || !material
            .credential_trust_anchor_pem
            .ends_with("-----END CERTIFICATE-----\n")
        || material.credential_trust_anchor_pem.contains("PRIVATE KEY")
    {
        return Err(ProtocolError::Policy(
            "invalid OpenID4VC conformance trust material",
        ));
    }
    let encoded = serde_json::to_vec(material).map_err(|_| ProtocolError::Json)?;
    if encoded.len() > 32 * 1024 {
        return Err(ProtocolError::Policy(
            "OpenID4VC conformance trust material exceeds 32 KiB",
        ));
    }
    for jwks in [
        &material.client_attestation_jwks,
        &material.key_attestation_jwks,
    ] {
        let keys = jwks
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .filter(|keys| !keys.is_empty())
            .ok_or(ProtocolError::Policy(
                "OpenID4VC conformance trust requires non-empty JWK Sets",
            ))?;
        if keys.iter().any(|key| {
            key.as_object().is_none_or(|object| {
                ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                    .iter()
                    .any(|name| object.contains_key(*name))
            })
        }) {
            return Err(ProtocolError::Policy(
                "OpenID4VC conformance trust must contain public keys only",
            ));
        }
    }
    Ok(())
}

fn validate_transition(transition: &ControllerTrustTransition) -> Result<(), ProtocolError> {
    if transition.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported trust transition version",
        ));
    }
    for value in [
        &transition.deployment_id,
        &transition.previous_key_id,
        &transition.next_key_id,
        &transition.previous_audit_key_id,
        &transition.next_audit_key_id,
        &transition.previous_break_glass_key_id,
        &transition.next_break_glass_key_id,
        &transition.reason,
    ] {
        validate_identifier(value)?;
    }
    validate_lower_hex(&transition.next_public_key_sha256, 64)?;
    validate_lower_hex(&transition.next_audit_public_key_sha256, 64)?;
    validate_lower_hex(&transition.next_break_glass_public_key_sha256, 64)
}

fn validate_management_event(event: &ManagementAuditEvent) -> Result<(), ProtocolError> {
    if event.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported management event version",
        ));
    }
    validate_file_identifier(&event.deployment_id)?;
    validate_file_identifier(&event.request_id)?;
    validate_lower_hex(&event.previous_sha256, 64)?;
    for value in [&event.actor.id, &event.operation, &event.release] {
        validate_identifier(value)?;
    }
    validate_audit_boundary(&event.recovery_boundary)?;
    Ok(())
}

fn validate_audit_boundary(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 4096
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+_-".contains(character))
    {
        return Err(ProtocolError::Policy("invalid audit recovery boundary"));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_/@+-".contains(character))
    {
        return Err(ProtocolError::Policy("invalid identifier"));
    }
    Ok(())
}

fn validate_file_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
    {
        return Err(ProtocolError::Policy("invalid file identifier"));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize) -> Result<(), ProtocolError> {
    if value.len() != length
        || !value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(ProtocolError::Policy("invalid digest"));
    }
    Ok(())
}

fn encode_json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ProtocolError::Json)
}

fn decode_json<T: DeserializeOwned>(encoded: &str) -> Result<T, ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::Base64)?;
    serde_json::from_slice(&bytes).map_err(|_| ProtocolError::Json)
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "../tests/unit/mod.rs"]
mod tests;
