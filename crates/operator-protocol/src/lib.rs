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
pub const MAX_COMPACT_JWS_BYTES: usize = 64 * 1024;
pub const MAX_TASK_LIFETIME_SECONDS: i64 = 60;

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
    decode_json(protected)
}

fn sign_compact<T: Serialize>(
    claims: &T,
    key_id: &str,
    expected_type: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_identifier(key_id)?;
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
    let header: ProtectedHeader = decode_json(protected)?;
    if header.alg != FixedAlgorithm::EdDSA
        || header.kid != expected_key_id
        || header.typ != expected_type
    {
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
        TaskOperation::MigrateApply | TaskOperation::KeysList | TaskOperation::KeysValidate => {}
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
