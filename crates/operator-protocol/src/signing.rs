//! Signing and compact-JWS encoding for the operator protocol.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::verification::{
    validate_adoption_receipt, validate_deployment_statement, validate_discovery_statement,
    validate_file_identifier, validate_final_receipt, validate_identifier,
    validate_management_event, validate_task, validate_transition, verify_task_window,
};
use crate::wire::{
    AdoptionReceipt, CanonicalConfigManifest, ControllerTrustTransition, DeploymentStatement,
    DiscoveryStatement, FinalReceipt, FixedAlgorithm, ManagementAuditEvent, ProtectedHeader,
    RuntimeReceipt, TaskEnvelope,
};
use crate::{
    ADOPTION_RECEIPT_JWS_TYPE, CONFIG_MANIFEST_VERSION, CONTROL_DISCOVERY_JWS_TYPE,
    DEPLOYMENT_STATEMENT_JWS_TYPE, FINAL_RECEIPT_JWS_TYPE, MANAGEMENT_EVENT_JWS_TYPE,
    MAX_COMPACT_JWS_BYTES, PROTOCOL_VERSION, ProtocolError, RUNTIME_RECEIPT_JWS_TYPE,
    TASK_JWS_TYPE, TRUST_TRANSITION_JWS_TYPE,
};

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

pub fn sign_adoption_receipt(
    receipt: &AdoptionReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_adoption_receipt(receipt)?;
    sign_compact(receipt, key_id, ADOPTION_RECEIPT_JWS_TYPE, key)
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

pub fn sign_task(
    task: &TaskEnvelope,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_task(task)?;
    verify_task_window(task, task.iat)?;
    sign_compact(task, key_id, TASK_JWS_TYPE, key)
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

pub fn sign_final_receipt(
    receipt: &FinalReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_final_receipt(receipt)?;
    sign_compact(receipt, key_id, FINAL_RECEIPT_JWS_TYPE, key)
}

pub fn sign_trust_transition(
    transition: &ControllerTrustTransition,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_transition(transition)?;
    sign_compact(transition, key_id, TRUST_TRANSITION_JWS_TYPE, key)
}

pub fn sign_management_event(
    event: &ManagementAuditEvent,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_management_event(event)?;
    sign_compact(event, key_id, MANAGEMENT_EVENT_JWS_TYPE, key)
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

pub(crate) fn sign_compact<T: Serialize>(
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

pub(crate) fn compact_segments(compact: &str) -> Result<(&str, &str, &str), ProtocolError> {
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

pub(crate) fn decode_protected_header(protected: &str) -> Result<ProtectedHeader, ProtocolError> {
    let header: ProtectedHeader = decode_json(protected).map_err(|_| ProtocolError::Header)?;
    if header.alg != FixedAlgorithm::EdDSA
        || validate_file_identifier(&header.kid).is_err()
        || validate_identifier(&header.typ).is_err()
    {
        return Err(ProtocolError::Header);
    }
    Ok(header)
}

fn encode_json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ProtocolError::Json)
}

pub(crate) fn decode_json<T: DeserializeOwned>(encoded: &str) -> Result<T, ProtocolError> {
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
