//! Signing and compact-JWS encoding for the operator protocol.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::verification::{
    validate_adoption_receipt, validate_deployment_statement, validate_discovery_statement,
    validate_file_identifier, validate_final_receipt, validate_identifier,
    validate_management_event, validate_openid4vp_verification_intent,
    validate_openid4vp_verification_receipt, validate_runtime_receipt, validate_task,
    validate_tenant_resource_capability, validate_tenant_resource_identities,
    validate_tenant_resource_receipt, validate_tenant_resource_task, validate_transition,
    verify_task_window, verify_tenant_resource_task_window,
};
use crate::wire::{
    AdoptionReceipt, CanonicalConfigManifest, ControllerTrustTransition, DeploymentStatement,
    DiscoveryStatement, FinalReceipt, FixedAlgorithm, ManagementAuditEvent,
    Openid4vpEvidenceContext, Openid4vpNormalizedCreateRequest, Openid4vpPresentationBinding,
    Openid4vpVerificationIntent, Openid4vpVerificationReceipt, ProtectedHeader, RuntimeReceipt,
    TaskEnvelope, TenantResourceCapability, TenantResourceIdentity, TenantResourceKind,
    TenantResourceReceipt, TenantResourceTask,
};
use crate::{
    ADOPTION_RECEIPT_JWS_TYPE, CONFIG_MANIFEST_VERSION, CONTROL_DISCOVERY_JWS_TYPE,
    DEPLOYMENT_STATEMENT_JWS_TYPE, FINAL_RECEIPT_JWS_TYPE, MANAGEMENT_EVENT_JWS_TYPE,
    MAX_COMPACT_JWS_BYTES, OPENID4VP_VERIFICATION_INTENT_JWS_TYPE,
    OPENID4VP_VERIFICATION_RECEIPT_JWS_TYPE, ProtocolError, RUNTIME_RECEIPT_JWS_TYPE,
    TASK_JWS_TYPE, TENANT_RESOURCE_CAPABILITY_JWS_TYPE, TENANT_RESOURCE_RECEIPT_JWS_TYPE,
    TENANT_RESOURCE_TASK_JWS_TYPE, TRUST_TRANSITION_JWS_TYPE,
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
    validate_runtime_receipt(receipt)?;
    sign_compact(receipt, key_id, RUNTIME_RECEIPT_JWS_TYPE, key)
}

pub fn sign_openid4vp_verification_receipt(
    receipt: &Openid4vpVerificationReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_openid4vp_verification_receipt(receipt)?;
    if receipt.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt key id does not match signer",
        ));
    }
    sign_compact(
        receipt,
        key_id,
        OPENID4VP_VERIFICATION_RECEIPT_JWS_TYPE,
        key,
    )
}

pub fn sign_openid4vp_verification_intent(
    intent: &Openid4vpVerificationIntent,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_openid4vp_verification_intent(intent)?;
    if intent.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification intent key id does not match signer",
        ));
    }
    sign_compact(intent, key_id, OPENID4VP_VERIFICATION_INTENT_JWS_TYPE, key)
}

pub fn canonical_openid4vp_evidence_context_sha256(
    context: &Openid4vpEvidenceContext,
) -> Result<String, ProtocolError> {
    crate::verification::validate_openid4vp_evidence_context(context)?;
    let bytes = serde_json::to_vec(context).map_err(|_| ProtocolError::Json)?;
    Ok(hex_sha256(&bytes))
}

/// Return the exact canonical JSON and lowercase SHA-256 used to bind an
/// OpenID4VP create JTI to its complete, normalized request.
pub fn canonical_openid4vp_normalized_create_request(
    request: &Openid4vpNormalizedCreateRequest,
) -> Result<(String, String), ProtocolError> {
    let value = serde_json::to_value(request).map_err(|_| ProtocolError::Json)?;
    let canonical =
        serde_json::to_string(&canonicalize_json(value)).map_err(|_| ProtocolError::Json)?;
    let sha256 = hex_sha256(canonical.as_bytes());
    Ok((canonical, sha256))
}

pub fn canonical_openid4vp_presentation_binding_sha256(
    binding: &Openid4vpPresentationBinding,
) -> Result<String, ProtocolError> {
    crate::verification::validate_openid4vp_presentation_binding(binding)?;
    let bytes = serde_json::to_vec(binding).map_err(|_| ProtocolError::Json)?;
    Ok(hex_sha256(&bytes))
}

pub fn openid4vp_verification_capability_sha256(capability: &str) -> Result<String, ProtocolError> {
    if capability.len() != 43
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolError::Policy(
            "invalid OpenID4VP verification capability",
        ));
    }
    let mut binding = b"nazoauth-openid4vp-verification-capability-v1\0".to_vec();
    binding.extend_from_slice(capability.as_bytes());
    Ok(hex_sha256(&binding))
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

pub fn sign_tenant_resource_capability(
    capability: &TenantResourceCapability,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_tenant_resource_capability(capability, capability.issued_at)?;
    if capability.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "tenant resource capability key id does not match signer",
        ));
    }
    sign_compact(capability, key_id, TENANT_RESOURCE_CAPABILITY_JWS_TYPE, key)
}

pub fn sign_tenant_resource_task(
    task: &TenantResourceTask,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_tenant_resource_task(task)?;
    verify_tenant_resource_task_window(task, task.iat)?;
    sign_compact(task, key_id, TENANT_RESOURCE_TASK_JWS_TYPE, key)
}

pub fn sign_tenant_resource_receipt(
    receipt: &TenantResourceReceipt,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_tenant_resource_receipt(receipt)?;
    sign_compact(receipt, key_id, TENANT_RESOURCE_RECEIPT_JWS_TYPE, key)
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

/// Compute the canonical digest of an active tenant-resource identity set.
///
/// The manifest bytes themselves are deliberately not part of the signed wire
/// contract.  Callers must pass the complete active set, not an Apply/Revoke
/// delta.  The encoding is domain-separated, length-prefixed, and sorted by
/// the fixed wire kind label, resource ID, and resource digest.  Validation is
/// shared with the signed task/receipt validators, so malformed or duplicate
/// identities fail closed.  An empty set is valid and has one deterministic
/// digest.
pub fn canonical_tenant_resource_manifest_sha256(
    resources: &[TenantResourceIdentity],
) -> Result<String, ProtocolError> {
    validate_tenant_resource_identities(resources, false)?;

    let mut entries: Vec<(&str, &str, &str)> = resources
        .iter()
        .map(|resource| {
            (
                tenant_resource_kind_wire_label(resource.kind),
                resource.resource_id.as_str(),
                resource.digest.as_str(),
            )
        })
        .collect();
    entries.sort_unstable();

    let mut encoded = Vec::new();
    append_len_prefixed(&mut encoded, b"nazoauth:tenant-resource-manifest:v1");
    encoded.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for (kind, resource_id, digest) in entries {
        append_len_prefixed(&mut encoded, kind.as_bytes());
        append_len_prefixed(&mut encoded, resource_id.as_bytes());
        append_len_prefixed(&mut encoded, digest.as_bytes());
    }
    Ok(hex_sha256(&encoded))
}

fn tenant_resource_kind_wire_label(kind: TenantResourceKind) -> &'static str {
    match kind {
        TenantResourceKind::OauthClient => "oauth-client",
        TenantResourceKind::MtlsTrustAnchor => "mtls-trust-anchor",
        TenantResourceKind::Openid4vcDataset => "openid4vc-dataset",
        TenantResourceKind::Openid4vcTrustPolicy => "openid4vc-trust-policy",
        TenantResourceKind::User => "user",
    }
}

fn append_len_prefixed(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
    encoded.extend_from_slice(value);
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(canonicalize_json)
                .collect::<Vec<_>>(),
        ),
        serde_json::Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
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
