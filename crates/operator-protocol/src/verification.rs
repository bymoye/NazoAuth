//! Signature verification, receipt handling, and protocol-policy checks.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::DeserializeOwned;

use crate::signing::{compact_segments, decode_json, decode_protected_header};
use crate::wire::*;
use crate::{
    CONTROL_DISCOVERY_JWS_TYPE, CONTROL_DISCOVERY_PRODUCT, CONTROL_DISCOVERY_SCHEMA,
    DEPLOYMENT_STATEMENT_JWS_TYPE, MAX_DISCOVERY_LIFETIME_SECONDS,
    OPENID4VP_VERIFICATION_INTENT_JWS_TYPE, OPENID4VP_VERIFICATION_RECEIPT_JWS_TYPE,
    PROTOCOL_VERSION, ProtocolError,
};

pub fn validate_discovery_request(request: &DiscoveryRequest) -> Result<(), ProtocolError> {
    if request.schema != CONTROL_DISCOVERY_SCHEMA {
        return Err(ProtocolError::Policy(
            "unsupported control discovery schema",
        ));
    }
    validate_discovery_nonce(&request.nonce)
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

pub struct Openid4vpVerificationReceiptExpectations<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub deployment_id: &'a str,
    pub runtime_instance_id: &'a str,
    pub instance_key_id: &'a str,
    pub tenant_id: &'a str,
    pub transaction_id: &'a str,
    pub receipt_id: &'a str,
    pub issuance_request_jti: &'a str,
    pub evidence_context_sha256: &'a str,
    pub presentation_binding_sha256: &'a str,
    pub intent_sha256: &'a str,
    pub capability_sha256: &'a str,
}

pub struct Openid4vpVerificationIntentExpectations<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub deployment_id: &'a str,
    pub runtime_instance_id: &'a str,
    pub instance_key_id: &'a str,
    pub tenant_id: &'a str,
    pub transaction_id: &'a str,
    pub evidence_context_sha256: &'a str,
    pub presentation_binding_sha256: &'a str,
}

pub fn verify_openid4vp_verification_receipt(
    compact: &str,
    expected: &Openid4vpVerificationReceiptExpectations<'_>,
    key: &VerifyingKey,
    now: i64,
) -> Result<Openid4vpVerificationReceipt, ProtocolError> {
    let receipt: Openid4vpVerificationReceipt = verify_compact(
        compact,
        expected.instance_key_id,
        OPENID4VP_VERIFICATION_RECEIPT_JWS_TYPE,
        key,
    )?;
    validate_openid4vp_verification_receipt(&receipt)?;
    let context_sha256 =
        crate::signing::canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context)?;
    let presentation_binding_sha256 =
        crate::signing::canonical_openid4vp_presentation_binding_sha256(
            &receipt.presentation_binding,
        )?;
    if receipt.iss != expected.issuer
        || receipt.aud != expected.audience
        || receipt.deployment_id != expected.deployment_id
        || receipt.runtime_instance_id != expected.runtime_instance_id
        || receipt.instance_key_id != expected.instance_key_id
        || receipt.tenant_id != expected.tenant_id
        || receipt.transaction_id != expected.transaction_id
        || receipt.jti != expected.receipt_id
        || receipt.issuance_request_jti != expected.issuance_request_jti
        || context_sha256 != expected.evidence_context_sha256
        || presentation_binding_sha256 != expected.presentation_binding_sha256
        || receipt.intent_sha256 != expected.intent_sha256
        || receipt.capability_sha256 != expected.capability_sha256
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt binding does not match expectations",
        ));
    }
    if now < receipt.iat || now >= receipt.exp {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt is outside its validity window",
        ));
    }
    Ok(receipt)
}

pub fn verify_openid4vp_verification_intent(
    compact: &str,
    expected: &Openid4vpVerificationIntentExpectations<'_>,
    key: &VerifyingKey,
    now: i64,
) -> Result<Openid4vpVerificationIntent, ProtocolError> {
    let intent: Openid4vpVerificationIntent = verify_compact(
        compact,
        expected.instance_key_id,
        OPENID4VP_VERIFICATION_INTENT_JWS_TYPE,
        key,
    )?;
    validate_openid4vp_verification_intent(&intent)?;
    let context_sha256 =
        crate::signing::canonical_openid4vp_evidence_context_sha256(&intent.evidence_context)?;
    let presentation_binding_sha256 =
        crate::signing::canonical_openid4vp_presentation_binding_sha256(
            &intent.presentation_binding,
        )?;
    if intent.iss != expected.issuer
        || intent.aud != expected.audience
        || intent.deployment_id != expected.deployment_id
        || intent.runtime_instance_id != expected.runtime_instance_id
        || intent.instance_key_id != expected.instance_key_id
        || intent.tenant_id != expected.tenant_id
        || intent.transaction_id != expected.transaction_id
        || intent.jti != expected.transaction_id
        || context_sha256 != expected.evidence_context_sha256
        || presentation_binding_sha256 != expected.presentation_binding_sha256
        || now < intent.iat
        || now >= intent.exp
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification intent binding does not match expectations",
        ));
    }
    Ok(intent)
}

pub(crate) fn validate_openid4vp_evidence_context(
    context: &Openid4vpEvidenceContext,
) -> Result<(), ProtocolError> {
    validate_file_identifier(&context.run_jti)?;
    validate_lower_hex(&context.artifact_sha256, 64)?;
    validate_lower_hex(&context.matrix_sha256, 64)?;
    validate_file_identifier(&context.suite_plan_id)?;
    validate_file_identifier(&context.suite_module_id)?;
    validate_identifier(&context.test_name)?;
    validate_lower_hex(&context.variant_sha256, 64)
}

/// Validate the caller-owned create idempotency JTI.
///
/// Only canonical lowercase RFC UUIDs with versions 1 through 8 are allowed;
/// accepting alternative spellings would create multiple database keys for
/// the same UUID.
pub fn validate_openid4vp_create_request_jti(value: &str) -> Result<(), ProtocolError> {
    validate_uuid(value)?;
    let bytes = value.as_bytes();
    if !matches!(bytes[14], b'1'..=b'8') || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return Err(ProtocolError::Policy(
            "invalid OpenID4VP create request JTI",
        ));
    }
    Ok(())
}

pub(crate) fn validate_openid4vp_presentation_binding(
    binding: &Openid4vpPresentationBinding,
) -> Result<(), ProtocolError> {
    validate_lower_hex(&binding.presentation_request_sha256, 64)?;
    match (
        binding.trust_policy.binding_id.as_deref(),
        binding.trust_policy.resource_id.as_deref(),
        binding.trust_policy.resource_digest.as_deref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(binding_id), Some(resource_id), Some(resource_digest)) => {
            validate_uuid(binding_id)?;
            validate_file_identifier(resource_id)?;
            validate_lower_hex(resource_digest, 64)
        }
        _ => Err(ProtocolError::Policy(
            "OpenID4VP trust policy binding must be all present or all absent",
        )),
    }
}

pub(crate) fn validate_openid4vp_verification_receipt(
    receipt: &Openid4vpVerificationReceipt,
) -> Result<(), ProtocolError> {
    if receipt.schema != 1 {
        return Err(ProtocolError::Policy(
            "unsupported OpenID4VP verification receipt schema",
        ));
    }
    validate_openid4vc_trust_policy_issuer(&receipt.iss)?;
    validate_openid4vc_trust_policy_issuer(&receipt.aud)?;
    validate_file_identifier(&receipt.deployment_id)?;
    validate_file_identifier(&receipt.runtime_instance_id)?;
    validate_file_identifier(&receipt.instance_key_id)?;
    validate_uuid(&receipt.tenant_id)?;
    validate_uuid(&receipt.jti)?;
    validate_uuid(&receipt.transaction_id)?;
    validate_uuid(&receipt.issuance_request_jti)?;
    validate_openid4vp_evidence_context(&receipt.evidence_context)?;
    validate_openid4vp_presentation_binding(&receipt.presentation_binding)?;
    validate_lower_hex(&receipt.intent_sha256, 64)?;
    validate_lower_hex(&receipt.capability_sha256, 64)?;
    let completed_at = chrono::DateTime::parse_from_rfc3339(&receipt.completed_at)
        .map_err(|_| ProtocolError::Policy("invalid OpenID4VP receipt completion time"))?;
    let lifetime = receipt.exp.checked_sub(receipt.iat);
    if completed_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) != receipt.completed_at
        || receipt.iat < 0
        || lifetime.is_none_or(|value| value <= 0 || value > 600)
        || completed_at.timestamp() > receipt.iat
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification receipt expiry is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn validate_openid4vp_verification_intent(
    intent: &Openid4vpVerificationIntent,
) -> Result<(), ProtocolError> {
    if intent.schema != 1 {
        return Err(ProtocolError::Policy(
            "unsupported OpenID4VP verification intent schema",
        ));
    }
    validate_openid4vc_trust_policy_issuer(&intent.iss)?;
    validate_openid4vc_trust_policy_issuer(&intent.aud)?;
    validate_file_identifier(&intent.deployment_id)?;
    validate_file_identifier(&intent.runtime_instance_id)?;
    validate_file_identifier(&intent.instance_key_id)?;
    validate_uuid(&intent.tenant_id)?;
    validate_uuid(&intent.transaction_id)?;
    validate_uuid(&intent.jti)?;
    validate_openid4vp_evidence_context(&intent.evidence_context)?;
    validate_openid4vp_presentation_binding(&intent.presentation_binding)?;
    let lifetime = intent.exp.checked_sub(intent.iat);
    if intent.jti != intent.transaction_id
        || intent.iat < 0
        || lifetime.is_none_or(|value| value <= 0 || value > 600)
    {
        return Err(ProtocolError::Policy(
            "OpenID4VP verification intent window is invalid",
        ));
    }
    Ok(())
}

pub fn validate_file_identifier_value(value: &str) -> Result<(), ProtocolError> {
    validate_file_identifier(value)
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

pub(crate) fn validate_discovery_statement(
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

pub(crate) fn validate_deployment_statement(
    statement: &DeploymentStatement,
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
    if statement.issued_at <= 0 {
        return Err(ProtocolError::Policy(
            "deployment statement has an invalid issuance time",
        ));
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

/// Validate the public trust policy carried by the ordinary OpenID4VC
/// provider. The policy uses a stricter JSON boundary: only the supported public JWK
/// members are accepted, so an unknown member cannot smuggle private or
/// provider-specific state into the signed policy.
pub fn validate_openid4vc_trust_policy(policy: &Openid4vcTrustPolicy) -> Result<(), ProtocolError> {
    if policy.schema != 1 {
        return Err(ProtocolError::Policy(
            "invalid OpenID4VC trust policy schema",
        ));
    }
    validate_openid4vc_trust_policy_issuer(&policy.client_attestation_issuer)?;
    validate_openid4vc_wallet_authorization_origins(&policy.wallet_authorization_origins)?;
    validate_public_certificate_bundle(
        &policy.credential_trust_anchor_pem,
        "invalid OpenID4VC trust policy credential anchor",
    )?;
    let encoded = serde_json::to_vec(policy).map_err(|_| ProtocolError::Json)?;
    if encoded.len() > 32 * 1024 {
        return Err(ProtocolError::Policy(
            "OpenID4VC trust policy exceeds 32 KiB",
        ));
    }
    validate_openid4vc_trust_jwks_with_options(&policy.client_attestation_jwks, true, true)?;
    validate_openid4vc_trust_jwks_with_options(&policy.key_attestation_jwks, false, true)?;
    Ok(())
}

fn validate_openid4vc_trust_policy_issuer(value: &str) -> Result<(), ProtocolError> {
    let host_and_path = value.strip_prefix("https://");
    if value.is_empty()
        || value.len() > 2048
        || host_and_path.is_none_or(str::is_empty)
        || host_and_path.is_some_and(|suffix| {
            suffix
                .as_bytes()
                .first()
                .is_some_and(|byte| matches!(*byte, b'/' | b'?' | b'#'))
        })
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
        || value.contains('?')
        || value.contains('#')
    {
        return Err(ProtocolError::Policy(
            "invalid OpenID4VC trust policy issuer",
        ));
    }
    Ok(())
}

fn validate_openid4vc_wallet_authorization_origins(
    origins: &[String],
) -> Result<(), ProtocolError> {
    const MAX_ORIGINS: usize = 16;
    const MAX_ORIGIN_LENGTH: usize = 2048;

    if origins.is_empty() || origins.len() > MAX_ORIGINS {
        return Err(ProtocolError::Policy(
            "OpenID4VC trust policy origins are out of bounds",
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for origin in origins {
        if origin.is_empty()
            || origin.len() > MAX_ORIGIN_LENGTH
            || !origin.is_ascii()
            || origin != &origin.to_ascii_lowercase()
            || !origin.starts_with("https://")
            || origin
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == 0)
        {
            return Err(ProtocolError::Policy(
                "invalid OpenID4VC wallet authorization origin",
            ));
        }
        let authority = &origin["https://".len()..];
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.contains('%')
            || authority.contains('\\')
        {
            return Err(ProtocolError::Policy(
                "invalid OpenID4VC wallet authorization origin",
            ));
        }
        let (host, port) = if authority.starts_with('[') {
            let close = authority.find(']').ok_or(ProtocolError::Policy(
                "invalid OpenID4VC wallet authorization origin",
            ))?;
            let host = &authority[1..close];
            let suffix = &authority[close + 1..];
            let port = if suffix.is_empty() {
                None
            } else {
                Some(suffix.strip_prefix(":").ok_or(ProtocolError::Policy(
                    "invalid OpenID4VC wallet authorization origin",
                ))?)
            };
            (host, port)
        } else {
            let mut pieces = authority.split(':');
            let host = pieces.next().unwrap_or_default();
            let port = pieces.next();
            if pieces.next().is_some() {
                return Err(ProtocolError::Policy(
                    "invalid OpenID4VC wallet authorization origin",
                ));
            }
            (host, port)
        };
        if host.is_empty()
            || host.starts_with('.')
            || host.ends_with('.')
            || host.contains("..")
            || (host.starts_with('[') || host.ends_with(']'))
        {
            return Err(ProtocolError::Policy(
                "invalid OpenID4VC wallet authorization origin",
            ));
        }
        if authority.starts_with('[') {
            if !host
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
            {
                return Err(ProtocolError::Policy(
                    "invalid OpenID4VC wallet authorization origin",
                ));
            }
        } else if !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            || host
                .split('.')
                .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        {
            return Err(ProtocolError::Policy(
                "invalid OpenID4VC wallet authorization origin",
            ));
        }
        if let Some(port) = port {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ProtocolError::Policy(
                    "invalid OpenID4VC wallet authorization origin",
                ));
            }
            let parsed = port.parse::<u16>().map_err(|_| {
                ProtocolError::Policy("invalid OpenID4VC wallet authorization origin")
            })?;
            if parsed == 0 {
                return Err(ProtocolError::Policy(
                    "invalid OpenID4VC wallet authorization origin",
                ));
            }
            if parsed == 443 || port != parsed.to_string() {
                return Err(ProtocolError::Policy(
                    "invalid OpenID4VC wallet authorization origin",
                ));
            }
        }
        if !unique.insert(origin.as_str()) {
            return Err(ProtocolError::Policy(
                "OpenID4VC trust policy origins must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_public_certificate_bundle(
    value: &str,
    message: &'static str,
) -> Result<(), ProtocolError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const END: &str = "-----END CERTIFICATE-----";
    const MAX_CERTIFICATES: usize = 4;

    if value.is_empty()
        || value.len() > 16 * 1024
        || value.contains("PRIVATE KEY")
        || value.chars().any(|character| character == '\0')
    {
        return Err(ProtocolError::Policy(message));
    }
    let normalized = value.replace("\r\n", "\n");
    if normalized.contains('\r') || !normalized.starts_with(BEGIN) {
        return Err(ProtocolError::Policy(message));
    }
    let certificate_count = normalized.matches(BEGIN).count();
    if certificate_count == 0
        || certificate_count > MAX_CERTIFICATES
        || certificate_count != normalized.matches(END).count()
    {
        return Err(ProtocolError::Policy(message));
    }

    let mut remainder = normalized.as_str();
    let mut encoded_certificates = std::collections::BTreeSet::new();
    for _ in 0..certificate_count {
        remainder = remainder.trim_start_matches(|character: char| character.is_ascii_whitespace());
        if !remainder.starts_with(BEGIN) {
            return Err(ProtocolError::Policy(message));
        }
        let body = &remainder[BEGIN.len()..];
        let end_offset = body.find(END).ok_or(ProtocolError::Policy(message))?;
        let certificate_body = &body[..end_offset];
        if certificate_body.trim().is_empty()
            || certificate_body.contains("-----BEGIN ")
            || certificate_body.contains("-----END ")
        {
            return Err(ProtocolError::Policy(message));
        }
        let encoded_body = certificate_body.lines().map(str::trim).collect::<String>();
        if !encoded_certificates.insert(encoded_body.clone()) {
            return Err(ProtocolError::Policy(message));
        }
        let decoded = STANDARD
            .decode(encoded_body.as_bytes())
            .map_err(|_| ProtocolError::Policy(message))?;
        if decoded.first() != Some(&0x30) {
            return Err(ProtocolError::Policy(message));
        }
        remainder = &body[end_offset + END.len()..];
    }
    if !remainder.trim().is_empty() {
        return Err(ProtocolError::Policy(message));
    }
    Ok(())
}

fn validate_openid4vc_trust_jwks_with_options(
    jwks: &serde_json::Value,
    client_attestation: bool,
    reject_unknown: bool,
) -> Result<(), ProtocolError> {
    if reject_unknown {
        let object = jwks.as_object().ok_or(ProtocolError::Policy(
            "OpenID4VC trust policy JWKS must be an object",
        ))?;
        if object.keys().any(|name| name != "keys") {
            return Err(ProtocolError::Policy(
                "OpenID4VC trust policy JWKS contains an unknown member",
            ));
        }
    }
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(ProtocolError::Policy(
            "OpenID4VC conformance trust requires non-empty JWK Sets",
        ))?;
    let mut key_ids = std::collections::BTreeSet::new();
    for key in keys {
        let object = key.as_object().ok_or(ProtocolError::Policy(
            "OpenID4VC conformance trust must contain public keys only",
        ))?;
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|name| object.contains_key(*name))
        {
            return Err(ProtocolError::Policy(
                "OpenID4VC conformance trust must contain public keys only",
            ));
        }
        if reject_unknown
            && object
                .keys()
                .any(|name| !matches!(name.as_str(), "alg" | "crv" | "kid" | "kty" | "x" | "y"))
        {
            return Err(ProtocolError::Policy(
                "OpenID4VC trust policy contains an unknown JWK member",
            ));
        }
        let kid = object
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .filter(|kid| !kid.is_empty() && kid.len() <= 256);
        if let Some(kid) = kid {
            if !key_ids.insert(kid.to_owned()) {
                return Err(ProtocolError::Policy(
                    "OpenID4VC conformance trust keys require unique key ids",
                ));
            }
        } else if !client_attestation || keys.len() != 1 {
            return Err(ProtocolError::Policy(
                "OpenID4VC conformance trust keys require unique key ids",
            ));
        }
        let key_type = object.get("kty").and_then(serde_json::Value::as_str);
        let algorithm = object
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(match key_type {
                Some("EC") => "ES256",
                Some("OKP") => "EdDSA",
                _ => "",
            });
        match (key_type, algorithm) {
            (Some("EC"), "ES256")
                if object.get("crv").and_then(serde_json::Value::as_str) == Some("P-256")
                    && valid_jwk_coordinate(object.get("x"), 32)
                    && valid_jwk_coordinate(object.get("y"), 32) =>
            {
                // Key-attestation ES256 keys may omit alg; the JWT header
                // still selects the supported algorithm at verification.
            }
            (Some("OKP"), "EdDSA")
                if !client_attestation
                    && object.get("crv").and_then(serde_json::Value::as_str) == Some("Ed25519")
                    && valid_jwk_coordinate(object.get("x"), 32) =>
            {
                // Supported holder key-attestation Ed25519 key.
            }
            _ => {
                return Err(ProtocolError::Policy(
                    "OpenID4VC conformance trust contains an unsupported public key",
                ));
            }
        }
    }
    Ok(())
}

fn valid_jwk_coordinate(value: Option<&serde_json::Value>, expected_len: usize) -> bool {
    let Some(value) = value.and_then(serde_json::Value::as_str) else {
        return false;
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == expected_len)
}

pub(crate) fn validate_identifier(value: &str) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_file_identifier(value: &str) -> Result<(), ProtocolError> {
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

/// Validate a canonical UUID string without pulling UUID parsing and its
/// feature surface into this deliberately small wire crate.
pub(crate) fn validate_uuid(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(ProtocolError::Policy("invalid UUID"));
    }
    Ok(())
}

/// Authoritative controller identity shape (D01): a canonical lowercase
/// RFC 9562 UUIDv7.  NazoAuth assigns it when a controller slot is created and
/// keeps it stable across key rotations, so it — unlike the `kid` — names the
/// controller rather than one generation of its key material.  The same rule
/// validates the `controller_id` persisted in the control operation journal
/// authorization snapshot (E03/D02).
pub fn validate_controller_id(value: &str) -> Result<(), ProtocolError> {
    validate_uuid(value)?;
    let bytes = value.as_bytes();
    if bytes[14] != b'7' {
        return Err(ProtocolError::Policy("controller_id must be a UUIDv7"));
    }
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return Err(ProtocolError::Policy(
            "controller_id must use the RFC 9562 variant",
        ));
    }
    Ok(())
}

pub(crate) fn validate_lower_hex(value: &str, length: usize) -> Result<(), ProtocolError> {
    if value.len() != length
        || !value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(ProtocolError::Policy("invalid digest"));
    }
    Ok(())
}
