//! Signature verification, receipt handling, and protocol-policy checks.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::DeserializeOwned;

use crate::signing::{compact_segments, decode_json, decode_protected_header};
use crate::wire::*;
use crate::{
    ADOPTION_RECEIPT_JWS_TYPE, CONFIG_MANIFEST_VERSION, CONTROL_DISCOVERY_JWS_TYPE,
    CONTROL_DISCOVERY_PRODUCT, CONTROL_DISCOVERY_SCHEMA, DEPLOYMENT_STATEMENT_JWS_TYPE,
    FINAL_RECEIPT_JWS_TYPE, MANAGEMENT_EVENT_JWS_TYPE, MAX_DISCOVERY_LIFETIME_SECONDS,
    MAX_TASK_LIFETIME_SECONDS, PROTOCOL_VERSION, ProtocolError, RUNTIME_RECEIPT_JWS_TYPE,
    TASK_JWS_TYPE, TRUST_TRANSITION_JWS_TYPE,
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

pub fn verify_adoption_receipt(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<AdoptionReceipt, ProtocolError> {
    let receipt = verify_compact(compact, expected_key_id, ADOPTION_RECEIPT_JWS_TYPE, key)?;
    validate_adoption_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_file_identifier_value(value: &str) -> Result<(), ProtocolError> {
    validate_file_identifier(value)
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

pub(crate) fn validate_adoption_receipt(receipt: &AdoptionReceipt) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_task(task: &TaskEnvelope) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_final_receipt(receipt: &FinalReceipt) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_operation(operation: &TaskOperation) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_transition(
    transition: &ControllerTrustTransition,
) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_management_event(event: &ManagementAuditEvent) -> Result<(), ProtocolError> {
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
