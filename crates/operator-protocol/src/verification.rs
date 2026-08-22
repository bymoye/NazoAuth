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
    ADOPTION_RECEIPT_JWS_TYPE, CONFIG_MANIFEST_VERSION, CONTROL_DISCOVERY_JWS_TYPE,
    CONTROL_DISCOVERY_PRODUCT, CONTROL_DISCOVERY_SCHEMA, DEPLOYMENT_STATEMENT_JWS_TYPE,
    FINAL_RECEIPT_JWS_TYPE, MANAGEMENT_EVENT_JWS_TYPE, MAX_DISCOVERY_LIFETIME_SECONDS,
    MAX_TASK_LIFETIME_SECONDS, MAX_TENANT_RESOURCE_IDENTITIES, MAX_TENANT_RESOURCE_KINDS,
    OPENID4VP_VERIFICATION_INTENT_JWS_TYPE, OPENID4VP_VERIFICATION_RECEIPT_JWS_TYPE,
    PROTOCOL_VERSION, ProtocolError, RUNTIME_RECEIPT_JWS_TYPE, TASK_JWS_TYPE,
    TENANT_RESOURCE_CAPABILITY_JWS_TYPE, TENANT_RESOURCE_CAPABILITY_VERSION,
    TENANT_RESOURCE_RECEIPT_JWS_TYPE, TENANT_RESOURCE_TASK_JWS_TYPE, TRUST_TRANSITION_JWS_TYPE,
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
    validate_uuid(&context.suite_plan_id)?;
    validate_uuid(&context.suite_module_id)?;
    validate_identifier(&context.test_name)?;
    validate_lower_hex(&context.variant_sha256, 64)
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

/// Verify a signed tenant resource capability and its bounded discovery
/// window.  The signer key is still selected by the caller; no key URL or
/// endpoint is accepted from the wire payload.
pub fn verify_tenant_resource_capability(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
    now: i64,
) -> Result<TenantResourceCapability, ProtocolError> {
    let capability: TenantResourceCapability = verify_compact(
        compact,
        expected_key_id,
        TENANT_RESOURCE_CAPABILITY_JWS_TYPE,
        key,
    )?;
    if capability.instance_key_id != expected_key_id {
        return Err(ProtocolError::Policy(
            "tenant resource capability key id does not match signer",
        ));
    }
    validate_tenant_resource_capability(&capability, now)?;
    Ok(capability)
}

/// Verify a capability signature and schema without applying its freshness
/// window.  This is useful when a caller first authenticates evidence and
/// then evaluates the clock at a separate policy boundary.
pub fn verify_tenant_resource_capability_signature(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<TenantResourceCapability, ProtocolError> {
    let capability: TenantResourceCapability = verify_compact(
        compact,
        expected_key_id,
        TENANT_RESOURCE_CAPABILITY_JWS_TYPE,
        key,
    )?;
    if capability.instance_key_id != expected_key_id {
        return Err(ProtocolError::Policy(
            "tenant resource capability key id does not match signer",
        ));
    }
    validate_tenant_resource_capability_shape(&capability)?;
    Ok(capability)
}

pub fn verify_tenant_resource_task(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
    now: i64,
) -> Result<TenantResourceTask, ProtocolError> {
    let task = verify_tenant_resource_task_signature(compact, expected_key_id, key)?;
    verify_tenant_resource_task_window(&task, now)?;
    Ok(task)
}

pub fn verify_tenant_resource_task_signature(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<TenantResourceTask, ProtocolError> {
    let task: TenantResourceTask =
        verify_compact(compact, expected_key_id, TENANT_RESOURCE_TASK_JWS_TYPE, key)?;
    validate_tenant_resource_task(&task)?;
    Ok(task)
}

pub fn verify_tenant_resource_receipt(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
    now: i64,
) -> Result<TenantResourceReceipt, ProtocolError> {
    let receipt = verify_tenant_resource_receipt_signature(compact, expected_key_id, key)?;
    verify_tenant_resource_receipt_window(&receipt, now)?;
    Ok(receipt)
}

/// Verify a receipt signature and wire shape without evaluating expiry.  This
/// archival path is intentionally explicit; callers processing a live result
/// should use [`verify_tenant_resource_receipt`] instead.
pub fn verify_tenant_resource_receipt_signature(
    compact: &str,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<TenantResourceReceipt, ProtocolError> {
    let receipt: TenantResourceReceipt = verify_compact(
        compact,
        expected_key_id,
        TENANT_RESOURCE_RECEIPT_JWS_TYPE,
        key,
    )?;
    validate_tenant_resource_receipt(&receipt)?;
    Ok(receipt)
}

pub fn verify_tenant_resource_receipt_window(
    receipt: &TenantResourceReceipt,
    now: i64,
) -> Result<(), ProtocolError> {
    if now < receipt.completed_at || now > receipt.exp {
        return Err(ProtocolError::Policy(
            "tenant resource receipt is outside its validity window",
        ));
    }
    Ok(())
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
    validate_runtime_receipt(&receipt)?;
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
    if receipt.runtime_instances.len() > 128
        || receipt.instance_key_ids.len() > 128
        || receipt.runtime_instances.len() != receipt.instance_key_ids.len()
    {
        return Err(ProtocolError::Policy(
            "adoption receipt instance identities are inconsistent",
        ));
    }
    let mut runtime_ids = std::collections::BTreeSet::new();
    for runtime in &receipt.runtime_instances {
        validate_file_identifier(&runtime.runtime_instance_id)?;
        if !runtime_ids.insert(runtime.runtime_instance_id.as_str()) {
            return Err(ProtocolError::Policy(
                "adoption receipt runtime identities must be unique",
            ));
        }
        for value in [
            &runtime.backend,
            &runtime.object_reference,
            &runtime.artifact_identity,
        ] {
            validate_audit_boundary(value)?;
        }
    }
    let mut key_ids = std::collections::BTreeSet::new();
    for key_id in &receipt.instance_key_ids {
        validate_file_identifier(key_id)?;
        if !key_ids.insert(key_id.as_str()) {
            return Err(ProtocolError::Policy(
                "adoption receipt key identities must be unique",
            ));
        }
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
    if receipt.recovery_proven && receipt.recovery_evidence.is_empty() {
        return Err(ProtocolError::Policy(
            "adoption recovery proof requires evidence",
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
    if task.iat <= 0
        || task.nbf <= 0
        || task.exp <= 0
        || task.exp < task.iat
        || task.exp - task.iat > MAX_TASK_LIFETIME_SECONDS
    {
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
    validate_embedded_identity(&task.embedded)?;
    match &task.target {
        TargetExpectation::OciImage {
            image_ref,
            image_digest,
        } => {
            validate_oci_image_reference(image_ref)?;
            let digest = image_digest
                .strip_prefix("sha256:")
                .ok_or(ProtocolError::Policy("OCI target must use a sha256 digest"))?;
            validate_lower_hex(digest, 64)?;
        }
        TargetExpectation::HostBinary { path, sha256 } => {
            validate_host_binary_path(path)?;
            validate_lower_hex(sha256, 64)?;
        }
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

/// Validate a tenant resource task without evaluating its current clock
/// window.
pub fn validate_tenant_resource_task(task: &TenantResourceTask) -> Result<(), ProtocolError> {
    if task.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported tenant resource task version",
        ));
    }
    for value in [&task.iss, &task.aud, &task.actor.id] {
        validate_identifier(value)?;
    }
    validate_file_identifier(&task.jti)?;
    validate_file_identifier(&task.deployment_id)?;
    validate_uuid(&task.tenant_id)?;
    validate_file_identifier(&task.capability_jti)?;
    validate_lower_hex(&task.capability_sha256, 64)?;
    if task.iss != format!("controller:{}", task.deployment_id)
        || task.aud != format!("runtime:{}", task.deployment_id)
    {
        return Err(ProtocolError::Policy(
            "tenant resource task issuer or audience is not deployment-bound",
        ));
    }
    if task.iat <= 0
        || task.nbf <= 0
        || task.exp <= 0
        || task.nbf < task.iat
        || task.exp < task.nbf
        || task
            .exp
            .checked_sub(task.iat)
            .is_none_or(|lifetime| lifetime > MAX_TASK_LIFETIME_SECONDS)
    {
        return Err(ProtocolError::Policy(
            "tenant resource task validity window is invalid",
        ));
    }
    validate_file_identifier(&task.change_set_id)?;
    validate_lower_hex(&task.change_set_sha256, 64)?;
    validate_lower_hex(&task.baseline_manifest_sha256, 64)?;
    validate_lower_hex(&task.resource_manifest_sha256, 64)?;
    if matches!(task.operation, TenantResourceOperation::Enumerate)
        && task.resource_manifest_sha256 != task.baseline_manifest_sha256
    {
        return Err(ProtocolError::Policy(
            "tenant resource enumerate manifest must equal baseline",
        ));
    }
    validate_tenant_resource_task_payload(&task.operation, &task.payload)?;
    Ok(())
}

pub fn verify_tenant_resource_task_window(
    task: &TenantResourceTask,
    now: i64,
) -> Result<(), ProtocolError> {
    if now < task.nbf || now > task.exp {
        return Err(ProtocolError::Policy(
            "tenant resource task is outside its validity window",
        ));
    }
    Ok(())
}

fn validate_tenant_resource_task_payload(
    operation: &TenantResourceOperation,
    payload: &TenantResourceTaskPayload,
) -> Result<(), ProtocolError> {
    match (operation, payload) {
        (TenantResourceOperation::Apply, TenantResourceTaskPayload::Apply { resources }) => {
            validate_tenant_resource_identities(resources, true)
        }
        (
            TenantResourceOperation::Enumerate,
            TenantResourceTaskPayload::Enumerate { selectors },
        ) => validate_tenant_resource_selectors(selectors),
        (TenantResourceOperation::Revoke, TenantResourceTaskPayload::Revoke { resources }) => {
            validate_tenant_resource_identities(resources, true)
        }
        _ => Err(ProtocolError::Policy(
            "tenant resource operation and payload do not match",
        )),
    }
}

pub fn validate_tenant_resource_capability(
    capability: &TenantResourceCapability,
    now: i64,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_capability_shape(capability)?;
    if now < capability.issued_at || now > capability.expires_at {
        return Err(ProtocolError::Policy(
            "tenant resource capability is outside its validity window",
        ));
    }
    Ok(())
}

pub(crate) fn validate_tenant_resource_capability_shape(
    capability: &TenantResourceCapability,
) -> Result<(), ProtocolError> {
    if capability.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported tenant resource capability protocol version",
        ));
    }
    if capability.capability_version != TENANT_RESOURCE_CAPABILITY_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported tenant resource capability version",
        ));
    }
    validate_file_identifier(&capability.jti)?;
    validate_discovery_nonce(&capability.nonce)?;
    validate_file_identifier(&capability.deployment_id)?;
    validate_uuid(&capability.tenant_id)?;
    validate_file_identifier(&capability.runtime_instance_id)?;
    validate_identifier(&capability.issuer)?;
    if capability.issuer != format!("runtime:{}", capability.deployment_id) {
        return Err(ProtocolError::Policy(
            "tenant resource capability issuer is not deployment-bound",
        ));
    }
    validate_file_identifier(&capability.instance_key_id)?;
    validate_embedded_identity(&capability.embedded)?;
    validate_lower_hex(&capability.resource_manifest_sha256, 64)?;
    if capability.resource_kinds.is_empty()
        || capability.resource_kinds.len() > MAX_TENANT_RESOURCE_KINDS
    {
        return Err(ProtocolError::Policy(
            "tenant resource capability kinds are out of bounds",
        ));
    }
    let mut kinds = std::collections::BTreeSet::new();
    for kind in &capability.resource_kinds {
        if !kinds.insert(*kind) {
            return Err(ProtocolError::Policy(
                "tenant resource capability kinds must be unique",
            ));
        }
    }
    if capability.actions.is_empty() || capability.actions.len() > 3 {
        return Err(ProtocolError::Policy(
            "tenant resource capability actions are out of bounds",
        ));
    }
    let mut actions = std::collections::BTreeSet::new();
    for action in &capability.actions {
        if !actions.insert(*action) {
            return Err(ProtocolError::Policy(
                "tenant resource capability actions must be unique",
            ));
        }
    }
    if capability.issued_at <= 0
        || capability.expires_at < capability.issued_at
        || capability
            .expires_at
            .checked_sub(capability.issued_at)
            .is_none_or(|lifetime| lifetime > MAX_TASK_LIFETIME_SECONDS)
    {
        return Err(ProtocolError::Policy(
            "tenant resource capability validity window is invalid",
        ));
    }
    Ok(())
}

pub fn validate_tenant_resource_receipt(
    receipt: &TenantResourceReceipt,
) -> Result<(), ProtocolError> {
    if receipt.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported tenant resource receipt version",
        ));
    }
    for value in [&receipt.iss, &receipt.aud, &receipt.actor.id] {
        validate_identifier(value)?;
    }
    validate_file_identifier(&receipt.jti)?;
    validate_file_identifier(&receipt.deployment_id)?;
    validate_uuid(&receipt.tenant_id)?;
    validate_file_identifier(&receipt.capability_jti)?;
    validate_lower_hex(&receipt.capability_sha256, 64)?;
    if receipt.iss != format!("runtime:{}", receipt.deployment_id)
        || receipt.aud != format!("controller:{}", receipt.deployment_id)
    {
        return Err(ProtocolError::Policy(
            "tenant resource receipt issuer or audience is not deployment-bound",
        ));
    }
    validate_lower_hex(&receipt.request_sha256, 64)?;
    validate_file_identifier(&receipt.change_set_id)?;
    validate_lower_hex(&receipt.change_set_sha256, 64)?;
    validate_lower_hex(&receipt.baseline_manifest_sha256, 64)?;
    validate_lower_hex(&receipt.resource_manifest_sha256, 64)?;
    if matches!(receipt.operation, TenantResourceOperation::Enumerate)
        && receipt.resource_manifest_sha256 != receipt.baseline_manifest_sha256
    {
        return Err(ProtocolError::Policy(
            "tenant resource enumerate receipt manifest must equal baseline",
        ));
    }
    validate_tenant_resource_identities(&receipt.resources, false)?;
    validate_tenant_resource_mappings(receipt)?;
    if receipt.started_at <= 0
        || receipt.completed_at < receipt.started_at
        || receipt.exp < receipt.completed_at
        || receipt
            .exp
            .checked_sub(receipt.completed_at)
            .is_none_or(|lifetime| lifetime > MAX_TASK_LIFETIME_SECONDS)
        || receipt.audit_sequence == 0
    {
        return Err(ProtocolError::Policy(
            "tenant resource receipt time or audit sequence is invalid",
        ));
    }
    validate_lower_hex(&receipt.audit_previous_sha256, 64)?;
    if let TenantResourceOutcome::Failed { code } = &receipt.outcome {
        validate_identifier(code)?;
        if !receipt.resources.is_empty() || receipt.revision != receipt.expected_revision {
            return Err(ProtocolError::Policy(
                "failed tenant resource receipt claims a resource change",
            ));
        }
    } else {
        let revision_matches = match receipt.operation {
            TenantResourceOperation::Enumerate => receipt.revision == receipt.expected_revision,
            TenantResourceOperation::Apply | TenantResourceOperation::Revoke => receipt
                .expected_revision
                .checked_add(1)
                .is_some_and(|next| receipt.revision == next),
        };
        if !revision_matches {
            return Err(ProtocolError::Policy(
                "successful tenant resource receipt revision is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_tenant_resource_mappings(receipt: &TenantResourceReceipt) -> Result<(), ProtocolError> {
    if receipt.resource_mappings.len() > MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(ProtocolError::Policy(
            "tenant resource mappings are out of bounds",
        ));
    }
    if !matches!(
        (&receipt.outcome, receipt.operation),
        (
            TenantResourceOutcome::Succeeded,
            TenantResourceOperation::Apply
        )
    ) {
        if receipt.resource_mappings.is_empty() {
            return Ok(());
        }
        return Err(ProtocolError::Policy(
            "tenant resource mappings are only allowed for successful apply",
        ));
    }

    let expected = receipt
        .resources
        .iter()
        .filter(|resource| {
            matches!(
                resource.kind,
                TenantResourceKind::User | TenantResourceKind::OauthClient
            )
        })
        .map(|resource| (resource.kind, resource.resource_id.as_str()))
        .collect::<std::collections::BTreeSet<_>>();
    let mut seen = std::collections::BTreeSet::new();
    for mapping in &receipt.resource_mappings {
        validate_file_identifier(&mapping.resource_id)?;
        match mapping.kind {
            TenantResourceKind::User => validate_uuid(&mapping.public_id)?,
            TenantResourceKind::OauthClient => validate_identifier(&mapping.public_id)?,
            TenantResourceKind::MtlsTrustAnchor
            | TenantResourceKind::Openid4vcDataset
            | TenantResourceKind::Openid4vcTrustPolicy => {
                return Err(ProtocolError::Policy(
                    "tenant resource mapping kind is not public",
                ));
            }
        }
        let key = (mapping.kind, mapping.resource_id.as_str());
        if !expected.contains(&key) || !seen.insert(key) {
            return Err(ProtocolError::Policy(
                "tenant resource mappings must cover apply resources exactly",
            ));
        }
    }
    if seen != expected {
        return Err(ProtocolError::Policy(
            "tenant resource mappings must cover apply resources exactly",
        ));
    }
    Ok(())
}

pub(crate) fn validate_tenant_resource_identities(
    resources: &[TenantResourceIdentity],
    require_nonempty: bool,
) -> Result<(), ProtocolError> {
    if resources.len() > MAX_TENANT_RESOURCE_IDENTITIES
        || (require_nonempty && resources.is_empty())
    {
        return Err(ProtocolError::Policy(
            "tenant resource identities are out of bounds",
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    for resource in resources {
        validate_file_identifier(&resource.resource_id)?;
        validate_lower_hex(&resource.digest, 64)?;
        if !identities.insert(resource.resource_id.as_str()) {
            return Err(ProtocolError::Policy(
                "tenant resource identities must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_tenant_resource_selectors(
    selectors: &[TenantResourceSelector],
) -> Result<(), ProtocolError> {
    if selectors.len() > MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(ProtocolError::Policy(
            "tenant resource selectors are out of bounds",
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    for selector in selectors {
        validate_file_identifier(&selector.resource_id)?;
        if !identities.insert((selector.kind, selector.resource_id.as_str())) {
            return Err(ProtocolError::Policy(
                "tenant resource selectors must be unique",
            ));
        }
    }
    Ok(())
}

/// Bind a task to the locally trusted deployment and tenant identity.
pub fn validate_tenant_resource_task_deployment_binding(
    task: &TenantResourceTask,
    expected_deployment_id: &str,
    expected_tenant_id: &str,
) -> Result<(), ProtocolError> {
    validate_file_identifier(expected_deployment_id)?;
    validate_uuid(expected_tenant_id)?;
    if task.deployment_id != expected_deployment_id
        || task.tenant_id != expected_tenant_id
        || task.iss != format!("controller:{expected_deployment_id}")
        || task.aud != format!("runtime:{expected_deployment_id}")
    {
        return Err(ProtocolError::Policy(
            "tenant resource task deployment or tenant binding mismatch",
        ));
    }
    Ok(())
}

/// Bind a task to a freshly discovered capability.
///
/// The task's expected revision and baseline manifest must equal the
/// capability's current values.  Apply and Revoke carry a desired external
/// manifest that may intentionally differ; Enumerate must retain the baseline.
/// No manifest bytes are inferred from the task payload.
pub fn validate_tenant_resource_task_capability_binding(
    task: &TenantResourceTask,
    capability: &TenantResourceCapability,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_task(task)?;
    validate_tenant_resource_capability_shape(capability)?;
    if task.deployment_id != capability.deployment_id
        || task.tenant_id != capability.tenant_id
        || task.capability_jti != capability.jti
        || task.expected_revision != capability.revision
        || !capability.actions.contains(&task.operation)
    {
        return Err(ProtocolError::Policy(
            "tenant resource task capability binding mismatch",
        ));
    }
    if task.baseline_manifest_sha256 != capability.resource_manifest_sha256 {
        return Err(ProtocolError::Policy(
            "tenant resource task capability baseline manifest mismatch",
        ));
    }
    if matches!(task.operation, TenantResourceOperation::Enumerate)
        && task.resource_manifest_sha256 != task.baseline_manifest_sha256
    {
        return Err(ProtocolError::Policy(
            "tenant resource enumerate manifest must equal baseline",
        ));
    }
    match &task.payload {
        TenantResourceTaskPayload::Apply { resources }
        | TenantResourceTaskPayload::Revoke { resources } => {
            for resource in resources {
                if !capability.resource_kinds.contains(&resource.kind) {
                    return Err(ProtocolError::Policy(
                        "tenant resource task requests an unsupported resource kind",
                    ));
                }
            }
        }
        TenantResourceTaskPayload::Enumerate { selectors } => {
            for selector in selectors {
                if !capability.resource_kinds.contains(&selector.kind) {
                    return Err(ProtocolError::Policy(
                        "tenant resource task requests an unsupported resource kind",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Bind a task to the exact compact capability bytes that were verified by
/// the caller.  This is the non-time-aware form for code that already applied
/// the capability freshness check.
pub fn validate_tenant_resource_task_capability_binding_with_digest(
    task: &TenantResourceTask,
    capability: &TenantResourceCapability,
    expected_capability_sha256: &str,
) -> Result<(), ProtocolError> {
    validate_lower_hex(expected_capability_sha256, 64)?;
    validate_tenant_resource_task_capability_binding(task, capability)?;
    if task.capability_sha256 != expected_capability_sha256 {
        return Err(ProtocolError::Policy(
            "tenant resource task capability digest mismatch",
        ));
    }
    Ok(())
}

/// Bind a task to a freshness-verified capability and its exact compact JWS
/// digest in one operation.
pub fn validate_tenant_resource_task_capability_binding_at(
    task: &TenantResourceTask,
    capability: &TenantResourceCapability,
    expected_capability_sha256: &str,
    now: i64,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_capability(capability, now)?;
    validate_tenant_resource_task_capability_binding_with_digest(
        task,
        capability,
        expected_capability_sha256,
    )
}

/// Bind receipt evidence to the capability that authorized the operation.
/// Apply and Revoke may report a new desired/result manifest and revision;
/// Enumerate retains the capability's baseline manifest.  Every returned
/// resource kind must be advertised by the capability.
pub fn validate_tenant_resource_receipt_capability_binding(
    receipt: &TenantResourceReceipt,
    capability: &TenantResourceCapability,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_receipt(receipt)?;
    validate_tenant_resource_capability_shape(capability)?;
    if receipt.deployment_id != capability.deployment_id
        || receipt.tenant_id != capability.tenant_id
        || receipt.capability_jti != capability.jti
        || receipt.expected_revision != capability.revision
        || !capability.actions.contains(&receipt.operation)
    {
        return Err(ProtocolError::Policy(
            "tenant resource receipt capability binding mismatch",
        ));
    }
    if receipt.baseline_manifest_sha256 != capability.resource_manifest_sha256 {
        return Err(ProtocolError::Policy(
            "tenant resource receipt capability baseline manifest mismatch",
        ));
    }
    if matches!(receipt.operation, TenantResourceOperation::Enumerate)
        && receipt.resource_manifest_sha256 != receipt.baseline_manifest_sha256
    {
        return Err(ProtocolError::Policy(
            "tenant resource enumerate receipt manifest must equal baseline",
        ));
    }
    if receipt
        .resources
        .iter()
        .any(|resource| !capability.resource_kinds.contains(&resource.kind))
    {
        return Err(ProtocolError::Policy(
            "tenant resource receipt contains an unsupported resource kind",
        ));
    }
    Ok(())
}

/// Bind a receipt to the exact compact capability bytes used by the task.
pub fn validate_tenant_resource_receipt_capability_binding_with_digest(
    receipt: &TenantResourceReceipt,
    capability: &TenantResourceCapability,
    expected_capability_sha256: &str,
) -> Result<(), ProtocolError> {
    validate_lower_hex(expected_capability_sha256, 64)?;
    validate_tenant_resource_receipt_capability_binding(receipt, capability)?;
    if receipt.capability_sha256 != expected_capability_sha256 {
        return Err(ProtocolError::Policy(
            "tenant resource receipt capability digest mismatch",
        ));
    }
    Ok(())
}

/// Bind a receipt to a freshness-verified capability and exact compact JWS
/// digest in one operation.
pub fn validate_tenant_resource_receipt_capability_binding_at(
    receipt: &TenantResourceReceipt,
    capability: &TenantResourceCapability,
    expected_capability_sha256: &str,
    now: i64,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_capability(capability, now)?;
    validate_tenant_resource_receipt_capability_binding_with_digest(
        receipt,
        capability,
        expected_capability_sha256,
    )
}

/// Ensure that a receipt repeats every request-bound identity and intent.
/// `request_sha256` is checked separately because the compact request bytes
/// are not present in a decoded task value.
pub fn validate_tenant_resource_receipt_binding(
    task: &TenantResourceTask,
    receipt: &TenantResourceReceipt,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_task(task)?;
    validate_tenant_resource_receipt(receipt)?;
    if receipt.deployment_id != task.deployment_id
        || receipt.tenant_id != task.tenant_id
        || receipt.jti != task.jti
        || receipt.capability_jti != task.capability_jti
        || receipt.capability_sha256 != task.capability_sha256
        || receipt.actor != task.actor
        || receipt.expected_revision != task.expected_revision
        || receipt.change_set_id != task.change_set_id
        || receipt.change_set_sha256 != task.change_set_sha256
        || receipt.operation != task.operation
        || receipt.baseline_manifest_sha256 != task.baseline_manifest_sha256
        || receipt.resource_manifest_sha256 != task.resource_manifest_sha256
        || receipt.iss != format!("runtime:{}", task.deployment_id)
        || receipt.aud != format!("controller:{}", task.deployment_id)
        || receipt.started_at < task.nbf
        || receipt.started_at > task.exp
    {
        return Err(ProtocolError::Policy(
            "tenant resource receipt request binding mismatch",
        ));
    }
    validate_tenant_resource_receipt_task_mappings(task, receipt)?;
    if matches!(receipt.outcome, TenantResourceOutcome::Succeeded) {
        match (&task.operation, &task.payload) {
            (TenantResourceOperation::Apply, TenantResourceTaskPayload::Apply { resources })
            | (TenantResourceOperation::Revoke, TenantResourceTaskPayload::Revoke { resources })
                if !tenant_resource_identity_sets_equal(&receipt.resources, resources) =>
            {
                return Err(ProtocolError::Policy(
                    "tenant resource receipt resources do not match request",
                ));
            }
            (
                TenantResourceOperation::Enumerate,
                TenantResourceTaskPayload::Enumerate { selectors },
            ) if !selectors.is_empty()
                && receipt.resources.iter().any(|resource| {
                    !selectors.iter().any(|selector| {
                        selector.kind == resource.kind
                            && selector.resource_id == resource.resource_id
                    })
                }) =>
            {
                return Err(ProtocolError::Policy(
                    "tenant resource enumeration result is outside selectors",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_tenant_resource_receipt_task_mappings(
    task: &TenantResourceTask,
    receipt: &TenantResourceReceipt,
) -> Result<(), ProtocolError> {
    if matches!(
        (&task.operation, &receipt.outcome),
        (
            TenantResourceOperation::Apply,
            TenantResourceOutcome::Succeeded
        )
    ) {
        return validate_tenant_resource_mappings(receipt);
    }
    if receipt.resource_mappings.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::Policy(
            "tenant resource receipt mappings are not allowed for this operation",
        ))
    }
}

fn tenant_resource_identity_sets_equal(
    left: &[TenantResourceIdentity],
    right: &[TenantResourceIdentity],
) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left = left
        .iter()
        .map(|identity| {
            (
                identity.kind,
                identity.resource_id.as_str(),
                identity.digest.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let mut right = right
        .iter()
        .map(|identity| {
            (
                identity.kind,
                identity.resource_id.as_str(),
                identity.digest.as_str(),
            )
        })
        .collect::<Vec<_>>();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

pub fn validate_tenant_resource_receipt_request_binding(
    receipt: &TenantResourceReceipt,
    expected_request_sha256: &str,
) -> Result<(), ProtocolError> {
    validate_lower_hex(expected_request_sha256, 64)?;
    if receipt.request_sha256 != expected_request_sha256 {
        return Err(ProtocolError::Policy(
            "tenant resource receipt request digest mismatch",
        ));
    }
    Ok(())
}

pub fn validate_tenant_resource_capability_binding(
    capability: &TenantResourceCapability,
    expected_deployment_id: &str,
    expected_tenant_id: &str,
) -> Result<(), ProtocolError> {
    validate_file_identifier(expected_deployment_id)?;
    validate_uuid(expected_tenant_id)?;
    if capability.deployment_id != expected_deployment_id
        || capability.tenant_id != expected_tenant_id
    {
        return Err(ProtocolError::Policy(
            "tenant resource capability deployment or tenant binding mismatch",
        ));
    }
    Ok(())
}

/// Bind discovery evidence to the operation request that caused it.  The
/// caller must still maintain replay state for the JTI/nonce pair; this wire
/// crate only enforces exact shape and equality.
pub fn validate_tenant_resource_capability_request_binding(
    capability: &TenantResourceCapability,
    expected_deployment_id: &str,
    expected_tenant_id: &str,
    expected_jti: &str,
    expected_nonce: &str,
) -> Result<(), ProtocolError> {
    validate_tenant_resource_capability_binding(
        capability,
        expected_deployment_id,
        expected_tenant_id,
    )?;
    validate_file_identifier(expected_jti)?;
    validate_discovery_nonce(expected_nonce)?;
    if capability.jti != expected_jti || capability.nonce != expected_nonce {
        return Err(ProtocolError::Policy(
            "tenant resource capability discovery binding mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn validate_runtime_receipt(receipt: &RuntimeReceipt) -> Result<(), ProtocolError> {
    if receipt.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("unsupported receipt version"));
    }
    for value in [
        &receipt.iss,
        &receipt.aud,
        &receipt.operation,
        &receipt.actor.id,
    ] {
        validate_identifier(value)?;
    }
    validate_file_identifier(&receipt.jti)?;
    validate_file_identifier(&receipt.deployment_id)?;
    validate_lower_hex(&receipt.request_sha256, 64)?;
    validate_embedded_identity(&receipt.embedded)?;
    validate_config_binding(&receipt.config)?;
    if receipt.started_at <= 0
        || receipt.completed_at <= 0
        || receipt.completed_at < receipt.started_at
    {
        return Err(ProtocolError::Policy(
            "runtime receipt time range is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn validate_final_receipt(receipt: &FinalReceipt) -> Result<(), ProtocolError> {
    if receipt.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("unsupported receipt version"));
    }
    for value in [
        &receipt.iss,
        &receipt.aud,
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
    validate_embedded_identity(&receipt.embedded)?;
    validate_config_binding(&receipt.config)?;
    if receipt.completed_at <= 0 || receipt.audit_sequence == 0 {
        return Err(ProtocolError::Policy(
            "final receipt time or audit sequence is invalid",
        ));
    }
    match &receipt.controller_verified_target {
        RuntimeTargetClaim::OciImage {
            image_ref,
            image_digest,
        } => {
            validate_oci_image_reference(image_ref)?;
            let digest = image_digest
                .strip_prefix("sha256:")
                .ok_or(ProtocolError::Policy("OCI target must use a sha256 digest"))?;
            validate_lower_hex(digest, 64)?;
        }
        RuntimeTargetClaim::HostBinary { path, sha256 } => {
            validate_host_binary_path(path)?;
            validate_lower_hex(sha256, 64)?;
        }
    }
    Ok(())
}

fn validate_embedded_identity(identity: &EmbeddedIdentity) -> Result<(), ProtocolError> {
    if identity.protocol != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy("embedded protocol version mismatch"));
    }
    for value in [&identity.release, &identity.revision, &identity.build_id] {
        validate_identifier(value)?;
    }
    Ok(())
}

fn validate_config_binding(config: &ConfigBinding) -> Result<(), ProtocolError> {
    if config.manifest_version != CONFIG_MANIFEST_VERSION {
        return Err(ProtocolError::Policy("unsupported config manifest version"));
    }
    validate_lower_hex(&config.config_sha256, 64)?;
    match &config.secret_binding {
        SecretBinding::OpaqueRevision { revision } => validate_identifier(revision),
        SecretBinding::HmacSha256 { key_id, digest } => {
            validate_identifier(key_id)?;
            validate_lower_hex(digest, 64)
        }
    }
}

pub(crate) fn validate_operation(operation: &TaskOperation) -> Result<(), ProtocolError> {
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

pub(crate) fn validate_transition(
    transition: &ControllerTrustTransition,
) -> Result<(), ProtocolError> {
    if transition.ver != PROTOCOL_VERSION {
        return Err(ProtocolError::Policy(
            "unsupported trust transition version",
        ));
    }
    if transition.issued_at <= 0 {
        return Err(ProtocolError::Policy(
            "trust transition has an invalid issuance time",
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
    if event.issued_at <= 0 || event.sequence == 0 {
        return Err(ProtocolError::Policy(
            "management event time or sequence is invalid",
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

fn validate_oci_image_reference(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 2048
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ProtocolError::Policy("invalid OCI image reference"));
    }
    Ok(())
}

fn validate_host_binary_path(value: &str) -> Result<(), ProtocolError> {
    let windows_absolute = value.as_bytes().get(1) == Some(&b':')
        && value
            .as_bytes()
            .get(2)
            .is_some_and(|byte| matches!(byte, b'/' | b'\\'));
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains(['{', '}'])
        || !(value.starts_with('/') || value.starts_with("\\\\") || windows_absolute)
    {
        return Err(ProtocolError::Policy("invalid host binary path"));
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

/// Validate a canonical UUID string without pulling UUID parsing and its
/// feature surface into this deliberately small wire crate.
fn validate_uuid(value: &str) -> Result<(), ProtocolError> {
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
