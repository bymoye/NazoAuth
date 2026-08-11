//! Signature verification, receipt handling, and protocol-policy checks.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::DeserializeOwned;

use crate::signing::{compact_segments, decode_json, decode_protected_header};
use crate::wire::*;
use crate::{
    ADOPTION_RECEIPT_JWS_TYPE, CONFIG_MANIFEST_VERSION, CONTROL_DISCOVERY_JWS_TYPE,
    CONTROL_DISCOVERY_PRODUCT, CONTROL_DISCOVERY_SCHEMA, DEPLOYMENT_STATEMENT_JWS_TYPE,
    FINAL_RECEIPT_JWS_TYPE, MANAGEMENT_EVENT_JWS_TYPE, MAX_CONFORMANCE_MATRIX_GROUPS,
    MAX_CONFORMANCE_MATRIX_PLANS, MAX_CONFORMANCE_ONBOARDING_CLIENTS,
    MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_BYTES,
    MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_TOTAL_BYTES,
    MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASETS, MAX_DISCOVERY_LIFETIME_SECONDS,
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
        | TaskOperation::ConformanceMatrixDescribe
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
        TaskOperation::ConformanceOnboardingApply {
            profile,
            bundle_schema,
            bundle_sha256,
            matrix_sha256,
            client_count,
            ttl_seconds,
        } => {
            validate_identifier(profile)?;
            if profile != "nazoauth-full" {
                return Err(ProtocolError::Policy(
                    "unsupported conformance onboarding profile",
                ));
            }
            if *bundle_schema != 2 {
                return Err(ProtocolError::Policy(
                    "unsupported conformance onboarding bundle schema",
                ));
            }
            validate_lower_hex(bundle_sha256, 64)?;
            validate_lower_hex(matrix_sha256, 64)?;
            if !(1..=MAX_CONFORMANCE_ONBOARDING_CLIENTS).contains(client_count) {
                return Err(ProtocolError::Policy(
                    "conformance onboarding client count is out of bounds",
                ));
            }
            if !(60..=86_400).contains(ttl_seconds) {
                return Err(ProtocolError::Policy(
                    "conformance onboarding ttl must be between 60 and 86400 seconds",
                ));
            }
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

pub fn validate_conformance_matrix_descriptor(
    descriptor: &ConformanceMatrixDescriptor,
) -> Result<(), ProtocolError> {
    if descriptor.schema != 1 {
        return Err(ProtocolError::Policy(
            "unsupported conformance matrix schema",
        ));
    }
    validate_identifier(&descriptor.source.release)?;
    validate_lower_hex(&descriptor.source.digest, 64)?;
    validate_conformance_openid4vc_credential_datasets(&descriptor.openid4vc_credential_datasets)?;
    if descriptor.groups.is_empty() || descriptor.groups.len() > MAX_CONFORMANCE_MATRIX_GROUPS {
        return Err(ProtocolError::Policy(
            "conformance matrix group count is out of bounds",
        ));
    }
    let mut groups = std::collections::BTreeSet::new();
    let mut plans = std::collections::BTreeSet::new();
    let mut logical_clients =
        std::collections::BTreeMap::<String, ConformanceMatrixCryptoPolicy>::new();
    let mut registrations = std::collections::BTreeMap::<String, serde_json::Value>::new();
    let mut plan_count = 0usize;
    for group in &descriptor.groups {
        validate_identifier(&group.id)?;
        validate_identifier(&group.profile)?;
        validate_conformance_matrix_variant(&group.variant)?;
        if !groups.insert(&group.id) {
            return Err(ProtocolError::Policy("duplicate conformance matrix group"));
        }
        validate_conformance_matrix_roles(&group.required_roles, None, &mut logical_clients)?;
        if group.plans.is_empty() {
            return Err(ProtocolError::Policy("duplicate conformance matrix group"));
        }
        for plan in &group.plans {
            plan_count = plan_count.saturating_add(1);
            if plan_count > MAX_CONFORMANCE_MATRIX_PLANS {
                return Err(ProtocolError::Policy(
                    "conformance matrix plan count is out of bounds",
                ));
            }
            validate_identifier(&plan.id)?;
            validate_identifier(&plan.plan)?;
            if !plans.insert(&plan.id) {
                return Err(ProtocolError::Policy("duplicate conformance matrix plan"));
            }
            if !plan.config_template.is_object() {
                return Err(ProtocolError::Policy(
                    "conformance matrix plan config must be an object",
                ));
            }
            validate_conformance_matrix_variant_map(&plan.variant)?;
            validate_conformance_matrix_crypto(&plan.crypto)?;
            if plan.expected_results.len() > 64 {
                return Err(ProtocolError::Policy(
                    "conformance matrix expected result count is out of bounds",
                ));
            }
            for (test_name, result) in &plan.expected_results {
                validate_identifier(test_name)?;
                if result != "SKIPPED" {
                    return Err(ProtocolError::Policy(
                        "conformance matrix expected result must be SKIPPED",
                    ));
                }
            }
            // Group roles participate in every plan's client materialization;
            // bind them to each plan's crypto policy just as CTL does.
            validate_conformance_matrix_roles(
                &group.required_roles,
                Some(&plan.crypto),
                &mut logical_clients,
            )?;
            validate_conformance_matrix_roles(
                &plan.required_roles,
                Some(&plan.crypto),
                &mut logical_clients,
            )?;
            let mut plan_logical_ids = std::collections::BTreeSet::new();
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                if let Some(template) = &role.registration_template {
                    let logical = role.logical_client_id.as_deref().unwrap_or(&role.role);
                    if let Some(previous) = registrations.get(logical)
                        && previous != template
                    {
                        return Err(ProtocolError::Policy(
                            "conformance matrix client registration is inconsistent",
                        ));
                    }
                    registrations.insert(logical.to_owned(), template.clone());
                }
                let logical = role.logical_client_id.as_deref().unwrap_or(&role.role);
                if !plan_logical_ids.insert(logical) {
                    return Err(ProtocolError::Policy(
                        "duplicate conformance matrix role in plan",
                    ));
                }
            }
        }
    }
    if plan_count == 0 {
        return Err(ProtocolError::Policy(
            "conformance matrix must contain at least one plan",
        ));
    }
    validate_conformance_openid4vc_dataset_references(
        descriptor,
        &descriptor.openid4vc_credential_datasets,
    )?;
    // Resolve placeholders only after all groups/plans have contributed their
    // logical clients, allowing a role declared in one plan to be referenced
    // by another plan without making validation order observable.
    for group in &descriptor.groups {
        for plan in &group.plans {
            validate_conformance_matrix_bindings(&plan.secret_bindings, &logical_clients)?;
            validate_conformance_matrix_template(
                &plan.config_template,
                &plan.secret_bindings,
                &logical_clients,
            )?;
            for role in group.required_roles.iter().chain(&plan.required_roles) {
                if let Some(template) = &role.registration_template {
                    validate_conformance_registration_template_shape(template)?;
                    validate_conformance_matrix_template(
                        template,
                        &plan.secret_bindings,
                        &logical_clients,
                    )?;
                }
                for reference in &role.secret_refs {
                    validate_conformance_matrix_reference(
                        reference,
                        &plan.secret_bindings,
                        &logical_clients,
                        &mut std::collections::BTreeSet::new(),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_conformance_openid4vc_dataset_references(
    descriptor: &ConformanceMatrixDescriptor,
    datasets: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), ProtocolError> {
    let mut referenced = std::collections::BTreeSet::new();
    for group in &descriptor.groups {
        for plan in &group.plans {
            let Some(config_id) = plan
                .config_template
                .get("vci")
                .and_then(serde_json::Value::as_object)
                .and_then(|vci| vci.get("credential_configuration_id"))
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            // Multiple plans may intentionally use the same credential
            // configuration; the map remains one value per ID.
            referenced.insert(config_id.to_owned());
            let Some(claims) = datasets.get(config_id) else {
                return Err(ProtocolError::Policy(
                    "conformance VCI plan references an unknown credential dataset",
                ));
            };
            if let Some(plan_claims) = plan
                .config_template
                .get("nazo")
                .and_then(serde_json::Value::as_object)
                .and_then(|nazo| nazo.get("credential_dataset"))
                && plan_claims != claims
            {
                return Err(ProtocolError::Policy(
                    "conformance VCI plan credential dataset drifts from the Matrix map",
                ));
            }
        }
    }
    if referenced
        != datasets
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
    {
        return Err(ProtocolError::Policy(
            "conformance Matrix credential dataset map does not match VCI plans",
        ));
    }
    Ok(())
}

/// Validates the public claims that are copied into a lease-owned OpenID4VC
/// applicant.  This is intentionally independent of issuer storage: the
/// checked-in Matrix is the authority for which configuration IDs are
/// available, while the runtime performs its normal credential-format checks
/// before writing the values.
fn validate_conformance_openid4vc_credential_datasets(
    datasets: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), ProtocolError> {
    if datasets.len() > usize::try_from(MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASETS).unwrap() {
        return Err(ProtocolError::Policy(
            "conformance OpenID4VC credential dataset count is out of bounds",
        ));
    }
    let mut total_bytes = 0usize;
    for (configuration_id, claims) in datasets {
        validate_identifier(configuration_id)?;
        let Some(object) = claims.as_object() else {
            return Err(ProtocolError::Policy(
                "conformance OpenID4VC credential dataset must be an object",
            ));
        };
        if object.is_empty() {
            return Err(ProtocolError::Policy(
                "conformance OpenID4VC credential dataset must not be empty",
            ));
        }
        let encoded = serde_json::to_vec(claims).map_err(|_| ProtocolError::Json)?;
        if encoded.len() > MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_BYTES
            || total_bytes.saturating_add(encoded.len())
                > MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_TOTAL_BYTES
        {
            return Err(ProtocolError::Policy(
                "conformance OpenID4VC credential dataset size is out of bounds",
            ));
        }
        total_bytes = total_bytes.saturating_add(encoded.len());
        let mut nodes = 0usize;
        validate_public_credential_claims(claims, 0, &mut nodes)?;
    }
    Ok(())
}

fn validate_public_credential_claims(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ProtocolError> {
    *nodes = nodes.saturating_add(1);
    if depth > 8 || *nodes > 512 {
        return Err(ProtocolError::Policy(
            "conformance OpenID4VC credential dataset structure is too deep",
        ));
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if key.is_empty()
                    || key.len() > 255
                    || key.chars().any(char::is_control)
                    || is_forbidden_public_credential_claim_key(key)
                {
                    return Err(ProtocolError::Policy(
                        "conformance OpenID4VC credential dataset contains a forbidden claim",
                    ));
                }
                validate_public_credential_claims(child, depth + 1, nodes)?;
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                validate_public_credential_claims(child, depth + 1, nodes)?;
            }
        }
        serde_json::Value::String(string) => {
            if string.len() > 4096 || string.contains("{{") || string.contains("}}") {
                return Err(ProtocolError::Policy(
                    "conformance OpenID4VC credential dataset contains an invalid value",
                ));
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn is_forbidden_public_credential_claim_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "password"
            | "password_hash"
            | "token"
            | "access_token"
            | "refresh_token"
            | "client_secret"
            | "private_key"
            | "private_jwk"
            | "private_jwks"
            | "d"
            | "p"
            | "q"
            | "dp"
            | "dq"
            | "qi"
            | "oth"
            | "k"
    )
}

fn validate_conformance_matrix_variant(
    variant: &ConformanceMatrixVariant,
) -> Result<(), ProtocolError> {
    validate_identifier(&variant.id)?;
    validate_conformance_matrix_variant_map(&variant.values)
}

fn validate_conformance_registration_template_shape(
    template: &serde_json::Value,
) -> Result<(), ProtocolError> {
    let object = template.as_object().ok_or(ProtocolError::Policy(
        "conformance matrix registration template must be an object",
    ))?;
    for field in [
        "client_name",
        "client_type",
        "redirect_uris",
        "scopes",
        "allowed_audiences",
        "grant_types",
        "token_endpoint_auth_method",
    ] {
        if !object.contains_key(field) {
            return Err(ProtocolError::Policy(
                "conformance matrix registration template is incomplete",
            ));
        }
    }
    // These fields map directly to `Vec<String>` members of
    // `CreateClientRequest`.  Keeping the descriptor as arbitrary JSON here
    // would defer a schema error until the privileged onboarding path, after
    // the bundle has been materialized.  Reject scalar (or non-string element)
    // vectors at the signed Matrix boundary instead.
    const VECTOR_FIELDS: &[&str] = &[
        "redirect_uris",
        "post_logout_redirect_uris",
        "scopes",
        "allowed_audiences",
        "grant_types",
        "tls_client_auth_san_dns",
        "tls_client_auth_san_uri",
        "tls_client_auth_san_ip",
        "tls_client_auth_san_email",
    ];
    for field in VECTOR_FIELDS {
        let Some(value) = object.get(*field) else {
            // Optional vector fields (`post_logout_redirect_uris` and SAN
            // selectors) are defaulted by CreateClientRequest.  Required
            // vectors were checked above and therefore cannot reach here as
            // missing values.
            continue;
        };
        let Some(values) = value.as_array() else {
            return Err(ProtocolError::Policy(
                "conformance matrix registration vector field must be an array",
            ));
        };
        if values.iter().any(|value| !value.is_string()) {
            return Err(ProtocolError::Policy(
                "conformance matrix registration vector field must contain strings",
            ));
        }
    }
    if let Some(policy) = object.get("security_policy") {
        let policy = policy.as_object().ok_or(ProtocolError::Policy(
            "conformance matrix registration security policy must be an object",
        ))?;
        if policy.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(ProtocolError::Policy(
                "conformance matrix registration security policy version must be 1",
            ));
        }
        const BOOLEAN_FIELDS: &[&str] = &[
            "require_signed_authorization_request",
            "require_signed_authorization_response",
            "require_signed_introspection_response",
            "session_management",
            "allow_cross_device_flows",
            "allow_confidential_oidc_without_pkce",
        ];
        for (field, value) in policy {
            match field.as_str() {
                "version" => {}
                "assurance" => {
                    if !matches!(value.as_str(), Some("baseline" | "fapi2")) {
                        return Err(ProtocolError::Policy(
                            "conformance matrix registration assurance is invalid",
                        ));
                    }
                }
                field if BOOLEAN_FIELDS.contains(&field) => {
                    if !value.is_boolean() {
                        return Err(ProtocolError::Policy(
                            "conformance matrix registration security policy flag must be boolean",
                        ));
                    }
                }
                _ => {
                    return Err(ProtocolError::Policy(
                        "conformance matrix registration security policy field is unknown",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_conformance_matrix_variant_map(
    values: &std::collections::BTreeMap<String, String>,
) -> Result<(), ProtocolError> {
    if values.len() > 64 {
        return Err(ProtocolError::Policy(
            "conformance matrix variant is too large",
        ));
    }
    for (key, value) in values {
        validate_identifier(key)?;
        validate_identifier(value)?;
    }
    Ok(())
}

fn validate_conformance_matrix_roles(
    roles: &[ConformanceMatrixRoleRequirement],
    crypto: Option<&ConformanceMatrixCryptoPolicy>,
    clients: &mut std::collections::BTreeMap<String, ConformanceMatrixCryptoPolicy>,
) -> Result<(), ProtocolError> {
    if roles.len() > 64 {
        return Err(ProtocolError::Policy(
            "conformance matrix role count is too large",
        ));
    }
    let mut local = std::collections::BTreeSet::new();
    for role in roles {
        validate_identifier(&role.role)?;
        let logical = role.logical_client_id.as_deref().unwrap_or(&role.role);
        validate_identifier(logical)?;
        if !local.insert(logical) {
            return Err(ProtocolError::Policy("duplicate conformance matrix role"));
        }
        if role.secret_refs.len() > 32 {
            return Err(ProtocolError::Policy(
                "conformance matrix secret references are too large",
            ));
        }
        for reference in &role.secret_refs {
            if reference.is_empty()
                || reference.len() > 256
                || reference.chars().any(char::is_control)
            {
                return Err(ProtocolError::Policy(
                    "conformance matrix secret reference is invalid",
                ));
            }
        }
        if let Some(template) = &role.registration_template
            && !template.is_object()
        {
            return Err(ProtocolError::Policy(
                "conformance matrix registration template must be an object",
            ));
        }
        if let Some(crypto) = crypto
            && role.registration_template.is_some()
        {
            if let Some(previous) = clients.get(logical)
                && previous != crypto
            {
                return Err(ProtocolError::Policy(
                    "conformance matrix client crypto policy is inconsistent",
                ));
            }
            clients.insert(logical.to_owned(), crypto.clone());
        }
    }
    Ok(())
}

fn validate_conformance_matrix_crypto(
    crypto: &ConformanceMatrixCryptoPolicy,
) -> Result<(), ProtocolError> {
    if !matches!(crypto.rsa_bits, 2048 | 3072 | 4096)
        || crypto.ec_curve != "P-256"
        || crypto.mtls_signature != "ECDSA-P256-SHA256"
    {
        return Err(ProtocolError::Policy(
            "conformance matrix crypto policy is weak",
        ));
    }
    Ok(())
}

fn validate_conformance_matrix_bindings(
    bindings: &std::collections::BTreeMap<String, String>,
    clients: &std::collections::BTreeMap<String, ConformanceMatrixCryptoPolicy>,
) -> Result<(), ProtocolError> {
    if bindings.len() > 64 {
        return Err(ProtocolError::Policy(
            "conformance matrix secret bindings are too large",
        ));
    }
    for (name, value) in bindings {
        validate_identifier(name)?;
        let reference = parse_conformance_matrix_placeholder(value)?;
        validate_conformance_matrix_reference(
            reference,
            bindings,
            clients,
            &mut std::collections::BTreeSet::new(),
        )?;
    }
    Ok(())
}

fn validate_conformance_matrix_template(
    value: &serde_json::Value,
    bindings: &std::collections::BTreeMap<String, String>,
    clients: &std::collections::BTreeMap<String, ConformanceMatrixCryptoPolicy>,
) -> Result<(), ProtocolError> {
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .try_for_each(|child| validate_conformance_matrix_template(child, bindings, clients)),
        serde_json::Value::Object(values) => {
            for (key, child) in values {
                if is_conformance_sensitive_key(key)
                    && matches!(child, serde_json::Value::String(text) if !is_conformance_placeholder(text))
                {
                    return Err(ProtocolError::Policy(
                        "conformance matrix embeds sensitive material",
                    ));
                }
                validate_conformance_matrix_template(child, bindings, clients)?;
            }
            Ok(())
        }
        serde_json::Value::String(text)
            if text.contains("{{") || text.contains("}}") || text.contains("${") =>
        {
            let reference = parse_conformance_matrix_placeholder(text)?;
            validate_conformance_matrix_reference(
                reference,
                bindings,
                clients,
                &mut std::collections::BTreeSet::new(),
            )
        }
        _ => Ok(()),
    }
}

fn parse_conformance_matrix_placeholder(value: &str) -> Result<&str, ProtocolError> {
    if !value.starts_with("{{") || !value.ends_with("}}") || value.len() < 5 {
        return Err(ProtocolError::Policy(
            "conformance matrix placeholder is invalid",
        ));
    }
    let name = value[2..value.len() - 2].trim();
    if name.is_empty()
        || name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || name.contains("{{")
        || name.contains("}}")
    {
        return Err(ProtocolError::Policy(
            "conformance matrix placeholder is invalid",
        ));
    }
    Ok(name)
}

fn is_conformance_placeholder(value: &str) -> bool {
    value.starts_with("{{")
        && value.ends_with("}}")
        && parse_conformance_matrix_placeholder(value).is_ok()
}

fn validate_conformance_matrix_reference(
    reference: &str,
    bindings: &std::collections::BTreeMap<String, String>,
    clients: &std::collections::BTreeMap<String, ConformanceMatrixCryptoPolicy>,
    stack: &mut std::collections::BTreeSet<String>,
) -> Result<(), ProtocolError> {
    let name = reference.trim();
    if name.starts_with("plan.") || name.starts_with("group.") || name.contains("::") {
        return Err(ProtocolError::Policy(
            "conformance matrix cross-plan reference is forbidden",
        ));
    }
    if let Some(binding) = name.strip_prefix("secret.") {
        let value = bindings.get(binding).ok_or(ProtocolError::Policy(
            "conformance matrix references an unknown secret",
        ))?;
        if !stack.insert(binding.to_owned()) {
            return Err(ProtocolError::Policy(
                "conformance matrix secret reference cycle",
            ));
        }
        let nested = parse_conformance_matrix_placeholder(value)?;
        let result = validate_conformance_matrix_reference(nested, bindings, clients, stack);
        stack.remove(binding);
        return result;
    }
    if bindings.contains_key(name) {
        return validate_conformance_matrix_reference(
            &format!("secret.{name}"),
            bindings,
            clients,
            stack,
        );
    }
    if let Some(rest) = name.strip_prefix("client.") {
        let (logical, field) = rest.split_once('.').ok_or(ProtocolError::Policy(
            "conformance matrix client reference is invalid",
        ))?;
        if !clients.contains_key(logical)
            || !matches!(
                field,
                "id" | "client_secret"
                    | "rsa.private_jwks"
                    | "rsa.public_jwks"
                    | "ec.private_jwks"
                    | "ec.public_jwks"
                    | "mtls.ca_cert"
                    | "mtls.client_cert"
                    | "mtls.client_key"
                    | "mtls.cert_sha256"
            )
        {
            return Err(ProtocolError::Policy(
                "conformance matrix client reference is invalid",
            ));
        }
        return Ok(());
    }
    if matches!(
        name,
        "target.issuer"
            | "target.suite"
            | "suite.origin"
            | "target.host"
            | "target.ciba_automated_decision_url"
            | "generated.applicant_email"
            | "generated.applicant_password"
            | "generated.credential_holder_email_sha256"
            | "generated.client_secret"
            | "generated.rsa.private_jwks"
            | "generated.rsa.public_jwks"
            | "generated.ec.private_jwks"
            | "generated.ec.public_jwks"
            | "generated.mtls.ca_cert"
            | "generated.mtls.client_cert"
            | "generated.mtls.client_key"
            | "generated.mtls.cert_sha256"
            | "generated.dynamic_registration_initial_access_token"
            | "generated.ciba_automated_decision_token"
            | "onboarding.applicant_id"
            | "onboarding.openid4vc_request_object_trust_anchor_pem"
    ) {
        return Ok(());
    }
    if valid_conformance_dynamic_reference(name) {
        return Ok(());
    }
    if matches!(name, "onboarding.client_id" | "onboarding.client_secret") {
        if clients.len() != 1 {
            return Err(ProtocolError::Policy(
                "conformance matrix onboarding reference is ambiguous",
            ));
        }
        return Ok(());
    }
    Err(ProtocolError::Policy(
        "conformance matrix references an unknown secret",
    ))
}

fn valid_conformance_dynamic_reference(name: &str) -> bool {
    if let Some(path) = name.strip_prefix("target.url.") {
        return valid_conformance_path(path, false);
    }
    if let Some(path) = name.strip_prefix("target.pattern.") {
        return valid_conformance_path(path, true);
    }
    if let Some(segment) = name.strip_prefix("run.alias.") {
        return valid_conformance_segment(segment);
    }
    if let Some(reference) = name.strip_prefix("suite.test.") {
        return reference.split_once('.').is_some_and(|(alias, endpoint)| {
            valid_conformance_segment(alias) && valid_conformance_segment(endpoint)
        });
    }
    if let Some(reference) = name.strip_prefix("suite.test_query.") {
        return reference.split_once('.').is_some_and(|(alias, endpoint)| {
            valid_conformance_segment(alias) && valid_conformance_segment(endpoint)
        });
    }
    if let Some(endpoint) = name.strip_prefix("suite.pattern.") {
        return valid_conformance_segment(endpoint);
    }
    false
}

fn valid_conformance_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_conformance_path(value: &str, allow_trailing_wildcard: bool) -> bool {
    let path = value.strip_suffix('*').unwrap_or(value);
    let has_wildcard = path.len() != value.len();
    path.starts_with('/')
        && path.len() <= 512
        && !path.contains("//")
        && !path.contains(['?', '#', '\\', '{', '}'])
        && !path.split('/').any(|segment| segment == "..")
        && !path.contains('*')
        && (!has_wildcard || allow_trailing_wildcard)
}

fn is_conformance_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "password"
            | "token"
            | "access_token"
            | "refresh_token"
            | "password_hash"
            | "client_secret"
            | "private_key"
            | "private_jwk"
            | "private_jwks"
            | "d"
            | "p"
            | "q"
            | "dp"
            | "dq"
            | "qi"
            | "oth"
            | "k"
    )
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
