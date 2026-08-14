//! Closed, non-secret wire protocol for privileged NazoAuth operator tasks.

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
pub const TENANT_RESOURCE_CAPABILITY_JWS_TYPE: &str = "nazoauth-tenant-resource-capability+jwt";
pub const TENANT_RESOURCE_TASK_JWS_TYPE: &str = "nazoauth-tenant-resource-task+jwt";
pub const TENANT_RESOURCE_RECEIPT_JWS_TYPE: &str = "nazoauth-tenant-resource-receipt+jwt";
pub const TENANT_RESOURCE_CAPABILITY_VERSION: u32 = 1;
pub const CONTROL_DISCOVERY_SCHEMA: u32 = 1;
pub const CONTROL_DISCOVERY_PRODUCT: &str = "nazoauth";
pub const MAX_COMPACT_JWS_BYTES: usize = 64 * 1024;
pub const MAX_TASK_LIFETIME_SECONDS: i64 = 60;
pub const MAX_DISCOVERY_LIFETIME_SECONDS: i64 = 60;
pub const MAX_CONFORMANCE_ONBOARDING_CLIENTS: u32 = 256;
/// Maximum number of lease-owned OpenID4VC credential datasets accepted by
/// the signed Matrix and secure onboarding bundle.
pub const MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASETS: u32 = 16;
/// Maximum encoded JSON size of one lease-owned credential dataset.
pub const MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_BYTES: usize = 64 * 1024;
/// Maximum encoded JSON size of all lease-owned credential datasets in one
/// onboarding request.
pub const MAX_CONFORMANCE_ONBOARDING_CREDENTIAL_DATASET_TOTAL_BYTES: usize = 512 * 1024;
pub const MAX_CONFORMANCE_MATRIX_GROUPS: usize = 64;
pub const MAX_CONFORMANCE_MATRIX_PLANS: usize = 512;
/// Maximum number of resource identities/selectors carried by one machine
/// contract.  This bounds both signed payload size and receipt fan-out.
pub const MAX_TENANT_RESOURCE_IDENTITIES: usize = 256;
/// Maximum number of distinct resource kinds advertised by a capability.
pub const MAX_TENANT_RESOURCE_KINDS: usize = 64;

#[derive(Debug, thiserror::Error)]
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

mod signing;
mod verification;
mod wire;

#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub use signing::{
    canonical_config_sha256, compact_sha256, decode_instance_public_key,
    encode_instance_public_key, instance_key_id, protected_header, sign_adoption_receipt,
    sign_deployment_statement, sign_discovery_statement, sign_final_receipt, sign_management_event,
    sign_runtime_receipt, sign_task, sign_tenant_resource_capability, sign_tenant_resource_receipt,
    sign_tenant_resource_task, sign_trust_transition,
};
pub use verification::{
    validate_conformance_matrix_descriptor, validate_discovery_request,
    validate_file_identifier_value, validate_openid4vc_conformance_trust,
    validate_runtime_receipt_deployment_binding, validate_task_deployment_binding,
    validate_tenant_resource_capability, validate_tenant_resource_capability_binding,
    validate_tenant_resource_capability_request_binding, validate_tenant_resource_receipt,
    validate_tenant_resource_receipt_binding, validate_tenant_resource_receipt_capability_binding,
    validate_tenant_resource_receipt_capability_binding_at,
    validate_tenant_resource_receipt_capability_binding_with_digest,
    validate_tenant_resource_receipt_request_binding, validate_tenant_resource_task,
    validate_tenant_resource_task_capability_binding,
    validate_tenant_resource_task_capability_binding_at,
    validate_tenant_resource_task_capability_binding_with_digest,
    validate_tenant_resource_task_deployment_binding, verify_adoption_receipt,
    verify_deployment_statement, verify_discovery_statement, verify_final_receipt,
    verify_management_event, verify_runtime_receipt, verify_task, verify_task_signature,
    verify_task_window, verify_tenant_resource_capability,
    verify_tenant_resource_capability_signature, verify_tenant_resource_receipt,
    verify_tenant_resource_receipt_signature, verify_tenant_resource_receipt_window,
    verify_tenant_resource_task, verify_tenant_resource_task_signature,
    verify_tenant_resource_task_window, verify_trust_transition,
};
pub use wire::*;

#[cfg(test)]
pub(crate) use signing::sign_compact;
#[cfg(test)]
pub(crate) use verification::validate_operation;

#[cfg(test)]
#[path = "../tests/unit/mod.rs"]
mod tests;
