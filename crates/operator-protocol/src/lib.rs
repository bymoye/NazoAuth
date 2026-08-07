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
pub const CONTROL_DISCOVERY_SCHEMA: u32 = 1;
pub const CONTROL_DISCOVERY_PRODUCT: &str = "nazoauth";
pub const MAX_COMPACT_JWS_BYTES: usize = 64 * 1024;
pub const MAX_TASK_LIFETIME_SECONDS: i64 = 60;
pub const MAX_DISCOVERY_LIFETIME_SECONDS: i64 = 60;

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
    sign_runtime_receipt, sign_task, sign_trust_transition,
};
pub use verification::{
    validate_discovery_request, validate_file_identifier_value,
    validate_runtime_receipt_deployment_binding, validate_task_deployment_binding,
    verify_adoption_receipt, verify_deployment_statement, verify_discovery_statement,
    verify_final_receipt, verify_management_event, verify_runtime_receipt, verify_task,
    verify_task_signature, verify_task_window, verify_trust_transition,
};
pub use wire::*;

#[cfg(test)]
pub(crate) use signing::sign_compact;
#[cfg(test)]
pub(crate) use verification::validate_operation;

#[cfg(test)]
#[path = "../tests/unit/mod.rs"]
mod tests;
