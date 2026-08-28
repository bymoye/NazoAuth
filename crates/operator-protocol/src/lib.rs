//! Closed, non-secret wire protocol for privileged NazoAuth operator tasks.

pub const PROTOCOL_VERSION: u32 = 2;
pub const CONTROL_DISCOVERY_JWS_TYPE: &str = "nazoauth-control-discovery+jwt";
pub const DEPLOYMENT_STATEMENT_JWS_TYPE: &str = "nazoauth-deployment-statement+jwt";
pub const OPENID4VP_VERIFICATION_RECEIPT_JWS_TYPE: &str =
    "nazoauth-openid4vp-verification-receipt+jwt";
pub const OPENID4VP_VERIFICATION_INTENT_JWS_TYPE: &str =
    "nazoauth-openid4vp-verification-intent+jwt";
pub const CONTROL_DISCOVERY_SCHEMA: u32 = 1;
pub const CONTROL_DISCOVERY_PRODUCT: &str = "nazoauth";
pub const MAX_COMPACT_JWS_BYTES: usize = 64 * 1024;
/// Maximum canonical OpenID4VP create request retained for idempotent replay.
pub const MAX_OPENID4VP_NORMALIZED_CREATE_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_DISCOVERY_LIFETIME_SECONDS: i64 = 60;
/// Maximum number of resource identities/selectors carried by one machine
/// contract.  This bounds both signed payload size and receipt fan-out.
pub const MAX_TENANT_RESOURCE_IDENTITIES: usize = 256;

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
    #[error("protocol policy violation: {0}")]
    Policy(&'static str),
}

mod control_operation;
mod recovery;
mod signing;
mod verification;
mod wire;

#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub use control_operation::*;
pub use recovery::{
    RECOVERY_CHALLENGE_ACTION, RECOVERY_CHALLENGE_ALLOCATION_ACTION, RECOVERY_KDF_ID,
    RECOVERY_KDF_INFO, RECOVERY_ROOT_ROTATE_ACTION, RECOVERY_SECRET_PREFIX, RecoveryProposal,
    RecoveryRootRotation, derive_recovery_seed, format_recovery_secret, hkdf_sha256_v1,
    parse_recovery_secret, recovery_kid, recovery_public_key_bytes, recovery_verifying_key,
};
pub use signing::{
    canonical_openid4vp_evidence_context_sha256, canonical_openid4vp_normalized_create_request,
    canonical_openid4vp_presentation_binding_sha256, canonical_tenant_resource_manifest_sha256,
    compact_sha256, decode_instance_public_key, encode_instance_public_key, instance_key_id,
    openid4vp_verification_capability_sha256, protected_header, sign_deployment_statement,
    sign_discovery_statement, sign_openid4vp_verification_intent,
    sign_openid4vp_verification_receipt,
};
pub use verification::{
    Openid4vpVerificationIntentExpectations, Openid4vpVerificationReceiptExpectations,
    validate_controller_id, validate_discovery_request, validate_file_identifier_value,
    validate_openid4vc_trust_policy, validate_openid4vp_create_request_jti,
    verify_deployment_statement, verify_discovery_statement, verify_openid4vp_verification_intent,
    verify_openid4vp_verification_receipt,
};
pub use wire::*;

#[cfg(test)]
pub(crate) use signing::sign_compact;

#[cfg(test)]
#[path = "../tests/unit/mod.rs"]
mod tests;
