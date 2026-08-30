//! Stable serde wire models for the operator protocol.

use serde::{Deserialize, Serialize};

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

/// Closed kinds understood by the tenant resource provider.  Adding a kind is
/// a protocol change: older runtimes must reject it rather than treating an
/// unknown resource as an opaque object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TenantResourceKind {
    OauthClient,
    MtlsTrustAnchor,
    Openid4vcDataset,
    Openid4vcTrustPolicy,
    User,
}

/// Resource identity and its public manifest digest.  The digest is the
/// provider's canonical resource representation digest; no resource payload
/// or endpoint is carried in this protocol.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceIdentity {
    pub kind: TenantResourceKind,
    pub resource_id: String,
    pub digest: String,
}

/// Public identity mapping returned for resources that are wired into the
/// caller's tenant.  Only User and OauthClient mappings are defined by this
/// protocol; other resource kinds must never expose a public identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceMapping {
    pub kind: TenantResourceKind,
    pub resource_id: String,
    pub public_id: String,
}

/// Bounded selector used by enumerate requests.  A selector is typed so a
/// client resource ID cannot be interpreted as a different provider kind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceSelector {
    pub kind: TenantResourceKind,
    pub resource_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub release: String,
    pub protocol: u32,
}

/// Unauthenticated, bounded challenge for the read-only control discovery endpoint.
///
/// The nonce is 32 random bytes encoded as unpadded base64url.  It provides
/// freshness, not trust; callers still have to bind the returned instance key
/// to runtime evidence and a trusted release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRequest {
    pub schema: u32,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryResponse {
    pub statement: String,
    pub instance_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryStatement {
    pub schema: u32,
    pub product: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub issuer: String,
    pub release: String,
    pub control_protocol_versions: Vec<u32>,
    pub operator_protocol_versions: Vec<u32>,
    pub instance_key_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Long-lived identity evidence written beside the instance public key.
///
/// This statement deliberately has no freshness claim.  It identifies an
/// offline deployment but never proves that its named artifact is trusted;
/// recovery controllers must independently verify the mounted binary or OCI
/// digest against a cached trusted release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentStatement {
    pub schema: u32,
    pub product: String,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub issuer: String,
    pub release: String,
    pub control_protocol_versions: Vec<u32>,
    pub operator_protocol_versions: Vec<u32>,
    pub instance_key_id: String,
    pub issued_at: i64,
}

/// Public trust material for the ordinary OpenID4VC provider.
///
/// It carries only the public trust policy needed by a production provider and
/// has no controller-specific fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vcTrustPolicy {
    pub schema: u32,
    pub client_attestation_issuer: String,
    pub client_attestation_jwks: serde_json::Value,
    pub key_attestation_jwks: serde_json::Value,
    pub credential_trust_anchor_pem: String,
    pub wallet_authorization_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpEvidenceContext {
    pub run_jti: String,
    pub artifact_sha256: String,
    pub matrix_sha256: String,
    /// Opaque suite identifier: 1-128 file-safe ASCII bytes.
    pub suite_plan_id: String,
    /// Opaque module identifier: 1-128 file-safe ASCII bytes.
    pub suite_module_id: String,
    pub test_name: String,
    pub variant_sha256: String,
}

/// Caller-owned idempotency key for creating one OpenID4VP presentation.
///
/// The value is a canonical lowercase UUID. It is intentionally separate
/// from the normalized request digest so a repeated JTI with different input
/// can be rejected instead of silently replaying the first transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Openid4vpCreateIdempotencyRequest {
    pub create_request_jti: String,
}

/// Idempotency projection flattened into a successful create response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Openid4vpCreateIdempotencyBinding {
    pub create_request_jti: String,
    pub create_request_sha256: String,
}

/// Complete, default-expanded create input used for durable replay binding.
///
/// `dcql_query` and `transaction_data` remain JSON because this protocol
/// crate must bind the HTTP contract without duplicating the DCQL domain
/// model. Canonicalization recursively sorts every JSON object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpNormalizedCreateRequest {
    pub wallet_authorization_endpoint: String,
    pub dcql_query: serde_json::Value,
    pub haip: bool,
    pub client_id_prefix: String,
    pub request_method: String,
    pub response_mode: String,
    pub transaction_data: Option<Vec<serde_json::Value>>,
    pub openid4vc_trust_policy_resource_id: Option<String>,
    pub openid4vc_trust_policy_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpAttachEvidenceRequest {
    pub schema: u32,
    pub evidence_context: Openid4vpEvidenceContext,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Openid4vpEvidenceAttachmentStatus {
    Attached,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpAttachEvidenceResponse {
    pub schema: u32,
    pub transaction_id: String,
    pub status: Openid4vpEvidenceAttachmentStatus,
    pub evidence_context_sha256: String,
    pub presentation_binding: Openid4vpPresentationBinding,
    pub presentation_binding_sha256: String,
    pub intent_jws: String,
    pub intent_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpTrustPolicyBinding {
    pub binding_id: Option<String>,
    pub resource_id: Option<String>,
    pub resource_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpPresentationBinding {
    pub presentation_request_sha256: String,
    pub trust_policy: Openid4vpTrustPolicyBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpIssueVerificationReceiptRequest {
    pub schema: u32,
    pub issuance_request_jti: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpVerificationReceipt {
    pub schema: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub tenant_id: String,
    pub transaction_id: String,
    pub issuance_request_jti: String,
    pub status: Openid4vpVerificationStatus,
    pub evidence_context: Openid4vpEvidenceContext,
    pub presentation_binding: Openid4vpPresentationBinding,
    pub intent_sha256: String,
    pub completed_at: String,
    pub capability_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vpVerificationIntent {
    pub schema: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub deployment_id: String,
    pub runtime_instance_id: String,
    pub instance_key_id: String,
    pub tenant_id: String,
    pub transaction_id: String,
    pub evidence_context: Openid4vpEvidenceContext,
    pub presentation_binding: Openid4vpPresentationBinding,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Openid4vpVerificationStatus {
    Verified,
}
