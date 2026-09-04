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
