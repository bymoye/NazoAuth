//! Stable serde wire models for the operator protocol.

use std::collections::BTreeMap;

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEnvelope {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub deployment_id: String,
    pub actor: Actor,
    pub target: TargetExpectation,
    pub embedded: EmbeddedIdentity,
    pub config: ConfigBinding,
    pub operation: TaskOperation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    LocalRoot,
    Automation,
    BreakGlass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TargetExpectation {
    OciImage {
        image_ref: String,
        image_digest: String,
    },
    HostBinary {
        path: String,
        sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedIdentity {
    pub release: String,
    pub revision: String,
    pub protocol: u32,
    pub build_id: String,
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
    pub revision: String,
    pub build_id: String,
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
    pub revision: String,
    pub build_id: String,
    pub control_protocol_versions: Vec<u32>,
    pub operator_protocol_versions: Vec<u32>,
    pub instance_key_id: String,
    pub issued_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionReceipt {
    pub schema: u32,
    pub deployment_id: String,
    pub issuer: String,
    pub runtime_instances: Vec<AdoptedRuntimeIdentity>,
    pub verified_release: String,
    pub release_manifest_sha256: String,
    pub instance_key_ids: Vec<String>,
    pub resource_references: BTreeMap<String, String>,
    pub capabilities: BTreeMap<String, String>,
    pub recovery_proven: bool,
    pub recovery_evidence: Vec<String>,
    pub plan_sha256: String,
    pub adopted_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedRuntimeIdentity {
    pub runtime_instance_id: String,
    pub backend: String,
    pub object_reference: String,
    pub artifact_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBinding {
    pub manifest_version: u32,
    pub config_sha256: String,
    pub secret_binding: SecretBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretBinding {
    OpaqueRevision { revision: String },
    HmacSha256 { key_id: String, digest: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "name", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TaskOperation {
    MigrateApply,
    ConformanceLeaseCreate {
        profile: String,
        material_sha256: String,
        /// SHA-256 of the per-run dynamic-registration initial-access token.
        ///
        /// The token itself is deliberately never part of the operator
        /// protocol.  This digest is only used to bind a short-lived
        /// conformance lease to the registration guard.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dynamic_registration_initial_access_token_sha256: Option<String>,
        /// SHA-256 of the per-run CIBA automated-decision token.
        ///
        /// The token itself never crosses the operator protocol boundary.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ciba_automated_decision_token_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_material: Option<Openid4vcConformanceTrust>,
        ttl_seconds: u64,
    },
    ConformanceLeaseList,
    ConformanceLeaseRevoke {
        lease_id: String,
    },
    ConformanceLeaseCleanup,
    KeysList,
    KeysValidate,
    KeysGenerateLocal {
        alg: String,
        purposes: Vec<String>,
    },
    KeysRegisterExternal {
        kid: String,
        alg: String,
        key_ref: String,
        public_jwk_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Openid4vcConformanceTrust {
    pub schema: u32,
    pub client_attestation_issuer: String,
    pub client_attestation_jwks: serde_json::Value,
    pub key_attestation_jwks: serde_json::Value,
    pub credential_trust_anchor_pem: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceipt {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub request_sha256: String,
    pub deployment_id: String,
    pub actor: Actor,
    pub operation: String,
    pub started_at: i64,
    pub completed_at: i64,
    pub embedded: EmbeddedIdentity,
    pub config: ConfigBinding,
    pub outcome: TaskOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeTargetClaim {
    OciImage {
        image_ref: String,
        image_digest: String,
    },
    HostBinary {
        path: String,
        sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalReceipt {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub request_sha256: String,
    pub deployment_id: String,
    pub actor: Actor,
    pub operation: String,
    pub completed_at: i64,
    pub audit_sequence: u64,
    pub audit_previous_sha256: String,
    pub controller_verified_target: RuntimeTargetClaim,
    pub embedded: EmbeddedIdentity,
    pub config: ConfigBinding,
    pub runtime_receipt_sha256: String,
    pub outcome: TaskOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerTrustTransition {
    pub ver: u32,
    pub deployment_id: String,
    pub issued_at: i64,
    pub authorization: TransitionAuthorization,
    pub previous_key_id: String,
    pub next_key_id: String,
    pub next_public_key_sha256: String,
    pub previous_audit_key_id: String,
    pub next_audit_key_id: String,
    pub next_audit_public_key_sha256: String,
    pub previous_break_glass_key_id: String,
    pub next_break_glass_key_id: String,
    pub next_break_glass_public_key_sha256: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionAuthorization {
    Controller,
    BreakGlass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementAuditEvent {
    pub ver: u32,
    pub deployment_id: String,
    pub sequence: u64,
    pub previous_sha256: String,
    pub request_id: String,
    pub issued_at: i64,
    pub actor: Actor,
    pub operation: String,
    pub release: String,
    pub recovery_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TaskOutcome {
    Succeeded { result: TaskResult },
    Failed { code: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TaskResult {
    Migration {
        applied: bool,
    },
    KeyList {
        keyset_revision: String,
    },
    KeyValidation {
        keyset_revision: String,
    },
    KeyGenerated {
        kid: String,
        keyset_revision: String,
    },
    ExternalKeyRegistered {
        kid: String,
        keyset_revision: String,
    },
    ConformanceLeaseCreated {
        lease: ConformanceLeaseSummary,
    },
    ConformanceLeaseList {
        leases: Vec<ConformanceLeaseSummary>,
    },
    ConformanceLeaseRevoked {
        lease_id: String,
        deactivated_clients: u64,
    },
    ConformanceLeaseCleaned {
        cleaned_leases: u64,
        deleted_clients: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceLeaseSummary {
    pub lease_id: String,
    pub profile: String,
    pub material_sha256: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub cleaned_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalConfigManifest {
    pub version: u32,
    pub entries: BTreeMap<String, String>,
}
