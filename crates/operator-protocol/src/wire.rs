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

/// Closed operation names for the tenant resource management contract.
///
/// This is deliberately separate from [`TaskOperation`].  The existing
/// operator task protocol is consumed by older controllers; adding variants
/// there would make those consumers silently accept a capability they do not
/// understand.  Tenant resource management therefore has its own signed
/// envelope and a closed operation set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TenantResourceOperation {
    Apply,
    Enumerate,
    Revoke,
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

/// Operation-specific payload for a tenant resource task.
///
/// `Apply` carries the desired resource identities and digests.  `Enumerate`
/// may carry an empty selector (list all resources) or a bounded set of typed
/// selectors.  `Revoke` requires at least one version-fenced resource identity
/// (including its digest).  Validation
/// rejects a payload whose variant does not match the top-level operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TenantResourceTaskPayload {
    Apply {
        resources: Vec<TenantResourceIdentity>,
    },
    Enumerate {
        selectors: Vec<TenantResourceSelector>,
    },
    Revoke {
        resources: Vec<TenantResourceIdentity>,
    },
}

/// Signed, deployment- and tenant-bound machine contract for resource
/// management.  It intentionally contains no OIDF/Suite, lease, endpoint, or
/// database semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceTask {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub deployment_id: String,
    /// Canonical UUID string for the tenant scope.
    pub tenant_id: String,
    /// JTI and compact-JWS digest of the freshness-verified capability used
    /// to authorize this task.
    pub capability_jti: String,
    pub capability_sha256: String,
    pub actor: Actor,
    /// CAS revision expected by the provider.  Zero is the initial state.
    pub expected_revision: u64,
    pub change_set_id: String,
    /// SHA-256 of the external raw Apply-manifest bytes.  Those bytes are
    /// intentionally not carried in this wire contract.
    pub change_set_sha256: String,
    pub operation: TenantResourceOperation,
    pub payload: TenantResourceTaskPayload,
    /// SHA-256 of the capability's current external canonical resource
    /// manifest.  Every operation is fenced against this baseline.
    pub baseline_manifest_sha256: String,
    /// SHA-256 of the canonical digest computed from the complete final active
    /// `TenantResourceIdentity` set expected after the operation.  Apply and
    /// Revoke may change it; Enumerate must retain the baseline.  Manifest
    /// bytes remain outside this wire contract.
    pub resource_manifest_sha256: String,
}

/// Signed capability discovery for the tenant resource contract.
///
/// `embedded` and `runtime_instance_id` bind the capability to the runtime
/// build that emitted it.  `issued_at`/`expires_at` make discovery replay
/// bounded, independently of task freshness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceCapability {
    pub ver: u32,
    pub capability_version: u32,
    /// Per-discovery operation identifier and challenge nonce; these values
    /// prevent a valid capability from being replayed across discovery calls.
    pub jti: String,
    pub nonce: String,
    pub deployment_id: String,
    pub tenant_id: String,
    pub runtime_instance_id: String,
    pub issuer: String,
    pub instance_key_id: String,
    pub embedded: EmbeddedIdentity,
    /// Current provider revision at capability discovery; zero is the
    /// initial state.
    pub revision: u64,
    /// SHA-256 of the runtime's external canonical resource manifest at
    /// `revision`; the manifest itself is not part of discovery.
    pub resource_manifest_sha256: String,
    pub resource_kinds: Vec<TenantResourceKind>,
    pub actions: Vec<TenantResourceOperation>,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Compatibility spelling for callers that use the discovery terminology.
pub type TenantResourceCapabilityStatement = TenantResourceCapability;

/// Closed receipt outcome.  A failed outcome never carries resource
/// identities and must retain the expected revision, so it cannot be read as
/// evidence that a mutation succeeded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TenantResourceOutcome {
    Succeeded,
    Failed { code: String },
}

/// Signed receipt for a tenant resource task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResourceReceipt {
    pub ver: u32,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub request_sha256: String,
    pub deployment_id: String,
    pub tenant_id: String,
    pub capability_jti: String,
    pub capability_sha256: String,
    pub actor: Actor,
    pub change_set_id: String,
    /// SHA-256 of the external raw Apply-manifest bytes echoed from the task.
    pub change_set_sha256: String,
    pub operation: TenantResourceOperation,
    pub expected_revision: u64,
    pub revision: u64,
    pub outcome: TenantResourceOutcome,
    pub resources: Vec<TenantResourceIdentity>,
    /// Apply-only public identities used by CTL applicant/client wiring.
    /// Enumerate, Revoke, and Failed receipts must leave this empty.
    pub resource_mappings: Vec<TenantResourceMapping>,
    /// Baseline manifest echoed from the task/capability fence.
    pub baseline_manifest_sha256: String,
    /// Canonical digest of the complete final active identity set echoed from
    /// the task.  Apply and Revoke may differ from the baseline; Enumerate must
    /// equal it.
    pub resource_manifest_sha256: String,
    pub started_at: i64,
    pub completed_at: i64,
    pub exp: i64,
    pub audit_sequence: u64,
    pub audit_previous_sha256: String,
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
    /// Read-only compatibility for historic signed audit records.
    ConformanceMatrix {
        summary: ConformanceMatrixSummary,
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
    /// Read-only compatibility for historic signed audit records.
    ConformanceLeaseCreated {
        lease: ConformanceLeaseSummary,
    },
    /// Read-only compatibility for historic signed audit records.
    ConformanceOnboardingApplied {
        onboarding: ConformanceOnboardingSummary,
    },
    /// Read-only compatibility for historic signed audit records.
    ConformanceLeaseList {
        leases: Vec<ConformanceLeaseSummary>,
    },
    /// Read-only compatibility for historic signed audit records.
    ConformanceLeaseRevoked {
        lease_id: String,
        deactivated_clients: u64,
    },
    /// Read-only compatibility for historic signed audit records.
    ConformanceLeaseCleaned {
        cleaned_leases: u64,
        deleted_clients: u64,
        #[serde(default)]
        deleted_credential_datasets: u64,
    },
}

/// Historic lease metadata retained only to deserialize and authenticate
/// already-signed conformance receipts.
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
pub struct ConformanceOnboardingSummary {
    pub lease_id: String,
    pub request_jti: String,
    pub applicant_id: String,
    pub client_mappings: Vec<ConformanceClientIdMapping>,
    pub client_count: u32,
    pub matrix_sha256: String,
    pub bundle_sha256: String,
    pub expires_at: i64,
    pub idempotent_replay: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceClientIdMapping {
    pub logical_client_id: String,
    pub client_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceMatrixSummary {
    pub schema: u32,
    pub sha256: String,
    pub size: u64,
    pub group_count: u32,
    pub plan_count: u32,
    pub source_release: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalConfigManifest {
    pub version: u32,
    pub entries: BTreeMap<String, String>,
}
