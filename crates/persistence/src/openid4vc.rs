use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_openid4vci::{CredentialStoreError, CredentialStorePort, StoredCredentialOffer};
use nazo_openid4vp::{PresentationStoreError, PresentationStorePort};
use serde_json::Value;
use uuid::Uuid;

/// Complete OpenID4VCI issuance store used by the application.
///
/// All nonce, deferred-credential and response transitions remain defined by
/// [`CredentialStorePort`]. Offer creation is kept on the same adapter so the
/// application never needs a database handle or backend-specific repository.
pub trait Openid4vciStore: CredentialStorePort {
    fn insert_offer<'a>(
        &'a self,
        offer: &'a StoredCredentialOffer,
        issuer_state_hash: Option<&'a str>,
        pre_authorized_code_hash: Option<&'a str>,
        tx_code_hash: Option<&'a str>,
    ) -> BoxFuture<'a, Result<(), CredentialStoreError>>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedCredentialDataset {
    pub claims: Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedCredentialDatasetWrite {
    pub tenant_id: Uuid,
    pub actor_user_id: Uuid,
    pub subject_id: Uuid,
    pub credential_configuration_id: String,
    pub claims: Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

/// Encrypted issuer dataset capability. Encryption, actor authorization and
/// the corresponding audit record are adapter-owned implementation details.
pub trait Openid4vciDatasetStore: Send + Sync {
    fn dataset<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Value>, CredentialStoreError>>;

    fn managed_dataset<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<ManagedCredentialDataset>, CredentialStoreError>>;

    fn upsert_managed_dataset(
        &self,
        write: ManagedCredentialDatasetWrite,
    ) -> BoxFuture<'_, Result<bool, CredentialStoreError>>;

    fn delete_managed_dataset<'a>(
        &'a self,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &'a str,
    ) -> BoxFuture<'a, Result<bool, CredentialStoreError>>;
}

/// Minimal subject projection required before creating offers or datasets.
pub trait Openid4vcSubjectStore: Send + Sync {
    fn is_active(
        &self,
        tenant_id: nazo_identity::TenantId,
        subject_id: nazo_identity::UserId,
    ) -> BoxFuture<'_, Result<bool, RepositoryError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewOpenid4vpVerificationAttachment {
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: String,
    pub intent_jws: String,
    pub presentation_request_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewOpenid4vpVerificationEvidence {
    pub transaction_id: Uuid,
    pub receipt_id: Uuid,
    pub issuance_request_jti: String,
    pub capability: String,
    pub capability_sha256: String,
    pub receipt_jws: String,
    pub expected_intent_jws: String,
    pub expected_context_sha256: String,
    pub expected_presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    pub issued_at: DateTime<Utc>,
    pub requested_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOpenid4vpVerificationAttachment {
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: String,
    pub intent_jws: String,
    pub presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Openid4vpVerificationAttachmentState {
    Pending {
        transaction_id: Uuid,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    Attached(Box<StoredOpenid4vpVerificationAttachment>),
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOpenid4vpVerificationEvidence {
    pub receipt_id: Uuid,
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub capability_sha256: String,
    pub issuance_request_jti: String,
    pub intent_jws: String,
    pub receipt_jws: String,
    pub presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    pub completed_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOpenid4vpVerificationEvidence {
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: String,
    pub intent_jws: String,
    pub presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    pub completed_at: DateTime<Utc>,
    pub issuance_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedOpenid4vpVerificationEvidence {
    pub evidence: StoredOpenid4vpVerificationEvidence,
    pub capability: String,
}

/// OpenID4VP transaction and verification-evidence capability. Evidence
/// attachment, encrypted capability issuance and idempotent receipt replay are
/// deliberately adapter-owned operations.
pub trait Openid4vpStore: PresentationStorePort {
    fn verification_attachment_state(
        &self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<Option<Openid4vpVerificationAttachmentState>, PresentationStoreError>>;

    fn attach_verification_evidence(
        &self,
        transaction_id: Uuid,
        evidence: NewOpenid4vpVerificationAttachment,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<Option<StoredOpenid4vpVerificationAttachment>, PresentationStoreError>>;

    fn verification_attachment_for_completion(
        &self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<Option<StoredOpenid4vpVerificationAttachment>, PresentationStoreError>>;

    fn prepare_verification_evidence(
        &self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<Option<PreparedOpenid4vpVerificationEvidence>, PresentationStoreError>>;

    fn issue_verification_evidence(
        &self,
        issuance: NewOpenid4vpVerificationEvidence,
    ) -> BoxFuture<'_, Result<Option<IssuedOpenid4vpVerificationEvidence>, PresentationStoreError>>;

    fn verification_evidence_by_capability_sha256<'a>(
        &'a self,
        capability_sha256: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Option<StoredOpenid4vpVerificationEvidence>, PresentationStoreError>>;
}
