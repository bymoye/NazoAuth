use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_openid4vci::{CredentialStoreError, CredentialStorePort, StoredCredentialOffer};
use nazo_openid4vp::PresentationStorePort;
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

/// Complete OpenID4VP transaction store used by the application.
pub trait Openid4vpStore: PresentationStorePort {}

impl<T> Openid4vpStore for T where T: PresentationStorePort + ?Sized {}
