use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_digital_credentials::CredentialFormat;
use serde_json::Value;
use uuid::Uuid;

use crate::{CredentialIdentifier, CredentialOfferGrants, NotificationEvent};

pub type CredentialStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait AuthorizationOfferPort: Send + Sync {
    fn resolve_authorization_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        issuer_state_hash: &'a str,
        subject_id: Uuid,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceRecord {
    pub nonce_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAuthorization {
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub client_id: String,
    pub configuration_ids: Vec<String>,
    pub credential_identifiers: Vec<CredentialIdentifier>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCredentialOffer {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Option<Uuid>,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAccess {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub client_id: String,
    pub configuration_ids: Vec<String>,
    pub credential_identifiers: Vec<CredentialIdentifier>,
    pub dpop_jkt: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeferredCredential {
    pub id: Uuid,
    pub transaction_hash: String,
    pub access: CredentialAccess,
    pub configuration_id: String,
    pub format: CredentialFormat,
    pub holder_bindings: Vec<Value>,
    pub payload_ciphertext: Vec<u8>,
    pub ready_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A deferred transaction that is leased to one issuance attempt.
///
/// The lease is deliberately separate from `consumed_at`: signing and response
/// persistence can fail after a transaction has become ready, in which case a
/// later request must be able to retry the same transaction without allowing
/// two concurrent issuers to sign it.
#[derive(Clone, Debug, PartialEq)]
pub struct DeferredCredentialClaim {
    pub credential: DeferredCredential,
    pub claim_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceNotification {
    pub notification_id: String,
    pub token_id: Uuid,
    pub event: NotificationEvent,
    pub description: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationHandle {
    pub notification_id: String,
    pub token_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialResponseEncoding {
    Json,
    Jwt,
}

/// The exact wire response committed with an issuance state transition. The
/// repository encrypts `body` at rest; the digest and issuance id prevent a
/// different request from retrieving a previously committed response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCredentialResponse {
    pub issuance_id: Uuid,
    pub token_id: Uuid,
    pub request_digest: String,
    pub body: Vec<u8>,
    pub encoding: CredentialResponseEncoding,
    pub status: u16,
    pub dpop_nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
}

pub trait CredentialStorePort: Send + Sync {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn offer<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>;

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>;

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    /// Legacy one-step operation retained for older adapters. New issuance
    /// code must use claim/finalize/release so transient failures are retryable.
    fn consume_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    /// Lease a nonce for one issuance attempt. A lease may be reclaimed after
    /// its expiry; finalization is the only transition that makes the nonce
    /// permanently single-use.
    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    /// Atomically persist the notification handle and finalize the nonce.
    /// Implementations must own this transition in one transaction; composing
    /// the two lower-level methods is not safe because a process failure could
    /// leave a notification without a consumed nonce (or vice versa).
    fn finalize_nonce_with_notification<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>;

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let _ = (nonce_hash, claim_id, handle, response, now);
            Err(CredentialStoreError::Unavailable)
        })
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let _ = (handle, response, now);
            Err(CredentialStoreError::Unavailable)
        })
    }

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>>;

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    /// Persist a deferred transaction and finalize its proof nonce as one
    /// state transition. Implementations must own this transition in one
    /// transaction rather than composing the lower-level operations.
    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let _ = (credential, nonce_hash, claim_id, response, now);
            Err(CredentialStoreError::Unavailable)
        })
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let _ = (credential, response, now);
            Err(CredentialStoreError::Unavailable)
        })
    }

    /// Legacy one-step operation retained for older adapters. New deferred
    /// issuance code must use claim/finalize/release around signing.
    fn consume_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>>;

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>;

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    /// Atomically persist the notification handle and finalize a deferred
    /// transaction. The store owns this transition so a retry can never
    /// observe a notification without the corresponding consumed transaction.
    fn finalize_deferred_with_notification<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let _ = (transaction_hash, token_id, claim_id, handle, response, now);
            Err(CredentialStoreError::Unavailable)
        })
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialStoreError {
    #[error("credential store is unavailable")]
    Unavailable,
    #[error("credential store rejected an invalid transition")]
    InvalidTransition,
}
