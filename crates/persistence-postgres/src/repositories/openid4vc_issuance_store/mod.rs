use std::str::FromStr;

use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::{
    CredentialAccess, CredentialAuthorization, CredentialResponseEncoding, CredentialStoreError,
    CredentialStoreFuture, CredentialStorePort, DeferredCredential, DeferredCredentialClaim,
    IssuanceNotification, NonceRecord, NotificationHandle, StoredCredentialOffer,
    StoredCredentialResponse,
};
use uuid::Uuid;

use super::Openid4vciRepository;

pub(super) use super::crypto::{protect_payload, unprotect_payload};

mod access;
mod deferred;
mod nonce;
mod notification;
mod offer;

/// The repository remains the single owner of the pool and encryption key.
///
/// Lifecycle-specific SQL lives in the child modules.  This impl is the only
/// `CredentialStorePort` boundary; the child modules expose only inherent
/// methods so no lifecycle can accidentally construct or own a second store.
impl CredentialStorePort for Openid4vciRepository {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.access_upsert(token_hash, access)
    }

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        self.notification_find_response(issuance_id, token_id, request_digest, now)
    }

    fn offer<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        self.offer_lookup(tenant_id, id, now)
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        self.offer_consume_pre_authorized(tenant_id, code_hash, tx_code, client_id, now)
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.nonce_issue(nonce)
    }

    fn consume_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.nonce_consume(nonce_hash, now)
    }

    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.nonce_claim(nonce_hash, claim_id, now)
    }

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.nonce_finalize(nonce_hash, claim_id, now)
    }

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.nonce_release(nonce_hash, claim_id, now)
    }

    fn finalize_nonce_with_notification<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.notification_finalize_nonce(nonce_hash, claim_id, handle, now)
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.notification_finalize_nonce_with_response(nonce_hash, claim_id, handle, response, now)
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.notification_store_response(handle, response, now)
    }

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        self.access_resolve(token_hash, now)
    }

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.deferred_store(credential)
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.deferred_store_with_response(credential, response, now)
    }

    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.deferred_store_and_finalize_nonce(credential, nonce_hash, claim_id, now)
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.deferred_store_and_finalize_nonce_with_response(
            credential, nonce_hash, claim_id, response, now,
        )
    }

    fn consume_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>> {
        self.deferred_consume_ready(transaction_hash, token_id, now)
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        self.deferred_claim_ready(transaction_hash, token_id, claim_id, now)
    }

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.deferred_finalize(transaction_hash, token_id, claim_id, now)
    }

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.deferred_release(transaction_hash, token_id, claim_id, now)
    }

    fn finalize_deferred_with_notification<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.notification_finalize_deferred(transaction_hash, token_id, claim_id, handle, now)
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.notification_finalize_deferred_with_response(
            transaction_hash,
            token_id,
            claim_id,
            handle,
            response,
            now,
        )
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.notification_record(notification)
    }

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.notification_issue_handle(handle)
    }
}

#[derive(QueryableByName)]
pub(super) struct AccessRow {
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) token_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) subject_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    pub(super) client_id: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    pub(super) credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    pub(super) credential_identifiers: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    pub(super) dpop_jkt: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub(super) expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
pub(super) struct DeferredRow {
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    pub(super) transaction_hash: String,
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) token_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    pub(super) credential_configuration_id: String,
    #[diesel(sql_type = sql_types::Text)]
    pub(super) credential_format: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    pub(super) holder_bindings: serde_json::Value,
    #[diesel(sql_type = sql_types::Binary)]
    pub(super) payload_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub(super) ready_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub(super) expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
pub(super) struct IssuanceResponseRow {
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) issuance_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) token_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    pub(super) request_digest: String,
    #[diesel(sql_type = sql_types::Binary)]
    pub(super) body_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Text)]
    pub(super) encoding: String,
    #[diesel(sql_type = sql_types::SmallInt)]
    pub(super) status: i16,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    pub(super) dpop_nonce: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) struct NewIssuanceResponse<'a> {
    pub(super) issuance_id: Uuid,
    pub(super) token_id: Uuid,
    pub(super) request_digest: &'a str,
    pub(super) body_ciphertext: Vec<u8>,
    pub(super) encoding: &'a str,
    pub(super) status: i16,
    pub(super) dpop_nonce: Option<&'a str>,
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) async fn insert_issuance_response(
    connection: &mut AsyncPgConnection,
    response: NewIssuanceResponse<'_>,
) -> Result<usize, diesel::result::Error> {
    sql_query(
        "INSERT INTO openid4vci_issuance_responses \
         (issuance_id, token_id, request_digest, body_ciphertext, encoding, status, dpop_nonce, expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind::<sql_types::Uuid, _>(response.issuance_id)
    .bind::<sql_types::Uuid, _>(response.token_id)
    .bind::<sql_types::Text, _>(response.request_digest)
    .bind::<sql_types::Binary, _>(response.body_ciphertext)
    .bind::<sql_types::Text, _>(response.encoding)
    .bind::<sql_types::SmallInt, _>(response.status)
    .bind::<sql_types::Nullable<sql_types::Text>, _>(response.dpop_nonce)
    .bind::<sql_types::Timestamptz, _>(response.expires_at)
    .execute(connection)
    .await
}

pub(super) fn response_encoding_name(encoding: &CredentialResponseEncoding) -> &'static str {
    match encoding {
        CredentialResponseEncoding::Json => "json",
        CredentialResponseEncoding::Jwt => "jwt",
    }
}

impl TryFrom<AccessRow> for CredentialAccess {
    type Error = diesel::result::Error;

    fn try_from(row: AccessRow) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: row.token_id,
            tenant_id: row.tenant_id,
            subject_id: row.subject_id,
            client_id: row.client_id,
            configuration_ids: serde_json::from_value(row.credential_configuration_ids)
                .map_err(decode_error)?,
            credential_identifiers: serde_json::from_value(row.credential_identifiers)
                .map_err(decode_error)?,
            dpop_jkt: row.dpop_jkt,
            expires_at: row.expires_at,
        })
    }
}

impl DeferredRow {
    pub(super) fn into_domain(
        self,
        access: CredentialAccess,
    ) -> Result<DeferredCredential, diesel::result::Error> {
        if self.token_id != access.token_id {
            return Err(diesel::result::Error::NotFound);
        }
        Ok(DeferredCredential {
            id: self.id,
            transaction_hash: self.transaction_hash,
            access,
            configuration_id: self.credential_configuration_id,
            format: CredentialFormat::from_str(&self.credential_format).map_err(|error| {
                decode_error(serde_json::Error::io(std::io::Error::other(error)))
            })?,
            holder_bindings: serde_json::from_value(self.holder_bindings).map_err(decode_error)?,
            payload_ciphertext: self.payload_ciphertext,
            ready_at: self.ready_at,
            expires_at: self.expires_at,
        })
    }
}

pub(super) fn notification_event(event: &nazo_openid4vci::NotificationEvent) -> &'static str {
    match event {
        nazo_openid4vci::NotificationEvent::CredentialAccepted => "credential_accepted",
        nazo_openid4vci::NotificationEvent::CredentialFailure => "credential_failure",
        nazo_openid4vci::NotificationEvent::CredentialDeleted => "credential_deleted",
    }
}

pub(super) fn decode_error(error: serde_json::Error) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(error))
}
