use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::{
    CredentialResponseEncoding, CredentialStoreError, CredentialStoreFuture, IssuanceNotification,
    NotificationHandle, StoredCredentialResponse,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::{
    IssuanceResponseRow, NewIssuanceResponse, insert_issuance_response, notification_event,
    protect_payload, response_encoding_name, unprotect_payload,
};

impl Openid4vciRepository {
    pub(super) fn notification_find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT issuance_id, token_id, request_digest, body_ciphertext, encoding, \
                        status, dpop_nonce, expires_at \
                 FROM openid4vci_issuance_responses \
                 WHERE issuance_id = $1 AND token_id = $2 AND request_digest = $3 \
                   AND expires_at > $4",
            )
            .bind::<sql_types::Uuid, _>(issuance_id)
            .bind::<sql_types::Uuid, _>(token_id)
            .bind::<sql_types::Text, _>(request_digest)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<IssuanceResponseRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(|row| {
                let encoding = match row.encoding.as_str() {
                    "json" => CredentialResponseEncoding::Json,
                    "jwt" => CredentialResponseEncoding::Jwt,
                    _ => return Err(CredentialStoreError::InvalidTransition),
                };
                let status = u16::try_from(row.status)
                    .map_err(|_| CredentialStoreError::InvalidTransition)?;
                if !matches!(status, 200 | 202) {
                    return Err(CredentialStoreError::InvalidTransition);
                }
                Ok(StoredCredentialResponse {
                    issuance_id: row.issuance_id,
                    token_id: row.token_id,
                    request_digest: row.request_digest,
                    body: unprotect_payload(&self.data_key, row.issuance_id, &row.body_ciphertext)
                        .map_err(|_| CredentialStoreError::InvalidTransition)?,
                    encoding,
                    status,
                    dpop_nonce: row.dpop_nonce,
                    expires_at: row.expires_at,
                })
            })
            .transpose()
        })
    }

    pub(super) fn notification_finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let notification_id = handle.notification_id.clone();
            let token_id = handle.token_id;
            let expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .execute(connection)
                    .await?;
                    let changed = sql_query(
                        "UPDATE openid4vci_nonces SET consumed_at = GREATEST($3, created_at), claim_id = NULL, claim_expires_at = NULL \
                         WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL AND expires_at > $3",
                    )
                    .bind::<sql_types::Text, _>(nonce_hash)
                    .bind::<sql_types::Text, _>(claim_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_nonce_with_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let body_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let issuance_id = response.issuance_id;
            let token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let dpop_nonce = response.dpop_nonce.clone();
            let expires_at = response.expires_at;
            let notification_id = handle.notification_id.clone();
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            issuance_id,
                            token_id,
                            request_digest: &request_digest,
                            body_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at,
                        },
                    )
                    .await?;
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .execute(connection)
                    .await?;
                    let changed = sql_query(
                        "UPDATE openid4vci_nonces SET consumed_at = GREATEST($3, created_at), claim_id = NULL, claim_expires_at = NULL \
                         WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL AND expires_at > $3",
                    )
                    .bind::<sql_types::Text, _>(nonce_hash)
                    .bind::<sql_types::Text, _>(claim_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_store_response<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let body_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let issuance_id = response.issuance_id;
            let token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let dpop_nonce = response.dpop_nonce.clone();
            let expires_at = response.expires_at;
            let notification_id = handle.notification_id.clone();
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            issuance_id,
                            token_id,
                            request_digest: &request_digest,
                            body_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at,
                        },
                    )
                    .await?;
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .execute(connection)
                    .await?;
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let notification_id = handle.notification_id.clone();
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .execute(connection)
                    .await?;
                    let changed = sql_query(
                        "UPDATE openid4vci_deferred_transactions \
                         SET consumed_at = GREATEST($4, ready_at), claim_id = NULL, claim_expires_at = NULL \
                         WHERE transaction_hash = $1 AND token_id = $2 AND claim_id = $3 \
                           AND consumed_at IS NULL AND expires_at > $4",
                    )
                    .bind::<sql_types::Text, _>(transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(claim_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_finalize_deferred_with_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let body_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let issuance_id = response.issuance_id;
            let response_token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let dpop_nonce = response.dpop_nonce.clone();
            let response_expires_at = response.expires_at;
            let notification_id = handle.notification_id.clone();
            let notification_token_id = handle.token_id;
            let notification_expires_at = handle.expires_at;
            connection
                .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            issuance_id,
                            token_id: response_token_id,
                            request_digest: &request_digest,
                            body_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at: response_expires_at,
                        },
                    )
                    .await?;
                    sql_query(
                        "INSERT INTO openid4vci_notifications \
                         (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
                    )
                    .bind::<sql_types::Text, _>(&notification_id)
                    .bind::<sql_types::Uuid, _>(notification_token_id)
                    .bind::<sql_types::Timestamptz, _>(notification_expires_at)
                    .execute(connection)
                    .await?;
                    let changed = sql_query(
                        "UPDATE openid4vci_deferred_transactions \
                         SET consumed_at = GREATEST($4, ready_at), claim_id = NULL, claim_expires_at = NULL \
                         WHERE transaction_hash = $1 AND token_id = $2 AND claim_id = $3 \
                           AND consumed_at IS NULL AND expires_at > $4",
                    )
                    .bind::<sql_types::Text, _>(transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(claim_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .execute(connection)
                    .await?;
                    if changed != 1 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    Ok(true)
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    pub(super) fn notification_record<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_notifications \
                 SET event = $3, description = $4, occurred_at = $5 \
                 WHERE notification_id = $1 AND token_id = $2 AND event IS NULL AND expires_at > $5",
            )
            .bind::<sql_types::Text, _>(&notification.notification_id)
            .bind::<sql_types::Uuid, _>(notification.token_id)
            .bind::<sql_types::Text, _>(notification_event(&notification.event))
            .bind::<sql_types::Nullable<sql_types::Text>, _>(notification.description.as_deref())
            .bind::<sql_types::Timestamptz, _>(notification.occurred_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    pub(super) fn notification_issue_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_notifications \
                 (notification_id, token_id, expires_at) VALUES ($1,$2,$3)",
            )
            .bind::<sql_types::Text, _>(&handle.notification_id)
            .bind::<sql_types::Uuid, _>(handle.token_id)
            .bind::<sql_types::Timestamptz, _>(handle.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }
}
