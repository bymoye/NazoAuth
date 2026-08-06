use std::str::FromStr;

use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::{
    CredentialAccess, CredentialAuthorization, CredentialResponseEncoding, CredentialStoreError,
    CredentialStoreFuture, CredentialStorePort, DeferredCredential, DeferredCredentialClaim,
    IssuanceNotification, NonceRecord, NotificationHandle, StoredCredentialOffer,
    StoredCredentialResponse,
};
use uuid::Uuid;

use super::Openid4vciRepository;
use super::crypto::{protect_payload, unprotect_payload};
use super::offer::{OfferRow, PreAuthorizedOfferRow, tx_code_matches};
impl CredentialStorePort for Openid4vciRepository {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_access_grants \
                 (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,dpop_jkt,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                 ON CONFLICT (token_hash) DO UPDATE SET \
                   credential_configuration_ids = EXCLUDED.credential_configuration_ids, \
                   credential_identifiers = EXCLUDED.credential_identifiers, \
                   dpop_jkt = EXCLUDED.dpop_jkt, expires_at = EXCLUDED.expires_at \
                 WHERE openid4vci_access_grants.token_id = EXCLUDED.token_id \
                   AND openid4vci_access_grants.tenant_id = EXCLUDED.tenant_id \
                   AND openid4vci_access_grants.subject_id = EXCLUDED.subject_id \
                   AND openid4vci_access_grants.client_id = EXCLUDED.client_id",
            )
            .bind::<sql_types::Uuid, _>(access.token_id)
            .bind::<sql_types::Text, _>(token_hash)
            .bind::<sql_types::Uuid, _>(access.tenant_id)
            .bind::<sql_types::Uuid, _>(access.subject_id)
            .bind::<sql_types::Text, _>(&access.client_id)
            .bind::<sql_types::Jsonb, _>(serde_json::json!(access.configuration_ids))
            .bind::<sql_types::Jsonb, _>(serde_json::json!(access.credential_identifiers))
            .bind::<sql_types::Nullable<sql_types::Text>, _>(access.dpop_jkt.as_deref())
            .bind::<sql_types::Timestamptz, _>(access.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn find_response<'a>(
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

    fn offer<'a>(
        &'a self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT id,tenant_id,subject_id,credential_configuration_ids,grants_ciphertext,expires_at \
                 FROM openid4vci_offers WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Uuid, _>(id)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<OfferRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(|row| row.into_domain(&self.data_key)).transpose()
        })
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection.transaction::<Option<CredentialAuthorization>, diesel::result::Error, _>(async move |connection| {
                let row = sql_query(
                    "SELECT id,tenant_id,subject_id,credential_configuration_ids,tx_code_hash,expires_at \
                     FROM openid4vci_offers WHERE pre_authorized_code_hash = $1 \
                       AND consumed_at IS NULL AND expires_at > $2 FOR UPDATE",
                )
                .bind::<sql_types::Text, _>(code_hash)
                .bind::<sql_types::Timestamptz, _>(now)
                .get_result::<PreAuthorizedOfferRow>(connection)
                .await
                .optional()?;
                let Some(row) = row else { return Ok(None); };
                if !tx_code_matches(row.tx_code_hash.as_deref(), tx_code) { return Ok(None); }
                let Some(subject_id) = row.subject_id else { return Ok(None); };
                let configuration_ids = serde_json::from_value(row.credential_configuration_ids)
                    .map_err(decode_error)?;
                let consumed = sql_query(
                    "UPDATE openid4vci_offers SET consumed_at = GREATEST($2, created_at) \
                     WHERE id = $1 AND consumed_at IS NULL",
                )
                .bind::<sql_types::Uuid, _>(row.id)
                .bind::<sql_types::Timestamptz, _>(now)
                .execute(connection)
                .await?;
                if consumed != 1 {
                    return Ok(None);
                }
                Ok(Some(CredentialAuthorization {
                    tenant_id: row.tenant_id,
                    subject_id,
                    client_id: client_id.to_owned(),
                    configuration_ids,
                    credential_identifiers: Vec::new(),
                    expires_at: (now + chrono::Duration::minutes(10)).min(row.expires_at),
                }))
            }).await.map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_nonces (nonce_hash, expires_at) VALUES ($1, $2) \
                 ON CONFLICT (nonce_hash) DO NOTHING",
            )
            .bind::<sql_types::Text, _>(&nonce.nonce_hash)
            .bind::<sql_types::Timestamptz, _>(nonce.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn consume_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET consumed_at = GREATEST($2, created_at) \
                 WHERE nonce_hash = $1 AND consumed_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let claim_expires_at = now + chrono::Duration::minutes(5);
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET claim_id = $2, claim_expires_at = $3 \
                 WHERE nonce_hash = $1 AND consumed_at IS NULL AND expires_at > $4 \
                   AND (claim_id IS NULL OR claim_expires_at <= $4)",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Text, _>(claim_id)
            .bind::<sql_types::Timestamptz, _>(claim_expires_at)
            .bind::<sql_types::Timestamptz, _>(now)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET consumed_at = GREATEST($3, created_at), claim_id = NULL, claim_expires_at = NULL \
                 WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL AND expires_at > $3",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Text, _>(claim_id)
            .bind::<sql_types::Timestamptz, _>(now)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_nonces SET claim_id = NULL, claim_expires_at = NULL \
                 WHERE nonce_hash = $1 AND claim_id = $2 AND consumed_at IS NULL",
            )
            .bind::<sql_types::Text, _>(nonce_hash)
            .bind::<sql_types::Text, _>(claim_id)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn finalize_nonce_with_notification<'a>(
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

    fn finalize_nonce_with_notification_and_response<'a>(
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

    fn store_response_with_notification<'a>(
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

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT token_id, tenant_id, subject_id, client_id, credential_configuration_ids, \
                 credential_identifiers, dpop_jkt, expires_at FROM openid4vci_access_grants \
                 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Text, _>(token_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<AccessRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(TryInto::try_into)
                .transpose()
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &credential.payload_ciphertext,
            )?;
            sql_query(
                "INSERT INTO openid4vci_deferred_transactions \
                 (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                  holder_bindings, payload_ciphertext, ready_at, expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind::<sql_types::Uuid, _>(credential.id)
            .bind::<sql_types::Text, _>(&credential.transaction_hash)
            .bind::<sql_types::Uuid, _>(credential.access.token_id)
            .bind::<sql_types::Text, _>(&credential.configuration_id)
            .bind::<sql_types::Text, _>(credential.format.as_str())
            .bind::<sql_types::Jsonb, _>(serde_json::Value::Array(
                credential.holder_bindings.clone(),
            ))
            .bind::<sql_types::Binary, _>(protected_payload)
            .bind::<sql_types::Timestamptz, _>(credential.ready_at)
            .bind::<sql_types::Timestamptz, _>(credential.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &credential.payload_ciphertext,
            )?;
            let response_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let id = credential.id;
            let transaction_hash = credential.transaction_hash.clone();
            let token_id = credential.access.token_id;
            let configuration_id = credential.configuration_id.clone();
            let format = credential.format.as_str().to_owned();
            let holder_bindings = serde_json::Value::Array(credential.holder_bindings.clone());
            let ready_at = credential.ready_at;
            let expires_at = credential.expires_at;
            let issuance_id = response.issuance_id;
            let response_token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let dpop_nonce = response.dpop_nonce.clone();
            let response_expires_at = response.expires_at;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_deferred_transactions \
                         (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                          holder_bindings, payload_ciphertext, ready_at, expires_at) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    )
                    .bind::<sql_types::Uuid, _>(id)
                    .bind::<sql_types::Text, _>(&transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(&configuration_id)
                    .bind::<sql_types::Text, _>(&format)
                    .bind::<sql_types::Jsonb, _>(holder_bindings)
                    .bind::<sql_types::Binary, _>(protected_payload)
                    .bind::<sql_types::Timestamptz, _>(ready_at)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .execute(connection)
                    .await?;
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            issuance_id,
                            token_id: response_token_id,
                            request_digest: &request_digest,
                            body_ciphertext: response_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at: response_expires_at,
                        },
                    )
                    .await?;
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &credential.payload_ciphertext,
            )?;
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let id = credential.id;
            let transaction_hash = credential.transaction_hash.clone();
            let token_id = credential.access.token_id;
            let configuration_id = credential.configuration_id.clone();
            let format = credential.format.as_str().to_owned();
            let holder_bindings = serde_json::Value::Array(credential.holder_bindings.clone());
            let ready_at = credential.ready_at;
            let expires_at = credential.expires_at;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_deferred_transactions \
                         (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                          holder_bindings, payload_ciphertext, ready_at, expires_at) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    )
                    .bind::<sql_types::Uuid, _>(id)
                    .bind::<sql_types::Text, _>(&transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(&configuration_id)
                    .bind::<sql_types::Text, _>(&format)
                    .bind::<sql_types::Jsonb, _>(holder_bindings)
                    .bind::<sql_types::Binary, _>(protected_payload)
                    .bind::<sql_types::Timestamptz, _>(ready_at)
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
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let protected_payload = protect_payload(
                &self.data_key,
                credential.id,
                &credential.payload_ciphertext,
            )?;
            let response_ciphertext =
                protect_payload(&self.data_key, response.issuance_id, &response.body)?;
            let encoding = response_encoding_name(&response.encoding);
            let status = i16::try_from(response.status)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let id = credential.id;
            let transaction_hash = credential.transaction_hash.clone();
            let token_id = credential.access.token_id;
            let configuration_id = credential.configuration_id.clone();
            let format = credential.format.as_str().to_owned();
            let holder_bindings = serde_json::Value::Array(credential.holder_bindings.clone());
            let ready_at = credential.ready_at;
            let expires_at = credential.expires_at;
            let issuance_id = response.issuance_id;
            let response_token_id = response.token_id;
            let request_digest = response.request_digest.clone();
            let dpop_nonce = response.dpop_nonce.clone();
            let response_expires_at = response.expires_at;
            connection
                .transaction::<(), diesel::result::Error, _>(async move |connection| {
                    sql_query(
                        "INSERT INTO openid4vci_deferred_transactions \
                         (id, transaction_hash, token_id, credential_configuration_id, credential_format, \
                          holder_bindings, payload_ciphertext, ready_at, expires_at) \
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    )
                    .bind::<sql_types::Uuid, _>(id)
                    .bind::<sql_types::Text, _>(&transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Text, _>(&configuration_id)
                    .bind::<sql_types::Text, _>(&format)
                    .bind::<sql_types::Jsonb, _>(holder_bindings)
                    .bind::<sql_types::Binary, _>(protected_payload)
                    .bind::<sql_types::Timestamptz, _>(ready_at)
                    .bind::<sql_types::Timestamptz, _>(expires_at)
                    .execute(connection)
                    .await?;
                    insert_issuance_response(
                        connection,
                        NewIssuanceResponse {
                            issuance_id,
                            token_id: response_token_id,
                            request_digest: &request_digest,
                            body_ciphertext: response_ciphertext,
                            encoding,
                            status,
                            dpop_nonce: dpop_nonce.as_deref(),
                            expires_at: response_expires_at,
                        },
                    )
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
                    Ok(())
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let claim_expires_at = now + chrono::Duration::minutes(5);
            let claim_id_owned = claim_id.to_owned();
            connection
                .transaction::<Option<DeferredCredentialClaim>, diesel::result::Error, _>(
                    async move |connection| {
                        let row = sql_query(
                            "UPDATE openid4vci_deferred_transactions \
                             SET claim_id = $3, claim_expires_at = $4 \
                             WHERE transaction_hash = $1 AND token_id = $2 AND consumed_at IS NULL \
                               AND ready_at <= $5 AND expires_at > $5 \
                               AND (claim_id IS NULL OR claim_expires_at <= $5) \
                             RETURNING id, transaction_hash, token_id, credential_configuration_id, \
                               credential_format, holder_bindings, payload_ciphertext, ready_at, expires_at",
                        )
                        .bind::<sql_types::Text, _>(transaction_hash)
                        .bind::<sql_types::Uuid, _>(token_id)
                        .bind::<sql_types::Text, _>(claim_id)
                        .bind::<sql_types::Timestamptz, _>(claim_expires_at)
                        .bind::<sql_types::Timestamptz, _>(now)
                        .get_result::<DeferredRow>(connection)
                        .await
                        .optional()?;
                        let Some(row) = row else { return Ok(None); };
                        let access = sql_query(
                            "SELECT token_id, tenant_id, subject_id, client_id, credential_configuration_ids, \
                             credential_identifiers, dpop_jkt, expires_at FROM openid4vci_access_grants \
                             WHERE token_id = $1",
                        )
                        .bind::<sql_types::Uuid, _>(token_id)
                        .get_result::<AccessRow>(connection)
                        .await?;
                        let mut deferred = row.into_domain(access.try_into()? )?;
                        deferred.payload_ciphertext = unprotect_payload(
                            &self.data_key,
                            deferred.id,
                            &deferred.payload_ciphertext,
                        )?;
                        Ok(Some(DeferredCredentialClaim {
                            credential: deferred,
                            claim_id: claim_id_owned,
                        }))
                    },
                )
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
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
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        _now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let changed = sql_query(
                "UPDATE openid4vci_deferred_transactions \
                 SET claim_id = NULL, claim_expires_at = NULL \
                 WHERE transaction_hash = $1 AND token_id = $2 AND claim_id = $3 \
                   AND consumed_at IS NULL",
            )
            .bind::<sql_types::Text, _>(transaction_hash)
            .bind::<sql_types::Uuid, _>(token_id)
            .bind::<sql_types::Text, _>(claim_id)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn finalize_deferred_with_notification<'a>(
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

    fn consume_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            connection
                .transaction::<Option<DeferredCredential>, diesel::result::Error, _>(async move |connection| {
                    let row = sql_query(
                        "UPDATE openid4vci_deferred_transactions SET consumed_at = GREATEST($3, ready_at) \
                         WHERE transaction_hash = $1 AND token_id = $2 AND consumed_at IS NULL \
                           AND ready_at <= $3 AND expires_at > $3 \
                         RETURNING id, transaction_hash, token_id, credential_configuration_id, \
                           credential_format, holder_bindings, payload_ciphertext, ready_at, expires_at",
                    )
                    .bind::<sql_types::Text, _>(transaction_hash)
                    .bind::<sql_types::Uuid, _>(token_id)
                    .bind::<sql_types::Timestamptz, _>(now)
                    .get_result::<DeferredRow>(connection)
                    .await
                    .optional()?;
                    let Some(row) = row else { return Ok(None); };
                    let access = sql_query(
                        "SELECT token_id, tenant_id, subject_id, client_id, credential_configuration_ids, \
                         credential_identifiers, dpop_jkt, expires_at FROM openid4vci_access_grants \
                         WHERE token_id = $1",
                    )
                    .bind::<sql_types::Uuid, _>(token_id)
                    .get_result::<AccessRow>(connection)
                    .await?;
                    let mut deferred = row.into_domain(access.try_into()? )?;
                    deferred.payload_ciphertext = unprotect_payload(
                        &self.data_key,
                        deferred.id,
                        &deferred.payload_ciphertext,
                    )?;
                    Ok(Some(deferred))
                })
                .await
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn record_notification<'a>(
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

    fn issue_notification_handle<'a>(
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
#[derive(QueryableByName)]
struct AccessRow {
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    subject_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_id: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_identifiers: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    dpop_jkt: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

struct NewIssuanceResponse<'a> {
    issuance_id: Uuid,
    token_id: Uuid,
    request_digest: &'a str,
    body_ciphertext: Vec<u8>,
    encoding: &'a str,
    status: i16,
    dpop_nonce: Option<&'a str>,
    expires_at: DateTime<Utc>,
}

async fn insert_issuance_response(
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

fn response_encoding_name(encoding: &CredentialResponseEncoding) -> &'static str {
    match encoding {
        CredentialResponseEncoding::Json => "json",
        CredentialResponseEncoding::Jwt => "jwt",
    }
}

#[derive(QueryableByName)]
struct DeferredRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    transaction_hash: String,
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    credential_configuration_id: String,
    #[diesel(sql_type = sql_types::Text)]
    credential_format: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    holder_bindings: serde_json::Value,
    #[diesel(sql_type = sql_types::Binary)]
    payload_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    ready_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
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
    fn into_domain(
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

#[derive(QueryableByName)]
struct IssuanceResponseRow {
    #[diesel(sql_type = sql_types::Uuid)]
    issuance_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    request_digest: String,
    #[diesel(sql_type = sql_types::Binary)]
    body_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Text)]
    encoding: String,
    #[diesel(sql_type = sql_types::SmallInt)]
    status: i16,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    dpop_nonce: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}
fn notification_event(event: &nazo_openid4vci::NotificationEvent) -> &'static str {
    match event {
        nazo_openid4vci::NotificationEvent::CredentialAccepted => "credential_accepted",
        nazo_openid4vci::NotificationEvent::CredentialFailure => "credential_failure",
        nazo_openid4vci::NotificationEvent::CredentialDeleted => "credential_deleted",
    }
}

fn decode_error(error: serde_json::Error) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(error))
}
