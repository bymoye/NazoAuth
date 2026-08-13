use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::{
    CredentialStoreError, CredentialStoreFuture, DeferredCredential, DeferredCredentialClaim,
    StoredCredentialResponse,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::{
    AccessRow, DeferredRow, NewIssuanceResponse, insert_issuance_response, protect_payload,
    response_encoding_name, unprotect_payload,
};

impl Openid4vciRepository {
    pub(super) fn deferred_store<'a>(
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

    pub(super) fn deferred_store_with_response<'a>(
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

    pub(super) fn deferred_store_and_finalize_nonce<'a>(
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

    pub(super) fn deferred_store_and_finalize_nonce_with_response<'a>(
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

    pub(super) fn deferred_claim_ready<'a>(
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

    pub(super) fn deferred_finalize<'a>(
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

    pub(super) fn deferred_release<'a>(
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

    pub(super) fn deferred_consume_ready<'a>(
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
}
