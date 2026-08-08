use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vci::{
    CredentialAuthorization, CredentialStoreError, CredentialStoreFuture, StoredCredentialOffer,
};
use uuid::Uuid;

use super::super::Openid4vciRepository;
use super::super::offer::{OfferRow, PreAuthorizedOfferRow, tx_code_matches};
use super::decode_error;

impl Openid4vciRepository {
    pub(super) fn offer_lookup<'a>(
        &'a self,
        tenant_id: Uuid,
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
                 FROM openid4vci_offers WHERE tenant_id = $1 AND id = $2 \
                   AND consumed_at IS NULL AND expires_at > $3",
            )
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Uuid, _>(id)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<OfferRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(|row| row.into_domain(&self.data_key)).transpose()
        })
    }

    pub(super) fn offer_consume_pre_authorized<'a>(
        &'a self,
        tenant_id: Uuid,
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
                     FROM openid4vci_offers WHERE tenant_id = $1 \
                       AND pre_authorized_code_hash = $2 \
                       AND consumed_at IS NULL AND expires_at > $3 FOR UPDATE",
                )
                .bind::<sql_types::Uuid, _>(tenant_id)
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
                    "UPDATE openid4vci_offers SET consumed_at = GREATEST($3, created_at) \
                     WHERE tenant_id = $1 AND id = $2 AND consumed_at IS NULL",
                )
                .bind::<sql_types::Uuid, _>(tenant_id)
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
}
