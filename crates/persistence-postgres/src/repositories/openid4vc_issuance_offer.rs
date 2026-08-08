use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_openid4vci::{
    AuthorizationOfferPort, CredentialAuthorization, CredentialStoreError, CredentialStoreFuture,
    StoredCredentialOffer,
};
use uuid::Uuid;

use super::Openid4vciRepository;
use super::crypto::{protect_payload, unprotect_payload};

impl Openid4vciRepository {
    pub async fn insert_offer(
        &self,
        offer: &StoredCredentialOffer,
        issuer_state_hash: Option<&str>,
        pre_authorized_code_hash: Option<&str>,
        tx_code_hash: Option<&str>,
    ) -> Result<(), CredentialStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        sql_query(
            "INSERT INTO openid4vci_offers \
             (id,tenant_id,subject_id,credential_configuration_ids,grants_ciphertext,issuer_state_hash,pre_authorized_code_hash,tx_code_hash,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind::<sql_types::Uuid, _>(offer.id)
        .bind::<sql_types::Uuid, _>(offer.tenant_id)
        .bind::<sql_types::Nullable<sql_types::Uuid>, _>(offer.subject_id)
        .bind::<sql_types::Jsonb, _>(serde_json::json!(offer.credential_configuration_ids))
        .bind::<sql_types::Binary, _>(protect_payload(
            &self.data_key,
            offer.id,
            &serde_json::to_vec(&offer.grants).map_err(|_| CredentialStoreError::InvalidTransition)?,
        )?)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(issuer_state_hash)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(pre_authorized_code_hash)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(tx_code_hash)
        .bind::<sql_types::Timestamptz, _>(offer.expires_at)
        .execute(&mut connection)
        .await
        .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(())
    }
}
impl AuthorizationOfferPort for Openid4vciRepository {
    fn resolve_authorization_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        issuer_state_hash: &'a str,
        subject_id: Uuid,
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
            let row = sql_query(
                "SELECT tenant_id,credential_configuration_ids,expires_at \
                 FROM openid4vci_offers WHERE tenant_id = $1 \
                   AND issuer_state_hash = $2 AND subject_id = $3 AND expires_at > $4",
            )
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Text, _>(issuer_state_hash)
            .bind::<sql_types::Uuid, _>(subject_id)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<AuthorizationOfferRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            let Some(row) = row else { return Ok(None) };
            let configuration_ids = serde_json::from_value(row.credential_configuration_ids)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            Ok(Some(CredentialAuthorization {
                tenant_id: row.tenant_id,
                subject_id,
                client_id: client_id.to_owned(),
                configuration_ids,
                credential_identifiers: Vec::new(),
                expires_at: (now + chrono::Duration::minutes(10)).min(row.expires_at),
            }))
        })
    }
}
#[derive(QueryableByName)]
pub(super) struct OfferRow {
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    pub(super) subject_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Jsonb)]
    pub(super) credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Binary)]
    pub(super) grants_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub(super) expires_at: DateTime<Utc>,
}

impl OfferRow {
    pub(super) fn into_domain(
        self,
        data_key: &[u8; 32],
    ) -> Result<StoredCredentialOffer, CredentialStoreError> {
        let grants = unprotect_payload(data_key, self.id, &self.grants_ciphertext)
            .map_err(|_| CredentialStoreError::InvalidTransition)?;
        Ok(StoredCredentialOffer {
            id: self.id,
            tenant_id: self.tenant_id,
            subject_id: self.subject_id,
            credential_configuration_ids: serde_json::from_value(self.credential_configuration_ids)
                .map_err(|_| CredentialStoreError::InvalidTransition)?,
            grants: serde_json::from_slice(&grants)
                .map_err(|_| CredentialStoreError::InvalidTransition)?,
            expires_at: self.expires_at,
        })
    }
}

#[derive(QueryableByName)]
pub(super) struct PreAuthorizedOfferRow {
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    pub(super) tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    pub(super) subject_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Jsonb)]
    pub(super) credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    pub(super) tx_code_hash: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub(super) expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct AuthorizationOfferRow {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

pub(super) fn tx_code_matches(expected: Option<&str>, presented: Option<&str>) -> bool {
    match (expected, presented) {
        (None, None) => true,
        (Some(expected), Some(presented)) => PasswordHash::new(expected).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(presented.as_bytes(), &hash)
                .is_ok()
        }),
        _ => false,
    }
}
