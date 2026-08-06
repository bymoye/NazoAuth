use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_openid4vci::CredentialStoreError;
use rand::Rng;
use uuid::Uuid;

use crate::DbPool;
#[derive(Clone)]
pub struct Openid4vciDatasetRepository {
    pool: DbPool,
    data_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedCredentialDataset {
    pub claims: serde_json::Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

pub struct ManagedCredentialDatasetWrite<'a> {
    pub tenant_id: Uuid,
    pub actor_user_id: Uuid,
    pub subject_id: Uuid,
    pub credential_configuration_id: &'a str,
    pub claims: &'a serde_json::Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

impl Openid4vciDatasetRepository {
    #[must_use]
    pub fn new(pool: DbPool, data_key: [u8; 32]) -> Self {
        Self { pool, data_key }
    }

    pub async fn dataset(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &str,
    ) -> Result<Option<serde_json::Value>, CredentialStoreError> {
        #[derive(QueryableByName)]
        struct DatasetRow {
            #[diesel(sql_type = sql_types::Binary)]
            claims_ciphertext: Vec<u8>,
        }

        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let row = sql_query(
            "SELECT claims_ciphertext FROM openid4vci_credential_datasets \
             WHERE tenant_id = $1 AND subject_id = $2 \
               AND credential_configuration_id = $3 \
               AND (valid_from IS NULL OR valid_from <= CURRENT_TIMESTAMP) \
               AND (valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP)",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(subject_id)
        .bind::<sql_types::Text, _>(credential_configuration_id)
        .get_result::<DatasetRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| CredentialStoreError::Unavailable)?;
        row.map(|row| {
            unprotect_dataset_claims(
                &self.data_key,
                tenant_id,
                subject_id,
                credential_configuration_id,
                &row.claims_ciphertext,
            )
        })
        .transpose()
    }

    pub async fn managed_dataset(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &str,
    ) -> Result<Option<ManagedCredentialDataset>, CredentialStoreError> {
        #[derive(QueryableByName)]
        struct DatasetRow {
            #[diesel(sql_type = sql_types::Binary)]
            claims_ciphertext: Vec<u8>,
            #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
            valid_from: Option<DateTime<Utc>>,
            #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
            valid_until: Option<DateTime<Utc>>,
            #[diesel(sql_type = sql_types::Timestamptz)]
            updated_at: DateTime<Utc>,
        }
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        sql_query(
            "SELECT claims_ciphertext, valid_from, valid_until, updated_at
             FROM openid4vci_credential_datasets
             WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = $3",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(subject_id)
        .bind::<sql_types::Text, _>(credential_configuration_id)
        .get_result::<DatasetRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| CredentialStoreError::Unavailable)?
        .map(|row| {
            Ok(ManagedCredentialDataset {
                claims: unprotect_dataset_claims(
                    &self.data_key,
                    tenant_id,
                    subject_id,
                    credential_configuration_id,
                    &row.claims_ciphertext,
                )?,
                valid_from: row.valid_from,
                valid_until: row.valid_until,
                updated_at: row.updated_at,
            })
        })
        .transpose()
    }

    pub async fn upsert_managed_dataset(
        &self,
        write: ManagedCredentialDatasetWrite<'_>,
    ) -> Result<bool, CredentialStoreError> {
        let ManagedCredentialDatasetWrite {
            tenant_id,
            actor_user_id,
            subject_id,
            credential_configuration_id,
            claims,
            valid_from,
            valid_until,
        } = write;
        let claims_ciphertext = protect_dataset_claims(
            &self.data_key,
            tenant_id,
            subject_id,
            credential_configuration_id,
            claims,
        )?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let affected = sql_query(
            "WITH authorized_actor AS (
                SELECT id FROM users
                WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE
                  AND role = 'admin' AND admin_level > 0
             ), upserted AS (
                INSERT INTO openid4vci_credential_datasets
                    (tenant_id, subject_id, credential_configuration_id, claims_ciphertext, source, valid_from, valid_until)
                SELECT $1, $3, $4, $5, 'admin-session', $6, $7
                FROM users u CROSS JOIN authorized_actor a
                WHERE u.tenant_id = $1 AND u.id = $3 AND u.is_active = TRUE
                ON CONFLICT (tenant_id, subject_id, credential_configuration_id) DO UPDATE SET
                    claims_ciphertext = EXCLUDED.claims_ciphertext, source = EXCLUDED.source,
                    valid_from = EXCLUDED.valid_from, valid_until = EXCLUDED.valid_until,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING tenant_id, subject_id, credential_configuration_id
             )
             INSERT INTO openid4vci_credential_dataset_events
                (tenant_id, subject_id, credential_configuration_id, action, actor_user_id, source)
             SELECT tenant_id, subject_id, credential_configuration_id, 1, $2, 'admin-session'
             FROM upserted",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(actor_user_id)
        .bind::<sql_types::Uuid, _>(subject_id)
        .bind::<sql_types::Text, _>(credential_configuration_id)
        .bind::<sql_types::Binary, _>(claims_ciphertext)
        .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(valid_from)
        .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(valid_until)
        .execute(&mut connection)
        .await
        .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(affected == 1)
    }

    pub async fn delete_managed_dataset(
        &self,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &str,
    ) -> Result<bool, CredentialStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        sql_query(
            "WITH authorized_actor AS (
                SELECT id FROM users
                WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE
                  AND role = 'admin' AND admin_level > 0
             ), deleted AS (
                DELETE FROM openid4vci_credential_datasets d
                USING authorized_actor a
                WHERE d.tenant_id = $1 AND d.subject_id = $3
                  AND d.credential_configuration_id = $4
                RETURNING d.tenant_id, d.subject_id, d.credential_configuration_id
             )
             INSERT INTO openid4vci_credential_dataset_events
                (tenant_id, subject_id, credential_configuration_id, action, actor_user_id, source)
             SELECT tenant_id, subject_id, credential_configuration_id, 2, $2, 'admin-session'
             FROM deleted",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(actor_user_id)
        .bind::<sql_types::Uuid, _>(subject_id)
        .bind::<sql_types::Text, _>(credential_configuration_id)
        .execute(&mut connection)
        .await
        .map(|affected| affected == 1)
        .map_err(|_| CredentialStoreError::Unavailable)
    }
}

fn dataset_aad(tenant_id: Uuid, subject_id: Uuid, credential_configuration_id: &str) -> Vec<u8> {
    let configuration = credential_configuration_id.as_bytes();
    let mut aad = Vec::with_capacity(16 + 16 + 8 + configuration.len());
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.extend_from_slice(subject_id.as_bytes());
    aad.extend_from_slice(&(configuration.len() as u64).to_be_bytes());
    aad.extend_from_slice(configuration);
    aad
}

fn protect_dataset_claims(
    key: &[u8; 32],
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
    claims: &serde_json::Value,
) -> Result<Vec<u8>, CredentialStoreError> {
    let plaintext =
        serde_json::to_vec(claims).map_err(|_| CredentialStoreError::InvalidTransition)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CredentialStoreError::Unavailable)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: &dataset_aad(tenant_id, subject_id, credential_configuration_id),
                },
            )
            .map_err(|_| CredentialStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn unprotect_dataset_claims(
    key: &[u8; 32],
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
    protected: &[u8],
) -> Result<serde_json::Value, CredentialStoreError> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(CredentialStoreError::InvalidTransition)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| CredentialStoreError::InvalidTransition)?;
    let plaintext = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CredentialStoreError::Unavailable)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &dataset_aad(tenant_id, subject_id, credential_configuration_id),
            },
        )
        .map_err(|_| CredentialStoreError::InvalidTransition)?;
    serde_json::from_slice(&plaintext).map_err(|_| CredentialStoreError::InvalidTransition)
}
