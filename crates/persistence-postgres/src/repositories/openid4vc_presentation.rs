use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_openid4vp::{
    PresentationResult, PresentationStoreError, PresentationStoreFuture, PresentationStorePort,
    PresentationTransaction, StoredPresentation,
};
use rand::Rng;
use uuid::Uuid;

use crate::DbPool;
#[derive(Clone)]
pub struct Openid4vpRepository {
    pool: DbPool,
    tenant_id: Uuid,
    data_key: [u8; 32],
}

impl Openid4vpRepository {
    #[must_use]
    pub fn new(pool: DbPool, tenant_id: Uuid, data_key: [u8; 32]) -> Self {
        Self {
            pool,
            tenant_id,
            data_key,
        }
    }
}

impl PresentationStorePort for Openid4vpRepository {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let state_hash = blake3::hash(transaction.request.state.as_bytes())
                .to_hex()
                .to_string();
            let protected_private_key = transaction
                .response_encryption_private_key
                .as_deref()
                .map(|key| protect_result(&self.data_key, transaction.id, key))
                .transpose()?;
            sql_query(
                "INSERT INTO openid4vp_transactions \
                 (id, tenant_id, client_id_prefix, request_method, response_mode, \
                  wallet_authorization_endpoint, state_hash, request, request_object, request_uri, \
                  conformance_lease_id, ephemeral_private_key_ciphertext, expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind::<sql_types::Uuid, _>(transaction.id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Text, _>(transaction.client_id_prefix.as_str())
            .bind::<sql_types::Text, _>(transaction.request_method.as_str())
            .bind::<sql_types::Text, _>(transaction.response_mode.as_str())
            .bind::<sql_types::Text, _>(&transaction.wallet_authorization_endpoint)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Jsonb, _>(
                serde_json::to_value(&transaction.request)
                    .map_err(|_| PresentationStoreError::InvalidTransition)?,
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(transaction.request_object.as_deref())
            .bind::<sql_types::Nullable<sql_types::Text>, _>(transaction.request_uri.as_deref())
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(transaction.conformance_lease_id)
            .bind::<sql_types::Nullable<sql_types::Binary>, _>(protected_private_key)
            .bind::<sql_types::Timestamptz, _>(transaction.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            Ok(())
        })
    }

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let row = load_presentation(&mut connection, self.tenant_id, transaction_id, now)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            row.map(|value| value.transaction_with_key(&self.data_key))
                .transpose()
        })
    }

    fn bind_wallet_nonce<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: &'a str,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let Some(mut row) =
                load_presentation(&mut connection, self.tenant_id, transaction_id, now)
                    .await
                    .map_err(|_| PresentationStoreError::Unavailable)?
            else {
                return Ok(None);
            };
            let mut request = row.transaction()?.request;
            request.wallet_nonce = Some(wallet_nonce.to_owned());
            let encoded = serde_json::to_value(&request)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET request = $4 \
                 WHERE id = $1 AND tenant_id = $2 AND completed_at IS NULL AND expires_at > $3 \
                   AND (conformance_lease_id IS NULL OR \
                        nazo_oauth_conformance_lease_is_active(tenant_id, conformance_lease_id))",
            )
            .bind::<sql_types::Uuid, _>(transaction_id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Jsonb, _>(&encoded)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            if changed != 1 {
                return Ok(None);
            }
            row.request = encoded;
            row.transaction_with_key(&self.data_key).map(Some)
        })
    }

    fn complete<'a>(
        &'a self,
        transaction_id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let encoded = serde_json::to_vec(result)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
            let encoded = protect_result(&self.data_key, transaction_id, &encoded)?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET result_ciphertext = $5, completed_at = $4 \
                 WHERE id = $1 AND tenant_id = $2 AND state_hash = $3 \
                   AND completed_at IS NULL AND expires_at > $4 \
                   AND (conformance_lease_id IS NULL OR \
                        nazo_oauth_conformance_lease_is_active(tenant_id, conformance_lease_id))",
            )
            .bind::<sql_types::Uuid, _>(transaction_id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Binary, _>(encoded)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let row = load_presentation(&mut connection, self.tenant_id, transaction_id, now)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            row.map(|value| value.stored(&self.data_key)).transpose()
        })
    }
}

#[derive(QueryableByName)]
struct PresentationRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_id_prefix: String,
    #[diesel(sql_type = sql_types::Text)]
    request_method: String,
    #[diesel(sql_type = sql_types::Text)]
    response_mode: String,
    #[diesel(sql_type = sql_types::Text)]
    wallet_authorization_endpoint: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    request: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_object: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_uri: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    conformance_lease_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    ephemeral_private_key_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    result_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    completed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
}

impl PresentationRow {
    fn transaction(&self) -> Result<PresentationTransaction, PresentationStoreError> {
        Ok(PresentationTransaction {
            id: self.id,
            client_id_prefix: parse_client_id_prefix(&self.client_id_prefix)?,
            request_method: self
                .request_method
                .parse()
                .map_err(|_| PresentationStoreError::InvalidTransition)?,
            response_mode: parse_response_mode(&self.response_mode)?,
            wallet_authorization_endpoint: self.wallet_authorization_endpoint.clone(),
            request: serde_json::from_value(self.request.clone())
                .map_err(|_| PresentationStoreError::InvalidTransition)?,
            request_object: self.request_object.clone(),
            request_uri: self.request_uri.clone(),
            conformance_lease_id: self.conformance_lease_id,
            response_encryption_private_key: None,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
    fn transaction_with_key(
        &self,
        data_key: &[u8; 32],
    ) -> Result<PresentationTransaction, PresentationStoreError> {
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        Ok(transaction)
    }
    fn stored(self, data_key: &[u8; 32]) -> Result<StoredPresentation, PresentationStoreError> {
        let decrypted = self
            .result_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        let completed = decrypted
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        if completed
            .as_ref()
            .map(|result: &PresentationResult| result.completed_at.timestamp_micros())
            != self
                .completed_at
                .map(|completed_at| completed_at.timestamp_micros())
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        Ok(StoredPresentation {
            transaction,
            completed,
        })
    }
}

async fn load_presentation(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<PresentationRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, client_id_prefix, request_method, response_mode, wallet_authorization_endpoint, \
         request, request_object, request_uri, conformance_lease_id, ephemeral_private_key_ciphertext, result_ciphertext, completed_at, expires_at, created_at \
         FROM openid4vp_transactions WHERE id = $1 AND tenant_id = $2 AND expires_at > $3 \
           AND (conformance_lease_id IS NULL OR \
                nazo_oauth_conformance_lease_is_active(tenant_id, conformance_lease_id))",
    )
    .bind::<sql_types::Uuid, _>(id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .get_result(connection)
    .await
    .optional()
}

fn parse_client_id_prefix(
    value: &str,
) -> Result<nazo_openid4vp::ClientIdPrefix, PresentationStoreError> {
    match value {
        "redirect_uri" => Ok(nazo_openid4vp::ClientIdPrefix::RedirectUri),
        "x509_san_dns" => Ok(nazo_openid4vp::ClientIdPrefix::X509SanDns),
        "x509_hash" => Ok(nazo_openid4vp::ClientIdPrefix::X509Hash),
        _ => Err(PresentationStoreError::InvalidTransition),
    }
}

fn parse_response_mode(
    value: &str,
) -> Result<nazo_openid4vp::ResponseMode, PresentationStoreError> {
    match value {
        "direct_post" => Ok(nazo_openid4vp::ResponseMode::DirectPost),
        "direct_post.jwt" => Ok(nazo_openid4vp::ResponseMode::DirectPostJwt),
        _ => Err(PresentationStoreError::InvalidTransition),
    }
}

fn protect_result(
    key: &[u8; 32],
    transaction_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PresentationStoreError::Unavailable)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: transaction_id.as_bytes(),
                },
            )
            .map_err(|_| PresentationStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn unprotect_result(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(PresentationStoreError::InvalidTransition)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| PresentationStoreError::Unavailable)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: transaction_id.as_bytes(),
            },
        )
        .map_err(|_| PresentationStoreError::InvalidTransition)
}
