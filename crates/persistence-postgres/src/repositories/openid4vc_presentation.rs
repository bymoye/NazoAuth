use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_openid4vp::{
    PresentationCreateIdempotency, PresentationCreateOutcome, PresentationResult,
    PresentationStoreError, PresentationStoreFuture, PresentationStorePort,
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

    async fn create_inner(
        &self,
        transaction: &PresentationTransaction,
        idempotency: PresentationCreateIdempotency<'_>,
    ) -> Result<PresentationCreateOutcome, PresentationStoreError> {
        validate_create_idempotency(idempotency)?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        clear_expired_create_request(
            &mut connection,
            self.tenant_id,
            idempotency.request_jti,
            Utc::now(),
        )
        .await
        .map_err(|_| PresentationStoreError::Unavailable)?;
        cleanup_expired_transactions(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let state_hash = blake3::hash(transaction.request.state.as_bytes())
            .to_hex()
            .to_string();
        let protected_private_key = transaction
            .response_encryption_private_key
            .as_deref()
            .map(|key| {
                protect_payload(
                    &self.data_key,
                    b"nazo-openid4vp-ephemeral-v2",
                    self.tenant_id,
                    transaction.id,
                    key,
                )
            })
            .transpose()?;
        let inserted = sql_query(
            "INSERT INTO openid4vp_transactions \
             (id, tenant_id, client_id_prefix, request_method, response_mode, \
              wallet_authorization_endpoint, state_hash, request, request_object, request_uri, \
              openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
              openid4vc_trust_policy_digest, ephemeral_private_key_ciphertext, expires_at, \
              create_request_jti, create_request_sha256, create_request_canonical_json, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) \
             ON CONFLICT (tenant_id, create_request_jti) \
                 WHERE create_request_jti IS NOT NULL DO NOTHING",
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
        .bind::<sql_types::Nullable<sql_types::Uuid>, _>(
            transaction.openid4vc_trust_policy_binding_id,
        )
        .bind::<sql_types::Nullable<sql_types::Text>, _>(
            transaction.openid4vc_trust_policy_resource_id.as_deref(),
        )
        .bind::<sql_types::Nullable<sql_types::Text>, _>(
            transaction.openid4vc_trust_policy_digest.as_deref(),
        )
        .bind::<sql_types::Nullable<sql_types::Binary>, _>(protected_private_key)
        .bind::<sql_types::Timestamptz, _>(transaction.expires_at)
        .bind::<sql_types::Text, _>(idempotency.request_jti)
        .bind::<sql_types::Text, _>(idempotency.request_sha256)
        .bind::<sql_types::Text, _>(idempotency.canonical_request)
        .bind::<sql_types::Timestamptz, _>(transaction.created_at)
        .execute(&mut connection)
        .await
        .map_err(|error| match error {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => PresentationStoreError::Unavailable,
            _ => PresentationStoreError::Unavailable,
        })?;
        match inserted {
            1 => Ok(PresentationCreateOutcome::Created),
            0 => self
                .load_idempotent_create(&mut connection, idempotency)
                .await?
                .map(|transaction| PresentationCreateOutcome::Existing(Box::new(transaction)))
                .ok_or(PresentationStoreError::InvalidTransition),
            _ => Err(PresentationStoreError::InvalidTransition),
        }
    }

    async fn load_idempotent_create(
        &self,
        connection: &mut diesel_async::AsyncPgConnection,
        idempotency: PresentationCreateIdempotency<'_>,
    ) -> Result<Option<PresentationTransaction>, PresentationStoreError> {
        validate_create_idempotency(idempotency)?;
        let row = load_presentation_by_create_request(
            connection,
            self.tenant_id,
            idempotency.request_jti,
        )
        .await
        .map_err(|_| PresentationStoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.create_request_sha256 != idempotency.request_sha256
            || row.create_request_canonical_json != idempotency.canonical_request
        {
            return Err(PresentationStoreError::IdempotencyConflict);
        }
        row.transaction().map(Some)
    }
}

impl PresentationStorePort for Openid4vpRepository {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
        idempotency: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<PresentationCreateOutcome, PresentationStoreError>>
    {
        Box::pin(async move { self.create_inner(transaction, idempotency).await })
    }

    fn find_by_create_request<'a>(
        &'a self,
        idempotency: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            clear_expired_create_request(
                &mut connection,
                self.tenant_id,
                idempotency.request_jti,
                Utc::now(),
            )
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            cleanup_expired_transactions(&mut connection)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            self.load_idempotent_create(&mut connection, idempotency)
                .await
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
            row.map(|value| value.transaction_with_key(&self.data_key, self.tenant_id))
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
                   AND openid4vc_presentation_trust_policy_is_active( \
                       tenant_id, openid4vc_trust_policy_binding_id, \
                       openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
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
            row.transaction_with_key(&self.data_key, self.tenant_id)
                .map(Some)
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
            let encoded = protect_payload(
                &self.data_key,
                b"nazo-openid4vp-result-v2",
                self.tenant_id,
                transaction_id,
                &encoded,
            )?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET result_ciphertext = $5, completed_at = $4, \
                     ephemeral_private_key_ciphertext = NULL \
                 WHERE id = $1 AND tenant_id = $2 AND state_hash = $3 \
                   AND completed_at IS NULL AND expires_at > $4 \
                   AND openid4vc_presentation_trust_policy_is_active( \
                       tenant_id, openid4vc_trust_policy_binding_id, \
                       openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
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
            row.map(|value| value.stored(&self.data_key, self.tenant_id))
                .transpose()
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
    #[diesel(sql_type = sql_types::Text)]
    create_request_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    create_request_canonical_json: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    request: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_object: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_uri: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    openid4vc_trust_policy_binding_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_resource_id: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_digest: Option<String>,

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

#[derive(QueryableByName)]
struct CleanupResult {
    #[diesel(sql_type = sql_types::Integer)]
    deleted_transactions: i32,
}

async fn cleanup_expired_transactions(
    connection: &mut diesel_async::AsyncPgConnection,
) -> Result<(), diesel::result::Error> {
    let result =
        sql_query("SELECT nazo_openid4vp_cleanup_expired_transactions() AS deleted_transactions")
            .get_result::<CleanupResult>(connection)
            .await?;
    debug_assert!((0..=256).contains(&result.deleted_transactions));
    Ok(())
}

async fn clear_expired_create_request(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    request_jti: &str,
    now: DateTime<Utc>,
) -> Result<(), diesel::result::Error> {
    sql_query(
        "DELETE FROM openid4vp_transactions \
         WHERE tenant_id = $1 AND create_request_jti = $2 \
           AND expires_at <= $3",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(request_jti)
    .bind::<sql_types::Timestamptz, _>(now)
    .execute(connection)
    .await?;
    Ok(())
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
            openid4vc_trust_policy_binding_id: self.openid4vc_trust_policy_binding_id,
            openid4vc_trust_policy_resource_id: self.openid4vc_trust_policy_resource_id.clone(),
            openid4vc_trust_policy_digest: self.openid4vc_trust_policy_digest.clone(),
            response_encryption_private_key: None,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
    fn transaction_with_key(
        &self,
        data_key: &[u8; 32],
        tenant_id: Uuid,
    ) -> Result<PresentationTransaction, PresentationStoreError> {
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| {
                unprotect_payload(
                    data_key,
                    b"nazo-openid4vp-ephemeral-v2",
                    tenant_id,
                    self.id,
                    value,
                )
            })
            .transpose()?;
        Ok(transaction)
    }
    fn stored(
        self,
        data_key: &[u8; 32],
        tenant_id: Uuid,
    ) -> Result<StoredPresentation, PresentationStoreError> {
        let decrypted = self
            .result_ciphertext
            .as_deref()
            .map(|value| {
                unprotect_payload(
                    data_key,
                    b"nazo-openid4vp-result-v2",
                    tenant_id,
                    self.id,
                    value,
                )
            })
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
            .map(|value| {
                unprotect_payload(
                    data_key,
                    b"nazo-openid4vp-ephemeral-v2",
                    tenant_id,
                    self.id,
                    value,
                )
            })
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
         create_request_sha256, create_request_canonical_json, \
         request, request_object, request_uri, openid4vc_trust_policy_binding_id, \
         openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest, \
         ephemeral_private_key_ciphertext, result_ciphertext, completed_at, expires_at, created_at \
         FROM openid4vp_transactions WHERE id = $1 AND tenant_id = $2 AND expires_at > $3 \
           AND openid4vc_presentation_trust_policy_is_active( \
               tenant_id, openid4vc_trust_policy_binding_id, \
               openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
    )
    .bind::<sql_types::Uuid, _>(id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .get_result(connection)
    .await
    .optional()
}

async fn load_presentation_by_create_request(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    request_jti: &str,
) -> Result<Option<PresentationRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, client_id_prefix, request_method, response_mode, wallet_authorization_endpoint, \
         create_request_sha256, create_request_canonical_json, \
         request, request_object, request_uri, openid4vc_trust_policy_binding_id, \
         openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest, \
         ephemeral_private_key_ciphertext, result_ciphertext, completed_at, expires_at, created_at \
         FROM openid4vp_transactions WHERE tenant_id = $1 AND create_request_jti = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(request_jti)
    .get_result(connection)
    .await
    .optional()
}

fn validate_create_idempotency(
    idempotency: PresentationCreateIdempotency<'_>,
) -> Result<(), PresentationStoreError> {
    nazo_operator_protocol::validate_openid4vp_create_request_jti(idempotency.request_jti)
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    if idempotency.request_sha256.len() != 64
        || !idempotency
            .request_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || idempotency.canonical_request.is_empty()
        || idempotency.canonical_request.len()
            > nazo_operator_protocol::MAX_OPENID4VP_NORMALIZED_CREATE_REQUEST_BYTES
    {
        return Err(PresentationStoreError::InvalidTransition);
    }
    let normalized: nazo_operator_protocol::Openid4vpNormalizedCreateRequest =
        serde_json::from_str(idempotency.canonical_request)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
    let (canonical, sha256) =
        nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
    if canonical != idempotency.canonical_request || sha256 != idempotency.request_sha256 {
        return Err(PresentationStoreError::InvalidTransition);
    }
    Ok(())
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

fn payload_aad(domain: &[u8], tenant_id: Uuid, transaction_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    for value in [domain, tenant_id.as_bytes(), transaction_id.as_bytes()] {
        aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
        aad.extend_from_slice(value);
    }
    aad
}
fn protect_payload(
    key: &[u8; 32],
    domain: &[u8],
    tenant_id: Uuid,
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
                    aad: &payload_aad(domain, tenant_id, transaction_id),
                },
            )
            .map_err(|_| PresentationStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn unprotect_payload(
    key: &[u8; 32],
    domain: &[u8],
    tenant_id: Uuid,
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(PresentationStoreError::InvalidTransition)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PresentationStoreError::Unavailable)?;
    let aad = payload_aad(domain, tenant_id, transaction_id);
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| PresentationStoreError::InvalidTransition)
}
