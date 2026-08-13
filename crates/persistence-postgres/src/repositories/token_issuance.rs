use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper,
};
use diesel_async::RunQueryDsl;
use nazo_auth::{
    NewRefreshToken, OAuthClient, RefreshToken, RefreshTokenPersistResult, TokenFuture,
    TokenIssuanceClaimResult, TokenPortError, TokenRepositoryPort, TokenRevocation,
};
use nazo_auth::{
    PrepareTokenIssuance, PrepareTokenIssuanceResult, TokenIssuancePhase, TokenIssuanceRecord,
    TokenIssuanceTransitionResult,
};
use nazo_identity::{SubjectClaims, TenantId, UserId, ports::RepositoryError};
use rand::Rng;
use uuid::Uuid;

use crate::{DbPool, schema::oauth_token_issuances};

use super::{AuthorizationRepository, OAuthClientRepository, TokenRepository, UserRepository};

/// The persisted envelope format is deliberately independent from the key id.
/// A format migration can therefore be introduced without pretending that a
/// key rotation changed the ciphertext layout.
pub const TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION: &str = "v1";
const TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE: u8 = 1;
const RESPONSE_NONCE_LEN: usize = 12;
const RESPONSE_MIN_PROTECTED_LEN: usize = 1 + RESPONSE_NONCE_LEN + 16;

#[derive(Clone)]
pub struct TokenIssuanceResponseKeyRing {
    current: TokenIssuanceResponseKey,
    previous: Option<TokenIssuanceResponseKey>,
}

impl std::fmt::Debug for TokenIssuanceResponseKeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenIssuanceResponseKeyRing")
            .field("current_id", &self.current.id)
            .field(
                "previous_id",
                &self.previous.as_ref().map(|key| key.id.as_str()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct TokenIssuanceResponseKey {
    id: String,
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenIssuanceResponseKeyError {
    EmptyId,
    IdTooLong,
    DuplicateId,
}

impl std::fmt::Display for TokenIssuanceResponseKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "token issuance response encryption key id must not be empty",
            Self::IdTooLong => {
                "token issuance response encryption key id must be at most 128 bytes"
            }
            Self::DuplicateId => "token issuance response current and previous key ids must differ",
        })
    }
}

impl std::error::Error for TokenIssuanceResponseKeyError {}

impl TokenIssuanceResponseKeyRing {
    pub fn new(
        current_id: impl Into<String>,
        current_key: [u8; 32],
        previous: Option<(String, [u8; 32])>,
    ) -> Result<Self, TokenIssuanceResponseKeyError> {
        let current = TokenIssuanceResponseKey::new(current_id.into(), current_key)?;
        let previous = previous
            .map(|(id, key)| TokenIssuanceResponseKey::new(id, key))
            .transpose()?;
        if previous
            .as_ref()
            .is_some_and(|candidate| candidate.id == current.id)
        {
            return Err(TokenIssuanceResponseKeyError::DuplicateId);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current_id(&self) -> &str {
        &self.current.id
    }

    fn current(&self) -> &TokenIssuanceResponseKey {
        &self.current
    }

    fn key_for(&self, id: &str) -> Option<&TokenIssuanceResponseKey> {
        if self.current.id == id {
            Some(&self.current)
        } else {
            self.previous.as_ref().filter(|key| key.id == id)
        }
    }
}

impl TokenIssuanceResponseKey {
    fn new(id: String, key: [u8; 32]) -> Result<Self, TokenIssuanceResponseKeyError> {
        if id.trim().is_empty() {
            return Err(TokenIssuanceResponseKeyError::EmptyId);
        }
        if id.len() > 128 {
            return Err(TokenIssuanceResponseKeyError::IdTooLong);
        }
        Ok(Self { id, key })
    }
}

struct ResponseEnvelopeContext<'a> {
    issuance_id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    grant_key_hash: &'a str,
    response_digest: &'a str,
    envelope_version: &'a str,
    key_id: &'a str,
}

/// PostgreSQL transaction boundary used by authorization-code and refresh-token issuance.
#[derive(Clone)]
pub struct TokenIssuanceRepository {
    pool: DbPool,
    response_keys: Option<TokenIssuanceResponseKeyRing>,
    tokens: TokenRepository,
    authorization: AuthorizationRepository,
    users: UserRepository,
    clients: OAuthClientRepository,
}

impl TokenIssuanceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool: pool.clone(),
            response_keys: None,
            tokens: TokenRepository::new(pool.clone()),
            authorization: AuthorizationRepository::new(pool.clone()),
            clients: OAuthClientRepository::new(pool.clone()),
            users: UserRepository::new(pool),
        }
    }

    /// Production constructor. The response body is sealed before it is
    /// persisted. The key ring is supplied independently from client-secret
    /// hashing so that rotating one secret cannot silently invalidate the
    /// other capability.
    #[must_use]
    pub fn new_with_response_key_ring(
        pool: DbPool,
        response_keys: TokenIssuanceResponseKeyRing,
    ) -> Self {
        let mut repository = Self::new(pool);
        repository.response_keys = Some(response_keys);
        repository
    }

    /// Verifies that every non-expired persisted response can still be
    /// decrypted by the configured current/previous key ring. This runs
    /// before the HTTP server starts so retiring a previous key cannot leave
    /// only a request-time failure for a still-recoverable issuance.
    pub async fn validate_response_key_ring(&self) -> Result<(), RepositoryError> {
        let Some(response_keys) = self.response_keys.as_ref() else {
            return Err(RepositoryError::Consistency(
                "token issuance response encryption keys are not configured".to_owned(),
            ));
        };
        let mut connection = self.connection().await?;
        let key_ids = oauth_token_issuances::table
            .filter(oauth_token_issuances::expires_at.gt(Utc::now()))
            .filter(oauth_token_issuances::response_ciphertext.is_not_null())
            .select(oauth_token_issuances::response_key_id)
            .distinct()
            .load::<Option<String>>(&mut connection)
            .await
            .map_err(|error| {
                RepositoryError::Unexpected(format!(
                    "failed to inspect token issuance response key ids: {error}"
                ))
            })?;
        validate_response_key_ids(response_keys, key_ids)?;

        const PREFLIGHT_BATCH_SIZE: i64 = 512;
        let mut after_issuance_id = None;
        loop {
            let mut query = oauth_token_issuances::table
                .filter(oauth_token_issuances::expires_at.gt(Utc::now()))
                .into_boxed();
            if let Some(after) = after_issuance_id {
                query = query.filter(oauth_token_issuances::issuance_id.gt(after));
            }
            let rows = query
                .order(oauth_token_issuances::issuance_id.asc())
                .limit(PREFLIGHT_BATCH_SIZE)
                .select(TokenIssuanceRow::as_select())
                .load::<TokenIssuanceRow>(&mut connection)
                .await
                .map_err(|error| {
                    RepositoryError::Unexpected(format!(
                        "failed to authenticate token issuance response envelopes: {error}"
                    ))
                })?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after_issuance_id = Some(row.issuance_id);
                let _ = row.into_record(Some(response_keys))?;
            }
        }
        Ok(())
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

#[derive(diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = oauth_token_issuances)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct TokenIssuanceRow {
    issuance_id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    grant_key_blake3: String,
    request_digest: String,
    phase: String,
    claim_owner_id: Option<Uuid>,
    #[allow(dead_code)]
    claim_started_at: Option<DateTime<Utc>>,
    access_token_jti: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    response_ciphertext: Option<Vec<u8>>,
    response_digest: Option<String>,
    response_envelope_version: Option<String>,
    response_key_id: Option<String>,
    #[allow(dead_code)]
    expires_at: DateTime<Utc>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

impl TokenIssuanceRow {
    fn into_record(
        self,
        response_keys: Option<&TokenIssuanceResponseKeyRing>,
    ) -> Result<TokenIssuanceRecord, RepositoryError> {
        let phase = match self.phase.as_str() {
            "prepared" => TokenIssuancePhase::Prepared,
            "signed" => TokenIssuancePhase::Signed,
            "persisted" => TokenIssuancePhase::Persisted,
            "delivered" => TokenIssuancePhase::Delivered,
            _ => {
                return Err(RepositoryError::Consistency(
                    "token issuance contains an unknown phase".to_owned(),
                ));
            }
        };
        let response_body = match (
            &self.response_ciphertext,
            &self.response_digest,
            &self.response_envelope_version,
            &self.response_key_id,
        ) {
            (None, None, None, None) => None,
            (Some(ciphertext), Some(digest), Some(envelope_version), Some(key_id))
                if envelope_version == TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION =>
            {
                let Some(response_keys) = response_keys else {
                    return Err(RepositoryError::Consistency(
                        "token issuance response encryption keys are not configured".to_owned(),
                    ));
                };
                Some(unseal_response(
                    response_keys,
                    &ResponseEnvelopeContext {
                        issuance_id: self.issuance_id,
                        tenant_id: self.tenant_id,
                        client_id: self.client_id,
                        grant_key_hash: &self.grant_key_blake3,
                        response_digest: digest,
                        envelope_version,
                        key_id,
                    },
                    ciphertext,
                )?)
            }
            (Some(_), Some(_), Some(_), Some(_)) => {
                return Err(RepositoryError::Consistency(
                    "token issuance response envelope format is unsupported".to_owned(),
                ));
            }
            _ => {
                return Err(RepositoryError::Consistency(
                    "token issuance response envelope is incomplete".to_owned(),
                ));
            }
        };
        if matches!(phase, TokenIssuancePhase::Prepared) != response_body.is_none() {
            return Err(RepositoryError::Consistency(
                "token issuance phase and response envelope are inconsistent".to_owned(),
            ));
        }
        Ok(TokenIssuanceRecord {
            issuance_id: self.issuance_id,
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            grant_key: self.grant_key_blake3,
            request_digest: self.request_digest,
            phase,
            claim_owner_id: self.claim_owner_id,
            access_token_jti: self.access_token_jti,
            access_token_expires_at: self.access_token_expires_at.map(|value| value.timestamp()),
            response_body,
            response_digest: self.response_digest,
            // The core record predates key rotation and calls this field a
            // version. Keep it as the envelope format version; key identity is
            // an at-rest concern and is never exposed to token handlers.
            response_key_version: self.response_envelope_version,
        })
    }
}

fn validate_response_key_ids(
    response_keys: &TokenIssuanceResponseKeyRing,
    key_ids: impl IntoIterator<Item = Option<String>>,
) -> Result<(), RepositoryError> {
    for key_id in key_ids {
        let Some(key_id) = key_id else {
            return Err(RepositoryError::Consistency(
                "token issuance response is missing its encryption key id".to_owned(),
            ));
        };
        if response_keys.key_for(&key_id).is_none() {
            return Err(RepositoryError::Consistency(format!(
                "token issuance response uses an unavailable encryption key: {key_id}"
            )));
        }
    }
    Ok(())
}

fn grant_key_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn response_aad(context: &ResponseEnvelopeContext<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        16 + 16
            + 16
            + context.grant_key_hash.len()
            + context.response_digest.len()
            + context.envelope_version.len()
            + context.key_id.len(),
    );
    aad.extend_from_slice(context.issuance_id.as_bytes());
    aad.extend_from_slice(context.tenant_id.as_bytes());
    aad.extend_from_slice(context.client_id.as_bytes());
    aad.extend_from_slice(context.grant_key_hash.as_bytes());
    aad.extend_from_slice(context.response_digest.as_bytes());
    aad.extend_from_slice(context.envelope_version.as_bytes());
    aad.extend_from_slice(context.key_id.as_bytes());
    aad
}

fn seal_response(
    response_keys: Option<&TokenIssuanceResponseKeyRing>,
    context: &ResponseEnvelopeContext<'_>,
    response_body: &[u8],
) -> Result<Vec<u8>, RepositoryError> {
    let response_keys = response_keys.ok_or(RepositoryError::Unavailable)?;
    let key = response_keys.current();
    let cipher = Aes256Gcm::new_from_slice(&key.key)
        .map_err(|_| RepositoryError::Consistency("invalid issuance response key".to_owned()))?;
    let mut nonce = [0_u8; RESPONSE_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: response_body,
                aad: &response_aad(context),
            },
        )
        .map_err(|_| {
            RepositoryError::Unexpected("token issuance response encryption failed".to_owned())
        })?;
    let mut protected = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    protected.push(TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE);
    protected.extend_from_slice(&nonce);
    protected.extend_from_slice(&ciphertext);
    Ok(protected)
}

fn unseal_response(
    response_keys: &TokenIssuanceResponseKeyRing,
    context: &ResponseEnvelopeContext<'_>,
    protected: &[u8],
) -> Result<Vec<u8>, RepositoryError> {
    if protected.len() < RESPONSE_MIN_PROTECTED_LEN
        || protected[0] != TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE
    {
        return Err(RepositoryError::Consistency(
            "token issuance response envelope is malformed".to_owned(),
        ));
    }
    let Some(key) = response_keys.key_for(context.key_id) else {
        return Err(RepositoryError::Consistency(
            "token issuance response uses an unavailable encryption key".to_owned(),
        ));
    };
    let (nonce, ciphertext) = protected[1..]
        .split_at_checked(RESPONSE_NONCE_LEN)
        .ok_or_else(|| {
            RepositoryError::Consistency("token issuance response is malformed".to_owned())
        })?;
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| {
        RepositoryError::Consistency("token issuance response nonce is malformed".to_owned())
    })?;
    let plaintext = Aes256Gcm::new_from_slice(&key.key)
        .map_err(|_| RepositoryError::Consistency("invalid issuance response key".to_owned()))?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &response_aad(context),
            },
        )
        .map_err(|_| {
            RepositoryError::Consistency("token issuance response authentication failed".to_owned())
        })?;
    if blake3::hash(&plaintext).to_hex().to_string() != context.response_digest {
        return Err(RepositoryError::Consistency(
            "token issuance response digest mismatch".to_owned(),
        ));
    }
    Ok(plaintext)
}

impl TokenRepositoryPort for TokenIssuanceRepository {
    fn prepare_token_issuance<'a>(
        &'a self,
        input: PrepareTokenIssuance,
    ) -> TokenFuture<'a, PrepareTokenIssuanceResult> {
        Box::pin(async move {
            let mut connection = self.connection().await.map_err(map_repository_error)?;
            let grant_hash = grant_key_hash(&input.grant_key);
            diesel::delete(
                oauth_token_issuances::table
                    .filter(oauth_token_issuances::tenant_id.eq(input.tenant_id))
                    .filter(oauth_token_issuances::client_id.eq(input.client_id))
                    .filter(oauth_token_issuances::grant_key_blake3.eq(&grant_hash))
                    .filter(oauth_token_issuances::expires_at.le(Utc::now()))
                    .filter(oauth_token_issuances::claim_owner_id.is_null().or(
                        oauth_token_issuances::phase.ne(TokenIssuancePhase::Prepared.as_str()),
                    )),
            )
            .execute(&mut connection)
            .await
            .map_err(map_diesel_error)?;
            let inserted = diesel::insert_into(oauth_token_issuances::table)
                .values((
                    oauth_token_issuances::issuance_id.eq(input.issuance_id),
                    oauth_token_issuances::tenant_id.eq(input.tenant_id),
                    oauth_token_issuances::client_id.eq(input.client_id),
                    oauth_token_issuances::grant_key_blake3.eq(&grant_hash),
                    oauth_token_issuances::request_digest.eq(&input.request_digest),
                    oauth_token_issuances::phase.eq(TokenIssuancePhase::Prepared.as_str()),
                    oauth_token_issuances::expires_at.eq(input.expires_at),
                    oauth_token_issuances::updated_at.eq(Utc::now()),
                ))
                .on_conflict((
                    oauth_token_issuances::tenant_id,
                    oauth_token_issuances::client_id,
                    oauth_token_issuances::grant_key_blake3,
                ))
                .do_nothing()
                .execute(&mut connection)
                .await
                .map_err(map_diesel_error)?;
            let row = oauth_token_issuances::table
                .filter(oauth_token_issuances::tenant_id.eq(input.tenant_id))
                .filter(oauth_token_issuances::client_id.eq(input.client_id))
                .filter(oauth_token_issuances::grant_key_blake3.eq(&grant_hash))
                .select(TokenIssuanceRow::as_select())
                .first::<TokenIssuanceRow>(&mut connection)
                .await
                .map_err(map_diesel_error)?;
            let record = row
                .into_record(self.response_keys.as_ref())
                .map_err(map_repository_error)?;
            if inserted == 1 {
                Ok(PrepareTokenIssuanceResult::Created(record))
            } else if record.request_digest == input.request_digest {
                Ok(PrepareTokenIssuanceResult::Existing(record))
            } else {
                Ok(PrepareTokenIssuanceResult::Conflict)
            }
        })
    }

    fn claim_token_issuance<'a>(
        &'a self,
        issuance_id: Uuid,
        request_digest: &'a str,
        claim_owner_id: Uuid,
    ) -> TokenFuture<'a, TokenIssuanceClaimResult> {
        Box::pin(async move {
            // The NULL-owner predicate is the concurrency boundary. There is
            // intentionally no lease takeover path: a crashed owner leaves
            // the row blocked until an operator repairs the durable record.
            let mut connection = self.connection().await.map_err(map_repository_error)?;
            let affected = diesel::update(
                oauth_token_issuances::table
                    .filter(oauth_token_issuances::issuance_id.eq(issuance_id))
                    .filter(oauth_token_issuances::request_digest.eq(request_digest))
                    .filter(oauth_token_issuances::phase.eq(TokenIssuancePhase::Prepared.as_str()))
                    .filter(oauth_token_issuances::claim_owner_id.is_null()),
            )
            .set((
                oauth_token_issuances::claim_owner_id.eq(claim_owner_id),
                oauth_token_issuances::claim_started_at.eq(Utc::now()),
                oauth_token_issuances::updated_at.eq(Utc::now()),
            ))
            .execute(&mut connection)
            .await
            .map_err(map_diesel_error)?;
            if affected == 1 {
                return Ok(TokenIssuanceClaimResult::Applied);
            }

            let current = oauth_token_issuances::table
                .filter(oauth_token_issuances::issuance_id.eq(issuance_id))
                .select((
                    oauth_token_issuances::request_digest,
                    oauth_token_issuances::phase,
                    oauth_token_issuances::claim_owner_id,
                ))
                .first::<(String, String, Option<Uuid>)>(&mut connection)
                .await
                .optional()
                .map_err(map_diesel_error)?;
            Ok(match current {
                None => TokenIssuanceClaimResult::Missing,
                Some((digest, _phase, _)) if digest != request_digest => {
                    TokenIssuanceClaimResult::Conflict
                }
                Some((_, _, Some(_))) => TokenIssuanceClaimResult::Busy,
                Some(_) => TokenIssuanceClaimResult::Conflict,
            })
        })
    }

    fn record_token_issuance_signed<'a>(
        &'a self,
        input: nazo_auth::RecordTokenIssuanceSigned<'a>,
    ) -> TokenFuture<'a, TokenIssuanceTransitionResult> {
        Box::pin(async move {
            let nazo_auth::RecordTokenIssuanceSigned {
                issuance_id,
                request_digest,
                claim_owner_id,
                access_token_jti,
                access_token_expires_at,
                response_body,
                response_digest,
            } = input;
            let mut connection = self.connection().await.map_err(map_repository_error)?;
            let row = oauth_token_issuances::table
                .filter(oauth_token_issuances::issuance_id.eq(issuance_id))
                .filter(oauth_token_issuances::request_digest.eq(request_digest))
                .filter(oauth_token_issuances::claim_owner_id.eq(claim_owner_id))
                .select(TokenIssuanceRow::as_select())
                .first::<TokenIssuanceRow>(&mut connection)
                .await
                .optional()
                .map_err(map_diesel_error)?;
            let Some(row) = row else {
                return Ok(TokenIssuanceTransitionResult::Missing);
            };
            if row.phase != TokenIssuancePhase::Prepared.as_str() {
                return Ok(TokenIssuanceTransitionResult::Conflict);
            }
            let ciphertext = seal_response(
                self.response_keys.as_ref(),
                &ResponseEnvelopeContext {
                    issuance_id,
                    tenant_id: row.tenant_id,
                    client_id: row.client_id,
                    grant_key_hash: &row.grant_key_blake3,
                    response_digest,
                    envelope_version: TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
                    key_id: self
                        .response_keys
                        .as_ref()
                        .ok_or(TokenPortError::Unavailable)?
                        .current_id(),
                },
                response_body,
            )
            .map_err(map_repository_error)?;
            let Some(expires_at) = DateTime::<Utc>::from_timestamp(access_token_expires_at, 0)
            else {
                return Err(TokenPortError::CorruptData);
            };
            let affected = diesel::update(
                oauth_token_issuances::table
                    .filter(oauth_token_issuances::issuance_id.eq(issuance_id))
                    .filter(oauth_token_issuances::request_digest.eq(request_digest))
                    .filter(oauth_token_issuances::claim_owner_id.eq(claim_owner_id))
                    .filter(oauth_token_issuances::phase.eq(TokenIssuancePhase::Prepared.as_str())),
            )
            .set((
                oauth_token_issuances::phase.eq(TokenIssuancePhase::Signed.as_str()),
                oauth_token_issuances::access_token_jti.eq(access_token_jti),
                oauth_token_issuances::access_token_expires_at.eq(expires_at),
                oauth_token_issuances::response_ciphertext.eq(ciphertext),
                oauth_token_issuances::response_digest.eq(response_digest),
                oauth_token_issuances::response_envelope_version
                    .eq(TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION),
                oauth_token_issuances::response_key_id.eq(self
                    .response_keys
                    .as_ref()
                    .ok_or(TokenPortError::Unavailable)?
                    .current_id()),
                oauth_token_issuances::updated_at.eq(Utc::now()),
            ))
            .execute(&mut connection)
            .await
            .map_err(map_diesel_error)?;
            Ok(if affected == 1 {
                TokenIssuanceTransitionResult::Applied
            } else {
                TokenIssuanceTransitionResult::Conflict
            })
        })
    }

    fn mark_token_issuance_persisted<'a>(
        &'a self,
        issuance_id: Uuid,
        request_digest: &'a str,
    ) -> TokenFuture<'a, TokenIssuanceTransitionResult> {
        Box::pin(async move {
            transition_token_issuance(
                &self.pool,
                issuance_id,
                request_digest,
                TokenIssuancePhase::Signed,
                TokenIssuancePhase::Persisted,
            )
            .await
        })
    }

    fn mark_token_issuance_delivered<'a>(
        &'a self,
        issuance_id: Uuid,
        request_digest: &'a str,
    ) -> TokenFuture<'a, TokenIssuanceTransitionResult> {
        Box::pin(async move {
            transition_token_issuance(
                &self.pool,
                issuance_id,
                request_digest,
                TokenIssuancePhase::Persisted,
                TokenIssuancePhase::Delivered,
            )
            .await
        })
    }

    fn token_issuance_by_grant<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<TokenIssuanceRecord>> {
        Box::pin(async move {
            let mut connection = self.connection().await.map_err(map_repository_error)?;
            let grant_hash = grant_key_hash(grant_key);
            let row = oauth_token_issuances::table
                .filter(oauth_token_issuances::tenant_id.eq(tenant_id))
                .filter(oauth_token_issuances::client_id.eq(client_id))
                .filter(oauth_token_issuances::grant_key_blake3.eq(grant_hash))
                .filter(oauth_token_issuances::expires_at.gt(Utc::now()))
                .select(TokenIssuanceRow::as_select())
                .first::<TokenIssuanceRow>(&mut connection)
                .await
                .optional()
                .map_err(map_diesel_error)?;
            row.map(|row| row.into_record(self.response_keys.as_ref()))
                .transpose()
                .map_err(map_repository_error)
        })
    }

    fn client_by_id(&self, client_id: Uuid) -> TokenFuture<'_, Option<OAuthClient>> {
        Box::pin(async move {
            self.clients
                .by_id(client_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn client_by_protocol_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.clients
                .by_client_id(tenant_id, client_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        Box::pin(async move {
            self.tokens
                .by_raw_refresh_token(tenant_id, raw_token)
                .await
                .map_err(map_repository_error)
        })
    }

    fn lost_response_successor_or_compromise<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        Box::pin(async move {
            self.tokens
                .lost_response_successor_or_compromise(token, client_id, retry_started_at)
                .await
                .map_err(map_repository_error)
        })
    }

    fn persist_refresh_token<'a>(
        &'a self,
        token: NewRefreshToken,
    ) -> TokenFuture<'a, RefreshTokenPersistResult> {
        Box::pin(async move {
            self.tokens
                .persist_refresh_token(token)
                .await
                .map_err(map_repository_error)
        })
    }

    fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, Option<SubjectClaims>> {
        Box::pin(async move {
            let tenant_id = TenantId::new(tenant_id).map_err(|_| TokenPortError::CorruptData)?;
            let user_id = UserId::new(user_id).map_err(|_| TokenPortError::CorruptData)?;
            self.users
                .active_subject_claims_by_tenant_id(tenant_id, user_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .revoke_issued_tokens(
                    tenant_id,
                    client_id,
                    access_token_jti,
                    access_token_expires_at,
                    refresh_token_family_id,
                )
                .await
                .map_err(map_repository_error)
        })
    }

    fn access_token_revoked<'a>(&'a self, tenant_id: Uuid, jti: &'a str) -> TokenFuture<'a, bool> {
        Box::pin(async move {
            self.tokens
                .access_token_revoked(tenant_id, jti)
                .await
                .map_err(map_repository_error)
        })
    }

    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool> {
        Box::pin(async move {
            self.tokens
                .family_active(tenant_id, family_id, user_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> TokenFuture<'a, usize> {
        Box::pin(async move {
            self.tokens
                .revoke_for_client(
                    input.tenant_id,
                    input.client_id,
                    input.raw_token,
                    input.access_token.as_ref(),
                )
                .await
                .map_err(map_repository_error)
        })
    }
}

async fn transition_token_issuance(
    pool: &DbPool,
    issuance_id: Uuid,
    request_digest: &str,
    from: TokenIssuancePhase,
    to: TokenIssuancePhase,
) -> Result<TokenIssuanceTransitionResult, TokenPortError> {
    let mut connection = pool.get().await.map_err(|_| TokenPortError::Unavailable)?;
    let affected = diesel::update(
        oauth_token_issuances::table
            .filter(oauth_token_issuances::issuance_id.eq(issuance_id))
            .filter(oauth_token_issuances::request_digest.eq(request_digest))
            .filter(oauth_token_issuances::phase.eq(from.as_str())),
    )
    .set((
        oauth_token_issuances::phase.eq(to.as_str()),
        oauth_token_issuances::updated_at.eq(Utc::now()),
    ))
    .execute(&mut connection)
    .await
    .map_err(map_diesel_error)?;
    if affected == 1 {
        return Ok(TokenIssuanceTransitionResult::Applied);
    }
    let exists = oauth_token_issuances::table
        .filter(oauth_token_issuances::issuance_id.eq(issuance_id))
        .filter(oauth_token_issuances::request_digest.eq(request_digest))
        .select(oauth_token_issuances::phase)
        .first::<String>(&mut connection)
        .await
        .optional()
        .map_err(map_diesel_error)?;
    Ok(match exists.as_deref() {
        None => TokenIssuanceTransitionResult::Missing,
        Some(current) if current == to.as_str() => TokenIssuanceTransitionResult::Applied,
        Some(_) => TokenIssuanceTransitionResult::Conflict,
    })
}

fn map_repository_error(error: RepositoryError) -> TokenPortError {
    match error {
        RepositoryError::Unavailable => TokenPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => TokenPortError::Conflict,
        RepositoryError::Consistency(_) => TokenPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => TokenPortError::Unexpected,
    }
}

fn map_diesel_error(error: diesel::result::Error) -> TokenPortError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => TokenPortError::Conflict,
        diesel::result::Error::NotFound => TokenPortError::CorruptData,
        _ => TokenPortError::Unexpected,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/token_issuance.rs"]
mod tests;
