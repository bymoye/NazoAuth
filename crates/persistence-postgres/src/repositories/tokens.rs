use chrono::{DateTime, Duration, Utc};
use diesel::{
    ExpressionMethods, OptionalExtension, PgExpressionMethods, QueryDsl, SelectableHelper,
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{NewRefreshToken, RefreshToken, RefreshTokenPersistResult};
use nazo_identity::ports::RepositoryError;
use nazo_resource_server::{
    AccessTokenRevocationLookup, ProtectedResourceDependencyError, ResourceServerPortFuture,
    RevocationLookupKey,
};
use uuid::Uuid;

use crate::{
    DbPool,
    rows::auth::RefreshTokenRow,
    schema::{access_token_revocations, oauth_tokens},
};

const LOST_REFRESH_TOKEN_RETRY_SECONDS: i64 = 60;

#[derive(Clone)]
pub struct TokenRepository {
    pool: DbPool,
}

impl TokenRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn by_raw_refresh_token(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::refresh_token_blake3.eq(blake3_hex(raw_token)))
            .select(RefreshTokenRow::as_select())
            .first::<RefreshTokenRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(RefreshToken::try_from)
            .transpose()
    }

    pub async fn persist_refresh_token(
        &self,
        token: NewRefreshToken,
    ) -> Result<RefreshTokenPersistResult, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<RefreshTokenPersistResult, diesel::result::Error, _>(
                async |connection| {
                    lock_refresh_grant_scope(
                        connection,
                        token.tenant_id,
                        token.user_id,
                        token.client_id,
                    )
                    .await?;
                    lock_refresh_family(connection, token.family_id).await?;
                    if let Some(rotated_from_id) = token.rotated_from_id {
                        if let Some(retry) = token.lost_response_retry {
                            let original = load_family_token(
                                connection,
                                token.tenant_id,
                                token.family_id,
                                token.client_id,
                                retry.original_id,
                            )
                            .await?;
                            let successor = match original {
                                Some(original) => {
                                    lost_response_successor(
                                        connection,
                                        &original,
                                        token.client_id,
                                        retry.retry_started_at,
                                    )
                                    .await?
                                }
                                None => None,
                            };
                            if successor.as_ref().map(|row| row.id) != Some(rotated_from_id) {
                                compromise_family(connection, token.tenant_id, token.family_id)
                                    .await?;
                                return Ok(RefreshTokenPersistResult::RotationConflict);
                            }
                        }
                        let rotated = diesel::update(
                            oauth_tokens::table
                                .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
                                .filter(oauth_tokens::token_family_id.eq(token.family_id))
                                .filter(oauth_tokens::client_id.eq(token.client_id))
                                .filter(oauth_tokens::id.eq(rotated_from_id))
                                .filter(oauth_tokens::revoked_at.is_null()),
                        )
                        .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                        .execute(connection)
                        .await?;
                        if rotated == 0 {
                            compromise_family(connection, token.tenant_id, token.family_id).await?;
                            return Ok(RefreshTokenPersistResult::RotationConflict);
                        }
                    }
                    insert_refresh_token(connection, token).await?;
                    Ok(RefreshTokenPersistResult::Inserted)
                },
            )
            .await
            .map_err(map_error)
    }

    pub async fn lost_response_successor_or_compromise(
        &self,
        token: &RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        let mut connection = self.connection().await?;
        let row = connection
            .transaction::<Option<RefreshTokenRow>, diesel::result::Error, _>(async |connection| {
                lock_refresh_family(connection, token.token_family_id).await?;
                let original = load_family_token(
                    connection,
                    token.tenant_id,
                    token.token_family_id,
                    client_id,
                    token.id,
                )
                .await?;
                let successor = match original {
                    Some(original) => {
                        lost_response_successor(connection, &original, client_id, retry_started_at)
                            .await?
                    }
                    None => None,
                };
                if successor.is_none() {
                    compromise_family(connection, token.tenant_id, token.token_family_id).await?;
                }
                Ok(successor)
            })
            .await
            .map_err(map_error)?;
        row.map(RefreshToken::try_from).transpose()
    }

    pub async fn inspect_lost_response_successor(
        &self,
        token: &RefreshToken,
        client_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        let mut connection = self.connection().await?;
        lost_response_successor(&mut connection, &row_from_domain(token), client_id, now)
            .await
            .map_err(map_error)?
            .map(RefreshToken::try_from)
            .transpose()
    }

    pub async fn family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(family_id))
            .filter(oauth_tokens::user_id.eq(user_id))
            .filter(oauth_tokens::revoked_at.is_null())
            .filter(oauth_tokens::expires_at.gt(Utc::now()))
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map(|count| count > 0)
            .map_err(map_error)
    }

    pub async fn access_token_revoked(
        &self,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        access_token_revocations::table
            .filter(access_token_revocations::tenant_id.eq(tenant_id))
            .filter(access_token_revocations::access_token_jti_blake3.eq(blake3_hex(jti)))
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map(|count| count > 0)
            .map_err(map_error)
    }

    /// Revokes a refresh-token family or records an access-token JTI in one transaction.
    /// The family lock is shared with rotation so a successor cannot escape revocation.
    pub(crate) async fn revoke_for_client(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        raw_token: &str,
        access_token: Option<&nazo_auth::AccessTokenRevocation>,
    ) -> Result<usize, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<usize, diesel::result::Error, _>(async |connection| {
                let family_id = oauth_tokens::table
                    .filter(oauth_tokens::tenant_id.eq(tenant_id))
                    .filter(oauth_tokens::client_id.eq(client_id))
                    .filter(oauth_tokens::refresh_token_blake3.eq(blake3_hex(raw_token)))
                    .select(oauth_tokens::token_family_id)
                    .first::<Uuid>(connection)
                    .await
                    .optional()?;
                if let Some(family_id) = family_id {
                    lock_refresh_family(connection, family_id).await?;
                    return diesel::update(
                        oauth_tokens::table
                            .filter(oauth_tokens::tenant_id.eq(tenant_id))
                            .filter(oauth_tokens::client_id.eq(client_id))
                            .filter(oauth_tokens::token_family_id.eq(family_id))
                            .filter(oauth_tokens::revoked_at.is_null()),
                    )
                    .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                    .execute(connection)
                    .await;
                }
                if let Some(access_token) = access_token {
                    diesel::insert_into(access_token_revocations::table)
                        .values((
                            access_token_revocations::access_token_jti_blake3
                                .eq(blake3_hex(&access_token.jti)),
                            access_token_revocations::tenant_id.eq(tenant_id),
                            access_token_revocations::client_id.eq(client_id),
                            access_token_revocations::revoked_at.eq(Utc::now()),
                            access_token_revocations::expires_at.eq(access_token.expires_at),
                        ))
                        .on_conflict((
                            access_token_revocations::tenant_id,
                            access_token_revocations::access_token_jti_blake3,
                        ))
                        .do_nothing()
                        .execute(connection)
                        .await?;
                }
                Ok(0)
            })
            .await
            .map_err(map_error)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl AccessTokenRevocationLookup for TokenRepository {
    fn is_revoked<'a>(
        &'a self,
        key: RevocationLookupKey<'a>,
    ) -> ResourceServerPortFuture<'a, Result<bool, ProtectedResourceDependencyError>> {
        Box::pin(async move {
            let tenant_id = Uuid::parse_str(key.tenant_id)
                .map_err(|_| ProtectedResourceDependencyError::InvalidTenantBoundary)?;
            self.access_token_revoked(tenant_id, key.jti)
                .await
                .map_err(|_| ProtectedResourceDependencyError::RevocationLookupUnavailable)
        })
    }
}

async fn insert_refresh_token(
    connection: &mut AsyncPgConnection,
    token: NewRefreshToken,
) -> diesel::QueryResult<usize> {
    diesel::insert_into(oauth_tokens::table)
        .values((
            oauth_tokens::refresh_token_blake3.eq(blake3_hex(&token.raw_token)),
            oauth_tokens::tenant_id.eq(token.tenant_id),
            oauth_tokens::token_family_id.eq(token.family_id),
            oauth_tokens::rotated_from_id.eq(token.rotated_from_id),
            oauth_tokens::client_id.eq(token.client_id),
            oauth_tokens::user_id.eq(token.user_id),
            oauth_tokens::scopes.eq(serde_json::json!(token.scopes)),
            oauth_tokens::audience.eq(serde_json::json!(token.audiences)),
            oauth_tokens::authorization_details.eq(token.authorization_details),
            oauth_tokens::issued_at.eq(token.issued_at),
            oauth_tokens::expires_at.eq(token.expires_at),
            oauth_tokens::subject.eq(token.subject),
            oauth_tokens::dpop_jkt.eq(token.dpop_jkt),
            oauth_tokens::mtls_x5t_s256.eq(token.mtls_x5t_s256),
        ))
        .execute(connection)
        .await
}

async fn load_family_token(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
    client_id: Uuid,
    token_id: Uuid,
) -> diesel::QueryResult<Option<RefreshTokenRow>> {
    oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(tenant_id))
        .filter(oauth_tokens::token_family_id.eq(family_id))
        .filter(oauth_tokens::client_id.eq(client_id))
        .filter(oauth_tokens::id.eq(token_id))
        .select(RefreshTokenRow::as_select())
        .first::<RefreshTokenRow>(connection)
        .await
        .optional()
}

pub(super) async fn lock_refresh_family(
    connection: &mut AsyncPgConnection,
    family_id: Uuid,
) -> diesel::QueryResult<()> {
    let bytes = family_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(high ^ low)
        .execute(connection)
        .await?;
    Ok(())
}

pub(super) async fn lock_refresh_grant_scope(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    client_id: Uuid,
) -> diesel::QueryResult<()> {
    let mut hasher = blake3::Hasher::new_derive_key("nazo.refresh-grant-advisory-lock.v1");
    hasher.update(tenant_id.as_bytes());
    match user_id {
        Some(user_id) => {
            hasher.update(&[1]);
            hasher.update(user_id.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(client_id.as_bytes());
    let key = i64::from_be_bytes(
        hasher.finalize().as_bytes()[..8]
            .try_into()
            .expect("BLAKE3 output contains eight bytes"),
    );
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .execute(connection)
        .await?;
    Ok(())
}

async fn compromise_family(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
) -> diesel::QueryResult<()> {
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(family_id)),
    )
    .set(oauth_tokens::reuse_detected_at.eq(diesel::dsl::now))
    .execute(connection)
    .await?;
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(family_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
    .execute(connection)
    .await?;
    Ok(())
}

async fn lost_response_successor(
    connection: &mut AsyncPgConnection,
    token: &RefreshTokenRow,
    client_id: Uuid,
    now: DateTime<Utc>,
) -> diesel::QueryResult<Option<RefreshTokenRow>> {
    if token.dpop_jkt.is_none() && token.mtls_x5t_s256.is_none() {
        return Ok(None);
    }
    let Some(revoked_at) = token.revoked_at else {
        return Ok(None);
    };
    let elapsed = now.signed_duration_since(revoked_at);
    if elapsed < Duration::zero() || elapsed > Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS) {
        return Ok(None);
    }
    let reuse_count = oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
        .filter(oauth_tokens::token_family_id.eq(token.token_family_id))
        .filter(oauth_tokens::reuse_detected_at.is_not_null())
        .select(diesel::dsl::count_star())
        .first::<i64>(connection)
        .await?;
    if reuse_count != 0 {
        return Ok(None);
    }
    let mut successors = oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
        .filter(oauth_tokens::token_family_id.eq(token.token_family_id))
        .filter(oauth_tokens::client_id.eq(client_id))
        .filter(oauth_tokens::rotated_from_id.eq(token.id))
        .filter(oauth_tokens::dpop_jkt.is_not_distinct_from(token.dpop_jkt.as_deref()))
        .filter(oauth_tokens::mtls_x5t_s256.is_not_distinct_from(token.mtls_x5t_s256.as_deref()))
        .filter(oauth_tokens::revoked_at.is_null())
        .filter(oauth_tokens::expires_at.gt(now))
        .select(RefreshTokenRow::as_select())
        .limit(2)
        .load::<RefreshTokenRow>(connection)
        .await?;
    if successors.len() == 1 {
        Ok(successors.pop())
    } else {
        Ok(None)
    }
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn row_from_domain(token: &RefreshToken) -> RefreshTokenRow {
    RefreshTokenRow {
        id: token.id,
        tenant_id: token.tenant_id,
        token_family_id: token.token_family_id,
        client_id: token.client_id,
        user_id: token.user_id,
        scopes: token.scopes.clone(),
        audience: token.audience.clone(),
        authorization_details: token.authorization_details.clone(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        revoked_at: token.revoked_at,
        subject: token.subject.clone(),
        dpop_jkt: token.dpop_jkt.clone(),
        mtls_x5t_s256: token.mtls_x5t_s256.clone(),
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
