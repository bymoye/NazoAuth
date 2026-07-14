use chrono::{DateTime, Utc};
use nazo_auth::{
    NewRefreshToken, OAuthClient, RefreshToken, RefreshTokenPersistResult, TokenFuture,
    TokenPortError, TokenRepositoryPort, TokenRevocation,
};
use nazo_identity::{SubjectClaims, TenantId, UserId, ports::RepositoryError};
use uuid::Uuid;

use crate::DbPool;

use super::{AuthorizationRepository, OAuthClientRepository, TokenRepository, UserRepository};

/// PostgreSQL transaction boundary used by authorization-code and refresh-token issuance.
#[derive(Clone)]
pub struct TokenIssuanceRepository {
    tokens: TokenRepository,
    authorization: AuthorizationRepository,
    users: UserRepository,
    clients: OAuthClientRepository,
}

impl TokenIssuanceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            tokens: TokenRepository::new(pool.clone()),
            authorization: AuthorizationRepository::new(pool.clone()),
            clients: OAuthClientRepository::new(pool.clone()),
            users: UserRepository::new(pool),
        }
    }
}

impl TokenRepositoryPort for TokenIssuanceRepository {
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

fn map_repository_error(error: RepositoryError) -> TokenPortError {
    match error {
        RepositoryError::Unavailable => TokenPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => TokenPortError::Conflict,
        RepositoryError::Consistency(_) => TokenPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => TokenPortError::Unexpected,
    }
}
