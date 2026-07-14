use chrono::{DateTime, Utc};
use nazo_auth::{
    AuthorizationCodeBeginResult, AuthorizationCodeState, AuthorizationCodeTransitionResult,
    TokenFuture, TokenPortError, TokenStateStorePort,
};
use uuid::Uuid;

use crate::{
    AuthorizationCodeBegin, AuthorizationStore, AuthorizationTransition, Error, ErrorKind,
    RateDimension, RateLimitStore, TokenStateStore, ValkeyConnection,
};

/// Valkey mechanisms required by token issuance. Business policy remains in `nazo-auth`.
#[derive(Clone, Debug)]
pub struct TokenIssuanceStateAdapter {
    authorization: AuthorizationStore,
    tokens: TokenStateStore,
    rate_limits: RateLimitStore,
}

impl TokenIssuanceStateAdapter {
    #[must_use]
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            authorization: AuthorizationStore::new(connection),
            tokens: TokenStateStore::new(connection),
            rate_limits: RateLimitStore::new(connection),
        }
    }
}

impl TokenStateStorePort for TokenIssuanceStateAdapter {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>> {
        Box::pin(async move {
            self.authorization
                .load_authorization_code_hash(code_hash)
                .await
                .map_err(map_error)
        })
    }

    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: DateTime<Utc>,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult> {
        Box::pin(async move {
            self.authorization
                .begin_authorization_code(code_hash, consuming_at)
                .await
                .map(map_begin)
                .map_err(map_error)
        })
    }

    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult> {
        Box::pin(async move {
            self.authorization
                .mark_authorization_code(code_hash, replacement, ttl_seconds)
                .await
                .map(map_transition)
                .map_err(map_error)
        })
    }

    fn store_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        user_id: Uuid,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.tokens
                .store_access_token_subject(tenant_id, jti, user_id, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn load_access_token_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        Box::pin(async move {
            self.tokens
                .load_access_token_subject(tenant_id, jti)
                .await
                .map_err(map_error)
        })
    }

    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window_seconds: u64,
    ) -> TokenFuture<'a, u64> {
        Box::pin(async move {
            self.rate_limits
                .increment(RateDimension::TokenManagement, subject, window_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a serde_json::Value,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.tokens
                .store_native_sso(secret, value, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn load_native_sso<'a>(
        &'a self,
        secret: &'a str,
    ) -> TokenFuture<'a, Option<serde_json::Value>> {
        Box::pin(async move { self.tokens.load_native_sso(secret).await.map_err(map_error) })
    }
}

fn map_begin(result: AuthorizationCodeBegin) -> AuthorizationCodeBeginResult {
    match result {
        AuthorizationCodeBegin::Consuming(payload) => {
            AuthorizationCodeBeginResult::Consuming(payload)
        }
        AuthorizationCodeBegin::Busy => AuthorizationCodeBeginResult::Busy,
        AuthorizationCodeBegin::Consumed(state) => AuthorizationCodeBeginResult::Consumed(state),
        AuthorizationCodeBegin::Failed => AuthorizationCodeBeginResult::Failed,
        AuthorizationCodeBegin::Missing => AuthorizationCodeBeginResult::Missing,
        AuthorizationCodeBegin::Malformed => AuthorizationCodeBeginResult::Malformed,
    }
}

fn map_transition(result: AuthorizationTransition) -> AuthorizationCodeTransitionResult {
    match result {
        AuthorizationTransition::Applied => AuthorizationCodeTransitionResult::Applied,
        AuthorizationTransition::Missing => AuthorizationCodeTransitionResult::Missing,
        AuthorizationTransition::Malformed => AuthorizationCodeTransitionResult::Malformed,
        AuthorizationTransition::Pending => AuthorizationCodeTransitionResult::Pending,
        AuthorizationTransition::Consuming => AuthorizationCodeTransitionResult::Consuming,
        AuthorizationTransition::Consumed => AuthorizationCodeTransitionResult::Consumed,
        AuthorizationTransition::Failed => AuthorizationCodeTransitionResult::Failed,
    }
}

fn map_error(error: Error) -> TokenPortError {
    match error.kind() {
        ErrorKind::Timeout | ErrorKind::Unavailable => TokenPortError::Unavailable,
        ErrorKind::CorruptData => TokenPortError::CorruptData,
        ErrorKind::Protocol | ErrorKind::UnexpectedResult => TokenPortError::Unexpected,
    }
}
