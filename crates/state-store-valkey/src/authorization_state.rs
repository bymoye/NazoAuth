use nazo_auth::{
    AuthorizationCodeState, AuthorizationFuture, AuthorizationPortError,
    AuthorizationRateDimension, AuthorizationStateStorePort, ConsentPayload,
    PushedAuthorizationRequest,
};

use crate::{
    AuthorizationStore, Error, ErrorKind, RateDimension, RateLimitStore, ReplayStore,
    ValkeyConnection,
};

/// Valkey mechanisms required by an authorization flow, grouped at the
/// infrastructure boundary rather than in the HTTP layer.
#[derive(Clone, Debug)]
pub struct AuthorizationStateAdapter {
    authorization: AuthorizationStore,
    replay: ReplayStore,
    rate_limits: RateLimitStore,
}

impl AuthorizationStateAdapter {
    #[must_use]
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            authorization: AuthorizationStore::new(connection),
            replay: ReplayStore::new(connection),
            rate_limits: RateLimitStore::new(connection),
        }
    }
}

impl AuthorizationStateStorePort for AuthorizationStateAdapter {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        Box::pin(async move {
            self.authorization
                .load_par(request_uri)
                .await
                .map_err(map_error)
        })
    }

    fn take_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        Box::pin(async move {
            self.authorization
                .take_par(request_uri)
                .await
                .map_err(map_error)
        })
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.authorization
                .compare_and_delete_par(request_uri, expected)
                .await
                .map_err(map_error)
        })
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_par(request_uri, payload, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        Box::pin(async move {
            self.authorization
                .load_consent(request_id)
                .await
                .map_err(map_error)
        })
    }

    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        Box::pin(async move {
            self.authorization
                .take_consent(request_id)
                .await
                .map_err(map_error)
        })
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.authorization
                .compare_and_delete_consent(request_id, expected)
                .await
                .map_err(map_error)
        })
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_consent(request_id, payload, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_authorization_code_hash(code_hash, state, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .delete_authorization_code_hash(code_hash)
                .await
                .map(|_| ())
                .map_err(map_error)
        })
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        Box::pin(async move {
            self.authorization
                .take_reauth_nonce(nonce)
                .await
                .map_err(map_error)
        })
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .store_reauth_nonce(nonce, started_at, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_jar(client_id, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_private_key_jwt(client_id, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_jwt_bearer(client_id, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_dpop(thumbprint, jti, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.replay
                .issue_dpop_nonce(nonce, ttl_seconds)
                .await
                .map_err(map_error)
        })
    }

    fn consume_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.replay
                .consume_dpop_nonce(nonce)
                .await
                .map_err(map_error)
        })
    }

    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        Box::pin(async move {
            let dimension = match dimension {
                AuthorizationRateDimension::Token => RateDimension::Token,
                AuthorizationRateDimension::TokenManagement => RateDimension::TokenManagement,
            };
            self.rate_limits
                .increment(dimension, subject, window_seconds)
                .await
                .map_err(map_error)
        })
    }
}

fn map_error(error: Error) -> AuthorizationPortError {
    match error.kind() {
        ErrorKind::Timeout | ErrorKind::Unavailable => AuthorizationPortError::Unavailable,
        ErrorKind::CorruptData => AuthorizationPortError::CorruptData,
        ErrorKind::Protocol | ErrorKind::UnexpectedResult => AuthorizationPortError::Unexpected,
    }
}
