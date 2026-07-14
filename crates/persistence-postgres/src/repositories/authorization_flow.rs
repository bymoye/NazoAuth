use nazo_auth::{
    AuthorizationFuture, AuthorizationPortError, AuthorizationRepositoryPort, DeviceGrantFuture,
    DeviceGrantPortError, DeviceGrantRepositoryPort, DeviceGrantWrite, GrantWrite, OAuthClient,
    StoredAuthorizationGrant,
};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::DbPool;

use super::{GrantRepository, OAuthClientRepository};

/// PostgreSQL implementation of the persistence boundary used by authorization flows.
///
/// The tenant is fixed when the composition root constructs the adapter, so protocol
/// code cannot accidentally query a client from a different tenant.
#[derive(Clone)]
pub struct AuthorizationFlowRepository {
    clients: OAuthClientRepository,
    grants: GrantRepository,
    tenant_id: Uuid,
}

impl AuthorizationFlowRepository {
    #[must_use]
    pub fn new(pool: DbPool, tenant_id: Uuid) -> Self {
        Self {
            clients: OAuthClientRepository::new(pool.clone()),
            grants: GrantRepository::new(pool),
            tenant_id,
        }
    }
}

impl AuthorizationRepositoryPort for AuthorizationFlowRepository {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.clients
                .by_client_id(self.tenant_id, client_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn active_mtls_candidates(&self, limit: usize) -> AuthorizationFuture<'_, Vec<OAuthClient>> {
        Box::pin(async move {
            let limit = i64::try_from(limit).map_err(|_| AuthorizationPortError::Unexpected)?;
            self.clients
                .active_mtls_candidates(self.tenant_id, limit)
                .await
                .map_err(map_repository_error)
        })
    }

    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        Box::pin(async move {
            self.grants
                .authorization(user_id, client_id)
                .await
                .map(|grant| {
                    grant.map(|grant| StoredAuthorizationGrant {
                        scopes: grant.scopes,
                        resource_indicators: grant.resource_indicators,
                        authorization_details: grant.authorization_details,
                    })
                })
                .map_err(map_repository_error)
        })
    }

    fn upsert_grant<'a>(&'a self, write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.grants
                .upsert(
                    write.tenant_id,
                    write.user_id,
                    write.client_id,
                    write.scopes,
                    write.resource_indicators,
                    write.authorization_details,
                )
                .await
                .map_err(map_repository_error)
        })
    }

    fn client_secret_salt<'a>(
        &'a self,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<String>> {
        Box::pin(async move {
            self.clients
                .client_secret_salt(client_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.clients
                .client_secret_digest_matches(client_id, candidate_digest)
                .await
                .map_err(map_repository_error)
        })
    }
}

impl DeviceGrantRepositoryPort for AuthorizationFlowRepository {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> DeviceGrantFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.clients
                .by_client_id(self.tenant_id, client_id)
                .await
                .map_err(map_device_repository_error)
        })
    }

    fn upsert_grant<'a>(&'a self, write: DeviceGrantWrite<'a>) -> DeviceGrantFuture<'a, ()> {
        Box::pin(async move {
            self.grants
                .upsert(
                    write.tenant_id,
                    write.user_id,
                    write.client_id,
                    write.scopes,
                    write.resource_indicators,
                    write.authorization_details,
                )
                .await
                .map_err(map_device_repository_error)
        })
    }
}

fn map_repository_error(error: RepositoryError) -> AuthorizationPortError {
    match error {
        RepositoryError::Unavailable => AuthorizationPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            AuthorizationPortError::Conflict
        }
        RepositoryError::Consistency(_) => AuthorizationPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            AuthorizationPortError::Unexpected
        }
    }
}

fn map_device_repository_error(error: RepositoryError) -> DeviceGrantPortError {
    match error {
        RepositoryError::Unavailable => DeviceGrantPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            DeviceGrantPortError::Conflict
        }
        RepositoryError::Consistency(_) => DeviceGrantPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            DeviceGrantPortError::Unexpected
        }
    }
}
