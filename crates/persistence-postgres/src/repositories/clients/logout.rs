use nazo_auth::{
    LogoutClientRepositoryPort, LogoutDependencyError, LogoutFuture, RegisteredLogoutClient,
};
use uuid::Uuid;

use super::base::OAuthClientRepository;
use super::registered_logout_client;

impl LogoutClientRepositoryPort for OAuthClientRepository {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_client_id(self, tenant_id, client_id)
                .await
                .map(|client| client.map(registered_logout_client))
                .map_err(|_| LogoutDependencyError::Unavailable)
        })
    }
}
