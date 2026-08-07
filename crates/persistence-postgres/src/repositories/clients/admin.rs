use nazo_auth::{AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort, OAuthClient};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use super::base::OAuthClientRepository;

impl AdminClientRepositoryPort for OAuthClientRepository {
    fn page(&self, offset: i64, limit: i64) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        Box::pin(async move {
            OAuthClientRepository::page(self, offset, limit)
                .await
                .map_err(|error: RepositoryError| map_admin_client_error(error))
        })
    }

    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_client_id(self, tenant_id, client_id)
                .await
                .map_err(|error: RepositoryError| map_admin_client_error(error))
        })
    }

    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
        conformance_lease_id: Option<Uuid>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::insert(
                self,
                client,
                client_secret_hash,
                registration_access_token_blake3,
                conformance_lease_id,
            )
            .await
            .map_err(|error: RepositoryError| map_admin_client_error(error))
        })
    }

    fn update<'a>(&'a self, client: &'a OAuthClient) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::update_metadata(self, client)
                .await
                .map_err(|error: RepositoryError| map_admin_client_error(error))
        })
    }
}

fn map_admin_client_error(error: RepositoryError) -> AdminClientPortError {
    match error {
        RepositoryError::Unavailable => AdminClientPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            AdminClientPortError::Conflict
        }
        RepositoryError::Consistency(_) => AdminClientPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            AdminClientPortError::Unexpected
        }
    }
}
