use nazo_auth::OAuthClient;
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use super::base::OAuthClientRepository;

impl nazo_auth::DynamicRegistrationClientStore for OAuthClientRepository {
    fn insert<'a>(
        &'a self,
        prepared: &'a nazo_auth::PreparedClientRegistration,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            nazo_auth::insert_prepared_client(self, prepared)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_registration_access_token(
                self, tenant_id, client_id, token_hash,
            )
            .await
            .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn has_client_secret(&self, client_id: Uuid) -> nazo_auth::DynamicRegistrationFuture<'_, bool> {
        Box::pin(async move {
            OAuthClientRepository::has_client_secret(self, client_id)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn client_secret_salt(
        &self,
        client_id: Uuid,
    ) -> nazo_auth::DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async move {
            OAuthClientRepository::client_secret_salt(self, client_id)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            OAuthClientRepository::client_secret_digest_matches(self, client_id, candidate_digest)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::rotate_credentials(
                self,
                tenant_id,
                client_id,
                client_secret_hash,
                expected_registration_access_token_hash,
                new_registration_access_token_hash,
            )
            .await
            .map_err(|error: RepositoryError| map_dynamic_registration_mutation_error(error))
        })
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::replace_registration(
                self,
                client,
                client_secret_hash,
                expected_registration_access_token_hash,
                new_registration_access_token_hash,
            )
            .await
            .map_err(|error: RepositoryError| map_dynamic_registration_mutation_error(error))
        })
    }

    fn deactivate<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        expected_registration_access_token_hash: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            OAuthClientRepository::deactivate(
                self,
                tenant_id,
                client_id,
                expected_registration_access_token_hash,
            )
            .await
            .map_err(|error: RepositoryError| map_dynamic_registration_mutation_error(error))
        })
    }
}

fn map_dynamic_registration_mutation_error(
    error: RepositoryError,
) -> nazo_auth::DynamicRegistrationDependencyError {
    match error {
        RepositoryError::NotFound => {
            nazo_auth::DynamicRegistrationDependencyError::StaleCredentials
        }
        _ => nazo_auth::DynamicRegistrationDependencyError::Unavailable,
    }
}
