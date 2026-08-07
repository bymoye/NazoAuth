//! Ports and dependency futures for dynamic client registration.

use std::{future::Future, pin::Pin};

use uuid::Uuid;

use crate::{OAuthClient, PreparedClientRegistration};

pub type DynamicRegistrationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DynamicRegistrationDependencyError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationDependencyError {
    Unavailable,
    StaleCredentials,
}

/// Persistence boundary for RFC 7591 registration and RFC 7592 client management.
pub trait DynamicRegistrationClientStore: Send + Sync {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>>;

    fn has_client_secret(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool>;

    fn client_secret_salt(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, Option<String>>;

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool>;

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn deactivate<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        expected_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool>;
}

/// Secret-material operations kept outside protocol and transport code.
pub trait DynamicRegistrationSecretPort: Send + Sync {
    fn random_token(&self) -> String;
    fn token_hash(&self, token: &str) -> String;
    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool;
}

pub trait ClientSecretDigesterPort: Send + Sync {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String;
}
