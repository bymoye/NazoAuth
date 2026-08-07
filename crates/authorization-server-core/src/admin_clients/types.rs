use nazo_identity::TenantContext;
use uuid::Uuid;

use crate::{OAuthClient, ValidatedClientRegistration};

#[derive(Clone)]
pub struct PreparedClientRegistration {
    pub tenant: TenantContext,
    pub conformance_lease_id: Option<Uuid>,
    pub registration: ValidatedClientRegistration,
    pub require_mtls_bound_tokens: bool,
    pub issued_secret: Option<String>,
    pub client_secret_hash: Option<String>,
    pub registration_access_token_blake3: Option<String>,
}

impl std::fmt::Debug for PreparedClientRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientRegistration")
            .field("tenant", &self.tenant)
            .field("conformance_lease_id", &self.conformance_lease_id)
            .field("registration", &self.registration)
            .field("require_mtls_bound_tokens", &self.require_mtls_bound_tokens)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "registration_access_token_blake3",
                &self
                    .registration_access_token_blake3
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl std::ops::Deref for PreparedClientRegistration {
    type Target = ValidatedClientRegistration;

    fn deref(&self) -> &Self::Target {
        &self.registration
    }
}

impl std::ops::DerefMut for PreparedClientRegistration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.registration
    }
}

#[derive(Clone)]
pub struct CreatedClient {
    pub client: OAuthClient,
    pub issued_secret: Option<String>,
}

impl std::fmt::Debug for CreatedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedClient")
            .field("client", &self.client)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}
