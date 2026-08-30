//! Shared tenant-resource registration-policy bridge.
//!
//! [`TenantResourcePreparation`] implementations must delegate to the
//! deployment's existing client-registration and password-hashing services so
//! operator-driven resources obey exactly the same policy as every other
//! client/user creation path. This adapter is constructed by the current
//! ControlOperation pipeline so those rules cannot drift apart.

use std::sync::Arc;

use anyhow::Context as _;
use futures_util::future::BoxFuture;
use nazo_auth::{AdminClientError, CreateClientRequest, OAuthClient, SuppliedClientSecret};
use nazo_identity::ports::SecretHashPort as _;
use uuid::Uuid;

use crate::bootstrap::RegistrationSecretHasher;
use crate::http::admin::clients::{
    ServerAdminClientCrypto, ServerAdminClientService, ServerSectorIdentifierResolver,
    admin_client_policy,
};
use crate::settings::Settings;
use nazo_persistence::tenant_resources::{
    PreparedMtlsTrustAnchor, PreparedOAuthClient, TenantResourcePreparation,
    TenantResourcePreparationError,
};

/// Bridges onto [`ServerAdminClientService`] (client registration policy) and
/// [`RegistrationSecretHasher`] (Argon2 password hashing).
pub(crate) struct ServerTenantResourcePreparation {
    clients: ServerAdminClientService,
}

impl ServerTenantResourcePreparation {
    pub(crate) fn new(clients: ServerAdminClientService) -> Self {
        Self { clients }
    }
}

impl TenantResourcePreparation for ServerTenantResourcePreparation {
    fn hash_user_password<'a>(
        &'a self,
        password: String,
    ) -> BoxFuture<'a, Result<String, TenantResourcePreparationError>> {
        Box::pin(async move {
            RegistrationSecretHasher
                .hash_secret(password)
                .await
                .map(|hash| hash.into_persistence_value())
                .map_err(|_| TenantResourcePreparationError::Unavailable)
        })
    }

    fn prepare_oauth_client<'a>(
        &'a self,
        request: CreateClientRequest,
        supplied_secret: Option<String>,
        tenant: nazo_identity::TenantContext,
    ) -> BoxFuture<'a, Result<PreparedOAuthClient, TenantResourcePreparationError>> {
        Box::pin(async move {
            let supplied_secret_expected = supplied_secret.is_some();
            let prepared = match supplied_secret {
                Some(secret) => {
                    let secret = SuppliedClientSecret::new(secret)
                        .map_err(|_| TenantResourcePreparationError::Rejected)?;
                    self.clients
                        .prepare_registration_with_secret(request, secret)
                        .await
                }
                None => self.clients.prepare_registration(request).await,
            }
            .map_err(map_admin_client_error)?;
            if prepared.tenant.tenant_id != tenant.tenant_id
                || prepared.tenant.realm_id != tenant.realm_id
                || prepared.tenant.organization_id != tenant.organization_id
                || prepared.registration_access_token_blake3.is_some()
                // A newly generated secret cannot be returned after the
                // transaction. A caller-supplied secret is deliberately
                // echoed by the existing preparation service and is allowed;
                // that temporary copy is wiped when `prepared` is dropped.
                || (prepared.issued_secret.is_some() && !supplied_secret_expected)
            {
                return Err(TenantResourcePreparationError::Rejected);
            }
            Ok(PreparedOAuthClient {
                client: OAuthClient {
                    id: Uuid::now_v7(),
                    tenant_id: tenant.tenant_id.as_uuid(),
                    realm_id: tenant.realm_id.as_uuid(),
                    organization_id: tenant.organization_id.as_uuid(),
                    registration: prepared.registration.clone(),
                    require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
                    is_active: true,
                },
                client_secret_hash: prepared.client_secret_hash.clone(),
            })
        })
    }

    fn prepare_mtls_trust_anchor<'a>(
        &'a self,
        certificate_pem: String,
    ) -> BoxFuture<'a, Result<PreparedMtlsTrustAnchor, TenantResourcePreparationError>> {
        Box::pin(async move {
            let prepared = nazo_key_management::validate_mtls_trust_anchor(&certificate_pem)
                .map_err(|_| TenantResourcePreparationError::Rejected)?;
            Ok(PreparedMtlsTrustAnchor {
                certificate_pem: prepared.certificate_pem,
                certificate_sha256: prepared.certificate_sha256,
                subject_dn: prepared.subject_dn,
                not_before: prepared.not_before,
                not_after: prepared.not_after,
            })
        })
    }
}

pub(crate) fn map_admin_client_error(error: AdminClientError) -> TenantResourcePreparationError {
    match error {
        AdminClientError::InvalidRequest(_) | AdminClientError::NotFound => {
            TenantResourcePreparationError::Rejected
        }
        AdminClientError::Repository(_)
        | AdminClientError::Lookup(_)
        | AdminClientError::Write(_)
        | AdminClientError::Consistency(_) => TenantResourcePreparationError::Unavailable,
    }
}

/// Everything the one-shot pipeline needs to drive a tenant-resource
/// persistence adapter with the running server's own policy inputs.
pub(crate) struct ControlPlaneTenantResources {
    pub(crate) preparation: Arc<dyn TenantResourcePreparation>,
    pub(crate) tenant: nazo_identity::TenantContext,
    pub(crate) data_encryption_key: Option<[u8; 32]>,
}

/// Composition for the one-shot ControlOperation pipeline (H07): builds the
/// same registration-policy bridge and tenant/data-key inputs as the running
/// server, from the same full configuration source. The launcher supplies the
/// backend-specific client repository behind the semantic port.
pub(crate) async fn control_plane_resources(
    clients: Arc<dyn nazo_auth::AdminClientRepositoryPort>,
) -> anyhow::Result<ControlPlaneTenantResources> {
    let config = crate::config::ConfigSource::load()
        .context("tenant-resource operations require the application configuration")?;
    let settings = Settings::from_config(&config)
        .context("tenant-resource operations require valid application settings")?;
    let keyset = nazo_key_management::KeyManager::load_or_create(settings.key_settings()).await?;
    let service = ServerAdminClientService::new(
        clients,
        ServerSectorIdentifierResolver,
        ServerAdminClientCrypto::new(keyset),
        admin_client_policy(&settings),
    );
    Ok(ControlPlaneTenantResources {
        preparation: Arc::new(ServerTenantResourcePreparation::new(service)),
        tenant: settings.tenant.context,
        data_encryption_key: settings.openid4vc.data_encryption_key,
    })
}
