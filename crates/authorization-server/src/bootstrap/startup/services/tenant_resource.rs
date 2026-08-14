//! Composition for the optional tenant-resource machine control plane.
//!
//! The protocol/provider and PostgreSQL executor own their respective policy
//! and transaction boundaries.  This module only connects them to the
//! deployment's existing client-registration and password-hashing services.

use std::{net::SocketAddr, sync::Arc};

use actix_web::web;
use futures_util::future::BoxFuture;
use nazo_auth::{AdminClientError, CreateClientRequest, OAuthClient, SuppliedClientSecret};
use nazo_identity::ports::SecretHashPort as _;
use nazo_operator_protocol::{TenantResourceKind, TenantResourceOperation};
use uuid::Uuid;

use super::super::configuration::StartupConfiguration;
use crate::bootstrap::{RegistrationSecretHasher, ServerAdminClientService};
use crate::settings::TransportMode;
use crate::{
    tenant_resource_executor::{
        PostgresTenantResourceExecutor, PreparedOAuthClient, TenantResourcePreparation,
        TenantResourcePreparationError,
    },
    tenant_resource_provider::{
        TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE, TenantResourceProvider,
        TenantResourceProviderConfig, load_controller_public_key,
    },
};

struct ServerTenantResourcePreparation {
    clients: web::Data<ServerAdminClientService>,
}

impl ServerTenantResourcePreparation {
    fn new(clients: web::Data<ServerAdminClientService>) -> Self {
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
            if request.conformance_lease_id.is_some() {
                return Err(TenantResourcePreparationError::Rejected);
            }
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
                || prepared.conformance_lease_id.is_some()
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
}

fn map_admin_client_error(error: AdminClientError) -> TenantResourcePreparationError {
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

pub(super) async fn build(
    startup: &StartupConfiguration,
    admin_clients: web::Data<ServerAdminClientService>,
) -> anyhow::Result<Option<web::Data<TenantResourceProvider>>> {
    let Some(_) = startup
        .config
        .optional_string(TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE)
    else {
        return Ok(None);
    };
    let bind: SocketAddr = startup
        .config
        .string("BIND", "0.0.0.0:8000")
        .parse()
        .map_err(|error| anyhow::anyhow!("tenant-resource BIND is invalid: {error}"))?;
    validate_management_transport(startup.settings.endpoint.transport_mode, bind)?;
    let controller_path = startup
        .config
        .persistent_path(TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE, None)?;
    let controller = load_controller_public_key(&controller_path).map_err(|error| {
        anyhow::anyhow!("tenant-resource controller key preflight failed: {error}")
    })?;
    let preparation = Arc::new(ServerTenantResourcePreparation::new(admin_clients));
    let executor = Arc::new(PostgresTenantResourceExecutor::new(
        nazo_postgres::TenantResourceRepository::new(startup.diesel_db.clone()),
        startup.settings.tenant.context,
        startup.settings.openid4vc.data_encryption_key,
        preparation,
    ));
    let mut resource_kinds = vec![
        TenantResourceKind::User,
        TenantResourceKind::OauthClient,
        TenantResourceKind::MtlsTrustAnchor,
    ];
    if startup.settings.openid4vc.data_encryption_key.is_some() {
        resource_kinds.push(TenantResourceKind::Openid4vcDataset);
    }
    let signer = startup.control_discovery.clone().into_inner();
    let provider = TenantResourceProvider::new(
        controller,
        TenantResourceProviderConfig {
            deployment_id: startup.control_discovery.deployment_id().to_owned(),
            tenant_id: startup
                .settings
                .tenant
                .context
                .tenant_id
                .as_uuid()
                .to_string(),
            runtime_instance_id: startup.control_discovery.runtime_instance_id().to_owned(),
            issuer: format!("runtime:{}", startup.control_discovery.deployment_id()),
            instance_key_id: startup.control_discovery.instance_key_id().to_owned(),
            runtime_public_key: startup.control_discovery.instance_verifying_key(),
            embedded: startup.control_discovery.embedded_identity(),
            resource_kinds,
            actions: vec![
                TenantResourceOperation::Apply,
                TenantResourceOperation::Enumerate,
                TenantResourceOperation::Revoke,
            ],
        },
        signer,
        executor.clone(),
        executor,
    )
    .map_err(|error| anyhow::anyhow!("tenant-resource provider preflight failed: {error}"))?;
    Ok(Some(web::Data::new(provider)))
}

fn validate_management_transport(mode: TransportMode, bind: SocketAddr) -> anyhow::Result<()> {
    if mode == TransportMode::LoopbackHttp && !bind.ip().is_loopback() {
        anyhow::bail!(
            "tenant-resource management over loopback HTTP requires BIND to use a loopback address"
        );
    }
    // Direct TLS provides transport confidentiality itself. Trusted-proxy
    // mode is the deployment's explicit TLS-termination trust boundary and
    // already requires a non-loopback HTTPS issuer and trusted proxy CIDRs.
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/bootstrap/startup/services/tenant_resource.rs"]
mod tests;
