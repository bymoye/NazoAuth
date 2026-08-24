//! Composition for the optional tenant-resource machine control plane.
//!
//! The protocol/provider and PostgreSQL executor own their respective policy
//! and transaction boundaries.  This module only connects them to the
//! deployment's existing client-registration and password-hashing services
//! through the shared [`crate::tenant_resource_preparation`] bridge.

use std::{net::SocketAddr, sync::Arc};

use actix_web::web;
use nazo_operator_protocol::{TenantResourceKind, TenantResourceOperation};

use super::super::configuration::StartupConfiguration;
use crate::bootstrap::ServerAdminClientService;
use crate::settings::TransportMode;
use crate::tenant_resource_preparation::ServerTenantResourcePreparation;
use crate::{
    tenant_resource_executor::PostgresTenantResourceExecutor,
    tenant_resource_provider::{
        TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE, TenantResourceProvider,
        TenantResourceProviderConfig, load_controller_public_key,
    },
};

fn supported_resource_kinds(openid4vc_dataset_enabled: bool) -> Vec<TenantResourceKind> {
    let mut resource_kinds = vec![
        TenantResourceKind::User,
        TenantResourceKind::OauthClient,
        TenantResourceKind::MtlsTrustAnchor,
        TenantResourceKind::Openid4vcTrustPolicy,
    ];
    if openid4vc_dataset_enabled {
        resource_kinds.push(TenantResourceKind::Openid4vcDataset);
    }
    resource_kinds
}

pub(super) async fn build(
    startup: &StartupConfiguration,
    admin_clients: ServerAdminClientService,
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
    let resource_kinds =
        supported_resource_kinds(startup.settings.openid4vc.data_encryption_key.is_some());
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
