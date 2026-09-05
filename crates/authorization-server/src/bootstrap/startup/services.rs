use super::configuration::StartupConfiguration;
use super::tenant_runtime::{
    ProcessRuntime, TenantRuntimeRefresher, TenantRuntimeRegistry, spawn_directory_refresher,
};
use super::*;
use actix_web::dev::Extensions;
use std::rc::Rc;

mod dependencies;
mod factory;
mod identity;

/// The service phase is deliberately a small composition facade.  Process-wide
/// resources are initialized by [`super::configuration`]; this phase wires
/// request-facing adapters and hands the resulting graph to the Actix factory.
pub(super) async fn build(startup: StartupConfiguration) -> anyhow::Result<ServiceAssembly> {
    let core = dependencies::build(&startup).await?;
    let identity = identity::build(&startup, &core).await?;
    Ok(ServiceAssembly {
        startup,
        core,
        identity,
    })
}

pub(super) async fn run(
    process: Arc<ProcessRuntime>,
    registry: TenantRuntimeRegistry,
    refresher: Arc<TenantRuntimeRefresher>,
    backchannel_logout_worker: Option<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let refresh_task = spawn_directory_refresher(refresher.clone());
    let result = factory::run(process, registry).await;
    refresh_task.abort();
    await_aborted_task(refresh_task, "tenant directory refresher").await;
    refresher.shutdown().await;
    if let Some(worker) = backchannel_logout_worker {
        worker.abort();
        await_aborted_task(worker, "back-channel logout worker").await;
    }
    result
}

async fn await_aborted_task(worker: tokio::task::JoinHandle<()>, task: &'static str) {
    if let Err(error) = worker.await
        && !error.is_cancelled()
    {
        tracing::warn!(%error, task, "process background task stopped unexpectedly");
    }
}

pub(super) struct ServiceAssembly {
    pub(super) startup: StartupConfiguration,
    core: dependencies::CoreServices,
    identity: identity::IdentityServices,
}

impl ServiceAssembly {
    pub(super) fn app_data_container(&self) -> Rc<Extensions> {
        fn insert<T: 'static>(extensions: &mut Extensions, value: T) {
            let _ = extensions.insert(value);
        }

        let core = &self.core;
        let identity = &self.identity;
        let startup = &self.startup;
        let mut extensions = Extensions::new();

        insert(
            &mut extensions,
            web::Data::new(startup.settings.tenant.context),
        );
        if let Some(source) =
            crate::keyctl::MdocCrlSource::from_settings(&startup.settings, startup.keyset.clone())
        {
            insert(&mut extensions, web::Data::new(source));
        }
        insert(
            &mut extensions,
            identity.runtime_module_admin_endpoint.clone(),
        );
        insert(
            &mut extensions,
            identity.authorization_decision_endpoint.clone(),
        );
        insert(&mut extensions, identity.authorization_endpoint.clone());
        insert(&mut extensions, core.authorization_service.clone());
        insert(&mut extensions, core.token_service.clone());
        insert(&mut extensions, core.userinfo_endpoint.clone());
        insert(&mut extensions, startup.mtls_certificate_source.clone());
        insert(&mut extensions, startup.readiness_dependencies.clone());
        insert(&mut extensions, core.token_endpoint_handles.clone());
        insert(&mut extensions, core.ciba_service.clone());
        insert(&mut extensions, core.ciba_users.clone());
        insert(&mut extensions, core.ciba_config.clone());
        insert(&mut extensions, core.token_issuance_config.clone());
        insert(&mut extensions, core.device_service.clone());
        insert(&mut extensions, core.device_grants.clone());
        insert(&mut extensions, identity.device_decision_handles.clone());
        insert(&mut extensions, core.device_config.clone());
        insert(&mut extensions, core.authorization_config.clone());
        insert(&mut extensions, core.authorization_runtime.clone());
        insert(&mut extensions, core.metadata_handles.clone());
        insert(&mut extensions, identity.admin_sessions.clone());
        insert(&mut extensions, identity.admin_federation.clone());
        insert(&mut extensions, identity.session_profiles.clone());
        insert(
            &mut extensions,
            identity.session_management_endpoint.clone(),
        );
        insert(&mut extensions, identity.profile_logout_endpoint.clone());
        insert(&mut extensions, identity.profile_account_endpoint.clone());
        insert(&mut extensions, identity.oidc_logout.clone());
        insert(&mut extensions, identity.csrf_http_config.clone());
        insert(&mut extensions, identity.mfa_profiles.clone());
        insert(&mut extensions, identity.account_profiles.clone());
        insert(&mut extensions, identity.avatar_profiles.clone());
        insert(&mut extensions, identity.profile_access_requests.clone());
        insert(&mut extensions, identity.profile_federation.clone());
        insert(&mut extensions, core.resource_server_http_data.clone());
        insert(&mut extensions, identity.admin_users.clone());
        insert(&mut extensions, identity.admin_user_registration.clone());
        insert(&mut extensions, identity.admin_grants.clone());
        insert(&mut extensions, identity.admin_access_requests.clone());
        insert(&mut extensions, identity.controller_registry.clone());
        insert(&mut extensions, identity.recovery_root.clone());
        insert(&mut extensions, identity.mtls_trust_anchors.clone());
        insert(&mut extensions, identity.admin_access_delivery.clone());
        insert(
            &mut extensions,
            identity.admin_access_request_config.clone(),
        );
        insert(&mut extensions, core.admin_client_service.clone());
        insert(&mut extensions, core.admin_client_config.clone());
        insert(&mut extensions, identity.client_ip_config.clone());
        insert(&mut extensions, identity.auth_request_limiter.clone());
        insert(&mut extensions, identity.token_management_limiter.clone());
        insert(
            &mut extensions,
            identity.local_registration_endpoint.clone(),
        );
        insert(&mut extensions, identity.password_login_endpoint.clone());
        insert(&mut extensions, identity.passkey_login_endpoint.clone());
        insert(&mut extensions, identity.passkey_profile_endpoint.clone());
        insert(&mut extensions, identity.federation.clone());
        insert(&mut extensions, identity.federation_http_config.clone());
        insert(&mut extensions, core.dynamic_registration_handles.clone());
        insert(&mut extensions, core.scim_endpoint.clone());
        #[cfg(not(test))]
        insert(&mut extensions, core.token_management_endpoint.clone());
        if let Some(endpoint) = core.credential_issuer_endpoint.clone() {
            insert(&mut extensions, endpoint);
        }
        if let Some(service) = core.credential_dataset_admin.clone() {
            insert(&mut extensions, service);
        }
        if let Some(endpoint) = core.presentation_endpoint.clone() {
            insert(&mut extensions, endpoint);
        }
        if let Some(validator) = core.client_attestation_validator.clone() {
            insert(&mut extensions, web::Data::from(validator));
        }

        Rc::new(extensions)
    }
}
