//! OAuth 授权码流程 HTTP handler 聚合模块。
// 三个端点分别负责发起授权、读取授权确认页数据、提交授权决策。
mod config;
pub(crate) mod consent;
pub(crate) mod jar;
pub(crate) mod par;
pub(crate) mod presentation;
pub(crate) mod request;

use std::sync::Arc;

use nazo_openid4vci::AuthorizationOfferPort;
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId};
use uuid::Uuid;

use crate::domain::remote_client_documents::RemoteClientDocumentResolver;
use crate::http::sessions::AdminSessionHandles;
use crate::runtime_modules::ServerRuntimeModuleRegistry;

pub(crate) use config::AuthorizationHttpConfig;

pub(crate) type ServerAuthorizationService = nazo_auth::AuthorizationService<
    nazo_postgres::AuthorizationFlowRepository,
    nazo_valkey::AuthorizationStateAdapter,
    nazo_key_management::KeyManager,
>;

/// Focused dependencies for the authorization transport entrypoints.
///
/// This is a composition handle, not a forwarding service: handlers borrow the
/// concrete authorization, identity-session, configuration, and capability
/// handles directly through a per-request immutable context.
pub(crate) struct AuthorizationEndpoint {
    service: Arc<ServerAuthorizationService>,
    config: Arc<AuthorizationHttpConfig>,
    sessions: Arc<AdminSessionHandles>,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    remote_client_documents: Arc<RemoteClientDocumentResolver>,
    request_object_keys: nazo_key_management::KeyManager,
    tenant_id: Uuid,
    credential_authorization_offers: Option<Arc<dyn AuthorizationOfferPort>>,
}

impl AuthorizationEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        service: Arc<ServerAuthorizationService>,
        config: Arc<AuthorizationHttpConfig>,
        sessions: Arc<AdminSessionHandles>,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
        remote_client_documents: Arc<RemoteClientDocumentResolver>,
        request_object_keys: nazo_key_management::KeyManager,
        tenant_id: Uuid,
        credential_authorization_offers: Option<Arc<dyn AuthorizationOfferPort>>,
    ) -> Self {
        Self {
            service,
            config,
            sessions,
            runtime_modules,
            remote_client_documents,
            request_object_keys,
            tenant_id,
            credential_authorization_offers,
        }
    }

    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        AuthorizationRequestContext {
            service: &self.service,
            config: &self.config,
            sessions: &self.sessions,
            modules: self.runtime_modules.snapshot().as_ref().clone(),
            remote_client_documents: Some(&self.remote_client_documents),
            request_object_keys: &self.request_object_keys,
            tenant_id: self.tenant_id,
            credential_authorization_offers: self.credential_authorization_offers.as_deref(),
        }
    }
}

pub(crate) struct AuthorizationRequestContext<'a> {
    pub(crate) service: &'a ServerAuthorizationService,
    pub(crate) config: &'a AuthorizationHttpConfig,
    pub(crate) sessions: &'a AdminSessionHandles,
    pub(crate) modules: ActiveModuleSnapshot,
    pub(crate) remote_client_documents: Option<&'a RemoteClientDocumentResolver>,
    pub(crate) request_object_keys: &'a nazo_key_management::KeyManager,
    pub(crate) tenant_id: Uuid,
    pub(crate) credential_authorization_offers: Option<&'a dyn AuthorizationOfferPort>,
}

pub(crate) fn accepts_module(
    context: &AuthorizationRequestContext<'_>,
    module_id: ModuleId,
) -> bool {
    nazo_auth::module_admissible(
        &context.modules,
        module_id,
        nazo_auth::CapabilityAdmission::NewRequest,
    )
}

pub(crate) fn permits_existing_module_transaction(
    context: &AuthorizationRequestContext<'_>,
    module_id: ModuleId,
) -> bool {
    nazo_auth::module_admissible(
        &context.modules,
        module_id,
        nazo_auth::CapabilityAdmission::ExistingTransaction,
    )
}

#[cfg(test)]
#[path = "../../../tests/support/http/authorization.rs"]
pub(crate) mod test_support;

pub(crate) use jar::{apply_request_object_with_context, unverified_request_object_client_id};
pub(crate) use par::is_pushed_authorization_request_uri;
#[cfg(test)]
#[path = "../../../tests/unit/http/authorization/boundary.rs"]
mod boundary_tests;
