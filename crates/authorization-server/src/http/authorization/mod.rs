//! OAuth 授权码流程 HTTP handler 聚合模块。
// 三个端点分别负责发起授权、读取授权确认页数据、提交授权决策。
mod config;
pub(crate) mod consent;
#[cfg(test)]
pub(crate) mod decision;
pub(crate) mod jar;
pub(crate) mod par;
pub(crate) mod request;

use std::sync::Arc;

use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId};

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
}

impl AuthorizationEndpoint {
    pub(crate) fn new(
        service: Arc<ServerAuthorizationService>,
        config: Arc<AuthorizationHttpConfig>,
        sessions: Arc<AdminSessionHandles>,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            service,
            config,
            sessions,
            runtime_modules,
        }
    }

    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        AuthorizationRequestContext {
            service: &self.service,
            config: &self.config,
            sessions: &self.sessions,
            modules: self.runtime_modules.snapshot().as_ref().clone(),
        }
    }
}

pub(crate) struct AuthorizationRequestContext<'a> {
    pub(crate) service: &'a ServerAuthorizationService,
    pub(crate) config: &'a AuthorizationHttpConfig,
    pub(crate) sessions: &'a AdminSessionHandles,
    pub(crate) modules: ActiveModuleSnapshot,
}

impl<'a> AuthorizationRequestContext<'a> {
    #[cfg(test)]
    pub(crate) fn for_test(
        service: &'a ServerAuthorizationService,
        config: &'a AuthorizationHttpConfig,
        sessions: &'a AdminSessionHandles,
        enabled_modules: std::collections::BTreeSet<ModuleId>,
    ) -> Self {
        Self {
            service,
            config,
            sessions,
            modules: ActiveModuleSnapshot {
                revision: nazo_runtime_modules::ModuleRevision::new(0),
                accepting: enabled_modules,
                draining: std::collections::BTreeSet::new(),
            },
        }
    }
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
pub(crate) struct AuthorizationTestFixture {
    service: ServerAuthorizationService,
    config: AuthorizationHttpConfig,
    sessions: AdminSessionHandles,
    enabled_modules: std::collections::BTreeSet<ModuleId>,
}

#[cfg(test)]
impl AuthorizationTestFixture {
    pub(crate) fn new(
        service: ServerAuthorizationService,
        config: AuthorizationHttpConfig,
        sessions: AdminSessionHandles,
        enabled_modules: std::collections::BTreeSet<ModuleId>,
    ) -> Self {
        Self {
            service,
            config,
            sessions,
            enabled_modules,
        }
    }

    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        AuthorizationRequestContext::for_test(
            &self.service,
            &self.config,
            &self.sessions,
            self.enabled_modules.clone(),
        )
    }

    pub(crate) fn rebind_storage(
        &self,
        database: nazo_postgres::DbPool,
        connection: &nazo_valkey::ValkeyConnection,
        keyset: nazo_key_management::KeyManager,
    ) -> Self {
        Self::new(
            ServerAuthorizationService::new(
                nazo_postgres::AuthorizationFlowRepository::new(
                    database.clone(),
                    crate::domain::tenancy::DEFAULT_TENANT_ID,
                ),
                nazo_valkey::AuthorizationStateAdapter::new(connection),
                keyset,
            ),
            self.config.clone(),
            AdminSessionHandles::new(
                nazo_valkey::SessionStore::new(connection),
                nazo_postgres::UserRepository::new(database),
                self.sessions.http_config().clone(),
            ),
            self.enabled_modules.clone(),
        )
    }
}

#[cfg(test)]
pub(crate) struct TestAuthorizationDependencies {
    fixture: AuthorizationTestFixture,
}

#[cfg(test)]
impl TestAuthorizationDependencies {
    pub(crate) fn new(state: &crate::domain::TestAppState) -> Self {
        let connection = state.valkey_connection();
        let session = &state.settings.session;
        Self {
            fixture: AuthorizationTestFixture::new(
                ServerAuthorizationService::new(
                    nazo_postgres::AuthorizationFlowRepository::new(
                        state.diesel_db.clone(),
                        crate::domain::tenancy::DEFAULT_TENANT_ID,
                    ),
                    nazo_valkey::AuthorizationStateAdapter::new(&connection),
                    state.keyset.clone(),
                ),
                AuthorizationHttpConfig::from(state.settings.as_ref()),
                AdminSessionHandles::new(
                    nazo_valkey::SessionStore::new(&connection),
                    nazo_postgres::UserRepository::new(state.diesel_db.clone()),
                    crate::http::sessions::SessionHttpConfig::new(
                        &session.session_cookie_name,
                        &session.csrf_cookie_name,
                        session.cookie_secure,
                    ),
                ),
                crate::runtime_modules::inherited_enabled(&state.settings),
            ),
        }
    }

    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        self.fixture.context()
    }
}

#[cfg(test)]
pub(crate) const BASELINE_ACR_VALUE: &str = "1";

pub(crate) use jar::{
    apply_request_object_with_context, unverified_signed_request_object_client_id,
};
pub(crate) use par::is_pushed_authorization_request_uri;
#[cfg(test)]
pub(crate) use request::authorization_response_redirect;
#[cfg(test)]
pub(crate) use request::{
    AuthorizationResponseRedirect, authorization_response_redirect_with_context,
};

#[cfg(test)]
mod boundary_tests {
    #[test]
    fn authorization_entrypoints_use_focused_dependencies() {
        for (name, source) in [
            ("request", include_str!("request.rs")),
            ("par", include_str!("par.rs")),
            ("jar", include_str!("jar.rs")),
            ("consent", include_str!("consent.rs")),
            ("decision", include_str!("decision.rs")),
            ("prompt_none", include_str!("request/prompt_none.rs")),
        ] {
            assert!(
                !source.contains("Data<TestAppState>"),
                "{name} reintroduced the giant TestAppState extractor"
            );
            assert!(
                !source.contains("AuthorizationHandles"),
                "{name} reintroduced the authorization forwarding facade"
            );
        }
        for (name, source) in [
            ("request", include_str!("request.rs")),
            ("par", include_str!("par.rs")),
            ("consent", include_str!("consent.rs")),
            ("decision", include_str!("decision.rs")),
        ] {
            assert!(
                source.contains("Data<AuthorizationEndpoint>"),
                "{name} must extract only the focused authorization endpoint"
            );
            for dependency in [
                "Data<ServerAuthorizationService>",
                "Data<AuthorizationHttpConfig>",
                "Data<AdminSessionHandles>",
                "Data<ServerRuntimeModuleRegistry>",
            ] {
                assert!(
                    !source.contains(dependency),
                    "{name} directly extracts {dependency}"
                );
            }
        }
        for (name, source) in [
            ("par", include_str!("par.rs")),
            ("jar", include_str!("jar.rs")),
        ] {
            assert!(
                !source.contains("TestAppState")
                    && !source.contains("TestAuthorizationDependencies"),
                "{name} reintroduced the legacy authorization test state"
            );
        }
    }
}
