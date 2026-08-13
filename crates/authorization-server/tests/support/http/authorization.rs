use super::*;

pub(crate) struct AuthorizationTestFixture {
    service: ServerAuthorizationService,
    config: AuthorizationHttpConfig,
    sessions: AdminSessionHandles,
    enabled_modules: std::collections::BTreeSet<ModuleId>,
    request_object_keys: nazo_key_management::KeyManager,
}

impl AuthorizationTestFixture {
    pub(crate) fn new(
        service: ServerAuthorizationService,
        config: AuthorizationHttpConfig,
        sessions: AdminSessionHandles,
        enabled_modules: std::collections::BTreeSet<ModuleId>,
        request_object_keys: nazo_key_management::KeyManager,
    ) -> Self {
        Self {
            service,
            config,
            sessions,
            enabled_modules,
            request_object_keys,
        }
    }

    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        AuthorizationRequestContext::for_test(
            &self.service,
            &self.config,
            &self.sessions,
            self.enabled_modules.clone(),
            &self.request_object_keys,
        )
    }

    pub(crate) fn without_module(mut self, module: ModuleId) -> Self {
        self.enabled_modules.remove(&module);
        self
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
            self.request_object_keys.clone(),
        )
    }
}

pub(crate) struct TestAuthorizationDependencies {
    fixture: AuthorizationTestFixture,
}

impl TestAuthorizationDependencies {
    pub(crate) fn new(state: &crate::test_support::TestInfrastructure) -> Self {
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
                state.keyset.clone(),
            ),
        }
    }

    pub(crate) fn context(&self) -> AuthorizationRequestContext<'_> {
        self.fixture.context()
    }
}

impl<'a> AuthorizationRequestContext<'a> {
    pub(crate) fn for_test(
        service: &'a ServerAuthorizationService,
        config: &'a AuthorizationHttpConfig,
        sessions: &'a AdminSessionHandles,
        enabled_modules: std::collections::BTreeSet<ModuleId>,
        request_object_keys: &'a nazo_key_management::KeyManager,
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
            remote_client_documents: None,
            request_object_keys,
            tenant_id: nazo_identity::DEFAULT_TENANT_ID,
            credential_authorization_offers: None,
        }
    }
}
