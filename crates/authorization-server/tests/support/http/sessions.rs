use super::*;
use nazo_postgres::UserRepository;
use nazo_valkey::SessionStore;
use std::sync::Arc;

use crate::test_support::TestInfrastructure;

pub(crate) fn admin_session_handles(state: &TestInfrastructure) -> AdminSessionHandles {
    let session = &state.settings.session;
    AdminSessionHandles::from_port(
        Arc::new(SessionStore::new(&state.valkey_connection())),
        Arc::new(UserRepository::new(state.diesel_db.clone())),
        state.settings.tenant.context.tenant_id,
        SessionHttpConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    )
}

pub(crate) fn profile_session_handles(state: &TestInfrastructure) -> SessionProfileHandles {
    let session = &state.settings.session;
    SessionProfileHandles::from_port(
        Arc::new(SessionStore::new(&state.valkey_connection())),
        Arc::new(UserRepository::new(state.diesel_db.clone())),
        state.settings.tenant.context.tenant_id,
        SessionHttpConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    )
}
