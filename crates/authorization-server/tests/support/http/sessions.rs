use super::*;

use crate::test_support::TestInfrastructure;

pub(crate) fn admin_session_handles(state: &TestInfrastructure) -> AdminSessionHandles {
    let session = &state.settings.session;
    AdminSessionHandles::new(
        SessionStore::new(&state.valkey_connection()),
        UserRepository::new(state.diesel_db.clone()),
        SessionHttpConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    )
}

pub(crate) fn profile_session_handles(state: &TestInfrastructure) -> SessionProfileHandles {
    let session = &state.settings.session;
    SessionProfileHandles::new(
        SessionStore::new(&state.valkey_connection()),
        UserRepository::new(state.diesel_db.clone()),
        SessionHttpConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    )
}
