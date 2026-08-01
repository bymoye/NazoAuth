use super::*;

fn test_operations(
    state: &crate::test_support::TestInfrastructure,
) -> std::sync::Arc<PasskeyOperationsProvider> {
    std::sync::Arc::new(PasskeyOperationsProvider::new(
        crate::test_support::passkey_service(state)
            .get_ref()
            .clone(),
        SessionService::new(
            std::sync::Arc::new(nazo_valkey::SessionStore::new(&state.valkey_connection())),
            std::sync::Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            nazo_identity::TenantId::new(crate::domain::tenancy::DEFAULT_TENANT_ID)
                .expect("default tenant ID is valid"),
        ),
    ))
}

pub(crate) fn test_login_endpoint(
    state: &crate::test_support::TestInfrastructure,
) -> actix_web::web::Data<nazo_http_actix::PasskeyLoginEndpoint> {
    let identity = &state.settings.identity;
    let session = &state.settings.session;
    let endpoint = &state.settings.endpoint;
    actix_web::web::Data::new(nazo_http_actix::PasskeyLoginEndpoint::new(
        test_operations(state),
        std::sync::Arc::new(crate::domain::ServerAuthenticationRateLimit::new(
            nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            identity.rate_limit.window_seconds,
            identity.rate_limit.auth_max_requests,
        )),
        nazo_http_actix::ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        ),
        nazo_http_actix::PasskeyLoginConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            crate::domain::MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ))
}

pub(crate) fn test_profile_endpoint(
    state: &crate::test_support::TestInfrastructure,
) -> actix_web::web::Data<nazo_http_actix::PasskeyProfileEndpoint> {
    let session = &state.settings.session;
    actix_web::web::Data::new(nazo_http_actix::PasskeyProfileEndpoint::new(
        test_operations(state),
        nazo_http_actix::PasskeyProfileConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    ))
}
