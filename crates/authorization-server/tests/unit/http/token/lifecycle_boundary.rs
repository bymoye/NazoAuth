#[test]
fn token_management_request_facts_preserve_the_exact_endpoint_path() {
    let settings = crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    let extractor = super::ServerTokenManagementRequestFactsExtractor::new(std::sync::Arc::new(
        crate::http::authorization::AuthorizationHttpConfig::from(&settings),
    ));
    let request = actix_web::test::TestRequest::post()
        .uri("/introspect")
        .peer_addr("203.0.113.9:443".parse().unwrap())
        .to_http_request();
    let facts =
        nazo_http_actix::TokenManagementRequestFactsExtractor::extract(&extractor, &request);
    assert_eq!(facts.endpoint_path, "/introspect");
    assert_eq!(facts.source_ip, "203.0.113.9");
    assert!(facts.client_certificate.is_none());
}

fn function_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing boundary start {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing boundary end {end}"))
        .0
}

#[test]
fn production_token_dispatch_and_grants_do_not_receive_app_state() {
    let dispatch = include_str!("../../../../src/http/token/dispatch.rs");
    let dispatch = function_body(
        dispatch,
        "pub(crate) async fn token_with_service(",
        "pub(crate) use token_with_service as token;",
    );
    assert_eq!(
        include_str!("../../../../src/http/token/dispatch.rs")
            .matches("pub(crate) use token_with_service as token;")
            .count(),
        1,
        "token dispatch must expose exactly one production entry point"
    );
    for forbidden in [
        "Data<TestInfrastructure>",
        "state.settings",
        "state.diesel_db",
        "state.valkey_connection()",
        "TokenIssuanceRepository::new",
        "AuthorizationStore::new",
        "ReplayStore::new",
    ] {
        assert!(
            !dispatch.contains(forbidden),
            "production token dispatch reintroduced {forbidden}"
        );
    }

    for (name, source, start, end) in [
        (
            "authorization_code",
            include_str!("../../../../src/http/token/authorization_code.rs"),
            "pub(crate) async fn token_authorization_code_with_service(",
            "#[cfg(test)]\n#[path =",
        ),
        (
            "refresh_token",
            include_str!("../../../../src/http/token/refresh.rs"),
            "pub(crate) async fn token_refresh_with_service(",
            "#[cfg(test)]\n#[path =",
        ),
        (
            "native_sso",
            include_str!("../../../../src/http/token/native_sso.rs"),
            "pub(crate) async fn token_native_sso_exchange(",
            "#[cfg(test)]\n#[path =",
        ),
        (
            "ciba",
            include_str!("../../../../src/http/token/ciba.rs"),
            "pub(crate) async fn token_ciba(",
            "fn ciba_auth_req_id_client_error(",
        ),
    ] {
        let body = function_body(source, start, end);
        for forbidden in [
            "TestInfrastructure",
            "state.settings",
            "state.diesel_db",
            "state.valkey_connection()",
            "TokenRepository::new",
            "TokenStateStore::new",
            "ReplayStore::new",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} production grant reintroduced {forbidden}"
            );
        }
    }
}

#[test]
fn userinfo_transport_does_not_construct_storage_adapters() {
    let source = include_str!("../../../../../http-actix/src/userinfo.rs");
    assert!(source.contains("endpoint: Data<UserinfoEndpoint>"));
    for forbidden in [
        "Data<TestInfrastructure>",
        "Settings",
        "KeyManager",
        "nazo_postgres",
        "nazo_valkey",
        "diesel_db",
        "TokenRepository::new",
        "OAuthClientRepository::new",
        "UserRepository::new",
        "TokenStateStore::new",
    ] {
        assert!(
            !source.contains(forbidden),
            "userinfo handler reintroduced forbidden dependency {forbidden}"
        );
    }
}

#[test]
fn client_authentication_handlers_use_the_focused_authorization_boundary() {
    for (name, source) in [
        (
            "token",
            include_str!("../../../../src/http/token/dispatch.rs"),
        ),
        ("ciba", include_str!("../../../../src/http/token/ciba.rs")),
        (
            "device",
            include_str!("../../../../src/http/token/device.rs"),
        ),
        (
            "par",
            include_str!("../../../../src/http/authorization/par.rs"),
        ),
    ] {
        assert!(
            !source.contains("OAuthClientRepository::new"),
            "{name} reintroduced a direct PostgreSQL client-auth dependency"
        );
    }
    let auth_source = include_str!("../../../../src/http/token/client_auth.rs");
    for forbidden in [
        "match client.token_endpoint_auth_method.as_str()",
        ".expect(\"private_key_jwt",
        ".expect(\"secret-based client credentials",
        ".expect(\"mTLS client credentials",
    ] {
        assert!(
            !auth_source.contains(forbidden),
            "client authentication adapter reintroduced policy or panic: {forbidden}"
        );
    }
}

#[test]
fn ciba_transport_uses_composition_root_handles() {
    let source = include_str!("../../../../src/http/token/ciba.rs");
    for forbidden in [
        "CibaStore::new",
        "OAuthClientRepository::new",
        "UserRepository::new",
        "state.diesel_db",
        "state.valkey_connection()",
    ] {
        assert!(
            !source.contains(forbidden),
            "CIBA transport reintroduced composition dependency {forbidden}"
        );
    }
    assert!(!source.contains(
        "pub(crate) async fn backchannel_authentication(\n    state: Data<TestInfrastructure>"
    ));
    assert!(
        !source.contains(
            "pub(crate) async fn ciba_verification(\n    state: Data<TestInfrastructure>"
        )
    );
}

#[test]
fn shared_issuance_core_uses_typed_context_and_existing_service() {
    let source = include_str!("../../../../src/http/token/issue.rs");
    let core = source
        .split("pub(crate) async fn issue_token_response_with_service")
        .nth(1)
        .and_then(|source| source.split("#[cfg(test)]").next())
        .expect("issuance core must precede test-only fixture adapters");
    for forbidden in [
        "TestInfrastructure",
        "state.settings",
        "state.diesel_db",
        "state.valkey_connection",
        "TokenIssuanceRepository::new",
        "TokenIssuanceStateAdapter::new",
    ] {
        assert!(
            !core.contains(forbidden),
            "shared issuance core reintroduced {forbidden}"
        );
    }
}

#[test]
fn device_transport_uses_focused_composition_root_dependencies() {
    let source = include_str!("../../../../src/http/token/device.rs");
    for forbidden in [
        "Data<TestInfrastructure>",
        "Settings",
        "DeviceStore::new",
        "AuthorizationFlowRepository::new",
        "state.diesel_db",
        "state.valkey_connection()",
    ] {
        assert!(
            !source.contains(forbidden),
            "device transport reintroduced composition dependency {forbidden}"
        );
    }
    for required in [
        "Data<ServerDeviceGrantService>",
        "Data<DeviceHttpConfig>",
        "Data<SessionProfileHandles>",
        "Data<TokenManagementRequestLimiter>",
        "Data<ServerRuntimeModuleRegistry>",
    ] {
        assert!(
            source.contains(required),
            "device transport lost focused dependency {required}"
        );
    }
}

#[test]
fn ciba_decision_transport_uses_focused_composition_root_dependencies() {
    let source = include_str!("../../../../src/http/token/ciba.rs");
    for forbidden in [
        "Data<TestInfrastructure>",
        "state.permits_existing_module_transaction",
        "client_ip(&req, &state.settings)",
        "has_valid_csrf_token(&state",
        "current_user_or_login_required(&state",
    ] {
        assert!(
            !source.contains(forbidden),
            "CIBA decision transport reintroduced composition dependency {forbidden}"
        );
    }
    for required in [
        "Data<ServerCibaService>",
        "Data<CibaHttpConfig>",
        "Data<AdminSessionHandles>",
        "Data<ServerRuntimeModuleRegistry>",
    ] {
        assert!(
            source.contains(required),
            "CIBA decision transport lost focused dependency {required}"
        );
    }
}

#[test]
fn device_token_issuance_handoff_uses_focused_context_and_services() {
    let source = include_str!("../../../../src/http/token/device_issuance.rs");
    assert!(source.contains("device_service: &ServerDeviceGrantService"));
    assert!(source.contains("token_service: &ServerTokenService"));
    assert!(source.contains("issuance: &TokenIssuanceContext<'_>"));
    assert!(source.contains("issue_token_response_with_service"));
    assert!(source.contains("validate_dpop_proof_with_authorization_service"));
    assert!(source.contains("consume_token_client_assertion_with_authorization_service"));
    for forbidden in [
        "TestInfrastructure",
        "Settings",
        "state.settings",
        "DeviceStore::new",
        "DeviceGrantService::new",
        "TokenIssuanceRepository::new",
        "TokenIssuanceStateAdapter::new",
        "nazo_postgres",
        "nazo_valkey",
    ] {
        assert!(
            !source.contains(forbidden),
            "device issuance handoff reintroduced direct infrastructure {forbidden}"
        );
    }
}
