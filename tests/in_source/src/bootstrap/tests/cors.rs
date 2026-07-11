use super::*;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use std::path::PathBuf;

use crate::bootstrap::routes;
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, FederationSettings,
    PasskeySettings, RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
};
use crate::support::ClientIpHeaderMode;

#[actix_web::test]
async fn cors_preflight_allows_only_configured_origin_methods_and_security_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_browser_oauth(&settings)).route(
        "/token",
        web::post().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "dpop, x-csrf-token"))
        .to_request();
    let response = test::call_service(&app, allowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "cors_browser_oauth must NOT allow credentials (no cookies)"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("dpop"),
        "DPoP proofs must be explicitly allowed for browser token requests"
    );

    let denied = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://attacker.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .to_request();
    let response = test::call_service(&app, denied).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "unregistered browser origins must not receive CORS authorization"
    );
}

#[actix_web::test]
async fn authorization_endpoint_is_not_cors_enabled() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    let request = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/authorize")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "authorization endpoint must not answer browser CORS preflight"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "authorization endpoint must not expose itself to browser XHR through CORS"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "authorization endpoint must not allow credentialed CORS"
    );
}

#[actix_web::test]
async fn dynamic_client_registration_route_is_absent_when_disabled() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    let request = test::TestRequest::post()
        .uri("/register")
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("not json")
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "disabled dynamic registration must not expose a JSON parsing route"
    );
}

#[actix_web::test]
async fn openid_federation_route_is_not_registered() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    let request = test::TestRequest::get()
        .uri("/.well-known/openid-federation")
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "OpenID Federation is not part of the product surface"
    );
}

#[actix_web::test]
async fn perf_metrics_route_is_controlled_by_the_typed_startup_flag() {
    let settings = test_settings(Vec::new());
    let disabled =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;
    let response = test::call_service(
        &disabled,
        test::TestRequest::get().uri("/__perf/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let enabled =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, true)))
            .await;
    let response = test::call_service(
        &enabled,
        test::TestRequest::get().uri("/__perf/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn cors_actual_response_exposes_oauth_challenge_nonce_and_retry_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_browser_oauth(&settings)).route(
        "/resource",
        web::get().to(|| async {
            HttpResponse::Unauthorized()
                .insert_header((header::WWW_AUTHENTICATE, "DPoP error=\"use_dpop_nonce\""))
                .insert_header(("dpop-nonce", "nonce-1"))
                .insert_header((header::RETRY_AFTER, "5"))
                .finish()
        }),
    ))
    .await;

    let request = test::TestRequest::get()
        .uri("/resource")
        .insert_header((header::ORIGIN, "https://app.example"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let expose = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(expose.contains("www-authenticate"));
    assert!(expose.contains("dpop-nonce"));
    assert!(expose.contains("retry-after"));
}

#[actix_web::test]
async fn cors_well_known_allows_get_and_head_only() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_well_known(&settings)).route(
        "/.well-known/openid-configuration",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/.well-known/openid-configuration")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .to_request();
    let response = test::call_service(&app, allowed).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "cors_well_known must NOT allow credentials"
    );
}

#[actix_web::test]
async fn cors_admin_allows_csrf_header_for_credentialed_write_requests() {
    let settings = test_settings(vec!["https://admin.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_admin(&settings)).route(
        "/admin/clients",
        web::post().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/admin/clients")
        .insert_header((header::ORIGIN, "https://admin.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-csrf-token")
    );
}

#[actix_web::test]
async fn cors_auth_api_credentials_are_limited_to_configured_origins_and_csrf_headers() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_auth_api(&settings)).route(
        "/auth/me",
        web::patch().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, allowed).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-csrf-token"),
        "credentialed auth API writes must allow only explicit CSRF-bearing CORS requests"
    );

    let denied = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://attacker.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, denied).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "credentialed auth API CORS must not authorize unregistered browser origins"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "credentialed auth API CORS must not expose cookies to unregistered origins"
    );
}

#[actix_web::test]
async fn cors_scim_allows_put_without_browser_credentials() {
    let settings = test_settings(vec!["https://scim-admin.example".to_owned()]);
    let app = test::init_service(App::new().wrap(cors_scim(&settings)).route(
        "/scim/v2/Users/user-1",
        web::put().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/scim/v2/Users/user-1")
        .insert_header((header::ORIGIN, "https://scim-admin.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PUT"))
        .insert_header((
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization, content-type",
        ))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "SCIM uses bearer authentication and must not authorize browser credentials"
    );
}

fn test_settings(cors_allowed_origins: Vec<String>) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins,
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "session".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 28_800,
        auth_code_ttl_seconds: 300,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        client_secret_pepper: "client-secret-pepper-for-tests-000000000001".to_owned(),
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
            login_failure_window_seconds: 900,
            login_failure_email_max_attempts: 50,
            login_failure_ip_email_max_attempts: 5,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: Vec::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: FederationSettings {
            providers: crate::settings::FederationProviderRegistry::default(),
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
        enable_device_authorization_grant: false,
        enable_dynamic_client_registration: false,
        enable_frontchannel_logout: false,
        enable_session_management: false,
        enable_ciba: false,
        enable_native_sso: false,
        dynamic_client_registration_initial_access_token: None,
        device_authorization_ttl_seconds: 600,
        device_authorization_poll_interval_seconds: 5,
        ciba_auth_req_id_ttl_seconds: 600,
        ciba_poll_interval_seconds: 5,
        ciba_automated_decision_token: None,
    }
}
