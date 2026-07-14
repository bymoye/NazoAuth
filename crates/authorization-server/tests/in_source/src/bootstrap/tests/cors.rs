use super::*;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use chrono::{TimeZone, Utc};
use nazo_http_actix::{
    ProfileAccountEndpoint, ProfileAccountFuture, ProfileAccountOperations, ProfileMe,
    SessionCookieConfig,
};
use nazo_identity::{
    AccountProfileView, AuthorizedApplicationView, AuthorizedApplicationsView, ProfilePatch,
    SessionId,
};
use std::sync::Arc;

use crate::bootstrap::routes;
use crate::domain::{DynamicRegistrationHandles, TestAppState};

struct ContractProfileOperations;

impl ProfileAccountOperations for ContractProfileOperations {
    fn me(&self, _session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe> {
        Box::pin(async { Ok(ProfileMe::Active(Box::new(contract_profile()))) })
    }

    fn update(
        &self,
        _session_id: SessionId,
        _patch: ProfilePatch,
    ) -> ProfileAccountFuture<'_, AccountProfileView> {
        Box::pin(async { Ok(contract_profile()) })
    }

    fn applications(
        &self,
        _session_id: SessionId,
    ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView> {
        Box::pin(async {
            Ok(AuthorizedApplicationsView {
                total: 1,
                items: vec![AuthorizedApplicationView {
                    client_id: "contract-client".to_owned(),
                    client_name: "Contract Client".to_owned(),
                    last_scopes: vec!["openid".to_owned()],
                    last_authorized_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                    authorization_count: 1,
                }],
            })
        })
    }
}

fn contract_profile() -> AccountProfileView {
    AccountProfileView {
        id: uuid::Uuid::from_u128(1),
        email: "alice@example.test".to_owned(),
        display_name: Some("Alice".to_owned()),
        avatar_url: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile_url: None,
        website_url: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        mfa_enabled: false,
        role: "user",
        admin_level: 0,
        authorized_app_count: 1,
    }
}

fn assert_profile_security_headers(headers: &header::HeaderMap) {
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    );
}
#[actix_web::test]
async fn browser_token_management_cors_allows_post_dpop_without_credentials() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let app = test::init_service(
        App::new()
            .wrap(cors_browser_token_management(&settings))
            .route(
                "/token",
                web::post().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;

    let allowed = test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/token")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type, dpop"))
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
        "browser token management must NOT allow credentials (no cookies)"
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
async fn browser_userinfo_cors_allows_get_and_post_bearer_or_dpop() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    for method in ["GET", "POST"] {
        let app = test::init_service(
            App::new()
                .wrap(cors_browser_userinfo(&settings))
                .route(
                    "/userinfo",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                )
                .route(
                    "/userinfo",
                    web::post().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/userinfo")
            .insert_header((header::ORIGIN, "https://app.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization, dpop",
            ))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "method={method}");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }
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
async fn disabled_dynamic_client_registration_keeps_the_static_route_contract() {
    let settings = Arc::new(test_settings(vec!["https://app.example".to_owned()]));
    let state = web::Data::new(TestAppState {
        diesel_db: nazo_postgres::create_pool(
            "postgres://disabled_dcr:disabled_dcr@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("test pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("test Valkey client construction should not connect"),
        settings: settings.clone(),
        keyset: crate::test_support::test_key_manager(),
    });
    let dynamic_registration_handles =
        web::Data::new(DynamicRegistrationHandles::from_app_state(state.get_ref()));
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::from_fn(
                nazo_http_actix::security_headers,
            ))
            .app_data(state)
            .app_data(dynamic_registration_handles)
            .configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    let requests = [
        (
            actix_web::http::Method::POST,
            "/register",
            StatusCode::NOT_FOUND,
        ),
        (
            actix_web::http::Method::GET,
            "/register/client-test",
            StatusCode::NOT_FOUND,
        ),
        (
            actix_web::http::Method::PUT,
            "/register/client-test",
            StatusCode::NOT_FOUND,
        ),
        (
            actix_web::http::Method::DELETE,
            "/register/client-test",
            StatusCode::NOT_FOUND,
        ),
        (
            actix_web::http::Method::OPTIONS,
            "/register",
            StatusCode::NOT_FOUND,
        ),
    ];

    for (method, uri, expected_status) in requests {
        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(method)
                .uri(uri)
                .insert_header((header::ORIGIN, "https://browser.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .insert_header((header::CONTENT_TYPE, "text/plain"))
                .set_payload("not json")
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), expected_status, "{uri}");
        assert!(
            response.headers().get(header::CONTENT_TYPE).is_none(),
            "{uri}"
        );
        assert!(
            response.headers().get(header::CACHE_CONTROL).is_none(),
            "{uri}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "{uri}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "{uri}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff",
            "{uri}"
        );
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY",
            "{uri}"
        );
        assert_eq!(
            response.headers().get("Referrer-Policy").unwrap(),
            "no-referrer",
            "{uri}"
        );
        assert_eq!(
            response.headers().get("Permissions-Policy").unwrap(),
            "interest-cohort=()",
            "{uri}"
        );
        assert!(
            response
                .headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "{uri}"
        );
        let body = test::read_body(response).await;
        assert_eq!(body.as_ref(), b"", "{uri}");
    }
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
    let app = test::init_service(App::new().wrap(cors_browser_userinfo(&settings)).route(
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
async fn production_profile_routes_keep_method_cors_cache_and_security_contracts() {
    let settings = test_settings(vec!["https://app.example".to_owned()]);
    let endpoint = ProfileAccountEndpoint::new(
        Arc::new(ContractProfileOperations),
        SessionCookieConfig::new("session", "csrf", true),
    );
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::from_fn(
                nazo_http_actix::security_headers,
            ))
            .app_data(web::Data::new(endpoint))
            .configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    let get = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://app.example"))
        .cookie(actix_web::cookie::Cookie::new("session", "sid"))
        .to_request();
    let get = test::call_service(&app, get).await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        get.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(get.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        get.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert_eq!(
        get.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert_profile_security_headers(get.headers());
    let get_body: serde_json::Value = test::read_body_json(get).await;
    assert_eq!(get_body["email"], "alice@example.test");
    assert_eq!(get_body["mfa_required"], false);
    assert!(get_body.get("csrf_token").is_none());

    let patch = test::TestRequest::patch()
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header(("x-csrf-token", "csrf-token"))
        .cookie(actix_web::cookie::Cookie::new("session", "sid"))
        .cookie(actix_web::cookie::Cookie::new("csrf", "csrf-token"))
        .set_json(serde_json::json!({"display_name": "Alice"}))
        .to_request();
    let patch = test::call_service(&app, patch).await;
    assert_eq!(patch.status(), StatusCode::OK);
    assert_eq!(
        patch.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        patch.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(patch.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        patch
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert_profile_security_headers(patch.headers());
    let patch_body: serde_json::Value = test::read_body_json(patch).await;
    assert_eq!(patch_body["display_name"], "Alice");
    assert!(patch_body.get("mfa_required").is_none());

    let applications = test::TestRequest::get()
        .uri("/auth/me/applications")
        .insert_header((header::ORIGIN, "https://app.example"))
        .cookie(actix_web::cookie::Cookie::new("session", "sid"))
        .to_request();
    let applications = test::call_service(&app, applications).await;
    assert_eq!(applications.status(), StatusCode::OK);
    assert_eq!(
        applications.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        applications.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        applications
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert_profile_security_headers(applications.headers());
    let applications_body: serde_json::Value = test::read_body_json(applications).await;
    assert_eq!(applications_body["total"], 1);
    assert_eq!(
        applications_body["items"][0]["client_id"],
        "contract-client"
    );

    let post = test::TestRequest::post()
        .uri("/auth/me")
        .insert_header((header::ORIGIN, "https://app.example"))
        .to_request();
    let post = test::call_service(&app, post).await;
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
    assert!(post.headers().get(header::CONTENT_TYPE).is_none());
    assert!(post.headers().get(header::CACHE_CONTROL).is_none());
    assert_eq!(
        post.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert_profile_security_headers(post.headers());
    assert!(test::read_body(post).await.is_empty());

    for method in ["GET", "PATCH"] {
        let options = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/auth/me")
            .insert_header((header::ORIGIN, "https://app.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "x-csrf-token, content-type",
            ))
            .to_request();
        let options = test::call_service(&app, options).await;
        assert_eq!(options.status(), StatusCode::OK, "method={method}");
        assert!(options.headers().get(header::CONTENT_TYPE).is_none());
        assert!(options.headers().get(header::CACHE_CONTROL).is_none());
        assert_eq!(
            options
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_eq!(
            options
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
        assert_profile_security_headers(options.headers());
        assert!(test::read_body(options).await.is_empty());
    }
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

#[actix_web::test]
async fn production_token_route_rejects_get_csrf_and_unknown_origins() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    for (origin, method, headers) in [
        ("https://spa.example", "GET", "content-type"),
        ("https://spa.example", "POST", "x-csrf-token"),
        ("https://attacker.example", "POST", "content-type"),
    ] {
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/token")
            .insert_header((header::ORIGIN, origin))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, headers))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "token preflight must reject origin={origin}, method={method}, headers={headers}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "rejected token preflight must not authorize its origin"
        );
    }
}

#[actix_web::test]
async fn production_browser_oauth_routes_expose_only_required_cors() {
    let settings = test_settings(vec!["https://spa.example".to_owned()]);
    let app =
        test::init_service(App::new().configure(|cfg| routes::configure(cfg, &settings, false)))
            .await;

    for (path, method, headers) in [
        ("/token", "POST", "content-type, dpop"),
        ("/revoke", "POST", "content-type, authorization, dpop"),
        ("/userinfo", "GET", "authorization, dpop"),
        ("/userinfo", "POST", "authorization, content-type, dpop"),
    ] {
        let request = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri(path)
            .insert_header((header::ORIGIN, "https://spa.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
            .insert_header((header::ACCESS_CONTROL_REQUEST_HEADERS, headers))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "{path} {method}");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "public browser OAuth routes must not authorize cookies"
        );
    }
}

fn test_settings(cors_allowed_origins: Vec<String>) -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://issuer.example".to_owned();
    settings.endpoint.frontend_base_url = "https://app.example".to_owned();
    settings.endpoint.cors_allowed_origins = cors_allowed_origins;
    settings.session.cookie_secure = true;
    settings
}
