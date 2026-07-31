use super::*;
use actix_web::http::header;
use actix_web::{HttpResponse, test as actix_test};

#[test]
fn production_bootstrap_only_publishes_focused_application_data() {
    let source = include_str!("../../src/bootstrap/mod.rs");

    assert!(
        !source.contains("web::Data::new(TestInfrastructure"),
        "production bootstrap must not reconstruct the giant TestInfrastructure"
    );
    assert!(
        !source.contains(".app_data(state"),
        "production Actix app must not publish the giant TestInfrastructure"
    );
}

#[actix_web::test]
async fn security_headers_are_added_to_core_responses() {
    let app = actix_test::init_service(App::new().wrap(from_fn(security_headers)).route(
        "/ok",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = actix_test::TestRequest::get().uri("/ok").to_request();
    let response = actix_test::call_service(&app, request).await;
    let headers = response.headers();

    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get("Referrer-Policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("Permissions-Policy").unwrap(),
        "interest-cohort=()"
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert!(
        headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[actix_web::test]
async fn bundled_ui_serves_assets_and_spa_routes_without_masking_missing_assets() {
    let root = std::env::temp_dir().join(format!("nazoauth-ui-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(root.join("assets")).unwrap();
    std::fs::write(
        root.join("index.html"),
        "<!doctype html><title>NazoAuth</title>",
    )
    .unwrap();
    std::fs::write(root.join("assets/app.js"), "console.log('nazoauth');").unwrap();

    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(security_headers))
            .service(ui_static_files(root.clone())),
    )
    .await;

    for path in ["/ui/", "/ui/auth", "/ui/assets/app.js"] {
        let response =
            actix_test::call_service(&app, actix_test::TestRequest::get().uri(path).to_request())
                .await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK, "{path}");
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
    }

    let missing_asset = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/ui/assets/missing.js")
            .to_request(),
    )
    .await;
    assert_eq!(
        missing_asset.status(),
        actix_web::http::StatusCode::NOT_FOUND
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn check_session_iframe_is_frameable_by_relying_parties() {
    let app = actix_test::init_service(App::new().wrap(from_fn(security_headers)).route(
        "/check_session",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/check_session")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    let headers = response.headers();

    assert!(headers.get(header::X_FRAME_OPTIONS).is_none());
    assert!(
        !headers
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[actix_web::test]
async fn fapi_resource_static_route_rejects_options_without_cors_and_keeps_security_headers() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(security_headers))
            .configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    for method in [
        actix_web::http::Method::OPTIONS,
        actix_web::http::Method::PUT,
        actix_web::http::Method::DELETE,
    ] {
        let response = actix_test::call_service(
            &app,
            actix_test::TestRequest::default()
                .method(method)
                .uri("/fapi/resource")
                .insert_header((header::ORIGIN, "https://browser.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .to_request(),
        )
        .await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
    }
}

#[actix_web::test]
async fn openid4vci_dataset_route_is_nested_inside_the_admin_scope() {
    let config = crate::config::ConfigSource::from_pairs_for_test([
        ("ENABLE_OPENID4VCI_ISSUER", "true"),
        (
            "OPENID4VC_DATA_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "runtime/openid4vc-chain.pem",
        ),
        (
            "OPENID4VC_TRUST_ANCHORS_FILE",
            "runtime/openid4vc-roots.pem",
        ),
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON",
            r#"{"pid":{"format":"dc+sd-jwt","scope":"pid","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"vct":"https://issuer.example/credentials/pid"}}"#,
        ),
        (
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
            "openid4vci-management-token-at-least-32-bytes",
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let app = actix_test::init_service(
        App::new().configure(|cfg| routes::configure(cfg, &settings, false)),
    )
    .await;

    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/admin/openid4vci/credential-datasets/00000000-0000-0000-0000-000000000123/pid")
            .to_request(),
    )
    .await;

    assert_ne!(
        response.status(),
        actix_web::http::StatusCode::NOT_FOUND,
        "the generic /admin scope must not shadow the OpenID4VCI dataset route",
    );
}
