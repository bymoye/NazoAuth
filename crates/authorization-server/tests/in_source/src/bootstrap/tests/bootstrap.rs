use super::*;
use actix_web::{HttpResponse, test as actix_test};

#[test]
fn production_bootstrap_only_publishes_focused_application_data() {
    let source = include_str!("../../../../../src/bootstrap/mod.rs");

    assert!(
        !source.contains("web::Data::new(TestAppState"),
        "production bootstrap must not reconstruct the giant TestAppState"
    );
    assert!(
        !source.contains(".app_data(state"),
        "production Actix app must not publish the giant TestAppState"
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
