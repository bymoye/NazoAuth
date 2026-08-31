use super::*;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};

#[actix_web::test]
async fn dynamic_origin_predicate_keeps_the_token_endpoint_policy() {
    let app = test::init_service(
        App::new()
            .wrap(cors_browser_token_management_with_origin_predicate(
                |origin, request| {
                    origin == "https://app.tenant-a.example"
                        && request
                            .headers
                            .get(header::HOST)
                            .is_some_and(|host| host == "tenant-a.example")
                },
            ))
            .route("/token", web::post().to(HttpResponse::NoContent)),
    )
    .await;

    let allowed = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/token")
            .insert_header((header::HOST, "tenant-a.example"))
            .insert_header((header::ORIGIN, "https://app.tenant-a.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request(),
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("https://app.tenant-a.example"))
    );

    let wrong_tenant = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/token")
            .insert_header((header::HOST, "tenant-b.example"))
            .insert_header((header::ORIGIN, "https://app.tenant-a.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request(),
    )
    .await;
    assert_eq!(wrong_tenant.status(), StatusCode::BAD_REQUEST);

    let wrong_method = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/token")
            .insert_header((header::HOST, "tenant-a.example"))
            .insert_header((header::ORIGIN, "https://app.tenant-a.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
            .to_request(),
    )
    .await;
    assert_eq!(wrong_method.status(), StatusCode::BAD_REQUEST);
}
