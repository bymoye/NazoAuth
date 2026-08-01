use super::*;
use actix_web::{App, test, web};

#[derive(Clone)]
struct FakeOperations(Result<UserinfoSuccess, UserinfoError>);

impl UserinfoOperations for FakeOperations {
    fn userinfo<'a>(
        &'a self,
        _request: &'a HttpRequest,
        _scheme: AccessTokenAuthScheme,
        _token: String,
    ) -> UserinfoFuture<'a> {
        let result = self.0.clone();
        Box::pin(async move { result })
    }
}

fn endpoint(result: Result<UserinfoSuccess, UserinfoError>) -> UserinfoEndpoint {
    UserinfoEndpoint::new(Arc::new(FakeOperations(result)))
}

#[actix_web::test]
async fn missing_and_conflicting_token_transport_keep_exact_bearer_contract() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(Err(UserinfoError::InvalidAccessToken))))
            .route("/userinfo", web::get().to(userinfo))
            .route("/userinfo", web::post().to(userinfo)),
    )
    .await;

    let missing = test::call_service(
        &service,
        test::TestRequest::get().uri("/userinfo").to_request(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert_eq!(
        missing.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let conflicting = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, "Bearer header-token"))
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("access_token=body-token")
            .to_request(),
    )
    .await;
    assert_eq!(conflicting.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        conflicting.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_request", error_description="Only one access token transport method may be used.""#
    );
}

#[actix_web::test]
async fn json_success_is_no_store_and_returns_next_dpop_nonce() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(Ok(UserinfoSuccess {
                representation: UserinfoRepresentation::Claims(serde_json::json!({
                    "sub": "subject"
                })),
                dpop_nonce: Some("next-nonce".to_owned()),
            }))))
            .route("/userinfo", web::get().to(userinfo)),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::get()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, "DPoP access-token"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(response.headers().get("dpop-nonce").unwrap(), "next-nonce");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        test::read_body_json::<Value, _>(response).await,
        serde_json::json!({"sub": "subject"})
    );
}

#[actix_web::test]
async fn protected_success_keeps_jwt_media_type_and_cache_headers() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(Ok(UserinfoSuccess {
                representation: UserinfoRepresentation::Jwt("signed.jwt".to_owned()),
                dpop_nonce: None,
            }))))
            .route("/userinfo", web::post().to(userinfo)),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/userinfo")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("access_token=access-token")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/jwt"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(test::read_body(response).await, "signed.jwt");
}

#[actix_web::test]
async fn use_dpop_nonce_keeps_challenge_and_nonce_headers() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(Err(UserinfoError::Dpop(
                UserinfoDpopError::UseNonce("required-nonce".to_owned()),
            )))))
            .route("/userinfo", web::get().to(userinfo)),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::get()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, "DPoP access-token"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"DPoP error="use_dpop_nonce""#
    );
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        "required-nonce"
    );
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "use_dpop_nonce");
}

#[actix_web::test]
async fn error_mapping_preserves_bearer_status_and_code() {
    let cases = [
        (
            UserinfoError::InvalidAudience,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
        ),
        (
            UserinfoError::InsufficientScope,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        ),
        (
            UserinfoError::QueryUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
        (
            UserinfoError::ResponseProtectionFailed,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
    ];
    for (error, status, error_code) in cases {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(Err(error))))
                .route("/userinfo", web::get().to(userinfo)),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::get()
                .uri("/userinfo")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), status);
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], error_code);
    }
}
