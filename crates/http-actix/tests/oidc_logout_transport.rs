use std::sync::{Arc, Mutex};

use actix_web::{
    App,
    http::{Method, StatusCode, header},
    test, web,
};
use nazo_http_actix::{
    OidcLogoutCommand, OidcLogoutConfig, OidcLogoutEndpoint, OidcLogoutError, OidcLogoutFuture,
    OidcLogoutOperations, OidcLogoutSuccess, oidc_logout,
};

struct Operations {
    result: Mutex<Result<OidcLogoutSuccess, OidcLogoutError>>,
    commands: Mutex<Vec<OidcLogoutCommand>>,
}

impl OidcLogoutOperations for Operations {
    fn logout(&self, command: OidcLogoutCommand) -> OidcLogoutFuture<'_> {
        self.commands.lock().unwrap().push(command);
        let result = self.result.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

fn operations(result: Result<OidcLogoutSuccess, OidcLogoutError>) -> Arc<Operations> {
    Arc::new(Operations {
        result: Mutex::new(result),
        commands: Mutex::new(Vec::new()),
    })
}

fn endpoint(operations: Arc<Operations>) -> OidcLogoutEndpoint {
    OidcLogoutEndpoint::new(operations, OidcLogoutConfig::new("session", "csrf", true))
}

#[actix_web::test]
async fn get_and_form_post_preserve_parser_cookie_and_no_store_contracts() {
    let operations = operations(Ok(OidcLogoutSuccess {
        redirect_uri: None,
        frontchannel_logout_urls: Vec::new(),
    }));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint(operations.clone())))
            .service(
                web::resource("/logout")
                    .route(web::get().to(oidc_logout))
                    .route(web::post().to(oidc_logout)),
            ),
    )
    .await;

    for request in [
        test::TestRequest::get()
            .uri("/logout?client_id=%20client-a%20&unknown=ignored")
            .cookie(actix_web::cookie::Cookie::new("session", "sid"))
            .cookie(actix_web::cookie::Cookie::new("csrf", "csrf-value"))
            .insert_header(("x-csrf-token", "csrf-value"))
            .to_request(),
        test::TestRequest::post()
            .uri("/logout?client_id=client-a")
            .insert_header((
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            ))
            .set_payload("state=state-a")
            .to_request(),
    ] {
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(response.headers());
        assert_eq!(response.response().cookies().count(), 2);
    }
    let commands = operations.commands.lock().unwrap();
    assert_eq!(commands[0].request.client_id.as_deref(), Some("client-a"));
    assert_eq!(commands[0].session_id.as_deref(), Some("sid"));
    assert!(commands[0].csrf_authorized);
    assert_eq!(commands[1].request.state.as_deref(), Some("state-a"));
}

#[actix_web::test]
async fn malformed_posts_fail_before_operations_and_do_not_clear_retryable_cookies() {
    let operations = operations(Ok(OidcLogoutSuccess {
        redirect_uri: None,
        frontchannel_logout_urls: Vec::new(),
    }));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint(operations.clone())))
            .route("/logout", web::post().to(oidc_logout)),
    )
    .await;

    let cases = [
        (
            test::TestRequest::post()
                .uri("/logout")
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload("{}")
                .to_request(),
            StatusCode::BAD_REQUEST,
        ),
        (
            test::TestRequest::post()
                .uri("/logout?client_id=a")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload("client_id=b")
                .to_request(),
            StatusCode::BAD_REQUEST,
        ),
        (
            test::TestRequest::post()
                .uri("/logout")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload(format!("state={}", "x".repeat(16 * 1024)))
                .to_request(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ];
    for (request, expected) in cases {
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), expected);
        assert_eq!(response.response().cookies().count(), 0);
    }
    assert!(operations.commands.lock().unwrap().is_empty());
}

#[actix_web::test]
async fn frontchannel_document_escapes_urls_and_redirect_and_clears_cookies() {
    let operations = operations(Ok(OidcLogoutSuccess {
        redirect_uri: Some("https://client.example/after?x='</script>&".to_owned()),
        frontchannel_logout_urls: vec!["https://client.example/front?x=\"<&".to_owned()],
    }));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint(operations)))
            .route("/logout", web::get().to(oidc_logout)),
    )
    .await;
    let response =
        test::call_service(&app, test::TestRequest::get().uri("/logout").to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static(
            "text/html; charset=utf-8"
        ))
    );
    assert_no_store(response.headers());
    let cookies = response.response().cookies().count();
    let body = test::read_body(response).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(cookies, 2);
    assert!(body.contains("&quot;&lt;&amp;"));
    assert!(body.contains("\\'\\u003c/script\\u003e\\u0026"));
    assert!(!body.contains("'</script>"));
}

#[actix_web::test]
async fn valkey_delete_failure_is_retryable_and_never_clears_cookies() {
    let operations = operations(Err(OidcLogoutError::SessionDeleteUnavailable));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint(operations)))
            .route("/logout", web::get().to(oidc_logout)),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::default()
            .method(Method::GET)
            .uri("/logout")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(response.headers());
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/json"))
    );
    assert_eq!(response.response().cookies().count(), 0);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(
        body,
        serde_json::json!({
            "error": "server_error",
            "error_description": "back-channel logout persistence failed."
        })
    );
}

#[actix_web::test]
async fn options_remains_unhandled_and_never_invokes_logout_operations() {
    let operations = operations(Ok(OidcLogoutSuccess {
        redirect_uri: None,
        frontchannel_logout_urls: Vec::new(),
    }));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint(operations.clone())))
            .service(
                web::resource("/logout")
                    .route(web::get().to(oidc_logout))
                    .route(web::post().to(oidc_logout)),
            ),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/logout")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.response().cookies().count(), 0);
    assert!(operations.commands.lock().unwrap().is_empty());
}

fn assert_no_store(headers: &header::HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        headers.get(header::PRAGMA),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
}
