use actix_web::{
    App,
    cookie::Cookie,
    http::{Method, header},
    middleware::from_fn,
    test as actix_test, web,
};

use crate::security_headers;

use super::*;

#[derive(Clone)]
struct TestOperations {
    availability: SessionManagementAvailability,
    origin_allowed: bool,
    op_browser_state: Result<Option<String>, SessionManagementError>,
}

impl SessionManagementOperations for TestOperations {
    fn availability(&self) -> SessionManagementAvailability {
        self.availability
    }

    fn is_origin_allowed<'a>(
        &'a self,
        _client_id: &'a str,
        _origin: &'a str,
    ) -> SessionManagementOriginFuture<'a> {
        let allowed = self.origin_allowed;
        Box::pin(async move { Ok(allowed) })
    }

    fn op_browser_state<'a>(&'a self, _session_id: &'a str) -> SessionManagementFuture<'a> {
        let result = self.op_browser_state.clone();
        Box::pin(async move { result })
    }
}

fn endpoint(availability: SessionManagementAvailability) -> Data<SessionManagementEndpoint> {
    Data::new(SessionManagementEndpoint::new(
        Arc::new(TestOperations {
            availability,
            origin_allowed: true,
            op_browser_state: Ok(Some("opbs-1".to_owned())),
        }),
        SessionManagementConfig::new("https://issuer.example", "sid"),
    ))
}

#[test]
fn iframe_document_escapes_executable_string_context() {
    let html = session_management_iframe_document(
        "https://issuer.example/check?x=1&y='z'\u{2028}</script>",
    );
    assert!(html.contains("x=1\\u0026y=\\'z\\'\\u2028\\u003c/script\\u003e"));
    assert!(!html.contains("</script></script>"));
    assert!(html.contains("new XMLHttpRequest()"));
    assert!(!html.contains("fetch("));
}

#[actix_web::test]
async fn disabled_enabled_and_draining_route_contracts_are_stable() {
    for (availability, enabled) in [
        (SessionManagementAvailability::Disabled, false),
        (SessionManagementAvailability::Enabled, true),
        (SessionManagementAvailability::Draining, true),
    ] {
        let app = actix_test::init_service(
            App::new()
                .wrap(from_fn(security_headers))
                .app_data(endpoint(availability))
                .route("/check_session", web::get().to(check_session_iframe))
                .route("/check_session/status", web::get().to(check_session_status)),
        )
        .await;

        for (uri, iframe) in [
            ("/check_session", true),
            (
                "/check_session/status?client_id=client-1&origin=https%3A%2F%2Fclient.example&session_state=invalid.salt",
                false,
            ),
        ] {
            for method in [Method::GET, Method::POST, Method::OPTIONS] {
                let mut request = actix_test::TestRequest::default()
                    .method(method.clone())
                    .uri(uri)
                    .insert_header((header::ORIGIN, "https://client.example"));
                if !iframe {
                    request = request.cookie(Cookie::new("sid", "session-1"));
                }
                let response = actix_test::call_service(&app, request.to_request()).await;
                let served = method == Method::GET && enabled;
                assert_eq!(
                    response.status(),
                    if served {
                        StatusCode::OK
                    } else {
                        StatusCode::NOT_FOUND
                    },
                    "{availability:?} {method} {uri}"
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
                    response.headers().get("Referrer-Policy").unwrap(),
                    "no-referrer"
                );
                if served {
                    assert_eq!(
                        response.headers().get(header::CACHE_CONTROL).unwrap(),
                        "no-store"
                    );
                    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
                } else {
                    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
                    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
                }
                if iframe {
                    assert!(response.headers().get(header::X_FRAME_OPTIONS).is_none());
                } else {
                    assert_eq!(
                        response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
                        "DENY"
                    );
                }
            }
        }
    }
}

#[actix_web::test]
async fn status_is_unchanged_only_for_the_bound_live_session() {
    let state = nazo_auth::issue_oidc_session_state(
        "client-1",
        "https://client.example/callback",
        "opbs-1",
    )
    .expect("HTTPS callback has a browser origin");
    let uri = format!(
        "/check_session/status?client_id=client-1&origin=https%3A%2F%2Fclient.example&session_state={state}"
    );
    let app = actix_test::init_service(
        App::new()
            .app_data(endpoint(SessionManagementAvailability::Enabled))
            .route("/check_session/status", web::get().to(check_session_status)),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri(&uri)
            .cookie(Cookie::new("sid", "session-1"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        actix_test::read_body(response).await,
        r#"{"status":"unchanged"}"#.as_bytes()
    );
}

#[actix_web::test]
async fn status_rejects_an_origin_not_registered_for_the_client() {
    let state = nazo_auth::issue_oidc_session_state(
        "client-1",
        "https://client.example/callback",
        "opbs-1",
    )
    .expect("HTTPS callback has a browser origin");
    let operations = Arc::new(TestOperations {
        availability: SessionManagementAvailability::Enabled,
        origin_allowed: false,
        op_browser_state: Ok(Some("opbs-1".to_owned())),
    });
    let endpoint = Data::new(SessionManagementEndpoint::new(
        operations,
        SessionManagementConfig::new("https://issuer.example", "sid"),
    ));
    let app = actix_test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/check_session/status", web::get().to(check_session_status)),
    )
    .await;
    let uri = format!(
        "/check_session/status?client_id=client-1&origin=https%3A%2F%2Fclient.example&session_state={state}"
    );
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri(&uri)
            .cookie(Cookie::new("sid", "session-1"))
            .to_request(),
    )
    .await;
    assert_eq!(
        actix_test::read_body(response).await,
        r#"{"status":"error"}"#.as_bytes()
    );
}
