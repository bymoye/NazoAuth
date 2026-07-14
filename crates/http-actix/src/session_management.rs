use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Query},
};
use nazo_auth::{OidcSessionStatus, check_oidc_session_state};
use serde::Deserialize;
use serde_json::json;

use crate::{cookie_value, empty_response, json_response_no_store};

pub type SessionManagementFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, SessionManagementError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionManagementAvailability {
    Disabled,
    Enabled,
    Draining,
}

impl SessionManagementAvailability {
    const fn permits_existing_transaction(self) -> bool {
        matches!(self, Self::Enabled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionManagementError {
    SessionLookupUnavailable,
}

/// Storage and runtime-module boundary required by the session-management transport.
pub trait SessionManagementOperations: Send + Sync {
    fn availability(&self) -> SessionManagementAvailability;

    fn op_browser_state<'a>(&'a self, session_id: &'a str) -> SessionManagementFuture<'a>;
}

#[derive(Clone)]
pub struct SessionManagementConfig {
    issuer: Box<str>,
    session_cookie_name: Box<str>,
}

impl SessionManagementConfig {
    #[must_use]
    pub fn new(issuer: impl Into<Box<str>>, session_cookie_name: impl Into<Box<str>>) -> Self {
        Self {
            issuer: issuer.into(),
            session_cookie_name: session_cookie_name.into(),
        }
    }
}

#[derive(Clone)]
pub struct SessionManagementEndpoint {
    operations: Arc<dyn SessionManagementOperations>,
    config: SessionManagementConfig,
}

impl SessionManagementEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn SessionManagementOperations>,
        config: SessionManagementConfig,
    ) -> Self {
        Self { operations, config }
    }
}

pub async fn check_session_iframe(endpoint: Data<SessionManagementEndpoint>) -> HttpResponse {
    if !endpoint
        .operations
        .availability()
        .permits_existing_transaction()
    {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let status_endpoint = format!("{}/check_session/status", endpoint.config.issuer);
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .content_type("text/html; charset=utf-8")
        .body(session_management_iframe_document(&status_endpoint))
}

#[derive(Deserialize)]
pub struct CheckSessionStatusQuery {
    client_id: String,
    origin: String,
    session_state: String,
}

pub async fn check_session_status(
    endpoint: Data<SessionManagementEndpoint>,
    request: HttpRequest,
    Query(query): Query<CheckSessionStatusQuery>,
) -> HttpResponse {
    if !endpoint
        .operations
        .availability()
        .permits_existing_transaction()
    {
        return empty_response(StatusCode::NOT_FOUND);
    }

    // Preserve the protocol distinction between malformed state and a missing
    // OP session without performing a storage lookup for malformed input.
    if check_oidc_session_state(&query.client_id, &query.origin, &query.session_state, None)
        == OidcSessionStatus::Error
    {
        return status_response(OidcSessionStatus::Error);
    }

    let Some(session_id) = cookie_value(&request, &endpoint.config.session_cookie_name) else {
        return status_response(OidcSessionStatus::Changed);
    };
    let op_browser_state = match endpoint.operations.op_browser_state(&session_id).await {
        Ok(state) => state,
        Err(SessionManagementError::SessionLookupUnavailable) => {
            return status_response(OidcSessionStatus::Error);
        }
    };
    status_response(check_oidc_session_state(
        &query.client_id,
        &query.origin,
        &query.session_state,
        op_browser_state.as_deref(),
    ))
}

fn status_response(status: OidcSessionStatus) -> HttpResponse {
    let status = match status {
        OidcSessionStatus::Unchanged => "unchanged",
        OidcSessionStatus::Changed => "changed",
        OidcSessionStatus::Error => "error",
    };
    json_response_no_store(json!({ "status": status }))
}

fn session_management_iframe_document(status_endpoint: &str) -> String {
    let head = include_str!("session_management_iframe.head.html").trim_end_matches(['\r', '\n']);
    format!(
        "{}{}{}{}",
        head,
        escape_js_string(status_endpoint),
        include_str!("session_management_iframe.tail.html"),
        ""
    )
}

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\'', "\\'")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

#[cfg(test)]
mod tests {
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
        op_browser_state: Result<Option<String>, SessionManagementError>,
    }

    impl SessionManagementOperations for TestOperations {
        fn availability(&self) -> SessionManagementAvailability {
            self.availability
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
}
