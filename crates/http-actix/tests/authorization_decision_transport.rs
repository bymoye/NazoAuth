pub use nazo_http_actix::{
    ClientIpConfig, SessionCookieConfig, client_ip_with_config, csrf_error,
    form_post_authorization_response, login_required_response, oauth_error, redirect_found,
};

use std::sync::{Arc, Mutex};

use actix_web::{
    HttpResponse,
    body::to_bytes,
    cookie::Cookie,
    http::{StatusCode, header},
    test::TestRequest,
    web::{Data, Form},
};
use nazo_http_actix::ClientIpHeaderMode;
use nazo_http_actix::{
    AuthorizationDecisionCommand, AuthorizationDecisionEndpoint, AuthorizationDecisionError,
    AuthorizationDecisionForm, AuthorizationDecisionFuture, AuthorizationDecisionOperations,
    AuthorizationDecisionResponse, authorize_decision,
};
use serde_json::{Value, json};

struct FakeOperations {
    result: Mutex<Result<AuthorizationDecisionResponse, AuthorizationDecisionError>>,
    commands: Mutex<Vec<AuthorizationDecisionCommand>>,
}

impl AuthorizationDecisionOperations for FakeOperations {
    fn decide(&self, command: AuthorizationDecisionCommand) -> AuthorizationDecisionFuture<'_> {
        self.commands.lock().unwrap().push(command);
        let result = self.result.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

fn endpoint(
    result: Result<AuthorizationDecisionResponse, AuthorizationDecisionError>,
) -> (Data<AuthorizationDecisionEndpoint>, Arc<FakeOperations>) {
    let operations = Arc::new(FakeOperations {
        result: Mutex::new(result),
        commands: Mutex::new(Vec::new()),
    });
    (
        Data::new(AuthorizationDecisionEndpoint::new(
            operations.clone(),
            SessionCookieConfig::new("session", "csrf", true),
            ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        )),
        operations,
    )
}

fn request(include_session: bool, csrf: Option<&str>) -> actix_web::HttpRequest {
    let mut request = TestRequest::post()
        .peer_addr("198.51.100.10:443".parse().unwrap())
        .cookie(Cookie::new("csrf", "csrf-token"));
    if include_session {
        request = request.cookie(Cookie::new("session", "sid-1"));
    }
    if let Some(csrf) = csrf {
        request = request.insert_header(("x-csrf-token", csrf));
    }
    request.to_http_request()
}

fn form(decision: &str, csrf_token: Option<&str>) -> Form<AuthorizationDecisionForm> {
    Form(AuthorizationDecisionForm {
        request_id: "request-1".to_owned(),
        decision: decision.to_owned(),
        csrf_token: csrf_token.map(str::to_owned),
    })
}

async fn response_json(response: HttpResponse) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
}

#[actix_web::test]
async fn csrf_is_checked_before_decision_operations() {
    let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
        location: "https://client.example/callback?code=code".to_owned(),
    }));

    let response = authorize_decision(endpoint, request(true, None), form("approve", None)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(operations.commands.lock().unwrap().is_empty());
    assert_eq!(response_json(response).await["error"], "invalid_request");
}

#[actix_web::test]
async fn invalid_decision_is_rejected_before_session_or_operations() {
    let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
        location: "https://client.example/callback?code=code".to_owned(),
    }));

    let response = authorize_decision(
        endpoint,
        request(true, Some("csrf-token")),
        form("other", None),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(operations.commands.lock().unwrap().is_empty());
    assert_eq!(response_json(response).await["error"], "invalid_request");
}

#[actix_web::test]
async fn missing_session_preserves_login_required_and_cookie_clearing() {
    let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
        location: "https://client.example/callback?code=code".to_owned(),
    }));

    let response = authorize_decision(
        endpoint,
        request(false, Some("csrf-token")),
        form("approve", None),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 2);
    assert!(operations.commands.lock().unwrap().is_empty());
    assert_eq!(response_json(response).await["error"], "login_required");
}

#[actix_web::test]
async fn approved_transport_forwards_typed_command_and_preserves_redirect() {
    let location = "https://client.example/callback?code=code&state=state";
    let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
        location: location.to_owned(),
    }));

    let response = authorize_decision(
        endpoint,
        request(true, Some("csrf-token")),
        form("approve", None),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), location);
    let commands = operations.commands.lock().unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].request_id, "request-1");
    assert_eq!(commands[0].session_id.as_str(), "sid-1");
    assert_eq!(commands[0].source_ip, "198.51.100.10");
    assert_eq!(
        commands[0].decision,
        nazo_auth::UserAuthorizationDecision::Approve
    );
}

#[actix_web::test]
async fn form_post_decision_returns_no_store_auto_submit_document() {
    let (endpoint, _) = endpoint(Ok(AuthorizationDecisionResponse::FormPost {
        action: "https://client.example/callback".to_owned(),
        parameters: vec![("code".to_owned(), "code-value".to_owned())],
        session_state: Some("session-state".to_owned()),
        csp_nonce: "nonce-value".to_owned(),
    }));

    let response = authorize_decision(
        endpoint,
        request(true, Some("csrf-token")),
        form("approve", None),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = String::from_utf8(to_bytes(response.into_body()).await.unwrap().to_vec()).unwrap();
    assert!(body.contains("method=\"post\""));
    assert!(body.contains("name=\"code\" value=\"code-value\""));
    assert!(body.contains("name=\"session_state\" value=\"session-state\""));
}

#[actix_web::test]
async fn domain_failures_keep_existing_status_and_oauth_error_contracts() {
    for (error, expected_status, expected_code, expected_description) in [
        (
            AuthorizationDecisionError::LoginRequired,
            StatusCode::UNAUTHORIZED,
            "login_required",
            "Request failed.",
        ),
        (
            AuthorizationDecisionError::SessionLookupUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Request failed.",
        ),
        (
            AuthorizationDecisionError::ConsentInvalid,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Request failed.",
        ),
        (
            AuthorizationDecisionError::ConsentReadUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Request failed.",
        ),
        (
            AuthorizationDecisionError::UserMismatch,
            StatusCode::FORBIDDEN,
            "access_denied",
            "Request failed.",
        ),
        (
            AuthorizationDecisionError::ApprovalUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Request failed.",
        ),
        (
            AuthorizationDecisionError::UnsupportedResponseMode,
            StatusCode::BAD_REQUEST,
            "unsupported_response_mode",
            "JWT-secured authorization responses are disabled.",
        ),
        (
            AuthorizationDecisionError::ResponseProtectionUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "authorization response protection failed.",
        ),
        (
            AuthorizationDecisionError::ResponseSigningUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "authorization response signing failed.",
        ),
    ] {
        let (endpoint, _) = endpoint(Err(error));
        let response = authorize_decision(
            endpoint,
            request(true, Some("csrf-token")),
            form("deny", None),
        )
        .await;
        assert_eq!(response.status(), expected_status, "error={error:?}");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json",
            "error={error:?}"
        );
        assert_eq!(
            response_json(response).await,
            json!({
                "error": expected_code,
                "error_description": expected_description
            }),
            "error={error:?}"
        );
    }
}
