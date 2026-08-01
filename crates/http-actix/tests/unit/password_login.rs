use std::sync::Mutex;

use actix_web::{App, body::to_bytes, cookie::Cookie, middleware::from_fn, test, web};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;

use super::*;

struct FakeOperations {
    inputs: Mutex<Vec<AuthenticatePasswordInput>>,
    result: Mutex<Result<PasswordLoginResult, AuthenticatePasswordError>>,
}

impl PasswordLoginOperations for FakeOperations {
    fn authenticate_password(&self, input: AuthenticatePasswordInput) -> PasswordLoginFuture<'_> {
        self.inputs.lock().unwrap().push(input);
        let result = self.result.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

struct RecordingRateLimit {
    subjects: Mutex<Vec<String>>,
    result: Mutex<Result<(), AuthenticationRateLimitError>>,
}

impl AuthenticationRateLimit for RecordingRateLimit {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> crate::LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>> {
        self.subjects.lock().unwrap().push(subject.to_owned());
        let result = *self.result.lock().unwrap();
        Box::pin(async move { result })
    }
}

fn success() -> PasswordLoginResult {
    PasswordLoginResult {
        session_id: "new-session".to_owned(),
        csrf_token: "new-csrf".to_owned(),
        mfa_required: true,
    }
}

fn endpoint(
    result: Result<PasswordLoginResult, AuthenticatePasswordError>,
    rate_result: Result<(), AuthenticationRateLimitError>,
    proxies: &[crate::IpCidr],
    mode: crate::ClientIpHeaderMode,
) -> (
    PasswordLoginEndpoint,
    Arc<FakeOperations>,
    Arc<RecordingRateLimit>,
) {
    let operations = Arc::new(FakeOperations {
        inputs: Mutex::new(Vec::new()),
        result: Mutex::new(result),
    });
    let rate_limit = Arc::new(RecordingRateLimit {
        subjects: Mutex::new(Vec::new()),
        result: Mutex::new(rate_result),
    });
    (
        PasswordLoginEndpoint::new(
            operations.clone(),
            rate_limit.clone(),
            ClientIpConfig::new(proxies, mode),
            PasswordLoginConfig::new(
                "https://issuer.example",
                "https://app.example/ui/",
                "session",
                "csrf",
                "remembered",
                300,
                true,
            ),
        ),
        operations,
        rate_limit,
    )
}

async fn body_json(response: HttpResponse) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
}

fn assert_no_store(response: &HttpResponse) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
}

#[actix_web::test]
async fn json_success_sets_session_and_csrf_together_and_rotates_previous_id() {
    let (endpoint, operations, rate_limit) =
        endpoint(Ok(success()), Ok(()), &[], crate::ClientIpHeaderMode::None);
    let response = login(
        Data::new(endpoint),
        test::TestRequest::post()
            .peer_addr("203.0.113.10:49152".parse().unwrap())
            .cookie(Cookie::new("session", "old-session"))
            .cookie(Cookie::new("remembered", " remembered-token "))
            .insert_header((header::USER_AGENT, " unit-test-agent "))
            .insert_header((header::CONTENT_TYPE, "application/json; charset=utf-8"))
            .to_http_request(),
        Bytes::from_static(br#"{"email":" Alice@Example.TEST ","password":"secret"}"#),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies
            .iter()
            .any(|value| value.starts_with("session=new-session"))
    );
    assert!(
        cookies
            .iter()
            .any(|value| value.starts_with("csrf=new-csrf"))
    );
    let input = operations.inputs.lock().unwrap()[0].clone();
    assert_eq!(input.email, "alice@example.test");
    assert_eq!(input.source_ip, "203.0.113.10");
    assert_eq!(input.previous_session_id.as_deref(), Some("old-session"));
    assert_eq!(
        input.remembered_mfa,
        Some(RememberedMfaProof {
            token_hash: blake3_hex("remembered-token"),
            user_agent_hash: Some(blake3_hex("unit-test-agent")),
        })
    );
    assert_eq!(
        rate_limit.subjects.lock().unwrap().as_slice(),
        &["203.0.113.10"]
    );
    let body = body_json(response).await;
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["csrf_token"], "new-csrf");
    assert_eq!(body["mfa_required"], true);
}

#[actix_web::test]
async fn form_login_requires_exact_origin_and_redirects_only_to_authorize() {
    for next in [
        "/authorize?client_id=client",
        "https://evil.example/authorize",
        "//evil.example/authorize",
        "/%2f%2fevil.example",
        "/profile",
    ] {
        let (endpoint, operations, _) =
            endpoint(Ok(success()), Ok(()), &[], crate::ClientIpHeaderMode::None);
        let response = login(
            Data::new(endpoint),
            test::TestRequest::post()
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .insert_header((header::ORIGIN, "https://app.example"))
                .to_http_request(),
            Bytes::from(format!(
                "email=alice%40example.test&password=secret&next={}",
                url::form_urlencoded::byte_serialize(next.as_bytes()).collect::<String>()
            )),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_no_store(&response);
        let expected = if next.starts_with("/authorize") {
            next
        } else {
            "https://app.example/ui/profile"
        };
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), expected);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 2);
        assert_eq!(operations.inputs.lock().unwrap().len(), 1);
    }

    for origin in [
        None,
        Some("null"),
        Some("https://app.example/path"),
        Some(" https://app.example"),
        Some("https://evil.example"),
    ] {
        let (endpoint, operations, _) =
            endpoint(Ok(success()), Ok(()), &[], crate::ClientIpHeaderMode::None);
        let mut request = test::TestRequest::post()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"));
        if let Some(origin) = origin {
            request = request.insert_header((header::ORIGIN, origin));
        }
        let response = login(
            Data::new(endpoint),
            request.to_http_request(),
            Bytes::from_static(b"email=alice%40example.test&password=secret"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_no_store(&response);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 0);
        assert!(operations.inputs.lock().unwrap().is_empty());
    }
}

#[actix_web::test]
async fn malformed_requests_fail_before_rate_limit_and_authentication() {
    let cases = [
        (
            "application/json",
            Bytes::from_static(b"not-json"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"email=a%40b.test&email=c%40d.test&password=x"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "text/plain",
            Bytes::from_static(b"email=a"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ];
    for (content_type, body, status) in cases {
        let (endpoint, operations, rate_limit) =
            endpoint(Ok(success()), Ok(()), &[], crate::ClientIpHeaderMode::None);
        let response = login(
            Data::new(endpoint),
            test::TestRequest::post()
                .insert_header((header::CONTENT_TYPE, content_type))
                .to_http_request(),
            body,
        )
        .await;
        assert_eq!(response.status(), status);
        assert_no_store(&response);
        assert!(operations.inputs.lock().unwrap().is_empty());
        assert!(rate_limit.subjects.lock().unwrap().is_empty());
    }
}

#[actix_web::test]
async fn trusted_proxy_is_honored_but_untrusted_forwarding_is_ignored() {
    let trusted = crate::IpCidr::parse("10.0.0.0/8").unwrap();
    for (peer, expected) in [
        ("10.1.2.3:49152", "198.51.100.7"),
        ("203.0.113.8:49152", "203.0.113.8"),
    ] {
        let (endpoint, operations, rate_limit) = endpoint(
            Ok(success()),
            Ok(()),
            std::slice::from_ref(&trusted),
            crate::ClientIpHeaderMode::XForwardedFor,
        );
        let response = login(
            Data::new(endpoint),
            test::TestRequest::post()
                .peer_addr(peer.parse().unwrap())
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .insert_header(("x-forwarded-for", "198.51.100.7"))
                .to_http_request(),
            Bytes::from_static(br#"{"email":"alice@example.test","password":"secret"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(operations.inputs.lock().unwrap()[0].source_ip, expected);
        assert_eq!(rate_limit.subjects.lock().unwrap()[0], expected);
    }
}

#[actix_web::test]
async fn rate_limit_and_authentication_failures_set_no_cookies_and_no_store() {
    let cases = [
        (
            Err(AuthenticationRateLimitError::Limited {
                retry_after_seconds: 17,
            }),
            Ok(success()),
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            Some("17"),
        ),
        (
            Ok(()),
            Err(AuthenticatePasswordError::InvalidCredentials),
            StatusCode::UNAUTHORIZED,
            "access_denied",
            None,
        ),
        (
            Ok(()),
            Err(AuthenticatePasswordError::ThrottleUnavailable(
                RepositoryError::Unavailable,
            )),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            None,
        ),
        (
            Ok(()),
            Err(AuthenticatePasswordError::SecretBusy),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            Some("1"),
        ),
    ];
    for (rate, result, status, error, retry_after) in cases {
        let (endpoint, operations, _) =
            endpoint(result, rate, &[], crate::ClientIpHeaderMode::None);
        let response = login(
            Data::new(endpoint),
            test::TestRequest::post()
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .to_http_request(),
            Bytes::from_static(br#"{"email":"alice@example.test","password":"secret"}"#),
        )
        .await;
        assert_eq!(response.status(), status);
        assert_no_store(&response);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 0);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            retry_after
        );
        assert_eq!(body_json(response).await["error"], error);
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert!(operations.inputs.lock().unwrap().is_empty());
        }
    }
}

#[actix_web::test]
async fn route_methods_cors_and_security_headers_are_locked() {
    let (endpoint, _, _) = endpoint(Ok(success()), Ok(()), &[], crate::ClientIpHeaderMode::None);
    let service = test::init_service(
        App::new()
            .wrap(from_fn(crate::security_headers))
            .app_data(Data::new(endpoint))
            .route("/auth/login", web::post().to(login)),
    )
    .await;
    for method in [
        actix_web::http::Method::GET,
        actix_web::http::Method::OPTIONS,
    ] {
        let response = test::call_service(
            &service,
            test::TestRequest::default()
                .method(method)
                .uri("/auth/login")
                .insert_header((header::ORIGIN, "https://app.example"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
    }
}
