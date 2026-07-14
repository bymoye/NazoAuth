use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json},
};
use nazo_identity::{
    RegisterLocalAccountError, RegisterLocalAccountInput, SendVerificationCodeError,
    SendVerificationCodeOutcome, email::normalize_email_address, registration::RegisteredAccount,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    ClientIpConfig, authorization_error_response, client_ip_with_config, json_response,
    json_response_status, oauth_error,
};

pub type LocalRegistrationFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait LocalRegistrationOperations: Send + Sync {
    fn send_verification_code<'a>(
        &'a self,
        normalized_email: &'a str,
        peer_subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<SendVerificationCodeOutcome, SendVerificationCodeError>>;

    fn register_local_account(
        &self,
        input: RegisterLocalAccountInput,
    ) -> LocalRegistrationFuture<'_, Result<RegisteredAccount, RegisterLocalAccountError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub trait AuthenticationRateLimit: Send + Sync {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>>;
}

#[derive(Clone)]
pub struct LocalRegistrationEndpoint {
    operations: Arc<dyn LocalRegistrationOperations>,
    rate_limit: Arc<dyn AuthenticationRateLimit>,
    client_ip: ClientIpConfig,
    dev_response_enabled: bool,
}

impl LocalRegistrationEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn LocalRegistrationOperations>,
        rate_limit: Arc<dyn AuthenticationRateLimit>,
        client_ip: ClientIpConfig,
        dev_response_enabled: bool,
    ) -> Self {
        Self {
            operations,
            rate_limit,
            client_ip,
            dev_response_enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SendCodeRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    email: String,
    verification_code: String,
    password: String,
}

/// Sends a registration verification code without exposing account existence.
pub async fn send_code(
    endpoint: Data<LocalRegistrationEndpoint>,
    request: HttpRequest,
    Json(payload): Json<SendCodeRequest>,
) -> HttpResponse {
    if let Err(error) = endpoint
        .rate_limit
        .enforce(&client_ip_with_config(&request, &endpoint.client_ip))
        .await
    {
        return authentication_rate_limit_error_response(error);
    }

    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let peer_subject = request
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    match endpoint
        .operations
        .send_verification_code(&email, &peer_subject)
        .await
    {
        Ok(SendVerificationCodeOutcome::Suppressed) => {
            send_code_success_response(endpoint.dev_response_enabled, None)
        }
        Ok(SendVerificationCodeOutcome::Sent { code }) => {
            send_code_success_response(endpoint.dev_response_enabled, Some(&code))
        }
        Err(SendVerificationCodeError::DeliveryNotConfigured) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "邮件发送未配置.",
        ),
        Err(SendVerificationCodeError::AccountLookup(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "数据库连接失败.",
        ),
        Err(
            SendVerificationCodeError::Reservation(_) | SendVerificationCodeError::CodeStore(_),
        ) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        ),
        Err(SendVerificationCodeError::CodeHash(_)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "验证码生成失败.",
        ),
        Err(SendVerificationCodeError::Delivery(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码发送失败.",
        ),
    }
}

/// Creates a verified local account from a one-time email code.
pub async fn register(
    endpoint: Data<LocalRegistrationEndpoint>,
    request: HttpRequest,
    Json(payload): Json<RegisterRequest>,
) -> HttpResponse {
    if let Err(error) = endpoint
        .rate_limit
        .enforce(&client_ip_with_config(&request, &endpoint.client_ip))
        .await
    {
        return authentication_rate_limit_error_response(error);
    }

    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let input = RegisterLocalAccountInput {
        email,
        verification_code: payload.verification_code.trim().to_owned(),
        password: payload.password,
    };
    match endpoint.operations.register_local_account(input).await {
        Ok(account) => json_response_status(
            StatusCode::CREATED,
            json!({"id": account.id, "email": account.email}),
        ),
        Err(RegisterLocalAccountError::InvalidVerificationCode) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "验证码错误或已过期.",
        ),
        Err(RegisterLocalAccountError::VerificationUnavailable(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码校验失败.",
        ),
        Err(RegisterLocalAccountError::AccountLookup(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "数据库连接失败.",
        ),
        Err(RegisterLocalAccountError::Conflict) => {
            oauth_error(StatusCode::CONFLICT, "invalid_request", "该邮箱已注册.")
        }
        Err(RegisterLocalAccountError::PasswordHash(_)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "密码哈希失败.",
        ),
        Err(RegisterLocalAccountError::Create(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "用户创建失败.",
        ),
        Err(RegisterLocalAccountError::Consistency) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "用户创建失败.",
        ),
    }
}

fn authentication_rate_limit_error_response(error: AuthenticationRateLimitError) -> HttpResponse {
    match error {
        AuthenticationRateLimitError::Limited {
            retry_after_seconds,
        } => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        AuthenticationRateLimitError::Unavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        ),
    }
}

fn send_code_success_response(dev_response_enabled: bool, code: Option<&str>) -> HttpResponse {
    let mut body = json!({"success": true, "message": "如果邮箱尚未注册，验证码将会发送。"});
    if cfg!(debug_assertions)
        && dev_response_enabled
        && let Some(code) = code
    {
        body["verification_code"] = json!(code);
    }
    json_response(body)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use actix_web::{App, body::to_bytes, http::header, middleware::from_fn, test, web};
    use nazo_identity::ports::RepositoryError;
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::*;

    struct FakeOperations {
        sent: Mutex<Vec<(String, String)>>,
        registrations: Mutex<Vec<RegisterLocalAccountInput>>,
        send_result: Mutex<Result<SendVerificationCodeOutcome, SendVerificationCodeError>>,
        register_result: Mutex<Result<RegisteredAccount, RegisterLocalAccountError>>,
    }

    impl LocalRegistrationOperations for FakeOperations {
        fn send_verification_code<'a>(
            &'a self,
            normalized_email: &'a str,
            peer_subject: &'a str,
        ) -> LocalRegistrationFuture<
            'a,
            Result<SendVerificationCodeOutcome, SendVerificationCodeError>,
        > {
            self.sent
                .lock()
                .unwrap()
                .push((normalized_email.to_owned(), peer_subject.to_owned()));
            let result = self.send_result.lock().unwrap().clone();
            Box::pin(async move { result })
        }

        fn register_local_account(
            &self,
            input: RegisterLocalAccountInput,
        ) -> LocalRegistrationFuture<'_, Result<RegisteredAccount, RegisterLocalAccountError>>
        {
            self.registrations.lock().unwrap().push(input);
            let result = self.register_result.lock().unwrap().clone();
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
        ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>> {
            self.subjects.lock().unwrap().push(subject.to_owned());
            let result = *self.result.lock().unwrap();
            Box::pin(async move { result })
        }
    }

    fn account() -> RegisteredAccount {
        RegisteredAccount {
            id: Uuid::from_u128(4),
            email: "alice@example.test".to_owned(),
        }
    }

    fn endpoint(
        send_result: Result<SendVerificationCodeOutcome, SendVerificationCodeError>,
        register_result: Result<RegisteredAccount, RegisterLocalAccountError>,
        rate_result: Result<(), AuthenticationRateLimitError>,
        trusted_proxies: &[crate::IpCidr],
        header_mode: crate::ClientIpHeaderMode,
        dev_response_enabled: bool,
    ) -> (
        LocalRegistrationEndpoint,
        Arc<FakeOperations>,
        Arc<RecordingRateLimit>,
    ) {
        let operations = Arc::new(FakeOperations {
            sent: Mutex::new(Vec::new()),
            registrations: Mutex::new(Vec::new()),
            send_result: Mutex::new(send_result),
            register_result: Mutex::new(register_result),
        });
        let rate_limit = Arc::new(RecordingRateLimit {
            subjects: Mutex::new(Vec::new()),
            result: Mutex::new(rate_result),
        });
        (
            LocalRegistrationEndpoint::new(
                operations.clone(),
                rate_limit.clone(),
                ClientIpConfig::new(trusted_proxies, header_mode),
                dev_response_enabled,
            ),
            operations,
            rate_limit,
        )
    }

    async fn body_json(response: HttpResponse) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
    }

    #[actix_web::test]
    async fn transport_normalizes_email_and_preserves_raw_peer_cooldown_subject() {
        let (endpoint, operations, rate_limit) = endpoint(
            Ok(SendVerificationCodeOutcome::Sent {
                code: "123456".to_owned(),
            }),
            Ok(account()),
            Ok(()),
            &[],
            crate::ClientIpHeaderMode::None,
            false,
        );
        let response = send_code(
            Data::new(endpoint),
            test::TestRequest::post()
                .peer_addr("203.0.113.10:49152".parse().unwrap())
                .to_http_request(),
            Json(SendCodeRequest {
                email: " Alice@Example.TEST ".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            operations.sent.lock().unwrap().as_slice(),
            &[("alice@example.test".to_owned(), "203.0.113.10".to_owned())]
        );
        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            &["203.0.113.10"]
        );
        let body = body_json(response).await;
        assert_eq!(body["success"], true);
        assert!(body.get("verification_code").is_none());
    }

    #[actix_web::test]
    async fn untrusted_forwarded_header_cannot_spoof_rate_limit_subject() {
        let trusted = crate::IpCidr::parse("10.0.0.0/8").unwrap();
        let (endpoint, _, rate_limit) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[trusted],
            crate::ClientIpHeaderMode::XForwardedFor,
            false,
        );
        let request = test::TestRequest::post()
            .peer_addr("203.0.113.10:49152".parse().unwrap())
            .insert_header(("x-forwarded-for", "198.51.100.5"))
            .to_http_request();
        let _ = send_code(
            Data::new(endpoint),
            request,
            Json(SendCodeRequest {
                email: "alice@example.test".to_owned(),
            }),
        )
        .await;
        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            &["203.0.113.10"]
        );
    }

    #[actix_web::test]
    async fn trusted_proxy_header_controls_rate_limit_but_not_peer_cooldown() {
        let trusted = crate::IpCidr::parse("10.0.0.0/8").unwrap();
        let (endpoint, operations, rate_limit) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[trusted],
            crate::ClientIpHeaderMode::XForwardedFor,
            false,
        );
        let request = test::TestRequest::post()
            .peer_addr("10.1.2.3:49152".parse().unwrap())
            .insert_header(("x-forwarded-for", "198.51.100.5"))
            .to_http_request();
        let _ = send_code(
            Data::new(endpoint),
            request,
            Json(SendCodeRequest {
                email: "alice@example.test".to_owned(),
            }),
        )
        .await;
        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            &["198.51.100.5"]
        );
        assert_eq!(operations.sent.lock().unwrap()[0].1, "10.1.2.3");
    }

    #[actix_web::test]
    async fn rate_limit_runs_before_validation_and_preserves_retry_contract() {
        let (endpoint, operations, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Err(AuthenticationRateLimitError::Limited {
                retry_after_seconds: 17,
            }),
            &[],
            crate::ClientIpHeaderMode::None,
            false,
        );
        let response = register(
            Data::new(endpoint),
            test::TestRequest::post().to_http_request(),
            Json(RegisterRequest {
                email: "not an email".to_owned(),
                verification_code: "123456".to_owned(),
                password: "password".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "17");
        assert!(operations.registrations.lock().unwrap().is_empty());
        assert_eq!(
            body_json(response).await["error"],
            "temporarily_unavailable"
        );
    }

    #[actix_web::test]
    async fn register_trims_only_code_whitespace_and_returns_public_identity() {
        let expected = account();
        let (endpoint, operations, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(expected.clone()),
            Ok(()),
            &[],
            crate::ClientIpHeaderMode::None,
            false,
        );
        let response = register(
            Data::new(endpoint),
            test::TestRequest::post().to_http_request(),
            Json(RegisterRequest {
                email: "ALICE@EXAMPLE.TEST".to_owned(),
                verification_code: "  123456  ".to_owned(),
                password: "correct horse battery staple".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        {
            let calls = operations.registrations.lock().unwrap();
            assert_eq!(calls[0].email, "alice@example.test");
            assert_eq!(calls[0].verification_code, "123456");
        }
        assert_eq!(
            body_json(response).await,
            json!({"id": expected.id, "email": "alice@example.test"})
        );
    }

    #[actix_web::test]
    async fn error_mapping_preserves_status_and_oauth_code() {
        let cases = [
            (
                RegisterLocalAccountError::InvalidVerificationCode,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
            ),
            (
                RegisterLocalAccountError::Conflict,
                StatusCode::CONFLICT,
                "invalid_request",
            ),
            (
                RegisterLocalAccountError::PasswordHash(RepositoryError::Unavailable),
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
            ),
        ];
        for (error, status, code) in cases {
            let (endpoint, _, _) = endpoint(
                Ok(SendVerificationCodeOutcome::Suppressed),
                Err(error),
                Ok(()),
                &[],
                crate::ClientIpHeaderMode::None,
                false,
            );
            let response = register(
                Data::new(endpoint),
                test::TestRequest::post().to_http_request(),
                Json(RegisterRequest {
                    email: "alice@example.test".to_owned(),
                    verification_code: "123456".to_owned(),
                    password: "password".to_owned(),
                }),
            )
            .await;
            assert_eq!(response.status(), status);
            assert_eq!(body_json(response).await["error"], code);
        }
    }

    #[actix_web::test]
    async fn development_code_is_exposed_only_when_enabled_and_newly_sent() {
        let (enabled, _, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Sent {
                code: "654321".to_owned(),
            }),
            Ok(account()),
            Ok(()),
            &[],
            crate::ClientIpHeaderMode::None,
            true,
        );
        let response = send_code(
            Data::new(enabled),
            test::TestRequest::post().to_http_request(),
            Json(SendCodeRequest {
                email: "alice@example.test".to_owned(),
            }),
        )
        .await;
        let body = body_json(response).await;
        if cfg!(debug_assertions) {
            assert_eq!(body["verification_code"], "654321");
        } else {
            assert!(body.get("verification_code").is_none());
        }

        let (suppressed, _, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[],
            crate::ClientIpHeaderMode::None,
            true,
        );
        let response = send_code(
            Data::new(suppressed),
            test::TestRequest::post().to_http_request(),
            Json(SendCodeRequest {
                email: "alice@example.test".to_owned(),
            }),
        )
        .await;
        assert!(body_json(response).await.get("verification_code").is_none());
    }

    #[actix_web::test]
    async fn unavailable_rate_limit_fails_closed_before_registration() {
        let (endpoint, operations, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Err(AuthenticationRateLimitError::Unavailable),
            &[],
            crate::ClientIpHeaderMode::None,
            false,
        );
        let response = register(
            Data::new(endpoint),
            test::TestRequest::post().to_http_request(),
            Json(RegisterRequest {
                email: "alice@example.test".to_owned(),
                verification_code: "123456".to_owned(),
                password: "password".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_json(response).await["error"], "server_error");
        assert!(operations.registrations.lock().unwrap().is_empty());
    }

    #[actix_web::test]
    async fn route_methods_cors_cache_and_security_headers_remain_exact() {
        let (endpoint, _, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[],
            crate::ClientIpHeaderMode::None,
            false,
        );
        let service = test::init_service(
            App::new()
                .wrap(from_fn(crate::security_headers))
                .app_data(Data::new(endpoint))
                .route("/auth/send-code", web::post().to(send_code))
                .route("/auth/register", web::post().to(register)),
        )
        .await;

        let post = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/auth/send-code")
                .set_json(json!({"email": "alice@example.test"}))
                .to_request(),
        )
        .await;
        assert_eq!(post.status(), StatusCode::OK);
        assert_eq!(
            post.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(post.headers().get(header::CACHE_CONTROL).is_none());
        assert!(post.headers().get(header::PRAGMA).is_none());
        assert!(
            post.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(post.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            post.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert!(post.headers().contains_key("content-security-policy"));

        let register_post = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/auth/register")
                .set_json(json!({
                    "email": "alice@example.test",
                    "verification_code": "123456",
                    "password": "correct horse battery staple"
                }))
                .to_request(),
        )
        .await;
        assert_eq!(register_post.status(), StatusCode::CREATED);
        assert!(register_post.headers().get(header::CACHE_CONTROL).is_none());
        assert!(register_post.headers().get(header::PRAGMA).is_none());
        assert!(
            register_post
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            register_post
                .headers()
                .get(header::X_FRAME_OPTIONS)
                .unwrap(),
            "DENY"
        );

        for path in ["/auth/send-code", "/auth/register"] {
            for method in [
                actix_web::http::Method::GET,
                actix_web::http::Method::OPTIONS,
            ] {
                let response = test::call_service(
                    &service,
                    test::TestRequest::default()
                        .method(method)
                        .uri(path)
                        .insert_header((header::ORIGIN, "https://frontend.example"))
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
    }
}
