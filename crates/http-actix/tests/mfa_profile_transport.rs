use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{
    App,
    http::{Method, StatusCode, header},
    middleware::from_fn,
    test, web,
};
use nazo_http_actix::{
    AuthenticationRateLimitError, ClientIpConfig, ClientIpHeaderMode, MfaBackupCodesRegenerated,
    MfaChallengeCommand, MfaChallengeSuccess, MfaCodeCommand, MfaProfileConfig, MfaProfileEndpoint,
    MfaProfileError, MfaProfileErrorKind, MfaProfileFuture, MfaProfileOperations,
    MfaRequestContext, MfaSessionRotation, MfaStepUpSuccess, MfaTotpConfirmation,
    MfaTotpEnrollment, configure_mfa_challenge_route, configure_mfa_profile_routes,
};

#[derive(Clone, Default)]
struct Operations {
    verify_error: Option<MfaProfileError>,
    step_up_error: Option<MfaProfileError>,
    disable_changed: bool,
}

impl MfaProfileOperations for Operations {
    fn begin_totp(&self, _context: MfaRequestContext) -> MfaProfileFuture<'_, MfaTotpEnrollment> {
        Box::pin(async {
            Ok(MfaTotpEnrollment {
                secret_base32: "SECRET".to_owned(),
                otpauth_uri: "otpauth://totp/example".to_owned(),
            })
        })
    }

    fn confirm_totp(&self, _command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaTotpConfirmation> {
        Box::pin(async {
            Ok(MfaTotpConfirmation {
                rotation: rotation(),
                backup_codes: vec!["12345-67890".to_owned()],
            })
        })
    }

    fn verify_challenge(
        &self,
        _command: MfaChallengeCommand,
    ) -> MfaProfileFuture<'_, MfaChallengeSuccess> {
        let error = self.verify_error.clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(MfaChallengeSuccess {
                    rotation: rotation(),
                    method: "otp".to_owned(),
                    remembered_device_token: None,
                }),
            }
        })
    }

    fn step_up(&self, _command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaStepUpSuccess> {
        let error = self.step_up_error.clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(MfaStepUpSuccess {
                    rotation: rotation(),
                    method: "otp".to_owned(),
                }),
            }
        })
    }

    fn regenerate_backup_codes(
        &self,
        _command: MfaCodeCommand,
    ) -> MfaProfileFuture<'_, MfaBackupCodesRegenerated> {
        Box::pin(async {
            Ok(MfaBackupCodesRegenerated {
                rotation: rotation(),
                backup_codes: vec!["12345-67890".to_owned()],
            })
        })
    }

    fn disable(&self, _command: MfaCodeCommand) -> MfaProfileFuture<'_, bool> {
        let changed = self.disable_changed;
        Box::pin(async move { Ok(changed) })
    }
}

#[actix_web::test]
async fn missing_mfa_challenge_does_not_clear_an_authenticated_session() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint_with(Operations {
                verify_error: Some(MfaProfileError::new(MfaProfileErrorKind::ChallengeMissing)),
                ..Operations::default()
            })))
            .wrap(from_fn(nazo_http_actix::security_headers))
            .service(web::scope("/auth/mfa").configure(configure_mfa_challenge_route)),
    )
    .await;

    let response = test::call_service(
        &app,
        authenticated_request(Method::POST, "/auth/mfa/verify")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(r#"{"code":"000000","remember_device":false}"#)
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.response().cookies().count(), 0);
    assert_contract_headers(response.headers());
}

fn rotation() -> MfaSessionRotation {
    MfaSessionRotation {
        session_id: "new-session".to_owned(),
        csrf_token: "new-csrf".to_owned(),
    }
}

fn endpoint() -> MfaProfileEndpoint {
    endpoint_with(Operations {
        disable_changed: true,
        ..Operations::default()
    })
}

fn endpoint_with(operations: Operations) -> MfaProfileEndpoint {
    MfaProfileEndpoint::new(
        Arc::new(operations),
        ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        MfaProfileConfig::new("session", "csrf", "remembered", 300, 600, true),
    )
}

fn authenticated_request(method: Method, path: &str) -> test::TestRequest {
    test::TestRequest::default()
        .method(method)
        .uri(path)
        .cookie(actix_web::cookie::Cookie::new("session", "old-session"))
        .cookie(actix_web::cookie::Cookie::new("csrf", "old-csrf"))
        .insert_header(("x-csrf-token", "old-csrf"))
}

#[actix_web::test]
async fn static_mfa_routes_lock_methods_cors_security_headers_and_no_store() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint()))
            .wrap(from_fn(nazo_http_actix::security_headers))
            .service(web::scope("/auth/mfa").configure(configure_mfa_challenge_route))
            .service(
                web::scope("/auth/me/mfa")
                    .wrap(
                        Cors::default()
                            .allowed_origin("https://app.example")
                            .allowed_methods(vec!["POST", "OPTIONS"])
                            .allow_any_header(),
                    )
                    .configure(configure_mfa_profile_routes),
            ),
    )
    .await;

    let paths = [
        "/auth/mfa/verify",
        "/auth/me/mfa/totp/begin",
        "/auth/me/mfa/totp/confirm",
        "/auth/me/mfa/step-up",
        "/auth/me/mfa/backup-codes/regenerate",
        "/auth/me/mfa/disable",
    ];
    for path in paths {
        let response =
            test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert_contract_headers(response.headers());

        let request = authenticated_request(Method::POST, path)
            .insert_header((header::CONTENT_TYPE, "application/json"));
        let request = if path.ends_with("/begin") {
            request.to_request()
        } else {
            request.set_payload(r#"{"code":"123456"}"#).to_request()
        };
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_contract_headers(response.headers());

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(Method::OPTIONS)
                .uri(path)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_contract_headers(response.headers());
    }

    let profile_preflight = test::call_service(
        &app,
        test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/auth/me/mfa/step-up")
            .insert_header((header::ORIGIN, "https://app.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request(),
    )
    .await;
    assert_eq!(
        profile_preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&header::HeaderValue::from_static("https://app.example"))
    );

    let challenge_preflight = test::call_service(
        &app,
        test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/auth/mfa/verify")
            .insert_header((header::ORIGIN, "https://app.example"))
            .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
            .to_request(),
    )
    .await;
    assert!(
        challenge_preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}

#[actix_web::test]
async fn malformed_json_and_rate_limit_fail_closed_with_stable_http_contract() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint_with(Operations {
                step_up_error: Some(MfaProfileError::rate_limit(
                    AuthenticationRateLimitError::Limited {
                        retry_after_seconds: 7,
                    },
                )),
                ..Operations::default()
            })))
            .wrap(from_fn(nazo_http_actix::security_headers))
            .service(web::scope("/auth/me/mfa").configure(configure_mfa_profile_routes)),
    )
    .await;

    let malformed = test::call_service(
        &app,
        authenticated_request(Method::POST, "/auth/me/mfa/step-up")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload("{")
            .to_request(),
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_contract_headers(malformed.headers());

    let limited = test::call_service(
        &app,
        authenticated_request(Method::POST, "/auth/me/mfa/step-up")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(r#"{"code":"123456"}"#)
            .to_request(),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.headers().get(header::RETRY_AFTER),
        Some(&header::HeaderValue::from_static("7"))
    );
    assert_contract_headers(limited.headers());
    assert_eq!(limited.response().cookies().count(), 0);
}

#[actix_web::test]
async fn disabling_only_clears_remembered_device_cookie_when_state_changed() {
    for (changed, expected_cookies) in [(false, 0), (true, 1)] {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(endpoint_with(Operations {
                    disable_changed: changed,
                    ..Operations::default()
                })))
                .wrap(from_fn(nazo_http_actix::security_headers))
                .service(web::scope("/auth/me/mfa").configure(configure_mfa_profile_routes)),
        )
        .await;
        let response = test::call_service(
            &app,
            authenticated_request(Method::POST, "/auth/me/mfa/disable")
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload(r#"{"code":"123456"}"#)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_contract_headers(response.headers());
        assert_eq!(response.response().cookies().count(), expected_cookies);
    }
}

#[actix_web::test]
async fn successful_step_up_rotates_session_and_csrf_as_a_no_store_pair() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint()))
            .wrap(from_fn(nazo_http_actix::security_headers))
            .service(web::scope("/auth/me/mfa").configure(configure_mfa_profile_routes)),
    )
    .await;
    let response = test::call_service(
        &app,
        authenticated_request(Method::POST, "/auth/me/mfa/step-up")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(r#"{"code":"123456"}"#)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_contract_headers(response.headers());
    let cookies = response.response().cookies().collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.name() == "session" && cookie.http_only() == Some(true))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.name() == "csrf" && cookie.http_only() != Some(true))
    );
}

fn assert_contract_headers(headers: &header::HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        headers.get(header::PRAGMA),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
    assert_eq!(
        headers.get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/json"))
    );
    assert!(headers.contains_key("x-content-type-options"));
}
