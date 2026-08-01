use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use actix_web::{App, http::header, test, web};
use nazo_resource_server::{
    ProtectedResourceAuthorizationResult, VerifiedAccessToken, VerifiedSenderConstraintProof,
};
use serde_json::{Value, json};

use super::*;

struct Authorizer {
    calls: Arc<AtomicUsize>,
}

impl FapiResourceAuthorizer for Authorizer {
    fn authorize<'a>(
        &'a self,
        _request: ProtectedResourceAuthorizationRequest<'a>,
        _context: ProtectedResourceAuthorizationContext<'a>,
    ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async {
            Ok(ProtectedResourceAuthorizationResult {
                token: VerifiedAccessToken {
                    issuer: "https://auth.example".to_owned(),
                    subject: "subject-1".to_owned(),
                    tenant_id: Some("01900000-0000-7000-8000-000000000001".to_owned()),
                    client_id: "client-1".to_owned(),
                    audiences: vec!["resource-1".to_owned()],
                    scopes: vec!["openid".to_owned(), "profile".to_owned()],
                    jti: "jti-1".to_owned(),
                    exp: i64::MAX,
                    cnf: None,
                    authorization_details: Value::Null,
                },
                sender_constraint: VerifiedSenderConstraintProof::default(),
            })
        })
    }
}

struct NoMtls;

impl FapiMtlsThumbprintResolver for NoMtls {
    fn resolve(&self, _request: &HttpRequest) -> Option<String> {
        None
    }
}

struct DisabledSignatures;

impl FapiHttpMessageSignatures for DisabledSignatures {
    fn enabled(&self) -> bool {
        false
    }

    fn verify_and_consume<'a>(
        &'a self,
        _tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a VerifiedInput,
    ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
        Box::pin(async { unreachable!("disabled signatures are not verified") })
    }

    fn response_signature(
        &self,
    ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
        Err(FapiSignatureOperationError::Unavailable)
    }
}

#[derive(Clone, Copy)]
enum AuthorizationOutcome {
    Success,
    UseNonce,
    NonceUnavailable,
    InvalidDpop,
}

struct RecordingAuthorizer {
    calls: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Vec<String>>>>,
    outcome: AuthorizationOutcome,
}

impl FapiResourceAuthorizer for RecordingAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: ProtectedResourceAuthorizationRequest<'a>,
        context: ProtectedResourceAuthorizationContext<'a>,
    ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.targets.lock().unwrap().push(
            context
                .target_uris
                .iter()
                .map(|target| (*target).to_owned())
                .collect(),
        );
        let outcome = self.outcome;
        Box::pin(async move {
            match outcome {
                AuthorizationOutcome::Success => Ok(successful_authorization()),
                AuthorizationOutcome::UseNonce => {
                    Err(FapiAuthorizationError::UseDpopNonce("nonce-1".to_owned()))
                }
                AuthorizationOutcome::NonceUnavailable => {
                    Err(FapiAuthorizationError::DpopNonceUnavailable)
                }
                AuthorizationOutcome::InvalidDpop => Err(FapiAuthorizationError::Protocol(
                    ProtectedResourceAuthorizationError::InvalidDpopProof(
                        DpopProofVerifierError::InvalidSignature,
                    ),
                )),
            }
        })
    }
}

fn successful_authorization() -> ProtectedResourceAuthorizationResult {
    ProtectedResourceAuthorizationResult {
        token: VerifiedAccessToken {
            issuer: "https://auth.example".to_owned(),
            subject: "subject-1".to_owned(),
            tenant_id: Some("01900000-0000-7000-8000-000000000001".to_owned()),
            client_id: "client-1".to_owned(),
            audiences: vec!["resource-1".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            jti: "jti-1".to_owned(),
            exp: i64::MAX,
            cnf: None,
            authorization_details: Value::Null,
        },
        sender_constraint: VerifiedSenderConstraintProof::default(),
    }
}

struct TestResponseSigner {
    fail: bool,
    bases: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FapiResponseSignature for TestResponseSigner {
    fn kid(&self) -> &str {
        "response-key"
    }

    fn algorithm(&self) -> &str {
        "ed25519"
    }

    fn sign<'a>(
        &'a self,
        signature_base: &'a [u8],
    ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>> {
        self.bases.lock().unwrap().push(signature_base.to_vec());
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(FapiSignatureOperationError::Unavailable)
            } else {
                Ok(vec![7; 64])
            }
        })
    }
}

struct EnabledSignatures {
    verification: Result<(), FapiSignatureVerificationError>,
    verify_calls: Arc<AtomicUsize>,
    signer: Arc<TestResponseSigner>,
}

impl FapiHttpMessageSignatures for EnabledSignatures {
    fn enabled(&self) -> bool {
        true
    }

    fn verify_and_consume<'a>(
        &'a self,
        _tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a VerifiedInput,
    ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
        self.verify_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.verification;
        Box::pin(async move { result })
    }

    fn response_signature(
        &self,
    ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
        Ok(self.signer.clone())
    }
}

struct SignatureTestState {
    endpoint: Data<FapiResourceEndpoint>,
    authorizer_calls: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Vec<String>>>>,
    verify_calls: Arc<AtomicUsize>,
    bases: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn signature_endpoint(
    outcome: AuthorizationOutcome,
    verification: Result<(), FapiSignatureVerificationError>,
    signer_fails: bool,
) -> SignatureTestState {
    let authorizer_calls = Arc::new(AtomicUsize::new(0));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let verify_calls = Arc::new(AtomicUsize::new(0));
    let bases = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(FapiResourceEndpoint::new(
        "https://auth.example",
        "https://mtls.auth.example",
        60,
        Arc::new(RecordingAuthorizer {
            calls: authorizer_calls.clone(),
            targets: targets.clone(),
            outcome,
        }),
        Arc::new(NoMtls),
        Arc::new(EnabledSignatures {
            verification,
            verify_calls: verify_calls.clone(),
            signer: Arc::new(TestResponseSigner {
                fail: signer_fails,
                bases: bases.clone(),
            }),
        }),
    ));
    SignatureTestState {
        endpoint,
        authorizer_calls,
        targets,
        verify_calls,
        bases,
    }
}

fn request_signature_fields(method: &str, body: &[u8], dpop: Option<&str>) -> SignatureFields {
    let authorization = "Bearer access-token";
    let digest = (!body.is_empty()).then(|| content_digest(body));
    let mut headers = vec![("authorization", authorization)];
    if let Some(dpop) = dpop {
        headers.push(("dpop", dpop));
    }
    if let Some(digest) = digest.as_deref() {
        headers.push(("content-digest", digest));
    }
    nazo_http_signatures::prepare_request(
        RequestInput {
            method,
            target_uri: "https://auth.example/fapi/resource",
            headers: &headers,
            body,
        },
        nazo_http_signatures::RequestPolicy {
            created: Utc::now().timestamp(),
            keyid: "client-key",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap()
    .finish(&[3; 64])
}

fn endpoint(calls: Arc<AtomicUsize>) -> Data<FapiResourceEndpoint> {
    Data::new(FapiResourceEndpoint::new(
        "https://auth.example",
        "https://mtls.auth.example",
        60,
        Arc::new(Authorizer { calls }),
        Arc::new(NoMtls),
        Arc::new(DisabledSignatures),
    ))
}

#[actix_web::test]
async fn handler_extracts_calls_core_and_preserves_success_contract() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = test::init_service(
        App::new().app_data(endpoint(calls.clone())).service(
            web::resource("/fapi/resource")
                .route(web::get().to(fapi_resource))
                .route(web::post().to(fapi_resource)),
        ),
    )
    .await;
    let request = test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer access-token"))
        .insert_header(("x-fapi-interaction-id", "interaction-1"))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get("x-fapi-interaction-id").unwrap(),
        "interaction-1"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(!response.headers().contains_key("signature-input"));
    assert!(!response.headers().contains_key("signature"));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        test::read_body_json::<Value, _>(response).await,
        json!({
            "sub": "subject-1",
            "client_id": "client-1",
            "scope": "openid profile",
            "aud": "resource-1"
        })
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_form_body_access_tokens_without_signature_module() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = test::init_service(
        App::new()
            .app_data(endpoint(calls.clone()))
            .route("/fapi/resource", web::post().to(fapi_resource)),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/fapi/resource")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("access_token=form-token")
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        test::read_body_json::<Value, _>(response).await,
        json!({
            "error": "invalid_request",
            "error_description": "Only one access token transport method may be used."
        })
    );
}

#[actix_web::test]
async fn missing_token_preserves_bearer_error_and_skips_core() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = test::init_service(
        App::new()
            .app_data(endpoint(calls.clone()))
            .route("/fapi/resource", web::get().to(fapi_resource)),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/fapi/resource").to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer error=\"invalid_token\", error_description=\"Request failed.\""
    );
    assert_eq!(
        test::read_body_json::<Value, _>(response).await,
        json!({"error":"invalid_token","error_description":"Request failed."})
    );
}

#[actix_web::test]
async fn signed_get_uses_one_authorization_call_and_signs_the_success_response() {
    let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
    let app = test::init_service(
        App::new()
            .app_data(state.endpoint.clone())
            .route("/fapi/resource", web::get().to(fapi_resource)),
    )
    .await;
    let fields = request_signature_fields("GET", b"", None);
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "Bearer access-token"))
            .insert_header(("signature-input", fields.signature_input))
            .insert_header(("signature", fields.signature))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
    assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));
    let digest = response
        .headers()
        .get("content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = test::read_body(response).await;
    assert!(content_digest_field_matches(&digest, &body));
    assert_eq!(
        *state.targets.lock().unwrap(),
        vec![vec![
            "https://auth.example/fapi/resource".to_owned(),
            "https://mtls.auth.example/fapi/resource".to_owned(),
        ]]
    );
    let bases = state.bases.lock().unwrap();
    let base = std::str::from_utf8(&bases[0]).unwrap();
    assert!(base.contains("\"@status\""));
    assert!(base.contains("\"@method\";req"));
    assert!(base.contains("\"@target-uri\";req"));
    assert!(base.contains("\"signature\";req"));
}

#[actix_web::test]
async fn signed_post_binds_the_received_request_digest() {
    let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
    let app = test::init_service(
        App::new()
            .app_data(state.endpoint.clone())
            .route("/fapi/resource", web::post().to(fapi_resource)),
    )
    .await;
    let body = b"operation=read";
    let digest = content_digest(body);
    let fields = request_signature_fields("POST", body, None);
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "Bearer access-token"))
            .insert_header(("content-digest", digest.as_str()))
            .insert_header(("signature-input", fields.signature_input))
            .insert_header(("signature", fields.signature))
            .set_payload(body.as_slice())
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
    assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
    let bases = state.bases.lock().unwrap();
    let base = std::str::from_utf8(&bases[0]).unwrap();
    assert!(base.contains("\"content-digest\";req"));
    assert!(base.contains(digest.as_str()));
}

#[actix_web::test]
async fn malformed_or_duplicate_signature_fields_fail_before_authorization_and_are_signed() {
    for duplicate in [false, true] {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let mut request = test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "Bearer access-token"));
        if duplicate {
            request = request
                .append_header(("signature-input", "sig=()"))
                .append_header(("signature-input", "sig=()"))
                .insert_header(("signature", "sig=:AA=:"));
        }
        let response = test::call_service(&app, request.to_request()).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 0);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 0);
        assert!(response.headers().contains_key("signature-input"));
        assert!(response.headers().contains_key("signature"));
        assert!(!response.headers().contains_key(header::CACHE_CONTROL));
    }
}

#[actix_web::test]
async fn duplicate_dpop_header_preserves_invalid_dpop_contract_and_skips_core() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = test::init_service(
        App::new()
            .app_data(endpoint(calls.clone()))
            .route("/fapi/resource", web::get().to(fapi_resource)),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "DPoP access-token"))
            .append_header(("dpop", "first"))
            .append_header(("dpop", "second"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "DPoP error=\"invalid_dpop_proof\""
    );
    assert_eq!(
        test::read_body_json::<Value, _>(response).await,
        json!({
            "error": "invalid_dpop_proof",
            "error_description": "DPoP proof is malformed."
        })
    );
}

#[actix_web::test]
async fn nonce_challenge_and_nonce_dependency_failure_keep_exact_signed_http_contracts() {
    for (outcome, status, error, description, challenge) in [
        (
            AuthorizationOutcome::UseNonce,
            StatusCode::UNAUTHORIZED,
            "use_dpop_nonce",
            "Authorization server requires nonce in DPoP proof.",
            "DPoP error=\"use_dpop_nonce\"",
        ),
        (
            AuthorizationOutcome::NonceUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "DPoP nonce validation is unavailable.",
            "DPoP error=\"server_error\"",
        ),
    ] {
        let state = signature_endpoint(outcome, Ok(()), false);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let fields = request_signature_fields("GET", b"", Some("proof"));
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .insert_header(("dpop", "proof"))
                .insert_header(("signature-input", fields.signature_input))
                .insert_header(("signature", fields.signature))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            challenge
        );
        if matches!(outcome, AuthorizationOutcome::UseNonce) {
            assert_eq!(response.headers().get("dpop-nonce").unwrap(), "nonce-1");
        }
        assert!(response.headers().contains_key("signature-input"));
        assert_eq!(
            test::read_body_json::<Value, _>(response).await,
            json!({"error": error, "error_description": description})
        );
    }
}

#[actix_web::test]
async fn signature_verification_failures_preserve_status_and_signed_error_contracts() {
    for (verification, status) in [
        (
            Err(FapiSignatureVerificationError::Invalid),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Err(FapiSignatureVerificationError::Replay),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Err(FapiSignatureVerificationError::LookupUnavailable),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            Err(FapiSignatureVerificationError::ReplayUnavailable),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let state = signature_endpoint(AuthorizationOutcome::Success, verification, false);
        let app = test::init_service(
            App::new()
                .app_data(state.endpoint.clone())
                .route("/fapi/resource", web::get().to(fapi_resource)),
        )
        .await;
        let fields = request_signature_fields("GET", b"", None);
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .insert_header(("signature-input", fields.signature_input))
                .insert_header(("signature", fields.signature))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), status);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
        assert!(response.headers().contains_key("signature-input"));
        assert!(response.headers().contains_key("signature"));
    }
}

#[actix_web::test]
async fn response_signer_failure_returns_an_empty_unsigned_503() {
    let state = signature_endpoint(AuthorizationOutcome::InvalidDpop, Ok(()), true);
    let app = test::init_service(
        App::new()
            .app_data(state.endpoint.clone())
            .route("/fapi/resource", web::get().to(fapi_resource)),
    )
    .await;
    let fields = request_signature_fields("GET", b"", None);
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, "Bearer access-token"))
            .insert_header(("signature-input", fields.signature_input))
            .insert_header(("signature", fields.signature))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("signature-input"));
    assert!(!response.headers().contains_key("signature"));
    assert!(test::read_body(response).await.is_empty());
}

#[actix_web::test]
async fn response_signing_preserves_multiple_physical_header_values() {
    let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
    let fields = request_signature_fields("GET", b"", None);
    let request = test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer access-token"))
        .insert_header(("signature-input", fields.signature_input))
        .insert_header(("signature", fields.signature))
        .to_http_request();
    let original = CapturedRequest::capture("https://auth.example", &request, &Bytes::new());
    let response = HttpResponse::Ok()
        .append_header((header::SET_COOKIE, "first=1; Secure"))
        .append_header((header::SET_COOKIE, "second=2; Secure"))
        .json(json!({"ok": true}));

    let signed = sign_response(&state.endpoint, &original, response).await;
    assert_eq!(signed.status(), StatusCode::OK);
    assert_eq!(signed.headers().get_all(header::SET_COOKIE).count(), 2);
    assert!(signed.headers().contains_key("signature-input"));
    assert!(signed.headers().contains_key("signature"));
}

#[actix_web::test]
async fn signature_enabled_endpoint_rejects_form_body_access_tokens_before_core() {
    let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
    let app = test::init_service(
        App::new()
            .app_data(state.endpoint.clone())
            .route("/fapi/resource", web::post().to(fapi_resource)),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/fapi/resource")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("access_token=form-token")
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 0);
    assert_eq!(state.verify_calls.load(Ordering::Relaxed), 0);
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));
    assert_eq!(
        test::read_body_json::<Value, _>(response).await,
        json!({
            "error": "invalid_request",
            "error_description": "Only one access token transport method may be used."
        })
    );
}

#[actix_web::test]
async fn bearer_dpop_and_mtls_protocol_errors_keep_exact_http_contracts() {
    use nazo_resource_server::ProtectedResourceDependencyError;

    let cases = vec![
        (
            ProtectedResourceAuthorizationError::InvalidToken(
                ResourceServerVerifierError::AudienceMismatch,
            ),
            AccessTokenAuthScheme::Bearer,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Request failed.",
            "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
        ),
        (
            ProtectedResourceAuthorizationError::InvalidToken(ResourceServerVerifierError::Expired),
            AccessTokenAuthScheme::Bearer,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Request failed.",
            "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
        ),
        (
            ProtectedResourceAuthorizationError::InvalidTenantBoundary,
            AccessTokenAuthScheme::Bearer,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Request failed.",
            "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
        ),
        (
            ProtectedResourceAuthorizationError::Revoked,
            AccessTokenAuthScheme::Bearer,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Request failed.",
            "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
        ),
        (
            ProtectedResourceAuthorizationError::DependencyUnavailable(
                ProtectedResourceDependencyError::RevocationLookupUnavailable,
            ),
            AccessTokenAuthScheme::Bearer,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Request failed.",
            "Bearer error=\"server_error\", error_description=\"Request failed.\"",
        ),
        (
            ProtectedResourceAuthorizationError::TokenNotDpopBound,
            AccessTokenAuthScheme::DPoP,
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "Token is not DPoP-bound.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::MissingSenderConstraint,
            AccessTokenAuthScheme::DPoP,
            StatusCode::UNAUTHORIZED,
            "invalid_dpop_proof",
            "DPoP proof is required.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::MissingSenderConstraint,
            AccessTokenAuthScheme::Bearer,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token requires a verified client certificate.",
            "Bearer error=\"invalid_token\", error_description=\"mTLS-bound access token requires a verified client certificate.\"",
        ),
        (
            ProtectedResourceAuthorizationError::DpopBindingMismatch,
            AccessTokenAuthScheme::DPoP,
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP binding mismatch.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::ReplayDetected,
            AccessTokenAuthScheme::DPoP,
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof jti has already been used.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::InvalidDpopProof(
                DpopProofVerifierError::MalformedProof,
            ),
            AccessTokenAuthScheme::DPoP,
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof is malformed.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::InvalidDpopProof(
                DpopProofVerifierError::ReplayDetected,
            ),
            AccessTokenAuthScheme::DPoP,
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof jti has already been used.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::InvalidDpopProof(
                DpopProofVerifierError::InvalidSignature,
            ),
            AccessTokenAuthScheme::DPoP,
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof validation failed.",
            "DPoP error=\"invalid_dpop_proof\"",
        ),
        (
            ProtectedResourceAuthorizationError::MtlsBindingMismatch,
            AccessTokenAuthScheme::Bearer,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token certificate mismatch.",
            "Bearer error=\"invalid_token\", error_description=\"mTLS-bound access token certificate mismatch.\"",
        ),
        (
            ProtectedResourceAuthorizationError::DependencyUnavailable(
                ProtectedResourceDependencyError::DpopNonceStoreUnavailable,
            ),
            AccessTokenAuthScheme::DPoP,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "DPoP nonce validation is unavailable.",
            "DPoP error=\"server_error\"",
        ),
    ];

    for (error, scheme, status, code, description, challenge) in cases {
        let response = protocol_error_response(error, scheme);
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            challenge
        );
        let body = to_bytes(response.into_body()).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": code, "error_description": description})
        );
    }

    let nonce = "resource-nonce-1";
    let response = protocol_error_response(
        ProtectedResourceAuthorizationError::UseDpopNonce(nonce.to_owned()),
        AccessTokenAuthScheme::DPoP,
    );
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get("dpop-nonce").unwrap(), nonce);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "DPoP error=\"use_dpop_nonce\""
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&to_bytes(response.into_body()).await.unwrap()).unwrap(),
        json!({
            "error": "use_dpop_nonce",
            "error_description": "Authorization server requires nonce in DPoP proof."
        })
    );
}
