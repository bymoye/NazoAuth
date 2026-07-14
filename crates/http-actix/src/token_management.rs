use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use nazo_auth::TokenInspection;

use crate::{
    ClientCertificateFacts, TokenClientAuthForm, TokenClientAuthTransportFacts, TokenOnlyForm,
    authorization_error_response, empty_response_no_store, json_response_no_store,
    oauth_token_error, parse_token_management_form, token_client_auth_transport_facts,
    token_management_form_error, token_management_has_conflicting_client_auth,
    token_management_oauth_error,
};

pub const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub type TokenManagementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TokenManagementError>> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementError {
    InvalidClient { basic_challenge: bool },
    AuthenticationStoreUnavailable,
    ClientLookupUnavailable,
    InspectionUnavailable,
    RevocationUnavailable,
    ResponseProtectionFailed,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenIntrospectionRepresentation {
    Inspection(TokenInspection),
    Jwt(String),
}

/// Deployment-derived request facts shared by rate limiting and token-management operations.
///
/// Protocol/application implementations never receive the Actix request or its headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenManagementRequestFacts {
    pub source_ip: String,
    pub endpoint_path: String,
    pub client_certificate: Option<ClientCertificateFacts>,
}

pub trait TokenManagementRequestFactsExtractor: Send + Sync {
    /// Extracts only cheap facts needed before rate limiting.
    fn extract(&self, request: &HttpRequest) -> TokenManagementRequestFacts;

    /// Resolves a verified certificate after rate limiting and form/auth-source validation.
    /// Implementations must only return a certificate for a trusted forwarding peer.
    fn extract_client_certificate(&self, _request: &HttpRequest) -> Option<ClientCertificateFacts> {
        None
    }
}

pub trait TokenManagementRequestGuard: Send + Sync {
    fn enforce<'a>(
        &'a self,
        request: &'a TokenManagementRequestFacts,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>>;
}

pub trait TokenManagementOperations: Send + Sync {
    fn introspect<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation>;

    fn revoke<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()>;
}

#[derive(Clone)]
pub struct TokenManagementEndpoint {
    request_facts: Arc<dyn TokenManagementRequestFactsExtractor>,
    guard: Arc<dyn TokenManagementRequestGuard>,
    operations: Arc<dyn TokenManagementOperations>,
}

impl TokenManagementEndpoint {
    pub fn new(
        request_facts: Arc<dyn TokenManagementRequestFactsExtractor>,
        guard: Arc<dyn TokenManagementRequestGuard>,
        operations: Arc<dyn TokenManagementOperations>,
    ) -> Self {
        Self {
            request_facts,
            guard,
            operations,
        }
    }
}

pub async fn introspect(
    endpoint: Data<TokenManagementEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let mut request_facts = endpoint.request_facts.extract(&request);
    if let Err(response) = enforce_rate_limit(&endpoint, &request_facts).await {
        return response;
    }
    let form = match parse_token_management_form(&request, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };
    let client_auth = token_client_auth_transport_facts(
        &request,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let has_basic = client_auth.basic_challenge();
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    request_facts.client_certificate = endpoint.request_facts.extract_client_certificate(&request);
    let signed_response_requested = signed_introspection_requested(&request);
    match endpoint
        .operations
        .introspect(request_facts, client_auth, form, signed_response_requested)
        .await
    {
        Ok(TokenIntrospectionRepresentation::Inspection(inspection)) => {
            json_response_no_store(inspection.into_document())
        }
        Ok(TokenIntrospectionRepresentation::Jwt(token)) => HttpResponse::Ok()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static(TOKEN_INTROSPECTION_JWT_MEDIA_TYPE),
            ))
            .insert_header((
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            ))
            .insert_header((header::PRAGMA, header::HeaderValue::from_static("no-cache")))
            .body(token),
        Err(error) => token_management_error_response(error),
    }
}

pub async fn revoke(
    endpoint: Data<TokenManagementEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let mut request_facts = endpoint.request_facts.extract(&request);
    if let Err(response) = enforce_rate_limit(&endpoint, &request_facts).await {
        return response;
    }
    let form = match parse_token_management_form(&request, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };
    let client_auth = token_client_auth_transport_facts(
        &request,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let has_basic = client_auth.basic_challenge();
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    request_facts.client_certificate = endpoint.request_facts.extract_client_certificate(&request);
    match endpoint
        .operations
        .revoke(request_facts, client_auth, form)
        .await
    {
        Ok(()) => empty_response_no_store(StatusCode::OK),
        Err(error) => token_management_error_response(error),
    }
}

fn signed_introspection_requested(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type.trim() == TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
                })
            })
        })
}

async fn enforce_rate_limit(
    endpoint: &TokenManagementEndpoint,
    request: &TokenManagementRequestFacts,
) -> Result<(), HttpResponse> {
    match endpoint.guard.enforce(request).await {
        Ok(()) => Ok(()),
        Err(TokenManagementRateLimitError::Unavailable) => Err(token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        )),
        Err(TokenManagementRateLimitError::Limited {
            retry_after_seconds,
        }) => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Err(response)
        }
    }
}

fn token_management_error_response(error: TokenManagementError) -> HttpResponse {
    match error {
        TokenManagementError::InvalidClient { basic_challenge } => oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            basic_challenge,
        ),
        TokenManagementError::AuthenticationStoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
        TokenManagementError::ClientLookupUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端查询失败.",
        ),
        TokenManagementError::InspectionUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 状态查询失败.",
        ),
        TokenManagementError::RevocationUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 撤销失败.",
        ),
        TokenManagementError::ResponseProtectionFailed => token_management_oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token introspection JWT response build failed.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, http::header, middleware::from_fn, test, web};

    use super::*;

    #[derive(Clone, Copy)]
    struct FakeRequestFacts;

    impl TokenManagementRequestFactsExtractor for FakeRequestFacts {
        fn extract(&self, request: &HttpRequest) -> TokenManagementRequestFacts {
            TokenManagementRequestFacts {
                source_ip: "127.0.0.1".to_owned(),
                endpoint_path: request.path().to_owned(),
                client_certificate: None,
            }
        }
    }

    #[derive(Clone, Copy)]
    struct PanicCertificateFacts;

    impl TokenManagementRequestFactsExtractor for PanicCertificateFacts {
        fn extract(&self, request: &HttpRequest) -> TokenManagementRequestFacts {
            FakeRequestFacts.extract(request)
        }

        fn extract_client_certificate(
            &self,
            _request: &HttpRequest,
        ) -> Option<ClientCertificateFacts> {
            panic!("certificate parsing must not run before cheap request rejection")
        }
    }

    #[derive(Clone, Copy)]
    struct FakeGuard(Result<(), TokenManagementRateLimitError>);

    impl TokenManagementRequestGuard for FakeGuard {
        fn enforce<'a>(
            &'a self,
            _request: &'a TokenManagementRequestFacts,
        ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>>
        {
            let result = self.0;
            Box::pin(async move { result })
        }
    }

    #[derive(Clone)]
    struct FakeOperations {
        introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
        revocation: Result<(), TokenManagementError>,
    }

    impl TokenManagementOperations for FakeOperations {
        fn introspect<'a>(
            &'a self,
            _request: TokenManagementRequestFacts,
            _client_auth: TokenClientAuthTransportFacts,
            _form: TokenOnlyForm,
            _signed_response_requested: bool,
        ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation> {
            let result = self.introspection.clone();
            Box::pin(async move { result })
        }

        fn revoke<'a>(
            &'a self,
            _request: TokenManagementRequestFacts,
            _client_auth: TokenClientAuthTransportFacts,
            _form: TokenOnlyForm,
        ) -> TokenManagementFuture<'a, ()> {
            let result = self.revocation;
            Box::pin(async move { result })
        }
    }

    fn endpoint(
        guard: Result<(), TokenManagementRateLimitError>,
        introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
        revocation: Result<(), TokenManagementError>,
    ) -> TokenManagementEndpoint {
        endpoint_with_request_facts(Arc::new(FakeRequestFacts), guard, introspection, revocation)
    }

    fn endpoint_with_request_facts(
        request_facts: Arc<dyn TokenManagementRequestFactsExtractor>,
        guard: Result<(), TokenManagementRateLimitError>,
        introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
        revocation: Result<(), TokenManagementError>,
    ) -> TokenManagementEndpoint {
        TokenManagementEndpoint::new(
            request_facts,
            Arc::new(FakeGuard(guard)),
            Arc::new(FakeOperations {
                introspection,
                revocation,
            }),
        )
    }

    #[actix_web::test]
    async fn expensive_certificate_parsing_happens_after_rate_and_form_rejection() {
        let limited = test::init_service(
            App::new()
                .app_data(Data::new(endpoint_with_request_facts(
                    Arc::new(PanicCertificateFacts),
                    Err(TokenManagementRateLimitError::Limited {
                        retry_after_seconds: 30,
                    }),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &limited,
            test::TestRequest::post()
                .uri("/introspect")
                .set_payload("not-a-form")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let malformed = test::init_service(
            App::new()
                .app_data(Data::new(endpoint_with_request_facts(
                    Arc::new(PanicCertificateFacts),
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &malformed,
            test::TestRequest::post()
                .uri("/introspect")
                .set_payload("not-a-form")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn form_request(method: &'static str, path: &'static str) -> test::TestRequest {
        let request = match method {
            "POST" => test::TestRequest::post(),
            _ => unreachable!("only POST is used"),
        };
        request
            .uri(path)
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("token=opaque&client_id=client")
    }

    fn assert_security_headers(headers: &header::HeaderMap) {
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(
            headers.get("permissions-policy").unwrap(),
            "interest-cohort=()"
        );
        assert_eq!(
            headers.get("content-security-policy").unwrap(),
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[actix_web::test]
    async fn revocation_route_locks_post_get_options_cors_and_security_contracts() {
        let allowed_origin = "https://client.example";
        let service = test::init_service(
            App::new()
                .wrap(from_fn(crate::middleware::security_headers))
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .service(
                    web::resource("/revoke")
                        .wrap(crate::cors::cors_browser_token_management(&[
                            allowed_origin.to_owned(),
                        ]))
                        .route(web::post().to(revoke)),
                ),
        )
        .await;

        let post = test::call_service(
            &service,
            form_request("POST", "/revoke")
                .insert_header((header::ORIGIN, allowed_origin))
                .to_request(),
        )
        .await;
        assert_eq!(post.status(), StatusCode::OK);
        assert_eq!(
            post.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(post.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            post.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            allowed_origin
        );
        assert!(post.headers().get(header::CONTENT_TYPE).is_none());
        assert_security_headers(post.headers());
        assert!(test::read_body(post).await.is_empty());

        let get = test::call_service(
            &service,
            test::TestRequest::get().uri("/revoke").to_request(),
        )
        .await;
        assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(get.headers().get(header::CONTENT_TYPE).is_none());
        assert_security_headers(get.headers());
        assert!(test::read_body(get).await.is_empty());

        let options = test::call_service(
            &service,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/revoke")
                .insert_header((header::ORIGIN, allowed_origin))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .insert_header((
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization, content-type, dpop",
                ))
                .to_request(),
        )
        .await;
        assert_eq!(options.status(), StatusCode::OK);
        assert_eq!(
            options
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            allowed_origin
        );
        let methods = options
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.split(',').any(|method| method.trim() == "POST"));
        assert!(options.headers().get(header::CONTENT_TYPE).is_none());
        assert_security_headers(options.headers());
        assert!(test::read_body(options).await.is_empty());
    }

    #[actix_web::test]
    async fn introspection_route_has_no_browser_cors_and_rejects_get_and_options() {
        let service = test::init_service(
            App::new()
                .wrap(from_fn(crate::middleware::security_headers))
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;

        for request in [
            test::TestRequest::get().uri("/introspect").to_request(),
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/introspect")
                .insert_header((header::ORIGIN, "https://client.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                .to_request(),
        ] {
            let response = test::call_service(&service, request).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
            assert!(response.headers().get(header::CONTENT_TYPE).is_none());
            assert_security_headers(response.headers());
            assert!(test::read_body(response).await.is_empty());
        }
    }

    #[actix_web::test]
    async fn rate_limit_runs_before_form_parsing_and_keeps_retry_contract() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Err(TokenManagementRateLimitError::Limited {
                        retry_after_seconds: 30,
                    }),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/introspect")
                .set_payload("not-a-form")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "temporarily_unavailable");
    }

    #[actix_web::test]
    async fn inactive_introspection_is_exact_rfc7662_no_store_json() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response =
            test::call_service(&service, form_request("POST", "/introspect").to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body, serde_json::json!({"active": false}));
    }

    #[actix_web::test]
    async fn signed_introspection_keeps_media_type_and_cache_headers() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Jwt(
                        "signed.jwt".to_owned(),
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &service,
            form_request("POST", "/introspect")
                .insert_header((header::ACCEPT, TOKEN_INTROSPECTION_JWT_MEDIA_TYPE))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(test::read_body(response).await, "signed.jwt");
    }

    #[actix_web::test]
    async fn basic_invalid_client_keeps_challenge_and_oauth_error() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Err(TokenManagementError::InvalidClient {
                        basic_challenge: true,
                    }),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/introspect")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload("token=opaque")
                .insert_header((header::AUTHORIZATION, "Basic Y2xpZW50OnNlY3JldA=="))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"nazo-oauth\""
        );
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_client");
    }

    #[actix_web::test]
    async fn revocation_success_is_empty_and_non_cacheable() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/revoke", web::post().to(revoke)),
        )
        .await;
        let response =
            test::call_service(&service, form_request("POST", "/revoke").to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert!(test::read_body(response).await.is_empty());
    }
}
