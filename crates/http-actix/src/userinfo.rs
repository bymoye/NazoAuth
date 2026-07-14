use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use serde_json::Value;

use crate::{
    AccessTokenAuthScheme, ResourceAccessToken, json_response_no_store, oauth_bearer_error,
    oauth_error, resource_access_token,
};

pub type UserinfoFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UserinfoSuccess, UserinfoError>> + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub enum UserinfoRepresentation {
    Claims(Value),
    Jwt(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserinfoSuccess {
    pub representation: UserinfoRepresentation,
    pub dpop_nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserinfoDpopError {
    MissingProof,
    MalformedProof,
    InvalidProof,
    ReplayDetected,
    BindingMismatch,
    TokenNotBound,
    UseNonce(String),
    NonceStoreUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserinfoError {
    InvalidAccessToken,
    InvalidAudience,
    InvalidTenantBoundary,
    RevokedAccessToken,
    Dpop(UserinfoDpopError),
    MissingMtlsCertificate,
    MtlsCertificateMismatch,
    InsufficientScope,
    InvalidSubject,
    InactiveSubject,
    ClientUnavailable,
    QueryUnavailable,
    ResponseProtectionFailed,
}

pub trait UserinfoOperations: Send + Sync {
    fn userinfo<'a>(
        &'a self,
        request: &'a HttpRequest,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> UserinfoFuture<'a>;
}

#[derive(Clone)]
pub struct UserinfoEndpoint {
    operations: Arc<dyn UserinfoOperations>,
}

impl UserinfoEndpoint {
    pub fn new(operations: Arc<dyn UserinfoOperations>) -> Self {
        Self { operations }
    }
}

pub async fn userinfo(
    endpoint: Data<UserinfoEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let (scheme, token) = match resource_access_token(&request, &body, false) {
        ResourceAccessToken::Present(scheme, token) => (scheme, token),
        ResourceAccessToken::Missing => {
            return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
        }
        ResourceAccessToken::InvalidRequest => {
            return oauth_bearer_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Only one access token transport method may be used.",
            );
        }
    };

    match endpoint.operations.userinfo(&request, scheme, token).await {
        Ok(success) => userinfo_success_response(success),
        Err(error) => userinfo_error_response(error),
    }
}

fn userinfo_success_response(success: UserinfoSuccess) -> HttpResponse {
    let mut response = match success.representation {
        UserinfoRepresentation::Claims(claims) => json_response_no_store(claims),
        UserinfoRepresentation::Jwt(jwt) => HttpResponse::Ok()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/jwt"),
            ))
            .insert_header((
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            ))
            .insert_header((header::PRAGMA, header::HeaderValue::from_static("no-cache")))
            .body(jwt),
    };
    if let Some(nonce) = success.dpop_nonce
        && let Ok(value) = header::HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}

fn userinfo_error_response(error: UserinfoError) -> HttpResponse {
    match error {
        UserinfoError::InvalidAccessToken => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌无效或已过期.",
        ),
        UserinfoError::InvalidAudience => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌 audience 不适用于 userinfo.",
        ),
        UserinfoError::InvalidTenantBoundary => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌租户边界无效.",
        ),
        UserinfoError::RevokedAccessToken => {
            oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已撤销.")
        }
        UserinfoError::Dpop(error) => userinfo_dpop_error_response(error),
        UserinfoError::MissingMtlsCertificate => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token requires a verified client certificate.",
        ),
        UserinfoError::MtlsCertificateMismatch => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token certificate mismatch.",
        ),
        UserinfoError::InsufficientScope => oauth_bearer_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "userinfo 需要 openid scope.",
        ),
        UserinfoError::InvalidSubject => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌主体无效.",
        ),
        UserinfoError::InactiveSubject => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌主体不存在或已停用.",
        ),
        UserinfoError::ClientUnavailable => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "userinfo 客户端状态不可用.",
        ),
        UserinfoError::QueryUnavailable => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "userinfo 查询失败.",
        ),
        UserinfoError::ResponseProtectionFailed => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "userinfo 响应生成失败.",
        ),
    }
}

fn userinfo_dpop_error_response(error: UserinfoDpopError) -> HttpResponse {
    let description = match &error {
        UserinfoDpopError::MissingProof => "DPoP proof is required.",
        UserinfoDpopError::MalformedProof => "DPoP proof is malformed.",
        UserinfoDpopError::InvalidProof => "DPoP proof validation failed.",
        UserinfoDpopError::ReplayDetected => "DPoP proof jti has already been used.",
        UserinfoDpopError::BindingMismatch => "DPoP binding mismatch.",
        UserinfoDpopError::TokenNotBound => "Token is not DPoP-bound.",
        UserinfoDpopError::UseNonce(_) => "Authorization server requires nonce in DPoP proof.",
        UserinfoDpopError::NonceStoreUnavailable => "DPoP nonce validation is unavailable.",
    };
    let status = match &error {
        UserinfoDpopError::MissingProof | UserinfoDpopError::UseNonce(_) => {
            StatusCode::UNAUTHORIZED
        }
        UserinfoDpopError::NonceStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let error_code = match &error {
        UserinfoDpopError::UseNonce(_) => "use_dpop_nonce",
        UserinfoDpopError::NonceStoreUnavailable => "server_error",
        _ => "invalid_dpop_proof",
    };
    let mut response = oauth_error(status, error_code, description);
    if let UserinfoDpopError::UseNonce(nonce) = error
        && let Ok(value) = header::HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_str(&format!("DPoP error=\"{error_code}\""))
            .unwrap_or_else(|_| header::HeaderValue::from_static("DPoP")),
    );
    response
}

#[cfg(test)]
mod tests {
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
}
