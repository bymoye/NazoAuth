use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{self, Data, Json, Path, ServiceConfig},
};
use chrono::{DateTime, Utc};
use nazo_identity::{
    LoginSuccess, PasskeyError, PasskeyLoginBegin, PasskeyRegistrationBegin, RememberedMfaProof,
    ports::PasskeyCredential,
};
use passkey_auth::{AuthenticationResponse, RegistrationResponse};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AuthenticationRateLimit, AuthenticationRateLimitError, ClientIpConfig,
    authorization_error_response, clear_cookie, client_ip_with_config, cookie_value, csrf_error,
    empty_response_no_store, has_valid_csrf_token_for_cookies, json_response_no_store,
    json_response_status_no_store, make_cookie, with_cookie_headers,
};

pub type PasskeyFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PasskeyEndpointError>> + Send + 'a>>;

#[derive(Debug)]
pub enum PasskeyEndpointError {
    Core(PasskeyError),
    SessionMissing,
    SessionUnavailable,
}

impl From<PasskeyError> for PasskeyEndpointError {
    fn from(error: PasskeyError) -> Self {
        Self::Core(error)
    }
}

pub struct PasskeyLoginFinishCommand {
    pub ceremony_id: String,
    pub response: AuthenticationResponse,
    pub source_ip: String,
    pub remembered_mfa: Option<RememberedMfaProof>,
    pub previous_session_id: Option<String>,
    pub now: DateTime<Utc>,
}

pub trait PasskeyLoginOperations: Send + Sync {
    fn login_begin(&self, email: String) -> PasskeyFuture<'_, PasskeyLoginBegin>;

    fn login_finish(&self, command: PasskeyLoginFinishCommand) -> PasskeyFuture<'_, LoginSuccess>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyProfileContext {
    pub session_id: String,
    pub now: i64,
}

pub struct PasskeyRegistrationFinishCommand {
    pub context: PasskeyProfileContext,
    pub ceremony_id: String,
    pub response: RegistrationResponse,
}

pub trait PasskeyProfileOperations: Send + Sync {
    fn registration_begin(
        &self,
        context: PasskeyProfileContext,
        label: Option<String>,
    ) -> PasskeyFuture<'_, PasskeyRegistrationBegin>;

    fn registration_finish(
        &self,
        command: PasskeyRegistrationFinishCommand,
    ) -> PasskeyFuture<'_, PasskeyCredential>;

    fn list(&self, context: PasskeyProfileContext) -> PasskeyFuture<'_, Vec<PasskeyCredential>>;

    fn delete(&self, context: PasskeyProfileContext, passkey_id: Uuid) -> PasskeyFuture<'_, ()>;
}

#[derive(Clone)]
pub struct PasskeyLoginConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    remembered_mfa_cookie_name: String,
    session_ttl_seconds: u64,
    cookie_secure: bool,
}

impl PasskeyLoginConfig {
    #[must_use]
    pub fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        remembered_mfa_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            remembered_mfa_cookie_name: remembered_mfa_cookie_name.into(),
            session_ttl_seconds,
            cookie_secure,
        }
    }
}

#[derive(Clone)]
pub struct PasskeyProfileConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    cookie_secure: bool,
}

impl PasskeyProfileConfig {
    #[must_use]
    pub fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            cookie_secure,
        }
    }
}

#[derive(Clone)]
pub struct PasskeyLoginEndpoint {
    operations: Arc<dyn PasskeyLoginOperations>,
    rate_limit: Arc<dyn AuthenticationRateLimit>,
    client_ip: ClientIpConfig,
    config: PasskeyLoginConfig,
}

impl PasskeyLoginEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn PasskeyLoginOperations>,
        rate_limit: Arc<dyn AuthenticationRateLimit>,
        client_ip: ClientIpConfig,
        config: PasskeyLoginConfig,
    ) -> Self {
        Self {
            operations,
            rate_limit,
            client_ip,
            config,
        }
    }
}

#[derive(Clone)]
pub struct PasskeyProfileEndpoint {
    operations: Arc<dyn PasskeyProfileOperations>,
    config: PasskeyProfileConfig,
}

impl PasskeyProfileEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn PasskeyProfileOperations>,
        config: PasskeyProfileConfig,
    ) -> Self {
        Self { operations, config }
    }
}

#[derive(Deserialize)]
pub struct PasskeyLoginBeginRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct PasskeyLoginFinishRequest {
    pub ceremony_id: String,
    pub response: AuthenticationResponse,
}

#[derive(Deserialize)]
pub struct PasskeyRegistrationBeginRequest {
    pub label: Option<String>,
}

#[derive(Deserialize)]
pub struct PasskeyRegistrationFinishRequest {
    pub ceremony_id: String,
    pub response: RegistrationResponse,
}

pub fn configure_passkey_login_routes(config: &mut ServiceConfig) {
    config
        .route("/passkey/begin", web::post().to(passkey_login_begin))
        .route("/passkey/finish", web::post().to(passkey_login_finish));
}

pub fn configure_passkey_profile_routes(config: &mut ServiceConfig) {
    config
        .route("/passkeys", web::get().to(passkey_list))
        .route(
            "/passkeys/registration/begin",
            web::post().to(passkey_registration_begin),
        )
        .route(
            "/passkeys/registration/finish",
            web::post().to(passkey_registration_finish),
        )
        .route("/passkeys/{passkey_id}", web::delete().to(passkey_delete));
}

pub async fn passkey_login_begin(
    endpoint: Data<PasskeyLoginEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyLoginBeginRequest>, actix_web::Error>,
) -> HttpResponse {
    let Ok(Json(payload)) = payload else {
        return invalid_passkey_json_response();
    };
    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    if let Err(error) = endpoint.rate_limit.enforce(&source_ip).await {
        return rate_limit_error_response(error);
    }
    match endpoint
        .operations
        .login_begin(payload.email.trim().to_lowercase())
        .await
    {
        Ok(begin) => json_response_no_store(json!({
            "ceremony_id": begin.ceremony_id,
            "publicKey": begin.challenge,
        })),
        Err(error) => passkey_login_error(error),
    }
}

pub async fn passkey_login_finish(
    endpoint: Data<PasskeyLoginEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyLoginFinishRequest>, actix_web::Error>,
) -> HttpResponse {
    let Ok(Json(payload)) = payload else {
        return invalid_passkey_json_response();
    };
    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    if let Err(error) = endpoint.rate_limit.enforce(&source_ip).await {
        return rate_limit_error_response(error);
    }
    let command = PasskeyLoginFinishCommand {
        ceremony_id: payload.ceremony_id,
        response: payload.response,
        source_ip,
        remembered_mfa: remembered_mfa_proof(&request, &endpoint.config),
        previous_session_id: cookie_value(&request, &endpoint.config.session_cookie_name),
        now: Utc::now(),
    };
    match endpoint.operations.login_finish(command).await {
        Ok(success) => passkey_session_response(&endpoint.config, success),
        Err(error) => passkey_login_error(error),
    }
}

pub async fn passkey_registration_begin(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyRegistrationBeginRequest>, actix_web::Error>,
) -> HttpResponse {
    let Ok(Json(payload)) = payload else {
        return invalid_passkey_json_response();
    };
    let context = match profile_context(&endpoint, &request, true) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .registration_begin(context, payload.label)
        .await
    {
        Ok(begin) => json_response_no_store(json!({
            "ceremony_id": begin.ceremony_id,
            "publicKey": begin.challenge,
        })),
        Err(error) => registration_begin_error(&endpoint, error),
    }
}

pub async fn passkey_registration_finish(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
    payload: Result<Json<PasskeyRegistrationFinishRequest>, actix_web::Error>,
) -> HttpResponse {
    let Ok(Json(payload)) = payload else {
        return invalid_passkey_json_response();
    };
    let context = match profile_context(&endpoint, &request, true) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .registration_finish(PasskeyRegistrationFinishCommand {
            context,
            ceremony_id: payload.ceremony_id,
            response: payload.response,
        })
        .await
    {
        Ok(credential) => passkey_created_response(&credential),
        Err(error) => registration_error(&endpoint, error),
    }
}

pub async fn passkey_list(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let context = match profile_context(&endpoint, &request, false) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint.operations.list(context).await {
        Ok(credentials) => passkey_list_response(&credentials),
        Err(error) => passkey_management_error(&endpoint, error, "passkey state unavailable."),
    }
}

pub async fn passkey_delete(
    endpoint: Data<PasskeyProfileEndpoint>,
    request: HttpRequest,
    path: Path<Uuid>,
) -> HttpResponse {
    let context = match profile_context(&endpoint, &request, true) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint.operations.delete(context, path.into_inner()).await {
        Ok(()) => empty_response_no_store(StatusCode::NO_CONTENT),
        Err(PasskeyEndpointError::Core(PasskeyError::NotFound)) => authorization_error_response(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "passkey not found.",
        ),
        Err(error) => passkey_management_error(&endpoint, error, "passkey delete failed."),
    }
}

fn profile_context(
    endpoint: &PasskeyProfileEndpoint,
    request: &HttpRequest,
    require_csrf: bool,
) -> Result<PasskeyProfileContext, HttpResponse> {
    if require_csrf
        && !has_valid_csrf_token_for_cookies(
            request,
            None,
            &endpoint.config.session_cookie_name,
            &endpoint.config.csrf_cookie_name,
        )
    {
        return Err(no_store_response(csrf_error()));
    }
    let Some(session_id) = cookie_value(request, &endpoint.config.session_cookie_name) else {
        return Err(login_required_response(endpoint));
    };
    Ok(PasskeyProfileContext {
        session_id,
        now: Utc::now().timestamp(),
    })
}

fn remembered_mfa_proof(
    request: &HttpRequest,
    config: &PasskeyLoginConfig,
) -> Option<RememberedMfaProof> {
    let token = cookie_value(request, &config.remembered_mfa_cookie_name)?;
    let user_agent_hash = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(blake3_hex);
    Some(RememberedMfaProof {
        token_hash: blake3_hex(token.trim()),
        user_agent_hash,
    })
}

fn invalid_passkey_json_response() -> HttpResponse {
    authorization_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "passkey request body is invalid.",
    )
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn rate_limit_error_response(error: AuthenticationRateLimitError) -> HttpResponse {
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
        AuthenticationRateLimitError::Unavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        ),
    }
}

fn passkey_login_error(error: PasskeyEndpointError) -> HttpResponse {
    let PasskeyEndpointError::Core(error) = error else {
        return authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "session write failed.",
        );
    };
    match error {
        PasskeyError::InvalidCeremonyId => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid ceremony id.",
        ),
        PasskeyError::InvalidCredentialId => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid passkey credential id.",
        ),
        PasskeyError::CeremonyExpired => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony expired.",
        ),
        PasskeyError::Account(_) => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "user lookup failed.",
        ),
        PasskeyError::State(_) | PasskeyError::CeremonyState(_) => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        ),
        PasskeyError::Mfa(_) => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "MFA state lookup failed.",
        ),
        PasskeyError::Session(_) | PasskeyError::SessionCollision => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "session write failed.",
        ),
        _ => authorization_error_response(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "passkey login failed.",
        ),
    }
}

fn registration_begin_error(
    endpoint: &PasskeyProfileEndpoint,
    error: PasskeyEndpointError,
) -> HttpResponse {
    match error {
        PasskeyEndpointError::Core(PasskeyError::InvalidLabel) => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        ),
        error => passkey_management_error(endpoint, error, "passkey state unavailable."),
    }
}

fn registration_error(
    endpoint: &PasskeyProfileEndpoint,
    error: PasskeyEndpointError,
) -> HttpResponse {
    match error {
        PasskeyEndpointError::Core(PasskeyError::InvalidLabel) => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        ),
        PasskeyEndpointError::Core(PasskeyError::InvalidCeremonyId) => {
            authorization_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid ceremony id.",
            )
        }
        PasskeyEndpointError::Core(PasskeyError::CeremonyExpired) => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony expired.",
        ),
        PasskeyEndpointError::Core(PasskeyError::CeremonyMismatch) => authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey ceremony mismatch.",
        ),
        PasskeyEndpointError::Core(PasskeyError::RegistrationFailed) => {
            authorization_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "passkey registration failed.",
            )
        }
        PasskeyEndpointError::Core(PasskeyError::AlreadyRegistered) => {
            authorization_error_response(
                StatusCode::CONFLICT,
                "invalid_request",
                "passkey already registered.",
            )
        }
        PasskeyEndpointError::Core(error @ PasskeyError::CeremonyState(_)) => {
            passkey_management_error(
                endpoint,
                PasskeyEndpointError::Core(error),
                "passkey state unavailable.",
            )
        }
        error => passkey_management_error(endpoint, error, "passkey registration failed."),
    }
}

fn passkey_management_error(
    endpoint: &PasskeyProfileEndpoint,
    error: PasskeyEndpointError,
    description: &'static str,
) -> HttpResponse {
    match error {
        PasskeyEndpointError::SessionMissing => login_required_response(endpoint),
        PasskeyEndpointError::SessionUnavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "会话查询失败.",
        ),
        PasskeyEndpointError::Core(_) => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            description,
        ),
    }
}

fn login_required_response(endpoint: &PasskeyProfileEndpoint) -> HttpResponse {
    with_cookie_headers(
        authorization_error_response(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(
                &endpoint.config.session_cookie_name,
                endpoint.config.cookie_secure,
            ),
            clear_cookie(
                &endpoint.config.csrf_cookie_name,
                endpoint.config.cookie_secure,
            ),
        ],
    )
}

fn passkey_session_response(config: &PasskeyLoginConfig, success: LoginSuccess) -> HttpResponse {
    let cookies = [
        make_cookie(
            &config.session_cookie_name,
            &success.session_id,
            true,
            config.session_ttl_seconds,
            config.cookie_secure,
        ),
        make_cookie(
            &config.csrf_cookie_name,
            &success.csrf_token,
            false,
            config.session_ttl_seconds,
            config.cookie_secure,
        ),
    ];
    with_cookie_headers(
        json_response_no_store(json!({
            "expires_in": config.session_ttl_seconds,
            "csrf_token": success.csrf_token,
            "mfa_required": success.session.pending_mfa(),
        })),
        &cookies,
    )
}

fn passkey_public_json(row: &PasskeyCredential) -> Value {
    json!({
        "id": row.id,
        "label": row.label,
        "credential_id": row.credential_id,
        "sign_count": row.sign_count,
        "last_used_at": row.last_used_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })
}

fn passkey_list_response(rows: &[PasskeyCredential]) -> HttpResponse {
    json_response_no_store(json!({
        "passkeys": rows.iter().map(passkey_public_json).collect::<Vec<_>>()
    }))
}

fn passkey_created_response(row: &PasskeyCredential) -> HttpResponse {
    json_response_status_no_store(StatusCode::CREATED, passkey_public_json(row))
}

fn no_store_response(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
#[path = "../tests/unit/passkey.rs"]
mod tests;
