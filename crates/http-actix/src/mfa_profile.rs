use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{Method, StatusCode, header},
    web::{self, Data, Json, ServiceConfig},
};
use chrono::Utc;
use nazo_identity::mfa::{MFA_TOTP_DIGITS, MFA_TOTP_PERIOD_SECONDS};
use serde::Deserialize;
use serde_json::json;

use crate::{
    AuthenticationRateLimitError, ClientIpConfig, authorization_error_response, clear_cookie,
    client_ip_with_config, cookie_value, has_valid_csrf_token_for_cookies, json_response_no_store,
    make_cookie, mfa_json_config, mfa_method_not_allowed, mfa_options, with_cookie_headers,
};

pub type MfaProfileFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, MfaProfileError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaRequestContext {
    pub session_id: String,
    pub source_ip: String,
    pub user_agent_hash: Option<String>,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaCodeCommand {
    pub context: MfaRequestContext,
    pub code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaChallengeCommand {
    pub context: MfaRequestContext,
    pub code: String,
    pub remember_device: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaSessionRotation {
    pub session_id: String,
    pub csrf_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaTotpEnrollment {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaTotpConfirmation {
    pub rotation: MfaSessionRotation,
    pub backup_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaChallengeSuccess {
    pub rotation: MfaSessionRotation,
    pub method: String,
    pub remembered_device_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaStepUpSuccess {
    pub rotation: MfaSessionRotation,
    pub method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaBackupCodesRegenerated {
    pub rotation: MfaSessionRotation,
    pub backup_codes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaProfileErrorKind {
    SessionMissing,
    ChallengeMissing,
    SessionUnavailable,
    RateLimitUnavailable,
    RateLimited,
    AlreadyEnabled,
    EnrollmentMissing,
    InvalidCode,
    MfaDisabled,
    CredentialUnavailable,
    HashUnavailable,
    SessionWriteFailed,
    RememberDeviceFailed,
    BackupCodesFailed,
    DisableFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaProfileError {
    pub kind: MfaProfileErrorKind,
    pub retry_after_seconds: Option<u64>,
    pub rotation: Option<MfaSessionRotation>,
    pub clear_session_cookies: bool,
}

impl MfaProfileError {
    #[must_use]
    pub const fn new(kind: MfaProfileErrorKind) -> Self {
        Self {
            kind,
            retry_after_seconds: None,
            rotation: None,
            clear_session_cookies: false,
        }
    }

    #[must_use]
    pub const fn rate_limit(error: AuthenticationRateLimitError) -> Self {
        match error {
            AuthenticationRateLimitError::Unavailable => {
                Self::new(MfaProfileErrorKind::RateLimitUnavailable)
            }
            AuthenticationRateLimitError::Limited {
                retry_after_seconds,
            } => Self {
                kind: MfaProfileErrorKind::RateLimited,
                retry_after_seconds: Some(retry_after_seconds),
                rotation: None,
                clear_session_cookies: false,
            },
        }
    }
}

pub trait MfaProfileOperations: Send + Sync {
    fn begin_totp(&self, context: MfaRequestContext) -> MfaProfileFuture<'_, MfaTotpEnrollment>;
    fn confirm_totp(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaTotpConfirmation>;
    fn verify_challenge(
        &self,
        command: MfaChallengeCommand,
    ) -> MfaProfileFuture<'_, MfaChallengeSuccess>;
    fn step_up(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaStepUpSuccess>;
    fn regenerate_backup_codes(
        &self,
        command: MfaCodeCommand,
    ) -> MfaProfileFuture<'_, MfaBackupCodesRegenerated>;
    fn disable(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, bool>;
}

#[derive(Clone)]
pub struct MfaProfileConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    remembered_mfa_cookie_name: String,
    session_ttl_seconds: u64,
    remembered_mfa_ttl_seconds: u64,
    cookie_secure: bool,
}

impl MfaProfileConfig {
    #[must_use]
    pub fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        remembered_mfa_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        remembered_mfa_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            remembered_mfa_cookie_name: remembered_mfa_cookie_name.into(),
            session_ttl_seconds,
            remembered_mfa_ttl_seconds,
            cookie_secure,
        }
    }
}

#[derive(Clone)]
pub struct MfaProfileEndpoint {
    operations: Arc<dyn MfaProfileOperations>,
    client_ip: ClientIpConfig,
    config: MfaProfileConfig,
}

impl MfaProfileEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn MfaProfileOperations>,
        client_ip: ClientIpConfig,
        config: MfaProfileConfig,
    ) -> Self {
        Self {
            operations,
            client_ip,
            config,
        }
    }
}

#[derive(Deserialize)]
pub struct ConfirmTotpRequest {
    code: String,
}

#[derive(Deserialize)]
pub struct MfaChallengeRequest {
    code: String,
    remember_device: Option<bool>,
}

#[derive(Deserialize)]
pub struct MfaProtectedRequest {
    code: String,
}

pub fn configure_mfa_challenge_route(config: &mut ServiceConfig) {
    config.service(
        web::resource("/verify")
            .app_data(mfa_json_config())
            .route(web::post().to(mfa_verify))
            .route(web::method(Method::OPTIONS).to(mfa_options))
            .default_service(web::to(mfa_method_not_allowed)),
    );
}

pub fn configure_mfa_profile_routes(config: &mut ServiceConfig) {
    config
        .app_data(mfa_json_config())
        .service(
            web::resource("/totp/begin")
                .route(web::post().to(mfa_totp_begin))
                .route(web::method(Method::OPTIONS).to(mfa_options))
                .default_service(web::to(mfa_method_not_allowed)),
        )
        .service(
            web::resource("/totp/confirm")
                .route(web::post().to(mfa_totp_confirm))
                .route(web::method(Method::OPTIONS).to(mfa_options))
                .default_service(web::to(mfa_method_not_allowed)),
        )
        .service(
            web::resource("/step-up")
                .route(web::post().to(mfa_step_up))
                .route(web::method(Method::OPTIONS).to(mfa_options))
                .default_service(web::to(mfa_method_not_allowed)),
        )
        .service(
            web::resource("/backup-codes/regenerate")
                .route(web::post().to(mfa_backup_codes_regenerate))
                .route(web::method(Method::OPTIONS).to(mfa_options))
                .default_service(web::to(mfa_method_not_allowed)),
        )
        .service(
            web::resource("/disable")
                .route(web::post().to(mfa_disable))
                .route(web::method(Method::OPTIONS).to(mfa_options))
                .default_service(web::to(mfa_method_not_allowed)),
        );
}

pub async fn mfa_totp_begin(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let context = match request_context(&endpoint, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint.operations.begin_totp(context).await {
        Ok(enrollment) => json_response_no_store(json!({
            "secret_base32": enrollment.secret_base32,
            "otpauth_uri": enrollment.otpauth_uri,
            "period": MFA_TOTP_PERIOD_SECONDS,
            "digits": MFA_TOTP_DIGITS,
        })),
        Err(error) => error_response(&endpoint, MfaAction::Begin, error),
    }
}

pub async fn mfa_totp_confirm(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    let context = match request_context(&endpoint, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .confirm_totp(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(success) => with_rotation(
            &endpoint,
            json_response_no_store(json!({
                "mfa_enabled": true,
                "backup_codes": success.backup_codes,
            })),
            &success.rotation,
        ),
        Err(error) => error_response(&endpoint, MfaAction::Confirm, error),
    }
}

pub async fn mfa_verify(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<MfaChallengeRequest>,
) -> HttpResponse {
    let context = match request_context(&endpoint, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .verify_challenge(MfaChallengeCommand {
            context,
            code: payload.code,
            remember_device: payload.remember_device.unwrap_or(false),
        })
        .await
    {
        Ok(success) => {
            let mut cookies = rotation_cookies(&endpoint, &success.rotation).to_vec();
            if let Some(token) = success.remembered_device_token {
                cookies.push(make_cookie(
                    &endpoint.config.remembered_mfa_cookie_name,
                    &token,
                    true,
                    endpoint.config.remembered_mfa_ttl_seconds,
                    endpoint.config.cookie_secure,
                ));
            }
            with_cookie_headers(
                json_response_no_store(json!({
                    "success": true,
                    "method": success.method,
                })),
                &cookies,
            )
        }
        Err(error) => error_response(&endpoint, MfaAction::Verify, error),
    }
}

pub async fn mfa_step_up(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    let context = match request_context(&endpoint, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .step_up(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(success) => with_rotation(
            &endpoint,
            json_response_no_store(json!({
                "success": true,
                "method": success.method,
            })),
            &success.rotation,
        ),
        Err(error) => error_response(&endpoint, MfaAction::StepUp, error),
    }
}

pub async fn mfa_backup_codes_regenerate(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    let context = match request_context(&endpoint, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .regenerate_backup_codes(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(success) => with_rotation(
            &endpoint,
            json_response_no_store(json!({"backup_codes": success.backup_codes})),
            &success.rotation,
        ),
        Err(error) => error_response(&endpoint, MfaAction::Regenerate, error),
    }
}

pub async fn mfa_disable(
    endpoint: Data<MfaProfileEndpoint>,
    request: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    let context = match request_context(&endpoint, &request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .disable(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(changed) if changed => with_cookie_headers(
            json_response_no_store(json!({"mfa_enabled": false})),
            &[clear_cookie(
                &endpoint.config.remembered_mfa_cookie_name,
                endpoint.config.cookie_secure,
            )],
        ),
        Ok(_) => json_response_no_store(json!({"mfa_enabled": false})),
        Err(error) => error_response(&endpoint, MfaAction::Disable, error),
    }
}

fn request_context(
    endpoint: &MfaProfileEndpoint,
    request: &HttpRequest,
) -> Result<MfaRequestContext, HttpResponse> {
    if !has_valid_csrf_token_for_cookies(
        request,
        None,
        &endpoint.config.session_cookie_name,
        &endpoint.config.csrf_cookie_name,
    ) {
        return Err(crate::csrf_error());
    }
    let Some(session_id) = cookie_value(request, &endpoint.config.session_cookie_name) else {
        return Err(clear_session_cookies(
            endpoint,
            authorization_error_response(StatusCode::UNAUTHORIZED, "login_required", "请求失败."),
        ));
    };
    let user_agent_hash = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| blake3::hash(value.as_bytes()).to_hex().to_string());
    Ok(MfaRequestContext {
        session_id,
        source_ip: client_ip_with_config(request, &endpoint.client_ip),
        user_agent_hash,
        now: Utc::now().timestamp(),
    })
}

#[derive(Clone, Copy)]
enum MfaAction {
    Begin,
    Confirm,
    Verify,
    StepUp,
    Regenerate,
    Disable,
}

fn error_response(
    endpoint: &MfaProfileEndpoint,
    action: MfaAction,
    error: MfaProfileError,
) -> HttpResponse {
    let mut response = match error.kind {
        MfaProfileErrorKind::SessionMissing => clear_session_cookies(
            endpoint,
            authorization_error_response(
                StatusCode::UNAUTHORIZED,
                "login_required",
                session_missing_description(action),
            ),
        ),
        MfaProfileErrorKind::ChallengeMissing => authorization_error_response(
            StatusCode::UNAUTHORIZED,
            "login_required",
            session_missing_description(action),
        ),
        MfaProfileErrorKind::SessionUnavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::RateLimitUnavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::RateLimited => {
            authorization_error_response(StatusCode::TOO_MANY_REQUESTS, "slow_down", "请求失败.")
        }
        MfaProfileErrorKind::AlreadyEnabled => {
            authorization_error_response(StatusCode::CONFLICT, "invalid_request", "请求失败.")
        }
        MfaProfileErrorKind::EnrollmentMissing => {
            authorization_error_response(StatusCode::BAD_REQUEST, "invalid_request", "请求失败.")
        }
        MfaProfileErrorKind::InvalidCode => {
            authorization_error_response(StatusCode::BAD_REQUEST, "invalid_grant", "请求失败.")
        }
        MfaProfileErrorKind::MfaDisabled => {
            authorization_error_response(StatusCode::BAD_REQUEST, "invalid_request", "请求失败.")
        }
        MfaProfileErrorKind::CredentialUnavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::HashUnavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::SessionWriteFailed => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::RememberDeviceFailed => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::BackupCodesFailed => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::DisableFailed => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
    };
    if let Some(retry_after_seconds) = error.retry_after_seconds
        && let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string())
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    if let Some(rotation) = error.rotation {
        response = with_rotation(endpoint, response, &rotation);
    }
    if error.clear_session_cookies {
        response = clear_session_cookies(endpoint, response);
    }
    response
}

const fn session_missing_description(_action: MfaAction) -> &'static str {
    "请求失败."
}

fn with_rotation(
    endpoint: &MfaProfileEndpoint,
    response: HttpResponse,
    rotation: &MfaSessionRotation,
) -> HttpResponse {
    with_cookie_headers(response, &rotation_cookies(endpoint, rotation))
}

fn rotation_cookies(
    endpoint: &MfaProfileEndpoint,
    rotation: &MfaSessionRotation,
) -> [actix_web::cookie::Cookie<'static>; 2] {
    [
        make_cookie(
            &endpoint.config.session_cookie_name,
            &rotation.session_id,
            true,
            endpoint.config.session_ttl_seconds,
            endpoint.config.cookie_secure,
        ),
        make_cookie(
            &endpoint.config.csrf_cookie_name,
            &rotation.csrf_token,
            false,
            endpoint.config.session_ttl_seconds,
            endpoint.config.cookie_secure,
        ),
    ]
}

fn clear_session_cookies(endpoint: &MfaProfileEndpoint, response: HttpResponse) -> HttpResponse {
    with_cookie_headers(
        response,
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
