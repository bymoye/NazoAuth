use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use chrono::Utc;
use nazo_identity::{
    AuthenticatePasswordError, AuthenticatePasswordInput, RememberedMfaProof,
    authentication::PasswordLoginResult,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    AuthenticationRateLimit, AuthenticationRateLimitError, ClientIpConfig,
    authorization_error_response, client_ip_with_config, cookie_value, json_response, make_cookie,
    oauth_error, with_cookie_headers,
};

pub type PasswordLoginFuture<'a> = Pin<
    Box<dyn Future<Output = Result<PasswordLoginResult, AuthenticatePasswordError>> + Send + 'a>,
>;

pub trait PasswordLoginOperations: Send + Sync {
    fn authenticate_password(&self, input: AuthenticatePasswordInput) -> PasswordLoginFuture<'_>;
}

#[derive(Clone)]
pub struct PasswordLoginConfig {
    issuer: String,
    frontend_base_url: String,
    session_cookie_name: String,
    csrf_cookie_name: String,
    remembered_mfa_cookie_name: String,
    session_ttl_seconds: u64,
    cookie_secure: bool,
}

impl PasswordLoginConfig {
    #[must_use]
    pub fn new(
        issuer: impl Into<String>,
        frontend_base_url: impl Into<String>,
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        remembered_mfa_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            frontend_base_url: frontend_base_url.into(),
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            remembered_mfa_cookie_name: remembered_mfa_cookie_name.into(),
            session_ttl_seconds,
            cookie_secure,
        }
    }
}

#[derive(Clone)]
pub struct PasswordLoginEndpoint {
    operations: Arc<dyn PasswordLoginOperations>,
    rate_limit: Arc<dyn AuthenticationRateLimit>,
    client_ip: ClientIpConfig,
    config: PasswordLoginConfig,
}

impl PasswordLoginEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn PasswordLoginOperations>,
        rate_limit: Arc<dyn AuthenticationRateLimit>,
        client_ip: ClientIpConfig,
        config: PasswordLoginConfig,
    ) -> Self {
        Self {
            operations,
            rate_limit,
            client_ip,
            config,
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    next: Option<String>,
}

#[derive(Clone, Copy)]
enum LoginResponseMode {
    Json,
    Form,
}

pub async fn login(
    endpoint: Data<PasswordLoginEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    no_store(login_inner(endpoint, request, body).await)
}

async fn login_inner(
    endpoint: Data<PasswordLoginEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let (payload, response_mode) = match parse_login_request(&request, &body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if matches!(response_mode, LoginResponseMode::Form)
        && !form_login_origin_is_allowed(&endpoint.config, &request)
    {
        return oauth_error(StatusCode::FORBIDDEN, "access_denied", "登录来源无效.");
    }

    let source_ip = client_ip_with_config(&request, &endpoint.client_ip);
    if let Err(error) = endpoint.rate_limit.enforce(&source_ip).await {
        return authentication_rate_limit_error_response(error);
    }

    let result = endpoint
        .operations
        .authenticate_password(AuthenticatePasswordInput {
            email: payload.email.trim().to_lowercase(),
            password: payload.password,
            source_ip,
            remembered_mfa: remembered_mfa_proof(&request, &endpoint.config),
            previous_session_id: cookie_value(&request, &endpoint.config.session_cookie_name),
            now: Utc::now(),
        })
        .await;
    let success = match result {
        Ok(success) => success,
        Err(error) => return authentication_error_response(error),
    };
    let cookies = [
        make_cookie(
            &endpoint.config.session_cookie_name,
            &success.session_id,
            true,
            endpoint.config.session_ttl_seconds,
            endpoint.config.cookie_secure,
        ),
        make_cookie(
            &endpoint.config.csrf_cookie_name,
            &success.csrf_token,
            false,
            endpoint.config.session_ttl_seconds,
            endpoint.config.cookie_secure,
        ),
    ];
    if matches!(response_mode, LoginResponseMode::Form) {
        let location = safe_form_login_next(&endpoint.config, &request, payload.next.as_deref());
        let mut response = HttpResponse::SeeOther();
        if let Ok(value) = header::HeaderValue::from_str(&location) {
            response.insert_header((header::LOCATION, value));
        }
        return with_cookie_headers(response.finish(), &cookies);
    }
    with_cookie_headers(
        json_response(json!({
            "expires_in": endpoint.config.session_ttl_seconds,
            "csrf_token": success.csrf_token,
            "mfa_required": success.mfa_required,
        })),
        &cookies,
    )
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

fn authentication_error_response(error: AuthenticatePasswordError) -> HttpResponse {
    match error {
        AuthenticatePasswordError::ThrottleUnavailable(_) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "登录失败次数校验失败.",
        ),
        AuthenticatePasswordError::Throttled {
            retry_after_seconds,
        } => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "登录失败次数过多，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        AuthenticatePasswordError::AccountLookup(_) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "用户查询失败.",
        ),
        AuthenticatePasswordError::SecretBusy => {
            let mut response = oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "登录服务繁忙，请稍后重试.",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
            response
        }
        AuthenticatePasswordError::SecretUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "密码校验失败.",
        ),
        AuthenticatePasswordError::FailureRecord(_) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "登录失败次数记录失败.",
        ),
        AuthenticatePasswordError::InvalidCredentials => {
            oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.")
        }
        AuthenticatePasswordError::InactiveAccount => {
            oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "当前账号已停用.")
        }
        AuthenticatePasswordError::RememberedMfa(_) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "MFA 状态查询失败.",
        ),
        AuthenticatePasswordError::Session(_) | AuthenticatePasswordError::SessionCollision => {
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            )
        }
    }
}

fn remembered_mfa_proof(
    request: &HttpRequest,
    config: &PasswordLoginConfig,
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

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn parse_login_request(
    request: &HttpRequest,
    body: &Bytes,
) -> Result<(LoginRequest, LoginResponseMode), HttpResponse> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if content_type.eq_ignore_ascii_case("application/json") {
        let payload = serde_json::from_slice::<LoginRequest>(body).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "login request body must be valid JSON.",
            )
        })?;
        return Ok((payload, LoginResponseMode::Json));
    }
    if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        let raw = std::str::from_utf8(body).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "login form body must be valid UTF-8.",
            )
        })?;
        return parse_login_form(raw).map(|payload| (payload, LoginResponseMode::Form));
    }
    Err(oauth_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "invalid_request",
        "login request must use JSON or form encoding.",
    ))
}

fn parse_login_form(raw: &str) -> Result<LoginRequest, HttpResponse> {
    let mut email = None;
    let mut password = None;
    let mut next = None;
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "email" => assign_once(&mut email, value.into_owned())?,
            "password" => assign_once(&mut password, value.into_owned())?,
            "next" => assign_once(&mut next, value.into_owned())?,
            _ => {}
        }
    }
    let Some(email) = email else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "email is required.",
        ));
    };
    let Some(password) = password else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "password is required.",
        ));
    };
    Ok(LoginRequest {
        email,
        password,
        next,
    })
}

fn assign_once(slot: &mut Option<String>, value: String) -> Result<(), HttpResponse> {
    if slot.is_some() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "duplicate login form parameter.",
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn form_login_origin_is_allowed(config: &PasswordLoginConfig, request: &HttpRequest) -> bool {
    let mut origins = request.headers().get_all(header::ORIGIN);
    let Some(origin) = origins.next() else {
        return false;
    };
    if origins.next().is_some() {
        return false;
    }
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some(origin) = strict_request_origin(origin) else {
        return false;
    };
    [&config.issuer, &config.frontend_base_url]
        .into_iter()
        .filter_map(|trusted| normalized_url_origin(trusted))
        .any(|trusted| trusted == origin)
}

fn strict_request_origin(value: &str) -> Option<String> {
    if value == "null" || value != value.trim() {
        return None;
    }
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn normalized_url_origin(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn safe_form_login_next(
    config: &PasswordLoginConfig,
    request: &HttpRequest,
    submitted: Option<&str>,
) -> String {
    let default_next = format!("{}/profile", config.frontend_base_url.trim_end_matches('/'));
    submitted
        .and_then(safe_relative_next)
        .or_else(|| referer_login_next(request))
        .unwrap_or(default_next)
}

fn safe_relative_next(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || !value.starts_with('/') || value.starts_with("//") {
        return None;
    }
    let path = value
        .split_once(['?', '#'])
        .map(|(path, _)| path)
        .unwrap_or(value)
        .trim_end_matches('/');
    (path == "/authorize").then(|| value.to_owned())
}

fn referer_login_next(request: &HttpRequest) -> Option<String> {
    let referer = request.headers().get(header::REFERER)?.to_str().ok()?;
    let referer = url::Url::parse(referer).ok()?;
    let next = referer
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then(|| value.into_owned()))?;
    safe_relative_next(&next)
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
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
#[path = "../tests/unit/password_login.rs"]
mod tests;
