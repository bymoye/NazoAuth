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
mod tests {
    use std::sync::Mutex;

    use actix_web::{App, body::to_bytes, cookie::Cookie, middleware::from_fn, test, web};
    use nazo_identity::{TenantId, UserId, session::SessionRecord};

    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct CapturedLoginFinish {
        ceremony_id: String,
        source_ip: String,
        previous_session_id: Option<String>,
        remembered_mfa: Option<RememberedMfaProof>,
    }

    struct LoginOperations {
        finishes: Mutex<Vec<CapturedLoginFinish>>,
        result: Mutex<Option<Result<LoginSuccess, PasskeyEndpointError>>>,
    }

    impl PasskeyLoginOperations for LoginOperations {
        fn login_begin(&self, _email: String) -> PasskeyFuture<'_, PasskeyLoginBegin> {
            Box::pin(async { Err(PasskeyEndpointError::Core(PasskeyError::LoginFailed)) })
        }

        fn login_finish(
            &self,
            command: PasskeyLoginFinishCommand,
        ) -> PasskeyFuture<'_, LoginSuccess> {
            self.finishes.lock().unwrap().push(CapturedLoginFinish {
                ceremony_id: command.ceremony_id,
                source_ip: command.source_ip,
                previous_session_id: command.previous_session_id,
                remembered_mfa: command.remembered_mfa,
            });
            let result = self.result.lock().unwrap().take().unwrap();
            Box::pin(async move { result })
        }
    }

    struct RateLimit {
        subjects: Mutex<Vec<String>>,
        result: Result<(), AuthenticationRateLimitError>,
    }

    impl AuthenticationRateLimit for RateLimit {
        fn enforce<'a>(
            &'a self,
            subject: &'a str,
        ) -> crate::LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>> {
            self.subjects.lock().unwrap().push(subject.to_owned());
            let result = self.result;
            Box::pin(async move { result })
        }
    }

    struct ProfileOperations {
        contexts: Mutex<Vec<PasskeyProfileContext>>,
    }

    impl PasskeyProfileOperations for ProfileOperations {
        fn registration_begin(
            &self,
            context: PasskeyProfileContext,
            _label: Option<String>,
        ) -> PasskeyFuture<'_, PasskeyRegistrationBegin> {
            self.contexts.lock().unwrap().push(context);
            Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
        }

        fn registration_finish(
            &self,
            command: PasskeyRegistrationFinishCommand,
        ) -> PasskeyFuture<'_, PasskeyCredential> {
            self.contexts.lock().unwrap().push(command.context);
            Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
        }

        fn list(
            &self,
            context: PasskeyProfileContext,
        ) -> PasskeyFuture<'_, Vec<PasskeyCredential>> {
            self.contexts.lock().unwrap().push(context);
            Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
        }

        fn delete(
            &self,
            context: PasskeyProfileContext,
            _passkey_id: Uuid,
        ) -> PasskeyFuture<'_, ()> {
            self.contexts.lock().unwrap().push(context);
            Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
        }
    }

    fn login_endpoint(
        result: Result<LoginSuccess, PasskeyEndpointError>,
        rate_result: Result<(), AuthenticationRateLimitError>,
    ) -> (PasskeyLoginEndpoint, Arc<LoginOperations>, Arc<RateLimit>) {
        let operations = Arc::new(LoginOperations {
            finishes: Mutex::new(Vec::new()),
            result: Mutex::new(Some(result)),
        });
        let rate_limit = Arc::new(RateLimit {
            subjects: Mutex::new(Vec::new()),
            result: rate_result,
        });
        (
            PasskeyLoginEndpoint::new(
                operations.clone(),
                rate_limit.clone(),
                ClientIpConfig::new(&[], crate::ClientIpHeaderMode::None),
                PasskeyLoginConfig::new("session", "csrf", "remembered", 900, true),
            ),
            operations,
            rate_limit,
        )
    }

    fn profile_endpoint() -> (PasskeyProfileEndpoint, Arc<ProfileOperations>) {
        let operations = Arc::new(ProfileOperations {
            contexts: Mutex::new(Vec::new()),
        });
        (
            PasskeyProfileEndpoint::new(
                operations.clone(),
                PasskeyProfileConfig::new("session", "csrf", true),
            ),
            operations,
        )
    }

    fn login_success() -> LoginSuccess {
        LoginSuccess {
            session_id: "new-session".to_owned(),
            csrf_token: "new-csrf".to_owned(),
            session: SessionRecord::new(
                UserId::new(Uuid::from_u128(1)).unwrap(),
                Utc::now().timestamp(),
                vec!["passkey".to_owned()],
                false,
                Some("oidc-session".to_owned()),
            ),
        }
    }

    fn authentication_response() -> AuthenticationResponse {
        AuthenticationResponse {
            id: "credential".to_owned(),
            authenticator_data: "authenticator-data".to_owned(),
            signature: "signature".to_owned(),
            client_data_json: "client-data".to_owned(),
            user_handle: None,
        }
    }

    async fn response_json(response: HttpResponse) -> Value {
        assert_no_store(response.headers());
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
    }

    fn assert_no_store(headers: &header::HeaderMap) {
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
    }

    #[actix_web::test]
    async fn login_finish_extracts_security_context_and_sets_only_bound_session_material() {
        let (endpoint, operations, rate_limit) = login_endpoint(Ok(login_success()), Ok(()));
        let response = passkey_login_finish(
            Data::new(endpoint),
            test::TestRequest::post()
                .peer_addr("203.0.113.9:45123".parse().unwrap())
                .cookie(Cookie::new("session", "old-session"))
                .cookie(Cookie::new("remembered", " remembered-secret "))
                .insert_header((header::USER_AGENT, " passkey-test-agent "))
                .to_http_request(),
            Ok(Json(PasskeyLoginFinishRequest {
                ceremony_id: "ceremony".to_owned(),
                response: authentication_response(),
            })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("session=new-session;"))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("csrf=new-csrf;"))
        );
        let body = response_json(response).await;
        assert_eq!(
            body,
            json!({"expires_in": 900, "csrf_token": "new-csrf", "mfa_required": false})
        );

        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            ["203.0.113.9"]
        );
        let finishes = operations.finishes.lock().unwrap();
        assert_eq!(
            finishes.as_slice(),
            [CapturedLoginFinish {
                ceremony_id: "ceremony".to_owned(),
                source_ip: "203.0.113.9".to_owned(),
                previous_session_id: Some("old-session".to_owned()),
                remembered_mfa: Some(RememberedMfaProof {
                    token_hash: blake3_hex("remembered-secret"),
                    user_agent_hash: Some(blake3_hex("passkey-test-agent")),
                }),
            }]
        );
    }

    #[actix_web::test]
    async fn rate_limit_response_preserves_retry_after_and_does_not_call_core() {
        let (endpoint, operations, _) = login_endpoint(
            Ok(login_success()),
            Err(AuthenticationRateLimitError::Limited {
                retry_after_seconds: 17,
            }),
        );
        let response = passkey_login_finish(
            Data::new(endpoint),
            test::TestRequest::post().to_http_request(),
            Ok(Json(PasskeyLoginFinishRequest {
                ceremony_id: "ceremony".to_owned(),
                response: authentication_response(),
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "17");
        assert_eq!(
            response_json(response).await["error"],
            "temporarily_unavailable"
        );
        assert!(operations.finishes.lock().unwrap().is_empty());
    }

    #[actix_web::test]
    async fn missing_profile_session_clears_both_cookies_with_exact_protocol_error() {
        let (endpoint, operations) = profile_endpoint();
        let response = passkey_list(
            Data::new(endpoint),
            test::TestRequest::get()
                .cookie(Cookie::new("session", "missing-session"))
                .to_http_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 2);
        assert_eq!(
            response_json(response).await,
            json!({
                "error": "login_required",
                "error_description": "Request failed."
            })
        );
        assert_eq!(operations.contexts.lock().unwrap().len(), 1);
    }

    #[actix_web::test]
    async fn write_rejects_invalid_csrf_before_session_or_core_lookup() {
        let (endpoint, operations) = profile_endpoint();
        let response = passkey_delete(
            Data::new(endpoint),
            test::TestRequest::delete()
                .cookie(Cookie::new("session", "session-id"))
                .to_http_request(),
            Path::from(Uuid::from_u128(5)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            json!({
                "error": "invalid_request",
                "error_description": "Request failed."
            })
        );
        assert!(operations.contexts.lock().unwrap().is_empty());
    }

    #[actix_web::test]
    async fn public_passkey_projection_excludes_tenant_user_and_credential_material() {
        let now = Utc::now();
        let credential = PasskeyCredential {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::new(Uuid::from_u128(2)).unwrap(),
            user_id: UserId::new(Uuid::from_u128(3)).unwrap(),
            credential_id: "public-credential-id".to_owned(),
            credential: json!({"private": "credential-material"}),
            label: "Laptop".to_owned(),
            sign_count: 9,
            last_used_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let public = passkey_public_json(&credential);
        let public = public.as_object().unwrap();
        assert_eq!(public.len(), 7);
        assert_eq!(public["id"], json!(credential.id));
        assert_eq!(public["label"], "Laptop");
        assert_eq!(public["credential_id"], "public-credential-id");
        assert_eq!(public["sign_count"], 9);
        for forbidden in ["tenant_id", "user_id", "credential"] {
            assert!(
                public.get(forbidden).is_none(),
                "must not expose {forbidden}"
            );
        }

        for response in [
            passkey_list_response(std::slice::from_ref(&credential)),
            passkey_created_response(&credential),
            empty_response_no_store(StatusCode::NO_CONTENT),
        ] {
            assert_no_store(response.headers());
        }
    }

    fn assert_security_headers(headers: &header::HeaderMap) {
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(
            headers.get("content-security-policy").unwrap(),
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    }

    #[actix_web::test]
    async fn login_routes_preserve_post_only_no_cors_surface() {
        let (endpoint, _, _) = login_endpoint(Ok(login_success()), Ok(()));
        let service = test::init_service(
            App::new()
                .wrap(from_fn(crate::security_headers))
                .app_data(Data::new(endpoint))
                .service(web::scope("/auth").configure(configure_passkey_login_routes)),
        )
        .await;

        for path in ["/auth/passkey/begin", "/auth/passkey/finish"] {
            for method in [
                actix_web::http::Method::GET,
                actix_web::http::Method::DELETE,
                actix_web::http::Method::OPTIONS,
            ] {
                let response = test::call_service(
                    &service,
                    test::TestRequest::default()
                        .method(method.clone())
                        .uri(path)
                        .insert_header((header::ORIGIN, "https://app.example"))
                        .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "POST"))
                        .to_request(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
                assert!(response.headers().get(header::CONTENT_TYPE).is_none());
                assert!(
                    response
                        .headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .is_none()
                );
                assert_security_headers(response.headers());
                assert!(test::read_body(response).await.is_empty());
            }
        }

        let malformed = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/auth/passkey/begin")
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload("{}")
                .to_request(),
        )
        .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            malformed.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_no_store(malformed.headers());
        assert_security_headers(malformed.headers());
        let body: Value = test::read_body_json(malformed).await;
        assert_eq!(body["error"], "invalid_request");
    }

    #[actix_web::test]
    async fn profile_routes_preserve_wrong_method_cors_and_security_contract() {
        let (endpoint, _) = profile_endpoint();
        let allowed_origins = vec!["https://app.example".to_owned()];
        let service = test::init_service(
            App::new()
                .wrap(from_fn(crate::security_headers))
                .app_data(Data::new(endpoint))
                .service(
                    web::scope("/auth/me")
                        .wrap(crate::cors_auth_api(&allowed_origins))
                        .configure(configure_passkey_profile_routes),
                ),
        )
        .await;

        for (method, path) in [
            (actix_web::http::Method::POST, "/auth/me/passkeys"),
            (
                actix_web::http::Method::GET,
                "/auth/me/passkeys/registration/begin",
            ),
            (
                actix_web::http::Method::DELETE,
                "/auth/me/passkeys/registration/finish",
            ),
            (
                actix_web::http::Method::POST,
                "/auth/me/passkeys/00000000-0000-0000-0000-000000000001",
            ),
        ] {
            let response = test::call_service(
                &service,
                test::TestRequest::default()
                    .method(method.clone())
                    .uri(path)
                    .insert_header((header::ORIGIN, "https://app.example"))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "https://app.example"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .unwrap(),
                "true"
            );
            assert_security_headers(response.headers());
            assert!(test::read_body(response).await.is_empty());
        }
    }

    #[actix_web::test]
    async fn profile_routes_preserve_get_post_delete_options_preflight_contract() {
        let (endpoint, _) = profile_endpoint();
        let allowed_origins = vec!["https://app.example".to_owned()];
        let service = test::init_service(
            App::new()
                .wrap(from_fn(crate::security_headers))
                .app_data(Data::new(endpoint))
                .service(
                    web::scope("/auth/me")
                        .wrap(crate::cors_auth_api(&allowed_origins))
                        .configure(configure_passkey_profile_routes),
                ),
        )
        .await;

        for (path, method) in [
            ("/auth/me/passkeys", "GET"),
            ("/auth/me/passkeys/registration/begin", "POST"),
            ("/auth/me/passkeys/registration/finish", "POST"),
            (
                "/auth/me/passkeys/00000000-0000-0000-0000-000000000001",
                "DELETE",
            ),
        ] {
            let response = test::call_service(
                &service,
                test::TestRequest::default()
                    .method(actix_web::http::Method::OPTIONS)
                    .uri(path)
                    .insert_header((header::ORIGIN, "https://app.example"))
                    .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, method))
                    .insert_header((
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type, x-csrf-token",
                    ))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
            assert!(response.headers().get(header::CONTENT_TYPE).is_none());
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "https://app.example"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .unwrap(),
                "true"
            );
            assert_security_headers(response.headers());
            assert!(test::read_body(response).await.is_empty());
        }

        let malformed = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/auth/me/passkeys/registration/finish")
                .insert_header((header::ORIGIN, "https://app.example"))
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .set_payload("{}")
                .to_request(),
        )
        .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            malformed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_no_store(malformed.headers());
        assert_security_headers(malformed.headers());
        let body: Value = test::read_body_json(malformed).await;
        assert_eq!(body["error"], "invalid_request");

        let rejected = test::call_service(
            &service,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/auth/me/passkeys")
                .insert_header((header::ORIGIN, "https://app.example"))
                .insert_header((header::ACCESS_CONTROL_REQUEST_METHOD, "PUT"))
                .to_request(),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert!(
            rejected
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_security_headers(rejected.headers());
    }
}
