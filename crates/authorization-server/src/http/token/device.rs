//! RFC 8628 Device Authorization Grant.
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::ClientCredentials;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::extract_client_credentials_with_trusted_proxies;
use crate::adapters::security::has_basic_authorization_scheme;
use crate::adapters::security::random_urlsafe_token;
use crate::domain::ClientRow;
use crate::domain::client_policy::client_supports_grant;
use crate::domain::client_policy::parse_resource_indicators;
use crate::domain::client_policy::parse_scope;
use crate::http::client_ip::client_ip_with_context;
use crate::http::rate_limit::TokenManagementRequestLimiter;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data, Form, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::{cookie_value, csrf_error};
use nazo_http_actix::{json_response_no_store, oauth_error};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

use super::client_auth::{
    ClientAuthConfig, authenticate_client_with_dependencies,
    consume_token_management_client_assertion_with_authorization_service,
};
use super::{
    client_auth_request_facts, device_config::DeviceHttpConfig, token_management_auth_error,
};
use crate::http::authorization::ServerAuthorizationService;
use crate::http::sessions::SessionProfileHandles;
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use nazo_auth::{
    CapabilityAdmission, ClientAuthenticationContext, DeviceAuthorizationApproval,
    DeviceAuthorizationPayload, DeviceAuthorizationRequestError, DeviceAuthorizationRequestPolicy,
    DeviceDecisionFailure, DeviceGrantService,
};
use nazo_valkey::DeviceStore;

pub(crate) const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub(crate) type ServerDeviceGrantService = DeviceGrantService<DeviceStore>;

pub(crate) struct DeviceDecisionHandles {
    authorization_service: Data<ServerAuthorizationService>,
    device_service: Data<ServerDeviceGrantService>,
    grant_repository: Data<nazo_postgres::AuthorizationFlowRepository>,
    sessions: Data<SessionProfileHandles>,
    config: Data<DeviceHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
}

impl DeviceDecisionHandles {
    pub(crate) fn new(
        authorization_service: Data<ServerAuthorizationService>,
        device_service: Data<ServerDeviceGrantService>,
        grant_repository: Data<nazo_postgres::AuthorizationFlowRepository>,
        sessions: Data<SessionProfileHandles>,
        config: Data<DeviceHttpConfig>,
        runtime: Data<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            authorization_service,
            device_service,
            grant_repository,
            sessions,
            config,
            runtime,
        }
    }
}

fn device_module_admissible(
    runtime: &ServerRuntimeModuleRegistry,
    admission: CapabilityAdmission,
) -> bool {
    nazo_auth::module_admissible(
        runtime.snapshot().as_ref(),
        nazo_runtime_modules::ModuleId::DeviceAuthorization,
        admission,
    )
}

pub(crate) struct DeviceAuthorizationForm {
    pub(crate) client_id: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) resources: Vec<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion_type: Option<String>,
    pub(crate) client_assertion: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeviceAuthorizationFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    InvalidResourceParameter,
}

#[derive(Deserialize)]
pub(crate) struct DeviceDecisionForm {
    user_code: String,
    decision: String,
    csrf_token: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DeviceVerificationView {
    user_code: String,
    csrf_token: Option<String>,
    request: Option<DeviceAuthorizationPayload>,
}

pub(crate) fn parse_device_authorization_form(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<DeviceAuthorizationForm, DeviceAuthorizationFormError> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(DeviceAuthorizationFormError::InvalidContentType);
    }
    let raw =
        std::str::from_utf8(body).map_err(|_| DeviceAuthorizationFormError::InvalidEncoding)?;
    let mut seen = std::collections::HashSet::new();
    let mut resources = Vec::new();
    let mut form = DeviceAuthorizationForm {
        client_id: None,
        scope: None,
        resources: Vec::new(),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();
        match key.as_str() {
            "resource" => {
                resources.push(value);
            }
            "client_id" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_id = non_empty(value);
            }
            "scope" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.scope = non_empty(value);
            }
            "client_secret" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_secret = non_empty(value);
            }
            "client_assertion_type" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_assertion_type = non_empty(value);
            }
            "client_assertion" => {
                accept_device_authorization_parameter_once(&mut seen, key)?;
                form.client_assertion = non_empty(value);
            }
            _ => {}
        }
    }
    form.resources = parse_resource_indicators(&resources)
        .map_err(|_| DeviceAuthorizationFormError::InvalidResourceParameter)?;
    Ok(form)
}

pub(crate) async fn device_authorization(
    authorization_service: Data<ServerAuthorizationService>,
    device_service: Data<ServerDeviceGrantService>,
    limiter: Data<TokenManagementRequestLimiter>,
    config: Data<DeviceHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    device_authorization_with_admission(
        authorization_service,
        device_service,
        limiter,
        config,
        device_module_admissible(&runtime, CapabilityAdmission::NewRequest),
        req,
        body,
    )
    .await
}

async fn device_authorization_with_admission(
    authorization_service: Data<ServerAuthorizationService>,
    device_service: Data<ServerDeviceGrantService>,
    limiter: Data<TokenManagementRequestLimiter>,
    config: Data<DeviceHttpConfig>,
    module_admissible: bool,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if !module_admissible {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    if let Err(response) = limiter.enforce(&req).await {
        return response;
    }
    let form = match parse_device_authorization_form(&req, &body) {
        Ok(form) => form,
        Err(error) => return device_authorization_form_error(error),
    };
    let Some(client_id) = form.client_id.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };
    let has_basic = has_basic_authorization_scheme(req.headers());
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization request cannot mix client authentication methods.",
        );
    }
    let credentials = extract_client_credentials_with_trusted_proxies(
        &req,
        &config.trusted_proxy_cidrs,
        Some(client_id),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if has_basic && credentials.method != "client_secret_basic" {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    }
    let client = match authorization_service.client_by_id(client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            super::client_auth::perform_dummy_client_secret_verification(
                &credentials,
                &config.client_secret_pepper,
            );
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query device authorization client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(response) = authenticate_device_authorization_client(
        &authorization_service,
        &config,
        &req,
        &client,
        &credentials,
    )
    .await
    {
        return response;
    }
    let payload =
        match device_authorization_request_payload(&config, &client, &form, module_admissible) {
            Ok(payload) => payload,
            Err(error) => return device_authorization_request_error(error),
        };
    let (device_code, user_code) = match device_service
        .create_unique(
            &payload,
            config.ttl_seconds,
            random_urlsafe_token,
            random_device_user_code,
        )
        .await
    {
        Ok(codes) => codes,
        Err(error) => {
            tracing::warn!(%error, "failed to persist device authorization state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态写入失败.",
            );
        }
    };
    audit_event(
        "device_authorization_started",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            ("audience", json!(payload.resource_indicators)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_context(
                    &req,
                    config.client_ip_header_mode,
                    &config.trusted_proxy_cidrs,
                ))),
            ),
        ]),
    );
    let verification_uri = device_verification_uri(&config);
    json_response_no_store(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": format!("{verification_uri}?user_code={}", urlencoding::encode(&user_code)),
        "expires_in": config.ttl_seconds,
        "interval": config.poll_interval_seconds
    }))
}

pub(crate) fn device_authorization_request_payload(
    config: &DeviceHttpConfig,
    client: &ClientRow,
    form: &DeviceAuthorizationForm,
    enabled: bool,
) -> Result<DeviceAuthorizationPayload, DeviceAuthorizationRequestError> {
    let requested_scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    nazo_auth::device_authorization_request_payload(DeviceAuthorizationRequestPolicy {
        enabled,
        client_active: client.is_active,
        client_supports_grant: client_supports_grant(client, DEVICE_CODE_GRANT_TYPE),
        client_id: &client.client_id,
        client_name: &client.client_name,
        requested_scopes,
        allowed_scopes: &client.scopes,
        requested_resources: form.resources.clone(),
        allowed_resources: &client.allowed_audiences,
        default_resource: &config.default_audience,
        interval_seconds: config.poll_interval_seconds,
        ttl_seconds: config.ttl_seconds,
        now: Utc::now(),
    })
}

pub(crate) async fn device_verification_page(
    config: Data<DeviceHttpConfig>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    if !device_module_admissible(&runtime, CapabilityAdmission::ExistingTransaction) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    let user_code = query.get("user_code").cloned().unwrap_or_default();
    redirect_to_device_verification_ui(&config, &user_code)
}

pub(crate) async fn device_verification(
    device_service: Data<ServerDeviceGrantService>,
    sessions: Data<SessionProfileHandles>,
    runtime: Data<ServerRuntimeModuleRegistry>,
    req: HttpRequest,
    Query(query): Query<HashMap<String, String>>,
) -> HttpResponse {
    if !device_module_admissible(&runtime, CapabilityAdmission::ExistingTransaction) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    let user_code = query.get("user_code").cloned().unwrap_or_default();
    let normalized_user_code = normalize_user_code(&user_code);
    let payload = if normalized_user_code.is_empty() {
        None
    } else {
        match device_service
            .pending_request_for_user_code(&normalized_user_code, Utc::now)
            .await
        {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "failed to read device authorization request");
                None
            }
        }
    };
    let csrf_token = cookie_value(&req, sessions.http_config().csrf_cookie_name());
    json_response_no_store(DeviceVerificationView {
        user_code,
        csrf_token,
        request: payload,
    })
}

fn redirect_to_device_verification_ui(config: &DeviceHttpConfig, user_code: &str) -> HttpResponse {
    let mut location = device_verification_uri(config);
    if !user_code.trim().is_empty() {
        location.push_str("?user_code=");
        location.push_str(&urlencoding::encode(user_code));
    }
    HttpResponse::Found()
        .insert_header((header::LOCATION, location))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .finish()
}

fn device_verification_uri(config: &DeviceHttpConfig) -> String {
    format!("{}/device", config.frontend_base_url.trim_end_matches('/'))
}

pub(crate) async fn device_decision(
    handles: Data<DeviceDecisionHandles>,
    req: HttpRequest,
    Form(form): Form<DeviceDecisionForm>,
) -> HttpResponse {
    let authorization_service = handles.authorization_service.get_ref();
    let device_service = handles.device_service.get_ref();
    let grant_repository = handles.grant_repository.get_ref();
    let sessions = handles.sessions.get_ref();
    let config = handles.config.get_ref();
    let runtime = handles.runtime.get_ref();
    if !device_module_admissible(runtime, CapabilityAdmission::ExistingTransaction) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        );
    }
    if !sessions.has_valid_csrf_token(&req, form.csrf_token.as_deref()) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let normalized_user_code = normalize_user_code(&form.user_code);
    if normalized_user_code.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        );
    }
    let payload = match device_service
        .pending_request_for_user_code(&normalized_user_code, Utc::now)
        .await
    {
        Ok(Some(payload)) => payload,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "用户码无效或已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read device authorization state for user decision");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态读取失败.",
            );
        }
    };
    let result = match form.decision.as_str() {
        "deny" => device_service.deny(&normalized_user_code, Utc::now).await,
        "approve" => {
            let client = match authorization_service.client_by_id(&payload.client_id).await {
                Ok(Some(client)) if client.is_active => client,
                Ok(_) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "用户码无效或已过期.",
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to load device authorization client for approval");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "客户端查询失败.",
                    );
                }
            };
            let subject = match device_authorization_subject(config, user.id(), &client) {
                Ok(subject) => subject,
                Err(error) => {
                    tracing::warn!(%error, "failed to compute device authorization subject");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "授权主体计算失败.",
                    );
                }
            };
            device_service
                .approve(
                    &normalized_user_code,
                    DeviceAuthorizationApproval {
                        user_id: user.id(),
                        subject,
                        auth_time: Utc::now().timestamp(),
                        amr: vec!["pwd".to_owned()],
                        oidc_sid: None,
                    },
                    &client,
                    grant_repository,
                    Utc::now,
                )
                .await
        }
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效."),
    };
    match result {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(
            DeviceDecisionFailure::Missing
            | DeviceDecisionFailure::AlreadyHandled
            | DeviceDecisionFailure::Expired,
        ) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "用户码无效或已过期.",
        ),
        Err(DeviceDecisionFailure::Storage(error)) => {
            tracing::warn!(%error, "failed to persist device authorization decision");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态写入失败.",
            )
        }
        Err(DeviceDecisionFailure::Repository(error)) => {
            tracing::warn!(%error, "failed to persist device authorization grant");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录写入失败.",
            )
        }
        Err(DeviceDecisionFailure::Contended) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "设备授权状态正忙.",
        ),
    }
}

async fn authenticate_device_authorization_client(
    authorization_service: &ServerAuthorizationService,
    config: &DeviceHttpConfig,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), HttpResponse> {
    let auth_request = client_auth_request_facts(req, &config.trusted_proxy_cidrs);
    let assertion = authenticate_client_with_dependencies(
        authorization_service,
        ClientAuthConfig::new(&config.issuer, &config.client_secret_pepper),
        &auth_request,
        client,
        credentials,
        ClientAuthenticationContext::AllowPublicNone,
    )
    .await
    .map_err(token_management_auth_error)?;
    consume_token_management_client_assertion_with_authorization_service(
        authorization_service,
        client,
        assertion.as_ref(),
    )
    .await
    .map_err(token_management_auth_error)
}

fn device_authorization_form_error(error: DeviceAuthorizationFormError) -> HttpResponse {
    match error {
        DeviceAuthorizationFormError::InvalidContentType => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device authorization 请求必须使用 application/x-www-form-urlencoded.",
        ),
        DeviceAuthorizationFormError::InvalidEncoding => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "表单必须使用 UTF-8.",
        ),
        DeviceAuthorizationFormError::DuplicateParameter => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        ),
        DeviceAuthorizationFormError::InvalidResourceParameter => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource must be an absolute URI without a fragment.",
        ),
    }
}

fn device_authorization_request_error(error: DeviceAuthorizationRequestError) -> HttpResponse {
    match error {
        DeviceAuthorizationRequestError::Disabled => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        ),
        DeviceAuthorizationRequestError::UnauthorizedClient => oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 device_code 授权类型.",
        ),
        DeviceAuthorizationRequestError::InvalidScope => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
        ),
        DeviceAuthorizationRequestError::InvalidTarget => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
        ),
    }
}

fn device_authorization_subject(
    config: &DeviceHttpConfig,
    user_id: Uuid,
    client: &nazo_auth::OAuthClient,
) -> anyhow::Result<String> {
    let redirect_uri = client
        .redirect_uris
        .first()
        .cloned()
        .unwrap_or_else(|| config.issuer.to_string());
    nazo_auth::oidc_subject_for_client(
        &config.issuer,
        config.pairwise_subject_secret.as_deref(),
        user_id,
        client.subject_type.as_str(),
        client.sector_identifier_host.as_deref(),
        &redirect_uri,
    )
    .map_err(Into::into)
}

fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

fn random_device_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(9);
    let bytes = rand::random::<[u8; 8]>();
    for (idx, byte) in bytes.into_iter().enumerate() {
        if idx == 4 {
            out.push('-');
        }
        out.push(ALPHABET[(byte as usize) % ALPHABET.len()] as char);
    }
    out
}

fn accept_device_authorization_parameter_once(
    seen: &mut std::collections::HashSet<String>,
    key: String,
) -> Result<(), DeviceAuthorizationFormError> {
    if seen.insert(key) {
        Ok(())
    } else {
        Err(DeviceAuthorizationFormError::DuplicateParameter)
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/device.rs"]
mod tests;
