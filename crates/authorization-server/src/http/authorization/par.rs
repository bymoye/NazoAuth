//! Pushed Authorization Request endpoint.
use nazo_http_actix::{OAuthJsonErrorFields, json_response_status, oauth_error};

use super::jar::{
    apply_request_object_with_context, request_object_uses_unsigned_algorithm,
    unverified_signed_request_object_client_id,
};
#[cfg(test)]
use crate::adapters::security::blake3_hex;
use crate::adapters::security::extract_client_credentials_with_trusted_proxies;
use crate::adapters::security::has_basic_authorization_scheme;
use crate::adapters::security::random_urlsafe_token;
#[cfg(test)]
use crate::domain::ClientRow;
use crate::domain::PushedAuthorizationRequest;
#[cfg(test)]
use crate::domain::client_policy::{RedirectUriError, audiences_allowed, registered_redirect_uri};
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
#[cfg(test)]
use crate::http::authorization::AuthorizationHttpConfig;
use crate::http::authorization::{AuthorizationEndpoint, AuthorizationRequestContext};
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use crate::http::rate_limit::rate_limited_response;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::valkey::valkey_get;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
#[cfg(test)]
use nazo_auth::parse_resource_indicator_parameter;
use nazo_auth::{
    ExpandedParAdmissionPolicy, ParAdmissionError, RawParAdmissionPolicy,
    encode_resource_indicators, is_valid_dpop_jkt, validate_expanded_par_admission,
    validate_raw_par_admission,
};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
#[cfg(test)]
use uuid::Uuid;

pub(crate) const PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX: &str =
    "urn:ietf:params:oauth:request_uri:";
use crate::http::token::client_auth::{
    authenticate_client_with_dependencies,
    consume_token_management_client_assertion_with_authorization_service,
};
use crate::http::token::{client_auth_request_facts, token_management_auth_error};

const PAR_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "resource",
    "authorization_details",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "response_mode",
    "request",
];

async fn enforce_par_rate_limit(
    context: &AuthorizationRequestContext<'_>,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let subject = crate::http::client_ip::client_ip_with_context(
        req,
        context.config.client_ip_header_mode,
        &context.config.trusted_proxy_cidrs,
    );
    let count = context
        .service
        .increment_rate(&subject, context.config.rate_limit_window_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "PAR rate limit increment failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;
    if count > context.config.token_management_max_requests {
        return Err(rate_limited_response(
            context.config.rate_limit_window_seconds,
        ));
    }
    Ok(())
}

pub(crate) async fn par(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let context = endpoint.context();
    if let Err(response) = enforce_par_rate_limit(&context, &req).await {
        return response;
    }
    par_after_rate_limit_with_context(&context, req, body).await
}

async fn par_after_rate_limit_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let response = par_after_rate_limit_inner(context, req, body).await;
    log_par_error_response(&response);
    response
}

async fn par_after_rate_limit_inner(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
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
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR 请求必须使用 application/x-www-form-urlencoded.",
        );
    }
    let raw = match std::str::from_utf8(&body) {
        Ok(raw) => raw,
        Err(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "PAR 表单无效.");
        }
    };
    let mut params = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut resource_values = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();
        if key == "request_uri" {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求不能包含 request_uri.",
            );
        }
        if !PAR_AUTHORIZATION_PARAMETERS.contains(&key.as_str())
            && !matches!(
                key.as_str(),
                "client_secret" | "client_assertion_type" | "client_assertion"
            )
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求包含不支持的参数.",
            );
        }
        if key == "resource" {
            resource_values.push(value);
            continue;
        }
        if !seen.insert(key.clone()) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 参数不能重复.",
            );
        }
        params.insert(key, value);
    }
    if let Some(encoded) = encode_resource_indicators(&resource_values) {
        params.insert("resource".to_owned(), encoded);
    }
    let has_basic = has_basic_authorization_scheme(req.headers());
    let has_assertion =
        params.contains_key("client_assertion_type") || params.contains_key("client_assertion");
    if has_basic && (params.contains_key("client_secret") || has_assertion)
        || has_assertion && params.contains_key("client_secret")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR 请求不能同时使用多种客户端认证方式.",
        );
    }
    if (!crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::RequestObjects,
    ) || !context.config.enable_par_request_object)
        && !context
            .config
            .profile
            .requires_signed_request_object_at_par()
        && params.contains_key("request")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR request object 未启用.",
        );
    }
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::AuthorizationDetails,
    ) && params.contains_key("authorization_details")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 未启用.",
        );
    }

    if params
        .get("request")
        .is_some_and(|request| request_object_uses_unsigned_algorithm(request))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "PAR request object 必须签名.",
        );
    }
    if !params.contains_key("client_id")
        && let Some(request_object) = params.get("request")
        && let Some(client_id) = unverified_signed_request_object_client_id(request_object)
    {
        params.insert("client_id".to_owned(), client_id);
    }
    let Some(client_id) = params.get("client_id").cloned() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };
    let credentials = extract_client_credentials_with_trusted_proxies(
        &req,
        &context.config.trusted_proxy_cidrs,
        Some(&client_id),
        params.get("client_secret").map(String::as_str),
        params.get("client_assertion_type").map(String::as_str),
        params.get("client_assertion").map(String::as_str),
    );
    if has_basic && credentials.method != "client_secret_basic" {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    }
    let client = match context.service.client_by_id(&client_id).await {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            crate::http::token::client_auth::perform_dummy_client_secret_verification(
                &credentials,
                &context.config.client_secret_pepper,
            );
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query PAR client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    let auth_request = client_auth_request_facts(&req, &context.config.trusted_proxy_cidrs);
    let client_assertion = match authenticate_client_with_dependencies(
        context.service,
        crate::http::token::client_auth::ClientAuthConfig::new(
            &context.config.issuer,
            &context.config.client_secret_pepper,
        ),
        &auth_request,
        &client,
        &credentials,
        nazo_auth::ClientAuthenticationContext::AllowPublicNone,
    )
    .await
    {
        Ok(assertion) => assertion,
        Err(error) => return token_management_auth_error(error),
    };
    params.remove("client_secret");
    params.remove("client_assertion_type");
    params.remove("client_assertion");
    if let Err(error) = validate_raw_par_admission(
        &params,
        RawParAdmissionPolicy {
            client_is_confidential: client.client_type == "confidential",
            client_authentication_method: &client.token_endpoint_auth_method,
            require_dpop_bound_tokens: client.require_dpop_bound_tokens,
            require_mtls_bound_tokens: client.require_mtls_bound_tokens,
            require_request_object: client.require_par_request_object
                || context
                    .config
                    .profile
                    .requires_signed_authorization_request(),
            fapi2_security: context.config.profile.requires_fapi2_security(),
        },
    ) {
        return par_admission_error(error);
    }
    if let Err(response) = apply_request_object_with_context(context, &mut params, &client).await {
        return response;
    }
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::AuthorizationDetails,
    ) && params.contains_key("authorization_details")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 未启用.",
        );
    }
    params.remove("request");
    if let Err(error) = validate_expanded_par_admission(
        &params,
        ExpandedParAdmissionPolicy {
            client_type: &client.client_type,
            redirect_uris: &client.redirect_uris,
            allowed_audiences: &client.allowed_audiences,
            fapi2_requires_explicit_redirect_uri: context.config.profile.requires_fapi2_security(),
        },
    ) {
        return par_admission_error(error);
    }
    let request_dpop_jkt = match params.get("dpop_jkt") {
        Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
        Some(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "dpop_jkt 无效.");
        }
        None => None,
    };
    let header_dpop_jkt = match crate::http::dpop::validate_dpop_proof_with_authorization_service(
        context.service,
        &context.config.issuer,
        &context.config.mtls_endpoint_base_url,
        context.config.dpop_nonce_policy,
        &req,
        None,
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if let (Some(request_dpop_jkt), Some(header_dpop_jkt)) =
        (request_dpop_jkt.as_deref(), header_dpop_jkt.as_deref())
        && request_dpop_jkt != header_dpop_jkt
    {
        return dpop_error_response(DpopError::BindingMismatch, DpopErrorContext::TokenEndpoint);
    }
    if let Err(error) = consume_token_management_client_assertion_with_authorization_service(
        context.service,
        &client,
        client_assertion.as_ref(),
    )
    .await
    {
        return token_management_auth_error(error);
    }
    let dpop_jkt = request_dpop_jkt.or(header_dpop_jkt);
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        request_mtls_thumbprint_from_trusted_proxy(&req, &context.config.trusted_proxy_cidrs)
    } else {
        None
    };

    let now = Utc::now();
    let request_token = random_urlsafe_token();
    let request_uri = format!("{PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX}{request_token}");
    let payload = PushedAuthorizationRequest {
        client_id,
        params,
        dpop_jkt,
        mtls_x5t_s256,
        issued_at: now,
        expires_at: now + Duration::seconds(context.config.par_ttl_seconds as i64),
    };
    if let Err(error) = context
        .service
        .store_par(
            &request_uri,
            &payload,
            context.config.par_ttl_seconds.max(1),
        )
        .await
    {
        tracing::warn!(%error, "failed to persist PAR payload");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "PAR 写入失败.",
        );
    }
    json_response_status(
        StatusCode::CREATED,
        json!({
            "request_uri": request_uri,
            "expires_in": context.config.par_ttl_seconds
        }),
    )
}

fn par_admission_error(error: ParAdmissionError) -> HttpResponse {
    let (status, description) = match error {
        ParAdmissionError::RequestUriNotAllowed => (
            StatusCode::BAD_REQUEST,
            "PAR request object 不能包含 request_uri.",
        ),
        ParAdmissionError::UnsupportedResponseType => (
            StatusCode::BAD_REQUEST,
            "PAR response_type is not supported.",
        ),
        ParAdmissionError::RequestObjectRequired => {
            (StatusCode::BAD_REQUEST, "PAR 请求缺少 request object.")
        }
        ParAdmissionError::ConfidentialClientRequired => (
            StatusCode::BAD_REQUEST,
            "FAPI2 profiles require confidential clients.",
        ),
        ParAdmissionError::StrongClientAuthenticationRequired => (
            StatusCode::UNAUTHORIZED,
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
        ),
        ParAdmissionError::SenderConstraintRequired => (
            StatusCode::BAD_REQUEST,
            "FAPI2 profiles require sender-constrained access tokens.",
        ),
        ParAdmissionError::ExplicitRedirectUriRequired => (
            StatusCode::BAD_REQUEST,
            "FAPI2 PAR 请求必须显式包含 redirect_uri.",
        ),
        ParAdmissionError::RedirectUriRequired => {
            (StatusCode::BAD_REQUEST, "PAR 请求缺少 redirect_uri.")
        }
        ParAdmissionError::RedirectUriNotRegistered => {
            (StatusCode::BAD_REQUEST, "PAR 请求 redirect_uri 未注册.")
        }
        ParAdmissionError::InvalidResource => (
            StatusCode::BAD_REQUEST,
            "resource must be an absolute URI without a fragment.",
        ),
        ParAdmissionError::ResourceNotAllowed => (
            StatusCode::BAD_REQUEST,
            "请求的 resource 不在客户端允许范围内.",
        ),
    };
    oauth_error(status, error.oauth_error(), description)
}

fn log_par_error_response(response: &HttpResponse) {
    let Some((status, oauth_error)) = par_error_log_fields(response) else {
        return;
    };
    if let Some(oauth_error) = oauth_error {
        tracing::warn!("PAR request rejected http_status={status} oauth_error={oauth_error}");
    } else {
        tracing::warn!("PAR request rejected http_status={status}");
    }
}

fn par_error_log_fields(response: &HttpResponse) -> Option<(u16, Option<String>)> {
    if response.status() == StatusCode::CREATED || response.status().is_success() {
        return None;
    }

    Some((
        response.status().as_u16(),
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.clone()),
    ))
}

#[cfg(test)]
pub(crate) fn pushed_authorization_request_key(request_uri: &str) -> String {
    format!("oauth:par:{}", blake3_hex(request_uri))
}

pub(crate) fn is_pushed_authorization_request_uri(request_uri: &str) -> bool {
    request_uri.starts_with(PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX)
}

#[cfg(test)]
fn validate_pushed_authorization_request(
    client: &ClientRow,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    if pushed_authorization_request_has_unsupported_response_type(params) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "PAR response_type is not supported.",
        ));
    }
    registered_redirect_uri(client, params.get("redirect_uri").map(String::as_str))
        .map(|_| ())
        .map_err(|error| match error {
            RedirectUriError::Missing => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求缺少 redirect_uri.",
            ),
            RedirectUriError::Invalid => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求 redirect_uri 未注册.",
            ),
        })
}

#[cfg(test)]
fn pushed_authorization_request_has_unsupported_response_type(
    params: &HashMap<String, String>,
) -> bool {
    params
        .get("response_type")
        .is_some_and(|response_type| response_type != "code")
}

#[cfg(test)]
fn pushed_authorization_request_contains_request_uri(params: &HashMap<String, String>) -> bool {
    params.contains_key("request_uri")
}

#[cfg(test)]
fn validate_pushed_authorization_request_resources(
    client: &ClientRow,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    let resources = parse_resource_indicator_parameter(params.get("resource").map(String::as_str))
        .map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource must be an absolute URI without a fragment.",
            )
        })?;
    if !resources.is_empty() && !audiences_allowed(client, &resources) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 resource 不在客户端允许范围内.",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn pushed_authorization_request_requires_request_object(
    settings: &Settings,
    client: &ClientRow,
) -> bool {
    pushed_authorization_request_requires_request_object_with_config(
        &AuthorizationHttpConfig::from(settings),
        client,
    )
}

#[cfg(test)]
fn pushed_authorization_request_requires_request_object_with_config(
    config: &AuthorizationHttpConfig,
    client: &ClientRow,
) -> bool {
    client.require_par_request_object || config.profile.requires_signed_authorization_request()
}

#[cfg(test)]
fn validate_pushed_authorization_request_profile(
    settings: &Settings,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    validate_pushed_authorization_request_profile_with_config(
        &AuthorizationHttpConfig::from(settings),
        client,
        auth_method,
    )
}

#[cfg(test)]
fn validate_pushed_authorization_request_profile_with_config(
    config: &AuthorizationHttpConfig,
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    if !config.profile.requires_fapi2_security() {
        return Ok(());
    }
    if client.client_type != "confidential" {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "FAPI2 profiles require confidential clients.",
        ));
    }
    if !matches!(
        auth_method,
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
    ) {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
        ));
    }
    if !(client.require_dpop_bound_tokens || client.require_mtls_bound_tokens) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "FAPI2 profiles require sender-constrained access tokens.",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_pushed_authorization_request_profile_parameters(
    settings: &Settings,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    validate_pushed_authorization_request_profile_parameters_with_config(
        &AuthorizationHttpConfig::from(settings),
        params,
    )
}

#[cfg(test)]
fn validate_pushed_authorization_request_profile_parameters_with_config(
    config: &AuthorizationHttpConfig,
    params: &HashMap<String, String>,
) -> Result<(), HttpResponse> {
    if config.profile.requires_fapi2_security() && !params.contains_key("redirect_uri") {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "FAPI2 PAR 请求必须显式包含 redirect_uri.",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/par.rs"]
mod tests;
