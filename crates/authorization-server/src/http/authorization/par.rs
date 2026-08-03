//! Pushed Authorization Request endpoint.
use nazo_http_actix::{OAuthJsonErrorFields, json_response_status, oauth_error};

use super::jar::apply_request_object_with_context;
use crate::adapters::security::extract_client_credentials_with_trusted_proxies;
use crate::adapters::security::has_basic_authorization_scheme;
use crate::adapters::security::random_urlsafe_token;

use crate::domain::PushedAuthorizationRequest;

use crate::http::authorization::{AuthorizationEndpoint, AuthorizationRequestContext};
use crate::http::client_attestation::client_attestation_headers;
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use crate::http::rate_limit::rate_limited_response;

use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};

use nazo_auth::{
    ExpandedParAdmissionPolicy, ParAdmissionError, RawParAdmissionPolicy,
    encode_resource_indicators, is_valid_dpop_jkt, unverified_client_assertion_client_id,
    validate_expanded_par_admission, validate_raw_par_admission,
};

use serde_json::json;
use std::collections::HashMap;

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
    "issuer_state",
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
    let subject = nazo_http_actix::client_ip_with_context(
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
            // Authorization request parameters are extension points. OAuth 2.0
            // and OpenID4VCI require unrecognized authorization request
            // parameters to be ignored, not rejected. Do not retain them in the
            // pushed request: this preserves interoperability without allowing
            // attacker-controlled extension data into authenticated PAR state.
            continue;
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
    let attestation_headers = match client_attestation_headers(req.headers()) {
        Ok(headers) => headers,
        Err(()) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Exactly one of each client attestation header is required.",
            );
        }
    };
    if has_basic && (params.contains_key("client_secret") || has_assertion)
        || has_assertion && params.contains_key("client_secret")
        || attestation_headers.is_some()
            && (has_basic || has_assertion || params.contains_key("client_secret"))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PAR 请求不能同时使用多种客户端认证方式.",
        );
    }
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::RequestObjects,
    ) && params.contains_key("request")
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

    if !params.contains_key("client_id")
        && let Some(request_object) = params.get("request")
        && let Some(client_id) =
            super::unverified_request_object_client_id(context.request_object_keys, request_object)
    {
        params.insert("client_id".to_owned(), client_id);
    }
    if !params.contains_key("client_id")
        && let Some((attestation, _)) = attestation_headers
        && let Some(client_id) =
            crate::domain::Openid4vcClientAttestationValidator::unverified_client_id(attestation)
    {
        params.insert("client_id".to_owned(), client_id);
    }
    if !params.contains_key("client_id")
        && let Some(client_id) = params
            .get("client_assertion")
            .and_then(|assertion| unverified_client_assertion_client_id(assertion))
    {
        // This value is only a lookup hint. Client authentication below verifies
        // the assertion signature and binds its issuer/subject to the client.
        params.insert("client_id".to_owned(), client_id);
    }
    let Some(client_id) = params.get("client_id").cloned() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };
    let mut credentials = extract_client_credentials_with_trusted_proxies(
        &req,
        &context.config.trusted_proxy_cidrs,
        Some(&client_id),
        params.get("client_secret").map(String::as_str),
        params.get("client_assertion_type").map(String::as_str),
        params.get("client_assertion").map(String::as_str),
    );
    if attestation_headers.is_some() {
        credentials = nazo_auth::PresentedClientCredentials {
            client_id: Some(client_id.clone()),
            client_secret: None,
            client_assertion: None,
            method: "attest_jwt_client_auth".to_owned(),
        };
    }
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
    let client_policy = context.config.profile.effective_client_policy(&client);
    let par_ttl_seconds = if client_policy.requires_fapi2_security() {
        context.config.par_ttl_seconds.min(599)
    } else {
        context.config.par_ttl_seconds
    };
    let auth_request = client_auth_request_facts(&req, &context.config.trusted_proxy_cidrs);
    let client_assertion = if let Some((attestation, proof)) = attestation_headers {
        if client.token_endpoint_auth_method != "attest_jwt_client_auth" {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
                "Client attestation is not registered for this client.",
            );
        }
        let Some(validator) =
            req.app_data::<Data<crate::domain::Openid4vcClientAttestationValidator>>()
        else {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
                "Client attestation is not configured.",
            );
        };
        let validated = match validator
            .validate_for_client(
                attestation,
                proof,
                &context.config.issuer,
                Utc::now().timestamp(),
            )
            .await
        {
            Ok(validated) if validated.client_id == client.client_id => validated,
            _ => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation validation failed.",
                );
            }
        };
        let replay_key = format!("client-attestation:{}", validated.client_id);
        match context
            .service
            .consume_private_key_jwt(
                &replay_key,
                &validated.replay_id,
                validated.replay_ttl_seconds,
            )
            .await
        {
            Ok(true) => None,
            Ok(false) => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation proof was replayed.",
                );
            }
            Err(_) => {
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Client attestation replay state is unavailable.",
                );
            }
        }
    } else {
        match authenticate_client_with_dependencies(
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
        }
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
                || client_policy.require_signed_authorization_request,
            fapi2_security: client_policy.requires_fapi2_security(),
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
            fapi2_requires_explicit_redirect_uri: client_policy.requires_fapi2_security(),
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
        expires_at: now + Duration::seconds(par_ttl_seconds as i64),
    };
    if let Err(error) = context
        .service
        .store_par(&request_uri, &payload, par_ttl_seconds.max(1))
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
            "expires_in": par_ttl_seconds
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
        ParAdmissionError::PkceRequired => (StatusCode::BAD_REQUEST, "PAR requests require PKCE."),
        ParAdmissionError::InvalidPkce => (
            StatusCode::BAD_REQUEST,
            "PAR code_challenge must use a valid S256 value.",
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

pub(crate) fn is_pushed_authorization_request_uri(request_uri: &str) -> bool {
    request_uri.starts_with(PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX)
}

#[cfg(test)]
#[path = "../../../tests/unit/http/authorization/par.rs"]
mod tests;
