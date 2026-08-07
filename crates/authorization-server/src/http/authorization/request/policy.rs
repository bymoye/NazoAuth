use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use nazo_auth::parse_scope;
use nazo_http_actix::oauth_error;
use serde_json::Value;
use std::collections::HashMap;

use super::AuthorizationRequestContext;

pub(super) fn credential_configuration_ids(authorization_details: &Value) -> Vec<String> {
    authorization_details
        .as_array()
        .into_iter()
        .flatten()
        .filter(|detail| detail.get("type").and_then(Value::as_str) == Some("openid_credential"))
        .filter_map(|detail| {
            detail
                .get("credential_configuration_id")
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn runtime_authorization_capability_error(
    context: &AuthorizationRequestContext<'_>,
    parameters: &HashMap<String, String>,
) -> Option<HttpResponse> {
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::RequestObjects,
    ) && parameters.contains_key("request")
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request 参数未启用.",
        ));
    }
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::AuthorizationDetails,
    ) && parameters.contains_key("authorization_details")
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 参数未启用.",
        ));
    }
    if parameters
        .get("response_mode")
        .is_some_and(|mode| mode == "jwt")
        && !crate::http::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::Jarm,
        )
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_mode",
            "JWT-secured authorization responses are disabled.",
        ));
    }
    if parameters
        .get("scope")
        .is_some_and(|scope| parse_scope(scope).iter().any(|value| value == "device_sso"))
        && !crate::http::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::NativeSso,
        )
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO is disabled.",
        ));
    }
    None
}
