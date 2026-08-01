use nazo_auth::OidcClaimRequest;

use std::collections::HashMap;

pub(crate) const AUTHORIZED_REQUEST_PARAMETERS: &[&str] = &[
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
    "request_uri",
    "request",
];

const REAUTH_NONCE_PARAMETER: &str = "_nazo_reauth_nonce";

pub(super) fn authorization_duplicate_parameters() -> Vec<&'static str> {
    let mut parameters = AUTHORIZED_REQUEST_PARAMETERS
        .iter()
        .copied()
        .filter(|parameter| *parameter != "resource")
        .collect::<Vec<_>>();
    parameters.push(REAUTH_NONCE_PARAMETER);
    parameters
}

pub(super) fn reauth_nonce_parameter() -> &'static str {
    REAUTH_NONCE_PARAMETER
}

pub(super) fn claim_request_names(requests: &[OidcClaimRequest]) -> Vec<String> {
    requests
        .iter()
        .map(|request| request.name.clone())
        .collect()
}

pub(super) fn preserve_verified_dpop_binding(
    q: &mut HashMap<String, String>,
    dpop_jkt: Option<&str>,
) {
    if let Some(dpop_jkt) = dpop_jkt
        && !q.contains_key("dpop_jkt")
    {
        q.insert("dpop_jkt".to_owned(), dpop_jkt.to_owned());
    }
}

pub(super) fn outer_request_uri_parameters_match_pushed(
    outer: &HashMap<String, String>,
    pushed: &HashMap<String, String>,
) -> bool {
    outer.iter().all(|(key, outer_value)| {
        if key == "request_uri" || key == "client_id" {
            return true;
        }
        pushed.get(key) == Some(outer_value)
    })
}

pub(super) fn outer_request_uri_parameters_are_fapi_compliant(
    outer: &HashMap<String, String>,
) -> bool {
    outer
        .keys()
        .all(|key| matches!(key.as_str(), "client_id" | "request_uri"))
}

pub(super) fn authorization_login_query(
    expanded: &HashMap<String, String>,
    original: &HashMap<String, String>,
    request_uri: Option<&String>,
) -> HashMap<String, String> {
    if request_uri.is_some() {
        original.clone()
    } else {
        expanded.clone()
    }
}

pub(super) fn authorization_login_url_for_frontend(
    frontend_base_url: &str,
    q: &HashMap<String, String>,
    reauth_nonce: Option<&str>,
) -> String {
    let mut next_query = q.clone();
    if let Some(reauth_nonce) = reauth_nonce {
        next_query.insert(REAUTH_NONCE_PARAMETER.to_owned(), reauth_nonce.to_owned());
    }
    let query = next_query
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let next = if query.is_empty() {
        "/authorize".to_string()
    } else {
        format!("/authorize?{query}")
    };
    format!(
        "{}/auth?next={}",
        frontend_base_url.trim_end_matches('/'),
        urlencoding::encode(&next)
    )
}

#[cfg(test)]
#[path = "../../../../tests/unit/http/authorization/request/parameters.rs"]
mod tests;
