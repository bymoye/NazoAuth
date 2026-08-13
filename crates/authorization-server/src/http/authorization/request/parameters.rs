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

pub(super) fn authorization_login_query(
    expanded: &HashMap<String, String>,
    original: Option<&HashMap<String, String>>,
    request_uri: Option<&String>,
) -> HashMap<String, String> {
    if request_uri.is_some() {
        original.cloned().unwrap_or_else(|| expanded.clone())
    } else {
        expanded.clone()
    }
}

pub(super) fn authorization_login_url_for_frontend(
    frontend_base_url: &str,
    q: &HashMap<String, String>,
    reauth_nonce: Option<&str>,
) -> String {
    let mut next = String::from("/authorize");
    let mut has_query = false;
    for (key, value) in q {
        next.push(if has_query { '&' } else { '?' });
        has_query = true;
        next.push_str(&urlencoding::encode(key));
        next.push('=');
        next.push_str(&urlencoding::encode(value));
    }
    if let Some(reauth_nonce) = reauth_nonce {
        next.push(if has_query { '&' } else { '?' });
        next.push_str(REAUTH_NONCE_PARAMETER);
        next.push('=');
        next.push_str(&urlencoding::encode(reauth_nonce));
    }

    let mut location = String::with_capacity(frontend_base_url.len() + next.len() + 16);
    location.push_str(frontend_base_url.trim_end_matches('/'));
    location.push_str("/auth?next=");
    location.push_str(&urlencoding::encode(&next));
    location
}

#[cfg(test)]
#[path = "../../../../tests/unit/http/authorization/request/parameters.rs"]
mod tests;
