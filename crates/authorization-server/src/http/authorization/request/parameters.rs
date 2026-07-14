#[cfg(test)]
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::oidc_claims::supported_user_claim;
#[cfg(test)]
use crate::http::authorization::BASELINE_ACR_VALUE;
use nazo_auth::OidcClaimRequest;
#[cfg(test)]
use nazo_auth::is_valid_pkce_value;
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::collections::HashMap;
#[cfg(test)]
use uuid::Uuid;

pub(crate) const AUTHORIZED_REQUEST_PARAMETERS: &[&str] = &[
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
    "request_uri",
    "request",
];
#[cfg(test)]
pub(super) const AUTHORIZATION_NONCE_MAX_BYTES: usize = 256;
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

#[cfg(test)]
pub(super) fn authorization_request_requires_pkce(client: &ClientRow) -> bool {
    client.client_type == "public"
        || client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || !client.allow_authorization_code_without_pkce
}

#[cfg(test)]
pub(super) fn authorization_pkce(
    q: &HashMap<String, String>,
) -> Result<(Option<String>, Option<String>), ()> {
    match (
        q.get("code_challenge").map(String::as_str),
        q.get("code_challenge_method").map(String::as_str),
    ) {
        (None, None) => Ok((None, None)),
        (Some(code_challenge), Some("S256")) if is_valid_pkce_value(code_challenge) => {
            Ok((Some(code_challenge.to_owned()), Some("S256".to_owned())))
        }
        _ => Err(()),
    }
}

#[cfg(test)]
pub(super) fn authorization_response_mode(
    q: &HashMap<String, String>,
) -> Result<Option<String>, ()> {
    match q.get("response_mode").map(String::as_str) {
        None | Some("query") => Ok(None),
        Some("jwt") => Ok(Some("jwt".to_owned())),
        _ => Err(()),
    }
}

#[cfg(test)]
pub(super) fn requested_acr(
    q: &HashMap<String, String>,
    claims_acr: Option<&OidcClaimRequest>,
) -> Result<Option<String>, ()> {
    if let Some(claim) = claims_acr {
        let constrained = claim.value.is_some() || !claim.values.is_empty();
        let supports_baseline = claim
            .value
            .as_ref()
            .map(acr_value_is_baseline)
            .transpose()?
            .unwrap_or(false)
            || claim
                .values
                .iter()
                .map(acr_value_is_baseline)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .any(|supported| supported);
        if claim.essential && constrained && !supports_baseline {
            return Err(());
        }
        if !constrained || supports_baseline {
            return Ok(Some(BASELINE_ACR_VALUE.to_owned()));
        }
    }

    Ok(q.get("acr_values")
        .and_then(|values| {
            values
                .split_whitespace()
                .find(|value| *value == BASELINE_ACR_VALUE)
        })
        .map(str::to_owned))
}

#[cfg(test)]
fn acr_value_is_baseline(value: &Value) -> Result<bool, ()> {
    value
        .as_str()
        .map(|value| value == BASELINE_ACR_VALUE)
        .ok_or(())
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub(super) struct RequestedClaims {
    pub(super) userinfo: Vec<OidcClaimRequest>,
    pub(super) id_token: Vec<OidcClaimRequest>,
    pub(super) acr: Option<OidcClaimRequest>,
    pub(super) auth_time: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct PromptDirectives {
    pub(super) login: bool,
    pub(super) consent: bool,
    pub(super) select_account: bool,
    pub(super) none: bool,
}

#[cfg(test)]
pub(super) fn requested_prompt(q: &HashMap<String, String>) -> Result<PromptDirectives, ()> {
    let Some(raw) = q.get("prompt") else {
        return Ok(PromptDirectives::default());
    };
    let mut directives = PromptDirectives::default();
    for value in raw.split_whitespace() {
        match value {
            "login" => directives.login = true,
            "consent" => directives.consent = true,
            "select_account" => directives.select_account = true,
            "none" => directives.none = true,
            "" => {}
            _ => return Err(()),
        }
    }
    if directives.none && (directives.login || directives.consent || directives.select_account) {
        return Err(());
    }
    Ok(directives)
}

#[cfg(test)]
pub(super) fn requested_claims(q: &HashMap<String, String>) -> Result<RequestedClaims, ()> {
    let Some(raw_claims) = q.get("claims") else {
        return Ok(RequestedClaims {
            userinfo: Vec::new(),
            id_token: Vec::new(),
            acr: None,
            auth_time: false,
        });
    };
    let claims: Value = serde_json::from_str(raw_claims).map_err(|_| ())?;
    let userinfo = requested_claim_requests(claims.get("userinfo"))?;
    let id_token = requested_claim_requests(claims.get("id_token"))?;
    let acr = requested_acr_claim(claims.get("id_token"))?;
    let auth_time = requested_auth_time_claim(claims.get("id_token"))?;
    Ok(RequestedClaims {
        userinfo,
        id_token,
        acr,
        auth_time,
    })
}

#[cfg(test)]
fn requested_claim_requests(value: Option<&Value>) -> Result<Vec<OidcClaimRequest>, ()> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let mut requests = Vec::new();
    for (name, request) in object {
        if supported_user_claim(name) {
            requests.push(parse_claim_request(name, request)?);
        } else {
            validate_claim_request(request)?;
        }
    }
    requests.sort_by(|left, right| left.name.cmp(&right.name));
    requests.dedup_by(|left, right| left.name == right.name);
    Ok(requests)
}

#[cfg(test)]
fn validate_acr_claim(value: Option<&Value>) -> Result<(), ()> {
    requested_acr_claim(value).map(|_| ())
}

#[cfg(test)]
fn requested_acr_claim(value: Option<&Value>) -> Result<Option<OidcClaimRequest>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    object
        .get("acr")
        .map(|acr| parse_claim_request("acr", acr))
        .transpose()
}

#[cfg(test)]
fn requested_auth_time_claim(value: Option<&Value>) -> Result<bool, ()> {
    let Some(value) = value else {
        return Ok(false);
    };
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let Some(auth_time) = object.get("auth_time") else {
        return Ok(false);
    };
    validate_claim_request(auth_time)?;
    Ok(true)
}

#[cfg(test)]
fn validate_claim_request(value: &Value) -> Result<(), ()> {
    parse_optional_claim_request(None, value).map(|_| ())
}

#[cfg(test)]
fn parse_claim_request(name: &str, value: &Value) -> Result<OidcClaimRequest, ()> {
    parse_optional_claim_request(Some(name), value)?.ok_or(())
}

#[cfg(test)]
fn parse_optional_claim_request(
    name: Option<&str>,
    value: &Value,
) -> Result<Option<OidcClaimRequest>, ()> {
    if value.is_null() {
        return Ok(name.map(|name| OidcClaimRequest {
            name: name.to_owned(),
            essential: false,
            value: None,
            values: Vec::new(),
        }));
    }
    let Some(object) = value.as_object() else {
        return Err(());
    };
    let essential = match object.get("essential") {
        Some(essential) => essential.as_bool().ok_or(())?,
        None => false,
    };
    if object.contains_key("value") && object.contains_key("values") {
        return Err(());
    }
    let requested_value = object.get("value").cloned();
    let mut requested_values = Vec::new();
    if let Some(values) = object.get("values") {
        let Some(values) = values.as_array() else {
            return Err(());
        };
        if values.is_empty() {
            return Err(());
        }
        requested_values = values.clone();
    }
    Ok(name.map(|name| OidcClaimRequest {
        name: name.to_owned(),
        essential,
        value: requested_value,
        values: requested_values,
    }))
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

#[cfg(test)]
pub(super) fn session_requires_reauthentication(
    prompt: PromptDirectives,
    max_age: Option<i64>,
    auth_time: i64,
    reauth_started_at: Option<i64>,
    now: i64,
) -> bool {
    let prompt_requires_fresh_login = (prompt.login || prompt.select_account)
        && reauth_started_at.is_none_or(|started_at| auth_time < started_at);
    prompt_requires_fresh_login
        || match max_age {
            Some(0) => true,
            Some(max_age) => now.saturating_sub(auth_time) > max_age,
            None => false,
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

pub(super) fn append_authorization_response_query(
    redirect_uri: &str,
    issuer: &str,
    code: Option<&str>,
    error: Option<&str>,
    state_value: Option<&str>,
    session_state: Option<&str>,
) -> String {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return redirect_uri.to_owned();
    };
    {
        let mut query = url.query_pairs_mut();
        if let Some(code) = code {
            query.append_pair("code", code);
        }
        if let Some(error) = error {
            query.append_pair("error", error);
        }
        if let Some(state_value) = state_value {
            query.append_pair("state", state_value);
        }
        if let Some(session_state) = session_state {
            query.append_pair("session_state", session_state);
        }
        query.append_pair("iss", issuer);
    }
    url.to_string()
}

#[cfg(test)]
pub(super) fn authorization_nonce_too_long(q: &HashMap<String, String>) -> bool {
    q.get("nonce")
        .is_some_and(|value| value.len() > AUTHORIZATION_NONCE_MAX_BYTES)
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
#[path = "../../../../tests/in_source/src/http/authorization/request/tests/parameters.rs"]
mod tests;
