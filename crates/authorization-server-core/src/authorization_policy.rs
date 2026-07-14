use std::collections::HashMap;

use serde_json::Value;

use crate::{
    AuthorizationPortError, AuthorizationResponseSignInput, OidcClaimRequest, is_subset,
    is_valid_dpop_jkt, is_valid_pkce_value, parse_authorization_details,
    parse_resource_indicator_parameter, parse_scope, supported_user_claim,
};

pub const BASELINE_ACR_VALUE: &str = "1";
pub const AUTHORIZATION_NONCE_MAX_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PromptDirectives {
    pub login: bool,
    pub consent: bool,
    pub select_account: bool,
    pub none: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RequestedClaims {
    pub userinfo: Vec<OidcClaimRequest>,
    pub id_token: Vec<OidcClaimRequest>,
    pub acr: Option<OidcClaimRequest>,
    pub auth_time: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizationClientPolicy<'a> {
    pub client_type: &'a str,
    pub allowed_scopes: &'a [String],
    pub allowed_audiences: &'a [String],
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
    pub allow_authorization_code_without_pkce: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizationCapabilityPolicy {
    pub authorization_details: bool,
    pub jarm: bool,
    pub native_sso: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizationProfilePolicy {
    pub signed_authorization_response_required: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NormalizedAuthorizationRequest {
    pub response_mode: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: PromptDirectives,
    pub max_age: Option<i64>,
    pub requested_claims: RequestedClaims,
    pub acr: Option<String>,
    pub scopes: Vec<String>,
    pub resources: Vec<String>,
    pub authorization_details: Value,
    pub dpop_jkt: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationPolicyError {
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    UnsupportedResponseType,
    UnsupportedResponseMode,
}

impl AuthorizationPolicyError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::UnsupportedResponseMode => "unsupported_response_mode",
        }
    }
}

/// Normalizes authorization parameters after client, PAR and request-object
/// resolution. This function performs no session lookup or state mutation.
pub fn normalize_authorization_request(
    parameters: &HashMap<String, String>,
    client: AuthorizationClientPolicy<'_>,
    capabilities: AuthorizationCapabilityPolicy,
    profile: AuthorizationProfilePolicy,
    used_pushed_authorization_request: bool,
) -> Result<NormalizedAuthorizationRequest, AuthorizationPolicyError> {
    if parameters.get("response_type").map(String::as_str) != Some("code") {
        return Err(AuthorizationPolicyError::UnsupportedResponseType);
    }
    if parameters
        .get("nonce")
        .is_some_and(|nonce| nonce.len() > AUTHORIZATION_NONCE_MAX_BYTES)
    {
        return Err(AuthorizationPolicyError::InvalidRequest);
    }
    if (client.require_dpop_bound_tokens || client.require_mtls_bound_tokens)
        && !used_pushed_authorization_request
        && !parameters.contains_key("request")
    {
        return Err(AuthorizationPolicyError::InvalidRequest);
    }
    if parameters.contains_key("authorization_details") && !capabilities.authorization_details {
        return Err(AuthorizationPolicyError::InvalidRequest);
    }

    let response_mode = match parameters.get("response_mode").map(String::as_str) {
        None | Some("query") => None,
        Some("jwt") if capabilities.jarm => Some("jwt".to_owned()),
        Some("jwt") => return Err(AuthorizationPolicyError::UnsupportedResponseMode),
        _ => return Err(AuthorizationPolicyError::InvalidRequest),
    };
    if profile.signed_authorization_response_required && !capabilities.jarm {
        return Err(AuthorizationPolicyError::UnsupportedResponseMode);
    }

    let (code_challenge, code_challenge_method) = match (
        parameters.get("code_challenge").map(String::as_str),
        parameters.get("code_challenge_method").map(String::as_str),
    ) {
        (None, None) => (None, None),
        (Some(challenge), Some("S256")) if is_valid_pkce_value(challenge) => {
            (Some(challenge.to_owned()), Some("S256".to_owned()))
        }
        _ => return Err(AuthorizationPolicyError::InvalidRequest),
    };
    let pkce_required = client.client_type == "public"
        || client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || !client.allow_authorization_code_without_pkce;
    if pkce_required && code_challenge.is_none() {
        return Err(AuthorizationPolicyError::InvalidRequest);
    }

    let prompt = requested_prompt(parameters)?;
    let max_age = match parameters.get("max_age") {
        Some(value) => Some(
            value
                .parse::<i64>()
                .ok()
                .filter(|value| *value >= 0)
                .ok_or(AuthorizationPolicyError::InvalidRequest)?,
        ),
        None => None,
    };
    let requested_claims = requested_claims(parameters)?;
    let acr = requested_acr(parameters, requested_claims.acr.as_ref())?;
    let scopes = parse_scope(parameters.get("scope").map(String::as_str).unwrap_or(""));
    if !is_subset(&scopes, client.allowed_scopes) {
        return Err(AuthorizationPolicyError::InvalidScope);
    }
    if !capabilities.native_sso && scopes.iter().any(|scope| scope == "device_sso") {
        return Err(AuthorizationPolicyError::InvalidScope);
    }
    let resources =
        parse_resource_indicator_parameter(parameters.get("resource").map(String::as_str))
            .map_err(|_| AuthorizationPolicyError::InvalidTarget)?;
    if !resources.is_empty() && !is_subset(&resources, client.allowed_audiences) {
        return Err(AuthorizationPolicyError::InvalidTarget);
    }
    let authorization_details =
        parse_authorization_details(parameters.get("authorization_details").map(String::as_str))
            .map_err(|_| AuthorizationPolicyError::InvalidRequest)?;
    let dpop_jkt = match parameters.get("dpop_jkt") {
        Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
        Some(_) => return Err(AuthorizationPolicyError::InvalidRequest),
        None => None,
    };

    Ok(NormalizedAuthorizationRequest {
        response_mode,
        code_challenge,
        code_challenge_method,
        prompt,
        max_age,
        requested_claims,
        acr,
        scopes,
        resources,
        authorization_details,
        dpop_jkt,
    })
}

fn requested_prompt(
    parameters: &HashMap<String, String>,
) -> Result<PromptDirectives, AuthorizationPolicyError> {
    let Some(raw) = parameters.get("prompt") else {
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
            _ => return Err(AuthorizationPolicyError::InvalidRequest),
        }
    }
    if directives.none && (directives.login || directives.consent || directives.select_account) {
        return Err(AuthorizationPolicyError::InvalidRequest);
    }
    Ok(directives)
}

fn requested_claims(
    parameters: &HashMap<String, String>,
) -> Result<RequestedClaims, AuthorizationPolicyError> {
    let Some(raw) = parameters.get("claims") else {
        return Ok(RequestedClaims::default());
    };
    let claims: Value =
        serde_json::from_str(raw).map_err(|_| AuthorizationPolicyError::InvalidRequest)?;
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

fn requested_claim_requests(
    value: Option<&Value>,
) -> Result<Vec<OidcClaimRequest>, AuthorizationPolicyError> {
    let Some(object) = value.and_then(Value::as_object) else {
        return if value.is_none() {
            Ok(Vec::new())
        } else {
            Err(AuthorizationPolicyError::InvalidRequest)
        };
    };
    let mut requests = Vec::new();
    for (name, request) in object {
        if supported_user_claim(name) {
            requests.push(parse_claim_request(name, request)?);
        } else {
            parse_optional_claim_request(None, request)?;
        }
    }
    requests.sort_by(|left, right| left.name.cmp(&right.name));
    requests.dedup_by(|left, right| left.name == right.name);
    Ok(requests)
}

fn requested_acr_claim(
    value: Option<&Value>,
) -> Result<Option<OidcClaimRequest>, AuthorizationPolicyError> {
    let Some(object) = value.and_then(Value::as_object) else {
        return if value.is_none() {
            Ok(None)
        } else {
            Err(AuthorizationPolicyError::InvalidRequest)
        };
    };
    object
        .get("acr")
        .map(|acr| parse_claim_request("acr", acr))
        .transpose()
}

fn requested_auth_time_claim(value: Option<&Value>) -> Result<bool, AuthorizationPolicyError> {
    let Some(object) = value.and_then(Value::as_object) else {
        return if value.is_none() {
            Ok(false)
        } else {
            Err(AuthorizationPolicyError::InvalidRequest)
        };
    };
    let Some(auth_time) = object.get("auth_time") else {
        return Ok(false);
    };
    parse_optional_claim_request(None, auth_time)?;
    Ok(true)
}

fn parse_claim_request(
    name: &str,
    value: &Value,
) -> Result<OidcClaimRequest, AuthorizationPolicyError> {
    parse_optional_claim_request(Some(name), value)?.ok_or(AuthorizationPolicyError::InvalidRequest)
}

fn parse_optional_claim_request(
    name: Option<&str>,
    value: &Value,
) -> Result<Option<OidcClaimRequest>, AuthorizationPolicyError> {
    if value.is_null() {
        return Ok(name.map(|name| OidcClaimRequest {
            name: name.to_owned(),
            essential: false,
            value: None,
            values: Vec::new(),
        }));
    }
    let object = value
        .as_object()
        .ok_or(AuthorizationPolicyError::InvalidRequest)?;
    let essential = match object.get("essential") {
        Some(value) => value
            .as_bool()
            .ok_or(AuthorizationPolicyError::InvalidRequest)?,
        None => false,
    };
    if object.contains_key("value") && object.contains_key("values") {
        return Err(AuthorizationPolicyError::InvalidRequest);
    }
    let requested_value = object.get("value").cloned();
    let requested_values = match object.get("values") {
        Some(values) => {
            let values = values
                .as_array()
                .filter(|values| !values.is_empty())
                .ok_or(AuthorizationPolicyError::InvalidRequest)?;
            values.clone()
        }
        None => Vec::new(),
    };
    Ok(name.map(|name| OidcClaimRequest {
        name: name.to_owned(),
        essential,
        value: requested_value,
        values: requested_values,
    }))
}

fn requested_acr(
    parameters: &HashMap<String, String>,
    claims_acr: Option<&OidcClaimRequest>,
) -> Result<Option<String>, AuthorizationPolicyError> {
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
            return Err(AuthorizationPolicyError::InvalidRequest);
        }
        if !constrained || supports_baseline {
            return Ok(Some(BASELINE_ACR_VALUE.to_owned()));
        }
    }
    Ok(parameters
        .get("acr_values")
        .and_then(|values| {
            values
                .split_whitespace()
                .find(|value| *value == BASELINE_ACR_VALUE)
        })
        .map(str::to_owned))
}

fn acr_value_is_baseline(value: &Value) -> Result<bool, AuthorizationPolicyError> {
    value
        .as_str()
        .map(|value| value == BASELINE_ACR_VALUE)
        .ok_or(AuthorizationPolicyError::InvalidRequest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationSession {
    pub auth_time: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationSessionDecision {
    Continue,
    Login { fresh_authentication: bool },
    LoginRequired,
}

#[must_use]
pub fn authorization_session_decision(
    session: Option<AuthorizationSession>,
    prompt: PromptDirectives,
    max_age: Option<i64>,
    reauthentication_started_at: Option<i64>,
    now: i64,
) -> AuthorizationSessionDecision {
    let fresh_authentication = prompt.login || prompt.select_account;
    let Some(session) = session else {
        return if prompt.none {
            AuthorizationSessionDecision::LoginRequired
        } else {
            AuthorizationSessionDecision::Login {
                fresh_authentication,
            }
        };
    };
    let prompt_requires_fresh_login = fresh_authentication
        && reauthentication_started_at.is_none_or(|started_at| session.auth_time < started_at);
    let max_age_expired = match max_age {
        Some(0) => true,
        Some(max_age) => now.saturating_sub(session.auth_time) > max_age,
        None => false,
    };
    if prompt_requires_fresh_login || max_age_expired {
        if prompt.none {
            AuthorizationSessionDecision::LoginRequired
        } else {
            AuthorizationSessionDecision::Login {
                fresh_authentication,
            }
        }
    } else {
        AuthorizationSessionDecision::Continue
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptNoneDecision {
    IssueAuthorizationCode,
    ConsentRequired,
}

pub fn prompt_none_decision(
    grant_covers_request: Result<bool, AuthorizationPortError>,
) -> Result<PromptNoneDecision, AuthorizationPortError> {
    grant_covers_request.map(|covers| {
        if covers {
            PromptNoneDecision::IssueAuthorizationCode
        } else {
            PromptNoneDecision::ConsentRequired
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserAuthorizationDecision {
    Approve,
    Deny,
}

#[must_use]
pub fn parse_user_authorization_decision(value: &str) -> Option<UserAuthorizationDecision> {
    match value {
        "approve" => Some(UserAuthorizationDecision::Approve),
        "deny" => Some(UserAuthorizationDecision::Deny),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizationResponsePolicyInput<'a> {
    pub issuer: &'a str,
    pub redirect_uri: &'a str,
    pub client_id: &'a str,
    pub response_mode: Option<&'a str>,
    pub code: Option<&'a str>,
    pub error: Option<&'a str>,
    pub state: Option<&'a str>,
    pub ttl_seconds: i64,
    pub signed_response_required: bool,
    pub jarm_available: bool,
    pub session_management_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlainAuthorizationResponse {
    pub redirect_uri: String,
    pub parameters: Vec<(String, String)>,
    pub issue_session_state: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JarmAuthorizationResponse {
    pub redirect_uri: String,
    pub issuer: String,
    pub client_id: String,
    pub code: Option<String>,
    pub error: Option<String>,
    pub state: Option<String>,
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationResponsePlan {
    Plain(PlainAuthorizationResponse),
    Jarm(JarmAuthorizationResponse),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationResponsePolicyError {
    UnsupportedResponseMode,
    MissingClientId,
    Dependency(AuthorizationPortError),
}

impl AuthorizationResponsePolicyError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::UnsupportedResponseMode => "unsupported_response_mode",
            Self::MissingClientId | Self::Dependency(_) => "server_error",
        }
    }
}

pub fn plan_authorization_response(
    input: AuthorizationResponsePolicyInput<'_>,
) -> Result<AuthorizationResponsePlan, AuthorizationResponsePolicyError> {
    let use_jarm = input.response_mode == Some("jwt") || input.signed_response_required;
    if use_jarm && !input.jarm_available {
        return Err(AuthorizationResponsePolicyError::UnsupportedResponseMode);
    }
    if use_jarm {
        if input.client_id.trim().is_empty() {
            return Err(AuthorizationResponsePolicyError::MissingClientId);
        }
        return Ok(AuthorizationResponsePlan::Jarm(JarmAuthorizationResponse {
            redirect_uri: input.redirect_uri.to_owned(),
            issuer: input.issuer.to_owned(),
            client_id: input.client_id.to_owned(),
            code: input.code.map(str::to_owned),
            error: input.error.map(str::to_owned),
            state: input.state.map(str::to_owned),
            ttl_seconds: input.ttl_seconds,
        }));
    }
    let mut parameters = Vec::with_capacity(5);
    for (name, value) in [
        ("code", input.code),
        ("error", input.error),
        ("state", input.state),
    ] {
        if let Some(value) = value {
            parameters.push((name.to_owned(), value.to_owned()));
        }
    }
    parameters.push(("iss".to_owned(), input.issuer.to_owned()));
    Ok(AuthorizationResponsePlan::Plain(
        PlainAuthorizationResponse {
            redirect_uri: input.redirect_uri.to_owned(),
            parameters,
            issue_session_state: input.session_management_available
                && input.code.is_some()
                && input.error.is_none(),
        },
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedJarmAuthorizationResponse {
    pub redirect_uri: String,
    pub response: String,
}

#[must_use]
pub fn plain_authorization_response_uri(
    response: &PlainAuthorizationResponse,
    session_state: Option<&str>,
) -> String {
    let Ok(mut url) = url::Url::parse(&response.redirect_uri) else {
        return response.redirect_uri.clone();
    };
    let issuer = response
        .parameters
        .iter()
        .find(|(name, _)| name == "iss")
        .map(|(_, value)| value.as_str());
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in response.parameters.iter().filter(|(name, _)| name != "iss") {
            query.append_pair(name, value);
        }
        if let Some(session_state) = session_state {
            query.append_pair("session_state", session_state);
        }
        if let Some(issuer) = issuer {
            query.append_pair("iss", issuer);
        }
    }
    url.to_string()
}

#[must_use]
pub fn signed_jarm_authorization_response_uri(
    response: &SignedJarmAuthorizationResponse,
) -> String {
    let Ok(mut url) = url::Url::parse(&response.redirect_uri) else {
        return response.redirect_uri.clone();
    };
    url.query_pairs_mut()
        .append_pair("response", &response.response);
    url.to_string()
}

impl JarmAuthorizationResponse {
    #[must_use]
    pub fn signing_input<'a>(
        &'a self,
        signing_algorithm: Option<&'a str>,
    ) -> AuthorizationResponseSignInput<'a> {
        AuthorizationResponseSignInput {
            issuer: &self.issuer,
            client_id: &self.client_id,
            code: self.code.as_deref(),
            error: self.error.as_deref(),
            state: self.state.as_deref(),
            ttl: self.ttl_seconds,
            signing_algorithm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn client_policy<'a>(
        scopes: &'a [String],
        audiences: &'a [String],
    ) -> AuthorizationClientPolicy<'a> {
        AuthorizationClientPolicy {
            client_type: "confidential",
            allowed_scopes: scopes,
            allowed_audiences: audiences,
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
            allow_authorization_code_without_pkce: true,
        }
    }

    fn capabilities() -> AuthorizationCapabilityPolicy {
        AuthorizationCapabilityPolicy {
            authorization_details: true,
            jarm: true,
            native_sso: true,
        }
    }

    #[test]
    fn authorization_policy_normalizes_oidc_claims_rar_and_jarm() {
        let scopes = vec!["openid".to_owned(), "profile".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let parameters = HashMap::from([
            ("response_type".to_owned(), "code".to_owned()),
            ("response_mode".to_owned(), "jwt".to_owned()),
            ("scope".to_owned(), "openid profile".to_owned()),
            ("resource".to_owned(), "https://api.example".to_owned()),
            ("prompt".to_owned(), "consent".to_owned()),
            ("max_age".to_owned(), "300".to_owned()),
            (
                "claims".to_owned(),
                json!({
                    "userinfo": {"email": {"essential": true}},
                    "id_token": {"acr": {"essential": true, "values": ["1"]}, "auth_time": null}
                })
                .to_string(),
            ),
            (
                "authorization_details".to_owned(),
                json!([{"type": "payment_initiation", "actions": ["initiate"]}]).to_string(),
            ),
        ]);
        let normalized = normalize_authorization_request(
            &parameters,
            client_policy(&scopes, &audiences),
            capabilities(),
            AuthorizationProfilePolicy {
                signed_authorization_response_required: false,
            },
            false,
        )
        .expect("valid request");
        assert_eq!(normalized.response_mode.as_deref(), Some("jwt"));
        assert!(normalized.prompt.consent);
        assert_eq!(normalized.acr.as_deref(), Some(BASELINE_ACR_VALUE));
        assert_eq!(normalized.requested_claims.userinfo[0].name, "email");
        assert!(normalized.requested_claims.auth_time);
        assert_eq!(
            normalized.authorization_details[0]["type"],
            "payment_initiation"
        );
    }

    #[test]
    fn module_and_profile_failures_preserve_protocol_error_categories() {
        let scopes = vec!["openid".to_owned(), "device_sso".to_owned()];
        let audiences = Vec::new();
        let base = HashMap::from([
            ("response_type".to_owned(), "code".to_owned()),
            ("response_mode".to_owned(), "jwt".to_owned()),
            ("scope".to_owned(), "openid device_sso".to_owned()),
        ]);
        assert_eq!(
            normalize_authorization_request(
                &base,
                client_policy(&scopes, &audiences),
                AuthorizationCapabilityPolicy {
                    jarm: false,
                    ..capabilities()
                },
                AuthorizationProfilePolicy {
                    signed_authorization_response_required: false,
                },
                false,
            ),
            Err(AuthorizationPolicyError::UnsupportedResponseMode)
        );
        let mut no_jarm = base;
        no_jarm.remove("response_mode");
        assert_eq!(
            normalize_authorization_request(
                &no_jarm,
                client_policy(&scopes, &audiences),
                AuthorizationCapabilityPolicy {
                    native_sso: false,
                    ..capabilities()
                },
                AuthorizationProfilePolicy {
                    signed_authorization_response_required: false,
                },
                false,
            ),
            Err(AuthorizationPolicyError::InvalidScope)
        );
    }

    #[test]
    fn session_policy_handles_prompt_none_and_reauthentication_without_transport_state() {
        let prompt_none = PromptDirectives {
            none: true,
            ..PromptDirectives::default()
        };
        assert_eq!(
            authorization_session_decision(None, prompt_none, None, None, 1_000),
            AuthorizationSessionDecision::LoginRequired
        );
        assert_eq!(
            authorization_session_decision(
                Some(AuthorizationSession { auth_time: 900 }),
                PromptDirectives::default(),
                Some(50),
                None,
                1_000,
            ),
            AuthorizationSessionDecision::Login {
                fresh_authentication: false
            }
        );
    }

    #[test]
    fn response_plan_keeps_plain_and_jarm_outputs_distinct() {
        let plain = plan_authorization_response(AuthorizationResponsePolicyInput {
            issuer: "https://issuer.example",
            redirect_uri: "https://client.example/cb",
            client_id: "client",
            response_mode: None,
            code: Some("code"),
            error: None,
            state: Some("state"),
            ttl_seconds: 60,
            signed_response_required: false,
            jarm_available: true,
            session_management_available: true,
        })
        .expect("plain response");
        let AuthorizationResponsePlan::Plain(plain) = plain else {
            panic!("expected plain response");
        };
        assert!(plain.issue_session_state);
        assert!(
            plain
                .parameters
                .contains(&("iss".to_owned(), "https://issuer.example".to_owned()))
        );
        let plain_uri = plain_authorization_response_uri(&plain, Some("session-state"));
        let plain_uri = url::Url::parse(&plain_uri).unwrap();
        assert_eq!(
            plain_uri.query_pairs().collect::<Vec<_>>(),
            vec![
                ("code".into(), "code".into()),
                ("state".into(), "state".into()),
                ("session_state".into(), "session-state".into()),
                ("iss".into(), "https://issuer.example".into()),
            ]
        );

        let jarm = plan_authorization_response(AuthorizationResponsePolicyInput {
            response_mode: Some("jwt"),
            ..AuthorizationResponsePolicyInput {
                issuer: "https://issuer.example",
                redirect_uri: "https://client.example/cb",
                client_id: "client",
                response_mode: None,
                code: None,
                error: Some("access_denied"),
                state: Some("state"),
                ttl_seconds: 60,
                signed_response_required: false,
                jarm_available: true,
                session_management_available: true,
            }
        })
        .expect("JARM response");
        let AuthorizationResponsePlan::Jarm(jarm) = jarm else {
            panic!("expected JARM response");
        };
        assert_eq!(jarm.error.as_deref(), Some("access_denied"));
        assert_eq!(
            jarm.signing_input(Some("PS256")).signing_algorithm,
            Some("PS256")
        );
        let signed_uri = signed_jarm_authorization_response_uri(&SignedJarmAuthorizationResponse {
            redirect_uri: jarm.redirect_uri,
            response: "signed.response".to_owned(),
        });
        assert_eq!(
            url::Url::parse(&signed_uri)
                .unwrap()
                .query_pairs()
                .collect::<Vec<_>>(),
            vec![("response".into(), "signed.response".into())]
        );
    }

    #[test]
    fn interaction_and_response_failures_are_typed_and_fail_closed() {
        assert_eq!(
            prompt_none_decision(Ok(true)),
            Ok(PromptNoneDecision::IssueAuthorizationCode)
        );
        assert_eq!(
            prompt_none_decision(Ok(false)),
            Ok(PromptNoneDecision::ConsentRequired)
        );
        assert_eq!(
            prompt_none_decision(Err(AuthorizationPortError::Unavailable)),
            Err(AuthorizationPortError::Unavailable)
        );
        assert_eq!(
            parse_user_authorization_decision("approve"),
            Some(UserAuthorizationDecision::Approve)
        );
        assert_eq!(parse_user_authorization_decision("other"), None);

        for (client_id, jarm_available, expected) in [
            (
                "client",
                false,
                AuthorizationResponsePolicyError::UnsupportedResponseMode,
            ),
            (" ", true, AuthorizationResponsePolicyError::MissingClientId),
        ] {
            assert_eq!(
                plan_authorization_response(AuthorizationResponsePolicyInput {
                    issuer: "https://issuer.example",
                    redirect_uri: "https://client.example/cb",
                    client_id,
                    response_mode: Some("jwt"),
                    code: Some("code"),
                    error: None,
                    state: None,
                    ttl_seconds: 60,
                    signed_response_required: false,
                    jarm_available,
                    session_management_available: false,
                }),
                Err(expected)
            );
        }
    }

    proptest! {
        #[test]
        fn max_age_decision_matches_elapsed_session_age(
            auth_time in 0_i64..1_000_000,
            elapsed in 0_i64..100_000,
            max_age in 0_i64..100_000,
        ) {
            let now = auth_time.saturating_add(elapsed);
            let decision = authorization_session_decision(
                Some(AuthorizationSession { auth_time }),
                PromptDirectives::default(),
                Some(max_age),
                None,
                now,
            );
            let requires_login = max_age == 0 || elapsed > max_age;
            prop_assert_eq!(
                decision,
                if requires_login {
                    AuthorizationSessionDecision::Login { fresh_authentication: false }
                } else {
                    AuthorizationSessionDecision::Continue
                }
            );
        }
    }
}
