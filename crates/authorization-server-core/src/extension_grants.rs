use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppliedSenderConstraint, AuthorizationPortError, Claims, PresentedSenderConstraint,
    apply_sender_constraint, is_subset, parse_scope, sender_constraint_policy,
};

pub const JWT_BEARER_ASSERTION_MAX_TTL_SECONDS: i64 = 300;
pub const JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 30;
pub const JWT_BEARER_ASSERTION_MAX_JTI_BYTES: usize = 128;
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Claims produced only after a transport/crypto adapter has verified the JWT
/// signature and algorithm against the registered client key set.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct JwtBearerAssertionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedJwtBearerAssertion {
    pub subject: String,
    pub jti: String,
    pub replay_ttl_seconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct JwtBearerGrantPolicy<'a> {
    pub enabled: bool,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub client_is_confidential: bool,
    pub allowed_scopes: &'a [String],
    pub allowed_audiences: &'a [String],
    pub default_audience: &'a str,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtBearerGrantAdmission {
    pub assertion: String,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtBearerGrantError {
    Disabled,
    UnauthorizedClient,
    MissingAssertion,
    InvalidAssertion,
    ReplayDetected,
    InvalidScope,
    InvalidTarget,
    Dependency(AuthorizationPortError),
}

impl JwtBearerGrantError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::Disabled => "unsupported_grant_type",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::MissingAssertion => "invalid_request",
            Self::InvalidAssertion | Self::ReplayDetected => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::Dependency(_) => "server_error",
        }
    }
}

pub fn admit_jwt_bearer_grant(
    assertion: Option<&str>,
    requested_scope: Option<&str>,
    requested_audiences: &[String],
    policy: JwtBearerGrantPolicy<'_>,
) -> Result<JwtBearerGrantAdmission, JwtBearerGrantError> {
    validate_jwt_bearer_grant_prerequisites(assertion, policy)?;
    let assertion = assertion.expect("validated JWT bearer assertion must be present");
    let requested_scopes = parse_scope(requested_scope.unwrap_or(""));
    if !requested_scopes.is_empty() && !is_subset(&requested_scopes, policy.allowed_scopes) {
        return Err(JwtBearerGrantError::InvalidScope);
    }
    let scopes = if requested_scopes.is_empty() {
        policy.allowed_scopes.to_vec()
    } else {
        requested_scopes
    };
    if scopes.iter().any(|scope| scope == "openid") {
        return Err(JwtBearerGrantError::InvalidScope);
    }
    let audiences = if requested_audiences.is_empty() {
        vec![policy.default_audience.to_owned()]
    } else {
        requested_audiences.to_vec()
    };
    if audiences.is_empty() || !is_subset(&audiences, policy.allowed_audiences) {
        return Err(JwtBearerGrantError::InvalidTarget);
    }
    Ok(JwtBearerGrantAdmission {
        assertion: assertion.to_owned(),
        scopes,
        audiences,
    })
}

/// Checks only the grant-level prerequisites that precede transport security
/// processing. Scope and target policy remains in [`admit_jwt_bearer_grant`].
pub fn validate_jwt_bearer_grant_prerequisites(
    assertion: Option<&str>,
    policy: JwtBearerGrantPolicy<'_>,
) -> Result<(), JwtBearerGrantError> {
    if !policy.enabled {
        return Err(JwtBearerGrantError::Disabled);
    }
    if !policy.client_is_confidential {
        return Err(JwtBearerGrantError::UnauthorizedClient);
    }
    assertion.ok_or(JwtBearerGrantError::MissingAssertion)?;
    Ok(())
}

pub fn validate_jwt_bearer_assertion_claims(
    claims: JwtBearerAssertionClaims,
    policy: JwtBearerGrantPolicy<'_>,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerGrantError> {
    if claims.iss != policy.client_id
        || claims.sub != policy.client_id
        || claims.aud.as_str() != Some(policy.issuer)
        || claims.exp <= policy.now
        || claims.exp
            > policy
                .now
                .saturating_add(JWT_BEARER_ASSERTION_MAX_TTL_SECONDS)
        || claims.nbf.is_some_and(|not_before| {
            not_before
                > policy
                    .now
                    .saturating_add(JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS)
        })
        || claims.iat.is_some_and(|issued_at| {
            issued_at
                > policy
                    .now
                    .saturating_add(JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS)
                || policy.now.saturating_sub(issued_at) > JWT_BEARER_ASSERTION_MAX_TTL_SECONDS
        })
    {
        return Err(JwtBearerGrantError::InvalidAssertion);
    }
    let jti = claims.jti.trim();
    if jti.is_empty() || jti.len() > JWT_BEARER_ASSERTION_MAX_JTI_BYTES {
        return Err(JwtBearerGrantError::InvalidAssertion);
    }
    Ok(ValidatedJwtBearerAssertion {
        subject: claims.sub,
        jti: claims.jti,
        replay_ttl_seconds: claims
            .exp
            .saturating_sub(policy.now)
            .clamp(1, JWT_BEARER_ASSERTION_MAX_TTL_SECONDS) as u64,
    })
}

pub(crate) fn classify_jwt_bearer_replay(
    result: Result<bool, AuthorizationPortError>,
) -> Result<(), JwtBearerGrantError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(JwtBearerGrantError::ReplayDetected),
        Err(error) => Err(JwtBearerGrantError::Dependency(error)),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenExchangeRequestInput {
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub scope: Option<String>,
    pub audiences: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct TokenExchangePolicy<'a> {
    pub enabled: bool,
    pub client_id: &'a str,
    pub client_is_confidential: bool,
    pub client_tenant_id: Uuid,
    pub allowed_scopes: &'a [String],
    pub allowed_audiences: &'a [String],
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenExchangeAdmission {
    pub subject_token: String,
    pub actor_token: Option<String>,
    pub requested_scope: Option<String>,
    pub audiences: Vec<String>,
    pub issued_token_type: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenExchangeError {
    Disabled,
    UnauthorizedClient,
    MissingParameter,
    UnsupportedTokenType,
    InvalidScope,
    InvalidTarget,
    InvalidGrant,
}

impl TokenExchangeError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::Disabled => "unsupported_grant_type",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::MissingParameter | Self::UnsupportedTokenType => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidGrant => "invalid_grant",
        }
    }
}

pub fn admit_token_exchange(
    request: &TokenExchangeRequestInput,
    policy: TokenExchangePolicy<'_>,
) -> Result<TokenExchangeAdmission, TokenExchangeError> {
    validate_token_exchange_grant_prerequisites(request, policy)?;
    let subject_token = request
        .subject_token
        .as_ref()
        .expect("validated token exchange request must contain subject_token");
    validate_token_exchange_requested_scope(policy.allowed_scopes, request.scope.as_deref())?;
    if request.audiences.is_empty() || !is_subset(&request.audiences, policy.allowed_audiences) {
        return Err(TokenExchangeError::InvalidTarget);
    }
    Ok(TokenExchangeAdmission {
        subject_token: subject_token.clone(),
        actor_token: request.actor_token.clone(),
        requested_scope: request.scope.clone(),
        audiences: request.audiences.clone(),
        issued_token_type: ACCESS_TOKEN_TYPE.to_owned(),
    })
}

/// Checks module, client, and token-type prerequisites before a transport
/// adapter consumes a client assertion or reads token state.
pub fn validate_token_exchange_grant_prerequisites(
    request: &TokenExchangeRequestInput,
    policy: TokenExchangePolicy<'_>,
) -> Result<(), TokenExchangeError> {
    if !policy.enabled {
        return Err(TokenExchangeError::Disabled);
    }
    if !policy.client_is_confidential {
        return Err(TokenExchangeError::UnauthorizedClient);
    }
    request
        .subject_token
        .as_ref()
        .ok_or(TokenExchangeError::MissingParameter)?;
    match request.subject_token_type.as_deref() {
        Some(ACCESS_TOKEN_TYPE) => {}
        Some(_) => return Err(TokenExchangeError::UnsupportedTokenType),
        None => return Err(TokenExchangeError::MissingParameter),
    }
    match (
        request.actor_token.as_ref(),
        request.actor_token_type.as_deref(),
    ) {
        (None, None) => {}
        (None, Some(_)) | (Some(_), None) => return Err(TokenExchangeError::MissingParameter),
        (Some(_), Some(ACCESS_TOKEN_TYPE)) => {}
        (Some(_), Some(_)) => return Err(TokenExchangeError::UnsupportedTokenType),
    }
    if request
        .requested_token_type
        .as_deref()
        .is_some_and(|token_type| token_type != ACCESS_TOKEN_TYPE)
    {
        return Err(TokenExchangeError::UnsupportedTokenType);
    }
    Ok(())
}

fn validate_token_exchange_requested_scope(
    client_scopes: &[String],
    requested_scope: Option<&str>,
) -> Result<(), TokenExchangeError> {
    let requested = parse_scope(requested_scope.unwrap_or(""));
    if requested.iter().any(|scope| scope == "openid")
        || !requested.is_empty() && !is_subset(&requested, client_scopes)
    {
        return Err(TokenExchangeError::InvalidScope);
    }
    Ok(())
}

/// Resolves authoritative issuance scopes after the subject token has been
/// cryptographically verified and checked for revocation.
pub fn token_exchange_scopes(
    client_scopes: &[String],
    subject_scope: &str,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, TokenExchangeError> {
    let subject_scopes = parse_scope(subject_scope);
    let requested = parse_scope(requested_scope.unwrap_or(""));
    let scopes = if requested.is_empty() {
        subject_scopes
            .iter()
            .filter(|scope| *scope != "openid" && client_scopes.contains(scope))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        if requested.iter().any(|scope| scope == "openid")
            || !is_subset(&requested, &subject_scopes)
            || !is_subset(&requested, client_scopes)
        {
            return Err(TokenExchangeError::InvalidScope);
        }
        requested
    };
    if scopes.is_empty() {
        return Err(TokenExchangeError::InvalidScope);
    }
    Ok(scopes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenExchangeSenderBinding {
    Bearer,
    Dpop(String),
    MutualTls(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTokenExchangeSubject {
    pub subject: String,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub sender_binding: TokenExchangeSenderBinding,
}

pub fn validate_token_exchange_access_token(
    claims: &Claims,
    policy: TokenExchangePolicy<'_>,
) -> Result<(), TokenExchangeError> {
    if claims.tenant_id.parse::<Uuid>().ok() != Some(policy.client_tenant_id)
        || claims.token_use != "access"
        || claims.exp <= policy.now
    {
        return Err(TokenExchangeError::InvalidGrant);
    }
    Ok(())
}

pub fn validate_token_exchange_subject(
    claims: &Claims,
    requested_scope: Option<&str>,
    policy: TokenExchangePolicy<'_>,
) -> Result<ValidatedTokenExchangeSubject, TokenExchangeError> {
    validate_token_exchange_access_token(claims, policy)?;
    if claims.client_id != policy.client_id {
        return Err(TokenExchangeError::InvalidGrant);
    }
    let user_id = claims
        .user_id
        .as_deref()
        .map(str::parse::<Uuid>)
        .transpose()
        .map_err(|_| TokenExchangeError::InvalidGrant)?;
    let scopes = token_exchange_scopes(policy.allowed_scopes, &claims.scope, requested_scope)?;
    let sender_binding = match claims.cnf.as_ref() {
        None => TokenExchangeSenderBinding::Bearer,
        Some(confirmation) => match (confirmation.jkt.as_ref(), confirmation.x5t_s256.as_ref()) {
            (Some(jkt), None) => TokenExchangeSenderBinding::Dpop(jkt.clone()),
            (None, Some(thumbprint)) => TokenExchangeSenderBinding::MutualTls(thumbprint.clone()),
            _ => return Err(TokenExchangeError::InvalidGrant),
        },
    };
    Ok(ValidatedTokenExchangeSubject {
        subject: claims.sub.clone(),
        user_id,
        scopes,
        sender_binding,
    })
}

pub fn token_exchange_issuance_binding(
    subject_binding: &TokenExchangeSenderBinding,
    presented: PresentedSenderConstraint<'_>,
    policy: TokenExchangePolicy<'_>,
) -> Result<TokenExchangeSenderBinding, TokenExchangeError> {
    let sender_policy = sender_constraint_policy(
        policy.require_dpop_bound_tokens,
        policy.require_mtls_bound_tokens,
    );
    match subject_binding {
        TokenExchangeSenderBinding::Dpop(expected)
            if presented.dpop_jkt != Some(expected.as_str())
                || presented.mtls_x5t_s256.is_some() =>
        {
            return Err(TokenExchangeError::InvalidGrant);
        }
        TokenExchangeSenderBinding::MutualTls(expected)
            if presented.mtls_x5t_s256 != Some(expected.as_str())
                || presented.dpop_jkt.is_some() =>
        {
            return Err(TokenExchangeError::InvalidGrant);
        }
        _ => {}
    }
    let applied = apply_sender_constraint(sender_policy, presented)
        .map_err(|_| TokenExchangeError::InvalidGrant)?;
    Ok(match applied {
        AppliedSenderConstraint::Bearer => TokenExchangeSenderBinding::Bearer,
        AppliedSenderConstraint::Dpop(jkt) => TokenExchangeSenderBinding::Dpop(jkt.to_owned()),
        AppliedSenderConstraint::MutualTls(thumbprint) => {
            TokenExchangeSenderBinding::MutualTls(thumbprint.to_owned())
        }
    })
}

pub fn token_exchange_actor_claim(
    actor: &Claims,
    policy: TokenExchangePolicy<'_>,
) -> Result<Value, TokenExchangeError> {
    validate_token_exchange_access_token(actor, policy)?;
    if actor.client_id != policy.client_id || actor.cnf.is_some() {
        return Err(TokenExchangeError::InvalidGrant);
    }
    let mut claim = json!({
        "sub": actor.sub,
        "client_id": actor.client_id,
    });
    if let Some(previous_actor) = actor.act.as_ref() {
        claim["act"] = previous_actor.clone();
    }
    Ok(claim)
}

#[cfg(test)]
#[path = "../tests/unit/extension_grants.rs"]
mod tests;
