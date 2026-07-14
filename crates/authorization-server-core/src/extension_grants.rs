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
    let applied = match subject_binding {
        TokenExchangeSenderBinding::Dpop(jkt) => apply_sender_constraint(
            sender_policy,
            PresentedSenderConstraint {
                dpop_jkt: Some(jkt),
                mtls_x5t_s256: None,
            },
        ),
        TokenExchangeSenderBinding::MutualTls(thumbprint) => apply_sender_constraint(
            sender_policy,
            PresentedSenderConstraint {
                dpop_jkt: None,
                mtls_x5t_s256: Some(thumbprint),
            },
        ),
        TokenExchangeSenderBinding::Bearer => apply_sender_constraint(sender_policy, presented),
    }
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
mod tests {
    use super::*;
    use crate::ConfirmationClaims;

    fn jwt_policy<'a>(scopes: &'a [String], audiences: &'a [String]) -> JwtBearerGrantPolicy<'a> {
        JwtBearerGrantPolicy {
            enabled: true,
            issuer: "https://issuer.example",
            client_id: "client",
            client_is_confidential: true,
            allowed_scopes: scopes,
            allowed_audiences: audiences,
            default_audience: "https://api.example",
            now: 1_700_000_000,
        }
    }

    fn exchange_policy<'a>(
        scopes: &'a [String],
        audiences: &'a [String],
        tenant_id: Uuid,
    ) -> TokenExchangePolicy<'a> {
        TokenExchangePolicy {
            enabled: true,
            client_id: "client",
            client_is_confidential: true,
            client_tenant_id: tenant_id,
            allowed_scopes: scopes,
            allowed_audiences: audiences,
            require_dpop_bound_tokens: true,
            require_mtls_bound_tokens: false,
            now: 1_700_000_000,
        }
    }

    fn access_claims(tenant_id: Uuid) -> Claims {
        Claims {
            iss: "https://issuer.example".to_owned(),
            sub: "subject".to_owned(),
            tenant_id: tenant_id.to_string(),
            user_id: Some(Uuid::nil().to_string()),
            subject_type: "public".to_owned(),
            aud: json!("https://api.example"),
            client_id: "client".to_owned(),
            scope: "openid read write".to_owned(),
            authorization_details: json!([]),
            token_use: "access".to_owned(),
            jti: "jti".to_owned(),
            iat: 1_699_999_900,
            nbf: 1_699_999_900,
            exp: 1_700_000_100,
            cnf: None,
            act: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
        }
    }

    #[test]
    fn jwt_bearer_claims_require_exact_party_audience_time_and_replay_values() {
        let scopes = vec!["read".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let policy = jwt_policy(&scopes, &audiences);
        let assertion = validate_jwt_bearer_assertion_claims(
            JwtBearerAssertionClaims {
                iss: "client".to_owned(),
                sub: "client".to_owned(),
                aud: json!("https://issuer.example"),
                exp: policy.now + 120,
                nbf: Some(policy.now),
                iat: Some(policy.now),
                jti: "unique".to_owned(),
            },
            policy,
        )
        .expect("valid assertion");
        assert_eq!(assertion.replay_ttl_seconds, 120);
        assert_eq!(
            classify_jwt_bearer_replay(Ok(false)),
            Err(JwtBearerGrantError::ReplayDetected)
        );
        assert_eq!(
            classify_jwt_bearer_replay(Err(AuthorizationPortError::Unavailable)),
            Err(JwtBearerGrantError::Dependency(
                AuthorizationPortError::Unavailable
            ))
        );
    }

    #[test]
    fn empty_but_present_grant_tokens_reach_crypto_validation() {
        let scopes = vec!["read".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let jwt = admit_jwt_bearer_grant(
            Some(""),
            Some("read"),
            &audiences,
            jwt_policy(&scopes, &audiences),
        )
        .expect("an empty assertion is present but will fail signature validation");
        assert!(jwt.assertion.is_empty());

        let tenant_id = Uuid::nil();
        let exchange = admit_token_exchange(
            &TokenExchangeRequestInput {
                subject_token: Some(String::new()),
                subject_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
                audiences: audiences.clone(),
                ..TokenExchangeRequestInput::default()
            },
            exchange_policy(&scopes, &audiences, tenant_id),
        )
        .expect("an empty subject token is present but will fail token validation");
        assert!(exchange.subject_token.is_empty());
    }

    #[test]
    fn token_exchange_type_scope_and_target_policy_is_explicit() {
        let scopes = vec!["read".to_owned(), "write".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let tenant_id = Uuid::now_v7();
        let request = TokenExchangeRequestInput {
            subject_token: Some("subject-token".to_owned()),
            subject_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: Some(ACCESS_TOKEN_TYPE.to_owned()),
            scope: Some("read".to_owned()),
            audiences: audiences.clone(),
        };
        let admitted =
            admit_token_exchange(&request, exchange_policy(&scopes, &audiences, tenant_id))
                .expect("valid exchange request");
        assert_eq!(admitted.requested_scope.as_deref(), Some("read"));

        let mut unsupported = request;
        unsupported.requested_token_type = Some("urn:example:unknown".to_owned());
        assert_eq!(
            admit_token_exchange(
                &unsupported,
                exchange_policy(&scopes, &audiences, tenant_id)
            ),
            Err(TokenExchangeError::UnsupportedTokenType)
        );
    }

    #[test]
    fn verified_subject_limits_scope_and_preserves_sender_binding() {
        let scopes = vec!["read".to_owned(), "write".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let tenant_id = Uuid::now_v7();
        let policy = exchange_policy(&scopes, &audiences, tenant_id);
        let mut claims = access_claims(tenant_id);
        claims.cnf = Some(ConfirmationClaims {
            jkt: Some("subject-jkt".to_owned()),
            x5t_s256: None,
        });
        let subject =
            validate_token_exchange_subject(&claims, Some("read"), policy).expect("valid subject");
        assert_eq!(subject.scopes, ["read"]);
        assert_eq!(
            token_exchange_issuance_binding(
                &subject.sender_binding,
                PresentedSenderConstraint {
                    dpop_jkt: None,
                    mtls_x5t_s256: None,
                },
                policy,
            ),
            Ok(TokenExchangeSenderBinding::Dpop("subject-jkt".to_owned()))
        );
    }

    #[test]
    fn dual_subject_binding_and_sender_binding_conversion_fail_closed() {
        let scopes = vec!["read".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let tenant_id = Uuid::now_v7();
        let dpop_policy = exchange_policy(&scopes, &audiences, tenant_id);
        let mut claims = access_claims(tenant_id);
        claims.cnf = Some(ConfirmationClaims {
            jkt: Some("dpop".to_owned()),
            x5t_s256: Some("mtls".to_owned()),
        });
        assert_eq!(
            validate_token_exchange_subject(&claims, Some("read"), dpop_policy),
            Err(TokenExchangeError::InvalidGrant)
        );
        assert_eq!(
            token_exchange_issuance_binding(
                &TokenExchangeSenderBinding::MutualTls("mtls".to_owned()),
                PresentedSenderConstraint {
                    dpop_jkt: None,
                    mtls_x5t_s256: None,
                },
                dpop_policy,
            ),
            Err(TokenExchangeError::InvalidGrant)
        );
    }

    #[test]
    fn actor_claim_requires_same_client_and_rejects_sender_constraint() {
        let scopes = vec!["read".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let tenant_id = Uuid::now_v7();
        let policy = exchange_policy(&scopes, &audiences, tenant_id);
        let mut actor = access_claims(tenant_id);
        actor.act = Some(json!({"sub": "previous"}));
        let claim = token_exchange_actor_claim(&actor, policy).expect("valid actor");
        assert_eq!(claim["act"]["sub"], "previous");
        actor.cnf = Some(ConfirmationClaims {
            jkt: Some("jkt".to_owned()),
            x5t_s256: None,
        });
        assert_eq!(
            token_exchange_actor_claim(&actor, policy),
            Err(TokenExchangeError::InvalidGrant)
        );
    }
}
