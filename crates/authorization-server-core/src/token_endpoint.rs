use crate::{
    ClientAuthenticationMethod, ClientProfile, GrantType, ProtocolErrorCode, SecurityProfile,
    SenderConstraintPolicy, validate_token_request_profile,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenEndpointRequestInput {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationCodeTokenRequest {
    pub code: String,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
    pub scope: Option<String>,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCredentialsTokenRequest {
    pub scope: Option<String>,
    pub resources: Vec<String>,
}

/// Typed dispatch target. Extension grants remain explicit without forcing
/// their state machines into the core three-grant request model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenEndpointDispatch {
    AuthorizationCode(AuthorizationCodeTokenRequest),
    RefreshToken(RefreshTokenRequest),
    ClientCredentials(ClientCredentialsTokenRequest),
    Extension(GrantType),
}

impl TokenEndpointDispatch {
    #[must_use]
    pub const fn grant_type(&self) -> GrantType {
        match self {
            Self::AuthorizationCode(_) => GrantType::AuthorizationCode,
            Self::RefreshToken(_) => GrantType::RefreshToken,
            Self::ClientCredentials(_) => GrantType::ClientCredentials,
            Self::Extension(grant_type) => *grant_type,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEndpointError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    InvalidTarget,
    UnauthorizedClient,
    UnsupportedGrantType,
    ServerError,
}

impl TokenEndpointError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ServerError => "server_error",
        }
    }
}

/// Parses the transport-neutral token form into one typed dispatch target.
pub fn token_endpoint_dispatch(
    request: &TokenEndpointRequestInput,
) -> Result<TokenEndpointDispatch, TokenEndpointError> {
    let grant_type = GrantType::try_from(request.grant_type.as_str())
        .map_err(|_| TokenEndpointError::UnsupportedGrantType)?;
    match grant_type {
        GrantType::AuthorizationCode => {
            let code = required_nonempty(request.code.as_deref())
                .ok_or(TokenEndpointError::InvalidGrant)?;
            Ok(TokenEndpointDispatch::AuthorizationCode(
                AuthorizationCodeTokenRequest {
                    code,
                    redirect_uri: request.redirect_uri.clone(),
                    code_verifier: request.code_verifier.clone(),
                    resources: request.resources.clone(),
                },
            ))
        }
        GrantType::RefreshToken => {
            let refresh_token = required_nonempty(request.refresh_token.as_deref())
                .ok_or(TokenEndpointError::InvalidGrant)?;
            Ok(TokenEndpointDispatch::RefreshToken(RefreshTokenRequest {
                refresh_token,
                scope: request.scope.clone(),
                resources: request.resources.clone(),
            }))
        }
        GrantType::ClientCredentials => Ok(TokenEndpointDispatch::ClientCredentials(
            ClientCredentialsTokenRequest {
                scope: request.scope.clone(),
                resources: request.resources.clone(),
            },
        )),
        GrantType::DeviceCode
        | GrantType::TokenExchange
        | GrantType::JwtBearer
        | GrantType::Ciba => Ok(TokenEndpointDispatch::Extension(grant_type)),
    }
}

fn required_nonempty(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(str::to_owned)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenClientAuthPresentation {
    pub http_basic: bool,
    pub form_client_id: bool,
    pub form_client_secret: bool,
    pub client_assertion_type: bool,
    pub client_assertion: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenClientAuthenticationContext {
    pub http_basic: bool,
    pub has_assertion: bool,
    pub has_any_client_auth_material: bool,
}

pub fn token_client_authentication_context(
    presentation: TokenClientAuthPresentation,
) -> Result<TokenClientAuthenticationContext, TokenEndpointError> {
    let has_assertion = presentation.client_assertion_type || presentation.client_assertion;
    if presentation.http_basic
        && (presentation.form_client_id || presentation.form_client_secret || has_assertion)
        || has_assertion && presentation.form_client_secret
    {
        return Err(TokenEndpointError::InvalidRequest);
    }
    Ok(TokenClientAuthenticationContext {
        http_basic: presentation.http_basic,
        has_assertion,
        has_any_client_auth_material: presentation.http_basic
            || presentation.form_client_id
            || presentation.form_client_secret
            || has_assertion,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct TokenClientPolicy<'a> {
    pub active: bool,
    pub client_type: &'a str,
    pub enabled_grants: &'a [String],
    pub authentication_method: &'a str,
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedTokenClient {
    pub grant_type: GrantType,
    pub authentication_method: ClientAuthenticationMethod,
    pub sender_constraint: SenderConstraintPolicy,
}

/// Applies client grant, authentication method, sender-constraint and security
/// profile policy after the authentication adapter has verified credentials.
pub fn admit_token_client(
    grant_type: GrantType,
    profile: SecurityProfile,
    client: TokenClientPolicy<'_>,
) -> Result<AdmittedTokenClient, TokenEndpointError> {
    if !client.active
        || !client
            .enabled_grants
            .iter()
            .any(|enabled| enabled == grant_type.as_str())
    {
        return Err(TokenEndpointError::UnauthorizedClient);
    }
    let authentication_method = ClientAuthenticationMethod::try_from(client.authentication_method)
        .map_err(|_| TokenEndpointError::InvalidClient)?;
    let sender_constraint = sender_constraint_policy(
        client.require_dpop_bound_tokens,
        client.require_mtls_bound_tokens,
    );
    validate_token_request_profile(
        profile,
        ClientProfile {
            client_type: client.client_type,
            authentication_method: client.authentication_method,
            sender_constraint,
        },
    )
    .map_err(|error| match error.code {
        ProtocolErrorCode::UnauthorizedClient => TokenEndpointError::UnauthorizedClient,
        ProtocolErrorCode::InvalidClient => TokenEndpointError::InvalidClient,
        ProtocolErrorCode::InvalidRequest => TokenEndpointError::InvalidRequest,
        _ => TokenEndpointError::ServerError,
    })?;
    Ok(AdmittedTokenClient {
        grant_type,
        authentication_method,
        sender_constraint,
    })
}

#[must_use]
pub const fn sender_constraint_policy(
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
) -> SenderConstraintPolicy {
    match (require_dpop_bound_tokens, require_mtls_bound_tokens) {
        (false, false) => SenderConstraintPolicy::BearerAllowed,
        (true, false) => SenderConstraintPolicy::DpopRequired,
        (false, true) => SenderConstraintPolicy::MtlsRequired,
        (true, true) => SenderConstraintPolicy::DpopOrMtls,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentedSenderConstraint<'a> {
    pub dpop_jkt: Option<&'a str>,
    pub mtls_x5t_s256: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppliedSenderConstraint<'a> {
    Bearer,
    Dpop(&'a str),
    MutualTls(&'a str),
}

pub fn apply_sender_constraint<'a>(
    policy: SenderConstraintPolicy,
    presented: PresentedSenderConstraint<'a>,
) -> Result<AppliedSenderConstraint<'a>, TokenEndpointError> {
    let constraint = match (presented.dpop_jkt, presented.mtls_x5t_s256) {
        (Some(_), Some(_)) => return Err(TokenEndpointError::InvalidRequest),
        (Some(thumbprint), None) => AppliedSenderConstraint::Dpop(thumbprint),
        (None, Some(thumbprint)) => AppliedSenderConstraint::MutualTls(thumbprint),
        (None, None) => AppliedSenderConstraint::Bearer,
    };
    let allowed = matches!(
        (policy, constraint),
        (SenderConstraintPolicy::BearerAllowed, _)
            | (
                SenderConstraintPolicy::DpopRequired,
                AppliedSenderConstraint::Dpop(_)
            )
            | (
                SenderConstraintPolicy::MtlsRequired,
                AppliedSenderConstraint::MutualTls(_)
            )
            | (
                SenderConstraintPolicy::DpopOrMtls,
                AppliedSenderConstraint::Dpop(_) | AppliedSenderConstraint::MutualTls(_)
            )
    );
    allowed
        .then_some(constraint)
        .ok_or(TokenEndpointError::InvalidRequest)
}

#[cfg(test)]
#[path = "../tests/unit/token_endpoint.rs"]
mod tests;
