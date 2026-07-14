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
    pub has_legacy_audience_parameter: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenEndpointPolicy {
    pub legacy_audience_parameter_enabled: bool,
}

/// Parses the transport-neutral token form into one typed dispatch target.
pub fn token_endpoint_dispatch(
    request: &TokenEndpointRequestInput,
    policy: TokenEndpointPolicy,
) -> Result<TokenEndpointDispatch, TokenEndpointError> {
    let grant_type = GrantType::try_from(request.grant_type.as_str())
        .map_err(|_| TokenEndpointError::UnsupportedGrantType)?;
    if request.has_legacy_audience_parameter
        && grant_type != GrantType::TokenExchange
        && !policy.legacy_audience_parameter_enabled
    {
        return Err(TokenEndpointError::InvalidRequest);
    }
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
mod tests {
    use super::*;

    fn request(grant_type: &str) -> TokenEndpointRequestInput {
        TokenEndpointRequestInput {
            grant_type: grant_type.to_owned(),
            ..TokenEndpointRequestInput::default()
        }
    }

    #[test]
    fn core_grants_dispatch_to_distinct_typed_requests() {
        let mut authorization_code = request("authorization_code");
        authorization_code.code = Some("code".to_owned());
        assert!(matches!(
            token_endpoint_dispatch(
                &authorization_code,
                TokenEndpointPolicy {
                    legacy_audience_parameter_enabled: false
                }
            ),
            Ok(TokenEndpointDispatch::AuthorizationCode(_))
        ));

        let mut refresh = request("refresh_token");
        refresh.refresh_token = Some("refresh".to_owned());
        assert!(matches!(
            token_endpoint_dispatch(
                &refresh,
                TokenEndpointPolicy {
                    legacy_audience_parameter_enabled: false
                }
            ),
            Ok(TokenEndpointDispatch::RefreshToken(_))
        ));
        assert!(matches!(
            token_endpoint_dispatch(
                &request("client_credentials"),
                TokenEndpointPolicy {
                    legacy_audience_parameter_enabled: false
                }
            ),
            Ok(TokenEndpointDispatch::ClientCredentials(_))
        ));
    }

    #[test]
    fn every_extension_grant_is_exhaustively_classified_without_parsing_its_state_machine() {
        for grant_type in [
            GrantType::DeviceCode,
            GrantType::TokenExchange,
            GrantType::JwtBearer,
            GrantType::Ciba,
        ] {
            assert_eq!(
                token_endpoint_dispatch(
                    &request(grant_type.as_str()),
                    TokenEndpointPolicy {
                        legacy_audience_parameter_enabled: false
                    }
                ),
                Ok(TokenEndpointDispatch::Extension(grant_type))
            );
        }
        assert_eq!(
            token_endpoint_dispatch(
                &request("password"),
                TokenEndpointPolicy {
                    legacy_audience_parameter_enabled: false
                }
            ),
            Err(TokenEndpointError::UnsupportedGrantType)
        );
    }

    #[test]
    fn required_grant_material_and_legacy_audience_policy_fail_closed() {
        assert_eq!(
            token_endpoint_dispatch(
                &request("authorization_code"),
                TokenEndpointPolicy {
                    legacy_audience_parameter_enabled: false
                }
            ),
            Err(TokenEndpointError::InvalidGrant)
        );
        let mut client_credentials = request("client_credentials");
        client_credentials.has_legacy_audience_parameter = true;
        assert_eq!(
            token_endpoint_dispatch(
                &client_credentials,
                TokenEndpointPolicy {
                    legacy_audience_parameter_enabled: false
                }
            ),
            Err(TokenEndpointError::InvalidRequest)
        );
    }

    #[test]
    fn conflicting_client_authentication_material_is_rejected_before_crypto() {
        let conflicting = TokenClientAuthPresentation {
            http_basic: true,
            form_client_id: true,
            form_client_secret: false,
            client_assertion_type: false,
            client_assertion: false,
        };
        assert_eq!(
            token_client_authentication_context(conflicting),
            Err(TokenEndpointError::InvalidRequest)
        );
        let context = token_client_authentication_context(TokenClientAuthPresentation {
            http_basic: false,
            form_client_id: true,
            form_client_secret: false,
            client_assertion_type: true,
            client_assertion: true,
        })
        .expect("single assertion method");
        assert!(context.has_assertion);
        assert!(context.has_any_client_auth_material);
    }

    #[test]
    fn client_grant_profile_and_sender_constraint_are_admitted_together() {
        let grants = vec!["authorization_code".to_owned()];
        let admitted = admit_token_client(
            GrantType::AuthorizationCode,
            SecurityProfile::Fapi2Security,
            TokenClientPolicy {
                active: true,
                client_type: "confidential",
                enabled_grants: &grants,
                authentication_method: "private_key_jwt",
                require_dpop_bound_tokens: true,
                require_mtls_bound_tokens: false,
            },
        )
        .expect("FAPI client");
        assert_eq!(
            admitted.sender_constraint,
            SenderConstraintPolicy::DpopRequired
        );
        assert_eq!(
            apply_sender_constraint(
                admitted.sender_constraint,
                PresentedSenderConstraint {
                    dpop_jkt: Some("thumbprint"),
                    mtls_x5t_s256: None,
                }
            ),
            Ok(AppliedSenderConstraint::Dpop("thumbprint"))
        );
    }

    #[test]
    fn sender_constraint_matrix_rejects_missing_mismatched_and_dual_bindings() {
        for (policy, presented) in [
            (
                SenderConstraintPolicy::DpopRequired,
                PresentedSenderConstraint {
                    dpop_jkt: None,
                    mtls_x5t_s256: None,
                },
            ),
            (
                SenderConstraintPolicy::MtlsRequired,
                PresentedSenderConstraint {
                    dpop_jkt: Some("dpop"),
                    mtls_x5t_s256: None,
                },
            ),
            (
                SenderConstraintPolicy::DpopOrMtls,
                PresentedSenderConstraint {
                    dpop_jkt: Some("dpop"),
                    mtls_x5t_s256: Some("mtls"),
                },
            ),
        ] {
            assert_eq!(
                apply_sender_constraint(policy, presented),
                Err(TokenEndpointError::InvalidRequest)
            );
        }
    }
}
