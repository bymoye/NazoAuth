use nazo_auth::{
    ClientProfile, GrantType, ProtocolError, ProtocolErrorCode, SecurityProfile,
    SenderConstraintPolicy, validate_token_request_profile,
};
use serde_json::json;

#[test]
fn protocol_errors_serialize_exact_oauth_fields() {
    let error = ProtocolError::new(
        ProtocolErrorCode::UnauthorizedClient,
        "该客户端未启用当前授权类型.",
    );

    assert_eq!(
        serde_json::to_value(error).unwrap(),
        json!({
            "error": "unauthorized_client",
            "error_description": "该客户端未启用当前授权类型."
        })
    );
}

#[test]
fn protocol_error_code_wire_values_are_exhaustive() {
    assert_eq!(
        ProtocolErrorCode::InvalidRequest.as_str(),
        "invalid_request"
    );
    assert_eq!(ProtocolErrorCode::InvalidClient.as_str(), "invalid_client");
    assert_eq!(ProtocolErrorCode::InvalidGrant.as_str(), "invalid_grant");
    assert_eq!(
        ProtocolErrorCode::UnauthorizedClient.as_str(),
        "unauthorized_client"
    );
    assert_eq!(
        ProtocolErrorCode::UnsupportedGrantType.as_str(),
        "unsupported_grant_type"
    );
    assert_eq!(ProtocolErrorCode::InvalidScope.as_str(), "invalid_scope");
    assert_eq!(ProtocolErrorCode::AccessDenied.as_str(), "access_denied");
    assert_eq!(ProtocolErrorCode::ServerError.as_str(), "server_error");
    assert_eq!(
        ProtocolErrorCode::TemporarilyUnavailable.as_str(),
        "temporarily_unavailable"
    );
}

#[test]
fn sender_thumbprints_accept_only_canonical_sha256_evidence() {
    let url_safe = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(nazo_auth::is_valid_dpop_jkt(url_safe));
    assert_eq!(
        nazo_auth::normalize_sha256_thumbprint(
            "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        ),
        Some(url_safe.to_owned())
    );
    assert!(!nazo_auth::is_valid_dpop_jkt("not-a-thumbprint"));
    assert_eq!(
        nazo_auth::normalize_sha256_thumbprint("not-a-thumbprint"),
        None
    );
}

#[test]
fn grant_type_wire_values_are_protocol_stable() {
    assert_eq!(GrantType::AuthorizationCode.as_str(), "authorization_code");
    assert_eq!(GrantType::RefreshToken.as_str(), "refresh_token");
    assert_eq!(GrantType::ClientCredentials.as_str(), "client_credentials");
    assert_eq!(
        GrantType::DeviceCode.as_str(),
        "urn:ietf:params:oauth:grant-type:device_code"
    );
    assert_eq!(
        GrantType::TokenExchange.as_str(),
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(
        GrantType::JwtBearer.as_str(),
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    assert_eq!(
        GrantType::Ciba.as_str(),
        "urn:openid:params:grant-type:ciba"
    );
}

#[test]
fn baseline_profile_accepts_public_bearer_clients() {
    let client = ClientProfile {
        client_type: "public",
        authentication_method: "none",
        sender_constraint: SenderConstraintPolicy::BearerAllowed,
    };

    assert_eq!(
        validate_token_request_profile(SecurityProfile::Baseline, client),
        Ok(())
    );
}

#[test]
fn fapi2_profile_preserves_exact_rejection_codes_and_descriptions() {
    let public_client = ClientProfile {
        client_type: "public",
        authentication_method: "private_key_jwt",
        sender_constraint: SenderConstraintPolicy::DpopRequired,
    };
    assert_eq!(
        validate_token_request_profile(SecurityProfile::Fapi2Security, public_client),
        Err(ProtocolError::new(
            ProtocolErrorCode::UnauthorizedClient,
            "FAPI2 profiles require confidential clients.",
        ))
    );

    let bearer_client = ClientProfile {
        client_type: "confidential",
        authentication_method: "client_secret_basic",
        sender_constraint: SenderConstraintPolicy::BearerAllowed,
    };
    assert_eq!(
        validate_token_request_profile(SecurityProfile::Fapi2MessageSigning, bearer_client),
        Err(ProtocolError::new(
            ProtocolErrorCode::InvalidClient,
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
        ))
    );

    let unconstrained_client = ClientProfile {
        client_type: "confidential",
        authentication_method: "private_key_jwt",
        sender_constraint: SenderConstraintPolicy::BearerAllowed,
    };
    assert_eq!(
        validate_token_request_profile(SecurityProfile::Fapi2Security, unconstrained_client),
        Err(ProtocolError::new(
            ProtocolErrorCode::InvalidRequest,
            "FAPI2 profiles require sender-constrained access tokens.",
        ))
    );
}
