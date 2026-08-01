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
        token_endpoint_dispatch(&authorization_code),
        Ok(TokenEndpointDispatch::AuthorizationCode(_))
    ));

    let mut refresh = request("refresh_token");
    refresh.refresh_token = Some("refresh".to_owned());
    assert!(matches!(
        token_endpoint_dispatch(&refresh),
        Ok(TokenEndpointDispatch::RefreshToken(_))
    ));
    assert!(matches!(
        token_endpoint_dispatch(&request("client_credentials")),
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
            token_endpoint_dispatch(&request(grant_type.as_str())),
            Ok(TokenEndpointDispatch::Extension(grant_type))
        );
    }
    assert_eq!(
        token_endpoint_dispatch(&request("password")),
        Err(TokenEndpointError::UnsupportedGrantType)
    );
}

#[test]
fn required_grant_material_fails_closed() {
    assert_eq!(
        token_endpoint_dispatch(&request("authorization_code")),
        Err(TokenEndpointError::InvalidGrant)
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
