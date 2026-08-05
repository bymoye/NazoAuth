use super::*;

#[test]
fn legacy_message_signing_profiles_map_to_independent_policy_bits() {
    let request =
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest.legacy_client_policy();
    let response = AuthorizationServerProfile::Fapi2MessageSigningJarm.legacy_client_policy();
    let introspection =
        AuthorizationServerProfile::Fapi2MessageSigningIntrospection.legacy_client_policy();

    assert!(request.requires_fapi2_security());
    assert!(request.require_signed_authorization_request);
    assert!(!request.require_signed_authorization_response);
    assert!(!request.require_signed_introspection_response);

    assert!(response.requires_fapi2_security());
    assert!(!response.require_signed_authorization_request);
    assert!(response.require_signed_authorization_response);
    assert!(!response.require_signed_introspection_response);

    assert!(introspection.requires_fapi2_security());
    assert!(!introspection.require_signed_authorization_request);
    assert!(!introspection.require_signed_authorization_response);
    assert!(introspection.require_signed_introspection_response);
    assert!(
        !AuthorizationServerProfile::Oauth2Baseline
            .legacy_client_policy()
            .allow_confidential_oidc_without_pkce
    );
}

#[test]
fn explicit_client_policy_overrides_the_legacy_profile() {
    let explicit = ClientSecurityPolicy {
        require_signed_authorization_request: true,
        require_signed_authorization_response: true,
        require_signed_introspection_response: true,
        session_management: true,
        allow_cross_device_flows: true,
        ..ClientSecurityPolicy::fapi2()
    };

    assert_eq!(
        AuthorizationServerProfile::Oauth2Baseline.effective_security_policy(Some(&explicit)),
        explicit
    );
}
