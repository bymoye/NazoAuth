use super::RefreshTokenAuthenticationContext;

#[test]
fn authentication_context_accepts_only_the_current_version() {
    let context = RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: "https://issuer.example".to_owned(),
        audience: "client-1".to_owned(),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid".to_owned()),
        id_token_sid: Some("sid".to_owned()),
        acr: Some("1".to_owned()),
        nonce: Some("nonce".to_owned()),
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["email".to_owned()],
        id_token_claim_requests: Vec::new(),
    };
    assert!(context.is_well_formed());
    let unsupported = RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION + 1,
        ..context
    };
    assert!(!unsupported.is_supported_version());
}
