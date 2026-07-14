use super::*;

#[test]
fn signing_adapters_do_not_define_or_call_claim_forwarders() {
    let server_tokens =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/adapters/security/tokens.rs");
    let source = std::fs::read_to_string(&server_tokens)
        .expect("server token adapter source must exist relative to its manifest");
    let oidc_logout =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain/oidc_logout.rs");
    let oidc_logout_source = std::fs::read_to_string(&oidc_logout)
        .expect("OIDC logout domain service must exist relative to the server manifest");
    let key_management_tokens =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../key-management/src/token.rs");
    let key_management_source = std::fs::read_to_string(&key_management_tokens)
        .expect("key-management token adapter source must exist relative to the server manifest");
    let key_management_authorization_response = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../key-management/src/authorization_response.rs");
    let key_management_authorization_response_source = std::fs::read_to_string(
        &key_management_authorization_response,
    )
    .expect(
        "key-management authorization-response adapter must exist relative to the server manifest",
    );

    for forbidden in [
        "pub(super) fn access_token_claims(",
        "pub(super) fn id_token_claims(",
        "pub(super) fn backchannel_logout_token_claims(",
        "pub(super) fn authorization_response_jwt_claims(",
        "let claims = access_token_claims(",
        "let claims = id_token_claims(",
        "let claims = backchannel_logout_token_claims(",
        "let claims = authorization_response_jwt_claims(",
    ] {
        assert!(
            !source.contains(forbidden),
            "server claim forwarding boundary remains: {forbidden}"
        );
    }

    assert!(
        source.contains("nazo_auth::access_token_claims("),
        "signing adapter must call the public auth access-token builder directly"
    );
    assert!(
        oidc_logout_source.contains("nazo_auth::backchannel_logout_token_claims("),
        "OIDC logout domain service must call the public auth claim builder directly"
    );
    assert!(
        key_management_source.contains("id_token_claims("),
        "key-management token adapter must call the imported public auth ID-token builder directly"
    );
    assert!(
        key_management_authorization_response_source.contains("authorization_response_jwt_claims("),
        "key-management authorization-response adapter must call the imported public auth builder directly"
    );
}

#[test]
fn access_token_header_uses_active_alg_kid_and_at_jwt_type() {
    let header = access_token_header(jsonwebtoken::Algorithm::PS256, "active-kid");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.kid.as_deref(), Some("active-kid"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
}

#[test]
fn access_token_rejects_conflicting_sender_constraints() {
    assert!(validate_access_token_sender_constraint(Some("jkt"), Some("x5t")).is_err());
}

#[tokio::test]
async fn make_jwt_rejects_conflicting_sender_constraints_before_signing() {
    let settings = test_settings();
    let keyset = crate::test_support::test_key_manager();
    let audiences = vec!["resource://default".to_owned()];
    let scopes = vec!["read".to_owned()];
    let authorization_details = json!([]);

    let result = make_jwt(
        &keyset,
        &settings.endpoint.issuer,
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "subject-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: Some("jkt"),
            mtls_x5t_s256: Some("x5t"),
            actor: None,
        },
    )
    .await;

    let error = match result {
        Ok(_) => panic!("conflicting sender constraints must fail before signing"),
        Err(error) => error,
    };
    assert!(matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidToken
    ));
}

#[tokio::test]
async fn response_signing_uses_auxiliary_key_from_current_keyset_snapshot() {
    let auxiliary = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let _public_jwk = auxiliary.public_jwk("auxiliary-rs256");
    let keyset =
        crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::RS256);

    let token = sign_response_jwt(
        &keyset,
        nazo_auth::SigningPurpose::IdToken,
        &json!({"sub": "subject-1"}),
        "JWT",
        Some(jsonwebtoken::Algorithm::RS256),
    )
    .await
    .expect("response signing should use the key material loaded in the snapshot");
    let header = jsonwebtoken::decode_header(&token).expect("signed response header should decode");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some("test-aux-RS256"));
}
