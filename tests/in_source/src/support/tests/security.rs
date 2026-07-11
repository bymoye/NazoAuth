use super::tokens::*;
use super::*;
use crate::config::ConfigSource;
use crate::support::{generate_key_material, public_jwk_from_private_der};
use actix_web::test::TestRequest;

#[path = "security/client_assertion.rs"]
mod client_assertion;
#[path = "security/client_auth.rs"]
mod client_auth;
#[path = "security/entropy_passwords.rs"]
mod entropy_passwords;
#[path = "security_tokens.rs"]
mod security_tokens;
#[path = "security/token_claims.rs"]
mod token_claims;

fn test_settings() -> Settings {
    Settings::from_config(&ConfigSource::default()).expect("default settings should load")
}

fn private_key_jwt_client(jwks: Value) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: Some(jwks),
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

fn signed_client_assertion(
    client_id: &str,
    audience: &str,
    kid: &str,
    private_pkcs8_der: &[u8],
    jti: &str,
) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": jti
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
    )
    .expect("client assertion should sign")
}

#[tokio::test]
async fn verify_password_blocking_matches_argon2_verifier() {
    let hash = hash_password("correct horse battery staple").expect("password should hash");

    assert!(
        verify_password_blocking_limited("correct horse battery staple".to_owned(), hash.clone())
            .await
            .expect("password verification should run")
    );
    assert!(
        !verify_password_blocking_limited("wrong password".to_owned(), hash)
            .await
            .expect("password verification should run")
    );
}

#[test]
fn dummy_password_hash_is_valid_and_never_matches_the_probe_password() {
    let hash = dummy_password_hash().expect("dummy password hash should initialize");

    assert!(PasswordHash::new(&hash).is_ok());
    assert!(!verify_password("attacker supplied password", &hash));
}
