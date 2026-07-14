use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use nazo_postgres::create_pool;

use crate::adapters::security::hash_client_secret;
use crate::http::client_ip::IpCidr;
use crate::test_support::ClientSigningFixture;
use crate::test_support::client_signing_fixture;
use actix_web::test::TestRequest;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::time::Duration as StdDuration;

#[test]
fn dummy_client_secret_salt_is_deterministic_but_not_global() {
    assert_eq!(
        dummy_client_secret_salt(Some("unknown-client")),
        dummy_client_secret_salt(Some("unknown-client"))
    );
    assert_ne!(
        dummy_client_secret_salt(Some("unknown-client-a")),
        dummy_client_secret_salt(Some("unknown-client-b"))
    );
}

fn token_management_state() -> TestAppState {
    token_management_state_with_settings(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn request_facts(state: &TestAppState, request: &actix_web::HttpRequest) -> ClientAuthRequestFacts {
    crate::http::token::client_auth_request_facts(
        request,
        &state.settings.endpoint.trusted_proxy_cidrs,
    )
}

fn token_management_state_with_settings(settings: Settings) -> TestAppState {
    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_client_auth_test_invalid:nazo_client_auth_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn token_management_state_with_trusted_proxy() -> TestAppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    token_management_state_with_settings(settings)
}

fn unavailable_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(200);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(200);
        connection.internal_command_timeout = StdDuration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("unavailable valkey client construction should not connect")
}

fn fixture_secret(label: &str) -> String {
    format!("client-auth-fixture-secret-{label}")
}

fn fixture_secret_hash(secret: &str) -> String {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    hash_client_secret(secret, &settings.protocol.client_secret_pepper)
}

fn fixture_mtls_thumbprint(label: &str) -> String {
    blake3_hex(&format!("client-auth-fixture-thumbprint-{label}"))
}

fn confidential_client_with_secret(secret: &str) -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client 1".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: Some(fixture_secret_hash(secret)),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
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
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
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

fn client_credentials(method: &str) -> ClientCredentials {
    ClientCredentials {
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion: None,
        method: method.to_owned(),
    }
}

fn signed_client_assertion(
    client_id: &str,
    audience: &str,
    kid: &str,
    fixture: &ClientSigningFixture,
    jti: &str,
) -> String {
    signed_client_assertion_with_alg(
        client_id,
        audience,
        kid,
        fixture,
        jti,
        jsonwebtoken::Algorithm::RS256,
    )
}

fn signed_client_assertion_with_alg(
    client_id: &str,
    audience: &str,
    kid: &str,
    fixture: &ClientSigningFixture,
    jti: &str,
    alg: jsonwebtoken::Algorithm,
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
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

#[test]
fn public_revocation_client_accepts_only_none_without_secret_material() {
    let credentials = client_credentials("none");
    assert!(
        revocation_public_client_allows_credentials(&credentials),
        "public revocation may identify the client without authenticating as confidential"
    );

    let mut with_secret = client_credentials("none");
    with_secret.client_secret = Some("secret".to_owned());
    assert!(
        !revocation_public_client_allows_credentials(&with_secret),
        "public revocation must not accept confidential-client secret material"
    );

    let mut with_assertion = client_credentials("none");
    with_assertion.client_assertion = Some("jwt".to_owned());
    assert!(
        !revocation_public_client_allows_credentials(&with_assertion),
        "public revocation must not accept private_key_jwt assertion material"
    );

    let basic = client_credentials("client_secret_basic");
    assert!(
        !revocation_public_client_allows_credentials(&basic),
        "public revocation must not upgrade itself into a confidential auth method"
    );
}

#[test]
fn client_assertion_failures_keep_typed_security_classification() {
    assert!(matches!(
        token_management_client_assertion_error(ClientAssertionError::ReplayDetected),
        TokenManagementClientAuthError::InvalidClient
    ));
    assert!(matches!(
        token_management_client_assertion_error(ClientAssertionError::StoreUnavailable),
        TokenManagementClientAuthError::StoreUnavailable
    ));
}

#[actix_web::test]
async fn token_client_assertion_store_failure_fails_token_grant_as_server_error() {
    let mut state = token_management_state();
    state.valkey = unavailable_valkey_client();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = key.public_jwk("client-kid");
    let mut client = confidential_client_with_secret(&fixture_secret("unused"));
    client.token_endpoint_auth_method = "private_key_jwt".to_owned();
    client.jwks = Some(json!({"keys": [public_jwk]}));
    let req = TestRequest::post().uri("/token").to_http_request();
    let assertion = signed_client_assertion(
        &client.client_id,
        &state.settings.endpoint.issuer,
        "client-kid",
        &key,
        "token-store-unavailable-jti",
    );
    let mut credentials = client_credentials("private_key_jwt");
    credentials.client_assertion = Some(assertion);
    let assertion = match verify_confidential_client(
        &state,
        &request_facts(&state, &req),
        &client,
        &credentials,
    )
    .await
    {
        Ok(Some(assertion)) => assertion,
        Ok(None) => panic!("private_key_jwt verification should return replay material"),
        Err(_) => panic!("signed private_key_jwt assertion should verify"),
    };

    let error = consume_token_client_assertion(&state, &client, Some(&assertion))
        .await
        .expect_err("unavailable replay store must fail the token grant");
    assert!(matches!(
        error,
        TokenManagementClientAuthError::StoreUnavailable
    ));
}

#[test]
fn confidential_client_secret_auth_accepts_correct_and_rejects_wrong_secret_by_default() {
    let correct_secret = fixture_secret("correct");
    let wrong_secret = fixture_secret("wrong");
    let hash = fixture_secret_hash(&correct_secret);
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");

    let salt = hash
        .split(':')
        .nth(1)
        .expect("fixture verifier contains a salt");
    assert_eq!(
        client_secret_digest(
            &correct_secret,
            &settings.protocol.client_secret_pepper,
            salt
        ),
        hash
    );
    assert_ne!(
        client_secret_digest(&wrong_secret, &settings.protocol.client_secret_pepper, salt),
        hash
    );
    assert!(matches!(
        client_secret_auth_result::<nazo_identity::ports::RepositoryError>(Ok(true)),
        Ok(true)
    ));
    assert!(matches!(
        client_secret_auth_result::<nazo_identity::ports::RepositoryError>(Ok(false)),
        Ok(false)
    ));
}

#[test]
fn confidential_client_secret_auth_fails_closed_when_store_is_unavailable() {
    assert!(matches!(
        client_secret_auth_result(Err(nazo_identity::ports::RepositoryError::Unavailable)),
        Err(TokenManagementClientAuthError::StoreUnavailable)
    ));
}

#[actix_web::test]
async fn confidential_client_secret_auth_rejects_wrong_method_without_store_access() {
    let state = token_management_state();
    let req = TestRequest::default().to_http_request();
    let correct_secret = fixture_secret("correct");
    let client = confidential_client_with_secret(&correct_secret);
    let mut wrong_method = client_credentials("client_secret_post");
    wrong_method.client_secret = Some(correct_secret);
    assert!(matches!(
        verify_confidential_client(&state, &request_facts(&state, &req), &client, &wrong_method)
            .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[actix_web::test]
async fn confidential_client_auth_rejects_public_or_unknown_auth_method_even_with_secret() {
    let state = token_management_state();
    let req = TestRequest::default().to_http_request();
    let correct_secret = fixture_secret("correct");
    let mut client = confidential_client_with_secret(&correct_secret);
    let mut credentials = client_credentials("client_secret_basic");
    credentials.client_secret = Some(correct_secret);

    client.client_type = "public".to_owned();
    assert!(matches!(
        verify_confidential_client(&state, &request_facts(&state, &req), &client, &credentials)
            .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));

    client.client_type = "confidential".to_owned();
    client.token_endpoint_auth_method = "unsupported_method".to_owned();
    credentials.method = "unsupported_method".to_owned();
    assert!(matches!(
        verify_confidential_client(&state, &request_facts(&state, &req), &client, &credentials)
            .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[actix_web::test]
async fn private_key_jwt_requires_present_and_well_formed_assertion() {
    let state = token_management_state();
    let req = TestRequest::default().to_http_request();
    let mut client = confidential_client_with_secret(&fixture_secret("unused"));
    client.token_endpoint_auth_method = "private_key_jwt".to_owned();

    let mut missing_assertion = client_credentials("private_key_jwt");
    assert!(matches!(
        verify_confidential_client(
            &state,
            &request_facts(&state, &req),
            &client,
            &missing_assertion,
        )
        .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));

    missing_assertion.client_assertion = Some("not-a-jwt".to_owned());
    assert!(matches!(
        verify_confidential_client(
            &state,
            &request_facts(&state, &req),
            &client,
            &missing_assertion,
        )
        .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[actix_web::test]
async fn mtls_client_auth_requires_certificate_from_trusted_request_context() {
    let state = token_management_state();
    let thumbprint = fixture_mtls_thumbprint("untrusted-context");
    let req = TestRequest::default()
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-forwarded-tls-client-cert-sha256", thumbprint.as_str()))
        .to_http_request();
    let mut client = confidential_client_with_secret(&fixture_secret("unused"));
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    let credentials = client_credentials("tls_client_auth");

    assert!(matches!(
        verify_confidential_client(&state, &request_facts(&state, &req), &client, &credentials)
            .await,
        Err(TokenManagementClientAuthError::InvalidClient)
    ));
}

#[actix_web::test]
async fn mtls_client_auth_accepts_matching_certificate_from_trusted_proxy() {
    let state = token_management_state_with_trusted_proxy();
    let thumbprint = fixture_mtls_thumbprint("trusted-proxy");
    let req = TestRequest::default()
        .peer_addr("127.0.0.1:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-forwarded-tls-client-cert-sha256", thumbprint.as_str()))
        .to_http_request();
    let mut client = confidential_client_with_secret(&fixture_secret("unused"));
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    client.tls_client_auth_cert_sha256 = Some(thumbprint);
    let credentials = client_credentials("tls_client_auth");

    assert!(
        verify_confidential_client(&state, &request_facts(&state, &req), &client, &credentials)
            .await
            .is_ok(),
        "matching mTLS certificate from trusted proxy should authenticate the client"
    );
}

#[actix_web::test]
async fn token_endpoint_audience_is_allowed_only_by_registered_client_policy() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://auth.nazo.run".to_owned();
    let state = token_management_state_with_settings(settings);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = key.public_jwk("client-kid");
    let mut client = confidential_client_with_secret(&fixture_secret("unused"));
    client.token_endpoint_auth_method = "private_key_jwt".to_owned();
    client.jwks = Some(json!({"keys": [public_jwk]}));
    let req = TestRequest::post().uri("/token").to_http_request();
    let client_id = client.client_id.clone();

    let credentials = |jti: &str| {
        let mut credentials = client_credentials("private_key_jwt");
        credentials.client_assertion = Some(signed_client_assertion_with_alg(
            &client_id,
            "https://auth.nazo.run/token",
            "client-kid",
            &key,
            jti,
            jsonwebtoken::Algorithm::RS256,
        ));
        credentials
    };

    assert!(
        verify_confidential_client(
            &state,
            &request_facts(&state, &req),
            &client,
            &credentials("fapi-token-endpoint-audience"),
        )
        .await
        .is_err(),
        "FAPI/admin clients with endpoint audience disabled must remain issuer-only"
    );

    client.allow_client_assertion_endpoint_audience = true;
    assert!(
        verify_confidential_client(
            &state,
            &request_facts(&state, &req),
            &client,
            &credentials("oidc-token-endpoint-audience"),
        )
        .await
        .is_ok(),
        "ordinary OIDC DCR clients must accept the registered token endpoint audience"
    );
}

#[actix_web::test]
async fn ciba_private_key_jwt_accepts_ps256_endpoint_and_issuer_audiences() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://auth.nazo.run".to_owned();
    let state = token_management_state_with_settings(settings);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let public_jwk = key.public_jwk("client-kid");
    let mut client = confidential_client_with_secret(&fixture_secret("unused"));
    client.token_endpoint_auth_method = "private_key_jwt".to_owned();
    client.require_mtls_bound_tokens = true;
    client.allow_client_assertion_endpoint_audience = true;
    client.jwks = Some(json!({"keys": [public_jwk]}));
    let req = TestRequest::post().uri("/bc-authorize").to_http_request();

    for (index, audience) in [
        "https://auth.nazo.run",
        "https://auth.nazo.run/bc-authorize",
        "https://auth.nazo.run/token",
    ]
    .into_iter()
    .enumerate()
    {
        let mut credentials = client_credentials("private_key_jwt");
        credentials.client_assertion = Some(signed_client_assertion_with_alg(
            &client.client_id,
            audience,
            "client-kid",
            &key,
            &format!("ciba-client-assertion-aud-{index}"),
            jsonwebtoken::Algorithm::PS256,
        ));

        assert!(
            verify_confidential_client(&state, &request_facts(&state, &req), &client, &credentials)
                .await
                .is_ok(),
            "CIBA private_key_jwt should accept {audience} as client assertion audience"
        );
    }

    let mut wrong_endpoint = client_credentials("private_key_jwt");
    wrong_endpoint.client_assertion = Some(signed_client_assertion_with_alg(
        &client.client_id,
        "https://auth.nazo.run/introspect",
        "client-kid",
        &key,
        "ciba-client-assertion-wrong-endpoint",
        jsonwebtoken::Algorithm::PS256,
    ));
    assert!(
        verify_confidential_client(
            &state,
            &request_facts(&state, &req),
            &client,
            &wrong_endpoint,
        )
        .await
        .is_err(),
        "private_key_jwt audience must use the exact current endpoint path"
    );
}
