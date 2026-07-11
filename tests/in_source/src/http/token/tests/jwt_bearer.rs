use super::*;
use crate::{
    config::ConfigSource,
    db::create_pool,
    domain::{ActiveSigningKey, Keyset, KeysetStore},
};
use actix_web::test::TestRequest;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fred::{
    interfaces::ClientLike,
    prelude::{Builder as ValkeyBuilder, Config as ValkeyConfig},
};
use std::sync::Arc;

fn jwt_bearer_client(client_id: &str, kid: &str, private_pkcs8_der: &[u8]) -> ClientRow {
    let public_jwk =
        public_jwk_from_private_der(kid, jsonwebtoken::Algorithm::RS256, private_pkcs8_der)
            .expect("public jwk should derive");
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: "JWT Bearer Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!([]),
        scopes: json!(["accounts", "payments"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!([JWT_BEARER_GRANT_TYPE]),
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
        jwks: Some(json!({"keys": [public_jwk]})),
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

fn signed_jwt_bearer_assertion(
    client_id: &str,
    kid: &str,
    private_pkcs8_der: &[u8],
    extra: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://issuer.example",
        "exp": now + 120,
        "nbf": now,
        "iat": now,
        "jti": format!("jwt-bearer-{}", Uuid::now_v7())
    });
    let target = claims.as_object_mut().expect("claims must be an object");
    for (key, value) in extra.as_object().expect("extra must be an object") {
        target.insert(key.clone(), value.clone());
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
    )
    .expect("JWT bearer assertion should sign")
}

fn jwt_bearer_settings() -> Settings {
    Settings::from_config(&ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        ("PUBLIC_BASE_URL", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://app.example"),
        ("COOKIE_SECURE", "true"),
    ]))
    .expect("JWT bearer test settings should load")
}

fn jwt_bearer_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_jwt_bearer_test_invalid:nazo_jwt_bearer_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(jwt_bearer_settings()),
        keyset: KeysetStore::new(Keyset {
            active_kid: "jwt-bearer-test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

async fn live_jwt_bearer_state() -> Option<AppState> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let valkey = ValkeyBuilder::from_config(
        ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
    )
    .build()
    .expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");
    let mut state = jwt_bearer_state();
    state.valkey = valkey;
    Some(state)
}

fn jwt_bearer_form(assertion: Option<&str>) -> TokenForm {
    TokenForm {
        grant_type: JWT_BEARER_GRANT_TYPE.to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
        client_id: Some("client-a".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: assertion.map(ToOwned::to_owned),
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: vec!["resource://default".to_owned()],
        has_audience_param: false,
    }
}

fn jwt_bearer_claims(now: i64) -> JwtBearerAssertionClaims {
    JwtBearerAssertionClaims {
        iss: "client-a".to_owned(),
        sub: "client-a".to_owned(),
        aud: json!("https://issuer.example"),
        exp: now + 120,
        nbf: Some(now),
        iat: Some(now),
        jti: "jwt-bearer-jti".to_owned(),
    }
}

#[test]
fn jwt_bearer_assertion_validation_binds_client_issuer_audience_and_times() {
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("JWT bearer test key should generate")
        .private_pkcs8_der;
    let client = jwt_bearer_client("client-a", "jwt-bearer-kid", &private_key);
    let settings = jwt_bearer_settings();
    let assertion =
        signed_jwt_bearer_assertion("client-a", "jwt-bearer-kid", &private_key, json!({}));

    let claims = validate_jwt_bearer_assertion(&settings, &client, &assertion)
        .expect("valid client-bound JWT bearer assertion should validate");

    assert_eq!(claims.subject, "client-a");
    assert!(valid_jwt_bearer_jti(&claims.jti));

    let wrong_audience = signed_jwt_bearer_assertion(
        "client-a",
        "jwt-bearer-kid",
        &private_key,
        json!({"aud": "https://issuer.example/token"}),
    );
    assert!(validate_jwt_bearer_assertion(&settings, &client, &wrong_audience).is_err());

    let wrong_subject = signed_jwt_bearer_assertion(
        "client-a",
        "jwt-bearer-kid",
        &private_key,
        json!({"sub": "user-1"}),
    );
    assert!(validate_jwt_bearer_assertion(&settings, &client, &wrong_subject).is_err());

    let alg_none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(json!({"iss":"client-a","sub":"client-a"}).to_string())
    );
    assert!(validate_jwt_bearer_assertion(&settings, &client, &alg_none).is_err());
}

#[test]
fn jwt_bearer_time_jti_and_replay_ttl_boundaries_are_enforced() {
    let now = Utc::now().timestamp();

    let mut expired = jwt_bearer_claims(now);
    expired.exp = now;
    assert!(!valid_jwt_bearer_times(&expired, now));

    let mut excessive_ttl = jwt_bearer_claims(now);
    excessive_ttl.exp = now + JWT_BEARER_ASSERTION_MAX_TTL_SECONDS + 1;
    assert!(!valid_jwt_bearer_times(&excessive_ttl, now));

    let mut future_nbf = jwt_bearer_claims(now);
    future_nbf.nbf = Some(now + JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS + 1);
    assert!(!valid_jwt_bearer_times(&future_nbf, now));

    let mut future_iat = jwt_bearer_claims(now);
    future_iat.iat = Some(now + JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS + 1);
    assert!(!valid_jwt_bearer_times(&future_iat, now));

    let mut stale_iat = jwt_bearer_claims(now);
    stale_iat.iat = Some(now - JWT_BEARER_ASSERTION_MAX_TTL_SECONDS - 1);
    assert!(!valid_jwt_bearer_times(&stale_iat, now));

    let mut boundary = jwt_bearer_claims(now);
    boundary.exp = now + JWT_BEARER_ASSERTION_MAX_TTL_SECONDS;
    boundary.nbf = Some(now + JWT_BEARER_ASSERTION_CLOCK_SKEW_SECONDS);
    boundary.iat = Some(now - JWT_BEARER_ASSERTION_MAX_TTL_SECONDS);
    assert!(valid_jwt_bearer_times(&boundary, now));

    assert!(!valid_jwt_bearer_jti(""));
    assert!(!valid_jwt_bearer_jti("   "));
    assert!(!valid_jwt_bearer_jti(
        &"a".repeat(JWT_BEARER_ASSERTION_MAX_JTI_BYTES + 1)
    ));
    assert!(valid_jwt_bearer_jti(
        &"a".repeat(JWT_BEARER_ASSERTION_MAX_JTI_BYTES)
    ));

    let assertion = ValidatedJwtBearerAssertion {
        subject: "client-a".to_owned(),
        jti: "jti-1".to_owned(),
        exp: now + JWT_BEARER_ASSERTION_MAX_TTL_SECONDS + 50,
    };
    assert_eq!(
        assertion.replay_ttl_seconds(now),
        JWT_BEARER_ASSERTION_MAX_TTL_SECONDS as u64
    );
    let expired_assertion = ValidatedJwtBearerAssertion {
        exp: now - 5,
        ..assertion
    };
    assert_eq!(expired_assertion.replay_ttl_seconds(now), 1);
}

#[actix_web::test]
async fn jwt_bearer_grant_rejects_public_clients_and_missing_assertions() {
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("JWT bearer test key should generate")
        .private_pkcs8_der;
    let mut public_client = jwt_bearer_client("client-a", "jwt-bearer-kid", &private_key);
    public_client.client_type = "public".to_owned();
    let state = jwt_bearer_state();
    let req = TestRequest::post().uri("/token").to_http_request();

    let response =
        token_jwt_bearer(&state, &req, &public_client, &jwt_bearer_form(None), None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("unauthorized_client")
    );

    let confidential_client = jwt_bearer_client("client-a", "jwt-bearer-kid", &private_key);
    let response = token_jwt_bearer(
        &state,
        &req,
        &confidential_client,
        &jwt_bearer_form(None),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn jwt_bearer_assertion_jti_replay_is_rejected() {
    let Some(state) = live_jwt_bearer_state().await else {
        return;
    };
    let private_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("JWT bearer test key should generate")
        .private_pkcs8_der;
    let client = jwt_bearer_client("client-a", "jwt-bearer-kid", &private_key);
    let assertion = ValidatedJwtBearerAssertion {
        subject: "client-a".to_owned(),
        jti: format!("jwt-bearer-replay-{}", Uuid::now_v7()),
        exp: Utc::now().timestamp() + 120,
    };

    consume_jwt_bearer_assertion(&state, &client, &assertion)
        .await
        .expect("first JWT bearer assertion use should be accepted");
    assert!(matches!(
        consume_jwt_bearer_assertion(&state, &client, &assertion).await,
        Err(JwtBearerAssertionError::ReplayDetected)
    ));
}
