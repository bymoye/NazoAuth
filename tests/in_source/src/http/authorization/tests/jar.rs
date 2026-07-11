use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::support::{generate_key_material, public_jwk_from_private_der};

fn request_object(payload: Value, alg: &str, signature: &str) -> String {
    let header = if alg == "none" {
        json!({"alg": "none"})
    } else {
        json!({"alg": alg, "kid": "kid-1"})
    };
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        signature
    )
}

fn jar_client(client_id: &str) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!([]),
        scopes: json!([]),
        allowed_audiences: json!([]),
        grant_types: json!([]),
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

fn signed_jar_client(client_id: &str, kid: &str, private_pkcs8_der: &[u8]) -> ClientRow {
    let mut client = jar_client(client_id);
    let public_jwk =
        public_jwk_from_private_der(kid, jsonwebtoken::Algorithm::RS256, private_pkcs8_der)
            .expect("public jwk should derive from private key");
    client.jwks = Some(json!({"keys": [public_jwk]}));
    client
}

fn jar_state(issuer: &str) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = issuer.to_owned();

    jar_state_with_valkey(
        issuer,
        fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
    )
}

fn jar_state_with_valkey(issuer: &str, valkey: fred::prelude::Client) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = issuer.to_owned();

    AppState {
        diesel_db: create_pool(
            "postgres://nazo_jar_test_invalid:nazo_jar_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

async fn live_jar_state(issuer: &str) -> Option<AppState> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(1000);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(1000);
        connection.internal_command_timeout = StdDuration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");
    Some(jar_state_with_valkey(issuer, valkey))
}

fn unavailable_jar_state(issuer: &str) -> AppState {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(50);
        connection.internal_command_timeout = StdDuration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    jar_state_with_valkey(
        issuer,
        builder
            .build()
            .expect("unavailable Valkey client should construct"),
    )
}

fn signed_request_object_token(kid: &str, private_pkcs8_der: &[u8], claims: Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
    )
    .expect("request object should sign")
}

fn signed_request_object_claims_json(extra: Value) -> Value {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "client_id": "client-a",
        "iss": "client-a",
        "sub": "client-a",
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("request-object-{}", Uuid::now_v7()),
        "response_type": "code",
        "scope": "openid profile",
        "state": "state-1"
    });
    let target = claims.as_object_mut().expect("claims should be an object");
    for (key, value) in extra.as_object().expect("extra should be an object") {
        target.insert(key.clone(), value.clone());
    }
    claims
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[actix_web::test]
async fn apply_request_object_rejects_malformed_compact_or_decoding_before_claims_are_trusted() {
    let state = jar_state("https://issuer.example");
    let client = jar_client("client-a");

    for request in [
        "not-a-compact-jwt".to_owned(),
        format!(
            "{}.{}.{}",
            "not-base64",
            URL_SAFE_NO_PAD.encode(json!({"client_id": "client-a"}).to_string()),
            ""
        ),
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode("not-json"),
            URL_SAFE_NO_PAD.encode(json!({"client_id": "client-a"}).to_string()),
            ""
        ),
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg": "none"}).to_string()),
            "not-base64",
            ""
        ),
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(json!({"alg": "none"}).to_string()),
            URL_SAFE_NO_PAD.encode("not-json"),
            ""
        ),
    ] {
        let mut outer = HashMap::from([
            ("client_id".to_owned(), "client-a".to_owned()),
            ("request".to_owned(), request),
        ]);

        let response = apply_request_object(&state, &mut outer, &client)
            .await
            .expect_err("malformed request object must be rejected");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            oauth_error_code(&response).as_deref(),
            Some("invalid_request_object")
        );
        assert!(!outer.contains_key("response_type"));
    }
}

#[actix_web::test]
async fn apply_request_object_rejects_unknown_signed_alg_before_claims_are_trusted() {
    let state = jar_state("https://issuer.example");
    let client = jar_client("client-a");
    let request_object = request_object(
        json!({
            "client_id": "client-a",
            "response_type": "code",
            "redirect_uri": "https://client.example/callback"
        }),
        "not-real",
        &URL_SAFE_NO_PAD.encode("signature"),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
    ]);

    let response = apply_request_object(&state, &mut outer, &client)
        .await
        .expect_err("unknown JWS alg must fail before request claims are trusted");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
    assert!(!outer.contains_key("response_type"));
}

#[actix_web::test]
async fn holder_bound_client_rejects_unsigned_request_object_at_endpoint_boundary() {
    let state = jar_state("https://issuer.example");
    let mut client = jar_client("client-a");
    client.require_dpop_bound_tokens = true;
    let request_object = request_object(
        json!({
            "client_id": "client-a",
            "response_type": "code",
            "redirect_uri": "https://client.example/callback"
        }),
        "none",
        "",
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
    ]);

    let response = apply_request_object(&state, &mut outer, &client)
        .await
        .expect_err("holder-bound authorization requests must not accept unsigned JAR");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
    assert!(!outer.contains_key("response_type"));
}

#[actix_web::test]
async fn basic_request_object_applies_unsigned_request_object_claims() {
    let state = jar_state("https://issuer.example");
    let client = jar_client("client-a");
    let request_object = request_object(
        json!({
            "client_id": "client-a",
            "response_type": "code",
            "redirect_uri": "https://client.example/callback",
            "scope": "openid profile",
            "state": "state-from-jar",
            "max_age": 300
        }),
        "none",
        "",
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
        ("scope".to_owned(), "openid".to_owned()),
        ("nonce".to_owned(), "outer-nonce".to_owned()),
    ]);

    apply_request_object(&state, &mut outer, &client)
        .await
        .expect("baseline OIDC accepts unsigned request objects for compatibility");

    assert_eq!(outer.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        outer.get("scope").map(String::as_str),
        Some("openid profile")
    );
    assert_eq!(outer.get("nonce").map(String::as_str), Some("outer-nonce"));
    assert_eq!(
        outer.get("state").map(String::as_str),
        Some("state-from-jar")
    );
}

#[test]
fn unverified_signed_client_id_rejects_unsigned_request_object_claims() {
    let token = request_object(
        json!({
            "client_id": "client-a",
            "redirect_uri": "https://client.example/callback",
            "response_type": "code",
            "scope": "openid",
            "state": "state-1",
            "nonce": "nonce-1"
        }),
        "none",
        "",
    );
    assert!(request_object_uses_unsigned_algorithm(&token));
    assert!(unverified_signed_request_object_client_id(&token).is_none());
}

#[test]
fn request_object_alg_none_requires_unsecured_jwt_shape() {
    let header = RequestObjectHeader {
        alg: "none".to_owned(),
    };

    assert!(
        request_object_uses_none_algorithm(&header, "payload", "")
            .expect("alg none with empty signature is an unsigned request object")
    );
    assert!(request_object_uses_none_algorithm(&header, "", "").is_err());
    assert!(request_object_uses_none_algorithm(&header, "payload", "signature").is_err());
}

#[test]
fn request_object_unsigned_algorithm_detection_fails_closed_for_malformed_inputs() {
    assert!(!request_object_uses_unsigned_algorithm("not-a-compact-jwt"));
    assert!(!request_object_uses_unsigned_algorithm(&format!(
        "{}.{}.",
        "not-base64",
        URL_SAFE_NO_PAD.encode(json!({"client_id": "client-a"}).to_string())
    )));
    assert!(!request_object_uses_unsigned_algorithm(&format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode("not-json"),
        URL_SAFE_NO_PAD.encode(json!({"client_id": "client-a"}).to_string())
    )));
}

#[test]
fn signed_request_object_requires_signature_part() {
    let header = RequestObjectHeader {
        alg: "EdDSA".to_owned(),
    };

    assert!(
        !request_object_uses_none_algorithm(&header, "payload", "signature")
            .expect("signed request object has a signature")
    );
    assert!(request_object_uses_none_algorithm(&header, "payload", "").is_err());
}

#[test]
fn compact_request_object_must_have_exactly_three_parts() {
    assert_eq!(split_compact_jwt("a.b.c"), Some(("a", "b", "c")));
    assert!(split_compact_jwt("a.b").is_none());
    assert!(split_compact_jwt("a.b.c.d").is_none());
}

#[test]
fn outer_client_id_conflict_is_detected_before_claims_are_applied() {
    assert!(!outer_client_id_conflicts(&HashMap::new(), "client-a"));
    assert!(!outer_client_id_conflicts(
        &HashMap::from([("client_id".to_owned(), "client-a".to_owned())]),
        "client-a"
    ));
    assert!(outer_client_id_conflicts(
        &HashMap::from([("client_id".to_owned(), "client-b".to_owned())]),
        "client-a"
    ));
}

#[test]
fn unverified_client_id_rejects_mismatched_party_claims() {
    let token = request_object(
        json!({
            "iss": "client-a",
            "sub": "client-a",
            "client_id": "client-a",
            "aud": "https://issuer.example",
            "exp": 4102444800i64,
            "jti": "jar-1"
        }),
        "EdDSA",
        &URL_SAFE_NO_PAD.encode("signature"),
    );
    assert_eq!(
        unverified_signed_request_object_client_id(&token).as_deref(),
        Some("client-a")
    );

    let mismatched = request_object(
        json!({
            "iss": "client-a",
            "sub": "client-a",
            "client_id": "client-b",
            "aud": "https://issuer.example",
            "exp": 4102444800i64,
            "jti": "jar-2"
        }),
        "EdDSA",
        &URL_SAFE_NO_PAD.encode("signature"),
    );
    assert!(unverified_signed_request_object_client_id(&mismatched).is_none());
}

#[test]
fn unverified_signed_client_id_requires_signature_part() {
    let payload = json!({"client_id": "client-a"});
    let signed_without_signature = request_object(payload, "EdDSA", "");
    assert!(!request_object_uses_unsigned_algorithm(
        &signed_without_signature
    ));
    assert!(unverified_signed_request_object_client_id(&signed_without_signature).is_none());
}

#[test]
fn basic_request_object_party_claims_are_optional_but_bound_when_present() {
    let client = jar_client("client-a");
    let mut claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::new(),
    };

    assert!(request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::BasicOidc
    ));

    claims.iss = Some("client-b".to_owned());
    assert!(!request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::BasicOidc
    ));

    claims.iss = Some("client-a".to_owned());
    claims.sub = Some("client-b".to_owned());
    assert!(!request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::BasicOidc
    ));
}

#[test]
fn request_object_jti_is_optional_but_validated_when_present() {
    assert!(is_valid_request_object_jti("abc"));
    assert!(!is_valid_request_object_jti(""));
    assert!(!is_valid_request_object_jti(&"a".repeat(129)));

    let basic = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::new(),
    };
    assert!(request_object_jti_valid(
        &basic,
        RequestObjectMode::BasicOidc,
        RequestObjectJtiPolicy::RequiredForSignedJar
    ));
    assert!(request_object_jti_valid(
        &basic,
        RequestObjectMode::SignedJar,
        RequestObjectJtiPolicy::Optional
    ));
    assert!(!request_object_jti_valid(
        &basic,
        RequestObjectMode::SignedJar,
        RequestObjectJtiPolicy::RequiredForSignedJar
    ));

    let invalid = RequestObjectClaims {
        jti: Some(String::new()),
        ..basic
    };
    assert!(!request_object_jti_valid(
        &invalid,
        RequestObjectMode::SignedJar,
        RequestObjectJtiPolicy::RequiredForSignedJar
    ));
}

#[test]
fn request_object_params_rejects_request_uri_claim() {
    let mut claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::from([
            (
                "redirect_uri".to_owned(),
                json!("https://client.example/callback"),
            ),
            ("request_uri".to_owned(), json!("urn:example:bad")),
        ]),
    };
    assert!(request_object_params(&claims).is_err());

    claims.params.remove("request_uri");
    let params = request_object_params(&claims).expect("valid request object params");
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("https://client.example/callback")
    );
}

#[test]
fn request_object_params_allow_authorization_details_arrays() {
    let claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::from([(
            "authorization_details".to_owned(),
            json!([{"type": "account_information", "actions": ["read"]}]),
        )]),
    };

    let params = request_object_params(&claims).expect("authorization_details array is allowed");

    assert!(
        params
            .get("authorization_details")
            .is_some_and(|value| value.contains("account_information"))
    );
}

#[test]
fn outer_authorization_parameter_conflict_ignores_request_uri_and_client_id() {
    let outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        (
            "request_uri".to_owned(),
            "urn:ietf:params:oauth:request_uri:outer".to_owned(),
        ),
        ("scope".to_owned(), "openid profile".to_owned()),
    ]);
    let request_params = HashMap::from([
        ("client_id".to_owned(), "client-b".to_owned()),
        (
            "request_uri".to_owned(),
            "urn:ietf:params:oauth:request_uri:inner".to_owned(),
        ),
        ("scope".to_owned(), "openid email".to_owned()),
    ]);

    assert!(outer_authorization_params_conflict(&outer, &request_params));

    let matching_scope = HashMap::from([
        ("client_id".to_owned(), "client-b".to_owned()),
        (
            "request_uri".to_owned(),
            "urn:ietf:params:oauth:request_uri:inner".to_owned(),
        ),
        ("scope".to_owned(), "openid profile".to_owned()),
    ]);
    assert!(!outer_authorization_params_conflict(
        &outer,
        &matching_scope
    ));
}

#[test]
fn request_object_audience_accepts_issuer_or_authorization_endpoint() {
    let state = jar_state("https://issuer.example");

    assert!(request_object_audience_matches(
        &json!("https://issuer.example"),
        &state
    ));
    assert!(request_object_audience_matches(
        &json!("https://issuer.example/authorize"),
        &state
    ));
    assert!(request_object_audience_matches(
        &json!(["https://other.example", "https://issuer.example/authorize"]),
        &state
    ));
    assert!(!request_object_audience_matches(
        &json!("https://other.example"),
        &state
    ));
    assert!(!request_object_audience_matches(&json!({}), &state));
}

#[test]
fn request_object_audience_presence_depends_on_request_object_mode() {
    let state = jar_state("https://issuer.example");
    let mut claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: Some("client-a".to_owned()),
        sub: Some("client-a".to_owned()),
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::new(),
    };

    assert!(request_object_audience_valid(
        &claims,
        &state,
        RequestObjectMode::BasicOidc
    ));
    assert!(!request_object_audience_valid(
        &claims,
        &state,
        RequestObjectMode::SignedJar
    ));

    claims.aud = Some(json!("https://issuer.example/authorize"));
    assert!(request_object_audience_valid(
        &claims,
        &state,
        RequestObjectMode::SignedJar
    ));
}

#[actix_web::test]
async fn signed_request_object_requires_redirect_uri_before_applying_claims() {
    let state = jar_state("https://issuer.example");
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let client = signed_jar_client("client-a", "jar-kid", &key);
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({})),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
    ]);

    let response = apply_request_object(&state, &mut outer, &client)
        .await
        .expect_err("signed JAR without redirect_uri must fail");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
    assert!(!outer.contains_key("response_type"));
    assert!(!outer.contains_key("scope"));
}

#[actix_web::test]
async fn holder_bound_signed_request_object_rejects_outer_authorization_parameter_override() {
    let state = jar_state("https://issuer.example");
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let mut client = signed_jar_client("client-a", "jar-kid", &key);
    client.require_dpop_bound_tokens = true;
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback"
        })),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
        ("scope".to_owned(), "openid email".to_owned()),
    ]);

    let response = apply_request_object(&state, &mut outer, &client)
        .await
        .expect_err("holder-bound JAR must reject conflicting outer authorization parameters");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
    assert_eq!(outer.get("scope").map(String::as_str), Some("openid email"));
}

#[actix_web::test]
async fn holder_bound_signed_request_object_applies_only_jwt_authorization_parameters() {
    let Some(state) = live_jar_state("https://issuer.example").await else {
        return;
    };
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let mut client = signed_jar_client("client-a", "jar-kid", &key);
    client.require_dpop_bound_tokens = true;
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback",
            "nonce": "jwt-nonce"
        })),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
        ("prompt".to_owned(), "login".to_owned()),
    ]);

    apply_request_object(&state, &mut outer, &client)
        .await
        .expect("holder-bound signed JAR should apply");

    assert_eq!(outer.get("client_id").map(String::as_str), Some("client-a"));
    assert_eq!(
        outer.get("redirect_uri").map(String::as_str),
        Some("https://client.example/callback")
    );
    assert_eq!(outer.get("nonce").map(String::as_str), Some("jwt-nonce"));
    assert!(!outer.contains_key("prompt"));
}

#[actix_web::test]
async fn par_policy_signed_request_object_rejects_outer_authorization_parameter_override() {
    let state = jar_state("https://issuer.example");
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let mut client = signed_jar_client("client-a", "jar-kid", &key);
    client.require_par_request_object = true;
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback",
            "scope": "openid"
        })),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
        ("scope".to_owned(), "openid email".to_owned()),
    ]);

    let response = apply_request_object(&state, &mut outer, &client)
        .await
        .expect_err("PAR request object policy must reject unsigned outer overrides");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
    assert_eq!(outer.get("scope").map(String::as_str), Some("openid email"));
}

#[actix_web::test]
async fn par_policy_signed_request_object_applies_only_jwt_authorization_parameters() {
    let Some(state) = live_jar_state("https://issuer.example").await else {
        return;
    };
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let mut client = signed_jar_client("client-a", "jar-kid", &key);
    client.require_par_request_object = true;
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback",
            "nonce": "jwt-nonce"
        })),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
        ("prompt".to_owned(), "login".to_owned()),
    ]);

    apply_request_object(&state, &mut outer, &client)
        .await
        .expect("PAR request object policy should apply signed parameters");

    assert_eq!(outer.get("client_id").map(String::as_str), Some("client-a"));
    assert_eq!(
        outer.get("redirect_uri").map(String::as_str),
        Some("https://client.example/callback")
    );
    assert_eq!(outer.get("nonce").map(String::as_str), Some("jwt-nonce"));
    assert!(!outer.contains_key("prompt"));
}

#[test]
fn signed_request_object_rejects_unsupported_algorithm_before_claims_are_trusted() {
    let token = signed_request_object_token(
        "jar-kid",
        &generate_key_material(jsonwebtoken::Algorithm::RS256)
            .expect("request object key should generate")
            .private_pkcs8_der,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback"
        })),
    );
    let mut header = jsonwebtoken::decode_header(&token).expect("signed token header");
    header.alg = jsonwebtoken::Algorithm::HS256;
    let client = jar_client("client-a");

    let response = match super::signed_request_object_claims(&token, &client, header) {
        Ok(_) => panic!("JAR must reject unsupported or policy-invalid signing algorithms"),
        Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
}

#[test]
fn signed_request_object_rejects_missing_or_unknown_key_id() {
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let token = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback"
        })),
    );
    let client = signed_jar_client("client-a", "different-kid", &key);

    let mut missing_kid_header = jsonwebtoken::decode_header(&token).expect("signed token header");
    missing_kid_header.kid = None;
    let missing_kid = match super::signed_request_object_claims(&token, &client, missing_kid_header)
    {
        Ok(_) => panic!("JAR must not accept signed request objects without kid"),
        Err(response) => response,
    };
    assert_eq!(missing_kid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&missing_kid).as_deref(),
        Some("invalid_request_object")
    );

    let unknown_kid_header = jsonwebtoken::decode_header(&token).expect("signed token header");
    let unknown_kid = match super::signed_request_object_claims(&token, &client, unknown_kid_header)
    {
        Ok(_) => panic!("JAR must not accept keys outside the client's registered JWKS"),
        Err(response) => response,
    };
    assert_eq!(unknown_kid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&unknown_kid).as_deref(),
        Some("invalid_request_object")
    );
}

#[test]
fn signed_request_object_rejects_invalid_signature_with_registered_kid() {
    let trusted_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("trusted request object key should generate")
        .private_pkcs8_der;
    let attacker_key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("attacker request object key should generate")
        .private_pkcs8_der;
    let token = signed_request_object_token(
        "jar-kid",
        &attacker_key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback"
        })),
    );
    let client = signed_jar_client("client-a", "jar-kid", &trusted_key);
    let header = jsonwebtoken::decode_header(&token).expect("signed token header");

    let response = match super::signed_request_object_claims(&token, &client, header) {
        Ok(_) => panic!("JAR must reject signatures that do not verify against registered JWKS"),
        Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
}

#[actix_web::test]
async fn request_object_jti_store_failure_fails_closed_without_applying_claims() {
    let state = unavailable_jar_state("https://issuer.example");
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let client = signed_jar_client("client-a", "jar-kid", &key);
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback",
            "jti": format!("jar-jti-{}", Uuid::now_v7())
        })),
    );
    let mut outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
    ]);

    let response = apply_request_object(&state, &mut outer, &client)
        .await
        .expect_err("request object jti replay store outage must fail closed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
    assert!(!outer.contains_key("response_type"));
}

#[actix_web::test]
async fn signed_request_object_replay_state_requires_exp_claim() {
    let state = jar_state("https://issuer.example");
    let client = jar_client("client-a");
    let claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: Some("client-a".to_owned()),
        sub: Some("client-a".to_owned()),
        aud: Some(json!("https://issuer.example")),
        exp: None,
        nbf: Some(Utc::now().timestamp()),
        iat: None,
        jti: Some(format!("jar-jti-{}", Uuid::now_v7())),
        params: HashMap::new(),
    };

    let response = store_request_object_replay_state(
        &state,
        &client,
        &claims,
        Utc::now().timestamp(),
        RequestObjectMode::SignedJar,
    )
    .await
    .expect_err("signed JAR replay state must not accept jti without exp");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
}

#[actix_web::test]
async fn request_object_jti_replay_is_client_scoped_and_rejected() {
    let Some(state) = live_jar_state("https://issuer.example").await else {
        return;
    };
    let key = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("request object key should generate")
        .private_pkcs8_der;
    let client = signed_jar_client("client-a", "jar-kid", &key);
    let request_object = signed_request_object_token(
        "jar-kid",
        &key,
        signed_request_object_claims_json(json!({
            "redirect_uri": "https://client.example/callback",
            "jti": format!("jar-jti-{}", Uuid::now_v7())
        })),
    );

    let mut first_outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object.clone()),
    ]);
    apply_request_object(&state, &mut first_outer, &client)
        .await
        .expect("first request object jti use should be accepted");
    assert_eq!(
        first_outer.get("redirect_uri").map(String::as_str),
        Some("https://client.example/callback")
    );

    let mut replay_outer = HashMap::from([
        ("client_id".to_owned(), "client-a".to_owned()),
        ("request".to_owned(), request_object),
    ]);
    let response = apply_request_object(&state, &mut replay_outer, &client)
        .await
        .expect_err("replayed request object jti must fail closed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request_object")
    );
    assert!(!replay_outer.contains_key("redirect_uri"));
}

fn time_claims(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> RequestObjectClaims {
    RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: None,
        sub: None,
        aud: None,
        exp,
        nbf,
        iat,
        jti: None,
        params: HashMap::new(),
    }
}

#[test]
fn signed_request_object_requires_exp_and_nbf() {
    let now = 1_700_000_000;

    assert!(!request_object_times_valid(
        &time_claims(None, Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), None, None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(request_object_times_valid(
        &time_claims(Some(now + 60), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn signed_request_object_rejects_invalid_nbf_window() {
    let now = 1_700_000_000;

    assert!(request_object_times_valid(
        &time_claims(Some(now + 300), Some(now + 8), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 300), Some(now + 31), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), Some(now - 301), None),
        now,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn signed_request_object_accepts_small_future_nbf_during_decode() {
    let key =
        generate_key_material(jsonwebtoken::Algorithm::RS256).expect("client key should generate");
    let public_jwk = public_jwk_from_private_der(
        "jar-kid",
        jsonwebtoken::Algorithm::RS256,
        &key.private_pkcs8_der,
    )
    .expect("public jwk should derive");
    let mut client = jar_client("client-a");
    client.jwks = Some(json!({"keys": [public_jwk]}));
    let now = Utc::now().timestamp();
    let request_object = signed_request_object_token(
        "jar-kid",
        &key.private_pkcs8_der,
        signed_request_object_claims_json(json!({
            "iat": now,
            "nbf": now + 8,
            "exp": now + 120,
            "redirect_uri": "https://client.example/callback"
        })),
    );
    let header = jsonwebtoken::decode_header(&request_object).expect("header should decode");
    let claims = signed_request_object_claims(&request_object, &client, header)
        .expect("small request object clock skew should be accepted");

    assert!(request_object_times_valid(
        &claims,
        now,
        RequestObjectMode::SignedJar
    ));
    assert_eq!(
        claims.params.get("response_type").and_then(Value::as_str),
        Some("code")
    );
}

#[test]
fn signed_request_object_rejects_invalid_exp_window() {
    let now = 1_700_000_000;

    assert!(!request_object_times_valid(
        &time_claims(Some(now), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(request_object_times_valid(
        &time_claims(Some(now + 301), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 331), Some(now), None),
        now,
        RequestObjectMode::SignedJar
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), Some(now + 60), None),
        now,
        RequestObjectMode::SignedJar
    ));
}

#[test]
fn basic_request_object_time_window_allows_omitted_exp_nbf_but_bounds_exp_and_iat() {
    let now = 1_700_000_000;

    assert!(request_object_times_valid(
        &time_claims(None, None, None),
        now,
        RequestObjectMode::BasicOidc
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + REQUEST_OBJECT_MAX_TTL_SECONDS + 1), None, None),
        now,
        RequestObjectMode::BasicOidc
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), None, Some(now + 31)),
        now,
        RequestObjectMode::BasicOidc
    ));
    assert!(!request_object_times_valid(
        &time_claims(Some(now + 60), None, Some(now - 301)),
        now,
        RequestObjectMode::BasicOidc
    ));
}

#[test]
fn dpop_bound_client_rejects_unsigned_request_objects() {
    let mut client = jar_client("client-a");

    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc,
        false
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar,
        false
    ));

    client.require_dpop_bound_tokens = true;
    assert!(!request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc,
        false
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar,
        false
    ));
}

#[test]
fn par_request_object_policy_rejects_unsigned_request_objects() {
    let mut client = jar_client("client-a");

    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc,
        false
    ));

    client.require_par_request_object = true;
    assert!(!request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc,
        false
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar,
        false
    ));
}

#[test]
fn high_security_profiles_reject_unsigned_request_objects() {
    let client = jar_client("client-a");

    assert!(!request_object_mode_allowed(
        &client,
        RequestObjectMode::BasicOidc,
        true
    ));
    assert!(request_object_mode_allowed(
        &client,
        RequestObjectMode::SignedJar,
        true
    ));
}

#[test]
fn signed_request_object_sub_is_optional_but_must_match_when_present() {
    let mut claims = RequestObjectClaims {
        client_id: "client-a".to_owned(),
        iss: Some("client-a".to_owned()),
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
        params: HashMap::new(),
    };
    let client = jar_client("client-a");

    assert!(request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::SignedJar
    ));

    claims.sub = Some("client-a".to_owned());
    assert!(request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::SignedJar
    ));

    claims.sub = Some("client-b".to_owned());
    assert!(!request_object_party_claims_valid(
        &claims,
        &client,
        RequestObjectMode::SignedJar
    ));
}

proptest! {
    #[test]
    fn request_object_params_accept_supported_string_number_and_claims_object_values(
        state in "[A-Za-z0-9._~-]{1,32}",
        max_age in 0i64..=3_600
    ) {
        let claims = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::from([
                ("state".to_owned(), json!(state)),
                ("max_age".to_owned(), json!(max_age)),
                ("claims".to_owned(), json!({"id_token": {"auth_time": {"essential": true}}})),
                ("unknown".to_owned(), json!("ignored")),
            ]),
        };

        let params = request_object_params(&claims).unwrap();
        let expected_max_age = max_age.to_string();

        prop_assert_eq!(params.get("state").map(String::as_str), Some(state.as_str()));
        prop_assert_eq!(params.get("max_age").map(String::as_str), Some(expected_max_age.as_str()));
        prop_assert!(params.get("claims").is_some_and(|value| value.contains("auth_time")));
        prop_assert!(!params.contains_key("unknown"));
    }

    #[test]
    fn request_object_params_reject_invalid_supported_value_types(
        state in "[A-Za-z0-9._~-]{1,32}"
    ) {
        let claims = RequestObjectClaims {
            client_id: "client-a".to_owned(),
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            params: HashMap::from([
                ("state".to_owned(), json!([state])),
            ]),
        };

        prop_assert!(request_object_params(&claims).is_err());
    }

    #[test]
    fn signed_request_object_time_window_accepts_only_profile_bounds(
        lifetime in 1i64..=REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS,
        nbf_skew in 0i64..=REQUEST_OBJECT_CLOCK_SKEW_SECONDS
    ) {
        let now = 1_700_000_000;
        let nbf = now + nbf_skew;

        prop_assert!(request_object_times_valid(
            &time_claims(Some(nbf + lifetime), Some(nbf), None),
            now,
            RequestObjectMode::SignedJar
        ));
        prop_assert!(!request_object_times_valid(
            &time_claims(
                Some(nbf + REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS + 1),
                Some(nbf),
                None
            ),
            now,
            RequestObjectMode::SignedJar
        ));
    }
}
