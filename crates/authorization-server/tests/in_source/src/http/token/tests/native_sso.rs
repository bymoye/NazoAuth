use super::*;
use crate::config::ConfigSource;
use crate::settings::Settings;
use nazo_postgres::create_pool;

use std::sync::Arc;

fn native_sso_state_with_signing_key() -> TestAppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();

    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_native_sso_test_invalid:nazo_native_sso_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::PS256,
        ),
    }
}

async fn signed_native_sso_id_token(state: &TestAppState, issuer: &str) -> String {
    let now = Utc::now().timestamp();
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    state
        .keyset
        .encode_jwt(
            nazo_auth::SigningPurpose::IdToken,
            &header,
            &json!({
                "iss": issuer,
                "sub": "subject-1",
                "aud": "source-client",
                "ds_hash": native_sso_device_secret_hash("device-secret"),
                "sid": "sid-1",
                "iat": now,
                "exp": now + 120
            }),
        )
        .await
        .expect("Native SSO id_token should sign")
}

fn token_form() -> TokenForm {
    TokenForm {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: Some("id-token".to_owned()),
        subject_token_type: Some(NATIVE_SSO_ID_TOKEN_TYPE.to_owned()),
        actor_token: Some("device-secret".to_owned()),
        actor_token_type: Some(NATIVE_SSO_DEVICE_SECRET_TYPE.to_owned()),
        audiences: Vec::new(),
        has_audience_param: false,
    }
}

#[test]
fn native_sso_device_secret_hash_is_stable_and_non_raw() {
    let first = native_sso_device_secret_hash("secret");
    let second = native_sso_device_secret_hash("secret");

    assert_eq!(first, second);
    assert_ne!(first, "secret");
    assert!(!first.contains('='));
}

#[test]
fn native_sso_device_secret_key_does_not_embed_raw_secret() {
    let key = native_sso_device_secret_key("raw-device-secret");

    assert!(key.starts_with("oauth:native_sso:device_secret:"));
    assert!(!key.contains("raw-device-secret"));
}

#[test]
fn native_sso_profile_requires_id_token_and_device_secret_token_types() {
    let mut form = token_form();
    assert!(native_sso_profile_requested(&form));

    form.actor_token_type = Some("urn:ietf:params:oauth:token-type:access_token".to_owned());
    assert!(!native_sso_profile_requested(&form));
}

#[test]
fn new_native_sso_token_binding_requires_session_id() {
    assert!(new_native_sso_token_binding(None).is_none());

    let binding = new_native_sso_token_binding(Some("sid-1")).expect("sid should bind native SSO");
    assert_eq!(binding.sid, "sid-1");
    assert_eq!(
        binding.ds_hash,
        native_sso_device_secret_hash(&binding.device_secret)
    );
}

#[tokio::test]
async fn native_sso_id_token_decoder_accepts_configured_issuer() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token(&state, state.settings.endpoint.issuer.as_str()).await;

    let claims =
        decode_native_sso_id_token(&state, &token).expect("configured issuer should decode");

    assert_eq!(claims.iss, state.settings.endpoint.issuer.as_str());
    assert_eq!(claims.sub, "subject-1");
    assert_eq!(claims.sid, "sid-1");
}

#[tokio::test]
async fn native_sso_id_token_decoder_rejects_wrong_issuer() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token(&state, "https://attacker.example").await;

    assert!(decode_native_sso_id_token(&state, &token).is_none());
}
