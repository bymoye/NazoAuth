use crate::adapters::security::blake3_hex;

pub(crate) fn native_sso_device_secret_key(device_secret: &str) -> String {
    format!(
        "oauth:native_sso:device_secret:{}",
        blake3_hex(device_secret)
    )
}

use super::*;
use crate::config::ConfigSource;
use crate::settings::Settings;
use crate::test_support::TestInfrastructure;
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_postgres::create_pool;

use std::sync::Arc;

fn native_sso_state_with_signing_key() -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();

    TestInfrastructure {
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

async fn signed_native_sso_id_token(state: &TestInfrastructure, issuer: &str) -> String {
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

fn native_sso_client(scopes: Value) -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: crate::domain::tenancy::DEFAULT_TENANT_ID,
        realm_id: crate::domain::tenancy::DEFAULT_REALM_ID,
        organization_id: crate::domain::tenancy::DEFAULT_ORGANIZATION_ID,
        client_id: "native-client".to_owned(),
        client_name: "Native client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://native.example/callback"]),
        scopes: scopes,
        allowed_audiences: json!(["https://issuer.example"]),
        grant_types: json!(["urn:ietf:params:oauth:grant-type:token-exchange"]),
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
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

#[actix_web::test]
async fn native_sso_issue_binding_enforces_client_sender_policy() {
    let state = native_sso_state_with_signing_key();
    let config = crate::http::token::issue::TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = crate::http::token::issue::test_support::test_authorization_service(&state);
    let issuance = TokenIssuanceContext {
        config: &config,
        modules: &modules,
        authorization: &authorization,
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let client = native_sso_client(json!(["openid"]));
    assert_eq!(
        native_sso_issue_binding(&issuance, &request, &client)
            .await
            .expect("a client without sender constraints may issue an unbound token"),
        (None, None)
    );

    let mut dpop_client = native_sso_client(json!(["openid"]));
    dpop_client.require_dpop_bound_tokens = true;
    let response = native_sso_issue_binding(&issuance, &request, &dpop_client)
        .await
        .expect_err("a DPoP-required client must present proof");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut mtls_client = native_sso_client(json!(["openid"]));
    mtls_client.require_mtls_bound_tokens = true;
    let response = native_sso_issue_binding(&issuance, &request, &mtls_client)
        .await
        .expect_err("an mTLS-required client must present a verified certificate");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_grant")
    );
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

    let mut wrong_grant = token_form();
    wrong_grant.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned();
    assert!(!native_sso_profile_requested(&wrong_grant));

    let mut wrong_subject_type = token_form();
    wrong_subject_type.subject_token_type = Some(NATIVE_SSO_DEVICE_SECRET_TYPE.to_owned());
    assert!(!native_sso_profile_requested(&wrong_subject_type));
}

#[test]
fn native_sso_scope_and_client_admission_are_fail_closed() {
    assert!(!native_sso_requested(&["openid".to_owned()]));
    assert!(native_sso_requested(&[
        "openid".to_owned(),
        DEVICE_SSO_SCOPE.to_owned()
    ]));

    let authorized = native_sso_client(json!(["openid", "offline_access", "device_sso"]));
    assert!(native_sso_client_authorized(&authorized));
    let unauthorized = native_sso_client(json!(["openid", "offline_access"]));
    assert!(!native_sso_client_authorized(&unauthorized));

    let defaults = native_sso_requested_scopes(&authorized, None)
        .expect("the documented Native SSO default scope set should be accepted");
    assert_eq!(
        defaults,
        vec![
            "openid".to_owned(),
            "offline_access".to_owned(),
            "device_sso".to_owned()
        ]
    );

    for invalid in [
        Some("offline_access device_sso"),
        Some("openid offline_access"),
    ] {
        assert!(native_sso_requested_scopes(&authorized, invalid).is_err());
    }
    assert!(native_sso_requested_scopes(&authorized, Some("openid device_sso admin")).is_err());
}

#[test]
fn native_sso_id_token_audience_requires_the_source_client() {
    let base = NativeSsoIdTokenClaims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject-1".to_owned(),
        aud: json!("source-client"),
        ds_hash: "hash".to_owned(),
        sid: "sid-1".to_owned(),
    };
    assert!(native_sso_id_token_audience_contains(
        &base,
        "source-client"
    ));
    assert!(!native_sso_id_token_audience_contains(
        &base,
        "other-client"
    ));

    let array = NativeSsoIdTokenClaims {
        aud: json!(["other-client", "source-client"]),
        ..base
    };
    assert!(native_sso_id_token_audience_contains(
        &array,
        "source-client"
    ));
    assert!(!native_sso_id_token_audience_contains(
        &array,
        "missing-client"
    ));

    let invalid = NativeSsoIdTokenClaims {
        aud: json!(42),
        ..array
    };
    assert!(!native_sso_id_token_audience_contains(
        &invalid,
        "source-client"
    ));
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
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );

    let claims = decode_native_sso_id_token_with_service(
        &service,
        state.settings.endpoint.issuer.as_str(),
        &token,
    )
    .await
    .expect("token verification should remain available")
    .expect("configured issuer should decode");

    assert_eq!(claims.iss, state.settings.endpoint.issuer.as_str());
    assert_eq!(claims.sub, "subject-1");
    assert_eq!(claims.sid, "sid-1");
}

#[tokio::test]
async fn native_sso_id_token_decoder_rejects_wrong_issuer() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token(&state, "https://attacker.example").await;
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );

    assert!(
        decode_native_sso_id_token_with_service(
            &service,
            state.settings.endpoint.issuer.as_str(),
            &token,
        )
        .await
        .expect("token verification should remain available")
        .is_none()
    );
}
