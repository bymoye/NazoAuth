use super::*;
use crate::support::{LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER, hash_client_secret};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

async fn prepare_admin_client_insert_for_test(
    payload: crate::http::admin::CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    issuer: &str,
) -> Result<crate::http::admin::PreparedClientInsert, crate::http::admin::InsertClientError> {
    crate::http::admin::prepare_client_insert_with_secret_pepper(
        payload,
        pairwise_subject_secret,
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
        issuer,
        crate::support::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
}

async fn prepare_dynamic_client_insert_for_test(
    registration: PreparedDynamicClientRegistration,
    pairwise_subject_secret: Option<&str>,
    issuer: &str,
    registration_access_token: &str,
) -> Result<crate::http::admin::PreparedClientInsert, crate::http::admin::InsertClientError> {
    prepare_dynamic_client_insert_with_secret_pepper(
        registration,
        pairwise_subject_secret,
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
        issuer,
        registration_access_token,
        crate::support::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
}

fn parse_client_configuration_update_for_test(
    payload: Value,
    current: &ClientRow,
) -> Result<DynamicClientRegistrationRequest, DynamicRegistrationError> {
    parse_client_configuration_update_with_secret_pepper(
        payload,
        current,
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
    )
}

#[test]
fn oidc_dynamic_registration_defaults_to_confidential_authorization_code_client() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        scope: Some("openid profile email".to_owned()),
        client_name: Some("OIDF Dynamic Client".to_owned()),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("valid OIDC dynamic registration metadata should be accepted");

    assert_eq!(prepared.client_name, "OIDF Dynamic Client");
    assert_eq!(prepared.client_type, "confidential");
    assert_eq!(prepared.token_endpoint_auth_method, "client_secret_basic");
    assert_eq!(
        prepared.redirect_uris,
        vec!["https://client.example/callback"]
    );
    assert_eq!(prepared.scopes, vec!["openid", "profile", "email"]);
    assert_eq!(
        prepared.allowed_audiences,
        vec!["https://issuer.example/fapi/resource"]
    );
    assert_eq!(
        prepared.grant_types,
        vec!["authorization_code", "refresh_token"]
    );
    assert_eq!(prepared.response_types, vec!["code"]);
}

#[test]
fn oidc_dynamic_confidential_secret_clients_allow_code_without_pkce() {
    let prepared = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
            scope: Some("openid".to_owned()),
            token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
            ..Default::default()
        },
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("OIDC dynamic client metadata should be accepted");

    let create_request = prepared.to_create_client_request();
    assert!(create_request.allow_authorization_code_without_pkce);
}

#[test]
fn dynamic_registration_requires_pkce_for_public_or_sender_constrained_clients() {
    let public = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
            token_endpoint_auth_method: Some("none".to_owned()),
            ..Default::default()
        },
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("public dynamic client metadata should be accepted")
    .to_create_client_request();
    assert!(!public.allow_authorization_code_without_pkce);

    let dpop = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
            token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
            dpop_bound_access_tokens: true,
            ..Default::default()
        },
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("DPoP-bound dynamic client metadata should be accepted")
    .to_create_client_request();
    assert!(!dpop.allow_authorization_code_without_pkce);
}

#[test]
fn oidc_dynamic_code_clients_default_to_standard_claim_scopes() {
    let prepared = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
            ..Default::default()
        },
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("OIDC dynamic client metadata should be accepted");

    assert_eq!(
        prepared.scopes,
        vec![
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access"
        ]
    );
}

#[test]
fn dynamic_registration_rejects_inconsistent_grant_and_response_types() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        grant_types: Some(vec!["client_credentials".to_owned()]),
        response_types: Some(vec!["code".to_owned()]),
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("client_credentials must not be registered with code response type");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[test]
fn dynamic_registration_rejects_hybrid_response_types() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        grant_types: Some(vec!["authorization_code".to_owned()]),
        response_types: Some(vec!["code id_token".to_owned()]),
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("hybrid FAPI 1.0 response types must not be registered");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[test]
fn dynamic_registration_rejects_jwks_uri_and_jwks_in_same_request() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        jwks_uri: Some("https://client.example/jwks.json".to_owned()),
        jwks: Some(json!({"keys": []})),
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("RFC 7591 forbids jwks_uri and jwks in the same request");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[test]
fn dynamic_registration_accepts_request_uris_metadata_when_request_uri_is_not_supported() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        request_uris: vec!["https://client.example/request.jwt".to_owned()],
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("request_uris metadata should not block registration when request_uri is unsupported");

    assert_eq!(
        prepared.redirect_uris,
        vec!["https://client.example/callback"]
    );
}

#[test]
fn dynamic_registration_rejects_malformed_request_uris_metadata() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        request_uris: vec!["urn:ietf:params:oauth:request_uri:external".to_owned()],
        ..Default::default()
    };

    let err = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect_err("request_uris metadata should remain syntactically constrained");

    assert_eq!(err.error, "invalid_client_metadata");
}

#[actix_web::test]
async fn dynamic_registration_accepts_oidf_inline_jwks_without_kid_for_secret_clients() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://nginx:8443/test/a/client/callback".to_owned()]),
        jwks: Some(json!({
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "alg": "RS256",
                "n": "tHZtslxU00LSm1czViLa4PGegfMzw2LJci1nDiwws-UgJdPRgwffLBUoFDW1FZVFt7dDUK8H1emYG4QimXPS6BuE6XZQ6MN2y9rbfs6pvQz6bsITuOjNAxydM4FNiU4M4SlA9bqOf7PAU8NMsNBLP8_3HpWogUPvafgr8pymHgWmV6NJgRp41LQtul-1qzsDbO-pvLRWeFX0d2mFdKVPJttxK2_eIJVCtMzIcGfFj0bPEvQWxMUMRAra3Qu-HqTzzV3DnsZWs1B3bSBRedZVSroLzKBIfKXo5JhqqZsDu_CRL3g2V0D8gs0zmM2A46XEX-PlUq-39mEswFgTGQ3y4Q"
            }]
        })),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("OIDF Basic dynamic registration metadata should parse");

    let create_request = prepared.to_create_client_request();
    assert_eq!(
        create_request.scopes,
        vec![
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access"
        ]
    );
    assert!(create_request.allow_authorization_code_without_pkce);

    prepare_admin_client_insert_for_test(create_request, None, "https://issuer.example")
        .await
        .expect("OIDF inline jwks without kid should be accepted for secret clients");
}

#[actix_web::test]
async fn dynamic_registration_preserves_valid_userinfo_and_jarm_crypto_metadata() {
    let encryption_jwk = json!({
        "kty": "RSA",
        "kid": "dynamic-response-enc",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
        "e": "AQAB"
    });
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        jwks: Some(json!({"keys": [encryption_jwk]})),
        userinfo_signed_response_alg: Some("RS256".to_owned()),
        userinfo_encrypted_response_alg: Some("RSA-OAEP-256".to_owned()),
        userinfo_encrypted_response_enc: Some("A256GCM".to_owned()),
        authorization_signed_response_alg: Some("PS256".to_owned()),
        authorization_encrypted_response_alg: Some("RSA-OAEP-256".to_owned()),
        authorization_encrypted_response_enc: Some("A256GCM".to_owned()),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("OIDC response crypto metadata should parse");
    let create_request = prepared.to_create_client_request();
    assert_eq!(
        create_request.userinfo_signed_response_alg.as_deref(),
        Some("RS256")
    );
    assert_eq!(
        create_request.authorization_signed_response_alg.as_deref(),
        Some("PS256")
    );
    assert_eq!(
        create_request
            .authorization_encrypted_response_enc
            .as_deref(),
        Some("A256GCM")
    );

    let inserted =
        prepare_admin_client_insert_for_test(create_request, None, "https://issuer.example")
            .await
            .expect("supported response crypto metadata should pass shared validation");
    assert_eq!(
        inserted.userinfo_encrypted_response_alg.as_deref(),
        Some("RSA-OAEP-256")
    );
    assert_eq!(
        inserted.authorization_encrypted_response_alg.as_deref(),
        Some("RSA-OAEP-256")
    );
}

#[actix_web::test]
async fn dynamic_registration_rejects_response_signing_alg_unavailable_to_runtime_keyset() {
    let registration = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
            userinfo_signed_response_alg: Some("RS256".to_owned()),
            ..Default::default()
        },
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("dynamic response metadata should parse before runtime capability validation");

    let error = match prepare_dynamic_client_insert_with_secret_pepper(
        registration,
        None,
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
        "https://issuer.example",
        "registration-token",
        &["PS256"],
    )
    .await
    {
        Ok(_) => panic!("unavailable response signing algorithm must be rejected"),
        Err(InsertClientError::InvalidRequest(message)) => message,
        Err(InsertClientError::Server(message)) => {
            panic!("capability mismatch must be a client metadata error: {message}")
        }
    };

    assert!(
        error.contains("签名算法必须是当前服务可用算法: PS256"),
        "unexpected error: {error}"
    );
}

#[test]
fn dynamic_registration_refresh_clients_receive_offline_access_by_default() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        grant_types: Some(vec![
            "authorization_code".to_owned(),
            "refresh_token".to_owned(),
        ]),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("refresh-capable dynamic registration metadata should be accepted");

    assert_eq!(
        prepared.scopes,
        vec![
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access"
        ]
    );
}

#[test]
fn protected_dynamic_registration_requires_matching_initial_access_token() {
    assert!(!initial_access_token_authorized(None, None));
    assert!(initial_access_token_authorized(
        Some("Bearer register-token"),
        Some("register-token")
    ));
    assert!(!initial_access_token_authorized(
        None,
        Some("register-token")
    ));
    assert!(!initial_access_token_authorized(
        Some("Bearer wrong-token"),
        Some("register-token")
    ));
    assert!(!initial_access_token_authorized(
        Some("Basic cmVnaXN0ZXItdG9rZW4="),
        Some("register-token")
    ));
}

#[test]
fn registration_access_token_authorization_requires_stored_matching_hash() {
    let stored_hash = blake3_hex("registration-token");

    assert!(registration_access_token_authorized(
        Some("Bearer registration-token"),
        Some(&stored_hash)
    ));
    assert!(!registration_access_token_authorized(
        Some("Bearer wrong-token"),
        Some(&stored_hash)
    ));
    assert!(!registration_access_token_authorized(
        Some("Bearer registration-token"),
        None
    ));
    assert!(!registration_access_token_authorized(
        Some("Basic registration-token"),
        Some(&stored_hash)
    ));
    assert!(!registration_access_token_authorized(
        None,
        Some(&stored_hash)
    ));
}

#[actix_web::test]
async fn dynamic_registration_prepared_insert_hashes_registration_access_token() {
    let registration = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
            ..Default::default()
        },
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("dynamic registration metadata should be valid");

    let prepared = prepare_dynamic_client_insert_for_test(
        registration,
        None,
        "https://issuer.example",
        "registration-token",
    )
    .await
    .expect("dynamic registration insert should be prepared");

    assert_eq!(
        prepared.registration_access_token_blake3.as_deref(),
        Some(blake3_hex("registration-token").as_str())
    );
    assert_ne!(
        prepared.registration_access_token_blake3.as_deref(),
        Some("registration-token")
    );
}

#[test]
fn client_configuration_update_rejects_forbidden_management_fields() {
    let client = dynamic_registration_client_row();

    for field in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        let submitted_secret = random_urlsafe_token();
        let mut payload = json!({
            "client_id": "dynamic-client",
            "client_secret": submitted_secret,
        });
        payload
            .as_object_mut()
            .expect("test payload should be an object")
            .insert(field.to_owned(), json!("client-controlled"));

        let err = parse_client_configuration_update_for_test(payload, &client)
            .expect_err("RFC 7592 forbids client-controlled management fields in PUT");

        assert_eq!(err.error, "invalid_request");
    }
}

#[test]
fn client_configuration_update_requires_matching_client_id_and_secret() {
    let mut client = dynamic_registration_client_row();
    let issued_secret = random_urlsafe_token();
    let wrong_submitted_secret = random_urlsafe_token();
    client.client_secret_hash = Some(hash_client_secret(
        &issued_secret,
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
    ));

    let missing_client_id = parse_client_configuration_update_for_test(
        json!({
            "client_secret": issued_secret,
            "redirect_uris": ["https://client.example/callback"]
        }),
        &client,
    )
    .expect_err("PUT must include the current client_id");
    assert_eq!(missing_client_id.error, "invalid_client_metadata");

    let wrong_client_id = parse_client_configuration_update_for_test(
        json!({
            "client_id": "other-client",
            "client_secret": issued_secret,
            "redirect_uris": ["https://client.example/callback"]
        }),
        &client,
    )
    .expect_err("PUT client_id must match the current client");
    assert_eq!(wrong_client_id.error, "invalid_client_metadata");

    let wrong_secret = parse_client_configuration_update_for_test(
        json!({
            "client_id": "dynamic-client",
            "client_secret": wrong_submitted_secret,
            "redirect_uris": ["https://client.example/callback"]
        }),
        &client,
    )
    .expect_err("PUT client_secret must match the current secret");
    assert_eq!(wrong_secret.error, "invalid_client_metadata");

    let parsed = parse_client_configuration_update_for_test(
        json!({
            "client_id": "dynamic-client",
            "client_secret": issued_secret,
            "redirect_uris": ["https://client.example/callback"],
            "scope": "openid profile"
        }),
        &client,
    )
    .expect("matching client_id and secret should parse");
    assert_eq!(
        parsed.redirect_uris,
        Some(vec!["https://client.example/callback".to_owned()])
    );
    assert_eq!(parsed.scope, Some("openid profile".to_owned()));
}

#[actix_web::test]
async fn dynamic_registration_accepts_single_oidf_private_key_jwt_jwk_without_kid() {
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
        jwks: Some(json!({
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "alg": "RS256",
                "n": "tHZtslxU00LSm1czViLa4PGegfMzw2LJci1nDiwws-UgJdPRgwffLBUoFDW1FZVFt7dDUK8H1emYG4QimXPS6BuE6XZQ6MN2y9rbfs6pvQz6bsITuOjNAxydM4FNiU4M4SlA9bqOf7PAU8NMsNBLP8_3HpWogUPvafgr8pymHgWmV6NJgRp41LQtul-1qzsDbO-pvLRWeFX0d2mFdKVPJttxK2_eIJVCtMzIcGfFj0bPEvQWxMUMRAra3Qu-HqTzzV3DnsZWs1B3bSBRedZVSroLzKBIfKXo5JhqqZsDu_CRL3g2V0D8gs0zmM2A46XEX-PlUq-39mEswFgTGQ3y4Q"
            }]
        })),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("private_key_jwt registration metadata should parse before key policy validation");

    let result = prepare_admin_client_insert_for_test(
        prepared.to_create_client_request(),
        None,
        "https://issuer.example",
    )
    .await;
    assert!(
        result.is_ok(),
        "OIDF dynamic registration must accept one unambiguous signing JWK without kid"
    );
}

#[actix_web::test]
async fn dynamic_registration_rejects_ambiguous_private_key_jwt_jwks_without_kid() {
    let signing_jwk = json!({
        "kty": "RSA",
        "e": "AQAB",
        "use": "sig",
        "alg": "RS256",
        "n": "tHZtslxU00LSm1czViLa4PGegfMzw2LJci1nDiwws-UgJdPRgwffLBUoFDW1FZVFt7dDUK8H1emYG4QimXPS6BuE6XZQ6MN2y9rbfs6pvQz6bsITuOjNAxydM4FNiU4M4SlA9bqOf7PAU8NMsNBLP8_3HpWogUPvafgr8pymHgWmV6NJgRp41LQtul-1qzsDbO-pvLRWeFX0d2mFdKVPJttxK2_eIJVCtMzIcGfFj0bPEvQWxMUMRAra3Qu-HqTzzV3DnsZWs1B3bSBRedZVSroLzKBIfKXo5JhqqZsDu_CRL3g2V0D8gs0zmM2A46XEX-PlUq-39mEswFgTGQ3y4Q"
    });
    let request = DynamicClientRegistrationRequest {
        redirect_uris: Some(vec!["https://client.example/callback".to_owned()]),
        token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
        jwks: Some(json!({"keys": [signing_jwk.clone(), signing_jwk]})),
        ..Default::default()
    };

    let prepared = prepare_dynamic_client_registration(
        request,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("private_key_jwt registration metadata should parse before key policy validation");

    let result = prepare_admin_client_insert_for_test(
        prepared.to_create_client_request(),
        None,
        "https://issuer.example",
    )
    .await;
    assert!(
        result.is_err(),
        "kid omission must remain rejected when signing-key selection is ambiguous"
    );
}

fn dynamic_registration_client_row() -> ClientRow {
    ClientRow {
        id: uuid::Uuid::now_v7(),
        tenant_id: uuid::Uuid::now_v7(),
        realm_id: uuid::Uuid::now_v7(),
        organization_id: uuid::Uuid::now_v7(),
        client_id: "dynamic-client".to_owned(),
        client_name: "Dynamic Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: Some("client-secret-v1:salt:digest".to_owned()),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["https://issuer.example/fapi/resource"]),
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

#[test]
fn dynamic_registration_secret_response_is_not_cacheable() {
    let now = chrono::Utc::now();
    let client = dynamic_registration_client_row();
    let response = dynamic_registration_created_response(
        &client,
        &["code".to_owned()],
        Some("issued-secret".to_owned()),
        "https://issuer.example",
        "registration-token",
        now,
    );

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
}

#[actix_web::test]
async fn dynamic_registration_created_response_includes_registration_management_credentials() {
    let now = chrono::Utc::now();
    let client = dynamic_registration_client_row();
    let response = dynamic_registration_created_response(
        &client,
        &["code".to_owned()],
        Some("issued-secret".to_owned()),
        "https://issuer.example",
        "registration-token",
        now,
    );

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body).expect("registration response should be JSON");

    assert_eq!(body["registration_access_token"], "registration-token");
    assert_eq!(
        body["registration_client_uri"],
        "https://issuer.example/register/dynamic-client"
    );
    assert_eq!(body["client_id_issued_at"], now.timestamp());
}

#[test]
fn dynamic_registration_response_includes_response_protection_metadata() {
    let mut client = dynamic_registration_client_row();
    client.userinfo_signed_response_alg = Some("RS256".to_owned());
    client.userinfo_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    client.userinfo_encrypted_response_enc = Some("A256GCM".to_owned());
    client.authorization_signed_response_alg = Some("PS256".to_owned());
    client.authorization_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    client.authorization_encrypted_response_enc = Some("A256GCM".to_owned());

    let body = dynamic_registration_response(
        &client,
        &["code".to_owned()],
        None,
        "https://issuer.example",
        "registration-token",
    );

    assert_eq!(body["userinfo_signed_response_alg"], "RS256");
    assert_eq!(body["userinfo_encrypted_response_alg"], "RSA-OAEP-256");
    assert_eq!(body["userinfo_encrypted_response_enc"], "A256GCM");
    assert_eq!(body["authorization_signed_response_alg"], "PS256");
    assert_eq!(body["authorization_encrypted_response_alg"], "RSA-OAEP-256");
    assert_eq!(body["authorization_encrypted_response_enc"], "A256GCM");
}

#[test]
fn client_configuration_get_to_put_round_trip_preserves_response_protection_metadata() {
    let mut client = dynamic_registration_client_row();
    client.client_secret_hash = Some(hash_client_secret(
        "current-secret",
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
    ));
    client.jwks = Some(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "response-enc",
            "use": "enc",
            "alg": "RSA-OAEP-256",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": "AQAB"
        }]
    }));
    client.userinfo_signed_response_alg = Some("RS256".to_owned());
    client.userinfo_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    client.userinfo_encrypted_response_enc = Some("A256GCM".to_owned());
    client.authorization_signed_response_alg = Some("PS256".to_owned());
    client.authorization_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    client.authorization_encrypted_response_enc = Some("A256GCM".to_owned());

    let mut get_body = dynamic_registration_response(
        &client,
        &["code".to_owned()],
        Some("current-secret".to_owned()),
        "https://issuer.example",
        "registration-token",
    );
    let object = get_body
        .as_object_mut()
        .expect("configuration response should be an object");
    object.remove("registration_access_token");
    object.remove("registration_client_uri");
    object.remove("client_secret_expires_at");

    let update = parse_client_configuration_update_for_test(get_body, &client)
        .expect("GET representation without server-managed fields should be a valid PUT body");
    let prepared = prepare_dynamic_client_registration(
        update,
        DynamicRegistrationDefaults {
            default_audience: "https://issuer.example/fapi/resource",
        },
    )
    .expect("round-tripped response protection metadata should remain valid");

    assert_eq!(
        prepared.userinfo_signed_response_alg.as_deref(),
        Some("RS256")
    );
    assert_eq!(
        prepared.userinfo_encrypted_response_alg.as_deref(),
        Some("RSA-OAEP-256")
    );
    assert_eq!(
        prepared.authorization_signed_response_alg.as_deref(),
        Some("PS256")
    );
    assert_eq!(
        prepared.authorization_encrypted_response_enc.as_deref(),
        Some("A256GCM")
    );
}

#[test]
fn dynamic_client_audit_fields_exclude_management_credentials() {
    let client = dynamic_registration_client_row();
    let fields = dynamic_client_audit_fields(&client, "source-ip-hash".to_owned());

    assert_eq!(fields.get("client_id"), Some(&json!("dynamic-client")));
    assert_eq!(fields.get("source_ip_hash"), Some(&json!("source-ip-hash")));
    assert_eq!(
        fields.get("token_endpoint_auth_method"),
        Some(&json!("client_secret_basic"))
    );
    assert!(!fields.contains_key("registration_access_token"));
    assert!(!fields.contains_key("client_secret"));
}
