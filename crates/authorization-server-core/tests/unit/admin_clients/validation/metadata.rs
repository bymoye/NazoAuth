use super::test_support::{
    ClientMetadataFixture, ClientMtlsMetadataFixture, SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    validate_metadata_fixture,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

#[test]
fn ciba_and_logout_callback_uri_lengths_share_one_bound() {
    let prefix = "https://client.example/";
    let at_limit = format!(
        "{prefix}{}",
        "x".repeat(super::MAX_CIBA_LOGOUT_URI_BYTES - prefix.len())
    );
    assert!(super::validate_ciba_notification_uri(&at_limit).is_ok());
    assert!(super::validate_logout_uri("backchannel_logout_uri", &at_limit).is_ok());

    let over_limit = format!("{at_limit}x");
    for result in [
        super::validate_ciba_notification_uri(&over_limit),
        super::validate_logout_uri("frontchannel_logout_uri", &over_limit),
    ] {
        let error = result.expect_err("callback URI over the shared bound must fail");
        assert!(error.to_string().contains("2048"));
    }
}

#[allow(clippy::too_many_arguments)]
fn metadata<'a>(
    client_type: &'a str,
    redirect_uris: &'a [String],
    scopes: &'a [String],
    allowed_audiences: &'a [String],
    grant_types: &'a [String],
    token_endpoint_auth_method: &'a str,
    jwks: Option<&'a Value>,
    mtls_binding: Option<&'a ClientMtlsMetadataFixture>,
) -> ClientMetadataFixture<'a> {
    ClientMetadataFixture {
        client_type,
        redirect_uris,
        post_logout_redirect_uris: &[],
        scopes,
        allowed_audiences,
        grant_types,
        token_endpoint_auth_method,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        jwks,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        response_signing_algorithms: SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
        mtls_binding,
    }
}

#[test]
fn request_object_crypto_metadata_is_a_closed_supported_pair() {
    assert!(super::validate_request_object_crypto_metadata(None, None, None).is_ok());
    assert!(
        super::validate_request_object_crypto_metadata(
            Some("RS256"),
            Some("RSA-OAEP-256"),
            Some("A256GCM"),
        )
        .is_ok()
    );
    for (signing, algorithm, encryption, expected) in [
        (Some("none"), None, None, "request_object_signing_alg"),
        (None, None, Some("A256GCM"), "不能在未设置"),
        (None, Some("RSA-OAEP-256"), None, "必须同时配置"),
        (
            None,
            Some("RSA-OAEP"),
            Some("A128GCM"),
            "必须使用 RSA-OAEP-256 和 A256GCM",
        ),
    ] {
        let error = super::validate_request_object_crypto_metadata(signing, algorithm, encryption)
            .unwrap_err();
        assert!(error.to_string().contains(expected));
    }
}

#[test]
fn client_metadata_rejects_removed_or_unsafe_grants() {
    let invalid_type = validate_metadata_fixture(metadata(
        "native",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));
    assert!(
        invalid_type
            .expect_err("unknown client_type must fail closed")
            .to_string()
            .contains("客户端类型无效")
    );

    let result = validate_metadata_fixture(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["password".to_owned()],
        "none",
        None,
        None,
    ));

    let error = result.expect_err("password grant must be rejected");
    assert!(
        error.to_string().contains("不支持的 grant_type: password"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_accepts_implemented_jwt_bearer_grant() {
    validate_metadata_fixture(metadata(
        "confidential",
        &[],
        &["payments".to_owned()],
        &["resource://default".to_owned()],
        &["urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned()],
        "client_secret_basic",
        None,
        None,
    ))
    .expect("implemented RFC 7523 JWT bearer grant must be registrable");
}

#[test]
fn client_metadata_rejects_unsupported_auth_and_unsafe_grant_combinations() {
    let invalid_auth = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_jwt",
        None,
        None,
    ));
    assert!(
        invalid_auth
            .expect_err("unsupported token endpoint auth method must fail")
            .to_string()
            .contains("客户端认证方式无效")
    );

    let public_client_credentials = validate_metadata_fixture(metadata(
        "public",
        &[],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["client_credentials".to_owned()],
        "none",
        None,
        None,
    ));
    assert!(
        public_client_credentials
            .expect_err("public clients must not use client_credentials")
            .to_string()
            .contains("public 客户端不能使用 client_credentials 授权类型")
    );

    let client_credentials_openid = validate_metadata_fixture(metadata(
        "confidential",
        &[],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["client_credentials".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(
        client_credentials_openid
            .expect_err("client_credentials must not issue OIDC user scopes")
            .to_string()
            .contains("client_credentials 客户端不能申请 openid 作用域")
    );

    let refresh_without_issuing_grant = validate_metadata_fixture(metadata(
        "confidential",
        &[],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["refresh_token".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(
        refresh_without_issuing_grant
            .expect_err("refresh_token must be paired with an implemented issuing grant")
            .to_string()
            .contains("authorization_code、CIBA 或 device_code")
    );

    let auth_code_without_redirect = validate_metadata_fixture(metadata(
        "confidential",
        &[],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(
        auth_code_without_redirect
            .expect_err("authorization_code clients must register redirect_uri")
            .to_string()
            .contains("authorization_code 客户端必须注册 redirect_uri")
    );
}

#[test]
fn client_metadata_accepts_refresh_tokens_for_ciba_and_device_grants() {
    for grant in [
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:device_code",
    ] {
        validate_metadata_fixture(metadata(
            "confidential",
            &[],
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &[grant.to_owned(), "refresh_token".to_owned()],
            "client_secret_basic",
            None,
            None,
        ))
        .unwrap_or_else(|error| panic!("{grant} must support an optional refresh token: {error}"));
    }
}

#[test]
fn client_metadata_rejects_non_loopback_http_redirect_uri() {
    let result = validate_metadata_fixture(metadata(
        "public",
        &["http://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));

    let error = result.expect_err("non-loopback http redirect_uri must fail closed");
    assert!(
        error
            .to_string()
            .contains("http redirect_uri 只允许 public native client 使用 loopback 地址"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_requires_refresh_grant_for_offline_access() {
    let result = validate_metadata_fixture(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned(), "offline_access".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));

    let error = result.expect_err("offline_access without refresh_token grant must fail");
    assert!(
        error
            .to_string()
            .contains("offline_access 作用域必须与 refresh_token 授权类型一起启用"),
        "unexpected error: {error}"
    );

    validate_metadata_fixture(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned(), "offline_access".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned(), "refresh_token".to_owned()],
        "none",
        None,
        None,
    ))
    .expect("offline_access is valid when refresh_token grant is enabled");
}

#[test]
fn client_metadata_requires_public_jwks_for_private_key_jwt() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-1"
        }]
    });

    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        None,
        None,
    ));
    let error = result.expect_err("private_key_jwt without registered jwks must fail");
    assert!(
        error
            .to_string()
            .contains("private_key_jwt 客户端必须配置 jwks"),
        "unexpected error: {error}"
    );

    let encryption_only_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "enc-key"
        }]
    });
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&encryption_only_jwks),
        None,
    ));
    let error =
        result.expect_err("private_key_jwt must still require a signing key in registered jwks");
    assert!(
        error
            .to_string()
            .contains("private_key_jwt 客户端必须配置签名 jwks"),
        "unexpected error: {error}"
    );

    validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&jwks),
        None,
    ))
    .expect("private_key_jwt with a supported public jwks should be accepted");

    let public_private_key_jwt = validate_metadata_fixture(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&jwks),
        None,
    ));
    assert!(
        public_private_key_jwt
            .expect_err("private_key_jwt must not be available to public clients")
            .to_string()
            .contains("public 客户端只能使用 none 认证方式")
    );
}

#[test]
fn client_metadata_rejects_public_client_secret_and_confidential_none() {
    let public_with_secret = validate_metadata_fixture(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    let error =
        public_with_secret.expect_err("public clients must not use confidential client auth");
    assert!(
        error
            .to_string()
            .contains("public 客户端只能使用 none 认证方式"),
        "unexpected error: {error}"
    );

    let confidential_without_auth = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));
    let error = confidential_without_auth
        .expect_err("confidential clients must authenticate at token endpoint");
    assert!(
        error
            .to_string()
            .contains("confidential 客户端必须使用机密认证方式"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_rejects_backchannel_logout_uri_with_fragment_or_insecure_host() {
    let redirect_uris = ["https://client.example/callback".to_owned()];
    let scopes = ["openid".to_owned()];
    let audiences = ["resource://default".to_owned()];
    let grants = ["authorization_code".to_owned()];
    let mut fragment_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    fragment_metadata.backchannel_logout_uri = Some("https://client.example/backchannel#fragment");

    let error = validate_metadata_fixture(fragment_metadata)
        .expect_err("backchannel logout URI must reject fragments per OIDC logout security");
    assert!(
        error
            .to_string()
            .contains("backchannel_logout_uri 不能包含 fragment"),
        "unexpected error: {error}"
    );

    let mut insecure_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    insecure_metadata.backchannel_logout_uri = Some("http://client.example/backchannel");

    let error = validate_metadata_fixture(insecure_metadata)
        .expect_err("backchannel logout URI must reject non-loopback http");
    assert!(
        error
            .to_string()
            .contains("backchannel_logout_uri 必须使用 https 或 loopback http"),
        "unexpected error: {error}"
    );

    for uri in [
        "http://localhost/backchannel",
        "http://127.0.0.1:8080/backchannel",
        "http://app.localhost/backchannel",
    ] {
        let mut loopback_metadata = metadata(
            "confidential",
            &redirect_uris,
            &scopes,
            &audiences,
            &grants,
            "client_secret_basic",
            None,
            None,
        );
        loopback_metadata.backchannel_logout_uri = Some(uri);
        validate_metadata_fixture(loopback_metadata)
            .expect("OIDC backchannel logout may use loopback HTTP endpoints for local clients");
    }
}

#[test]
fn client_metadata_rejects_frontchannel_logout_uri_with_fragment_or_insecure_host() {
    let redirect_uris = ["https://client.example/callback".to_owned()];
    let scopes = ["openid".to_owned()];
    let audiences = ["resource://default".to_owned()];
    let grants = ["authorization_code".to_owned()];
    let mut fragment_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    fragment_metadata.frontchannel_logout_uri = Some("https://client.example/logout#fragment");

    let error = validate_metadata_fixture(fragment_metadata)
        .expect_err("front-channel logout URI must reject fragments");
    assert!(
        error
            .to_string()
            .contains("frontchannel_logout_uri 不能包含 fragment"),
        "unexpected error: {error}"
    );

    let mut insecure_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    insecure_metadata.frontchannel_logout_uri = Some("http://client.example/logout");

    let error = validate_metadata_fixture(insecure_metadata)
        .expect_err("front-channel logout URI must reject non-loopback http");
    assert!(
        error
            .to_string()
            .contains("frontchannel_logout_uri 必须使用 https 或 loopback http"),
        "unexpected error: {error}"
    );

    for (redirect_uri, logout_uri) in [
        (
            "https://client.example:443/callback",
            "https://client.example/logout",
        ),
        ("http://localhost/callback", "http://localhost/logout"),
        (
            "http://127.0.0.1:8080/callback",
            "http://127.0.0.1:8080/logout",
        ),
    ] {
        let redirect_uris = [redirect_uri.to_owned()];
        let is_loopback_http = redirect_uri.starts_with("http://");
        let mut loopback_metadata = metadata(
            if is_loopback_http {
                "public"
            } else {
                "confidential"
            },
            &redirect_uris,
            &scopes,
            &audiences,
            &grants,
            if is_loopback_http {
                "none"
            } else {
                "client_secret_basic"
            },
            None,
            None,
        );
        loopback_metadata.frontchannel_logout_uri = Some(logout_uri);
        validate_metadata_fixture(loopback_metadata)
            .expect("front-channel logout origin must match a registered redirect origin");
    }

    let mut cross_origin_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    cross_origin_metadata.frontchannel_logout_uri = Some("https://logout.client.example/logout");
    let error = validate_metadata_fixture(cross_origin_metadata)
        .expect_err("front-channel logout origin must match a redirect URI origin");
    assert!(
        error.to_string().contains(
            "frontchannel_logout_uri 的 scheme、host 和有效端口必须与一个 redirect_uri 相同"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_validates_optional_jwks_for_all_auth_methods() {
    let public_jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-1"
        }]
    });

    for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut private_jwks = public_jwks.clone();
        private_jwks["keys"][0][private_member] = json!(URL_SAFE_NO_PAD.encode([8u8; 32]));
        let result = validate_metadata_fixture(metadata(
            "confidential",
            &["https://client.example/callback".to_owned()],
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &["authorization_code".to_owned()],
            "client_secret_basic",
            Some(&private_jwks),
            None,
        ));
        let error = result.expect_err("registered jwks must contain public material only");
        assert!(
            error.to_string().contains("jwks 不能包含私钥材料"),
            "unexpected error for {private_member}: {error}"
        );
    }

    validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ))
    .expect("client_secret_basic may omit jwks");
}

#[test]
fn client_metadata_validates_introspection_jwe_metadata() {
    let redirect_uris = ["https://client.example/callback".to_owned()];
    let scopes = ["openid".to_owned()];
    let audiences = ["resource://default".to_owned()];
    let grants = ["authorization_code".to_owned()];
    let encryption_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "enc-key"
        }]
    });

    let mut missing_enc = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    missing_enc.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    let error =
        validate_metadata_fixture(missing_enc).expect_err("JWE alg without enc must fail closed");
    assert!(
        error
            .to_string()
            .contains("introspection_encrypted_response_alg 必须同时配置"),
        "unexpected error: {error}"
    );

    let mut missing_alg = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    missing_alg.introspection_encrypted_response_enc = Some("A256GCM");
    let error =
        validate_metadata_fixture(missing_alg).expect_err("JWE enc without alg must fail closed");
    assert!(
        error
            .to_string()
            .contains("introspection_encrypted_response_enc 不能在未设置"),
        "unexpected error: {error}"
    );

    let mut unsupported_enc = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    unsupported_enc.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    unsupported_enc.introspection_encrypted_response_enc = Some("A128CBC-HS256");
    let error = validate_metadata_fixture(unsupported_enc)
        .expect_err("unsupported JWE enc must fail closed");
    assert!(
        error
            .to_string()
            .contains("introspection_encrypted_response_enc 必须是 A256GCM"),
        "unexpected error: {error}"
    );

    let signing_jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "sig-key"
        }]
    });
    let mut missing_encryption_key = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&signing_jwks),
        None,
    );
    missing_encryption_key.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    missing_encryption_key.introspection_encrypted_response_enc = Some("A256GCM");
    let error = validate_metadata_fixture(missing_encryption_key)
        .expect_err("JWE response requires a matching encryption JWK");
    assert!(
        error.to_string().contains("必须配置匹配的 jwks 加密公钥"),
        "unexpected error: {error}"
    );

    let mut valid = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    valid.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    valid.introspection_encrypted_response_enc = Some("A256GCM");
    validate_metadata_fixture(valid)
        .expect("supported JWE metadata with a matching encryption JWK should be accepted");
}

#[test]
fn client_metadata_validates_userinfo_and_authorization_response_crypto_metadata() {
    let redirect_uris = ["https://client.example/callback".to_owned()];
    let scopes = ["openid".to_owned()];
    let audiences = ["resource://default".to_owned()];
    let grants = ["authorization_code".to_owned()];
    let encryption_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "response-enc-key"
        }]
    });

    let base = || {
        metadata(
            "confidential",
            &redirect_uris,
            &scopes,
            &audiences,
            &grants,
            "client_secret_basic",
            Some(&encryption_jwks),
            None,
        )
    };

    for field in ["userinfo", "authorization"] {
        let mut missing_enc = base();
        if field == "userinfo" {
            missing_enc.userinfo_encrypted_response_alg = Some("RSA-OAEP-256");
        } else {
            missing_enc.authorization_encrypted_response_alg = Some("RSA-OAEP-256");
        }
        let error = validate_metadata_fixture(missing_enc)
            .expect_err("response JWE alg without enc must fail closed");
        assert!(
            error.to_string().contains("必须同时配置"),
            "unexpected {field} error: {error}"
        );

        let mut missing_alg = base();
        if field == "userinfo" {
            missing_alg.userinfo_encrypted_response_enc = Some("A256GCM");
        } else {
            missing_alg.authorization_encrypted_response_enc = Some("A256GCM");
        }
        let error = validate_metadata_fixture(missing_alg)
            .expect_err("response JWE enc without alg must fail closed");
        assert!(
            error.to_string().contains("不能在未设置"),
            "unexpected {field} error: {error}"
        );

        let mut unsupported_signing = base();
        if field == "userinfo" {
            unsupported_signing.userinfo_signed_response_alg = Some("none");
        } else {
            unsupported_signing.authorization_signed_response_alg = Some("HS256");
        }
        let error = validate_metadata_fixture(unsupported_signing)
            .expect_err("none and symmetric response signing must be rejected");
        assert!(
            error.to_string().contains("签名算法"),
            "unexpected {field} error: {error}"
        );
    }

    let mut valid = base();
    valid.userinfo_signed_response_alg = Some("RS256");
    valid.userinfo_encrypted_response_alg = Some("RSA-OAEP-256");
    valid.userinfo_encrypted_response_enc = Some("A256GCM");
    valid.authorization_signed_response_alg = Some("PS256");
    valid.authorization_encrypted_response_alg = Some("RSA-OAEP-256");
    valid.authorization_encrypted_response_enc = Some("A256GCM");
    validate_metadata_fixture(valid)
        .expect("supported UserInfo and JARM response crypto metadata should be accepted");

    let mut unavailable_signing = base();
    unavailable_signing.response_signing_algorithms = &["PS256"];
    unavailable_signing.userinfo_signed_response_alg = Some("RS256");
    let error = validate_metadata_fixture(unavailable_signing)
        .expect_err("registration must reject algorithms unavailable to the current keyset");
    assert!(
        error
            .to_string()
            .contains("签名算法必须是当前服务可用算法: PS256"),
        "unexpected error: {error}"
    );

    let signing_only_jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "sig-key"
        }]
    });
    let mut missing_encryption_key = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&signing_only_jwks),
        None,
    );
    missing_encryption_key.userinfo_encrypted_response_alg = Some("RSA-OAEP-256");
    missing_encryption_key.userinfo_encrypted_response_enc = Some("A256GCM");
    let error = validate_metadata_fixture(missing_encryption_key)
        .expect_err("response encryption requires a matching use=enc key");
    assert!(
        error.to_string().contains("必须配置匹配的 jwks 加密公钥"),
        "unexpected error: {error}"
    );

    let duplicate_encryption_jwks = json!({
        "keys": [
            encryption_jwks["keys"][0].clone(),
            {
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode([0x92u8; 256]),
                "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
                "alg": "RSA-OAEP-256",
                "use": "enc",
                "kid": "response-enc-key-2"
            }
        ]
    });
    let mut ambiguous_encryption_key = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&duplicate_encryption_jwks),
        None,
    );
    ambiguous_encryption_key.userinfo_encrypted_response_alg = Some("RSA-OAEP-256");
    ambiguous_encryption_key.userinfo_encrypted_response_enc = Some("A256GCM");
    let error = validate_metadata_fixture(ambiguous_encryption_key)
        .expect_err("response encryption key selection must be unambiguous");
    assert!(
        error
            .to_string()
            .contains("必须且只能配置一个匹配的 jwks 加密公钥"),
        "unexpected error: {error}"
    );
}
