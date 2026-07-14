use serde_json::{Value, json};

use super::test_support::{
    ClientMetadataFixture, ClientMtlsMetadataFixture, SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    validate_metadata_fixture,
};

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
        allow_jwks_without_kid: false,
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
fn client_metadata_requires_mtls_binding_material() {
    let empty_mtls = ClientMtlsMetadataFixture::default();
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "tls_client_auth",
        None,
        Some(&empty_mtls),
    ));
    let error = result.expect_err("tls_client_auth requires registered certificate binding");
    assert!(
        error
            .to_string()
            .contains("tls_client_auth 客户端必须注册 subject DN、SAN 或证书 SHA-256 绑定材料"),
        "unexpected error: {error}"
    );

    let subject_mtls = ClientMtlsMetadataFixture {
        tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientMtlsMetadataFixture::default()
    };
    validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "tls_client_auth",
        None,
        Some(&subject_mtls),
    ))
    .expect("tls_client_auth may bind by registered subject DN");
}

#[test]
fn client_metadata_rejects_mtls_auth_for_public_clients() {
    let subject_mtls = ClientMtlsMetadataFixture {
        tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "tls_client_auth",
        None,
        Some(&subject_mtls),
    ));
    assert!(
        result
            .expect_err("public clients must not use mTLS client authentication")
            .to_string()
            .contains("public 客户端只能使用 none 认证方式")
    );
}

#[test]
fn client_metadata_validates_mtls_binding_material_shape() {
    let blank_subject = ClientMtlsMetadataFixture {
        tls_client_auth_subject_dn: Some("  ".to_owned()),
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&blank_subject),
    ));
    assert!(
        result
            .expect_err("blank subject DN must fail closed")
            .to_string()
            .contains("tls_client_auth_subject_dn 不能为空")
    );

    let malformed_thumbprint = ClientMtlsMetadataFixture {
        tls_client_auth_cert_sha256: Some("not-a-thumbprint".to_owned()),
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&malformed_thumbprint),
    ));
    assert!(
        result
            .expect_err("malformed certificate SHA-256 binding must fail")
            .to_string()
            .contains("tls_client_auth_cert_sha256 必须是 SHA-256 证书指纹")
    );

    let duplicate_dns = ClientMtlsMetadataFixture {
        tls_client_auth_san_dns: vec!["client.example".to_owned(), "client.example".to_owned()],
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&duplicate_dns),
    ));
    assert!(
        result
            .expect_err("duplicate SAN DNS bindings must fail")
            .to_string()
            .contains("tls_client_auth_san_dns 不能重复")
    );

    let blank_uri = ClientMtlsMetadataFixture {
        tls_client_auth_san_uri: vec![
            "spiffe://client.example/workload".to_owned(),
            " ".to_owned(),
        ],
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&blank_uri),
    ));
    assert!(
        result
            .expect_err("blank SAN URI binding must fail")
            .to_string()
            .contains("tls_client_auth_san_uri 不能为空或包含空白字符")
    );

    let blank_email = ClientMtlsMetadataFixture {
        tls_client_auth_san_email: vec!["client@example.com".to_owned(), "\t".to_owned()],
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&blank_email),
    ));
    assert!(
        result
            .expect_err("blank SAN email binding must fail")
            .to_string()
            .contains("tls_client_auth_san_email 不能为空或包含空白字符")
    );

    let invalid_ip = ClientMtlsMetadataFixture {
        tls_client_auth_san_ip: vec!["not-an-ip".to_owned()],
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&invalid_ip),
    ));
    assert!(
        result
            .expect_err("SAN IP bindings must parse as IP addresses")
            .to_string()
            .contains("tls_client_auth_san_ip 必须是合法 IP 地址")
    );
}

#[test]
fn client_metadata_requires_self_signed_mtls_x5c_jwks() {
    let subject_only = ClientMtlsMetadataFixture {
        tls_client_auth_subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        None,
        Some(&subject_only),
    ));
    let error = result.expect_err("self_signed_tls_client_auth must be bound to x5c jwks");
    assert!(
        error
            .to_string()
            .contains("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书"),
        "unexpected error: {error}"
    );

    let thumbprint = ClientMtlsMetadataFixture {
        tls_client_auth_cert_sha256: Some(
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
                .to_owned(),
        ),
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        None,
        Some(&thumbprint),
    ));
    assert!(
        result
            .expect_err("self_signed_tls_client_auth must not accept bare SHA-256 binding")
            .to_string()
            .contains("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书")
    );

    let valid_jwks = json!({
        "keys": [{
            "kid": "cert-1",
            "x5c": ["validated-by-crypto-port"]
        }]
    });
    validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "self_signed_tls_client_auth",
        Some(&valid_jwks),
        None,
    ))
    .expect("valid x5c certificate jwks should satisfy self-signed mTLS registration");
}

#[test]
fn client_metadata_rejects_duplicate_san_email_bindings() {
    let duplicate_email = ClientMtlsMetadataFixture {
        tls_client_auth_san_email: vec![
            "client@example.com".to_owned(),
            "client@example.com".to_owned(),
        ],
        ..ClientMtlsMetadataFixture::default()
    };
    let result = validate_metadata_fixture(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        Some(&duplicate_email),
    ));
    assert!(
        result
            .expect_err("duplicate SAN email bindings must fail")
            .to_string()
            .contains("tls_client_auth_san_email 不能重复")
    );
}
