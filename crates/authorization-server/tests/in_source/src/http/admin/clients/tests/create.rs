use super::create_error_response;
use crate::adapters::security::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER;
use crate::adapters::security::client_secret_digest;
use crate::http::admin::clients::test_support::{
    CreateClientRequest, InsertClientError, PreparedClientRegistration,
    prepare_client_insert_with_secret_pepper,
};
use actix_web::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_http_actix::OAuthJsonErrorFields;
use serde_json::json;

async fn prepare_client_insert_for_test(
    payload: CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    issuer: &str,
) -> Result<PreparedClientRegistration, InsertClientError> {
    prepare_client_insert_with_secret_pepper(
        payload,
        pairwise_subject_secret,
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
        issuer,
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
}

fn create_request() -> CreateClientRequest {
    CreateClientRequest {
        client_name: "Payments client".to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: vec!["https://client.example/logout".to_owned()],
        scopes: vec!["openid".to_owned(), "payments".to_owned()],
        allowed_audiences: vec!["https://api.example".to_owned()],
        grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: true,
        allow_authorization_code_without_pkce: false,
        backchannel_logout_uri: Some("https://client.example/backchannel".to_owned()),
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: Some("https://client.example/frontchannel".to_owned()),
        frontchannel_logout_session_required: true,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: Vec::new(),
        tls_client_auth_san_uri: Vec::new(),
        tls_client_auth_san_ip: Vec::new(),
        tls_client_auth_san_email: Vec::new(),
        jwks: Some(json!({"keys": []})),
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        allow_jwks_without_kid: false,
        subject_type: None,
        sector_identifier_uri: None,
    }
}

#[actix_web::test]
async fn prepare_client_insert_issues_secret_only_for_secret_based_confidential_clients() {
    for method in ["client_secret_basic", "client_secret_post"] {
        let mut payload = create_request();
        payload.token_endpoint_auth_method = method.to_owned();
        payload.jwks = None;

        let prepared =
            match prepare_client_insert_for_test(payload, None, "http://localhost:8000").await {
                Ok(prepared) => prepared,
                Err(_) => {
                    panic!("secret-based confidential client registration should be accepted")
                }
            };
        let issued_secret = prepared
            .issued_secret
            .as_deref()
            .expect("created secret client must receive its one-time plaintext secret");
        let stored_hash = prepared
            .client_secret_hash
            .as_deref()
            .expect("plaintext secret must be represented only by a keyed digest at rest");

        assert_eq!(prepared.client_type, "confidential");
        assert_eq!(prepared.token_endpoint_auth_method, method);
        assert!(
            stored_hash.split(':').nth(1).is_some_and(|salt| {
                client_secret_digest(issued_secret, LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER, salt)
                    == stored_hash
            }),
            "stored secret digest must verify the one-time plaintext secret"
        );
        assert_ne!(
            issued_secret, stored_hash,
            "plaintext client secret must never be stored as the DB hash"
        );
    }
}

#[actix_web::test]
async fn prepare_client_insert_does_not_issue_secret_for_public_or_mtls_clients() {
    let mut public = create_request();
    public.client_type = "public".to_owned();
    public.token_endpoint_auth_method = "none".to_owned();
    public.jwks = None;
    let public = match prepare_client_insert_for_test(public, None, "http://localhost:8000").await {
        Ok(prepared) => prepared,
        Err(_) => panic!("public client registration without secret is valid"),
    };
    assert!(public.issued_secret.is_none());
    assert!(public.client_secret_hash.is_none());

    let mut mtls = create_request();
    mtls.token_endpoint_auth_method = "tls_client_auth".to_owned();
    mtls.jwks = None;
    mtls.tls_client_auth_subject_dn = Some("CN=client.example".to_owned());
    let mtls = match prepare_client_insert_for_test(mtls, None, "http://localhost:8000").await {
        Ok(prepared) => prepared,
        Err(_) => panic!("mTLS client registration should be accepted without client secret"),
    };
    assert!(mtls.issued_secret.is_none());
    assert!(mtls.client_secret_hash.is_none());
}

#[actix_web::test]
async fn prepare_client_insert_normalizes_optional_string_metadata() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "tls_client_auth".to_owned();
    payload.jwks = None;
    payload.backchannel_logout_uri = Some("  https://client.example/backchannel  ".to_owned());
    payload.frontchannel_logout_uri = Some("  https://client.example/frontchannel  ".to_owned());
    payload.post_logout_redirect_uris = vec!["https://client.example/logout".to_owned()];
    payload.tls_client_auth_subject_dn = Some("  CN=client.example  ".to_owned());
    payload.tls_client_auth_cert_sha256 = None;
    payload.tls_client_auth_san_dns = vec!["client.example".to_owned()];
    payload.tls_client_auth_san_uri = vec!["spiffe://client".to_owned()];
    payload.tls_client_auth_san_ip = vec!["192.0.2.10".to_owned()];
    payload.tls_client_auth_san_email = vec!["ops@example.com".to_owned()];

    let prepared =
        match prepare_client_insert_for_test(payload, None, "http://localhost:8000").await {
            Ok(prepared) => prepared,
            Err(_) => panic!("mTLS metadata with surrounding whitespace should be normalizable"),
        };

    assert_eq!(
        prepared.backchannel_logout_uri.as_deref(),
        Some("https://client.example/backchannel")
    );
    assert_eq!(
        prepared.frontchannel_logout_uri.as_deref(),
        Some("https://client.example/frontchannel")
    );
    assert!(prepared.frontchannel_logout_session_required);
    assert_eq!(
        prepared.post_logout_redirect_uris,
        vec!["https://client.example/logout".to_owned()]
    );
    assert_eq!(
        prepared.tls_client_auth_subject_dn.as_deref(),
        Some("CN=client.example")
    );
    assert!(prepared.tls_client_auth_cert_sha256.is_none());
    assert_eq!(prepared.tls_client_auth_san_dns, vec!["client.example"]);
    assert_eq!(prepared.tls_client_auth_san_uri, vec!["spiffe://client"]);
    assert_eq!(prepared.tls_client_auth_san_ip, vec!["192.0.2.10"]);
    assert_eq!(prepared.tls_client_auth_san_email, vec!["ops@example.com"]);
}

#[actix_web::test]
async fn prepare_client_insert_accepts_introspection_jwe_metadata() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "client_secret_basic".to_owned();
    payload.jwks = Some(json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "introspection-enc"
        }]
    }));
    payload.introspection_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    payload.introspection_encrypted_response_enc = Some("A256GCM".to_owned());

    let prepared = prepare_client_insert_for_test(payload, None, "http://localhost:8000")
        .await
        .expect("supported introspection JWE metadata should be accepted");

    assert_eq!(
        prepared.introspection_encrypted_response_alg.as_deref(),
        Some("RSA-OAEP-256")
    );
    assert_eq!(
        prepared.introspection_encrypted_response_enc.as_deref(),
        Some("A256GCM")
    );
}

#[actix_web::test]
async fn prepare_client_insert_rejects_empty_array_metadata_before_storage() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "client_secret_basic".to_owned();
    payload.jwks = None;
    payload.post_logout_redirect_uris = vec![" ".to_owned()];

    let err = prepare_client_insert_for_test(payload, None, "http://localhost:8000")
        .await
        .expect_err("empty array metadata must fail closed");
    match err {
        InsertClientError::InvalidRequest(message) => assert!(
            message.contains("post_logout_redirect_uri"),
            "error should identify the invalid array metadata boundary: {message}"
        ),
        other => {
            panic!("metadata validation failure must not be reported as server error: {other}")
        }
    }
}

#[actix_web::test]
async fn prepare_client_insert_rejects_secret_auth_for_public_clients() {
    let mut payload = create_request();
    payload.client_type = "public".to_owned();
    payload.token_endpoint_auth_method = "client_secret_post".to_owned();
    payload.jwks = None;

    let err = prepare_client_insert_for_test(payload, None, "http://localhost:8000")
        .await
        .expect_err("public clients must not be registered with client secrets");
    match err {
        InsertClientError::InvalidRequest(message) => assert!(
            message.contains("public"),
            "error should identify the invalid public-client metadata boundary: {message}"
        ),
        other => {
            panic!("metadata validation failure must not be reported as server error: {other}")
        }
    }
}

#[actix_web::test]
async fn prepare_client_insert_rejects_pairwise_when_secret_is_not_configured() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "client_secret_basic".to_owned();
    payload.jwks = None;
    payload.subject_type = Some("pairwise".to_owned());

    let err = prepare_client_insert_for_test(payload, None, "http://localhost:8000")
        .await
        .expect_err("pairwise subject registration requires a configured server secret");

    match err {
        InsertClientError::InvalidRequest(message) => assert!(
            message.contains("PAIRWISE_SUBJECT_SECRET"),
            "error should identify the missing pairwise server secret: {message}"
        ),
        other => {
            panic!("pairwise metadata validation must not be reported as server error: {other}")
        }
    }
}

#[actix_web::test]
async fn prepare_client_insert_derives_pairwise_sector_from_single_redirect_host() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "client_secret_basic".to_owned();
    payload.jwks = None;
    payload.subject_type = Some("pairwise".to_owned());
    payload.redirect_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://client.example/alternate".to_owned(),
    ];

    let prepared = prepare_client_insert_for_test(
        payload,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
    )
    .await
    .expect("pairwise registration with one redirect host should be accepted");

    assert_eq!(prepared.subject_type, "pairwise");
    assert!(prepared.sector_identifier_uri.is_none());
    assert_eq!(
        prepared.sector_identifier_host.as_deref(),
        Some("client.example")
    );
}

#[actix_web::test]
async fn prepare_client_insert_rejects_pairwise_redirects_with_multiple_hosts_without_sector_uri() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "client_secret_basic".to_owned();
    payload.jwks = None;
    payload.subject_type = Some("pairwise".to_owned());
    payload.redirect_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://other.example/callback".to_owned(),
    ];

    let err = prepare_client_insert_for_test(
        payload,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
    )
    .await
    .expect_err("multi-host pairwise redirect set requires a sector_identifier_uri");

    match err {
        InsertClientError::InvalidRequest(message) => assert!(
            message.contains("sector_identifier_uri"),
            "error should identify the missing sector identifier boundary: {message}"
        ),
        other => {
            panic!("pairwise metadata validation must not be reported as server error: {other}")
        }
    }
}

#[actix_web::test]
async fn prepare_client_insert_reports_sector_identifier_fetch_failure() {
    let mut payload = create_request();
    payload.token_endpoint_auth_method = "client_secret_basic".to_owned();
    payload.jwks = None;
    payload.subject_type = Some("pairwise".to_owned());
    payload.redirect_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://other.example/callback".to_owned(),
    ];
    payload.sector_identifier_uri = Some("https://sector.invalid/client.json".to_owned());

    let err = prepare_client_insert_for_test(
        payload,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
    )
    .await
    .expect_err("unresolvable sector_identifier_uri must fail registration");

    match err {
        InsertClientError::InvalidRequest(message) => assert!(
            message.contains("sector_identifier_uri 获取失败"),
            "error should identify sector identifier retrieval: {message}"
        ),
        other => {
            panic!("sector identifier validation must not be reported as server error: {other}")
        }
    }
}

#[actix_web::test]
async fn prepare_client_insert_discards_sector_identifier_for_public_subjects() {
    let mut payload = create_request();
    payload.client_type = "public".to_owned();
    payload.token_endpoint_auth_method = "none".to_owned();
    payload.jwks = None;
    payload.subject_type = Some("public".to_owned());
    payload.sector_identifier_uri = Some("https://sector.example/client.json".to_owned());

    let prepared = prepare_client_insert_for_test(payload, None, "http://localhost:8000")
        .await
        .expect("public subjects do not use sector identifiers");

    assert_eq!(prepared.subject_type, "public");
    assert!(prepared.sector_identifier_uri.is_none());
    assert!(prepared.sector_identifier_host.is_none());
}

#[test]
fn insert_client_error_response_preserves_oauth_error_category() {
    let invalid = create_error_response(InsertClientError::InvalidRequest(
        "redirect_uri is invalid".to_owned(),
    ));
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );

    let server = create_error_response(InsertClientError::Repository(
        nazo_auth::AdminClientPortError::Unavailable,
    ));
    assert_eq!(server.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        server
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}
