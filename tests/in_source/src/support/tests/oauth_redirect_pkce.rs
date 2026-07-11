use super::*;

fn client_with_redirects(redirect_uris: &[&str]) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(redirect_uris),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "none".to_owned(),
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
fn redirect_uri_uses_single_registered_uri_when_omitted() {
    let client = client_with_redirects(&["https://client.example/callback"]);

    assert_eq!(
        registered_redirect_uri(&client, None).unwrap(),
        "https://client.example/callback"
    );
}

#[test]
fn redirect_uri_requires_exact_match() {
    let client = client_with_redirects(&["https://client.example/callback"]);

    assert_eq!(
        registered_redirect_uri(&client, Some("https://client.example/callback/")),
        Err(RedirectUriError::Invalid)
    );
}

#[test]
fn public_loopback_redirect_uri_allows_runtime_port() {
    let client = client_with_redirects(&["http://127.0.0.1:3000/callback"]);

    assert_eq!(
        registered_redirect_uri(&client, Some("http://127.0.0.1:49152/callback")).unwrap(),
        "http://127.0.0.1:49152/callback"
    );
}

#[test]
fn token_audience_helpers_ignore_malformed_audience_values() {
    assert!(token_audience_values(&json!(true)).is_empty());
    assert!(token_audience_values(&json!({"aud": "resource://default"})).is_empty());
    assert_eq!(
        token_audience_values(&json!(["resource://default", 1, null, "resource://admin"])),
        vec![
            "resource://default".to_owned(),
            "resource://admin".to_owned()
        ]
    );
    assert!(!token_audience_contains(
        &json!(["resource://other", 1]),
        "resource://default"
    ));
}

#[test]
fn pkce_values_follow_rfc7636_length_and_charset() {
    assert!(is_valid_pkce_value(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
    ));
    assert!(!is_valid_pkce_value("short"));
    assert!(!is_valid_pkce_value(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO!"
    ));
}
