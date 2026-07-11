use super::*;

#[test]
fn cross_site_fetch_detection_is_case_insensitive_and_fail_closed() {
    let mut headers = HeaderMap::new();
    let sec_fetch_site = header::HeaderName::from_static("sec-fetch-site");
    assert!(!is_cross_site_fetch(&headers));

    headers.insert(
        sec_fetch_site.clone(),
        HeaderValue::from_static("  Cross-Site  "),
    );
    assert!(is_cross_site_fetch(&headers));

    headers.insert(
        sec_fetch_site.clone(),
        HeaderValue::from_static("same-origin"),
    );
    assert!(!is_cross_site_fetch(&headers));

    headers.insert(
        sec_fetch_site,
        HeaderValue::from_bytes(b"\xff").expect("raw header value can contain non-UTF8 bytes"),
    );
    assert!(
        !is_cross_site_fetch(&headers),
        "malformed Fetch Metadata headers must not be treated as cross-site proof"
    );
}

#[test]
fn pagination_rejects_non_positive_values_and_caps_page_size() {
    let empty = HashMap::new();
    assert_eq!(pagination(&empty), (1, 20, 0));

    let mut query = HashMap::new();
    query.insert("page".to_owned(), "3".to_owned());
    query.insert("page_size".to_owned(), "50".to_owned());
    assert_eq!(pagination(&query), (3, 50, 100));

    query.insert("page".to_owned(), "0".to_owned());
    query.insert("page_size".to_owned(), "1000".to_owned());
    assert_eq!(pagination(&query), (1, 100, 0));

    query.insert("page".to_owned(), "-2".to_owned());
    query.insert("page_size".to_owned(), "-1".to_owned());
    assert_eq!(pagination(&query), (1, 20, 0));
}

#[test]
fn append_query_preserves_invalid_base_and_skips_empty_values() {
    assert_eq!(append_query("not a url", &[("state", "abc")]), "not a url");

    let url = append_query(
        "https://issuer.example/authorize?client_id=client-1",
        &[("state", "abc"), ("nonce", ""), ("scope", "openid profile")],
    );

    assert!(url.starts_with("https://issuer.example/authorize?"));
    assert!(url.contains("client_id=client-1"));
    assert!(url.contains("state=abc"));
    assert!(url.contains("scope=openid+profile"));
    assert!(
        !url.contains("nonce="),
        "empty query values must not be serialized"
    );
}

#[test]
fn admin_user_json_omits_password_hash_and_tenant_context() {
    let user = user_row();
    let value = admin_user_json(user.clone());

    assert_eq!(value["id"], json!(user.id));
    assert_eq!(value["email"], "user@example.com");
    assert_eq!(value["role"], "admin");
    assert_eq!(value["admin_level"], 10);
    assert_eq!(value["is_active"], true);
    assert!(value.get("password_hash").is_none());
    assert!(value.get("tenant_id").is_none());
    assert!(value.get("realm_id").is_none());
    assert!(value.get("organization_id").is_none());
    assert!(value.get("updated_at").is_none());
}

#[test]
fn client_json_exposes_protocol_metadata_without_client_secret_hash() {
    let client = client_row();
    let value = client_json(client.clone());

    assert_eq!(value["client_id"], "client-1");
    assert_eq!(value["client_name"], "Client One");
    assert_eq!(value["client_type"], "confidential");
    assert_eq!(
        value["redirect_uris"],
        json!(["https://client.example/callback"])
    );
    assert_eq!(
        value["post_logout_redirect_uris"],
        json!(["https://client.example/logout"])
    );
    assert_eq!(value["scopes"], json!(["openid", "profile"]));
    assert_eq!(value["allowed_audiences"], json!(["resource://default"]));
    assert_eq!(
        value["grant_types"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(value["token_endpoint_auth_method"], "private_key_jwt");
    assert_eq!(value["require_dpop_bound_tokens"], true);
    assert_eq!(value["require_mtls_bound_tokens"], true);
    assert_eq!(value["tls_client_auth_subject_dn"], "CN=client");
    assert_eq!(value["tls_client_auth_cert_sha256"], "cert-thumbprint");
    assert_eq!(value["tls_client_auth_san_dns"], json!(["client.example"]));
    assert_eq!(value["tls_client_auth_san_uri"], json!(["spiffe://client"]));
    assert_eq!(value["tls_client_auth_san_ip"], json!(["192.0.2.10"]));
    assert_eq!(
        value["tls_client_auth_san_email"],
        json!(["ops@client.example"])
    );
    assert_eq!(value["allow_client_assertion_audience_array"], true);
    assert_eq!(value["allow_client_assertion_endpoint_audience"], true);
    assert_eq!(value["require_par_request_object"], true);
    assert_eq!(value["allow_authorization_code_without_pkce"], false);
    assert_eq!(
        value["backchannel_logout_uri"],
        "https://client.example/backchannel"
    );
    assert_eq!(value["backchannel_logout_session_required"], false);
    assert_eq!(value["jwks"], json!({"keys": []}));
    assert!(value.get("client_secret_hash").is_none());
    assert!(value.get("id").is_none());
    assert!(value.get("tenant_id").is_none());
}

#[test]
fn json_array_to_strings_drops_non_string_values_for_admin_views() {
    let mut client = client_row();
    client.redirect_uris = json!([
        "https://client.example/callback",
        42,
        null,
        {"uri": "https://evil.example/callback"}
    ]);

    let value = client_json(client);
    assert_eq!(
        value["redirect_uris"],
        json!(["https://client.example/callback"]),
        "admin JSON must not stringify malformed JSON array entries into protocol metadata"
    );
}

fn user_row() -> UserRow {
    let now = Utc::now();
    UserRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        username: "user@example.com".to_owned(),
        email: "user@example.com".to_owned(),
        display_name: Some("User".to_owned()),
        avatar_url: Some("https://cdn.example/avatar.png".to_owned()),
        given_name: Some("Given".to_owned()),
        family_name: Some("Family".to_owned()),
        middle_name: None,
        nickname: Some("nick".to_owned()),
        profile_url: Some("https://profile.example/user".to_owned()),
        website_url: Some("https://user.example".to_owned()),
        gender: None,
        birthdate: None,
        zoneinfo: Some("UTC".to_owned()),
        locale: Some("en-US".to_owned()),
        role: "admin".to_owned(),
        admin_level: 10,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: Some("+12025550100".to_owned()),
        phone_number_verified: true,
        email_verified: true,
        mfa_enabled: true,
        password_hash: "argon2-secret-hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

fn client_row() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        client_name: "Client One".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: Some("client-secret-v1:salt:digest".to_owned()),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "profile"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: true,
        tls_client_auth_subject_dn: Some("CN=client".to_owned()),
        tls_client_auth_cert_sha256: Some("cert-thumbprint".to_owned()),
        tls_client_auth_san_dns: json!(["client.example"]),
        tls_client_auth_san_uri: json!(["spiffe://client"]),
        tls_client_auth_san_ip: json!(["192.0.2.10"]),
        tls_client_auth_san_email: json!(["ops@client.example"]),
        allow_client_assertion_audience_array: true,
        allow_client_assertion_endpoint_audience: true,
        require_par_request_object: true,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: Some(json!({"keys": []})),
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!(["https://client.example/logout"]),
        backchannel_logout_uri: Some("https://client.example/backchannel".to_owned()),
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}
