use super::*;
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};
use actix_web::test::TestRequest;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Builder, X509Name};

struct TestCertificate {
    x5c: String,
    thumbprint: String,
}

fn client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "tls_client_auth".to_owned(),
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

fn test_private_key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).expect("test rsa key")).expect("test pkey")
}

fn test_certificate(
    common_name: &str,
    not_before_offset: i64,
    not_after_offset: i64,
) -> TestCertificate {
    let key = test_private_key();
    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("test common name");
    let name = name.build();
    let mut builder = X509Builder::new().expect("x509 builder");
    builder.set_version(2).expect("x509 version");
    builder.set_subject_name(&name).expect("x509 subject");
    builder.set_issuer_name(&name).expect("x509 issuer");
    builder.set_pubkey(&key).expect("x509 pubkey");
    let now = Utc::now().timestamp();
    let not_before = Asn1Time::from_unix(now + not_before_offset).expect("x509 not_before");
    let not_after = Asn1Time::from_unix(now + not_after_offset).expect("x509 not_after");
    builder
        .set_not_before(&not_before)
        .expect("set x509 not_before");
    builder
        .set_not_after(&not_after)
        .expect("set x509 not_after");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("sign test cert");
    let der = builder.build().to_der().expect("cert der");
    TestCertificate {
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

fn certificate_pem(certificate: &TestCertificate) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        certificate.x5c
    )
}

fn test_certificate_with_sans() -> TestCertificate {
    let key = test_private_key();
    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "client, one")
        .expect("test common name");
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Example + Org")
        .expect("test organization");
    let name = name.build();
    let mut builder = X509Builder::new().expect("x509 builder");
    builder.set_version(2).expect("x509 version");
    builder.set_subject_name(&name).expect("x509 subject");
    builder.set_issuer_name(&name).expect("x509 issuer");
    builder.set_pubkey(&key).expect("x509 pubkey");
    let now = Utc::now().timestamp();
    let not_before = Asn1Time::from_unix(now - 60).expect("x509 not_before");
    let not_after = Asn1Time::from_unix(now + 3600).expect("x509 not_after");
    builder
        .set_not_before(&not_before)
        .expect("set x509 not_before");
    builder
        .set_not_after(&not_after)
        .expect("set x509 not_after");
    let san = SubjectAlternativeName::new()
        .dns("client.example")
        .dns("api.client.example")
        .uri("urn:client:one")
        .email("client@example.com")
        .ip("192.0.2.44")
        .ip("2001:db8::44")
        .build(&builder.x509v3_context(None, None))
        .expect("subject alternative name");
    builder.append_extension(san).expect("append san");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("sign test cert");
    let der = builder.build().to_der().expect("cert der");
    TestCertificate {
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

fn test_certificate_with_full_subject() -> TestCertificate {
    let key = test_private_key();
    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COUNTRYNAME, "US")
        .expect("test country");
    name.append_entry_by_nid(Nid::STATEORPROVINCENAME, "CA")
        .expect("test state");
    name.append_entry_by_nid(Nid::LOCALITYNAME, "San Francisco")
        .expect("test locality");
    name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Security")
        .expect("test organizational unit");
    name.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, "client@example.com")
        .expect("test email address");
    let name = name.build();
    let mut builder = X509Builder::new().expect("x509 builder");
    builder.set_version(2).expect("x509 version");
    builder.set_subject_name(&name).expect("x509 subject");
    builder.set_issuer_name(&name).expect("x509 issuer");
    builder.set_pubkey(&key).expect("x509 pubkey");
    let now = Utc::now().timestamp();
    let not_before = Asn1Time::from_unix(now - 60).expect("x509 not_before");
    let not_after = Asn1Time::from_unix(now + 3600).expect("x509 not_after");
    builder
        .set_not_before(&not_before)
        .expect("set x509 not_before");
    builder
        .set_not_after(&not_after)
        .expect("set x509 not_after");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("sign test cert");
    let der = builder.build().to_der().expect("cert der");
    TestCertificate {
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

fn trusted_proxy_settings() -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        client_secret_pepper: "client-secret-pepper-for-tests-000000000001".to_owned(),
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
            login_failure_window_seconds: 900,
            login_failure_email_max_attempts: 50,
            login_failure_ip_email_max_attempts: 5,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: vec![IpCidr::parse("192.0.2.0/24").unwrap()],
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            providers: crate::settings::FederationProviderRegistry::default(),
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
        enable_device_authorization_grant: false,
        enable_dynamic_client_registration: false,
        enable_frontchannel_logout: false,
        enable_session_management: false,
        enable_ciba: false,
        enable_native_sso: false,
        dynamic_client_registration_initial_access_token: None,
        device_authorization_ttl_seconds: 600,
        device_authorization_poll_interval_seconds: 5,
        ciba_auth_req_id_ttl_seconds: 600,
        ciba_poll_interval_seconds: 5,
        ciba_automated_decision_token: None,
    }
}

#[test]
fn normalizes_colon_hex_sha256_to_x5t_s256() {
    let raw = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";

    assert_eq!(
        normalize_sha256_thumbprint(raw).as_deref(),
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
    );
}

#[test]
fn rejects_invalid_sha256_thumbprints() {
    assert!(normalize_sha256_thumbprint("not-a-thumbprint").is_none());
    assert!(normalize_sha256_thumbprint(&"a".repeat(63)).is_none());
    assert!(normalize_sha256_thumbprint(&"!".repeat(43)).is_none());
    assert!(normalize_sha256_thumbprint(&URL_SAFE_NO_PAD.encode([0u8; 31])).is_none());
}

#[test]
fn rejects_unverified_proxy_certificate_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
        HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn rejects_conflicting_forwarded_certificate_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
        HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
    );
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-cert-sha256"),
        HeaderValue::from_static("__________________________________________8"),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn rejects_successful_verification_without_binding_material() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn certificate_pem_identity_accepts_escaped_forwarded_pem() {
    let certificate = test_certificate("client-pem", -60, 3600);
    let escaped = certificate_pem(&certificate).replace('\n', "\\n");
    let parsed = certificate_pem_identity(&escaped).expect("forwarded PEM should parse");

    assert_eq!(
        parsed.thumbprint.as_deref(),
        Some(certificate.thumbprint.as_str())
    );
    assert_eq!(parsed.subject_dn.as_deref(), Some("CN=client-pem"));
    assert!(parsed.verified_certificate_expiry);
}

#[test]
fn certificate_pem_identity_extracts_san_values_and_escapes_subject_dn() {
    let certificate = test_certificate_with_sans();
    let parsed = certificate_pem_identity(&certificate_pem(&certificate))
        .expect("forwarded PEM with SAN should parse");

    assert_eq!(
        parsed.subject_dn.as_deref(),
        Some(r"CN=client\, one,O=Example \+ Org")
    );
    assert_eq!(
        parsed.san_dns,
        vec!["api.client.example".to_owned(), "client.example".to_owned()]
    );
    assert_eq!(parsed.san_uri, vec!["urn:client:one".to_owned()]);
    assert_eq!(parsed.san_email, vec!["client@example.com".to_owned()]);
    assert_eq!(
        parsed.san_ip,
        vec!["192.0.2.44".to_owned(), "2001:db8::44".to_owned()]
    );
}

#[test]
fn certificate_pem_identity_extracts_full_subject_dn_names() {
    let certificate = test_certificate_with_full_subject();
    let parsed =
        certificate_pem_identity(&certificate_pem(&certificate)).expect("certificate should parse");

    assert_eq!(
        parsed.subject_dn.as_deref(),
        Some("C=US,ST=CA,L=San Francisco,OU=Security,emailAddress=client@example.com")
    );
}

#[test]
fn certificate_pem_identity_rejects_reversed_pem_markers() {
    assert!(
        certificate_pem_identity("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ninvalid")
            .is_none()
    );
}

#[test]
fn certificate_pem_identity_rejects_future_and_expired_certificates() {
    let future = test_certificate("client-future", 3600, 7200);
    let expired = test_certificate("client-expired", -7200, -3600);

    assert!(certificate_pem_identity(&certificate_pem(&future)).is_none());
    assert!(certificate_pem_identity(&certificate_pem(&expired)).is_none());
}

#[test]
fn accepts_duplicate_matching_forwarded_certificate_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
        HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
    );
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-cert-sha256"),
        HeaderValue::from_static("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"),
    );

    assert_eq!(
        request_mtls_client_certificate_from_headers(&headers)
            .and_then(|certificate| certificate.thumbprint)
            .as_deref(),
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
    );
}

#[test]
fn rejects_conflicting_forwarded_pem_and_direct_thumbprint() {
    let certificate = test_certificate("client-pem", -60, 3600);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
        HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert"),
        HeaderValue::from_str(&urlencoding::encode(&certificate_pem(&certificate))).unwrap(),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn accepts_matching_forwarded_pem_and_direct_identity_material() {
    let certificate = test_certificate_with_sans();
    let parsed = certificate_pem_identity(&certificate_pem(&certificate))
        .expect("test certificate should parse");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
        HeaderValue::from_str(parsed.thumbprint.as_deref().unwrap()).unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-subject-dn"),
        HeaderValue::from_str(parsed.subject_dn.as_deref().unwrap()).unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert"),
        HeaderValue::from_str(&urlencoding::encode(&certificate_pem(&certificate))).unwrap(),
    );

    let merged =
        request_mtls_client_certificate_from_headers(&headers).expect("matching material accepted");
    assert_eq!(merged.thumbprint, parsed.thumbprint);
    assert_eq!(merged.subject_dn, parsed.subject_dn);
    assert_eq!(merged.san_dns, parsed.san_dns);
    assert_eq!(merged.san_uri, parsed.san_uri);
    assert_eq!(merged.san_ip, parsed.san_ip);
    assert_eq!(merged.san_email, parsed.san_email);
    assert!(merged.verified_certificate_expiry);
}

#[test]
fn rejects_conflicting_forwarded_pem_and_san_header() {
    let certificate = test_certificate_with_sans();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-dns"),
        HeaderValue::from_static("victim.example"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert"),
        HeaderValue::from_str(&urlencoding::encode(&certificate_pem(&certificate))).unwrap(),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn accepts_matching_forwarded_pem_and_san_headers() {
    let certificate = test_certificate_with_sans();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-dns"),
        HeaderValue::from_static("client.example, api.client.example"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-uri"),
        HeaderValue::from_static("urn:client:one"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-ip"),
        HeaderValue::from_static("2001:db8::44, 192.0.2.44"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-email"),
        HeaderValue::from_static("client@example.com"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert"),
        HeaderValue::from_str(&urlencoding::encode(&certificate_pem(&certificate))).unwrap(),
    );

    let parsed = certificate_pem_identity(&certificate_pem(&certificate))
        .expect("test certificate should parse");
    let merged = request_mtls_client_certificate_from_headers(&headers)
        .expect("matching SAN material accepted");

    assert_eq!(merged.san_dns, parsed.san_dns);
    assert_eq!(merged.san_uri, parsed.san_uri);
    assert_eq!(merged.san_ip, parsed.san_ip);
    assert_eq!(merged.san_email, parsed.san_email);
}

#[test]
fn rejects_conflicting_duplicate_forwarded_san_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-dns"),
        HeaderValue::from_static("client.example"),
    );
    headers.append(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-dns"),
        HeaderValue::from_static("victim.example"),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn mtls_identity_merge_helpers_are_fail_closed() {
    let mut current = None;
    assert_eq!(merge_matching(&mut current, None), Some(()));
    assert_eq!(current, None);

    assert_eq!(
        merge_matching(&mut current, Some("CN=client".to_owned())),
        Some(())
    );
    assert_eq!(current.as_deref(), Some("CN=client"));
    assert_eq!(
        merge_matching(&mut current, Some("CN=client".to_owned())),
        Some(())
    );
    assert_eq!(
        merge_matching(&mut current, Some("CN=other".to_owned())),
        None
    );

    let mut values = vec!["b.example".to_owned()];
    merge_sorted_unique(
        &mut values,
        vec!["a.example".to_owned(), "b.example".to_owned()],
    );
    assert_eq!(values, vec!["a.example".to_owned(), "b.example".to_owned()]);
}

#[test]
fn client_certificate_matches_registered_subject_dn() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    let certificate = MtlsClientCertificate {
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_matches_registered_thumbprint() {
    let mut client = client();
    client.tls_client_auth_cert_sha256 =
        Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());
    let certificate = MtlsClientCertificate {
        thumbprint: Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8".to_owned()),
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_matches_registered_san_dns() {
    let mut client = client();
    client.tls_client_auth_san_dns = json!(["client.example"]);
    let certificate = MtlsClientCertificate {
        san_dns: vec!["api.client.example".to_owned(), "client.example".to_owned()],
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_matches_registered_san_uri_ip_and_email() {
    let certificate = MtlsClientCertificate {
        san_uri: vec!["urn:client:one".to_owned()],
        san_ip: vec!["192.0.2.44".to_owned()],
        san_email: vec!["client@example.com".to_owned()],
        ..MtlsClientCertificate::default()
    };

    let mut uri_client = client();
    uri_client.tls_client_auth_san_uri = json!(["urn:client:one"]);
    assert!(client_mtls_certificate_matches(&uri_client, &certificate));

    let mut ip_client = client();
    ip_client.tls_client_auth_san_ip = json!(["192.0.2.44"]);
    assert!(client_mtls_certificate_matches(&ip_client, &certificate));

    let mut email_client = client();
    email_client.tls_client_auth_san_email = json!(["client@example.com"]);
    assert!(client_mtls_certificate_matches(&email_client, &certificate));
}

#[test]
fn client_certificate_rejects_unregistered_subject_and_san() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_san_uri = json!(["urn:client:1"]);
    let certificate = MtlsClientCertificate {
        subject_dn: Some("CN=other,O=Example".to_owned()),
        san_uri: vec!["urn:client:2".to_owned()],
        ..MtlsClientCertificate::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_rejects_subject_dn_and_thumbprint_shortcuts() {
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    let certificate = MtlsClientCertificate {
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..MtlsClientCertificate::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));

    client.tls_client_auth_cert_sha256 =
        Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());
    let certificate = MtlsClientCertificate {
        thumbprint: Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8".to_owned()),
        subject_dn: Some("CN=other,O=Example".to_owned()),
        ..MtlsClientCertificate::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_matches_registered_x5c() {
    let registered = test_certificate("client-1", -60, 3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({"keys": [{"kid": "cert-1", "x5c": [registered.x5c]}]}));
    let certificate = MtlsClientCertificate {
        thumbprint: Some(registered.thumbprint),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_ignores_non_leaf_x5c_entries() {
    let leaf = test_certificate("client-leaf", -60, 3600);
    let chain_member = test_certificate("client-chain-member", -60, 3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({
        "keys": [{
            "kid": "cert-chain",
            "x5c": [chain_member.x5c, leaf.x5c]
        }]
    }));
    let certificate = MtlsClientCertificate {
        thumbprint: Some(leaf.thumbprint),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn self_signed_client_certificate_rotation_accepts_only_registered_x5c_set() {
    let old = test_certificate("client-old", -60, 3600);
    let new = test_certificate("client-new", -60, 3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({
        "keys": [
            {"kid": "old", "x5c": [old.x5c.clone()]},
            {"kid": "new", "x5c": [new.x5c.clone()]}
        ]
    }));
    let old_certificate = MtlsClientCertificate {
        thumbprint: Some(old.thumbprint.clone()),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };
    let new_certificate = MtlsClientCertificate {
        thumbprint: Some(new.thumbprint.clone()),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };
    assert!(client_mtls_certificate_matches(&client, &old_certificate));
    assert!(client_mtls_certificate_matches(&client, &new_certificate));

    client.jwks = Some(json!({"keys": [{"kid": "new", "x5c": [new.x5c]}]}));
    assert!(!client_mtls_certificate_matches(&client, &old_certificate));
    assert!(client_mtls_certificate_matches(&client, &new_certificate));
}

#[test]
fn self_signed_client_certificate_rejects_expired_x5c() {
    let expired = test_certificate("client-expired", -7200, -3600);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.jwks = Some(json!({"keys": [{"kid": "expired", "x5c": [expired.x5c]}]}));
    let certificate = MtlsClientCertificate {
        thumbprint: Some(expired.thumbprint),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn rejects_conflicting_forwarded_subject_dn_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-subject-dn"),
        HeaderValue::from_static("CN=client-1,O=Example"),
    );
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-subject-dn"),
        HeaderValue::from_static("CN=client-2,O=Example"),
    );

    assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
}

#[test]
fn extracts_forwarded_subject_dn_and_san_values() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("x-ssl-client-verify"),
        HeaderValue::from_static("SUCCESS"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-subject-dn"),
        HeaderValue::from_static("CN=client-1,O=Example"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-dns"),
        HeaderValue::from_static("client.example, api.client.example"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-uri"),
        HeaderValue::from_static("urn:client:1"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-ip"),
        HeaderValue::from_static("192.0.2.44"),
    );
    headers.insert(
        header::HeaderName::from_static("x-forwarded-tls-client-cert-san-email"),
        HeaderValue::from_static("client@example.com"),
    );

    let certificate =
        request_mtls_client_certificate_from_headers(&headers).expect("certificate identity");
    assert_eq!(
        certificate.subject_dn.as_deref(),
        Some("CN=client-1,O=Example")
    );
    assert_eq!(
        certificate.san_dns,
        vec!["api.client.example".to_owned(), "client.example".to_owned()]
    );
    assert_eq!(certificate.san_uri, vec!["urn:client:1".to_owned()]);
    assert_eq!(certificate.san_ip, vec!["192.0.2.44".to_owned()]);
    assert_eq!(certificate.san_email, vec!["client@example.com".to_owned()]);
}

#[test]
fn mtls_ipaddress_parser_rejects_invalid_san_lengths() {
    assert!(ipaddress_to_string(&[192, 0, 2]).is_none());
}

#[test]
fn ignores_forwarded_certificate_headers_from_untrusted_peer() {
    let settings = trusted_proxy_settings();
    let req = TestRequest::default()
        .peer_addr("198.51.100.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();

    assert!(request_mtls_thumbprint(&req, &settings).is_none());
}

#[test]
fn accepts_forwarded_certificate_headers_from_trusted_peer() {
    let settings = trusted_proxy_settings();
    let req = TestRequest::default()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();

    assert_eq!(
        request_mtls_thumbprint(&req, &settings).as_deref(),
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
    );
}
