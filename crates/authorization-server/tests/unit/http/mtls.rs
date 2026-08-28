use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};

use actix_web::http::header;

use actix_web::http::header::HeaderValue;

use serde_json::json;

use uuid::Uuid;

use super::*;
use actix_web::test::TestRequest;
use nazo_http_actix::IpCidr;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
};

struct TestCertificate {
    der: Vec<u8>,
    x5c: String,
    thumbprint: String,
}

fn client() -> ClientRow {
    client_row! {
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
fn rfc9440_client_cert_uses_single_der_byte_sequence() {
    let certificate = test_certificate("rfc9440-client", -60, 60);
    let headers = {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("client-cert"),
            HeaderValue::from_str(&format!(":{}:", certificate.x5c)).unwrap(),
        );
        headers
    };
    let parsed =
        request_mtls_client_certificate_from_rfc9440(&headers).expect("valid RFC 9440 certificate");
    assert_eq!(
        parsed.thumbprint.as_deref(),
        Some(certificate.thumbprint.as_str())
    );

    let mut duplicate = headers;
    duplicate.append(
        header::HeaderName::from_static("client-cert"),
        HeaderValue::from_static(":AA==:"),
    );
    assert!(request_mtls_client_certificate_from_rfc9440(&duplicate).is_none());

    for malformed in ["::", ":AA AA:", "AA==", ":AA=="] {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("client-cert"),
            HeaderValue::from_str(malformed).unwrap(),
        );
        assert!(request_mtls_client_certificate_from_rfc9440(&headers).is_none());
    }
}

#[test]
fn mtls_certificate_source_requires_explicit_supported_mode() {
    assert_eq!(
        MtlsCertificateSourceMode::from_config(None).unwrap(),
        MtlsCertificateSourceMode::Disabled
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("rfc9440")).unwrap(),
        MtlsCertificateSourceMode::Rfc9440
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("direct-tls")).unwrap(),
        MtlsCertificateSourceMode::DirectTls
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("disabled")).unwrap(),
        MtlsCertificateSourceMode::Disabled
    );
    assert!(MtlsCertificateSourceMode::from_config(Some("legacy-verified-headers")).is_err());
    assert!(MtlsCertificateSourceMode::from_config(Some("direct")).is_err());
}

#[test]
fn disabled_certificate_source_cannot_fall_back_to_forwarded_headers() {
    let disabled = TestRequest::default()
        .app_data(Data::new(MtlsCertificateSource::new(
            MtlsCertificateSourceMode::Disabled,
        )))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .to_http_request();
    assert!(request_mtls_client_certificate_from_configured_source(&disabled, &[]).is_none());
}

#[test]
fn rfc9440_source_accepts_only_a_trusted_peer() {
    let certificate = test_certificate("rfc9440-request", -60, 3600);
    let source = Data::new(MtlsCertificateSource::new(
        MtlsCertificateSourceMode::Rfc9440,
    ));
    let trusted_proxy = [IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];
    let header_value = format!(":{}:", certificate.x5c);

    let trusted = TestRequest::default()
        .app_data(source.clone())
        .peer_addr("192.0.2.10:443".parse().expect("trusted peer address"))
        .insert_header(("client-cert", header_value.as_str()))
        .to_http_request();
    assert_eq!(
        request_mtls_client_certificate_from_configured_source(&trusted, &trusted_proxy)
            .and_then(|certificate| certificate.thumbprint)
            .as_deref(),
        Some(certificate.thumbprint.as_str())
    );

    let untrusted = TestRequest::default()
        .app_data(source)
        .peer_addr("198.51.100.10:443".parse().expect("untrusted peer address"))
        .insert_header(("client-cert", header_value.as_str()))
        .to_http_request();
    assert!(
        request_mtls_client_certificate_from_configured_source(&untrusted, &trusted_proxy)
            .is_none()
    );
}

#[test]
fn rfc9440_source_ignores_removed_nonstandard_headers() {
    let request = TestRequest::default()
        .app_data(Data::new(MtlsCertificateSource::new(
            MtlsCertificateSourceMode::Rfc9440,
        )))
        .peer_addr("192.0.2.10:443".parse().expect("trusted peer address"))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();
    let trusted_proxy = [IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];

    assert!(
        request_mtls_client_certificate_from_configured_source(&request, &trusted_proxy).is_none()
    );
}

fn test_certificate(
    common_name: &str,
    not_before_offset: i64,
    not_after_offset: i64,
) -> TestCertificate {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::seconds(not_before_offset);
    params.not_after = now + time::Duration::seconds(not_after_offset);
    finish_test_certificate(params)
}

fn test_certificate_with_sans() -> TestCertificate {
    let mut params = current_test_certificate_params();
    params
        .distinguished_name
        .push(DnType::CommonName, "client, one");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Example + Org");
    params.subject_alt_names = vec![
        SanType::DnsName("client.example".try_into().unwrap()),
        SanType::DnsName("api.client.example".try_into().unwrap()),
        SanType::URI("urn:client:one".try_into().unwrap()),
        SanType::Rfc822Name("client@example.com".try_into().unwrap()),
        SanType::IpAddress("192.0.2.44".parse().unwrap()),
        SanType::IpAddress("2001:db8::44".parse().unwrap()),
    ];
    finish_test_certificate(params)
}

fn test_certificate_with_full_subject() -> TestCertificate {
    let mut params = current_test_certificate_params();
    params.distinguished_name.push(DnType::CountryName, "US");
    params
        .distinguished_name
        .push(DnType::StateOrProvinceName, "CA");
    params
        .distinguished_name
        .push(DnType::LocalityName, "San Francisco");
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "Security");
    params.distinguished_name.push(
        DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
        "client@example.com",
    );
    finish_test_certificate(params)
}

fn current_test_certificate_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::hours(1);
    params
}

fn finish_test_certificate(params: CertificateParams) -> TestCertificate {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let der = params
        .self_signed(&key)
        .expect("test certificate")
        .der()
        .to_vec();
    TestCertificate {
        der: der.clone(),
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
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
fn certificate_der_identity_rejects_trailing_data() {
    let certificate = test_certificate("client-trailing-data", -60, 3600);
    let mut der = STANDARD.decode(certificate.x5c).unwrap();
    der.extend_from_slice(b"trailing-data");

    assert!(certificate_der_identity(&der).is_none());
}

#[test]
fn certificate_der_identity_extracts_san_values_and_escapes_subject_dn() {
    let certificate = test_certificate_with_sans();
    let parsed = certificate_der_identity(&certificate.der).expect("certificate should parse");

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
fn certificate_der_identity_extracts_full_subject_dn_names() {
    let certificate = test_certificate_with_full_subject();
    let parsed = certificate_der_identity(&certificate.der).expect("certificate should parse");

    assert_eq!(
        parsed.subject_dn.as_deref(),
        Some("C=US,ST=CA,L=San Francisco,OU=Security,emailAddress=client@example.com")
    );
}

#[test]
fn certificate_der_identity_rejects_future_and_expired_certificates() {
    let future = test_certificate("client-future", 3600, 7200);
    assert!(certificate_der_identity(&future.der).is_none());

    let expired = test_certificate("client-expired", -7200, -3600);
    assert!(certificate_der_identity(&expired.der).is_none());
}

#[test]
fn client_certificate_matches_registered_subject_dn() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    let certificate = MtlsClientCertificate {
        subject_dn: Some("CN=CLIENT-1,O=example".to_owned()),
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn administrator_thumbprint_pin_can_only_narrow_registered_subject_match() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_cert_sha256 =
        Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());
    let certificate = MtlsClientCertificate {
        thumbprint: Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8".to_owned()),
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));

    let wrong_subject = MtlsClientCertificate {
        thumbprint: certificate.thumbprint.clone(),
        subject_dn: Some("CN=other,O=Example".to_owned()),
        ..MtlsClientCertificate::default()
    };
    assert!(!client_mtls_certificate_matches(&client, &wrong_subject));

    let mut pin_without_standard_subject = client;
    pin_without_standard_subject.tls_client_auth_subject_dn = None;
    assert!(!client_mtls_certificate_matches(
        &pin_without_standard_subject,
        &certificate
    ));
}

#[test]
fn client_certificate_matches_registered_san_dns() {
    let mut client = client();
    client.tls_client_auth_san_dns = vec!["client.example".to_owned()];
    let certificate = MtlsClientCertificate {
        san_dns: vec!["api.client.example".to_owned(), "CLIENT.EXAMPLE".to_owned()],
        ..MtlsClientCertificate::default()
    };

    assert!(client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_matches_registered_san_uri_ip_and_email() {
    let certificate = MtlsClientCertificate {
        san_uri: vec!["urn:client:one".to_owned()],
        san_ip: vec!["2001:db8::2c".to_owned()],
        san_email: vec!["client@EXAMPLE.COM".to_owned()],
        ..MtlsClientCertificate::default()
    };

    let mut uri_client = client();
    uri_client.tls_client_auth_san_uri = vec!["urn:client:one".to_owned()];
    assert!(client_mtls_certificate_matches(&uri_client, &certificate));

    let mut ip_client = client();
    ip_client.tls_client_auth_san_ip = vec!["2001:0db8:0000:0000:0000:0000:0000:002c".to_owned()];
    assert!(client_mtls_certificate_matches(&ip_client, &certificate));

    let mut email_client = client();
    email_client.tls_client_auth_san_email = vec!["client@example.com".to_owned()];
    assert!(client_mtls_certificate_matches(&email_client, &certificate));
}

#[test]
fn client_certificate_rejects_unregistered_subject_and_san() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_san_uri = vec!["urn:client:1".to_owned()];
    let certificate = MtlsClientCertificate {
        subject_dn: Some("CN=other,O=Example".to_owned()),
        san_uri: vec!["urn:client:2".to_owned()],
        ..MtlsClientCertificate::default()
    };

    assert!(!client_mtls_certificate_matches(&client, &certificate));
}

#[test]
fn client_certificate_rejects_legacy_rows_with_multiple_rfc8705_selectors() {
    let mut client = client();
    client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
    client.tls_client_auth_san_dns = vec!["client.example".to_owned()];
    let certificate = MtlsClientCertificate {
        subject_dn: Some("CN=client-1,O=Example".to_owned()),
        san_dns: vec!["client.example".to_owned()],
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
fn mtls_ipaddress_parser_rejects_invalid_san_lengths() {
    assert!(ipaddress_to_string(&[192, 0, 2]).is_none());
}
