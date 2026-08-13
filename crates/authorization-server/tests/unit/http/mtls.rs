use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};

use crate::settings::Settings;

use actix_web::http::header;

use actix_web::http::header::HeaderValue;

use serde_json::json;

use uuid::Uuid;

pub(crate) fn request_mtls_thumbprint(req: &HttpRequest, settings: &Settings) -> Option<String> {
    request_mtls_client_certificate(req, settings)?.thumbprint
}

pub(crate) fn request_mtls_client_certificate(
    req: &HttpRequest,
    settings: &Settings,
) -> Option<MtlsClientCertificate> {
    request_mtls_client_certificate_from_trusted_proxy(req, &settings.endpoint.trusted_proxy_cidrs)
}

fn merge_sorted_unique(target: &mut Vec<String>, incoming: Vec<String>) {
    target.extend(incoming);
    target.sort();
    target.dedup();
}

use super::*;
use actix_web::test::TestRequest;
use nazo_http_actix::IpCidr;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
};

struct TestCertificate {
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
        MtlsCertificateSourceMode::from_config(None, false).unwrap(),
        MtlsCertificateSourceMode::Disabled
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("rfc9440"), true).unwrap(),
        MtlsCertificateSourceMode::Rfc9440
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("direct-tls"), false).unwrap(),
        MtlsCertificateSourceMode::DirectTls
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(None, true).unwrap(),
        MtlsCertificateSourceMode::LegacyVerifiedHeaders
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("disabled"), true).unwrap(),
        MtlsCertificateSourceMode::Disabled
    );
    assert_eq!(
        MtlsCertificateSourceMode::from_config(Some("legacy-verified-headers"), true).unwrap(),
        MtlsCertificateSourceMode::LegacyVerifiedHeaders
    );
    assert!(MtlsCertificateSourceMode::from_config(Some("direct"), true).is_err());
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

fn certificate_pem(certificate: &TestCertificate) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        certificate.x5c
    )
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
        x5c: STANDARD.encode(&der),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

fn trusted_proxy_settings() -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://issuer.example".to_owned();
    settings.endpoint.frontend_base_url = "https://app.example".to_owned();
    settings.endpoint.cors_allowed_origins = vec!["https://app.example".to_owned()];
    settings.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("192.0.2.0/24").expect("trusted proxy CIDR")];
    settings.session.cookie_secure = true;
    settings
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
fn certificate_der_identity_rejects_trailing_data() {
    let certificate = test_certificate("client-trailing-data", -60, 3600);
    let mut der = STANDARD.decode(certificate.x5c).unwrap();
    der.extend_from_slice(b"trailing-data");

    assert!(certificate_der_identity(&der).is_none());
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
