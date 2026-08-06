use nazo_digital_credentials::{CredentialTrustError, VcIssuerTrustPolicy};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};

fn leaf_for_dns_name(name: &str) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    CertificateParams::new(vec![name.to_owned()])
        .expect("certificate params")
        .self_signed(&key)
        .expect("self-signed certificate")
        .der()
        .to_vec()
}

fn leaf_for_uri(uri: &str) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let mut params = CertificateParams::default();
    params
        .subject_alt_names
        .push(SanType::URI(uri.try_into().expect("ASCII URI SAN")));
    params
        .self_signed(&key)
        .expect("self-signed certificate")
        .der()
        .to_vec()
}

fn leaf_for_ip_address(address: &str) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let mut params = CertificateParams::default();
    params.subject_alt_names.push(SanType::IpAddress(
        address.parse().expect("test IP address"),
    ));
    params
        .self_signed(&key)
        .expect("self-signed certificate")
        .der()
        .to_vec()
}

#[test]
fn san_binding_rejects_same_ca_style_cross_issuer_host() {
    let leaf = leaf_for_dns_name("issuer-a.example");
    let policy = VcIssuerTrustPolicy::san_bound();

    policy
        .validate("https://issuer-a.example/tenant-a", &leaf)
        .expect("the issuer host is bound to the leaf SAN");
    assert_eq!(
        policy.validate("https://issuer-b.example/tenant-b", &leaf),
        Err(CredentialTrustError::UntrustedIssuer)
    );
}

#[test]
fn allowlist_keeps_same_host_multi_tenant_explicit() {
    let leaf = leaf_for_dns_name("issuer.example");
    let policy = VcIssuerTrustPolicy::allowlisted([
        "https://issuer.example/tenant-a",
        "https://issuer.example/tenant-b",
    ]);

    policy
        .validate("https://issuer.example/tenant-a", &leaf)
        .expect("tenant-a is explicitly registered");
    policy
        .validate("https://issuer.example/tenant-b", &leaf)
        .expect("tenant-b is explicitly registered");
    assert_eq!(
        policy.validate("https://issuer.example/tenant-c", &leaf),
        Err(CredentialTrustError::UntrustedIssuer)
    );
}

#[test]
fn wildcard_san_does_not_bind_an_issuer() {
    let leaf = leaf_for_dns_name("*.example");
    let policy = VcIssuerTrustPolicy::san_bound();

    assert_eq!(
        policy.validate("https://issuer.example", &leaf),
        Err(CredentialTrustError::UntrustedIssuer)
    );
}

#[test]
fn exact_uri_san_can_bind_a_non_dns_issuer_identity() {
    let issuer = "https://issuer.example/tenant-a";
    let leaf = leaf_for_uri(issuer);
    let policy = VcIssuerTrustPolicy::san_bound();

    policy
        .validate(issuer, &leaf)
        .expect("the exact URI SAN is an issuer identity");
    assert_eq!(
        policy.validate("https://issuer.example/tenant-b", &leaf),
        Err(CredentialTrustError::UntrustedIssuer)
    );
}

#[test]
fn default_policy_is_the_san_bound_policy() {
    assert_eq!(
        VcIssuerTrustPolicy::default(),
        VcIssuerTrustPolicy::san_bound()
    );
}

#[test]
fn issuer_validation_rejects_malformed_or_credential_bearing_urls() {
    let policy = VcIssuerTrustPolicy::san_bound();

    for issuer in [
        "not a URL",
        "http://issuer.example",
        "https:///tenant-a",
        "https://user@issuer.example",
        "https://user:password@issuer.example",
        "https://issuer.example?tenant=tenant-a",
        "https://issuer.example#tenant-a",
    ] {
        assert_eq!(
            policy.validate(issuer, b"not a certificate"),
            Err(CredentialTrustError::UntrustedIssuer),
            "issuer URL must be rejected: {issuer}"
        );
    }
}

#[test]
fn allowlist_can_fail_closed_and_invalid_certificates_are_untrusted() {
    let leaf = leaf_for_dns_name("issuer.example");
    assert_eq!(
        VcIssuerTrustPolicy::allowlisted(std::iter::empty::<&str>())
            .validate("https://issuer.example", &leaf),
        Err(CredentialTrustError::UntrustedIssuer)
    );
    assert_eq!(
        VcIssuerTrustPolicy::san_bound().validate("https://issuer.example", b"not a certificate"),
        Err(CredentialTrustError::UntrustedIssuer)
    );
}

#[test]
fn non_dns_san_types_do_not_bind_an_issuer() {
    let leaf = leaf_for_ip_address("192.0.2.44");

    assert_eq!(
        VcIssuerTrustPolicy::san_bound().validate("https://192.0.2.44", &leaf),
        Err(CredentialTrustError::UntrustedIssuer)
    );
}
