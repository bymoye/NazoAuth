use nazo_key_management::{MtlsTrustAnchorError, validate_mtls_trust_anchor};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};

fn certificate(ca: bool, include_key_cert_sign: bool) -> String {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Trust Anchor Boundary Test");
    params.is_ca = if ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
    params.key_usages = if include_key_cert_sign {
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
    } else {
        vec![KeyUsagePurpose::DigitalSignature]
    };
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::hours(1);
    params
        .self_signed(&key)
        .expect("self-signed certificate")
        .pem()
}

#[test]
fn accepts_current_strong_ca_and_canonicalizes_pem() {
    let pem = certificate(true, true);

    let validated = validate_mtls_trust_anchor(&pem).expect("valid CA");

    assert_eq!(validated.certificate_sha256.len(), 64);
    assert!(validated.subject_dn.contains("Trust Anchor Boundary Test"));
    assert!(
        validated
            .certificate_pem
            .ends_with("-----END CERTIFICATE-----\n")
    );
    assert!(validated.not_before < validated.not_after);
}

#[test]
fn rejects_leaf_and_ca_without_key_cert_sign() {
    let leaf = certificate(false, false);
    assert_eq!(
        validate_mtls_trust_anchor(&leaf),
        Err(MtlsTrustAnchorError::NotCertificateAuthority)
    );

    let ca = certificate(true, false);
    assert_eq!(
        validate_mtls_trust_anchor(&ca),
        Err(MtlsTrustAnchorError::InvalidKeyUsage)
    );
}

#[test]
fn rejects_multiple_certificates_and_oversized_input() {
    let pem = certificate(true, true);
    assert_eq!(
        validate_mtls_trust_anchor(&format!("{pem}{pem}")),
        Err(MtlsTrustAnchorError::InvalidPem)
    );
    assert_eq!(
        validate_mtls_trust_anchor(&"A".repeat(16 * 1024 + 1)),
        Err(MtlsTrustAnchorError::TooLarge)
    );
}
