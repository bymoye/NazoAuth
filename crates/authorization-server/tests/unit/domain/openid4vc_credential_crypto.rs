use std::{path::PathBuf, sync::Arc, time::Duration as StdDuration};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use coset::{CoseKeyBuilder, SignatureContext, iana};
use jsonwebtoken::{Algorithm, EncodingKey, Header, decode, decode_header, encode};
use mdoc_rs::{
    MdocError,
    builder::{CoseSigner, DocumentBuilder},
    model::types::ValidityInfo,
    response_builder::DeviceResponseBuilder,
    session::SessionTranscript,
};
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialFormat, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError, HolderBinding, PresentedCredential, VcIssuerTrustPolicy,
};
use p256::{
    ecdsa::{SigningKey, signature::Signer as _},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use sha2::Digest as _;
use uuid::Uuid;

use super::*;

trait CredentialCryptoTestExt {
    fn verify_sd_jwt(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    >;

    fn validate_sd_jwt_chain(
        &self,
        x5c: &[String],
        additional_trust_anchors: &[Vec<u8>],
    ) -> Result<super::sd_jwt::ValidatedSdJwtChain, nazo_digital_credentials::CredentialTrustError>;

    fn verify_mdoc(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    >;
}

impl CredentialCryptoTestExt for Openid4vcCredentialCrypto {
    fn verify_sd_jwt(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    > {
        super::sd_jwt::verify(self, presentation)
    }

    fn validate_sd_jwt_chain(
        &self,
        x5c: &[String],
        additional_trust_anchors: &[Vec<u8>],
    ) -> Result<super::sd_jwt::ValidatedSdJwtChain, nazo_digital_credentials::CredentialTrustError>
    {
        super::sd_jwt::validate_sd_jwt_chain(self, x5c, additional_trust_anchors)
    }

    fn verify_mdoc(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    > {
        super::mdoc::verify(self, presentation)
    }
}

struct CertificateFixture {
    ca_der: Vec<u8>,
    ca_pem: String,
    leaf_der: Vec<u8>,
    leaf_pem: String,
    leaf_key: KeyPair,
}

fn certificate_fixture(host: &str) -> CertificateFixture {
    let now = time::OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenID4VC test root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::days(365);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-signed CA");

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec![host.to_owned()]).expect("leaf SAN");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, host);
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::days(365);
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca)
        .expect("leaf certificate");

    CertificateFixture {
        ca_der: ca.der().as_ref().to_vec(),
        ca_pem: ca.pem(),
        leaf_der: leaf.der().as_ref().to_vec(),
        leaf_pem: leaf.pem(),
        leaf_key,
    }
}

fn certificate_without_san() -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    CertificateParams::default()
        .self_signed(&key)
        .expect("certificate without SAN")
        .der()
        .as_ref()
        .to_vec()
}

async fn real_crypto_fixture() -> (Openid4vcCredentialCrypto, CertificateFixture, PathBuf) {
    let certs = certificate_fixture("issuer.example");
    let key_dir = std::env::temp_dir().join(format!(
        "nazo-openid4vc-credential-crypto-{}",
        Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&key_dir).expect("credential key directory");
    std::fs::write(
        key_dir.join("credential-test.pem"),
        certs.leaf_key.serialize_pem(),
    )
    .expect("credential private key");
    std::fs::write(
        key_dir.join("keyset.json"),
        serde_json::to_vec_pretty(&json!({
            "active_kid": "credential-test",
            "keys": [{
                "kid": "credential-test",
                "alg": "ES256",
                "file": "credential-test.pem",
                "created_at": Utc::now().to_rfc3339(),
                "retire_at": Value::Null,
                "purposes": ["credential", "presentation_request"]
            }]
        }))
        .expect("credential keyset JSON"),
    )
    .expect("credential keyset");
    let settings = nazo_key_management::KeySettings {
        keys_dir: key_dir.clone(),
        external_command: Vec::new(),
        external_timeout: StdDuration::from_secs(1),
        rotation_interval: chrono::Duration::days(1),
        prepublish_window: chrono::Duration::hours(1),
        verification_grace: chrono::Duration::hours(1),
    };
    let keyset = nazo_key_management::KeyManager::load_or_create(settings)
        .await
        .expect("credential keyset should load");
    let chain_pem = format!("{}{}", certs.leaf_pem, certs.ca_pem);
    let crypto = Openid4vcCredentialCrypto::new_with_policies(
        keyset,
        chain_pem.as_bytes(),
        certs.ca_pem.as_bytes(),
        VcIssuerTrustPolicy::san_bound(),
        CertificateRevocationPolicy::disabled(),
    )
    .expect("credential crypto should validate the generated chain");
    (crypto, certs, key_dir)
}

fn crypto_with_certificate(
    keyset: nazo_key_management::KeyManager,
    certs: &CertificateFixture,
) -> Openid4vcCredentialCrypto {
    Openid4vcCredentialCrypto {
        keyset,
        x5c: Arc::new(vec![STANDARD.encode(&certs.leaf_der)]),
        leaf_der: Arc::new(certs.leaf_der.clone()),
        trust_anchors: Arc::new(vec![certs.ca_der.clone()]),
        issuer_trust_policy: VcIssuerTrustPolicy::san_bound(),
        revocation_policy: CertificateRevocationPolicy::disabled(),
    }
}

struct TestMdocIssuerSigner {
    signing_key: SigningKey,
    certificate_der: Vec<u8>,
}

impl CoseSigner for TestMdocIssuerSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, MdocError> {
        let signature: p256::ecdsa::Signature = self.signing_key.sign(tbs);
        Ok(signature.to_bytes().to_vec())
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}

fn valid_mdoc_presentation(certs: &CertificateFixture) -> (String, Vec<u8>) {
    let issuer_secret =
        p256::SecretKey::from_pkcs8_der(&certs.leaf_key.serialize_der()).expect("leaf private key");
    let issuer_signing_key =
        SigningKey::from_slice(&issuer_secret.to_bytes()).expect("leaf signing key");
    let device_signing_key = SigningKey::from_slice(&[83; 32]).expect("device signing key");
    let device_point = device_signing_key.verifying_key().to_sec1_point(false);
    let device_key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        device_point.x().expect("device x").to_vec(),
        device_point.y().expect("device y").to_vec(),
    )
    .build();
    let now = Utc::now();
    let issuer_document = DocumentBuilder::new("org.iso.18013.5.1.mDL")
        .device_key(device_key)
        .validity(ValidityInfo {
            signed: now,
            valid_from: now - Duration::minutes(1),
            valid_until: now + Duration::hours(1),
            expected_update: None,
        })
        .add_namespace(
            "org.iso.18013.5.1",
            vec![
                ("given_name", ciborium::Value::Text("Ada".to_owned())),
                ("age", ciborium::Value::Integer(42.into())),
            ],
        )
        .sign(&TestMdocIssuerSigner {
            signing_key: issuer_signing_key,
            certificate_der: certs.leaf_der.clone(),
        })
        .expect("issuer-signed mdoc");
    let transcript = SessionTranscript::Oid4vp {
        mdoc_nonce: "mdoc-nonce".to_owned(),
        client_id: "https://verifier.example".to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        verifier_nonce: "verifier-nonce".to_owned(),
    };
    let transcript_bytes = transcript.to_cbor_bytes().expect("session transcript");
    let device_key_der = device_signing_key.to_bytes().to_vec();
    let mut response = DeviceResponseBuilder::from_documents(vec![issuer_document])
        .session_transcript(transcript)
        .authenticate_with_signature(device_key_der, -7)
        .build()
        .expect("device response");
    let document = response
        .documents
        .first_mut()
        .expect("device response document");
    let device_signed = document
        .device_signed
        .as_mut()
        .expect("device-signed response");
    let mdoc_rs::model::types::DeviceAuth::Signature(device_signature) =
        &mut device_signed.device_auth
    else {
        panic!("device response should use a signature");
    };
    let device_authentication = standard_device_authentication_bytes(
        &transcript_bytes,
        &document.doc_type,
        &device_signed.name_spaces_bytes,
    )
    .expect("standard DeviceAuthenticationBytes");
    let signature_input = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        &[],
        &device_authentication,
    );
    let signature: p256::ecdsa::Signature = device_signing_key.sign(&signature_input);
    device_signature.payload = None;
    device_signature.signature = signature.to_bytes().to_vec();
    (
        URL_SAFE_NO_PAD.encode(
            response
                .to_device_response_cbor()
                .expect("device response CBOR"),
        ),
        transcript_bytes,
    )
}

fn sd_input(
    holder_binding: Option<HolderBinding>,
    subject_claims: Value,
    status: Option<Value>,
) -> CredentialSignInput {
    let issued_at = Utc::now() - Duration::minutes(1);
    CredentialSignInput {
        payload: nazo_digital_credentials::CredentialPayload {
            format: CredentialFormat::SdJwtVc,
            issuer: "https://issuer.example".to_owned(),
            configuration_id: "example-sd-jwt".to_owned(),
            credential_type: "ExampleCredential".to_owned(),
            subject_claims,
            holder_binding,
            selectively_disclosable_claims: vec![],
        },
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        status,
    }
}

fn mdoc_input(holder_binding: Option<HolderBinding>, subject_claims: Value) -> CredentialSignInput {
    let issued_at = Utc::now() - Duration::minutes(1);
    CredentialSignInput {
        payload: nazo_digital_credentials::CredentialPayload {
            format: CredentialFormat::MsoMdoc,
            issuer: "https://issuer.example".to_owned(),
            configuration_id: "example-mdoc".to_owned(),
            credential_type: "org.iso.18013.5.1.mDL".to_owned(),
            subject_claims,
            holder_binding,
            selectively_disclosable_claims: vec![],
        },
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        status: None,
    }
}

fn es256_jwk(seed: u8) -> (Value, EncodingKey) {
    let signing_key = SigningKey::from_slice(&[seed; 32]).expect("P-256 key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("y")),
    });
    let der = signing_key.to_pkcs8_der().expect("PKCS#8");
    (jwk, EncodingKey::from_ec_der(der.as_bytes()))
}

fn sd_presentation_fixture() -> (
    Openid4vcCredentialCrypto,
    PresentedCredential,
    Value,
    CertificateFixture,
) {
    let certs = certificate_fixture("issuer.example");
    let (holder_jwk, holder_key) = es256_jwk(71);
    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let disclosure = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!(["salt", "given_name", "Ada"])).expect("disclosure"));
    let issued_at = Utc::now() - Duration::minutes(1);
    let credential_claims = json!({
        "iss": "https://issuer.example",
        "iat": issued_at.timestamp(),
        "nbf": issued_at.timestamp(),
        "exp": (issued_at + Duration::hours(1)).timestamp(),
        "vct": "ExampleCredential",
        "_sd_alg": "sha-256",
        "_sd": [URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(disclosure.as_bytes()))],
        "cnf": {"jwk": holder_jwk},
        "status": {"idx": 3},
    });
    let mut credential_header = Header::new(Algorithm::ES256);
    credential_header.typ = Some("dc+sd-jwt".to_owned());
    credential_header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let credential_jwt =
        encode(&credential_header, &credential_claims, &issuer_key).expect("credential JWT");
    let expected_audience = "https://verifier.example";
    let expected_nonce = "nonce-1";
    let sd_input = format!("{credential_jwt}~{disclosure}~");
    let mut kb_header = Header::new(Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".to_owned());
    let kb_jwt = encode(
        &kb_header,
        &json!({
            "nonce": expected_nonce,
            "aud": expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(sd_input.as_bytes())),
        }),
        &holder_key,
    )
    .expect("key binding JWT");
    let encoded = format!("{credential_jwt}~{disclosure}~{kb_jwt}");
    let presentation = PresentedCredential {
        format: CredentialFormat::SdJwtVc,
        encoded,
        expected_nonce: expected_nonce.to_owned(),
        expected_audience: expected_audience.to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        mdoc_session_transcript: None,
        additional_trust_anchors: vec![],
    };
    let crypto = Openid4vcCredentialCrypto {
        keyset: nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        x5c: Arc::new(vec![STANDARD.encode(&certs.leaf_der)]),
        leaf_der: Arc::new(certs.leaf_der.clone()),
        trust_anchors: Arc::new(vec![certs.ca_der.clone()]),
        issuer_trust_policy: VcIssuerTrustPolicy::san_bound(),
        revocation_policy: CertificateRevocationPolicy::disabled(),
    };
    (crypto, presentation, json!("Ada"), certs)
}

#[test]
fn conformance_trust_anchor_requires_one_current_ca() {
    let certs = certificate_fixture("issuer.example");
    assert_eq!(
        parse_conformance_credential_trust_anchor(&certs.ca_pem).expect("valid CA"),
        certs.ca_der
    );
    assert!(parse_conformance_credential_trust_anchor("").is_err());
    assert!(
        parse_conformance_credential_trust_anchor(&format!("{}{}", certs.ca_pem, certs.ca_pem))
            .is_err()
    );
    assert!(parse_conformance_credential_trust_anchor(&certs.leaf_pem).is_err());
    assert!(
        parse_conformance_credential_trust_anchor(
            "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----"
        )
        .is_err()
    );
}

#[test]
fn constructor_fails_closed_for_empty_untrusted_or_mismatched_certificate_inputs() {
    let certs = certificate_fixture("issuer.example");
    let keyset = nazo_key_management::KeyManager::for_test(Algorithm::ES256);
    assert!(
        Openid4vcCredentialCrypto::new_with_policies(
            keyset.clone(),
            b"",
            certs.ca_pem.as_bytes(),
            VcIssuerTrustPolicy::san_bound(),
            CertificateRevocationPolicy::disabled(),
        )
        .is_err()
    );
    assert!(
        Openid4vcCredentialCrypto::new_with_policies(
            keyset.clone(),
            certs.leaf_pem.as_bytes(),
            b"not a certificate",
            VcIssuerTrustPolicy::san_bound(),
            CertificateRevocationPolicy::disabled(),
        )
        .is_err()
    );
    assert!(
        Openid4vcCredentialCrypto::new_with_policies(
            keyset.clone(),
            certs.ca_pem.as_bytes(),
            certs.ca_pem.as_bytes(),
            VcIssuerTrustPolicy::san_bound(),
            CertificateRevocationPolicy::disabled(),
        )
        .is_err()
    );
    assert!(
        Openid4vcCredentialCrypto::new_with_policies(
            keyset,
            format!("{}{}", certs.leaf_pem, certs.ca_pem).as_bytes(),
            certs.ca_pem.as_bytes(),
            VcIssuerTrustPolicy::san_bound(),
            CertificateRevocationPolicy::disabled(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn request_and_metadata_signing_emit_required_jose_headers() {
    let (crypto, certs, key_dir) = real_crypto_fixture().await;
    let expected_x5c = vec![STANDARD.encode(&certs.leaf_der)];
    let request = crypto
        .sign_request_object(&json!({"client_id": "wallet", "response_type": ["vp_token"]}))
        .await
        .expect("request object");
    let request_header = decode_header(&request).expect("request header");
    assert_eq!(request_header.typ.as_deref(), Some("oauth-authz-req+jwt"));
    assert_eq!(request_header.alg, Algorithm::ES256);
    assert_eq!(request_header.kid.as_deref(), Some("credential-test"));
    assert_eq!(request_header.x5c.as_ref(), Some(&expected_x5c));

    let metadata = crypto
        .sign_issuer_metadata(&json!({"credential_issuer": "https://issuer.example"}))
        .await
        .expect("issuer metadata");
    let metadata_header = decode_header(&metadata).expect("metadata header");
    assert_eq!(
        metadata_header.typ.as_deref(),
        Some("openidvci-issuer-metadata+jwt")
    );
    assert_eq!(metadata_header.alg, Algorithm::ES256);
    assert_eq!(metadata_header.kid.as_deref(), Some("credential-test"));
    assert_eq!(metadata_header.x5c.as_ref(), Some(&expected_x5c));
    let _ = std::fs::remove_dir_all(key_dir);
}

#[tokio::test]
async fn request_and_metadata_signing_map_key_failures_to_errors() {
    let certs = certificate_fixture("issuer.example");
    let failing_keyset = nazo_key_management::KeyManager::for_test_behavior(
        Algorithm::ES256,
        nazo_key_management::TestSigningBehavior::Failing,
    );
    let crypto = crypto_with_certificate(failing_keyset, &certs);
    assert!(
        crypto
            .sign_request_object(&json!({"iss": "issuer"}))
            .await
            .is_err()
    );
    assert!(
        crypto
            .sign_issuer_metadata(&json!({"iss": "issuer"}))
            .await
            .is_err()
    );
}

#[test]
fn certificate_client_ids_bind_to_hash_and_dns_san() {
    let certs = certificate_fixture("issuer.example");
    let crypto = Openid4vcCredentialCrypto {
        keyset: nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        x5c: Arc::new(vec![]),
        leaf_der: Arc::new(certs.leaf_der.clone()),
        trust_anchors: Arc::new(vec![]),
        issuer_trust_policy: VcIssuerTrustPolicy::san_bound(),
        revocation_policy: CertificateRevocationPolicy::disabled(),
    };
    assert_eq!(
        crypto.x509_hash_client_id(),
        format!(
            "x509_hash:{}",
            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&certs.leaf_der))
        )
    );
    assert_eq!(
        crypto.x509_san_dns_client_id().expect("DNS SAN"),
        "x509_san_dns:issuer.example"
    );
    let no_san_crypto = Openid4vcCredentialCrypto {
        leaf_der: Arc::new(certificate_without_san()),
        ..crypto
    };
    assert!(no_san_crypto.x509_san_dns_client_id().is_err());
}

#[tokio::test]
async fn sd_jwt_signing_supports_disclosures_holder_binding_and_status() {
    let (holder_jwk, _) = es256_jwk(17);
    let input = sd_input(
        Some(HolderBinding::Jwk {
            jwk: holder_jwk.clone(),
        }),
        json!({"given_name": "Ada", "age": 42}),
        Some(json!({"idx": 2, "uri": "https://status.example"})),
    );
    let (crypto, certs, key_dir) = real_crypto_fixture().await;
    let (_, leaf) = x509_parser::parse_x509_certificate(&certs.leaf_der).expect("leaf certificate");
    let decoding_key =
        jsonwebtoken::DecodingKey::from_ec_der(leaf.public_key().subject_public_key.data.as_ref());
    let encoded = crypto.sign(&input).await.expect("SD-JWT signing");
    let parts = encoded.split('~').collect::<Vec<_>>();
    assert_eq!(parts.len(), 4);
    assert!(parts[0].split('.').count() == 3);
    assert_eq!(parts.last(), Some(&""));
    let header = decode_header(parts[0]).expect("SD-JWT header");
    assert_eq!(header.typ.as_deref(), Some("dc+sd-jwt"));
    let claims: Value = decode(
        parts[0],
        &decoding_key,
        &jsonwebtoken::Validation::new(Algorithm::ES256),
    )
    .expect("decode SD-JWT")
    .claims;
    assert_eq!(claims["vct"], "ExampleCredential");
    assert_eq!(claims["cnf"]["jwk"], holder_jwk);

    let malformed = sd_input(None, json!("not an object"), None);
    assert_eq!(
        crypto.sign(&malformed).await,
        Err(CredentialTrustError::InvalidEncoding)
    );
    let _ = std::fs::remove_dir_all(key_dir);
}

#[tokio::test]
async fn mdoc_signing_covers_holder_and_namespace_encoding_errors() {
    let (holder_jwk, _) = es256_jwk(33);
    let (crypto, _, key_dir) = real_crypto_fixture().await;
    let input = mdoc_input(
        Some(HolderBinding::Jwk { jwk: holder_jwk }),
        json!({
            "org.iso.18013.5.1": {
                "name": "Ada",
                "age": 42,
                "active": true,
                "score": 1.5,
                "empty": null,
                "tags": ["a", 2],
                "nested": {"ok": true},
            }
        }),
    );
    let encoded = crypto.sign(&input).await.expect("mDoc signing");
    assert!(!encoded.is_empty());
    assert!(URL_SAFE_NO_PAD.decode(encoded).is_ok());

    assert_eq!(
        crypto.sign(&mdoc_input(None, json!({"ns": {}}))).await,
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    assert_eq!(
        crypto
            .sign(&mdoc_input(
                Some(HolderBinding::Jwk {
                    jwk: json!({"kty": "RSA"})
                }),
                json!({"ns": {}}),
            ))
            .await,
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    assert_eq!(
        crypto
            .sign(&mdoc_input(
                Some(HolderBinding::Jwk {
                    jwk: json!({"kty": "EC", "crv": "P-256", "x": "bad", "y": "bad"})
                }),
                json!({"ns": {}}),
            ))
            .await,
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    let (valid_jwk, _) = es256_jwk(35);
    assert_eq!(
        crypto
            .sign(&mdoc_input(
                Some(HolderBinding::Jwk {
                    jwk: valid_jwk.clone()
                }),
                json!([]),
            ))
            .await,
        Err(CredentialTrustError::InvalidEncoding)
    );
    assert_eq!(
        crypto
            .sign(&mdoc_input(
                Some(HolderBinding::Jwk { jwk: valid_jwk }),
                json!({"ns": "not an object"}),
            ))
            .await,
        Err(CredentialTrustError::InvalidEncoding)
    );
    let _ = std::fs::remove_dir_all(key_dir);
}

#[test]
fn sd_jwt_chain_and_combined_anchor_validation_fail_closed() {
    let certs = certificate_fixture("issuer.example");
    let crypto = Openid4vcCredentialCrypto {
        keyset: nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        x5c: Arc::new(vec![]),
        leaf_der: Arc::new(certs.leaf_der.clone()),
        trust_anchors: Arc::new(vec![certs.ca_der.clone()]),
        issuer_trust_policy: VcIssuerTrustPolicy::san_bound(),
        revocation_policy: CertificateRevocationPolicy::disabled(),
    };
    let valid = crypto
        .validate_sd_jwt_chain(&[STANDARD.encode(&certs.leaf_der)], &[])
        .expect("valid SD-JWT chain");
    assert_eq!(valid.certificates, vec![certs.leaf_der.clone()]);
    assert_eq!(
        crypto
            .combined_trust_anchors(std::slice::from_ref(&certs.ca_der))
            .unwrap()
            .len(),
        1
    );
    let other_certs = certificate_fixture("other.example");
    assert_eq!(
        crypto
            .combined_trust_anchors(std::slice::from_ref(&other_certs.ca_der))
            .unwrap()
            .len(),
        2
    );
    assert!(crypto.validate_sd_jwt_chain(&[], &[]).is_err());
    assert!(matches!(
        crypto.validate_sd_jwt_chain(&["bad".to_owned()], &[]),
        Err(CredentialTrustError::InvalidEncoding)
    ));
    assert!(matches!(
        crypto.combined_trust_anchors(&[vec![1, 2, 3]]),
        Err(CredentialTrustError::InvalidEncoding)
    ));
    assert!(matches!(
        crypto.combined_trust_anchors(&[certs.leaf_der]),
        Err(CredentialTrustError::UntrustedIssuer)
    ));
}

#[tokio::test]
async fn sd_jwt_verification_accepts_valid_holder_binding_and_rejects_tampering() {
    let (crypto, presentation, disclosed, _certs) = sd_presentation_fixture();
    let verified = crypto
        .verify_sd_jwt(&presentation)
        .expect("valid SD-JWT presentation");
    let verified_via_port = crypto
        .verify(&presentation)
        .await
        .expect("credential verifier port");
    assert_eq!(verified_via_port, verified);
    assert_eq!(verified.format, CredentialFormat::SdJwtVc);
    assert_eq!(verified.issuer, "https://issuer.example");
    assert_eq!(verified.credential_type, "ExampleCredential");
    assert_eq!(verified.claims["given_name"], disclosed);
    assert_eq!(verified.status, Some(json!({"idx": 3})));
    assert!(verified.holder_key.is_some());

    let mut malformed = presentation.clone();
    malformed.encoded = "broken".to_owned();
    assert_eq!(
        crypto.verify_sd_jwt(&malformed),
        Err(CredentialTrustError::InvalidEncoding)
    );
    let mut wrong_typ = presentation.clone();
    let parts = wrong_typ.encoded.split('~').collect::<Vec<_>>();
    let mut header = decode_header(parts[0]).expect("header");
    header.typ = Some("JWT".to_owned());
    let (_, issuer_key) = es256_jwk(99);
    let claims = json!({"iss": "https://issuer.example", "exp": Utc::now().timestamp() + 300});
    let jwt = encode(&header, &claims, &issuer_key).expect("JWT");
    wrong_typ.encoded = format!("{jwt}~{}~{}", parts[1], parts[2]);
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_typ),
        Err(CredentialTrustError::InvalidEncoding)
    );

    let mut unknown_disclosure = presentation.clone();
    let parts = unknown_disclosure.encoded.split('~').collect::<Vec<_>>();
    let disclosure = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!(["salt2", "x", 1])).unwrap());
    unknown_disclosure.encoded = format!("{}~{}~{}", parts[0], disclosure, parts[2]);
    assert_eq!(
        crypto.verify_sd_jwt(&unknown_disclosure),
        Err(CredentialTrustError::InvalidSignature)
    );

    let mut duplicate = presentation.clone();
    let parts = duplicate.encoded.split('~').collect::<Vec<_>>();
    duplicate.encoded = format!("{}~{}~{}~{}", parts[0], parts[1], parts[1], parts[2]);
    assert_eq!(
        crypto.verify_sd_jwt(&duplicate),
        Err(CredentialTrustError::InvalidEncoding)
    );
}

#[test]
fn sd_jwt_key_binding_requires_type_and_matches_disclosure_hash() {
    let (crypto, presentation, _, certs) = sd_presentation_fixture();
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    let (holder_jwk, holder_key) = es256_jwk(71);

    let mut wrong_type_header = Header::new(Algorithm::ES256);
    wrong_type_header.typ = Some("jwt".to_owned());
    let wrong_type_kb = encode(
        &wrong_type_header,
        &json!({
            "nonce": presentation.expected_nonce,
            "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": "unused",
        }),
        &holder_key,
    )
    .expect("wrong-type key binding");
    let wrong_type = PresentedCredential {
        encoded: format!("{}~{}~{}", parts[0], parts[1], wrong_type_kb),
        ..presentation.clone()
    };
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_type),
        Err(CredentialTrustError::InvalidHolderBinding)
    );

    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let issued_at = Utc::now() - Duration::minutes(1);
    let mut credential_header = Header::new(Algorithm::ES256);
    credential_header.typ = Some("dc+sd-jwt".to_owned());
    credential_header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let credential_jwt = encode(
        &credential_header,
        &json!({
            "iss": "https://issuer.example",
            "iat": issued_at.timestamp(),
            "nbf": issued_at.timestamp(),
            "exp": (issued_at + Duration::hours(1)).timestamp(),
            "vct": "ExampleCredential",
            "_sd_alg": "sha-256",
            "_sd": [],
            "cnf": {"jwk": holder_jwk},
        }),
        &issuer_key,
    )
    .expect("credential without disclosures");
    let no_disclosure_input = format!("{credential_jwt}~");
    let mut kb_header = Header::new(Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".to_owned());
    let no_disclosure_kb = encode(
        &kb_header,
        &json!({
            "nonce": presentation.expected_nonce,
            "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(no_disclosure_input.as_bytes())),
        }),
        &holder_key,
    )
    .expect("empty disclosure key binding");
    let no_disclosure = PresentedCredential {
        encoded: format!("{credential_jwt}~{no_disclosure_kb}"),
        ..presentation.clone()
    };
    let verified = crypto
        .verify_sd_jwt(&no_disclosure)
        .expect("empty disclosure presentation");
    assert_eq!(verified.claims, json!({}));

    let wrong_hash_kb = encode(
        &kb_header,
        &json!({
            "nonce": presentation.expected_nonce,
            "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": "not-the-presentation-hash",
        }),
        &holder_key,
    )
    .expect("wrong disclosure hash key binding");
    let wrong_hash = PresentedCredential {
        encoded: format!("{}~{}~{}", parts[0], parts[1], wrong_hash_kb),
        ..presentation
    };
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_hash),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[test]
fn sd_jwt_verification_rejects_holder_and_issuer_policy_failures() {
    let (crypto, presentation, _, certs) = sd_presentation_fixture();
    let mut no_anchor = presentation.clone();
    no_anchor.additional_trust_anchors = vec![certs.leaf_der.clone()];
    assert_eq!(
        crypto.verify_sd_jwt(&no_anchor),
        Err(CredentialTrustError::UntrustedIssuer)
    );

    let mut no_cnf = presentation.clone();
    let parts = no_cnf.encoded.split('~').collect::<Vec<_>>();
    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let mut header = decode_header(parts[0]).expect("header");
    let claims = json!({
        "iss": "https://issuer.example",
        "exp": Utc::now().timestamp() + 300,
        "_sd_alg": "sha-256",
        "_sd": [],
        "vct": "ExampleCredential",
    });
    header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let jwt = encode(&header, &claims, &issuer_key).expect("JWT");
    no_cnf.encoded = format!("{jwt}~{}", parts[2]);
    assert_eq!(
        crypto.verify_sd_jwt(&no_cnf),
        Err(CredentialTrustError::InvalidHolderBinding)
    );

    let mut wrong_audience = presentation.clone();
    wrong_audience.expected_audience = "https://other.example".to_owned();
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_audience),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    let mut wrong_nonce = presentation.clone();
    wrong_nonce.expected_nonce = "other-nonce".to_owned();
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_nonce),
        Err(CredentialTrustError::InvalidHolderBinding)
    );

    let strict = Openid4vcCredentialCrypto {
        issuer_trust_policy: VcIssuerTrustPolicy::allowlisted(["https://other.example"]),
        ..crypto.clone()
    };
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::UntrustedIssuer)
    );
    let strict_revocation = Openid4vcCredentialCrypto {
        revocation_policy: CertificateRevocationPolicy::required_without_snapshot(),
        ..crypto
    };
    assert_eq!(
        strict_revocation.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevocationSnapshotUnavailable)
    );
}

#[tokio::test]
async fn mdoc_verification_rejects_missing_transcript_bad_cbor_and_bad_anchors() {
    let (crypto, _, key_dir) = real_crypto_fixture().await;
    let missing_transcript = PresentedCredential {
        format: CredentialFormat::MsoMdoc,
        encoded: URL_SAFE_NO_PAD.encode([0xa0]),
        expected_nonce: "nonce".to_owned(),
        expected_audience: "aud".to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        mdoc_session_transcript: None,
        additional_trust_anchors: vec![],
    };
    assert_eq!(
        crypto.verify_mdoc(&missing_transcript),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    let bad_cbor = PresentedCredential {
        mdoc_session_transcript: Some(vec![0x83, 0xf6, 0xf6, 0xf6]),
        ..missing_transcript.clone()
    };
    assert_eq!(
        crypto.verify_mdoc(&bad_cbor),
        Err(CredentialTrustError::InvalidEncoding)
    );
    let bad_anchor = PresentedCredential {
        mdoc_session_transcript: Some(vec![0x83, 0xf6, 0xf6, 0xf6]),
        encoded: URL_SAFE_NO_PAD.encode([0xa0]),
        additional_trust_anchors: vec![vec![1, 2, 3]],
        ..missing_transcript
    };
    assert_eq!(
        crypto.verify_mdoc(&bad_anchor),
        Err(CredentialTrustError::InvalidEncoding)
    );
    let _ = std::fs::remove_dir_all(key_dir);
}

#[tokio::test]
async fn mdoc_verification_accepts_signed_device_response_and_extracts_claims() {
    let (crypto, certs, key_dir) = real_crypto_fixture().await;
    let (encoded, transcript) = valid_mdoc_presentation(&certs);
    let presentation = PresentedCredential {
        format: CredentialFormat::MsoMdoc,
        encoded,
        expected_nonce: "verifier-nonce".to_owned(),
        expected_audience: "https://verifier.example".to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        mdoc_session_transcript: Some(transcript),
        additional_trust_anchors: vec![],
    };
    let verified = crypto
        .verify_mdoc(&presentation)
        .expect("signed mdoc presentation");
    assert_eq!(verified.format, CredentialFormat::MsoMdoc);
    assert_eq!(verified.credential_type, "org.iso.18013.5.1.mDL");
    assert_eq!(verified.claims["org.iso.18013.5.1"]["given_name"], "Ada");
    assert_eq!(verified.claims["org.iso.18013.5.1"]["age"], 42);
    assert!(verified.holder_key.is_some());
    assert_eq!(verified.status, None);
    assert_eq!(
        verified.issuer,
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&certs.leaf_der))
    );
    let strict_revocation = Openid4vcCredentialCrypto {
        revocation_policy: CertificateRevocationPolicy::required_without_snapshot(),
        ..crypto
    };
    assert_eq!(
        strict_revocation.verify_mdoc(&presentation),
        Err(CredentialTrustError::RevocationSnapshotUnavailable)
    );
    let _ = std::fs::remove_dir_all(key_dir);
}

#[test]
fn certificate_chain_at_checks_leaf_intermediates_anchor_and_time() {
    let certs = certificate_fixture("issuer.example");
    let now = Utc::now().timestamp();
    assert!(
        verify_certificate_chain_at(
            std::slice::from_ref(&certs.leaf_der),
            std::slice::from_ref(&certs.ca_der),
            now,
        )
        .expect("valid chain")
    );
    assert!(
        !verify_certificate_chain_at(
            std::slice::from_ref(&certs.ca_der),
            std::slice::from_ref(&certs.ca_der),
            now,
        )
        .expect("CA as leaf is a normal false result")
    );
    assert!(matches!(
        verify_certificate_chain_at(&[vec![1, 2, 3]], std::slice::from_ref(&certs.ca_der), now),
        Err(CredentialTrustError::InvalidEncoding)
    ));
    assert!(
        !verify_certificate_chain_at(std::slice::from_ref(&certs.leaf_der), &[], now,)
            .expect("unanchored chain")
    );
    assert!(matches!(
        verify_certificate_chain_at(
            std::slice::from_ref(&certs.leaf_der),
            std::slice::from_ref(&certs.ca_der),
            i64::MAX
        ),
        Err(CredentialTrustError::InvalidEncoding)
    ));
}

#[test]
fn mdoc_assessment_and_holder_helpers_fail_closed() {
    let passed = mdoc_rs::verifier::VerificationAssessment {
        status: mdoc_rs::verifier::VerificationStatus::Passed,
        check: "passed".to_owned(),
        reason: None,
        category: mdoc_rs::verifier::VerificationCategory::IssuerAuth,
        id: mdoc_rs::verifier::CheckId::IssuerCertificateValidity,
    };
    assert!(!mdoc_failed_assessments_accepted(
        [&passed].into_iter(),
        true,
        true
    ));
    assert!(!mdoc_assessments_accepted(
        &mdoc_rs::verifier::VerifiedMDoc {
            mdoc: mdoc_rs::model::MDoc {
                version: "1.0".to_owned(),
                status: mdoc_rs::model::MDocStatus::Ok,
                documents: vec![],
            },
            assessments: vec![],
            is_valid: true,
        },
        false,
        true,
    ));

    let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![1; 32], vec![2; 32])
        .build();
    let holder = mdoc_holder_key(Some(&key)).expect("holder key");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(holder["cose_key"].as_str().expect("encoded key"))
            .expect("COSE key"),
        key.to_vec().expect("COSE serialization")
    );
    assert_eq!(
        mdoc_holder_key(None),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[test]
fn standard_device_authentication_bytes_is_deterministic_and_rejects_bad_inputs() {
    let transcript = [0x83, 0xf6, 0xf6, 0xf6];
    let first = standard_device_authentication_bytes(&transcript, "org.iso.18013.5.1.mDL", &[0xa0])
        .expect("DeviceAuthenticationBytes");
    let second =
        standard_device_authentication_bytes(&transcript, "org.iso.18013.5.1.mDL", &[0xa0])
            .expect("DeviceAuthenticationBytes");
    assert_eq!(first, second);
    assert!(standard_device_authentication_bytes(&[0xff], "doc", &[0xa0]).is_err());
}

#[test]
fn async_cose_signer_uses_credential_scope_and_propagates_signing_errors() {
    let certs = certificate_fixture("issuer.example");
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let handle = runtime.handle().clone();
    let signer = AsyncCoseSigner {
        keyset: nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        certificate_der: Arc::new(certs.leaf_der),
        runtime: handle.clone(),
    };
    let signature = signer.sign(b"credential tbs").expect("signature");
    assert_eq!(signature.len(), 64);
    assert_eq!(signer.algorithm(), -7);
    assert!(!signer.certificate_der().is_empty());

    let failing = AsyncCoseSigner {
        keyset: nazo_key_management::KeyManager::for_test_behavior(
            Algorithm::ES256,
            nazo_key_management::TestSigningBehavior::Failing,
        ),
        certificate_der: Arc::new(vec![1, 2, 3]),
        runtime: handle,
    };
    assert!(failing.sign(b"credential tbs").is_err());
}
