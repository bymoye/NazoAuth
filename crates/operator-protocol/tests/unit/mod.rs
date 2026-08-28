use ed25519_dalek::SigningKey;
use proptest::prelude::*;

use super::*;
use crate::verification::*;

// This module is included by lib.rs so private protocol invariants remain testable.

mod control_operation_tests;
mod recovery_tests;

fn discovery_statement() -> DiscoveryStatement {
    DiscoveryStatement {
        schema: CONTROL_DISCOVERY_SCHEMA,
        product: CONTROL_DISCOVERY_PRODUCT.to_owned(),
        deployment_id: "deployment-1".to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        issuer: "https://auth.example".to_owned(),
        release: "v0.2.0".to_owned(),
        revision: "a".repeat(40),
        build_id: "github:123".to_owned(),
        control_protocol_versions: vec![CONTROL_DISCOVERY_SCHEMA],
        operator_protocol_versions: vec![PROTOCOL_VERSION],
        instance_key_id: "instance-1".to_owned(),
        nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned(),
        issued_at: 1_000,
        expires_at: 1_060,
    }
}

fn deployment_statement() -> DeploymentStatement {
    let online = discovery_statement();
    DeploymentStatement {
        schema: online.schema,
        product: online.product,
        deployment_id: online.deployment_id,
        runtime_instance_id: online.runtime_instance_id,
        issuer: online.issuer,
        release: online.release,
        revision: online.revision,
        build_id: online.build_id,
        control_protocol_versions: online.control_protocol_versions,
        operator_protocol_versions: online.operator_protocol_versions,
        instance_key_id: online.instance_key_id,
        issued_at: online.issued_at,
    }
}

#[test]
fn golden_control_discovery_vector_is_stable_and_nonce_bound() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let compact = sign_discovery_statement(&discovery_statement(), "instance-1", &key).unwrap();
    assert_eq!(
        compact,
        "eyJhbGciOiJFZERTQSIsImtpZCI6Imluc3RhbmNlLTEiLCJ0eXAiOiJuYXpvYXV0aC1jb250cm9sLWRpc2NvdmVyeStqd3QifQ.eyJzY2hlbWEiOjEsInByb2R1Y3QiOiJuYXpvYXV0aCIsImRlcGxveW1lbnRfaWQiOiJkZXBsb3ltZW50LTEiLCJydW50aW1lX2luc3RhbmNlX2lkIjoicnVudGltZS0xIiwiaXNzdWVyIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUiLCJyZWxlYXNlIjoidjAuMi4wIiwicmV2aXNpb24iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiYnVpbGRfaWQiOiJnaXRodWI6MTIzIiwiY29udHJvbF9wcm90b2NvbF92ZXJzaW9ucyI6WzFdLCJvcGVyYXRvcl9wcm90b2NvbF92ZXJzaW9ucyI6WzJdLCJpbnN0YW5jZV9rZXlfaWQiOiJpbnN0YW5jZS0xIiwibm9uY2UiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4IiwiaXNzdWVkX2F0IjoxMDAwLCJleHBpcmVzX2F0IjoxMDYwfQ.dBwSPMlQi8ay79aKXwhJiXFRRiRQdLDu-yQTtKMSRJDPy0B3tRoLE5q8pvYy4_OUxpWtFnQJvx1EcjOeLor4Dg"
    );
    assert_eq!(
        verify_discovery_statement(
            &compact,
            "instance-1",
            &key.verifying_key(),
            &discovery_statement().nonce,
            1_030,
        )
        .unwrap(),
        discovery_statement()
    );
    assert!(
        verify_discovery_statement(
            &compact,
            "instance-1",
            &key.verifying_key(),
            "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            1_030,
        )
        .is_err()
    );
}

#[test]
fn offline_deployment_statement_is_identity_evidence_not_artifact_trust() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let offline = deployment_statement();
    let compact = sign_deployment_statement(&offline, "instance-1", &key).unwrap();
    assert_eq!(
        verify_deployment_statement(&compact, "instance-1", &key.verifying_key()).unwrap(),
        offline
    );
    assert_eq!(
        protected_header(&compact).unwrap().typ,
        DEPLOYMENT_STATEMENT_JWS_TYPE
    );
}

#[test]
fn discovery_and_offline_identity_fail_closed_on_invalid_claims() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let nonce = discovery_statement().nonce;
    assert!(
        validate_discovery_request(&DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA + 1,
            nonce: nonce.clone(),
        })
        .is_err()
    );
    for invalid_nonce in ["short".to_owned(), "!".repeat(43)] {
        assert!(
            validate_discovery_request(&DiscoveryRequest {
                schema: CONTROL_DISCOVERY_SCHEMA,
                nonce: invalid_nonce,
            })
            .is_err()
        );
    }
    assert!(decode_instance_public_key("AA").is_err());

    let mut online = discovery_statement();
    online.instance_key_id = "instance-other".to_owned();
    assert!(sign_discovery_statement(&online, "instance-1", &key).is_err());
    let forged = sign_compact(&online, "instance-1", CONTROL_DISCOVERY_JWS_TYPE, &key).unwrap();
    assert!(
        verify_discovery_statement(&forged, "instance-1", &key.verifying_key(), &nonce, 1_030,)
            .is_err()
    );

    let mutations: [fn(&mut DiscoveryStatement); 5] = [
        |statement: &mut DiscoveryStatement| statement.schema += 1,
        |statement: &mut DiscoveryStatement| statement.product = "other".to_owned(),
        |statement: &mut DiscoveryStatement| statement.control_protocol_versions.clear(),
        |statement: &mut DiscoveryStatement| {
            statement.operator_protocol_versions = vec![PROTOCOL_VERSION, PROTOCOL_VERSION]
        },
        |statement: &mut DiscoveryStatement| statement.expires_at = statement.issued_at + 61,
    ];
    for mutate in mutations {
        let mut invalid = discovery_statement();
        mutate(&mut invalid);
        assert!(sign_discovery_statement(&invalid, "instance-1", &key).is_err());
    }

    let mut offline = deployment_statement();
    offline.instance_key_id = "instance-other".to_owned();
    assert!(sign_deployment_statement(&offline, "instance-1", &key).is_err());
    let forged = sign_compact(&offline, "instance-1", DEPLOYMENT_STATEMENT_JWS_TYPE, &key).unwrap();
    assert!(verify_deployment_statement(&forged, "instance-1", &key.verifying_key()).is_err());

    let mut offline = deployment_statement();
    offline.issued_at = 0;
    assert!(sign_deployment_statement(&offline, "instance-1", &key).is_err());
}

#[test]
fn protected_header_rejects_untrusted_key_lookup_inputs() {
    for header in [
        serde_json::json!({
            "alg": "EdDSA",
            "kid": "../../controller",
            "typ": CONTROL_DISCOVERY_JWS_TYPE,
        }),
        serde_json::json!({
            "alg": "EdDSA",
            "kid": "controller-1",
            "typ": CONTROL_DISCOVERY_JWS_TYPE,
            "jku": "https://attacker.example/jwks.json",
        }),
        serde_json::json!({
            "alg": "none",
            "kid": "controller-1",
            "typ": CONTROL_DISCOVERY_JWS_TYPE,
        }),
    ] {
        let compact = format!(
            "{}.e30.AA",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap())
        );
        assert!(matches!(
            protected_header(&compact),
            Err(ProtocolError::Header)
        ));
    }
}

#[test]
fn rejects_unknown_claims_and_algorithm_confusion() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let compact = sign_discovery_statement(&discovery_statement(), "instance-1", &key).unwrap();
    let mut segments = compact.split('.').collect::<Vec<_>>();
    let payload = URL_SAFE_NO_PAD.decode(segments[1]).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    value["secret"] = serde_json::json!("must-not-be-accepted");
    segments[1] = Box::leak(
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&value).unwrap())
            .into_boxed_str(),
    );
    let tampered = segments.join(".");
    assert!(matches!(
        verify_discovery_statement(
            &tampered,
            "instance-1",
            &key.verifying_key(),
            &discovery_statement().nonce,
            1_030,
        ),
        Err(ProtocolError::Signature)
    ));
}

#[test]
fn openid4vc_trust_policy_accepts_bounded_public_bundle_and_rejects_unknowns() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ec_key = |kid: &str| {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": coordinate,
            "y": coordinate,
            "kid": kid,
        })
    };
    let certificate =
        |label: &str| format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n");
    let policy = Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example/attestation".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [ec_key("client")]}),
        key_attestation_jwks: serde_json::json!({"keys": [ec_key("holder")]}),
        credential_trust_anchor_pem: format!("{}{}", certificate("MA=="), certificate("MDE=")),
        wallet_authorization_origins: vec!["https://wallet.example".to_owned()],
    };
    validate_openid4vc_trust_policy(&policy).unwrap();
    let mut no_trailing_newline = policy.clone();
    no_trailing_newline.credential_trust_anchor_pem = certificate("MA==").trim_end().to_owned();
    validate_openid4vc_trust_policy(&no_trailing_newline).unwrap();
    let mut crlf_bundle = policy.clone();
    crlf_bundle.credential_trust_anchor_pem = certificate("MA==").replace('\n', "\r\n");
    validate_openid4vc_trust_policy(&crlf_bundle).unwrap();

    let mut unknown_wire = serde_json::to_value(&policy).unwrap();
    unknown_wire["unexpected_wire_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Openid4vcTrustPolicy>(unknown_wire).is_err());

    let mut invalid_schema = policy.clone();
    invalid_schema.schema = 2;
    assert!(validate_openid4vc_trust_policy(&invalid_schema).is_err());

    for issuer in [
        "",
        "http://issuer.example",
        "https://",
        "https://issuer.example/path?x=1",
    ] {
        let mut invalid = policy.clone();
        invalid.client_attestation_issuer = issuer.to_owned();
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut oversized_issuer = policy.clone();
    oversized_issuer.client_attestation_issuer = format!("https://{}", "i".repeat(2048));
    assert!(validate_openid4vc_trust_policy(&oversized_issuer).is_err());

    let mut empty_jwks = policy.clone();
    empty_jwks.client_attestation_jwks = serde_json::json!({"keys": []});
    assert!(validate_openid4vc_trust_policy(&empty_jwks).is_err());

    let mut empty_origins = policy.clone();
    empty_origins.wallet_authorization_origins.clear();
    assert!(validate_openid4vc_trust_policy(&empty_origins).is_err());

    for origin in [
        "http://wallet.example",
        "https://wallet.example/",
        "https://user@wallet.example",
        "https://wallet.example/path",
        "https://wallet.example?query",
        "https://wallet.example#fragment",
        "https://wallet.example:443",
        "https://-wallet.example",
        "HTTPS://wallet.example",
    ] {
        let mut invalid = policy.clone();
        invalid.wallet_authorization_origins = vec![origin.to_owned()];
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut duplicate_origins = policy.clone();
    duplicate_origins.wallet_authorization_origins = vec![
        "https://wallet.example".to_owned(),
        "https://wallet.example".to_owned(),
    ];
    assert!(validate_openid4vc_trust_policy(&duplicate_origins).is_err());

    let mut private_jwk = policy.clone();
    private_jwk.client_attestation_jwks["keys"][0]["d"] = serde_json::json!("secret");
    assert!(validate_openid4vc_trust_policy(&private_jwk).is_err());

    let mut unknown_jwks_member = policy.clone();
    unknown_jwks_member.client_attestation_jwks["unexpected"] = serde_json::json!(true);
    assert!(validate_openid4vc_trust_policy(&unknown_jwks_member).is_err());

    let mut unknown_jwk_member = policy.clone();
    unknown_jwk_member.client_attestation_jwks["keys"][0]["unexpected"] = serde_json::json!(true);
    assert!(validate_openid4vc_trust_policy(&unknown_jwk_member).is_err());

    for pem in [
        "",
        "public",
        "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----\n",
        "-----BEGIN CERTIFICATE-----\rMA==\r-----END CERTIFICATE-----",
    ] {
        let mut invalid = policy.clone();
        invalid.credential_trust_anchor_pem = pem.to_owned();
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut oversized_pem = policy.clone();
    oversized_pem.credential_trust_anchor_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        "x".repeat(16 * 1024)
    );
    assert!(validate_openid4vc_trust_policy(&oversized_pem).is_err());

    let mut oversized_json = policy;
    oversized_json.client_attestation_jwks["keys"][0]["kid"] =
        serde_json::json!("k".repeat(33 * 1024));
    assert!(validate_openid4vc_trust_policy(&oversized_json).is_err());
}

proptest! {
    #[test]
    fn arbitrary_compact_input_never_panics(input in any::<Vec<u8>>()) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = String::from_utf8_lossy(&input);
        let _ = verify_discovery_statement(
            &input,
            "instance-1",
            &key.verifying_key(),
            &discovery_statement().nonce,
            1_030,
        );
    }

}

#[test]
fn discovery_identity_and_identifier_boundaries_are_checked() {
    let statement = discovery_statement();
    validate_discovery_statement(&statement, 1_030, Some(&statement.nonce)).unwrap();
    let mut invalid = statement.clone();
    invalid.schema += 1;
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.product = "other".to_owned();
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    for field in ["deployment/1", "runtime/1", "instance/1"] {
        let mut candidate = statement.clone();
        candidate.deployment_id = field.to_owned();
        assert!(validate_discovery_statement(&candidate, 1_030, None).is_err());
    }
    for field in [
        "issuer value",
        "release value",
        "revision value",
        "build value",
    ] {
        let mut candidate = statement.clone();
        candidate.issuer = field.to_owned();
        assert!(validate_discovery_statement(&candidate, 1_030, None).is_err());
    }
    let mut invalid = statement.clone();
    invalid.control_protocol_versions = vec![CONTROL_DISCOVERY_SCHEMA, CONTROL_DISCOVERY_SCHEMA];
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.control_protocol_versions = vec![CONTROL_DISCOVERY_SCHEMA + 1];
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.control_protocol_versions = (1..=17).collect();
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.operator_protocol_versions = vec![PROTOCOL_VERSION + 1];
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.instance_key_id = "instance/1".to_owned();
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    assert!(validate_discovery_statement(&statement, 1_030, Some("different-nonce")).is_err());
    assert!(validate_discovery_statement(&statement, 999, None).is_err());
    assert!(validate_discovery_statement(&statement, 1_061, None).is_err());
    let mut invalid = statement.clone();
    invalid.expires_at = invalid.issued_at - 1;
    assert!(validate_discovery_statement(&invalid, 1_000, None).is_err());
    let mut invalid = statement.clone();
    invalid.expires_at = invalid.issued_at + MAX_DISCOVERY_LIFETIME_SECONDS + 1;
    assert!(validate_discovery_statement(&invalid, 1_000, None).is_err());
    assert!(
        validate_discovery_request(&DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA,
            nonce: URL_SAFE_NO_PAD.encode([1u8; 31]),
        })
        .is_err()
    );

    let mut deployment = deployment_statement();
    validate_deployment_statement(&deployment).unwrap();
    deployment.issued_at = 0;
    assert!(validate_deployment_statement(&deployment).is_err());
    let mut deployment = deployment_statement();
    deployment.product = "other".to_owned();
    assert!(validate_deployment_statement(&deployment).is_err());
    let mut deployment = deployment_statement();
    deployment.control_protocol_versions.clear();
    assert!(validate_deployment_statement(&deployment).is_err());

    validate_identifier("issuer:https://auth.example").unwrap();
    for value in [String::new(), "bad value".to_owned(), "x".repeat(257)] {
        assert!(validate_identifier(&value).is_err());
    }
    validate_file_identifier("deployment-1_v2").unwrap();
    for value in [String::new(), "deployment/1".to_owned(), "x".repeat(129)] {
        assert!(validate_file_identifier(&value).is_err());
    }
    assert!(validate_file_identifier_value("file-1").is_ok());
    assert!(validate_file_identifier_value("file/1").is_err());
}

#[test]
fn openid4vc_trust_policy_rejects_ambiguous_origins_certificates_and_jwks() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let key = |kid: &str| {
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": kid
        })
    };
    let certificate =
        |body: &str| format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
    let policy = Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example/attestation".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [key("client")]}),
        key_attestation_jwks: serde_json::json!({"keys": [key("holder")]}),
        credential_trust_anchor_pem: certificate("MA=="),
        wallet_authorization_origins: vec!["https://wallet.example".to_owned()],
    };
    validate_openid4vc_trust_policy(&policy).unwrap();

    for issuer in [
        "https:///missing-host",
        "https://?query",
        "https://#fragment",
        "https://issuer.example/white space",
        "https://issuer.example\0",
    ] {
        let mut invalid = policy.clone();
        invalid.client_attestation_issuer = issuer.to_owned();
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let invalid_origins = [
        "",
        "https://wallet.exämple",
        "https://wallet.example ",
        "https://wallet.example%25",
        "https://wallet.example\\bad",
        "https://",
        "https://.wallet.example",
        "https://wallet.example.",
        "https://wallet..example",
        "https://wallet_example",
        "https://wallet-.example",
        "https://[not-ipv6]",
        "https://[::1",
        "https://[::1]extra",
        "https://wallet.example:",
        "https://wallet.example:abc",
        "https://wallet.example:0",
        "https://wallet.example:0443",
        "https://wallet.example:65536",
    ];
    for origin in invalid_origins {
        let mut invalid = policy.clone();
        invalid.wallet_authorization_origins = vec![origin.to_owned()];
        assert!(
            validate_openid4vc_trust_policy(&invalid).is_err(),
            "{origin}"
        );
    }
    let mut too_many_origins = policy.clone();
    too_many_origins.wallet_authorization_origins = (0..17)
        .map(|index| format!("https://wallet-{index}.example"))
        .collect();
    assert!(validate_openid4vc_trust_policy(&too_many_origins).is_err());
    let mut long_origin = policy.clone();
    long_origin.wallet_authorization_origins = vec![format!("https://{}", "a".repeat(2048))];
    assert!(validate_openid4vc_trust_policy(&long_origin).is_err());
    for origin in ["https://wallet.example:8443", "https://[::1]:8443"] {
        let mut valid = policy.clone();
        valid.wallet_authorization_origins = vec![origin.to_owned()];
        validate_openid4vc_trust_policy(&valid).unwrap();
    }

    let five_certificates = (0..5)
        .map(|index| {
            certificate(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0x30, index],
            ))
        })
        .collect::<String>();
    let invalid_certificates = [
        "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n".to_owned(),
        "-----BEGIN CERTIFICATE-----\nMA==\n".to_owned(),
        "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n".to_owned(),
        certificate("AA=="),
        format!("{}trailing", certificate("MA==")),
        format!("{}{}", certificate("MA=="), certificate("MA==")),
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "-----BEGIN PUBLIC KEY-----"
        ),
        five_certificates,
    ];
    for pem in invalid_certificates {
        let mut invalid = policy.clone();
        invalid.credential_trust_anchor_pem = pem;
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }

    let invalid_jwks = [
        serde_json::json!([]),
        serde_json::json!({"keys": ["not-an-object"]}),
        serde_json::json!({"keys": [{"kty": "oct", "k": "secret", "kid": "s"}]}),
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate}]}),
        serde_json::json!({"keys": [key("duplicate"), key("duplicate")]}),
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-384", "x": coordinate, "y": coordinate, "kid": "bad"}]}),
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "short", "y": coordinate, "kid": "bad"}]}),
    ];
    for jwks in invalid_jwks {
        let mut invalid = policy.clone();
        invalid.key_attestation_jwks = jwks;
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut ed25519 = policy;
    ed25519.key_attestation_jwks = serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "x": coordinate, "kid": "holder"
    }]});
    validate_openid4vc_trust_policy(&ed25519).unwrap();
}

#[test]
fn trust_policy_parser_rejects_multi_authority_and_inter_certificate_junk() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let policy = Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "client"
        }]}),
        key_attestation_jwks: serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "holder"
        }]}),
        credential_trust_anchor_pem:
            "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n".to_owned(),
        wallet_authorization_origins: vec!["https://wallet.example".to_owned()],
    };
    let mut multiple_ports = policy.clone();
    multiple_ports.wallet_authorization_origins =
        vec!["https://wallet.example:8443:9443".to_owned()];
    assert!(validate_openid4vc_trust_policy(&multiple_ports).is_err());

    let mut junk_between_certificates = policy;
    junk_between_certificates.credential_trust_anchor_pem = concat!(
        "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
        "junk\n",
        "-----BEGIN CERTIFICATE-----\nMDE=\n-----END CERTIFICATE-----\n"
    )
    .to_owned();
    assert!(validate_openid4vc_trust_policy(&junk_between_certificates).is_err());
}

fn openid4vp_verification_receipt() -> Openid4vpVerificationReceipt {
    Openid4vpVerificationReceipt {
        schema: 1,
        iss: "https://auth.example".to_owned(),
        aud: "https://auth.example/openid4vp/verification-receipts".to_owned(),
        jti: "019c8ca2-30a6-7000-8000-000000000001".to_owned(),
        iat: 1_787_367_660,
        exp: 1_787_367_960,
        deployment_id: "deployment-1".to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        instance_key_id: "instance-key".to_owned(),
        tenant_id: "019c8ca2-30a6-7000-8000-000000000005".to_owned(),
        transaction_id: "019c8ca2-30a6-7000-8000-000000000002".to_owned(),
        issuance_request_jti: "019c8ca2-30a6-7000-8000-000000000006".to_owned(),
        status: Openid4vpVerificationStatus::Verified,
        evidence_context: Openid4vpEvidenceContext {
            run_jti: "run-jti-1".to_owned(),
            artifact_sha256: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            suite_plan_id: "Ab3dEf5gHi7Jk".to_owned(),
            suite_module_id: "Ab3dEf5gHi7JkLm".to_owned(),
            test_name: "openid4vp-test".to_owned(),
            variant_sha256: "c".repeat(64),
        },
        presentation_binding: Openid4vpPresentationBinding {
            presentation_request_sha256: "e".repeat(64),
            trust_policy: Openid4vpTrustPolicyBinding {
                binding_id: Some("019c8ca2-30a6-7000-8000-000000000007".to_owned()),
                resource_id: Some("vp-policy-1".to_owned()),
                resource_digest: Some("f".repeat(64)),
            },
        },
        intent_sha256: "1".repeat(64),
        completed_at: "2026-08-22T03:00:00Z".to_owned(),
        capability_sha256: "d".repeat(64),
    }
}

#[test]
fn openid4vp_evidence_context_accepts_opaque_suite_identifiers_with_safe_bounds() {
    let context = openid4vp_verification_receipt().evidence_context;
    canonical_openid4vp_evidence_context_sha256(&context)
        .expect("official-length opaque suite identifiers must be accepted");

    let mut invalid = context.clone();
    invalid.suite_plan_id = "unsafe/plan".to_owned();
    assert!(canonical_openid4vp_evidence_context_sha256(&invalid).is_err());

    let mut oversized = context;
    oversized.suite_module_id = "a".repeat(129);
    assert!(canonical_openid4vp_evidence_context_sha256(&oversized).is_err());
}

fn openid4vp_normalized_create_request() -> Openid4vpNormalizedCreateRequest {
    Openid4vpNormalizedCreateRequest {
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        dcql_query: serde_json::from_str(
            r#"{"credentials":[{"meta":{"z":2,"a":1},"id":"credential-1"}]}"#,
        )
        .unwrap(),
        haip: true,
        client_id_prefix: "x509_san_dns".to_owned(),
        request_method: "request_uri_signed_get".to_owned(),
        response_mode: "direct_post.jwt".to_owned(),
        transaction_data: Some(vec![
            serde_json::from_str(r#"{"type":"payment","details":{"z":2,"a":1}}"#).unwrap(),
        ]),
        openid4vc_trust_policy_resource_id: Some("trust-policy-1".to_owned()),
        openid4vc_trust_policy_digest: Some("a".repeat(64)),
    }
}

#[test]
fn openid4vp_normalized_create_request_canonicalizes_recursive_object_order() {
    let first = openid4vp_normalized_create_request();
    let mut second = first.clone();
    second.dcql_query =
        serde_json::from_str(r#"{"credentials":[{"id":"credential-1","meta":{"a":1,"z":2}}]}"#)
            .unwrap();
    second.transaction_data = Some(vec![
        serde_json::from_str(r#"{"details":{"a":1,"z":2},"type":"payment"}"#).unwrap(),
    ]);

    let (first_json, first_sha256) = canonical_openid4vp_normalized_create_request(&first).unwrap();
    let (second_json, second_sha256) =
        canonical_openid4vp_normalized_create_request(&second).unwrap();

    assert_eq!(first_json, second_json);
    assert_eq!(first_sha256, second_sha256);
    assert_eq!(first_sha256.len(), 64);
    assert!(
        first_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(first_json.contains(r#""meta":{"a":1,"z":2}"#));
    assert!(first_json.contains(r#""details":{"a":1,"z":2}"#));
}

#[test]
fn openid4vp_normalized_create_request_hash_binds_every_field() {
    let baseline = openid4vp_normalized_create_request();
    let (_, baseline_sha256) = canonical_openid4vp_normalized_create_request(&baseline).unwrap();
    let mut changed = Vec::new();

    let mut request = baseline.clone();
    request.wallet_authorization_endpoint.push_str("/changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.dcql_query = serde_json::json!({"credentials": []});
    changed.push(request);
    let mut request = baseline.clone();
    request.haip = false;
    changed.push(request);
    let mut request = baseline.clone();
    request.client_id_prefix.push_str("_changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.request_method.push_str("_changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.response_mode.push_str("_changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.transaction_data = None;
    changed.push(request);
    let mut request = baseline.clone();
    request.openid4vc_trust_policy_resource_id = None;
    changed.push(request);
    let mut request = baseline.clone();
    request.openid4vc_trust_policy_digest = None;
    changed.push(request);

    for request in changed {
        let (_, changed_sha256) = canonical_openid4vp_normalized_create_request(&request).unwrap();
        assert_ne!(changed_sha256, baseline_sha256);
    }
}

#[test]
fn openid4vp_create_request_jti_requires_canonical_versioned_uuid() {
    for version in b'1'..=b'8' {
        let mut valid = b"00000000-0000-7000-8000-000000000001".to_vec();
        valid[14] = version;
        validate_openid4vp_create_request_jti(std::str::from_utf8(&valid).unwrap()).unwrap();
    }

    for malformed in [
        "00000000-0000-0000-8000-000000000001",
        "00000000-0000-9000-8000-000000000001",
        "00000000-0000-7000-7000-000000000001",
        "00000000-0000-7000-c000-000000000001",
        "00000000-0000-7000-8000-00000000000A",
        "00000000000070008000000000000001",
        "not-a-uuid",
    ] {
        assert!(validate_openid4vp_create_request_jti(malformed).is_err());
    }
}

#[test]
fn openid4vp_verification_receipt_is_server_bound_and_time_bounded() {
    let key = SigningKey::from_bytes(&[47; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    let compact = sign_openid4vp_verification_receipt(&receipt, &key_id, &key)
        .expect("valid verification receipt should sign");
    let context_sha256 =
        canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context).unwrap();
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding).unwrap();
    let expected = Openid4vpVerificationReceiptExpectations {
        issuer: &receipt.iss,
        audience: &receipt.aud,
        deployment_id: &receipt.deployment_id,
        runtime_instance_id: &receipt.runtime_instance_id,
        instance_key_id: &key_id,
        tenant_id: &receipt.tenant_id,
        transaction_id: &receipt.transaction_id,
        receipt_id: &receipt.jti,
        issuance_request_jti: &receipt.issuance_request_jti,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &presentation_binding_sha256,
        intent_sha256: &receipt.intent_sha256,
        capability_sha256: &receipt.capability_sha256,
    };
    assert_eq!(
        verify_openid4vp_verification_receipt(
            &compact,
            &expected,
            &key.verifying_key(),
            receipt.iat + 60,
        )
        .expect("valid verification receipt should verify"),
        receipt
    );
    assert!(
        verify_openid4vp_verification_receipt(
            &compact,
            &expected,
            &key.verifying_key(),
            receipt.exp,
        )
        .is_err(),
        "receipt must expire at the exclusive expiry boundary"
    );
}

#[test]
fn openid4vp_verification_receipt_rejects_context_or_signer_drift() {
    let key = SigningKey::from_bytes(&[48; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    receipt.evidence_context.matrix_sha256 = "A".repeat(64);
    assert!(sign_openid4vp_verification_receipt(&receipt, &key_id, &key).is_err());

    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id = "instance-other".to_owned();
    assert!(sign_openid4vp_verification_receipt(&receipt, &key_id, &key).is_err());

    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    receipt.exp = receipt.iat - 1;
    assert!(sign_openid4vp_verification_receipt(&receipt, &key_id, &key).is_err());
}

#[test]
fn openid4vp_verification_receipt_rejects_signed_substitution() {
    let key = SigningKey::from_bytes(&[49; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    let compact = sign_openid4vp_verification_receipt(&receipt, &key_id, &key).unwrap();
    let context_sha256 =
        canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context).unwrap();
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding).unwrap();
    let expected = Openid4vpVerificationReceiptExpectations {
        issuer: &receipt.iss,
        audience: &receipt.aud,
        deployment_id: &receipt.deployment_id,
        runtime_instance_id: &receipt.runtime_instance_id,
        instance_key_id: &key_id,
        tenant_id: &receipt.tenant_id,
        transaction_id: "019c8ca2-30a6-7000-8000-000000000099",
        receipt_id: &receipt.jti,
        issuance_request_jti: &receipt.issuance_request_jti,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &presentation_binding_sha256,
        intent_sha256: &receipt.intent_sha256,
        capability_sha256: &receipt.capability_sha256,
    };
    assert!(
        verify_openid4vp_verification_receipt(
            &compact,
            &expected,
            &key.verifying_key(),
            receipt.iat,
        )
        .is_err(),
        "a valid receipt for another transaction must not substitute"
    );
}

#[test]
fn openid4vp_verification_intent_is_immutable_and_typed() {
    let key = SigningKey::from_bytes(&[50; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let receipt = openid4vp_verification_receipt();
    let transaction_id = receipt.transaction_id.clone();
    let context_sha256 =
        canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context).unwrap();
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding).unwrap();
    let intent = Openid4vpVerificationIntent {
        schema: 1,
        iss: receipt.iss.clone(),
        aud: "https://auth.example/openid4vp/verification-intents".to_owned(),
        jti: transaction_id.clone(),
        iat: receipt.iat - 60,
        exp: receipt.exp,
        deployment_id: receipt.deployment_id.clone(),
        runtime_instance_id: receipt.runtime_instance_id.clone(),
        instance_key_id: key_id.clone(),
        tenant_id: "019c8ca2-30a6-7000-8000-000000000005".to_owned(),
        transaction_id: transaction_id.clone(),
        evidence_context: receipt.evidence_context,
        presentation_binding: receipt.presentation_binding,
    };
    let compact = sign_openid4vp_verification_intent(&intent, &key_id, &key).unwrap();
    let expected = Openid4vpVerificationIntentExpectations {
        issuer: &intent.iss,
        audience: &intent.aud,
        deployment_id: &intent.deployment_id,
        runtime_instance_id: &intent.runtime_instance_id,
        instance_key_id: &key_id,
        tenant_id: &intent.tenant_id,
        transaction_id: &transaction_id,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &presentation_binding_sha256,
    };
    assert_eq!(
        verify_openid4vp_verification_intent(
            &compact,
            &expected,
            &key.verifying_key(),
            intent.iat,
        )
        .unwrap(),
        intent
    );
    let wrong_context = "f".repeat(64);
    let wrong = Openid4vpVerificationIntentExpectations {
        evidence_context_sha256: &wrong_context,
        ..expected
    };
    assert!(
        verify_openid4vp_verification_intent(&compact, &wrong, &key.verifying_key(), intent.iat,)
            .is_err()
    );
    let mut reversed = intent;
    reversed.exp = reversed.iat - 1;
    assert!(sign_openid4vp_verification_intent(&reversed, &key_id, &key).is_err());
}
