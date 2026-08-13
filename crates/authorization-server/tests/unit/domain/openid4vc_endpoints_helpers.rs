use super::*;

use std::collections::BTreeMap;

use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::{CredentialIssuanceError, CredentialStoreError, ProofError, Proofs};
use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey as _};
use serde_json::json;

fn configuration(scope: Option<&str>) -> CredentialConfiguration {
    CredentialConfiguration {
        format: CredentialFormat::SdJwtVc,
        scope: scope.map(str::to_owned),
        cryptographic_binding_methods_supported: Vec::new(),
        credential_signing_alg_values_supported: vec!["ES256".to_owned()],
        proof_types_supported: BTreeMap::new(),
        vct: None,
        doctype: None,
        credential_metadata: None,
    }
}

fn access(configuration_ids: &[&str], credential_identifiers: &[&str]) -> CredentialAccess {
    CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        subject_id: Uuid::now_v7(),
        client_id: "wallet".to_owned(),
        configuration_ids: configuration_ids
            .iter()
            .map(|id| (*id).to_owned())
            .collect(),
        credential_identifiers: credential_identifiers
            .iter()
            .map(|id| nazo_openid4vci::CredentialIdentifier((*id).to_owned()))
            .collect(),
        dpop_jkt: None,
        expires_at: Utc::now(),
    }
}

fn request_configuration(id: &str) -> CredentialRequest {
    CredentialRequest {
        credential_identifier: None,
        credential_configuration_id: Some(id.to_owned()),
        proofs: None,
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    }
}

fn request_identifier(id: &str) -> CredentialRequest {
    CredentialRequest {
        credential_identifier: Some(nazo_openid4vci::CredentialIdentifier(id.to_owned())),
        credential_configuration_id: None,
        proofs: None,
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    }
}

#[test]
fn authorization_details_filter_by_type_issuer_and_scope() {
    let configurations = BTreeMap::from([
        ("pid".to_owned(), configuration(Some("openid"))),
        ("other".to_owned(), configuration(Some("other-scope"))),
    ]);
    let details = json!([
        {"type":"openid_credential", "credential_configuration_id":"pid", "locations":["https://issuer.example"], "credential_identifiers":["pid-1", "pid-2", "pid-1"]},
        {"type":"openid_credential", "credential_configuration_id":"other", "locations":["https://other.example"]},
        {"type":"not_openid_credential", "credential_configuration_id":"ignored"},
        {"type":"openid_credential", "credential_identifiers":["pid-3"]}
    ]);

    let (ids, identifiers) = authorized_credentials(
        &details,
        "openid",
        "https://issuer.example",
        &configurations,
    )
    .expect("matching details and scope should be authorized");
    assert_eq!(ids, vec!["pid"]);
    assert_eq!(
        identifiers,
        vec![
            nazo_openid4vci::CredentialIdentifier("pid-1".to_owned()),
            nazo_openid4vci::CredentialIdentifier("pid-2".to_owned()),
            nazo_openid4vci::CredentialIdentifier("pid-3".to_owned()),
        ]
    );
}

#[test]
fn authorization_details_reject_empty_and_unknown_configurations() {
    let configurations = BTreeMap::from([("pid".to_owned(), configuration(None))]);
    let empty = authorized_credentials(&json!([]), "", "https://issuer.example", &configurations)
        .expect_err("empty authorization details must not grant issuance");
    assert_eq!((empty.status, empty.error), (403, "insufficient_scope"));

    let unknown = authorized_credentials(
        &json!([{"type":"openid_credential", "credential_configuration_id":"missing"}]),
        "",
        "https://issuer.example",
        &configurations,
    )
    .expect_err("unknown configuration must be rejected");
    assert_eq!((unknown.status, unknown.error), (403, "insufficient_scope"));
}

#[test]
fn resolve_configuration_id_enforces_exactly_one_identifier_and_access() {
    let malformed = CredentialRequest {
        credential_identifier: None,
        credential_configuration_id: None,
        proofs: None,
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    };
    assert_eq!(
        resolve_configuration_id(&malformed, &access(&["pid"], &[]))
            .expect_err("missing identifier should fail")
            .error,
        "invalid_credential_request"
    );

    let both = CredentialRequest {
        credential_identifier: Some(nazo_openid4vci::CredentialIdentifier("pid".to_owned())),
        credential_configuration_id: Some("pid".to_owned()),
        proofs: None,
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    };
    assert_eq!(
        resolve_configuration_id(&both, &access(&["pid"], &[]))
            .expect_err("two identifiers should fail")
            .error,
        "invalid_credential_request"
    );
    assert_eq!(
        resolve_configuration_id(&request_configuration("pid"), &access(&[], &[]))
            .expect_err("unauthorized configuration should fail")
            .error,
        "unknown_credential_configuration"
    );
    assert_eq!(
        resolve_configuration_id(&request_configuration("pid"), &access(&["pid"], &["pid-1"]))
            .expect_err("identifier-scoped access must use an identifier")
            .error,
        "invalid_credential_request"
    );
    assert_eq!(
        resolve_configuration_id(&request_configuration("pid"), &access(&["pid"], &[]))
            .expect("configuration-scoped access should resolve"),
        "pid"
    );
}

#[test]
fn resolve_identifier_supports_derived_and_direct_configuration_ids() {
    let derived = request_identifier("nazo-vci-cGlk");
    assert_eq!(
        resolve_configuration_id(&derived, &access(&["pid"], &["nazo-vci-cGlk"]))
            .expect("identifier should derive its configuration"),
        "pid"
    );
    let direct = request_identifier("pid");
    assert_eq!(
        resolve_configuration_id(&direct, &access(&["pid"], &[]))
            .expect("identifier equal to configuration id should resolve"),
        "pid"
    );
    assert_eq!(
        resolve_configuration_id(&request_identifier("missing"), &access(&["pid"], &[]))
            .expect_err("unknown identifier should fail")
            .error,
        "unknown_credential_identifier"
    );
    assert_eq!(
        resolve_configuration_id(&derived, &access(&["other"], &["nazo-vci-cGlk"]))
            .expect_err("derived identifier must match an authorized configuration")
            .error,
        "unknown_credential_identifier"
    );
}

#[test]
fn proof_nonce_and_request_digest_are_stable_and_fail_closed() {
    assert_eq!(extract_proof_nonce(None), None);
    assert_eq!(
        extract_proof_nonce(Some(&Proofs(BTreeMap::from([(
            "jwt".to_owned(),
            vec![json!("not-a-jwt")],
        )])))),
        None
    );
    let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("valid P-256 fixture key");
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("openid4vci-proof+jwt".to_owned());
    let jwt = encode(
        &header,
        &json!({"nonce":"nonce-1"}),
        &EncodingKey::from_ec_der(
            signing_key
                .to_pkcs8_der()
                .expect("fixture key should encode")
                .as_bytes(),
        ),
    )
    .expect("valid JWT proof fixture");
    assert_eq!(
        extract_proof_nonce(Some(&Proofs(BTreeMap::from([(
            "jwt".to_owned(),
            vec![json!(jwt)],
        )])))),
        Some("nonce-1".to_owned())
    );

    let first = issuance_request_digest(
        "credential",
        &request_identifier("pid"),
        "/credential",
        "POST",
    )
    .expect("request model is serializable");
    assert_eq!(
        first,
        issuance_request_digest(
            "credential",
            &request_identifier("pid"),
            "/credential",
            "POST"
        )
        .expect("same request should hash identically")
    );
    assert_ne!(
        first,
        issuance_request_digest(
            "credential",
            &request_identifier("pid"),
            "/credential",
            "GET"
        )
        .expect("method is part of the digest")
    );
    assert_ne!(
        stable_issuance_id(Uuid::nil(), &first),
        stable_issuance_id(Uuid::now_v7(), &first)
    );

    struct Failing;
    impl serde::Serialize for Failing {
        fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("fixture serialization failure"))
        }
    }
    let error = issuance_request_digest("credential", &Failing, "/credential", "POST")
        .expect_err("serialization failures must become server errors");
    assert_eq!((error.status, error.error), (500, "server_error"));
}

#[test]
fn stored_and_recovered_responses_preserve_encoding_status_and_nonce() {
    let now = Utc::now();
    let final_body = CredentialResponseBody::Json(CredentialResponse {
        credentials: Some(vec![nazo_openid4vci::IssuedCredential {
            credential: json!("signed"),
        }]),
        transaction_id: None,
        notification_id: None,
        interval: None,
    });
    let stored = stored_response(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "digest".to_owned(),
        &final_body,
        Some("dpop".to_owned()),
        now,
    )
    .expect("JSON response should be stored");
    assert_eq!(stored.status, 200);
    assert_eq!(stored.dpop_nonce.as_deref(), Some("dpop"));
    let recovered = response_from_record(stored).expect("stored JSON should recover");
    assert_eq!(recovered.dpop_nonce.as_deref(), Some("dpop"));
    assert!(matches!(recovered.body, CredentialResponseBody::Json(_)));

    let deferred = CredentialResponseBody::Json(CredentialResponse {
        credentials: None,
        transaction_id: Some("transaction-1".to_owned()),
        notification_id: None,
        interval: None,
    });
    let stored = stored_response(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "digest".to_owned(),
        &deferred,
        None,
        now,
    )
    .expect("deferred response should be stored");
    assert_eq!(stored.status, 202);
    assert!(body_encoding_is_deferred(&stored.encoding, &stored.body));

    let jwt = CredentialResponseBody::Jwt("signed.jwt".to_owned());
    let stored = stored_response(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "digest".to_owned(),
        &jwt,
        None,
        now,
    )
    .expect("JWT response should be stored");
    assert!(!body_encoding_is_deferred(&stored.encoding, &stored.body));
    assert!(matches!(
        response_from_record(stored).expect("stored JWT should recover").body,
        CredentialResponseBody::Jwt(value) if value == "signed.jwt"
    ));

    let mut invalid = StoredCredentialResponse {
        issuance_id: Uuid::nil(),
        token_id: Uuid::nil(),
        request_digest: "digest".to_owned(),
        body: b"not-json".to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: now,
    };
    assert_eq!(
        response_from_record(invalid.clone())
            .expect_err("invalid JSON must fail")
            .error,
        "server_error"
    );
    invalid.encoding = CredentialResponseEncoding::Jwt;
    invalid.body = vec![0xff];
    assert_eq!(
        response_from_record(invalid)
            .expect_err("invalid UTF-8 must fail")
            .error,
        "server_error"
    );
}

#[test]
fn issuance_errors_map_to_stable_http_contracts() {
    let cases = [
        (
            CredentialIssuanceError::Credential(CredentialError::InvalidNonce),
            400,
            "invalid_nonce",
        ),
        (
            CredentialIssuanceError::Credential(CredentialError::InvalidProof),
            400,
            "invalid_proof",
        ),
        (
            CredentialIssuanceError::Proof(ProofError::Unavailable),
            400,
            "invalid_proof",
        ),
        (
            CredentialIssuanceError::InvalidHolderBinding,
            400,
            "invalid_proof",
        ),
        (
            CredentialIssuanceError::Unauthorized,
            403,
            "insufficient_scope",
        ),
        (CredentialIssuanceError::SigningFailed, 503, "server_error"),
        (
            CredentialIssuanceError::Store(CredentialStoreError::Unavailable),
            503,
            "server_error",
        ),
    ];
    for (error, status, code) in cases {
        let mapped = map_issuance_error(error);
        assert_eq!((mapped.status, mapped.error), (status, code));
    }
    assert_eq!(
        (
            vci_error(418, "teapot", "fixture").status,
            vci_error(418, "teapot", "fixture").error
        ),
        (418, "teapot")
    );
    assert_eq!(
        (
            vp_error(419, "vp_fixture", "fixture").status,
            vp_error(419, "vp_fixture", "fixture").error
        ),
        (419, "vp_fixture")
    );
}
