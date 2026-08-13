use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_digital_credentials::{
    EphemeralEncryptionKey, JweError, encrypt_ecdh_es, encrypt_ecdh_es_a128,
    encrypt_ecdh_es_deflate, parse_compact_jwe,
};

#[test]
fn ecdh_es_a256gcm_round_trip_is_authenticated() {
    let recipient = EphemeralEncryptionKey::generate();
    let compact = encrypt_ecdh_es(
        br#"{"vp_token":"credential"}"#,
        &recipient.public_jwk(),
        Some("application/json"),
    )
    .expect("encrypt");
    assert_eq!(
        recipient.decrypt(&compact).expect("decrypt"),
        br#"{"vp_token":"credential"}"#
    );
    let mut parts = compact.split('.').map(str::to_owned).collect::<Vec<_>>();
    let replacement = if parts[4].starts_with('A') { "B" } else { "A" };
    parts[4].replace_range(0..1, replacement);
    assert_eq!(
        recipient.decrypt(&parts.join(".")),
        Err(JweError::AuthenticationFailed)
    );
}

#[test]
fn ecdh_es_output_matches_compact_jwe_serialization_contract() {
    let recipient = EphemeralEncryptionKey::generate();
    let compact = encrypt_ecdh_es(
        br#"{"vp_token":"credential"}"#,
        &recipient.public_jwk(),
        Some("application/json"),
    )
    .expect("encrypt");

    let parsed = parse_compact_jwe(&compact).expect("parse compact JWE");
    assert!(parsed.encrypted_key.is_empty());
    assert!(!parsed.protected.is_empty());
    assert!(!parsed.initialization_vector.is_empty());
    assert!(!parsed.ciphertext.is_empty());
    assert!(!parsed.authentication_tag.is_empty());

    let protected: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&parsed.protected)
            .expect("decode protected header"),
    )
    .expect("protected header JSON");
    let ephemeral = protected["epk"].as_object().expect("ephemeral JWK");
    assert_eq!(
        ephemeral.get("kty").and_then(serde_json::Value::as_str),
        Some("EC")
    );
    assert_eq!(
        ephemeral.get("crv").and_then(serde_json::Value::as_str),
        Some("P-256")
    );
    assert!(ephemeral.get("alg").is_none());
    assert!(ephemeral.get("use").is_none());
    assert_eq!(
        recipient
            .decrypt(&compact)
            .expect("decrypt JWE with JOSE epk"),
        br#"{"vp_token":"credential"}"#
    );

    for malformed in [
        "a.b.c.d",
        "a.b.c.d.e.f",
        ".b.c.d.e",
        "a.b..d.e",
        "a.b.c..e",
        "a.b.c.d.",
    ] {
        assert!(
            parse_compact_jwe(malformed).is_err(),
            "malformed compact JWE should be rejected: {malformed}"
        );
    }
}

#[test]
fn ecdh_es_ephemeral_jwk_rejects_an_explicit_wrong_algorithm() {
    let recipient = EphemeralEncryptionKey::generate();
    let compact = encrypt_ecdh_es(
        b"credential",
        &recipient.public_jwk(),
        Some("application/json"),
    )
    .expect("encrypt");
    let mut parts = compact.split('.').map(str::to_owned).collect::<Vec<_>>();
    let mut protected: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&parts[0])
            .expect("decode protected header"),
    )
    .expect("protected header JSON");
    protected["epk"]["alg"] = serde_json::json!("ECDH-ES+A256KW");
    parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected).expect("encode header"));

    assert_eq!(
        recipient.decrypt(&parts.join(".")),
        Err(JweError::InvalidKey)
    );
}

#[test]
fn ecdh_es_recipient_jwk_requires_an_exact_algorithm_binding() {
    let recipient = EphemeralEncryptionKey::generate();
    let mut missing_algorithm = recipient.public_jwk();
    missing_algorithm
        .as_object_mut()
        .expect("public JWK object")
        .remove("alg");
    assert_eq!(
        encrypt_ecdh_es(b"credential", &missing_algorithm, Some("application/json")),
        Err(JweError::InvalidKey)
    );

    let mut wrong_algorithm = recipient.public_jwk();
    wrong_algorithm["alg"] = serde_json::json!("ECDH-ES+A256KW");
    assert_eq!(
        encrypt_ecdh_es(b"credential", &wrong_algorithm, Some("application/json")),
        Err(JweError::InvalidKey)
    );
}

#[test]
fn ecdh_es_a128gcm_round_trip_matches_oid4vp_default() {
    let recipient = EphemeralEncryptionKey::generate();
    let compact = encrypt_ecdh_es_a128(
        br#"{"vp_token":"credential"}"#,
        &recipient.public_jwk(),
        Some("json"),
    )
    .expect("encrypt A128GCM");

    assert_eq!(
        recipient.decrypt(&compact).expect("decrypt A128GCM"),
        br#"{"vp_token":"credential"}"#
    );
}

#[test]
fn deflate_round_trip_is_authenticated_and_bounded() {
    let recipient = EphemeralEncryptionKey::generate();
    let plaintext = br#"{"credential":"repetitive-repetitive-repetitive"}"#;
    let compact =
        encrypt_ecdh_es_deflate(plaintext, &recipient.public_jwk(), Some("application/json"))
            .expect("encrypt compressed JWE");

    assert_eq!(
        recipient.decrypt(&compact).expect("decrypt compressed JWE"),
        plaintext
    );
}
