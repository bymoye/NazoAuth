use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

use crate::KeyManager;

#[test]
fn dedicated_request_object_key_decrypts_authenticated_nested_jwt() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::RS256);
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let nested = "header.claims.signature";
    let compact = encrypt(&jwk, nested.as_bytes());

    assert_eq!(
        manager
            .decrypt_request_object(&compact)
            .expect("request object decrypts"),
        nested
    );
}

#[test]
fn request_object_decryption_rejects_tampered_ciphertext() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::RS256);
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let mut compact = encrypt(&jwk, b"header.claims.signature");
    let replacement = if compact.ends_with('A') { 'B' } else { 'A' };
    compact.pop();
    compact.push(replacement);

    assert!(manager.decrypt_request_object(&compact).is_err());
}

#[test]
fn request_object_decryption_rejects_invalid_encrypted_key_before_aead() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::RS256);
    let jwk = manager.snapshot().request_object_encryption_jwk.clone();
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "kid": jwk["kid"],
            "cty": "JWT"
        }))
        .expect("header"),
    );
    let compact = format!(
        "{}.{}.{}.{}.{}",
        protected,
        URL_SAFE_NO_PAD.encode([1_u8, 2, 3]),
        URL_SAFE_NO_PAD.encode([0_u8; 12]),
        URL_SAFE_NO_PAD.encode([0_u8; 1]),
        URL_SAFE_NO_PAD.encode([0_u8; 16])
    );

    let error = manager
        .decrypt_request_object(&compact)
        .expect_err("invalid RSA ciphertext must fail before AEAD");
    assert!(format!("{error:#}").contains("RSA") || format!("{error:#}").contains("decrypt"));
}

fn encrypt(jwk: &serde_json::Value, plaintext: &[u8]) -> String {
    let kid = jwk["kid"].as_str().expect("kid");
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "kid": kid,
            "cty": "JWT"
        }))
        .expect("header"),
    );
    let cek = rand::random::<[u8; 32]>();
    let encrypted_key = crate::crypto::test_support::rsa_oaep_sha256_encrypt(
        &URL_SAFE_NO_PAD
            .decode(jwk["n"].as_str().expect("n"))
            .expect("n encoding"),
        &URL_SAFE_NO_PAD
            .decode(jwk["e"].as_str().expect("e"))
            .expect("e encoding"),
        &cek,
    )
    .expect("encrypt key");

    let iv = rand::random::<[u8; 12]>();
    let (ciphertext, tag) = crate::crypto::test_support::aes_256_gcm_encrypt(
        &cek,
        &iv,
        protected.as_bytes(),
        plaintext,
    )
    .expect("encrypt payload");
    format!(
        "{}.{}.{}.{}.{}",
        protected,
        URL_SAFE_NO_PAD.encode(encrypted_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    )
}
