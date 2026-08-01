use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::BigNum,
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    symm::{Cipher, encrypt_aead},
};
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
    let rsa = Rsa::from_public_components(
        BigNum::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwk["n"].as_str().expect("n"))
                .expect("n encoding"),
        )
        .expect("n"),
        BigNum::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwk["e"].as_str().expect("e"))
                .expect("e encoding"),
        )
        .expect("e"),
    )
    .expect("public RSA");
    let key = PKey::from_rsa(rsa).expect("public key");
    let mut encrypter = Encrypter::new(&key).expect("encrypter");
    encrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .expect("padding");
    encrypter
        .set_rsa_oaep_md(MessageDigest::sha256())
        .expect("oaep digest");
    encrypter
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .expect("mgf1 digest");
    let cek = [7_u8; 32];
    let mut encrypted_key = vec![0_u8; encrypter.encrypt_len(&cek).expect("encrypted key length")];
    let encrypted_key_len = encrypter
        .encrypt(&cek, &mut encrypted_key)
        .expect("encrypt key");
    encrypted_key.truncate(encrypted_key_len);

    let iv = [9_u8; 12];
    let mut tag = [0_u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        protected.as_bytes(),
        plaintext,
        &mut tag,
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
