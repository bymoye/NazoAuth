use super::*;
use aws_lc_rs::key_wrap::{AES_128, AES_256, AesKek, KeyWrap};
use openssl::symm::decrypt_aead;
use p256::elliptic_curve::Generate;

#[test]
fn client_jwe_key_rejects_ambiguous_matching_keys() {
    let jwks = json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "enc-1",
                "use": "enc",
                "alg": "RSA-OAEP-256",
                "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "kid": "enc-2",
                "use": "enc",
                "alg": "RSA-OAEP-256",
                "n": URL_SAFE_NO_PAD.encode([0x92u8; 256]),
                "e": "AQAB"
            }
        ]
    });

    let error = match client_jwe_key(
        Some(&jwks),
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
        "userinfo",
    ) {
        Ok(_) => panic!("runtime encryption key selection must reject ambiguity"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("ambiguous encryption keys"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_jwe_encrypts_with_supported_ecdh_key_management_algorithms() {
    for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"] {
        let recipient = SecretKey::generate();
        let mut public = public_p256_jwk(recipient.public_key());
        public["kid"] = json!(format!("{alg}-kid"));
        public["use"] = json!("enc");
        public["alg"] = json!(alg);
        let jwks = json!({ "keys": [public] });
        let key = client_jwe_key(Some(&jwks), Some(alg), Some("A256GCM"), "userinfo")
            .expect("supported ECDH JWE key metadata")
            .expect("ECDH JWE key should be selected");

        let compact = encrypt_compact_jwe(&key, br#"{"sub":"user"}"#, JwePayloadKind::Claims)
            .expect("encrypt ECDH compact JWE");

        assert_eq!(
            decrypt_ecdh_compact_jwe(&compact, &recipient),
            br#"{"sub":"user"}"#
        );
    }
}

#[test]
fn client_jwe_key_rejects_unsupported_ecdh_and_symmetric_algorithms() {
    let recipient = SecretKey::generate();
    let mut public = public_p256_jwk(recipient.public_key());
    public["kid"] = json!("enc");
    public["use"] = json!("enc");
    public["alg"] = json!("ECDH-ES+A192KW");
    let jwks = json!({ "keys": [public] });

    let error = match client_jwe_key(
        Some(&jwks),
        Some("ECDH-ES+A192KW"),
        Some("A256GCM"),
        "userinfo",
    ) {
        Ok(_) => panic!("unsupported ECDH key-wrap algorithm must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsupported userinfo JWE alg"));

    let symmetric = json!({
        "keys": [{
            "kty": "oct",
            "kid": "sym",
            "use": "enc",
            "alg": "A256KW",
            "k": URL_SAFE_NO_PAD.encode([0xA5_u8; 32])
        }]
    });
    let error = match client_jwe_key(
        Some(&symmetric),
        Some("A256KW"),
        Some("A256GCM"),
        "userinfo",
    ) {
        Ok(_) => panic!("symmetric client JWE key management must not be accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsupported userinfo JWE alg"));
}

fn decrypt_ecdh_compact_jwe(compact: &str, recipient: &SecretKey) -> Vec<u8> {
    let parts = compact.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 5);
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("decode protected"))
            .expect("protected header JSON");
    assert_eq!(header.get("enc").and_then(Value::as_str), Some("A256GCM"));
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .expect("JWE alg header");
    let ephemeral = parse_p256_public_jwk(header.get("epk").expect("epk header")).expect("epk");
    let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
    let cek = if alg == "ECDH-ES" {
        assert!(parts[1].is_empty());
        concat_kdf(
            shared.raw_secret_bytes().as_slice(),
            "A256GCM",
            &[],
            &[],
            256,
        )
    } else {
        let kek_bits = match alg {
            "ECDH-ES+A128KW" => 128,
            "ECDH-ES+A256KW" => 256,
            other => panic!("unexpected alg: {other}"),
        };
        let kek = concat_kdf(
            shared.raw_secret_bytes().as_slice(),
            alg,
            &[],
            &[],
            kek_bits,
        );
        let encrypted_key = URL_SAFE_NO_PAD.decode(parts[1]).expect("encrypted key");
        aes_key_unwrap(&kek, &encrypted_key)
    };
    let iv: [u8; 12] = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("iv")
        .try_into()
        .expect("96-bit IV");
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[3]).expect("ciphertext");
    let tag: [u8; 16] = URL_SAFE_NO_PAD
        .decode(parts[4])
        .expect("tag")
        .try_into()
        .expect("128-bit tag");
    decrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        parts[0].as_bytes(),
        &ciphertext,
        &tag,
    )
    .expect("decrypt compact JWE")
}

fn aes_key_unwrap(kek: &[u8], encrypted_key: &[u8]) -> Vec<u8> {
    let mut output = vec![0_u8; encrypted_key.len() - 8];
    let unwrapped = match kek.len() {
        16 => AesKek::new(&AES_128, kek)
            .expect("A128KW")
            .unwrap(encrypted_key, &mut output),
        32 => AesKek::new(&AES_256, kek)
            .expect("A256KW")
            .unwrap(encrypted_key, &mut output),
        other => panic!("unexpected KEK length: {other}"),
    }
    .expect("unwrap CEK");
    unwrapped.to_vec()
}
