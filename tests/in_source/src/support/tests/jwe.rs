use super::*;

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
