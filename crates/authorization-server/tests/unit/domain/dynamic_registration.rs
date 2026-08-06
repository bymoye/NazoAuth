use super::*;
use nazo_auth::DynamicRegistrationSecretPort;

#[test]
fn dynamic_registration_initial_access_digest_is_lowercase_sha256() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn dynamic_registration_secret_port_hashes_and_compares_without_plaintext_reuse() {
    let secrets = ServerDynamicRegistrationTokens;
    let token = secrets.random_token();
    let hash = secrets.token_hash(&token);

    assert!(!token.is_empty());
    assert_ne!(hash, token);
    assert!(secrets.constant_time_eq(hash.as_bytes(), hash.as_bytes()));
    assert!(!secrets.constant_time_eq(hash.as_bytes(), token.as_bytes()));
}
