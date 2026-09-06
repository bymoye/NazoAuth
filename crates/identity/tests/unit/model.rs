use super::*;
use argon2::{Argon2, PasswordHasher};

#[test]
fn login_identity_debug_never_exposes_password_hash() {
    let secret = "$argon2id$v=19$m=19456,t=2,p=1$secret-salt$secret-digest";
    let login = LoginIdentity {
        account: AccountIdentity {
            username: "alice".to_owned(),
            email: "alice@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: false,
        },
        password_hash: PasswordHash::new(secret).unwrap(),
    };

    assert!(!format!("{login:?}").contains(secret));
}

#[test]
fn password_hash_verifies_candidates_without_exposing_the_verifier() {
    let encoded = Argon2::default()
        .hash_password_with_salt(b"correct horse battery staple", b"saltsalt")
        .unwrap()
        .to_string();
    let hash = PasswordHash::new(encoded).unwrap();

    assert!(hash.verify_password("correct horse battery staple"));
    assert!(!hash.verify_password("wrong password"));
}

#[test]
fn password_hash_accepts_argon2_0_5_phc_vector() {
    // Fixed Argon2id v19 vector from argon2 0.5.3 tests/kat.rs.
    // Keeping the encoded value proves compatibility without regenerating it.
    let encoded =
        "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";
    let hash = PasswordHash::new(encoded).unwrap();

    assert!(hash.verify_password("password"));
    assert!(!hash.verify_password("wrong password"));
}
