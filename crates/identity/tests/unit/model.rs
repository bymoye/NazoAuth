use super::*;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

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
        .hash_password(
            b"correct horse battery staple",
            &SaltString::from_b64("c2FsdHNhbHQ").unwrap(),
        )
        .unwrap()
        .to_string();
    let hash = PasswordHash::new(encoded).unwrap();

    assert!(hash.verify_password("correct horse battery staple"));
    assert!(!hash.verify_password("wrong password"));
}
