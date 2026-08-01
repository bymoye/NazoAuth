use super::*;

fn fixture_password(label: &str) -> String {
    format!("password-policy-fixture-{label}")
}

#[test]
fn password_hash_policy_is_explicit_argon2id_v19() {
    let password = fixture_password("registered");
    let wrong_password = fixture_password("presented");
    let hash = hash_password(&password).expect("password should hash");

    assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    let parsed = nazo_identity::PasswordHash::new(hash).expect("valid password hash");
    assert!(parsed.verify_password(&password));
    assert!(!parsed.verify_password(&wrong_password));
    let malformed = nazo_identity::PasswordHash::new("not-an-argon2-password-hash")
        .expect("persistence model accepts opaque non-empty values");
    assert!(!malformed.verify_password(&password));
}

#[test]
fn random_urlsafe_token_is_256_bit_opaque_value() {
    let token = random_urlsafe_token();

    assert_eq!(token.len(), 43);
    assert!(
        token
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '-' || value == '_')
    );
}
