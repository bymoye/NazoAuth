use super::*;

fn fixture_password(label: &str) -> String {
    format!("password-policy-fixture-{label}")
}

#[test]
fn numeric_code_is_six_ascii_digits() {
    let code = random_numeric_code();

    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|value| value.is_ascii_digit()));
}

#[test]
fn password_hash_policy_is_explicit_argon2id_v19() {
    let password = fixture_password("registered");
    let wrong_password = fixture_password("presented");
    let hash = hash_password(&password).expect("password should hash");

    assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(verify_password(&password, &hash));
    assert!(!verify_password(&wrong_password, &hash));
    assert!(!verify_password(&password, "not-an-argon2-password-hash"));
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
