use nazo_identity::{
    TenantContext, UserId,
    email::{VerificationEmail, normalize_email_address},
    federation::normalize_federation_token,
    mfa::{
        MFA_TOTP_PERIOD_SECONDS, MfaVerificationMethod, base32_decode, base32_encode,
        generate_backup_code, generate_totp_secret_base32, normalize_backup_code, otpauth_uri,
        totp_for_step, verified_totp_step,
    },
    passkey::{normalize_ceremony_id, normalize_passkey_label, passkey_user_handle},
    scim::{
        SCIM_PATCH_SCHEMA, SCIM_USER_SCHEMA, ScimEmail, ScimName, ScimPatchOperation,
        ScimUserRequest, normalize_patch, normalize_scim_user_filter, normalize_scim_user_payload,
    },
    session::{add_amr, valid_authentication_metadata},
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn mfa_policy_preserves_totp_and_backup_code_contracts() {
    let secret = b"12345678901234567890";
    for (timestamp, expected) in [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ] {
        assert_eq!(
            totp_for_step(secret, timestamp / MFA_TOTP_PERIOD_SECONDS).unwrap(),
            expected
        );
    }
    assert_eq!(MfaVerificationMethod::Totp.amr(), "otp");
    assert_eq!(MfaVerificationMethod::BackupCode.amr(), "recovery_code");
    assert_eq!(
        normalize_backup_code(" 12345-67890 ").as_deref(),
        Some("1234567890")
    );
    assert!(normalize_backup_code("12345--67890").is_none());
}

#[test]
fn totp_verification_rejects_replay_and_keeps_one_step_skew() {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let now = 1_234_567_890;
    let step = now / MFA_TOTP_PERIOD_SECONDS;
    let current = totp_for_step(b"12345678901234567890", step).unwrap();
    let previous = totp_for_step(b"12345678901234567890", step - 1).unwrap();
    let too_old = totp_for_step(b"12345678901234567890", step - 2).unwrap();
    let future = totp_for_step(b"12345678901234567890", step + 1).unwrap();
    let too_future = totp_for_step(b"12345678901234567890", step + 2).unwrap();
    assert_eq!(verified_totp_step(secret, &current, now, None), Some(step));
    assert_eq!(
        verified_totp_step(secret, &previous, now, None),
        Some(step - 1)
    );
    assert_eq!(
        verified_totp_step(secret, &future, now, None),
        Some(step + 1)
    );
    assert_eq!(verified_totp_step(secret, &current, now, Some(step)), None);
    assert_eq!(verified_totp_step(secret, &too_old, now, None), None);
    assert_eq!(verified_totp_step(secret, &too_future, now, None), None);
    assert!(totp_for_step(b"secret", -1).is_err());
}

#[test]
fn generated_totp_secret_is_base32_without_padding() {
    let secret = generate_totp_secret_base32();

    assert_eq!(secret.len(), 32);
    assert!(
        secret
            .chars()
            .all(|value| matches!(value, 'A'..='Z' | '2'..='7'))
    );
    assert_eq!(base32_decode(&secret).unwrap().len(), 20);
}

#[test]
fn generated_backup_code_uses_two_fixed_width_numeric_chunks() {
    for _ in 0..128 {
        let code = generate_backup_code();
        let (left, right) = code
            .split_once('-')
            .expect("generated backup code should contain a separator");

        assert_eq!(left.len(), 5);
        assert_eq!(right.len(), 5);
        assert!(left.bytes().all(|value| value.is_ascii_digit()));
        assert!(right.bytes().all(|value| value.is_ascii_digit()));
        assert_eq!(
            normalize_backup_code(&code).as_deref(),
            Some([left, right].concat().as_str())
        );
    }
}

#[test]
fn backup_code_normalization_preserves_strict_display_contract() {
    assert_eq!(
        normalize_backup_code("12345 67890").as_deref(),
        Some("1234567890")
    );
    for malformed in [
        "1234-67890",
        "abcdefghij",
        "12345--67890",
        "12345\t67890",
        "１２３４５６７８９０",
        "12345-678901",
    ] {
        assert!(normalize_backup_code(malformed).is_none(), "{malformed:?}");
    }
}

#[test]
fn base32_decode_accepts_transport_whitespace_case_and_padding_only() {
    let encoded = base32_encode(b"hello world");

    assert_eq!(
        base32_decode(&encoded).as_deref(),
        Some(b"hello world".as_slice())
    );
    assert_eq!(
        base32_decode(&format!("  {}\n=", encoded.to_ascii_lowercase())).as_deref(),
        Some(b"hello world".as_slice())
    );
    assert_eq!(base32_decode("===="), None);
    assert_eq!(base32_decode("JBSWY3DP!"), None);
}

#[test]
fn totp_verifier_rejects_malformed_code_or_secret_without_fallback() {
    let secret = base32_encode(b"12345678901234567890");
    let now = 1_234_567_890;
    let step = now / MFA_TOTP_PERIOD_SECONDS;
    let code = totp_for_step(b"12345678901234567890", step).unwrap();

    for malformed in ["", "00592", "0059247", "00592a", "005 24"] {
        assert_eq!(verified_totp_step(&secret, malformed, now, None), None);
    }
    assert_eq!(verified_totp_step("!!!!", &code, now, None), None);
    assert_eq!(verified_totp_step("", &code, now, None), None);
}

#[test]
fn otpauth_uri_keeps_existing_encoding_contract() {
    let uri = otpauth_uri("Nazo OAuth/Production", "user+admin@example.com", "SECRET");
    assert!(
        uri.starts_with("otpauth://totp/Nazo%20OAuth%2FProduction:user%2Badmin%40example.com?")
    );
    assert!(uri.contains("secret=SECRET"));
    assert!(uri.contains("issuer=Nazo%20OAuth%2FProduction"));
}

#[test]
fn session_policy_validates_metadata_and_preserves_amr_order() {
    assert!(valid_authentication_metadata(
        1_000,
        &["password".to_owned()],
        Some("sid-1"),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_031,
        &["password".to_owned()],
        Some("sid-1"),
        1_000
    ));
    assert!(!valid_authentication_metadata(
        1_000,
        &[],
        Some("sid-1"),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_000,
        &["password".to_owned()],
        Some(" "),
        1_001
    ));

    let mut amr = vec!["pwd".to_owned(), "otp".to_owned()];
    add_amr(&mut amr, "mfa");
    add_amr(&mut amr, "pwd");
    assert_eq!(amr, ["pwd", "otp", "mfa"]);
}

#[test]
fn passkey_policy_binds_tenant_user_and_validates_user_input() {
    let tenant = TenantContext::default_system();
    let user = UserId::new(Uuid::from_u128(4)).unwrap();
    let handle = passkey_user_handle(tenant.tenant_id, user);
    assert_eq!(handle.len(), 32);
    assert!(handle.starts_with(tenant.tenant_id.as_uuid().as_bytes()));
    assert!(handle.ends_with(user.as_uuid().as_bytes()));
    assert_eq!(normalize_passkey_label(None).unwrap(), "Passkey");
    assert_eq!(
        normalize_passkey_label(Some("  Laptop key  ")).unwrap(),
        "Laptop key"
    );
    assert!(normalize_passkey_label(Some(&"x".repeat(121))).is_err());
    assert_eq!(
        normalize_ceremony_id("abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_").unwrap(),
        "abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_"
    );
    assert!(normalize_ceremony_id("short").is_err());
}

#[test]
fn email_policy_normalizes_addresses_and_renders_existing_template() {
    assert_eq!(
        normalize_email_address(" USER@Example.COM ").unwrap(),
        "user@example.com"
    );
    for invalid in ["", "not an email", "Nazo <user@example.com>", "a@b,c@d"] {
        assert!(normalize_email_address(invalid).is_err(), "{invalid:?}");
    }
    let body = VerificationEmail::new("123456", 900).render_html();
    assert!(body.contains("123456"));
    assert!(body.contains("15 分钟"));
}

#[test]
fn email_policy_preserves_lettre_address_syntax_contract() {
    for invalid in [".alice@example.com", "alice..smith@example.com"] {
        assert!(
            normalize_email_address(invalid).is_err(),
            "invalid dot placement must be rejected: {invalid}"
        );
    }

    assert_eq!(
        normalize_email_address(r#""Alice Smith"@Example.COM"#).unwrap(),
        r#""alice smith"@example.com"#
    );
}

#[test]
fn federation_callback_token_policy_is_exact() {
    let token = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_";
    assert_eq!(normalize_federation_token(token).as_deref(), Some(token));
    assert!(normalize_federation_token("short").is_none());
    assert!(normalize_federation_token(&format!("{}!", "x".repeat(31))).is_none());
}

#[test]
fn scim_policy_normalizes_identity_filter_payload_and_patch() {
    assert_eq!(
        SCIM_USER_SCHEMA,
        "urn:ietf:params:scim:schemas:core:2.0:User"
    );
    assert_eq!(
        SCIM_PATCH_SCHEMA,
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    );
    assert_eq!(
        normalize_scim_user_filter(Some(r#"userName eq "USER@example.com""#))
            .unwrap()
            .as_deref(),
        Some("user@example.com")
    );

    let normalized = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: Some("USER@example.com".to_owned()),
            active: None,
            name: Some(ScimName {
                given_name: Some(" Alice ".to_owned()),
                family_name: Some(" Example ".to_owned()),
                formatted: Some(" Alice Example ".to_owned()),
            }),
            emails: Some(vec![ScimEmail {
                value: Some("user@example.com".to_owned()),
                primary: Some(true),
            }]),
        },
        true,
    )
    .unwrap();
    assert_eq!(normalized.user_name, "user@example.com");
    assert_eq!(normalized.display_name.as_deref(), Some("Alice Example"));
    assert!(normalized.active);

    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: None,
        value: json!({"emails": [{"value": "NEW@example.com", "primary": true}]}),
    }])
    .unwrap();
    assert_eq!(patch.user_name.as_deref(), Some("new@example.com"));
    assert_eq!(patch.email.as_deref(), Some("new@example.com"));
}

#[test]
fn scim_policy_rejects_invalid_email_dot_placement() {
    for invalid in [".alice@example.com", "alice..smith@example.com"] {
        let filter = format!(r#"userName eq "{invalid}""#);
        assert!(normalize_scim_user_filter(Some(&filter)).is_err());

        assert!(
            normalize_scim_user_payload(
                ScimUserRequest {
                    user_name: Some(invalid.to_owned()),
                    active: None,
                    name: None,
                    emails: Some(vec![ScimEmail {
                        value: Some(invalid.to_owned()),
                        primary: Some(true),
                    }]),
                },
                true,
            )
            .is_err()
        );
    }
}
