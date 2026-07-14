use super::*;
use crate::settings::SamlGatewaySettings;

const TEST_SECRET: &str = "01234567890123456789012345678901";

fn settings() -> SamlGatewaySettings {
    SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: TEST_SECRET.to_owned(),
    }
}

fn sign(settings: &SamlGatewaySettings, subject: &str, email: &str, iat: i64, exp: i64) -> String {
    saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        subject,
        email,
        iat,
        exp,
    )
}

fn assertion(
    settings: &SamlGatewaySettings,
    subject: &str,
    email: &str,
    iat: i64,
    exp: i64,
) -> SamlGatewayAssertion {
    SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: subject.to_owned(),
        email: email.to_owned(),
        name: None,
        iat,
        exp,
        signature: sign(settings, subject, email, iat, exp),
    }
}

#[test]
fn saml_gateway_signature_is_deterministic() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = saml_gateway_signature(
        &settings.secret,
        "iss",
        "aud",
        "sub",
        "e@m.co",
        now,
        now + 60,
    );
    let b = saml_gateway_signature(
        &settings.secret,
        "iss",
        "aud",
        "sub",
        "e@m.co",
        now,
        now + 60,
    );
    assert_eq!(a, b);
}

#[test]
fn saml_gateway_signature_differs_for_different_fields() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = saml_gateway_signature(
        &settings.secret,
        "iss",
        "aud",
        "sub",
        "e@m.co",
        now,
        now + 60,
    );
    let b = saml_gateway_signature(
        &settings.secret,
        "other",
        "aud",
        "sub",
        "e@m.co",
        now,
        now + 60,
    );
    assert_ne!(a, b);
}

#[test]
fn valid_saml_gateway_assertion_accepts_valid_assertion() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = assertion(&settings, "subject", "user@example.com", now, now + 60);
    assert!(valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_expired_assertion() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = assertion(
        &settings,
        "subject",
        "user@example.com",
        now - 600,
        now - 60,
    );
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_wrong_issuer() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let mut a = assertion(&settings, "subject", "user@example.com", now, now + 60);
    a.issuer = "other-gateway".to_owned();
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_wrong_audience() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let mut a = assertion(&settings, "subject", "user@example.com", now, now + 60);
    a.audience = "other-audience".to_owned();
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_empty_subject() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = assertion(&settings, "  ", "user@example.com", now, now + 60);
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_iat_too_far_in_future() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = assertion(
        &settings,
        "subject",
        "user@example.com",
        now + 61,
        now + 120,
    );
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_exp_iat_window_too_long() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = assertion(&settings, "subject", "user@example.com", now, now + 301);
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_signature_mismatch() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let mut a = assertion(&settings, "subject", "user@example.com", now, now + 60);
    a.signature = sign(
        &settings,
        "other-subject",
        "user@example.com",
        now,
        now + 60,
    );
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "user@example.com"
    ));
}

#[test]
fn valid_saml_gateway_assertion_rejects_normalized_email_mismatch() {
    let settings = settings();
    let now = Utc::now().timestamp();
    let a = assertion(&settings, "subject", "user@example.com", now, now + 60);
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &a,
        "other@example.com"
    ));
}
