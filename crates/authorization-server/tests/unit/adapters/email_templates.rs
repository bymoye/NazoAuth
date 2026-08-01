use super::*;

#[test]
fn verification_html_contains_code_and_inline_styles() {
    let body = VerificationEmail::new("123456", 900).render_html();

    assert!(body.contains("<!doctype html>"));
    assert!(body.contains("123456"));
    assert!(body.contains("letter-spacing:8px"));
    assert!(body.contains("15 分钟"));
}

#[test]
fn verification_html_uses_seconds_for_non_minute_ttl() {
    let body = VerificationEmail::new("654321", 59).render_html();

    assert!(body.contains("654321"));
    assert!(body.contains("59 秒"));
    assert!(!body.contains("0 分钟"));
}
