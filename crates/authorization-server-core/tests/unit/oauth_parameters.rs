use serde_json::json;

use super::*;

#[test]
fn scope_and_subset_policy_preserve_oauth_semantics() {
    assert_eq!(
        parse_scope("  openid   email openid "),
        ["openid", "email", "openid"]
    );
    assert!(is_subset(
        &parse_scope("openid email"),
        &parse_scope("email profile openid")
    ));
    assert!(is_subset(&[], &parse_scope("openid")));
}

#[test]
fn json_string_collections_ignore_non_string_members() {
    assert_eq!(
        string_array_values(&json!(["openid", 1, null, "email"])),
        ["openid", "email"]
    );
    assert!(string_array_values(&json!({"scope": "openid"})).is_empty());
}

#[test]
fn token_audience_policy_accepts_string_or_array_only() {
    assert_eq!(token_audience_values(&json!("api")), ["api"]);
    assert_eq!(
        token_audience_values(&json!(["api", 1, null, "admin"])),
        ["api", "admin"]
    );
    assert!(token_audience_values(&json!(true)).is_empty());
    assert!(token_audience_contains(&json!(["other", "api"]), "api"));
}

#[test]
fn duplicate_detection_is_limited_to_named_parameters() {
    assert!(has_duplicate_oauth_parameter(
        "client_id=one&scope=openid&client_id=two",
        &["client_id", "redirect_uri"]
    ));
    assert!(!has_duplicate_oauth_parameter(
        "scope=openid&scope=email&client_id=one",
        &["client_id", "redirect_uri"]
    ));
}
