use nazo_auth::{
    canonical_authorization_details, high_risk_authorization_details,
    normalize_authorization_details, parse_authorization_details,
};
use serde_json::{Value, json};

#[test]
fn authorization_details_require_array_of_supported_typed_objects() {
    assert_eq!(parse_authorization_details(None).unwrap(), json!([]));
    assert_eq!(
        parse_authorization_details(Some(r#"[{"type":"account_information"}]"#)).unwrap(),
        json!([{"type":"account_information"}])
    );

    for raw in [
        r#"{"type":"payment"}"#,
        r#"[{"type":"unknown"}]"#,
        r#"[{"locations":["x"]}]"#,
        r#"[{"type":" "}]"#,
        r#"[{"type":"payment","actions":"write"}]"#,
    ] {
        assert!(
            parse_authorization_details(Some(raw)).is_err(),
            "accepted malformed authorization_details: {raw}"
        );
    }
}

#[test]
fn authorization_details_enforce_rar_size_and_cardinality_limits() {
    let oversized = " ".repeat(16 * 1024 + 1);
    assert!(parse_authorization_details(Some(&oversized)).is_err());

    let too_many_items = json!(
        (0..33)
            .map(|_| json!({"type": "account_information"}))
            .collect::<Vec<_>>()
    );
    assert!(normalize_authorization_details(too_many_items).is_err());

    let too_many_actions = json!([{
        "type": "account_information",
        "actions": (0..33).map(|_| json!("read")).collect::<Vec<_>>()
    }]);
    assert!(normalize_authorization_details(too_many_actions).is_err());
}

#[test]
fn canonicalization_preserves_the_exact_valid_json_shape() {
    let details = json!([{
        "type": "payment_initiation",
        "actions": ["read", "transfer"],
        "locations": ["https://api.example/payments"]
    }]);

    assert_eq!(
        canonical_authorization_details(&details).unwrap(),
        r#"[{"actions":["read","transfer"],"locations":["https://api.example/payments"],"type":"payment_initiation"}]"#
    );
}

#[test]
fn high_risk_authorization_details_detect_payments_and_write_actions() {
    assert!(high_risk_authorization_details(&json!([
        {"type": "payment_initiation", "actions": ["read"]}
    ])));
    assert!(high_risk_authorization_details(&json!([
        {"type": "account_information", "actions": ["write"]}
    ])));
    assert!(!high_risk_authorization_details(&json!([
        {"type": "account_information", "actions": ["read"]}
    ])));
}

#[test]
fn authorization_details_normalization_preserves_only_empty_internal_states() {
    assert_eq!(
        normalize_authorization_details(Value::Null).unwrap(),
        json!([])
    );
    assert_eq!(
        normalize_authorization_details(json!({})).unwrap(),
        json!([])
    );
    assert_eq!(
        normalize_authorization_details(json!([{"type":"account_information"}])).unwrap(),
        json!([{"type":"account_information"}])
    );
    assert!(normalize_authorization_details(json!({"type":"account_information"})).is_err());
    assert!(normalize_authorization_details(json!([{"type":"unknown"}])).is_err());
}
