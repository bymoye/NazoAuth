use super::*;

// normalize_scim_string

#[test]
fn normalize_scim_string_returns_none_for_empty_when_not_required() {
    assert_eq!(
        normalize_scim_string(Some(String::new()), 120, "test", false).unwrap(),
        None
    );
}

#[test]
fn normalize_scim_string_returns_none_for_whitespace_when_not_required() {
    assert_eq!(
        normalize_scim_string(Some("  ".to_owned()), 120, "test", false).unwrap(),
        None
    );
}

#[test]
fn normalize_scim_string_returns_none_when_not_provided_and_not_required() {
    assert_eq!(
        normalize_scim_string(None, 120, "test", false).unwrap(),
        None
    );
}

#[test]
fn normalize_scim_string_errors_when_required_and_missing() {
    let err = normalize_scim_string(None, 120, "userName", true).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn normalize_scim_string_errors_when_too_long() {
    let long = "x".repeat(121);
    let err = normalize_scim_string(Some(long), 120, "userName", false).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn normalize_scim_string_trims_whitespace() {
    assert_eq!(
        normalize_scim_string(Some("  hello  ".to_owned()), 120, "test", false)
            .unwrap()
            .as_deref(),
        Some("hello")
    );
}

#[test]
fn normalize_scim_string_accepts_value_at_exact_max_bytes() {
    let exact = "x".repeat(120);
    assert_eq!(
        normalize_scim_string(Some(exact.clone()), 120, "test", false)
            .unwrap()
            .as_deref(),
        Some(exact.as_str())
    );
}

// required_string_value

#[test]
fn required_string_value_accepts_valid_string() {
    assert_eq!(
        required_string_value(json!("hello"), "field").unwrap(),
        "hello"
    );
}

#[test]
fn required_string_value_trims_input() {
    assert_eq!(
        required_string_value(json!("  hello  "), "field").unwrap(),
        "hello"
    );
}

#[test]
fn required_string_value_rejects_null() {
    assert!(required_string_value(json!(null), "field").is_err());
}

#[test]
fn required_string_value_rejects_non_string() {
    assert!(required_string_value(json!(42), "field").is_err());
    assert!(required_string_value(json!(true), "field").is_err());
    assert!(required_string_value(json!([]), "field").is_err());
}

#[test]
fn required_string_value_rejects_empty_after_trim() {
    assert!(required_string_value(json!("  "), "field").is_err());
}

// required_email_value

#[test]
fn required_email_value_accepts_valid_email() {
    assert_eq!(
        required_email_value(json!("user@example.com"), "email").unwrap(),
        "user@example.com"
    );
}

#[test]
fn required_email_value_normalizes_case() {
    assert_eq!(
        required_email_value(json!("USER@Example.COM"), "email").unwrap(),
        "user@example.com"
    );
}

#[test]
fn required_email_value_rejects_invalid_email() {
    let err = required_email_value(json!("not-an-email"), "email").unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn required_email_value_rejects_missing_value() {
    assert!(required_email_value(json!(null), "email").is_err());
}

// required_bool_value

#[test]
fn required_bool_value_accepts_true() {
    assert!(required_bool_value(json!(true), "active").unwrap());
}

#[test]
fn required_bool_value_accepts_false() {
    assert!(!required_bool_value(json!(false), "active").unwrap());
}

#[test]
fn required_bool_value_rejects_non_bool_string() {
    let err = required_bool_value(json!("true"), "active").unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn required_bool_value_rejects_number() {
    assert!(required_bool_value(json!(1), "active").is_err());
}

#[test]
fn required_bool_value_rejects_null() {
    assert!(required_bool_value(json!(null), "active").is_err());
}

#[test]
fn required_bool_value_rejects_array() {
    assert!(required_bool_value(json!([]), "active").is_err());
}

// normalize_scim_path

#[test]
fn normalize_scim_path_trims_outer_whitespace() {
    assert_eq!(normalize_scim_path("  userName  "), "username");
}

#[test]
fn normalize_scim_path_removes_inner_spaces() {
    assert_eq!(normalize_scim_path("name  formatted"), "nameformatted");
}

#[test]
fn normalize_scim_path_lowercases_mixed_case() {
    assert_eq!(normalize_scim_path("Name.GivenName"), "name.givenname");
}

#[test]
fn normalize_scim_path_handles_camelcase_path() {
    assert_eq!(
        normalize_scim_path("  name.FamilyName  "),
        "name.familyname"
    );
}

#[test]
fn normalize_scim_path_does_not_remove_periods() {
    assert_eq!(normalize_scim_path("name.givenName"), "name.givenname");
}

// normalize_email_address

#[test]
fn normalize_email_address_lowercases_and_trims() {
    assert_eq!(
        normalize_email_address("  USER@Example.COM  ").unwrap(),
        "user@example.com"
    );
}

#[test]
fn normalize_email_address_rejects_missing_at_sign() {
    assert!(normalize_email_address("not-email").is_err());
}

#[test]
fn normalize_email_address_rejects_empty_string() {
    assert!(normalize_email_address("").is_err());
}

// primary_email

#[test]
fn primary_email_selects_flagged_primary_over_others() {
    let emails = Some(vec![
        ScimEmail {
            value: Some("first@example.com".to_owned()),
            primary: Some(false),
        },
        ScimEmail {
            value: Some("second@example.com".to_owned()),
            primary: Some(true),
        },
        ScimEmail {
            value: Some("third@example.com".to_owned()),
            primary: Some(false),
        },
    ]);
    assert_eq!(primary_email(emails, false).unwrap(), "second@example.com");
}

#[test]
fn primary_email_falls_back_to_first_entry_when_none_marked_primary() {
    let emails = Some(vec![
        ScimEmail {
            value: Some("first@example.com".to_owned()),
            primary: Some(false),
        },
        ScimEmail {
            value: Some("second@example.com".to_owned()),
            primary: Some(false),
        },
    ]);
    assert_eq!(primary_email(emails, false).unwrap(), "first@example.com");
}

#[test]
fn primary_email_falls_back_to_first_entry_when_primary_null() {
    let emails = Some(vec![
        ScimEmail {
            value: Some("first@example.com".to_owned()),
            primary: None,
        },
        ScimEmail {
            value: Some("second@example.com".to_owned()),
            primary: Some(true),
        },
    ]);
    assert_eq!(primary_email(emails, false).unwrap(), "second@example.com");
}

#[test]
fn primary_email_errors_when_values_contain_null_email() {
    let err = primary_email(
        Some(vec![ScimEmail {
            value: None,
            primary: Some(true),
        }]),
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn primary_email_errors_when_values_empty() {
    let err = primary_email(Some(vec![]), true).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn primary_email_returns_empty_string_when_not_required_and_no_emails() {
    assert_eq!(primary_email(None, false).unwrap(), String::new());
}

#[test]
fn primary_email_errors_when_required_and_no_emails() {
    let err = primary_email(None, true).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn primary_email_errors_on_invalid_email() {
    let err = primary_email(
        Some(vec![ScimEmail {
            value: Some("invalid".to_owned()),
            primary: Some(true),
        }]),
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

// primary_email_from_value

#[test]
fn primary_email_from_value_accepts_valid_array() {
    assert_eq!(
        primary_email_from_value(json!([{"value": "user@example.com", "primary": true}])).unwrap(),
        "user@example.com"
    );
}

#[test]
fn primary_email_from_value_selects_primary_from_array() {
    assert_eq!(
        primary_email_from_value(json!([
            {"value": "first@example.com", "primary": false},
            {"value": "second@example.com", "primary": true}
        ]))
        .unwrap(),
        "second@example.com"
    );
}

#[test]
fn primary_email_from_value_rejects_non_array() {
    let err = primary_email_from_value(json!("not-array")).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn primary_email_from_value_rejects_object() {
    assert!(primary_email_from_value(json!({"value": "test@example.com"})).is_err());
}

#[test]
fn primary_email_from_value_rejects_invalid_email_in_array() {
    assert!(primary_email_from_value(json!([{"value": "invalid", "primary": true}])).is_err());
}

// normalize_scim_user_filter

#[test]
fn scim_user_filter_returns_none_for_no_filter() {
    assert_eq!(normalize_scim_user_filter(None).unwrap(), None);
}

#[test]
fn scim_user_filter_returns_none_for_empty_filter() {
    assert_eq!(normalize_scim_user_filter(Some("")).unwrap(), None);
}

#[test]
fn scim_user_filter_returns_none_for_whitespace_filter() {
    assert_eq!(normalize_scim_user_filter(Some("  ")).unwrap(), None);
}

#[test]
fn scim_user_filter_accepts_valid_user_name_eq_quoted_email() {
    let result = normalize_scim_user_filter(Some(r#"userName eq "USER@example.com""#)).unwrap();
    assert_eq!(result.as_deref(), Some("user@example.com"));
}

#[test]
fn scim_user_filter_normalizes_email_case() {
    let result = normalize_scim_user_filter(Some(r#"userName eq "UPPER@Example.COM""#)).unwrap();
    assert_eq!(result.as_deref(), Some("upper@example.com"));
}

#[test]
fn scim_user_filter_rejects_unsupported_operator() {
    let err = normalize_scim_user_filter(Some(r#"userName co "user@example.com""#)).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_user_filter_rejects_unsupported_field() {
    let err = normalize_scim_user_filter(Some(r#"email eq "user@example.com""#)).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_user_filter_rejects_unquoted_value() {
    let err = normalize_scim_user_filter(Some("userName eq user@example.com")).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_user_filter_rejects_partial_quotes() {
    let err = normalize_scim_user_filter(Some(r#"userName eq "user@example.com"#)).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_user_filter_rejects_invalid_email_in_quoted_value() {
    let err = normalize_scim_user_filter(Some(r#"userName eq "not-an-email""#)).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

// normalize_scim_user_payload

#[test]
fn scim_payload_normalizes_valid_input_with_all_fields() {
    let payload = ScimUserRequest {
        user_name: Some("USER@example.com".to_owned()),
        active: Some(true),
        name: Some(ScimName {
            given_name: Some(" Alice ".to_owned()),
            family_name: Some(" Example ".to_owned()),
            formatted: Some(" Alice Example ".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };
    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert_eq!(normalized.user_name, "user@example.com");
    assert_eq!(normalized.email, "user@example.com");
    assert_eq!(normalized.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(normalized.given_name.as_deref(), Some("Alice"));
    assert_eq!(normalized.family_name.as_deref(), Some("Example"));
    assert!(normalized.active);
}

#[test]
fn scim_payload_defaults_active_to_true_when_omitted() {
    let payload = ScimUserRequest {
        user_name: Some("user@example.com".to_owned()),
        active: None,
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };
    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert!(normalized.active);
}

#[test]
fn scim_payload_defaults_active_to_true_when_explicitly_true() {
    let payload = ScimUserRequest {
        user_name: Some("user@example.com".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };
    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert!(normalized.active);
}

#[test]
fn scim_payload_accepts_active_false() {
    let payload = ScimUserRequest {
        user_name: Some("user@example.com".to_owned()),
        active: Some(false),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };
    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert!(!normalized.active);
}

#[test]
fn scim_payload_sets_display_name_fields_to_none_when_name_omitted() {
    let payload = ScimUserRequest {
        user_name: Some("user@example.com".to_owned()),
        active: None,
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };
    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert!(normalized.display_name.is_none());
    assert!(normalized.given_name.is_none());
    assert!(normalized.family_name.is_none());
}

#[test]
fn scim_payload_rejects_missing_user_name_when_identity_required() {
    let err = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: None,
            active: None,
            name: None,
            emails: Some(vec![ScimEmail {
                value: Some("user@example.com".to_owned()),
                primary: Some(true),
            }]),
        },
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_payload_rejects_non_email_user_name() {
    let err = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: Some("not-an-email".to_owned()),
            active: None,
            name: None,
            emails: Some(vec![ScimEmail {
                value: Some("user@example.com".to_owned()),
                primary: Some(true),
            }]),
        },
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_payload_rejects_primary_email_mismatch_with_user_name() {
    let err = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: Some("user@example.com".to_owned()),
            active: None,
            name: None,
            emails: Some(vec![ScimEmail {
                value: Some("other@example.com".to_owned()),
                primary: Some(true),
            }]),
        },
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_payload_rejects_missing_emails_when_required() {
    let err = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: Some("user@example.com".to_owned()),
            active: None,
            name: None,
            emails: None,
        },
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_payload_rejects_empty_emails_array_when_required() {
    let err = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: Some("user@example.com".to_owned()),
            active: None,
            name: None,
            emails: Some(vec![]),
        },
        true,
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn scim_payload_accepts_missing_optional_identity_when_not_required() {
    let payload = ScimUserRequest {
        user_name: None,
        active: None,
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };
    let normalized = normalize_scim_user_payload(payload, false).unwrap();
    assert!(normalized.user_name.is_empty());
    assert_eq!(normalized.email, "user@example.com");
}

// normalize_patch

#[test]
fn patch_accepts_replace_operation_with_user_name_path() {
    let result = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("userName".to_owned()),
        value: json!("USER@example.com"),
    }]);
    let patch = result.unwrap();
    assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
    assert_eq!(patch.email.as_deref(), Some("user@example.com"));
}

#[test]
fn patch_accepts_replace_operation_with_active_path() {
    let result = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("active".to_owned()),
        value: json!(false),
    }]);
    let patch = result.unwrap();
    assert_eq!(patch.active, Some(false));
    assert!(patch.user_name.is_none());
    assert!(patch.email.is_none());
}

#[test]
fn patch_accepts_replace_operation_with_name_formatted_path() {
    let result = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("name.formatted".to_owned()),
        value: json!("New Display Name"),
    }]);
    let patch = result.unwrap();
    assert_eq!(patch.display_name.as_deref(), Some("New Display Name"));
}

#[test]
fn patch_accepts_replace_operation_with_name_givenname_path() {
    let result = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("name.givenName".to_owned()),
        value: json!("NewGiven"),
    }]);
    let patch = result.unwrap();
    assert_eq!(patch.given_name.as_deref(), Some("NewGiven"));
}

#[test]
fn patch_accepts_replace_operation_with_name_familyname_path() {
    let result = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("name.familyName".to_owned()),
        value: json!("NewFamily"),
    }]);
    let patch = result.unwrap();
    assert_eq!(patch.family_name.as_deref(), Some("NewFamily"));
}

#[test]
fn patch_accepts_replace_operation_with_emails_path() {
    let result = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("emails".to_owned()),
        value: json!([{"value": "new@example.com", "primary": true}]),
    }]);
    let patch = result.unwrap();
    assert_eq!(patch.email.as_deref(), Some("new@example.com"));
    assert_eq!(patch.user_name.as_deref(), Some("new@example.com"));
}

#[test]
fn patch_rejects_non_replace_operation() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "add".to_owned(),
        path: Some("active".to_owned()),
        value: json!(true),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_remove_operation() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "remove".to_owned(),
        path: Some("active".to_owned()),
        value: json!(null),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_case_insensitive_non_replace() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "ADD".to_owned(),
        path: Some("active".to_owned()),
        value: json!(true),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_empty_operations() {
    let err = normalize_patch(vec![]).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_unsupported_path() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("unsupported".to_owned()),
        value: json!("test"),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_non_boolean_active_value() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("active".to_owned()),
        value: json!("true"),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_non_email_user_name_value() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("userName".to_owned()),
        value: json!("not-an-email"),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_rejects_non_string_display_name() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("name.formatted".to_owned()),
        value: json!(42),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn patch_handles_multiple_operations() {
    let patch = normalize_patch(vec![
        ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("active".to_owned()),
            value: json!(false),
        },
        ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("name.formatted".to_owned()),
            value: json!("Display"),
        },
    ])
    .unwrap();
    assert_eq!(patch.active, Some(false));
    assert_eq!(patch.display_name.as_deref(), Some("Display"));
}

#[test]
fn patch_handles_object_style_value() {
    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: None,
        value: json!({
            "userName": "user@example.com",
            "active": true,
        }),
    }])
    .unwrap();
    assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
    assert_eq!(patch.email.as_deref(), Some("user@example.com"));
    assert_eq!(patch.active, Some(true));
}

#[test]
fn patch_accepts_emails_in_object_style_value() {
    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: None,
        value: json!({
            "emails": [{"value": "test@example.com", "primary": true}]
        }),
    }])
    .unwrap();
    assert_eq!(patch.email.as_deref(), Some("test@example.com"));
    assert_eq!(patch.user_name.as_deref(), Some("test@example.com"));
}

#[test]
fn patch_rejects_object_style_with_email_user_name_mismatch() {
    let err = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: None,
        value: json!({
            "userName": "user@example.com",
            "emails": [{"value": "other@example.com", "primary": true}]
        }),
    }])
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

// apply_patch_object

#[test]
fn apply_patch_object_rejects_non_object_value() {
    let mut patch = ScimPatch::default();
    let err = apply_patch_object(&mut patch, json!("string")).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn apply_patch_object_rejects_array_value() {
    let mut patch = ScimPatch::default();
    assert!(apply_patch_object(&mut patch, json!([])).is_err());
}

#[test]
fn apply_patch_object_rejects_number_value() {
    let mut patch = ScimPatch::default();
    assert!(apply_patch_object(&mut patch, json!(42)).is_err());
}

#[test]
fn apply_patch_object_parses_user_name() {
    let mut patch = ScimPatch::default();
    apply_patch_object(&mut patch, json!({"userName": "user@example.com"})).unwrap();
    assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
}

#[test]
fn apply_patch_object_parses_active() {
    let mut patch = ScimPatch::default();
    apply_patch_object(&mut patch, json!({"active": false})).unwrap();
    assert_eq!(patch.active, Some(false));
}

#[test]
fn apply_patch_object_parses_name_fields() {
    let mut patch = ScimPatch::default();
    apply_patch_object(
        &mut patch,
        json!({
            "name": {
                "formatted": "Formatted",
                "givenName": "Given",
                "familyName": "Family"
            }
        }),
    )
    .unwrap();
    assert_eq!(patch.display_name.as_deref(), Some("Formatted"));
    assert_eq!(patch.given_name.as_deref(), Some("Given"));
    assert_eq!(patch.family_name.as_deref(), Some("Family"));
}

#[test]
fn apply_patch_object_rejects_name_as_non_object() {
    let mut patch = ScimPatch::default();
    let err = apply_patch_object(&mut patch, json!({"name": "string"})).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn apply_patch_object_parses_emails() {
    let mut patch = ScimPatch::default();
    apply_patch_object(
        &mut patch,
        json!({"emails": [{"value": "email@example.com", "primary": true}]}),
    )
    .unwrap();
    assert_eq!(patch.email.as_deref(), Some("email@example.com"));
}

#[test]
fn apply_patch_object_rejects_email_user_name_mismatch() {
    let mut patch = ScimPatch::default();
    let err = apply_patch_object(
        &mut patch,
        json!({
            "userName": "user@example.com",
            "emails": [{"value": "other@example.com", "primary": true}]
        }),
    )
    .unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

// sync_scim_identity

#[test]
fn sync_identity_copies_user_name_to_email_when_email_missing() {
    let mut patch = ScimPatch {
        user_name: Some("user@example.com".to_owned()),
        ..Default::default()
    };
    sync_scim_identity(&mut patch).unwrap();
    assert_eq!(patch.email.as_deref(), Some("user@example.com"));
}

#[test]
fn sync_identity_copies_email_to_user_name_when_user_name_missing() {
    let mut patch = ScimPatch {
        email: Some("user@example.com".to_owned()),
        ..Default::default()
    };
    sync_scim_identity(&mut patch).unwrap();
    assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
}

#[test]
fn sync_identity_rejects_mismatch_between_user_name_and_email() {
    let mut patch = ScimPatch {
        user_name: Some("user@example.com".to_owned()),
        email: Some("other@example.com".to_owned()),
        ..Default::default()
    };
    let err = sync_scim_identity(&mut patch).unwrap_err();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn sync_identity_accepts_matching_user_name_and_email() {
    let mut patch = ScimPatch {
        user_name: Some("user@example.com".to_owned()),
        email: Some("user@example.com".to_owned()),
        ..Default::default()
    };
    sync_scim_identity(&mut patch).unwrap();
}

#[test]
fn sync_identity_is_noop_when_both_fields_missing() {
    let mut patch = ScimPatch::default();
    sync_scim_identity(&mut patch).unwrap();
    assert!(patch.user_name.is_none());
    assert!(patch.email.is_none());
}
