use chrono::{Duration, TimeZone, Utc};
use nazo_identity::scim::{
    SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN, SCIM_ERROR_SCHEMA, SCIM_LIST_SCHEMA,
    SCIM_PATCH_SCHEMA, SCIM_USER_SCHEMA, ScimCursorContext, ScimCursorError, ScimCursorSubject,
    ScimDeleteOutcome, ScimEmail, ScimListRequest, ScimName, ScimPagination, ScimPatchOperation,
    ScimRepositoryFailure, ScimRequiredScope, ScimUserRequest, build_scim_cursor_plaintext,
    decode_scim_cursor_envelope, decode_scim_cursor_plaintext, encode_scim_cursor_envelope,
    normalize_patch, normalize_scim_user_filter, normalize_scim_user_payload,
    parse_scim_list_query, scim_credential_allows, scim_cursor_list_document, scim_error_document,
    scim_index_list_document, scim_resource_types_document, scim_schemas_document,
    scim_service_provider_config_document, scim_user_document, scim_user_schema_document,
    select_scim_pagination, validate_patch_schema,
};
use nazo_identity::{
    AccountIdentity, Principal, PublicAccount, TenantContext, UserId, UserProfile, UserRole,
    ports::RepositoryError,
};
use serde_json::json;
use uuid::Uuid;

fn fixture_user() -> PublicAccount {
    let timestamp = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("fixture timestamp is valid");
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(0x11111111111111111111111111111111))
                .expect("fixture user ID is non-nil"),
            tenant: TenantContext::default_system(),
            role: UserRole::Admin { level: 99 },
            active: true,
        },
        account: AccountIdentity {
            username: "internal-name".to_owned(),
            email: "alice@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile {
            display_name: Some("Alice".to_owned()),
            given_name: Some("Alice".to_owned()),
            family_name: Some("Example".to_owned()),
            ..UserProfile::default()
        },
        created_at: timestamp,
        updated_at: timestamp + Duration::minutes(1),
    }
}

#[test]
fn list_query_parser_preserves_wire_names_and_exact_error_types() {
    let parsed = parse_scim_list_query(
        "startIndex=7&count=25&filter=userName%20eq%20%22ALICE%40example.test%22&cursor=opaque&ignored=value",
    )
    .expect("valid query should parse");
    assert_eq!(parsed.start_index, Some(7));
    assert_eq!(parsed.count, Some(25));
    assert_eq!(
        parsed.filter.as_deref(),
        Some(r#"userName eq "ALICE@example.test""#)
    );
    assert_eq!(parsed.cursor.as_deref(), Some("opaque"));

    for (query, scim_type, detail) in [
        (
            "startIndex=nope",
            "invalidValue",
            "startIndex must be an integer",
        ),
        (
            "startIndex=1&startIndex=2",
            "invalidValue",
            "startIndex must not be repeated",
        ),
        ("count=nope", "invalidCount", "count must be an integer"),
        (
            "count=1&count=2",
            "invalidCount",
            "count must not be repeated",
        ),
        (
            "filter=a&filter=b",
            "invalidValue",
            "filter must not be repeated",
        ),
        (
            "cursor=a&cursor=b",
            "invalidCursor",
            "cursor must not be repeated",
        ),
    ] {
        let error = parse_scim_list_query(query).expect_err(query);
        assert_eq!(error.scim_type, scim_type, "{query}");
        assert_eq!(error.detail, detail, "{query}");
    }
}

#[test]
fn pagination_is_total_and_bounded_across_boundary_values() {
    for count in [-10, -1, 0, 1, 100, 199, 200, 201, i64::MAX] {
        let index = select_scim_pagination(&ScimListRequest {
            start_index: Some(i64::MIN),
            count: Some(count),
            ..ScimListRequest::default()
        })
        .expect("index pagination clamps all integer inputs");
        let ScimPagination::Index { start_index, count } = index else {
            panic!("index request selected cursor pagination");
        };
        assert_eq!(start_index, 1);
        assert!((0..=200).contains(&count));
        assert_eq!(
            ScimPagination::Index { start_index, count }.repository_window(),
            (count, 0)
        );
    }

    for (count, expected) in [
        (-1, Ok(0)),
        (0, Ok(0)),
        (200, Ok(200)),
        (201, Err("invalidCount")),
    ] {
        let result = select_scim_pagination(&ScimListRequest {
            count: Some(count),
            cursor: Some(String::new()),
            ..ScimListRequest::default()
        });
        match expected {
            Ok(expected_count) => {
                assert_eq!(
                    result.expect("cursor count should be valid"),
                    ScimPagination::Cursor {
                        encoded: None,
                        count: expected_count,
                    }
                );
            }
            Err(expected_type) => assert_eq!(
                result.expect_err("cursor count should fail").scim_type,
                expected_type
            ),
        }
    }

    let mixed = select_scim_pagination(&ScimListRequest {
        start_index: Some(1),
        cursor: Some(String::new()),
        ..ScimListRequest::default()
    })
    .expect_err("pagination methods are mutually exclusive");
    assert_eq!(mixed.scim_type, "invalidValue");
}

#[test]
fn filter_and_identity_normalization_are_case_stable() {
    for (input, expected) in [
        (r#"userName eq "USER@EXAMPLE.TEST""#, "user@example.test"),
        (
            r#" USERNAME eq "Mixed.Case+Tag@Example.Test" "#,
            "mixed.case+tag@example.test",
        ),
    ] {
        assert_eq!(
            normalize_scim_user_filter(Some(input))
                .expect("supported filter should normalize")
                .as_deref(),
            Some(expected)
        );
    }

    for malformed in [
        "email eq \"user@example.test\"",
        "userName ne \"user@example.test\"",
        "userName eq user@example.test",
        "userName eq \"bad..dots@example.test\"",
    ] {
        assert_eq!(
            normalize_scim_user_filter(Some(malformed))
                .expect_err(malformed)
                .scim_type,
            "invalidFilter"
        );
    }

    let normalized = normalize_scim_user_payload(
        ScimUserRequest {
            user_name: Some(" USER@Example.Test ".to_owned()),
            active: None,
            name: Some(ScimName {
                formatted: Some(" Alice Example ".to_owned()),
                given_name: Some(" Alice ".to_owned()),
                family_name: Some(" Example ".to_owned()),
            }),
            emails: Some(vec![ScimEmail {
                value: Some("user@example.test".to_owned()),
                primary: Some(true),
            }]),
        },
        true,
    )
    .expect("equivalent identity fields should normalize");
    assert_eq!(normalized.user_name, "user@example.test");
    assert_eq!(normalized.email, normalized.user_name);
    assert_eq!(normalized.display_name.as_deref(), Some("Alice Example"));
    assert!(normalized.active);
}

#[test]
fn patch_schema_and_operations_preserve_scim_error_semantics() {
    assert!(validate_patch_schema(&[]).is_ok());
    assert!(validate_patch_schema(&[SCIM_PATCH_SCHEMA.to_owned()]).is_ok());
    let schema_error = validate_patch_schema(&[SCIM_USER_SCHEMA.to_owned()])
        .expect_err("unsupported schema must fail");
    assert_eq!(schema_error.scim_type, "invalidSyntax");
    assert_eq!(schema_error.detail, "unsupported PATCH schema");

    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "RePlAcE".to_owned(),
        path: None,
        value: json!({
            "userName": "PATCHED@Example.Test",
            "emails": [{"value": "patched@example.test", "primary": true}],
            "active": false,
            "name": {"givenName": " Pat ", "familyName": " Ched "}
        }),
    }])
    .expect("supported object patch should normalize");
    assert_eq!(patch.user_name.as_deref(), Some("patched@example.test"));
    assert_eq!(patch.email, patch.user_name);
    assert_eq!(patch.active, Some(false));
    assert_eq!(patch.given_name.as_deref(), Some("Pat"));

    for (operation, expected_type) in [
        (
            ScimPatchOperation {
                op: "add".to_owned(),
                path: Some("active".to_owned()),
                value: json!(true),
            },
            "mutability",
        ),
        (
            ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("unknown".to_owned()),
                value: json!(true),
            },
            "invalidPath",
        ),
        (
            ScimPatchOperation {
                op: "replace".to_owned(),
                path: None,
                value: json!([]),
            },
            "invalidSyntax",
        ),
    ] {
        assert_eq!(
            normalize_patch(vec![operation])
                .expect_err("malformed patch must fail")
                .scim_type,
            expected_type
        );
    }
}

#[test]
fn cursor_core_binds_tenant_actor_filter_count_and_lifetime() {
    let now = Utc
        .with_ymd_and_hms(2025, 2, 3, 4, 5, 6)
        .single()
        .expect("fixture timestamp is valid");
    let subject = ScimCursorSubject {
        tenant_id: Uuid::from_u128(0x22222222222222222222222222222222),
        actor: "database:33333333-3333-3333-3333-333333333333".to_owned(),
    };
    let position_time = now - Duration::seconds(30);
    let position_id = Uuid::from_u128(0x44444444444444444444444444444444);
    let plaintext = build_scim_cursor_plaintext(
        &ScimCursorContext {
            subject: &subject,
            filter: Some(r#"userName eq "alice@example.test""#),
            count: 25,
            last_created_at: position_time,
            last_id: position_id,
        },
        now,
    )
    .expect("cursor claims should serialize");
    let position = decode_scim_cursor_plaintext(
        &plaintext,
        &subject,
        Some(r#"userName eq "alice@example.test""#),
        25,
        now,
    )
    .expect("matching claims should validate");
    assert_eq!(position.last_created_at, position_time);
    assert_eq!(position.last_id, position_id);

    assert_eq!(
        decode_scim_cursor_plaintext(
            &plaintext,
            &subject,
            Some(r#"userName eq "alice@example.test""#),
            26,
            now,
        ),
        Err(ScimCursorError::InvalidCount)
    );
    assert_eq!(
        decode_scim_cursor_plaintext(&plaintext, &subject, None, 25, now),
        Err(ScimCursorError::Invalid)
    );
    assert_eq!(
        decode_scim_cursor_plaintext(
            &plaintext,
            &subject,
            Some(r#"userName eq "alice@example.test""#),
            25,
            now + Duration::seconds(600),
        ),
        Err(ScimCursorError::Expired)
    );

    let other_subject = ScimCursorSubject {
        actor: "database:other".to_owned(),
        ..subject.clone()
    };
    assert_eq!(
        decode_scim_cursor_plaintext(
            &plaintext,
            &other_subject,
            Some(r#"userName eq "alice@example.test""#),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );
}

#[test]
fn cursor_envelope_rejects_noncanonical_and_malformed_inputs() {
    let protected = vec![7_u8; SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN + 1];
    let encoded = encode_scim_cursor_envelope(&protected);
    assert_eq!(
        decode_scim_cursor_envelope(&encoded).expect("canonical envelope should decode"),
        protected
    );
    for invalid in [
        String::new(),
        format!("{encoded}="),
        "!not-url-safe!".to_owned(),
        encode_scim_cursor_envelope(&[0; SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN]),
        "A".repeat(4097),
    ] {
        assert_eq!(
            decode_scim_cursor_envelope(&invalid),
            Err(ScimCursorError::Invalid),
            "{invalid}"
        );
    }
}

#[test]
fn documents_preserve_public_wire_shape_and_hide_internal_identity_state() {
    let user = fixture_user();
    let document = scim_user_document(&user);
    assert_eq!(document["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(document["id"], json!(user.id()));
    assert_eq!(document["userName"], "alice@example.test");
    assert_eq!(document["emails"][0]["primary"], true);
    assert_eq!(
        document["meta"]["location"],
        format!("/scim/v2/Users/{}", user.id())
    );
    for forbidden in [
        "tenant_id",
        "password_hash",
        "role",
        "admin_level",
        "mfa_enabled",
    ] {
        assert!(document.get(forbidden).is_none(), "{forbidden}");
    }

    let schema = scim_user_schema_document();
    assert_eq!(schema["id"], SCIM_USER_SCHEMA);
    assert_eq!(
        scim_schemas_document()["schemas"],
        json!([SCIM_LIST_SCHEMA])
    );
    assert_eq!(
        scim_resource_types_document()["Resources"][0]["endpoint"],
        "/Users"
    );
    let config = scim_service_provider_config_document();
    assert_eq!(config["pagination"]["defaultPageSize"], 100);
    assert_eq!(config["pagination"]["maxPageSize"], 200);
    assert_eq!(config["pagination"]["cursorTimeout"], 600);

    let index = scim_index_list_document(9, 3, std::slice::from_ref(&user));
    assert_eq!(index["startIndex"], 3);
    assert_eq!(index["itemsPerPage"], 1);
    let cursor = scim_cursor_list_document(9, std::slice::from_ref(&user), Some("next"));
    assert!(cursor.get("startIndex").is_none());
    assert_eq!(cursor["nextCursor"], "next");
    assert!(
        scim_cursor_list_document(0, &[], None)
            .get("nextCursor")
            .is_none()
    );

    let error = scim_error_document(409, "uniqueness", "userName or email already exists");
    assert_eq!(error["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(error["status"], "409");
    assert_eq!(error.as_object().map(serde_json::Map::len), Some(4));
}

#[test]
fn repository_failures_delete_outcomes_and_scopes_are_typed() {
    for (error, expected) in [
        (RepositoryError::NotFound, ScimRepositoryFailure::NotFound),
        (RepositoryError::Conflict, ScimRepositoryFailure::Uniqueness),
        (
            RepositoryError::Unavailable,
            ScimRepositoryFailure::BackendUnavailable,
        ),
        (
            RepositoryError::Consistency("broken".to_owned()),
            ScimRepositoryFailure::BackendUnavailable,
        ),
    ] {
        assert_eq!(ScimRepositoryFailure::from(&error), expected);
    }
    assert_eq!(ScimDeleteOutcome::from(true), ScimDeleteOutcome::Deleted);
    assert_eq!(ScimDeleteOutcome::from(false), ScimDeleteOutcome::NotFound);

    for (scopes, required, allowed) in [
        (vec!["scim:read".to_owned()], ScimRequiredScope::Read, true),
        (
            vec!["scim:read".to_owned()],
            ScimRequiredScope::Write,
            false,
        ),
        (vec!["scim:*".to_owned()], ScimRequiredScope::Write, true),
        (vec!["other".to_owned()], ScimRequiredScope::Read, false),
    ] {
        assert_eq!(scim_credential_allows(&scopes, required), allowed);
    }
}

#[test]
fn malformed_cursor_plaintext_is_rejected_without_panicking() {
    let subject = ScimCursorSubject {
        tenant_id: Uuid::from_u128(1),
        actor: "actor".to_owned(),
    };
    let now = Utc::now();
    for plaintext in [
        Vec::new(),
        b"not-json".to_vec(),
        serde_json::to_vec(&json!({"v": 1})).expect("fixture should serialize"),
    ] {
        assert_eq!(
            decode_scim_cursor_plaintext(&plaintext, &subject, None, 10, now),
            Err(ScimCursorError::Invalid)
        );
    }
}

#[test]
fn scim_json_models_deserialize_post_and_patch_inputs_without_extra_dtos() {
    let create: ScimUserRequest = serde_json::from_value(json!({
        "schemas": [SCIM_USER_SCHEMA],
        "userName": "alice@example.test",
        "active": true,
        "emails": [{"value": "alice@example.test", "primary": true}]
    }))
    .expect("POST model should preserve existing tolerant schema handling");
    assert_eq!(create.user_name.as_deref(), Some("alice@example.test"));

    let patch: nazo_identity::scim::ScimPatchRequest = serde_json::from_value(json!({
        "schemas": [SCIM_PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": false}]
    }))
    .expect("PATCH wire model should deserialize");
    validate_patch_schema(&patch.schemas).expect("PATCH schema should validate");
    assert_eq!(
        normalize_patch(patch.operations).unwrap().active,
        Some(false)
    );
}
