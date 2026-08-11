use super::*;

fn minimal_request() -> ConformanceOnboardingRequest {
    ConformanceOnboardingRequest {
        tenant: TenantContext::default_system(),
        task_jti: "task-1".to_owned(),
        profile: ATOMIC_CONFORMANCE_PROFILE.to_owned(),
        bundle_schema: 1,
        bundle_sha256: "a".repeat(64),
        material_sha256: "b".repeat(64),
        public_material: serde_json::json!({"schema": 1}),
        suite_origin: "https://suite.example.test".to_owned(),
        dynamic_registration_initial_access_token_sha256: Some("c".repeat(64)),
        ciba_automated_decision_token_sha256: Some("d".repeat(64)),
        client_count: 0,
        ttl_seconds: MIN_CONFORMANCE_LEASE_SECONDS,
        applicant: ConformanceApplicant {
            username: "oidf-applicant".to_owned(),
            email: "oidf-applicant@example.invalid".to_owned(),
            password_hash: PasswordHashInput::new("opaque-test-hash").unwrap(),
            email_verified: true,
            display_name: "Conformance Test User".to_owned(),
            given_name: "Conformance".to_owned(),
            family_name: "User".to_owned(),
            middle_name: "Test".to_owned(),
            nickname: "ctu".to_owned(),
            profile_url: "https://example.invalid/conformance/profile".to_owned(),
            avatar_url: "https://example.invalid/conformance/avatar".to_owned(),
            website_url: "https://example.invalid/conformance".to_owned(),
            gender: "unspecified".to_owned(),
            birthdate: "2000-01-01".to_owned(),
            zoneinfo: "UTC".to_owned(),
            locale: "en-US".to_owned(),
            address: nazo_identity::PostalAddress {
                formatted: Some(
                    "100 Universal City Plaza\nUniversal City, CA 91608\nUS".to_owned(),
                ),
                street_address: Some("100 Universal City Plaza".to_owned()),
                locality: Some("Universal City".to_owned()),
                region: Some("CA".to_owned()),
                postal_code: Some("91608".to_owned()),
                country: Some("US".to_owned()),
            },
            phone_number: "+1 555 5550000".to_owned(),
            phone_number_verified: true,
        },
        clients: Vec::new(),
        mtls_trust_anchors: Vec::new(),
        openid4vc_credential_datasets: BTreeMap::new(),
    }
}

#[test]
fn onboarding_rejects_empty_client_bundle_before_database_access() {
    let request = minimal_request();
    let error = validate_onboarding_request(&request).unwrap_err();
    assert!(error.to_string().contains("client count"));
}

#[test]
fn onboarding_rejects_control_character_task_jti() {
    let mut request = minimal_request();
    request.task_jti = "task-\n1".to_owned();
    let error = validate_onboarding_request(&request).unwrap_err();
    assert!(error.to_string().contains("task_jti"));
}

#[test]
fn onboarding_rejects_out_of_range_ttl_before_database_access() {
    let mut request = minimal_request();
    request.ttl_seconds = MAX_CONFORMANCE_LEASE_SECONDS + 1;
    let error = validate_onboarding_request(&request).unwrap_err();
    assert!(error.to_string().contains("ttl_seconds"));
}

#[test]
fn onboarding_address_accepts_oidc_line_feeds_but_rejects_other_controls() {
    let mut address = minimal_request().applicant.address;
    validate_conformance_postal_address(&address).unwrap();

    address.formatted = Some("100 Universal City Plaza\r\nUniversal City, CA 91608".to_owned());
    let error = validate_conformance_postal_address(&address).unwrap_err();
    assert!(error.to_string().contains("address.formatted"));

    address.formatted = Some("100 Universal City Plaza".to_owned());
    address.street_address = Some("100 Universal City Plaza\tSuite 1".to_owned());
    let error = validate_conformance_postal_address(&address).unwrap_err();
    assert!(error.to_string().contains("address.street_address"));
}

#[test]
fn full_onboarding_requires_both_token_digests() {
    let mut request = minimal_request();
    request.ciba_automated_decision_token_sha256 = None;
    let error = validate_onboarding_request(&request).unwrap_err();
    assert!(error.to_string().contains("requires both"));
}

#[test]
fn onboarding_rejects_malformed_or_misprofiled_token_digest() {
    let mut request = minimal_request();
    request.dynamic_registration_initial_access_token_sha256 = Some("not-a-digest".to_owned());
    let error = validate_onboarding_request(&request).unwrap_err();
    assert!(error.to_string().contains("dynamic_registration"));

    request.dynamic_registration_initial_access_token_sha256 = Some("a".repeat(64));
    request.profile = "oidc-core".to_owned();
    let error = validate_onboarding_request(&request).unwrap_err();
    assert!(error.to_string().contains("only supports"));
}

#[test]
fn onboarding_debug_never_contains_password_hash_material() {
    let request = minimal_request();
    let debug = format!("{request:?}");
    assert!(!debug.contains("opaque-test-hash"));
    assert!(!debug.contains(&"c".repeat(64)));
    assert!(!debug.contains(&"d".repeat(64)));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn onboarding_rejects_unbounded_or_non_object_credential_dataset_claims() {
    let mut request = minimal_request();
    request.openid4vc_credential_datasets.insert(
        "org.example.pid".to_owned(),
        Value::String("not-an-object".to_owned()),
    );
    let error = validate_onboarding_credential_datasets(&request.openid4vc_credential_datasets)
        .unwrap_err();
    assert!(error.to_string().contains("non-empty object"));

    request.openid4vc_credential_datasets.clear();
    request.openid4vc_credential_datasets.insert(
        "org.example.pid".to_owned(),
        serde_json::json!({"claim": "x".repeat(MAX_ONBOARDING_CREDENTIAL_DATASET_BYTES)}),
    );
    let error = validate_onboarding_credential_datasets(&request.openid4vc_credential_datasets)
        .unwrap_err();
    assert!(error.to_string().contains("per-dataset bound"));
}

#[test]
fn onboarding_public_material_rejects_private_or_unbounded_values() {
    let error = validate_onboarding_public_material(&Value::Array(Vec::new())).unwrap_err();
    assert!(error.to_string().contains("non-empty object"));

    let error = validate_onboarding_public_material(
        &serde_json::json!({"key_attestation_jwks": {"keys": [{"d": "private"}]}}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("private-key"));

    let error = validate_onboarding_public_material(
        &serde_json::json!({"credential_trust_anchor_pem": "-----BEGIN PRIVATE KEY-----"}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("private-key"));

    let error = validate_onboarding_public_material(&serde_json::json!({
        "credential_trust_anchor_pem": "x".repeat(MAX_ONBOARDING_PUBLIC_MATERIAL_BYTES),
    }))
    .unwrap_err();
    assert!(error.to_string().contains("supported bound"));

    validate_onboarding_public_material(&serde_json::json!({
        "schema": 1,
        "credential_trust_anchor_pem": "public",
    }))
    .unwrap();
}

#[test]
fn suite_origin_canonicalizes_scheme_host_and_default_port() {
    assert_eq!(
        canonicalize_suite_origin("HTTPS://Suite.Example.test:443").unwrap(),
        "https://suite.example.test"
    );
    assert_eq!(
        canonicalize_suite_origin("https://Suite.Example.test:8443").unwrap(),
        "https://suite.example.test:8443"
    );
    assert_eq!(
        canonicalize_suite_origin("https://[2001:DB8::1]:443").unwrap(),
        "https://[2001:db8::1]"
    );
    assert_eq!(
        canonicalize_suite_origin("https://[2001:0db8:0:0:0:0:0:1]").unwrap(),
        "https://[2001:db8::1]"
    );
}

#[test]
fn suite_origin_rejects_non_origin_components_and_invalid_ports() {
    for value in [
        "http://suite.example.test",
        "https://suite.example.test/path",
        "https://suite.example.test?query",
        "https://suite.example.test#fragment",
        "https://user@suite.example.test",
        "https://suite.example.test:0",
        "https://suite.example.test:65536",
        "https://2001:db8::1",
    ] {
        assert!(
            canonicalize_suite_origin(value).is_err(),
            "accepted {value}"
        );
    }
}
