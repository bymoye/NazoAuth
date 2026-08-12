use super::*;

use chrono::{Duration, Utc};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use nazo_auth::{ClientPresentationMetadata, ClientSecurityPolicy, ValidatedClientRegistration};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(QueryableByName)]
struct UnitCountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct UnitMappingRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    storage_client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    public_client_id: String,
}

#[derive(QueryableByName)]
struct UnitDatasetRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    credential_configuration_id: String,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    claims_ciphertext: Vec<u8>,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI conformance lease tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

async fn test_pool() -> Option<crate::DbPool> {
    let url = database_url()?;
    crate::run_pending_migrations(&url).await.unwrap();
    Some(crate::create_pool(url, 4).unwrap())
}

fn test_digest(label: &str, suffix: &str) -> String {
    Sha256::digest(format!("{label}:{suffix}"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn test_registration(suffix: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: format!("lease-unit-client-{suffix}"),
        client_name: "Conformance lease unit client".to_owned(),
        client_type: "public".to_owned(),
        redirect_uris: vec!["https://client.example.test/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "none".to_owned(),
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: Vec::new(),
        tls_client_auth_san_uri: Vec::new(),
        tls_client_auth_san_ip: Vec::new(),
        tls_client_auth_san_email: Vec::new(),
        jwks_uri: None,
        jwks: None,
        request_uris: Vec::new(),
        initiate_login_uri: None,
        presentation: ClientPresentationMetadata::default(),
        id_token_signed_response_alg: None,
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        request_object_signing_alg: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        token_endpoint_auth_signing_alg: None,
        introspection_signed_response_alg: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        security_policy: Some(ClientSecurityPolicy::default()),
    }
}

fn test_prepared_client(
    tenant: TenantContext,
    suffix: &str,
    lease_id: Option<Uuid>,
    require_mtls_bound_tokens: bool,
) -> PreparedClientRegistration {
    PreparedClientRegistration {
        tenant,
        conformance_lease_id: lease_id,
        registration: test_registration(suffix),
        require_mtls_bound_tokens,
        issued_secret: None,
        client_secret_hash: None,
        registration_access_token_blake3: None,
    }
}

fn onboarding_fixture(
    tenant: TenantContext,
    suffix: &str,
    with_dataset: bool,
) -> ConformanceOnboardingRequest {
    let mut request = minimal_request();
    request.tenant = tenant;
    request.task_jti = format!("request-{suffix}");
    request.bundle_sha256 = test_digest("bundle", suffix);
    request.material_sha256 = test_digest("material", suffix);
    request.public_material = json!({
        "schema": 1,
        "credential_trust_anchor_pem": format!("PUBLIC-{suffix}"),
    });
    request.suite_origin = format!("https://lease-unit-{suffix}.example.test");
    request.dynamic_registration_initial_access_token_sha256 = Some(test_digest("dynamic", suffix));
    request.ciba_automated_decision_token_sha256 = Some(test_digest("ciba", suffix));
    request.applicant.username = format!("lease-unit-user-{suffix}");
    request.applicant.email = format!("lease-unit-user-{suffix}@example.invalid");
    request.applicant.password_hash =
        PasswordHashInput::new(format!("lease-unit-hash-{suffix}")).unwrap();
    request.client_count = 1;
    request.clients = vec![ConformanceClient {
        logical_client_id: "logical-client".to_owned(),
        prepared: test_prepared_client(tenant, suffix, None, true),
    }];
    let certificate_pem =
        format!("-----BEGIN CERTIFICATE-----\nLEASE-UNIT-{suffix}\n-----END CERTIFICATE-----\n");
    request.mtls_trust_anchors = vec![ConformanceMtlsTrustAnchor {
        logical_client_id: "logical-client".to_owned(),
        certificate_pem,
        certificate_sha256: test_digest("certificate", suffix),
        subject_dn: "CN=Lease Unit".to_owned(),
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::minutes(5),
    }];
    if with_dataset {
        request.openid4vc_credential_datasets.insert(
            "org.example.pid".to_owned(),
            json!({"given_name": "Lease", "family_name": "Unit"}),
        );
    } else {
        request.openid4vc_credential_datasets.clear();
    }
    request
}

async fn cleanup_onboarded_lease(pool: &crate::DbPool, tenant_id: Uuid, lease_id: Uuid) {
    let repository = ConformanceLeaseRepository::new(pool.clone());
    let _ = repository.revoke(tenant_id, lease_id).await;
    let _ = repository.cleanup().await;
}

async fn delete_created_lease(pool: &crate::DbPool, tenant_id: Uuid, lease_id: Uuid) {
    let mut connection = crate::get_conn(pool).await.unwrap();
    sql_query("DELETE FROM conformance_leases WHERE tenant_id = $1 AND id = $2")
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(lease_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

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
            password_hash: PasswordHashInput::new(format!(
                "opaque-test-hash-{}",
                Uuid::now_v7().simple()
            ))
            .unwrap(),
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

#[test]
fn binding_task_jti_requires_the_signed_request_shape() {
    for valid in [
        "request-00000000000000000000000000000000",
        "request-abcdefabcdefabcdefabcdefabcdefab",
    ] {
        validate_binding_task_jti(valid).unwrap();
    }
    for invalid in [
        "",
        "request-",
        "request-ABCDEFabcdefabcdefabcdefabcdefab",
        "request-abcdefabcdefabcdefabcdefabcdefa",
        "request-abcdefabcdefabcdefabcdefabcdefabc",
        "request-abcdefabcdefabcdefabcdefabcdefag",
        "task-abcdefabcdefabcdefabcdefabcdefab",
    ] {
        assert!(matches!(
            validate_binding_task_jti(invalid),
            Err(RepositoryError::Consistency(_))
        ));
    }
}

#[test]
fn bounded_json_and_private_material_walk_all_value_kinds() {
    for value in [
        Value::Null,
        Value::Bool(true),
        Value::Number(serde_json::Number::from(1)),
        Value::String("public".to_owned()),
    ] {
        let mut nodes = 0;
        assert!(bounded_public_material_json(&value, 0, &mut nodes));
        let mut nodes = 0;
        assert!(bounded_onboarding_json(&value, 0, &mut nodes));
        assert!(!contains_private_material(&value));
    }
    assert!(contains_private_material(
        &json!({"nested": ["public", "PRIVATE KEY"]})
    ));
    assert!(contains_private_material(
        &json!({"secret_value": "redacted"})
    ));
    assert!(contains_private_material(&json!({"d": "private"})));
    assert!(!contains_private_material(&json!({"kid": "public"})));

    let mut too_deep = json!("leaf");
    for _ in 0..10 {
        too_deep = json!({"nested": too_deep});
    }
    let mut nodes = 0;
    assert!(!bounded_public_material_json(&too_deep, 0, &mut nodes));
    let mut nodes = 0;
    assert!(!bounded_onboarding_json(&too_deep, 0, &mut nodes));

    let mut too_many_nodes = serde_json::Map::new();
    for index in 0..513 {
        too_many_nodes.insert(index.to_string(), Value::Null);
    }
    let mut nodes = 0;
    assert!(!bounded_public_material_json(
        &Value::Object(too_many_nodes.clone()),
        0,
        &mut nodes
    ));
    let mut nodes = 0;
    assert!(!bounded_onboarding_json(
        &Value::Object(too_many_nodes),
        0,
        &mut nodes
    ));
    let mut nodes = 0;
    assert!(!bounded_public_material_json(
        &json!({"key": "x".repeat(MAX_ONBOARDING_PUBLIC_MATERIAL_STRING_BYTES + 1)}),
        0,
        &mut nodes
    ));
    let mut nodes = 0;
    assert!(!bounded_onboarding_json(
        &json!({"key": "x".repeat(4097)}),
        0,
        &mut nodes
    ));
}

#[test]
fn phone_and_address_validation_reject_missing_and_unverified_values() {
    assert!(validate_conformance_phone_number("+1 555 5550000", true).is_ok());
    for (phone, verified) in [
        ("", true),
        (" +1 555 5550000", true),
        ("+1 555 5550000 ", true),
        ("+1\n555", true),
        ("+1 555 5550000", false),
    ] {
        assert!(matches!(
            validate_conformance_phone_number(phone, verified),
            Err(RepositoryError::Consistency(_))
        ));
    }
    assert!(validate_conformance_phone_number(&"x".repeat(33), true).is_err());

    let valid = minimal_request().applicant.address;
    for field in [
        "formatted",
        "street_address",
        "locality",
        "region",
        "postal_code",
        "country",
    ] {
        let mut address = valid.clone();
        match field {
            "formatted" => address.formatted = None,
            "street_address" => address.street_address = None,
            "locality" => address.locality = None,
            "region" => address.region = None,
            "postal_code" => address.postal_code = None,
            "country" => address.country = None,
            _ => unreachable!(),
        }
        let error = validate_conformance_postal_address(&address).unwrap_err();
        assert!(error.to_string().contains(field));
    }
}

#[test]
fn onboarding_validation_rejects_identity_client_and_anchor_drift() {
    let mut request = minimal_request();
    request.client_count = 1;
    request.clients = vec![ConformanceClient {
        logical_client_id: "logical".to_owned(),
        prepared: test_prepared_client(request.tenant, "validation", None, false),
    }];
    validate_onboarding_request(&request).unwrap();

    request.applicant.username = " ".to_owned();
    assert!(validate_onboarding_request(&request).is_err());
    request.applicant.username = "valid".to_owned();
    request.applicant.email = "valid\n@example.invalid".to_owned();
    assert!(validate_onboarding_request(&request).is_err());

    request.applicant = minimal_request().applicant;
    request.clients[0].logical_client_id = " logical".to_owned();
    assert!(validate_onboarding_request(&request).is_err());
    request.clients[0].logical_client_id = "logical".to_owned();
    request.clients.push(ConformanceClient {
        logical_client_id: "logical-two".to_owned(),
        prepared: test_prepared_client(request.tenant, "validation", None, false),
    });
    request.client_count = 2;
    request.clients[1].prepared.registration.client_id =
        request.clients[0].prepared.registration.client_id.clone();
    assert!(validate_onboarding_request(&request).is_err());

    request.clients[1].prepared.registration.client_id = "distinct-client".to_owned();
    request.mtls_trust_anchors = vec![ConformanceMtlsTrustAnchor {
        logical_client_id: "unknown".to_owned(),
        certificate_pem: "-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----".to_owned(),
        certificate_sha256: "e".repeat(64),
        subject_dn: "CN=Unknown".to_owned(),
        not_before: Utc::now(),
        not_after: Utc::now() + Duration::minutes(1),
    }];
    assert!(validate_onboarding_request(&request).is_err());
}

#[test]
fn onboarding_error_mapping_preserves_repository_and_diesel_variants() {
    assert!(matches!(
        OnboardingTxError::Repository(RepositoryError::Conflict).into_repository(),
        RepositoryError::Conflict
    ));
    assert!(matches!(
        OnboardingTxError::Diesel(diesel::result::Error::NotFound).into_repository(),
        RepositoryError::Unexpected(_)
    ));
    assert!(matches!(
        map_dataset_crypto_error(nazo_openid4vci::CredentialStoreError::Unavailable),
        OnboardingTxError::Repository(RepositoryError::Unavailable)
    ));
    assert!(matches!(
        map_dataset_crypto_error(nazo_openid4vci::CredentialStoreError::InvalidTransition),
        OnboardingTxError::Repository(RepositoryError::Consistency(_))
    ));
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn onboarding_replay_exercises_mapping_dataset_and_cleanup_state() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let tenant = TenantContext::default_system();
    let suffix = Uuid::now_v7().simple().to_string();
    let request = onboarding_fixture(tenant, &suffix, true);
    let repository =
        ConformanceLeaseRepository::new_with_openid4vc_data_key(pool.clone(), [0x37; 32]);

    let first = repository.onboard(request.clone()).await.unwrap();
    assert!(!first.idempotent_replay);
    assert_eq!(first.client_count, 1);
    assert_eq!(first.client_mappings.len(), 1);
    let replay = repository.onboard(request.clone()).await.unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(replay.lease_id, first.lease_id);
    assert_eq!(replay.client_mappings, first.client_mappings);

    let mut mapping_connection = crate::get_conn(&pool).await.unwrap();
    let mapping = sql_query(
        "SELECT mapping.client_id AS storage_client_id, client.client_id AS public_client_id
         FROM conformance_lease_clients mapping
         JOIN oauth_clients client
           ON client.tenant_id = mapping.tenant_id AND client.id = mapping.client_id
         WHERE mapping.tenant_id = $1 AND mapping.lease_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(first.lease_id)
    .get_result::<UnitMappingRow>(&mut mapping_connection)
    .await
    .unwrap();
    assert_ne!(mapping.storage_client_id, Uuid::nil());
    assert!(
        repository
            .active_for_client_profile(
                tenant.tenant_id.as_uuid(),
                &mapping.public_client_id,
                ATOMIC_CONFORMANCE_PROFILE,
            )
            .await
            .unwrap()
    );
    assert!(
        repository
            .active_for_client_lease_profile(
                tenant.tenant_id.as_uuid(),
                &mapping.public_client_id,
                first.lease_id,
                ATOMIC_CONFORMANCE_PROFILE,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        repository
            .active_lease_id_for_client(
                tenant.tenant_id.as_uuid(),
                &mapping.public_client_id,
                ATOMIC_CONFORMANCE_PROFILE,
            )
            .await
            .unwrap(),
        Some(first.lease_id)
    );
    assert_eq!(
        repository
            .active_public_material_for_client(
                tenant.tenant_id.as_uuid(),
                &mapping.public_client_id,
            )
            .await
            .unwrap(),
        Some(request.public_material.clone())
    );
    assert_eq!(
        repository
            .active_public_material_for_lease(tenant.tenant_id.as_uuid(), first.lease_id)
            .await
            .unwrap(),
        Some(request.public_material.clone())
    );
    assert_eq!(
        repository
            .active_public_materials_for_profile(
                tenant.tenant_id.as_uuid(),
                ATOMIC_CONFORMANCE_PROFILE,
            )
            .await
            .unwrap()
            .iter()
            .filter(|row| row.lease_id == first.lease_id)
            .count(),
        1
    );
    assert_eq!(
        repository
            .active_lease_for_binding(
                tenant.tenant_id.as_uuid(),
                first.lease_id,
                ATOMIC_CONFORMANCE_PROFILE,
                &request.suite_origin,
                &request.task_jti,
            )
            .await
            .unwrap(),
        Some(first.lease_id)
    );

    let without_key = ConformanceLeaseRepository::new(pool.clone());
    let missing_key_suffix = Uuid::now_v7().simple().to_string();
    let missing_key_request = onboarding_fixture(tenant, &missing_key_suffix, true);
    assert!(matches!(
        without_key.onboard(missing_key_request).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("application data key")
    ));
    assert!(matches!(
        without_key.onboard(request.clone()).await,
        Err(RepositoryError::Consistency(message)) if message.contains("application data key")
    ));

    assert_eq!(
        repository
            .revoke(tenant.tenant_id.as_uuid(), first.lease_id)
            .await
            .unwrap(),
        1
    );
    let cleanup = repository.cleanup().await.unwrap();
    assert!(cleanup.cleaned_leases >= 1);
    assert!(cleanup.deleted_clients >= 1);
    assert!(cleanup.deleted_credential_datasets >= 1);
    assert!(
        !repository
            .active_for_client_profile(
                tenant.tenant_id.as_uuid(),
                &mapping.public_client_id,
                ATOMIC_CONFORMANCE_PROFILE,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        repository
            .active_public_material_for_lease(tenant.tenant_id.as_uuid(), first.lease_id)
            .await
            .unwrap(),
        None
    );
    assert!(matches!(
        repository.onboard(request).await,
        Err(RepositoryError::Conflict)
    ));

    let no_dataset_suffix = Uuid::now_v7().simple().to_string();
    let no_dataset_request = onboarding_fixture(tenant, &no_dataset_suffix, false);
    let no_dataset_first = without_key
        .onboard(no_dataset_request.clone())
        .await
        .unwrap();
    let no_dataset_replay = without_key.onboard(no_dataset_request).await.unwrap();
    assert!(no_dataset_replay.idempotent_replay);
    cleanup_onboarded_lease(&pool, tenant.tenant_id.as_uuid(), no_dataset_first.lease_id).await;
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn onboarding_replay_rejects_tombstoned_and_drifted_ownership_rows() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let tenant = TenantContext::default_system();
    let repository = ConformanceLeaseRepository::new(pool.clone());

    let tombstone_suffix = Uuid::now_v7().simple().to_string();
    let tombstone_request = onboarding_fixture(tenant, &tombstone_suffix, false);
    let tombstone_first = repository.onboard(tombstone_request.clone()).await.unwrap();
    let applicant_user_id = tombstone_first.applicant_user_id.unwrap();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE conformance_lease_applicants
         SET applicant_user_id = NULL, cleaned_at = CURRENT_TIMESTAMP,
             deleted_at = CURRENT_TIMESTAMP
         WHERE tenant_id = $1 AND lease_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(tombstone_first.lease_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(tombstone_request).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("live onboarding applicant")
    ));
    cleanup_onboarded_lease(&pool, tenant.tenant_id.as_uuid(), tombstone_first.lease_id).await;
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
        .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
        .execute(&mut connection)
        .await
        .unwrap();

    let mapping_suffix = Uuid::now_v7().simple().to_string();
    let mapping_request = onboarding_fixture(tenant, &mapping_suffix, false);
    let mapping_first = repository.onboard(mapping_request.clone()).await.unwrap();
    sql_query("DELETE FROM conformance_lease_clients WHERE tenant_id = $1 AND lease_id = $2")
        .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
        .bind::<diesel::sql_types::Uuid, _>(mapping_first.lease_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(mapping_request).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("ownership rows")
    ));
    cleanup_onboarded_lease(&pool, tenant.tenant_id.as_uuid(), mapping_first.lease_id).await;

    let drift_suffix = Uuid::now_v7().simple().to_string();
    let drift_request = onboarding_fixture(tenant, &drift_suffix, false);
    let drift_first = repository.onboard(drift_request.clone()).await.unwrap();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE conformance_lease_clients
         SET logical_client_id = 'unexpected-logical'
         WHERE tenant_id = $1 AND lease_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(drift_first.lease_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(drift_request.clone()).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("logical IDs")
    ));

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE conformance_lease_clients
         SET logical_client_id = 'logical-client'
         WHERE tenant_id = $1 AND lease_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(drift_first.lease_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "UPDATE oauth_clients
         SET client_id = 'lease-unit-drifted-public-client'
         WHERE tenant_id = $1 AND conformance_lease_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(drift_first.lease_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(drift_request).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("public client IDs")
    ));
    cleanup_onboarded_lease(&pool, tenant.tenant_id.as_uuid(), drift_first.lease_id).await;

    let anchor_suffix = Uuid::now_v7().simple().to_string();
    let anchor_request = onboarding_fixture(tenant, &anchor_suffix, false);
    let anchor_first = repository.onboard(anchor_request.clone()).await.unwrap();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE oauth_client_mtls_trust_anchor_requests request
         SET not_after = CURRENT_TIMESTAMP - INTERVAL '1 second'
         FROM conformance_lease_clients mapping
         WHERE request.tenant_id = mapping.tenant_id
           AND request.client_id = mapping.client_id
           AND mapping.tenant_id = $1 AND mapping.lease_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(anchor_first.lease_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(anchor_request).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("trust-anchor row")
    ));
    cleanup_onboarded_lease(&pool, tenant.tenant_id.as_uuid(), anchor_first.lease_id).await;
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn dataset_replay_rejects_ciphertext_source_validity_and_ownership_drift() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let tenant = TenantContext::default_system();
    let suffix = Uuid::now_v7().simple().to_string();
    let request = onboarding_fixture(tenant, &suffix, true);
    let key = [0x48; 32];
    let repository = ConformanceLeaseRepository::new_with_openid4vc_data_key(pool.clone(), key);
    let first = repository.onboard(request.clone()).await.unwrap();
    let applicant_user_id = first.applicant_user_id.unwrap();

    let mut connection = crate::get_conn(&pool).await.unwrap();
    let dataset = sql_query(
        "SELECT credential_configuration_id, claims_ciphertext
         FROM openid4vci_credential_datasets
         WHERE tenant_id = $1 AND subject_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .get_result::<UnitDatasetRow>(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let changed_ciphertext = protect_dataset_claims(
        &key,
        tenant.tenant_id.as_uuid(),
        applicant_user_id,
        &dataset.credential_configuration_id,
        &json!({"given_name": "Changed", "family_name": "Unit"}),
    )
    .unwrap();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET claims_ciphertext = $1
         WHERE tenant_id = $2 AND subject_id = $3
           AND credential_configuration_id = $4",
    )
    .bind::<diesel::sql_types::Binary, _>(changed_ciphertext)
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(request.clone()).await,
        Err(RepositoryError::Conflict)
    ));

    let original_ciphertext = dataset.claims_ciphertext.clone();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET claims_ciphertext = $1
         WHERE tenant_id = $2 AND subject_id = $3
           AND credential_configuration_id = $4",
    )
    .bind::<diesel::sql_types::Binary, _>(original_ciphertext)
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET claims_ciphertext = $1
         WHERE tenant_id = $2 AND subject_id = $3
           AND credential_configuration_id = $4",
    )
    .bind::<diesel::sql_types::Binary, _>(vec![0_u8; 32])
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(request.clone()).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("could not be encrypted or decrypted")
    ));

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET claims_ciphertext = $1
         WHERE tenant_id = $2 AND subject_id = $3
           AND credential_configuration_id = $4",
    )
    .bind::<diesel::sql_types::Binary, _>(dataset.claims_ciphertext.clone())
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET source = 'admin-session'
         WHERE tenant_id = $1 AND subject_id = $2
           AND credential_configuration_id = $3",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(request.clone()).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("invalid source or validity")
    ));

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET source = 'operator-conformance', valid_until = CURRENT_TIMESTAMP + INTERVAL '1 minute'
         WHERE tenant_id = $1 AND subject_id = $2
           AND credential_configuration_id = $3",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(request.clone()).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("invalid source or validity")
    ));

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_until = NULL, credential_configuration_id = 'org.example.other'
         WHERE tenant_id = $1 AND subject_id = $2
           AND credential_configuration_id = $3",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .bind::<diesel::sql_types::Text, _>(&dataset.credential_configuration_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(request.clone()).await,
        Err(RepositoryError::Conflict)
    ));

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "DELETE FROM openid4vci_credential_datasets
         WHERE tenant_id = $1 AND subject_id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(applicant_user_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository.onboard(request.clone()).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("ownership rows are incomplete")
    ));
    let without_key = ConformanceLeaseRepository::new(pool.clone());
    assert!(matches!(
        without_key.onboard(request).await,
        Err(RepositoryError::Consistency(message))
            if message.contains("ownership rows are incomplete")
    ));

    cleanup_onboarded_lease(&pool, tenant.tenant_id.as_uuid(), first.lease_id).await;
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn lease_lookups_reject_ambiguous_credentials_and_ignore_dead_rows() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let tenant = TenantContext::default_system();
    let repository = ConformanceLeaseRepository::new(pool.clone());
    let tenant_id = tenant.tenant_id.as_uuid();
    assert!(matches!(
        repository.revoke(tenant_id, Uuid::now_v7()).await,
        Err(RepositoryError::NotFound)
    ));
    let valid_material = "a".repeat(64);
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "",
                &valid_material,
                ConformanceLeaseTokenDigests::default(),
                None,
                MIN_CONFORMANCE_LEASE_SECONDS - 1,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "oidc-fapi-ciba",
                "invalid",
                ConformanceLeaseTokenDigests::default(),
                None,
                MIN_CONFORMANCE_LEASE_SECONDS,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "oidc-fapi-ciba",
                &valid_material,
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: Some("invalid"),
                    ciba_automated_decision_token_sha256: None,
                },
                None,
                MIN_CONFORMANCE_LEASE_SECONDS,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "other-profile",
                &valid_material,
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: Some(&valid_material),
                    ciba_automated_decision_token_sha256: None,
                },
                None,
                MIN_CONFORMANCE_LEASE_SECONDS,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));

    let dynamic_digest = test_digest("duplicate-dynamic", &Uuid::now_v7().simple().to_string());
    let ciba_digest = test_digest("duplicate-ciba", &Uuid::now_v7().simple().to_string());
    let dynamic_material_a = test_digest("material-a", &Uuid::now_v7().simple().to_string());
    let dynamic_a = repository
        .create(
            tenant_id,
            "oidc-fapi-ciba",
            &dynamic_material_a,
            ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: Some(&dynamic_digest),
                ciba_automated_decision_token_sha256: Some(&ciba_digest),
            },
            Some(json!({"source": "a"})),
            300,
        )
        .await
        .unwrap();
    let dynamic_material_b = test_digest("material-b", &Uuid::now_v7().simple().to_string());
    let dynamic_b_ciba_digest = test_digest("ciba-b", &Uuid::now_v7().simple().to_string());
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "oidc-fapi-ciba",
                &dynamic_material_b,
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: Some(&dynamic_digest),
                    ciba_automated_decision_token_sha256: Some(&dynamic_b_ciba_digest),
                },
                Some(json!({"source": "b"})),
                300,
            )
            .await,
        Err(RepositoryError::Conflict)
    ));
    assert!(
        repository
            .list(tenant_id)
            .await
            .unwrap()
            .iter()
            .any(|lease| lease.id == dynamic_a.id)
    );
    assert_eq!(
        repository
            .active_dynamic_registration_lease_id(tenant_id, &dynamic_digest)
            .await
            .unwrap(),
        Some(dynamic_a.id)
    );
    let no_match_digest = "f".repeat(64);
    assert_eq!(
        repository
            .active_dynamic_registration_lease_id(tenant_id, &no_match_digest)
            .await
            .unwrap(),
        None
    );
    let ciba_material_b = test_digest("material-d", &Uuid::now_v7().simple().to_string());
    assert!(matches!(
        repository
            .create(
                tenant_id,
                "oidc-fapi-ciba",
                &ciba_material_b,
                ConformanceLeaseTokenDigests {
                    dynamic_registration_initial_access_token_sha256: None,
                    ciba_automated_decision_token_sha256: Some(&ciba_digest),
                },
                Some(json!({"source": "d"})),
                300,
            )
            .await,
        Err(RepositoryError::Conflict)
    ));
    assert_eq!(
        repository
            .active_ciba_automated_decision_lease_id(tenant_id, &ciba_digest)
            .await
            .unwrap(),
        Some(dynamic_a.id)
    );

    let origin = format!("https://ambiguous-{}.example.test", Uuid::now_v7().simple());
    let origin_material_a = test_digest("material-origin-a", &Uuid::now_v7().simple().to_string());
    let origin_a = repository
        .create(
            tenant_id,
            ATOMIC_CONFORMANCE_PROFILE,
            &origin_material_a,
            ConformanceLeaseTokenDigests::default(),
            Some(json!({"source": "origin-a"})),
            300,
        )
        .await
        .unwrap();
    let origin_material_b = test_digest("material-origin-b", &Uuid::now_v7().simple().to_string());
    let origin_b = repository
        .create(
            tenant_id,
            ATOMIC_CONFORMANCE_PROFILE,
            &origin_material_b,
            ConformanceLeaseTokenDigests::default(),
            Some(json!({"source": "origin-b"})),
            300,
        )
        .await
        .unwrap();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    for lease in [origin_a.id, origin_b.id] {
        sql_query(
            "UPDATE conformance_leases
             SET suite_origin = $1, task_jti = $2
             WHERE tenant_id = $3 AND id = $4",
        )
        .bind::<diesel::sql_types::Text, _>(&origin)
        .bind::<diesel::sql_types::Text, _>(format!("request-{}", Uuid::now_v7().simple()))
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(lease)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);
    assert!(matches!(
        repository
            .active_lease_for_suite_origin(tenant_id, ATOMIC_CONFORMANCE_PROFILE, &origin)
            .await,
        Err(RepositoryError::Consistency(message))
            if message.contains("multiple active nazoauth-full")
    ));
    delete_created_lease(&pool, tenant_id, origin_b.id).await;
    assert_eq!(
        repository
            .active_lease_for_suite_origin(tenant_id, ATOMIC_CONFORMANCE_PROFILE, &origin)
            .await
            .unwrap(),
        Some(origin_a.id)
    );
    assert!(matches!(
        repository
            .active_lease_for_suite_origin(tenant_id, "oidc-fapi-ciba", &origin)
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .active_lease_for_binding(
                tenant_id,
                origin_a.id,
                "oidc-fapi-ciba",
                &origin,
                "request-00000000000000000000000000000000",
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));

    let expired_material = test_digest("material-expired", &Uuid::now_v7().simple().to_string());
    let expired = repository
        .create(
            tenant_id,
            "oidc-fapi-ciba",
            &expired_material,
            ConformanceLeaseTokenDigests::default(),
            Some(json!({"source": "expired"})),
            300,
        )
        .await
        .unwrap();
    let revoked_material = test_digest("material-revoked", &Uuid::now_v7().simple().to_string());
    let revoked = repository
        .create(
            tenant_id,
            "oidc-fapi-ciba",
            &revoked_material,
            ConformanceLeaseTokenDigests::default(),
            Some(json!({"source": "revoked"})),
            300,
        )
        .await
        .unwrap();
    let cleaned_material = test_digest("material-cleaned", &Uuid::now_v7().simple().to_string());
    let cleaned = repository
        .create(
            tenant_id,
            "oidc-fapi-ciba",
            &cleaned_material,
            ConformanceLeaseTokenDigests::default(),
            Some(json!({"source": "cleaned"})),
            300,
        )
        .await
        .unwrap();
    repository.revoke(tenant_id, revoked.id).await.unwrap();
    repository.revoke(tenant_id, cleaned.id).await.unwrap();
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE conformance_leases
         SET created_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes',
             expires_at = CURRENT_TIMESTAMP - INTERVAL '5 minutes'
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(expired.id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query(
        "UPDATE conformance_leases SET cleaned_at = CURRENT_TIMESTAMP
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(cleaned.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let missing_digest = test_digest("none", "unused");
    assert_eq!(
        repository
            .active_dynamic_registration_lease_id(tenant_id, &missing_digest)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repository
            .active_public_material_for_lease(tenant_id, expired.id)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repository
            .active_public_material_for_lease(tenant_id, revoked.id)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repository
            .active_public_material_for_lease(tenant_id, cleaned.id)
            .await
            .unwrap(),
        None
    );

    let cleanup = repository.cleanup().await.unwrap();
    assert!(cleanup.cleaned_leases >= 2);
    for lease in [
        dynamic_a.id,
        origin_a.id,
        expired.id,
        revoked.id,
        cleaned.id,
    ] {
        delete_created_lease(&pool, tenant_id, lease).await;
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn ciba_claim_lifecycle_covers_missing_busy_unleased_and_clear_races() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let suffix = Uuid::now_v7().simple().to_string();
    let repository = ConformanceLeaseRepository::new(pool.clone());
    let ciba_material = test_digest("ciba-material", &suffix);
    let ciba_token = test_digest("ciba-token", &suffix);
    let lease = repository
        .create(
            tenant_id,
            "oidc-fapi-ciba",
            &ciba_material,
            ConformanceLeaseTokenDigests {
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: Some(&ciba_token),
            },
            Some(json!({"schema": 1})),
            300,
        )
        .await
        .unwrap();

    let prepared = test_prepared_client(tenant, &suffix, Some(lease.id), true);
    let mut connection = crate::get_conn(&pool).await.unwrap();
    let approved = insert_client(&mut connection, tenant, &prepared)
        .await
        .unwrap();
    drop(connection);

    let missing = repository
        .with_active_ciba_decision(tenant_id, "missing-client", None, |_| async { 1 })
        .await
        .unwrap();
    assert_eq!(missing, None);
    let wrong_lease = repository
        .with_active_ciba_decision(
            tenant_id,
            &approved.client_id,
            Some(Uuid::now_v7()),
            |_| async { 2 },
        )
        .await
        .unwrap();
    assert_eq!(wrong_lease, None);

    let first_claim = repository
        .with_active_ciba_decision(
            tenant_id,
            &approved.client_id,
            Some(lease.id),
            |expires| async move {
                assert!(expires.is_some());
                3
            },
        )
        .await
        .unwrap();
    assert_eq!(first_claim, Some(3));
    let mut connection = crate::get_conn(&pool).await.unwrap();
    let cleared_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count
         FROM conformance_leases
         WHERE tenant_id = $1 AND id = $2
           AND ciba_decision_claim_id IS NULL
           AND ciba_decision_claim_expires_at IS NULL",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(lease.id)
    .get_result::<UnitCountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(cleared_count.count, 1);

    sql_query(
        "UPDATE conformance_leases
         SET ciba_decision_claim_id = $1,
             ciba_decision_claim_expires_at = CURRENT_TIMESTAMP + INTERVAL '1 minute'
         WHERE tenant_id = $2 AND id = $3",
    )
    .bind::<diesel::sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(lease.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(matches!(
        repository
            .with_active_ciba_decision(tenant_id, &approved.client_id, None, |_| async { 4 })
            .await,
        Err(RepositoryError::Conflict)
    ));

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE conformance_leases
         SET ciba_decision_claim_id = $1,
             ciba_decision_claim_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 minute'
         WHERE tenant_id = $2 AND id = $3",
    )
    .bind::<diesel::sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(lease.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let reclaimed = repository
        .with_active_ciba_decision(tenant_id, &approved.client_id, None, |expires| async move {
            assert!(expires.is_some());
            5
        })
        .await
        .unwrap();
    assert_eq!(reclaimed, Some(5));

    let pool_for_clear = pool.clone();
    let clear_race = repository
        .with_active_ciba_decision(tenant_id, &approved.client_id, Some(lease.id), move |_| {
            let pool = pool_for_clear.clone();
            async move {
                let mut connection = crate::get_conn(&pool).await.unwrap();
                sql_query(
                    "UPDATE conformance_leases
                         SET ciba_decision_claim_id = NULL,
                             ciba_decision_claim_expires_at = NULL
                         WHERE tenant_id = $1 AND id = $2",
                )
                .bind::<diesel::sql_types::Uuid, _>(tenant_id)
                .bind::<diesel::sql_types::Uuid, _>(lease.id)
                .execute(&mut connection)
                .await
                .unwrap();
                6
            }
        })
        .await;
    assert!(matches!(clear_race, Err(RepositoryError::Conflict)));

    let inactive_client = repository
        .with_active_ciba_decision(tenant_id, &approved.client_id, None, |_| async { 7 })
        .await
        .unwrap();
    assert_eq!(inactive_client, Some(7));
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE oauth_clients
         SET is_active = FALSE
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(approved.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .with_active_ciba_decision(tenant_id, &approved.client_id, None, |_| async { 8 })
            .await
            .unwrap(),
        None
    );

    let unleased_suffix = format!("{suffix}-unleased");
    let unleased_prepared = test_prepared_client(tenant, &unleased_suffix, None, false);
    let mut connection = crate::get_conn(&pool).await.unwrap();
    let unleased = insert_client(&mut connection, tenant, &unleased_prepared)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .with_active_ciba_decision(tenant_id, &unleased.client_id, None, |expires| async move {
                assert!(expires.is_none());
                9
            })
            .await
            .unwrap(),
        Some(9)
    );
    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(unleased.id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let mut connection = crate::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE oauth_clients SET is_active = TRUE
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(approved.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(repository.revoke(tenant_id, lease.id).await.unwrap(), 1);
    let cleanup = repository.cleanup().await.unwrap();
    assert!(cleanup.cleaned_leases >= 1);
}
