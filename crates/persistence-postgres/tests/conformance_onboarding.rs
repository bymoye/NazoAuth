use chrono::{Duration, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text},
};
use diesel_async::RunQueryDsl;
use nazo_auth::{PreparedClientRegistration, ValidatedClientRegistration};
use nazo_identity::{
    TenantContext,
    ports::{PasswordHashInput, RepositoryError},
};
use nazo_postgres::{
    ConformanceApplicant, ConformanceClient, ConformanceLeaseRepository,
    ConformanceMtlsTrustAnchor, ConformanceOnboardingRequest, UserRepository, create_pool,
    get_conn,
};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use uuid::Uuid;

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn registration(suffix: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: format!("conformance-rollback-client-{suffix}"),
        client_name: "Conformance rollback client".to_owned(),
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
        presentation: nazo_auth::ClientPresentationMetadata::default(),
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
        security_policy: Some(nazo_auth::ClientSecurityPolicy::default()),
    }
}

fn prepared(
    tenant: TenantContext,
    suffix: &str,
    require_mtls_bound_tokens: bool,
) -> PreparedClientRegistration {
    PreparedClientRegistration {
        tenant,
        conformance_lease_id: None,
        registration: registration(suffix),
        require_mtls_bound_tokens,
        issued_secret: None,
        client_secret_hash: None,
        registration_access_token_blake3: None,
    }
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI conformance onboarding tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn digest_text(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        })
}

fn applicant(username: String, email: String, password_hash: &str) -> ConformanceApplicant {
    ConformanceApplicant {
        username,
        email,
        password_hash: PasswordHashInput::new(password_hash).unwrap(),
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
            formatted: Some("100 Universal City Plaza\nUniversal City, CA 91608\nUS".to_owned()),
            street_address: Some("100 Universal City Plaza".to_owned()),
            locality: Some("Universal City".to_owned()),
            region: Some("CA".to_owned()),
            postal_code: Some("91608".to_owned()),
            country: Some("US".to_owned()),
        },
        phone_number: "+1 555 5550000".to_owned(),
        phone_number_verified: true,
    }
}

fn replay_request(tenant: TenantContext, suffix: &str) -> ConformanceOnboardingRequest {
    let certificate_b =
        format!("-----BEGIN CERTIFICATE-----\nREPLAY-B-{suffix}\n-----END CERTIFICATE-----\n");
    let certificate_a =
        format!("-----BEGIN CERTIFICATE-----\nREPLAY-A-{suffix}\n-----END CERTIFICATE-----\n");
    ConformanceOnboardingRequest {
        tenant,
        task_jti: format!("replay-{suffix}"),
        profile: "nazoauth-full".to_owned(),
        bundle_schema: 1,
        bundle_sha256: digest_text(&format!("bundle-{suffix}")),
        material_sha256: digest_text(&format!("matrix-{suffix}")),
        suite_origin: format!("https://suite-{suffix}.example.test"),
        dynamic_registration_initial_access_token_sha256: Some(digest_text(&format!(
            "dcr-token-{suffix}"
        ))),
        ciba_automated_decision_token_sha256: Some(digest_text(&format!("ciba-token-{suffix}"))),
        client_count: 2,
        ttl_seconds: 300,
        applicant: applicant(
            format!("conformance-replay-{suffix}"),
            format!("conformance-replay-{suffix}@example.invalid"),
            "opaque-replay-test-hash",
        ),
        clients: vec![
            ConformanceClient {
                logical_client_id: "logical-b".to_owned(),
                prepared: prepared(tenant, &format!("{suffix}-b"), true),
            },
            ConformanceClient {
                logical_client_id: "logical-a".to_owned(),
                prepared: prepared(tenant, &format!("{suffix}-a"), true),
            },
        ],
        mtls_trust_anchors: vec![
            ConformanceMtlsTrustAnchor {
                logical_client_id: "logical-b".to_owned(),
                certificate_sha256: digest_text(&certificate_b),
                certificate_pem: certificate_b,
                subject_dn: "CN=Replay B".to_owned(),
                not_before: Utc::now() - Duration::minutes(1),
                not_after: Utc::now() + Duration::minutes(5),
            },
            ConformanceMtlsTrustAnchor {
                logical_client_id: "logical-a".to_owned(),
                certificate_sha256: digest_text(&certificate_a),
                certificate_pem: certificate_a,
                subject_dn: "CN=Replay A".to_owned(),
                not_before: Utc::now() - Duration::minutes(1),
                not_after: Utc::now() + Duration::minutes(5),
            },
        ],
    }
}

#[tokio::test]
async fn onboarding_rolls_back_lease_applicant_and_clients_when_late_step_fails() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(database_url, 4).unwrap();
    let tenant = TenantContext::default_system();
    let suffix = Uuid::now_v7().simple().to_string();
    let task_jti = format!("rollback-{suffix}");
    let username = format!("conformance-rollback-{suffix}");
    let email = format!("{username}@example.invalid");
    let certificate =
        format!("-----BEGIN CERTIFICATE-----\nVALID-{suffix}\n-----END CERTIFICATE-----\n");
    let valid_certificate_sha256 = digest_text("validated-certificate-der");
    let request = ConformanceOnboardingRequest {
        tenant,
        task_jti: task_jti.clone(),
        profile: "nazoauth-full".to_owned(),
        bundle_schema: 1,
        bundle_sha256: "a".repeat(64),
        material_sha256: "b".repeat(64),
        suite_origin: format!("https://rollback-suite-{suffix}.example.test"),
        dynamic_registration_initial_access_token_sha256: Some("c".repeat(64)),
        ciba_automated_decision_token_sha256: Some("d".repeat(64)),
        client_count: 2,
        ttl_seconds: 300,
        applicant: applicant(username.clone(), email, "opaque-test-hash"),
        clients: vec![
            ConformanceClient {
                logical_client_id: "rollback-client-a".to_owned(),
                prepared: prepared(tenant, &format!("{suffix}-a"), true),
            },
            ConformanceClient {
                logical_client_id: "rollback-client-b".to_owned(),
                prepared: prepared(tenant, &format!("{suffix}-b"), true),
            },
        ],
        mtls_trust_anchors: vec![
            ConformanceMtlsTrustAnchor {
                logical_client_id: "rollback-client-a".to_owned(),
                certificate_pem: certificate.clone(),
                certificate_sha256: valid_certificate_sha256,
                subject_dn: "CN=Rollback A".to_owned(),
                not_before: Utc::now() - Duration::minutes(1),
                not_after: Utc::now() + Duration::minutes(5),
            },
            ConformanceMtlsTrustAnchor {
                logical_client_id: "rollback-client-b".to_owned(),
                certificate_pem: format!(
                    "-----BEGIN CERTIFICATE-----\nINVALID-{suffix}\n-----END CERTIFICATE-----\n"
                ),
                certificate_sha256: digest_text("late-step-certificate-der"),
                // Persistence rejects this metadata after the lease,
                // applicant, and clients have been staged, proving that the
                // surrounding transaction rolls every earlier write back.
                subject_dn: String::new(),
                not_before: Utc::now() - Duration::minutes(1),
                not_after: Utc::now() + Duration::minutes(5),
            },
        ],
    };
    let repository = ConformanceLeaseRepository::new(pool.clone());
    assert!(matches!(
        repository.onboard(request).await,
        Err(RepositoryError::Consistency(_))
    ));

    let mut connection = get_conn(&pool).await.unwrap();
    let lease_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM conformance_leases WHERE tenant_id = $1 AND task_jti = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<Text, _>(task_jti)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    let applicant_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM users WHERE tenant_id = $1 AND username = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<Text, _>(username)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    let client_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM oauth_clients WHERE tenant_id = $1 AND client_id LIKE $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<Text, _>(format!("conformance-rollback-client-{suffix}-%"))
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    let mapping_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM conformance_lease_clients WHERE tenant_id = $1 AND lease_id IN (SELECT id FROM conformance_leases WHERE task_jti = $2)",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<Text, _>(format!("rollback-{suffix}"))
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(lease_count.count, 0);
    assert_eq!(applicant_count.count, 0);
    assert_eq!(client_count.count, 0);
    assert_eq!(mapping_count.count, 0);

    let trust_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM oauth_client_mtls_trust_anchor_requests WHERE tenant_id = $1 AND source = 'operator-conformance' AND certificate_pem LIKE $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<Text, _>(format!("%{suffix}%"))
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(trust_count.count, 0);
}

#[tokio::test]
async fn onboarding_replay_returns_stable_logical_client_mappings() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(database_url, 4).unwrap();
    let tenant = TenantContext::default_system();
    let suffix = Uuid::now_v7().simple().to_string();
    let repository = ConformanceLeaseRepository::new(pool.clone());
    let request = replay_request(tenant, &suffix);
    let expected_public_client_ids = request
        .clients
        .iter()
        .map(|client| client.prepared.registration.client_id.clone())
        .collect::<Vec<_>>();

    let first = repository.onboard(request.clone()).await.unwrap();
    let suite_origin = request.suite_origin.clone();
    assert!(!first.idempotent_replay);
    assert_eq!(first.client_count, 2);

    let applicant_id = first.applicant_user_id.expect("onboarding applicant");
    let claims = UserRepository::new(pool)
        .active_subject_claims_by_tenant_id(
            tenant.tenant_id,
            nazo_identity::UserId::new(applicant_id).unwrap(),
        )
        .await
        .unwrap()
        .expect("active conformance applicant claims");
    assert_eq!(claims.preferred_username, request.applicant.username);
    assert_eq!(claims.name.as_deref(), Some("Conformance Test User"));
    assert_eq!(claims.given_name.as_deref(), Some("Conformance"));
    assert_eq!(claims.family_name.as_deref(), Some("User"));
    assert_eq!(claims.middle_name.as_deref(), Some("Test"));
    assert_eq!(claims.nickname.as_deref(), Some("ctu"));
    assert_eq!(
        claims.profile.as_deref(),
        Some("https://example.invalid/conformance/profile")
    );
    assert_eq!(
        claims.picture.as_deref(),
        Some("https://example.invalid/conformance/avatar")
    );
    assert_eq!(
        claims.website.as_deref(),
        Some("https://example.invalid/conformance")
    );
    assert_eq!(claims.gender.as_deref(), Some("unspecified"));
    assert_eq!(claims.birthdate.as_deref(), Some("2000-01-01"));
    assert_eq!(claims.zoneinfo.as_deref(), Some("UTC"));
    assert_eq!(claims.locale.as_deref(), Some("en-US"));
    assert_eq!(
        claims
            .address
            .as_ref()
            .and_then(|address| address.formatted.as_deref()),
        Some("100 Universal City Plaza\nUniversal City, CA 91608\nUS")
    );
    assert_eq!(
        claims
            .address
            .as_ref()
            .and_then(|address| address.street_address.as_deref()),
        Some("100 Universal City Plaza")
    );
    assert_eq!(
        claims
            .address
            .as_ref()
            .and_then(|address| address.locality.as_deref()),
        Some("Universal City")
    );
    assert_eq!(
        claims
            .address
            .as_ref()
            .and_then(|address| address.region.as_deref()),
        Some("CA")
    );
    assert_eq!(
        claims
            .address
            .as_ref()
            .and_then(|address| address.postal_code.as_deref()),
        Some("91608")
    );
    assert_eq!(
        claims
            .address
            .as_ref()
            .and_then(|address| address.country.as_deref()),
        Some("US")
    );
    assert_eq!(claims.phone_number.as_deref(), Some("+1 555 5550000"));
    assert!(claims.phone_number_verified);
    assert!(claims.updated_at > 0);
    assert_eq!(
        first
            .client_mappings
            .iter()
            .map(|mapping| mapping.logical_client_id.as_str())
            .collect::<Vec<_>>(),
        vec!["logical-b", "logical-a"]
    );
    assert_eq!(
        first
            .client_mappings
            .iter()
            .map(|mapping| mapping.client_id.as_str())
            .collect::<Vec<_>>(),
        expected_public_client_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    assert!(
        first
            .client_mappings
            .iter()
            .all(|mapping| Uuid::parse_str(&mapping.client_id).is_err())
    );
    assert_eq!(
        repository
            .active_dynamic_registration_lease_id(
                tenant.tenant_id.as_uuid(),
                request
                    .dynamic_registration_initial_access_token_sha256
                    .as_deref()
                    .unwrap(),
            )
            .await
            .unwrap(),
        Some(first.lease_id)
    );
    assert_eq!(
        repository
            .active_ciba_automated_decision_lease_id(
                tenant.tenant_id.as_uuid(),
                request
                    .ciba_automated_decision_token_sha256
                    .as_deref()
                    .unwrap(),
            )
            .await
            .unwrap(),
        Some(first.lease_id)
    );
    assert_eq!(
        repository
            .active_lease_for_suite_origin(
                tenant.tenant_id.as_uuid(),
                "nazoauth-full",
                &suite_origin,
            )
            .await
            .unwrap(),
        Some(first.lease_id)
    );

    let replay = repository.onboard(request).await.unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(replay.lease_id, first.lease_id);
    assert_eq!(replay.applicant_user_id, first.applicant_user_id);
    assert_eq!(replay.client_mappings, first.client_mappings);

    repository
        .revoke(tenant.tenant_id.as_uuid(), first.lease_id)
        .await
        .unwrap();
    let cleanup = repository.cleanup().await.unwrap();
    assert!(cleanup.cleaned_leases >= 1);
    assert_eq!(
        repository
            .active_lease_for_suite_origin(
                tenant.tenant_id.as_uuid(),
                "nazoauth-full",
                &suite_origin,
            )
            .await
            .unwrap(),
        None
    );
}
