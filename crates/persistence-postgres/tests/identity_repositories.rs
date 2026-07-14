use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{Jsonb, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use nazo_identity::{
    AdminPolicyError, AdminUserUpdateOutcome, OrganizationId, RealmId, TenantContext, TenantId,
    UserId, UserProfile,
    ports::{
        AdminUserUpdate, FederationLogin, NewFederatedIdentity, NewFederationLink, ProfileUpdate,
        RepositoryError,
    },
    scim::NormalizedScimUser,
};
use nazo_postgres::{
    FederationRepository, MfaRepository, OAuthClientRepository, PasskeyRepository, ScimRepository,
    UserRepository, create_pool, get_conn,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, QueryableByName)]
struct IdentitySecurityEventRecord {
    #[diesel(sql_type = Text)]
    event_type: String,
    #[diesel(sql_type = Text)]
    outcome: String,
    #[diesel(sql_type = Text)]
    reason_code: String,
}

async fn identity_security_events(
    pool: &nazo_postgres::DbPool,
    user_id: UserId,
) -> Vec<IdentitySecurityEventRecord> {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query(
        "SELECT event_type, outcome, reason_code FROM identity_security_events WHERE actor_id = $1 OR target_user_id = $1 ORDER BY occurred_at, id",
    )
    .bind::<SqlUuid, _>(user_id.as_uuid())
    .load::<IdentitySecurityEventRecord>(&mut connection)
    .await
    .unwrap()
}

#[test]
fn repositories_accept_validated_tenant_and_user_ids() {
    fn assert_user_repository(_: &UserRepository) {}
    fn assert_mfa_repository(_: &MfaRepository) {}

    let _tenant = TenantContext::default_system();
    let _user = UserId::new(Uuid::now_v7()).expect("generated ID is non-nil");
    let _ = (assert_user_repository, assert_mfa_repository);
}

async fn database_fixture() -> Option<(nazo_postgres::DbPool, TenantContext, UserId)> {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires NAZO_TEST_DATABASE_URL or DATABASE_URL")
            }
            Err(_) => return None,
        };
    let pool = create_pool(database_url, 8).expect("test pool can be built");
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).expect("generated ID is non-nil");
    let token = Uuid::now_v7().simple().to_string();
    let mut connection = get_conn(&pool).await.expect("test database is reachable");
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid, _>(user_id.as_uuid()).bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid()).bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .bind::<Text, _>(format!("postgres-{token}")).bind::<Text, _>(format!("postgres-{token}@example.test"))
        .execute(&mut connection).await.expect("fixture user can be inserted");
    drop(connection);
    Some((pool, tenant, user_id))
}

async fn cleanup(pool: &nazo_postgres::DbPool, user_id: UserId) {
    if let Ok(mut connection) = get_conn(pool).await {
        let _ = sql_query(
            "DELETE FROM identity_security_events WHERE actor_id = $1 OR target_user_id = $1",
        )
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await;
        let _ = sql_query("DELETE FROM users WHERE id = $1")
            .bind::<SqlUuid, _>(user_id.as_uuid())
            .execute(&mut connection)
            .await;
    }
}

async fn foreign_tenant_user_fixture(pool: &nazo_postgres::DbPool) -> (TenantContext, UserId) {
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let suffix = tenant_id.simple();
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("INSERT INTO tenants (id,slug,display_name) VALUES ($1,$2,'Foreign test')")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<Text, _>(format!("foreign-{suffix}"))
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("INSERT INTO realms (id,tenant_id,slug,display_name) VALUES ($1,$2,'default','Foreign realm')")
        .bind::<SqlUuid, _>(realm_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("INSERT INTO organizations (id,tenant_id,slug,display_name) VALUES ($1,$2,'default','Foreign organization')")
        .bind::<SqlUuid, _>(organization_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(realm_id)
        .bind::<SqlUuid, _>(organization_id)
        .bind::<Text, _>(format!("foreign-{suffix}"))
        .bind::<Text, _>(format!("foreign-{suffix}@example.test"))
        .execute(&mut connection)
        .await
        .unwrap();
    (
        TenantContext {
            tenant_id: TenantId::new(tenant_id).unwrap(),
            realm_id: RealmId::new(realm_id).unwrap(),
            organization_id: OrganizationId::new(organization_id).unwrap(),
        },
        UserId::new(user_id).unwrap(),
    )
}

async fn cleanup_foreign_tenant(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    user_id: UserId,
) {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("DELETE FROM identity_security_events WHERE tenant_id = $1")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM organizations WHERE id = $1")
        .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM realms WHERE id = $1")
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
}

fn oauth_client(tenant: TenantContext, client_id: String) -> OAuthClient {
    OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        realm_id: tenant.realm_id.as_uuid(),
        organization_id: tenant.organization_id.as_uuid(),
        registration: ValidatedClientRegistration {
            client_id,
            client_name: "Original client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["resource://original".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "client_secret_basic".to_owned(),
            subject_type: "pairwise".to_owned(),
            sector_identifier_uri: Some("https://sector.example/redirects.json".to_owned()),
            sector_identifier_host: Some("sector.example".to_owned()),
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: false,
            backchannel_logout_uri: Some("https://client.example/backchannel".to_owned()),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: vec!["mtls.example".to_owned()],
            tls_client_auth_san_uri: vec![],
            tls_client_auth_san_ip: vec![],
            tls_client_auth_san_email: vec![],
            jwks: None,
            introspection_encrypted_response_alg: Some("RSA-OAEP".to_owned()),
            introspection_encrypted_response_enc: Some("A256GCM".to_owned()),
            userinfo_signed_response_alg: Some("ES256".to_owned()),
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

async fn cleanup_oauth_client(pool: &nazo_postgres::DbPool, id: Uuid) {
    if let Ok(mut connection) = get_conn(pool).await {
        let _ = sql_query("DELETE FROM oauth_clients WHERE id = $1")
            .bind::<SqlUuid, _>(id)
            .execute(&mut connection)
            .await;
    }
}

#[tokio::test]
async fn seed_upsert_is_atomic_and_preserves_unmanaged_client_state() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = OAuthClientRepository::new(pool.clone());
    let original = oauth_client(tenant, format!("seed-{}", Uuid::now_v7()));
    repository
        .insert(
            &original,
            Some("old-secret"),
            Some("keep-registration-token"),
        )
        .await
        .unwrap();
    let mut managed_update = original.clone();
    managed_update.id = Uuid::now_v7();
    managed_update.client_name = "Managed update".to_owned();
    managed_update.redirect_uris = vec!["https://updated.example/callback".to_owned()];
    managed_update.scopes = vec!["openid".to_owned(), "profile".to_owned()];
    managed_update.subject_type = "public".to_owned();
    managed_update.sector_identifier_uri = None;
    managed_update.sector_identifier_host = None;
    managed_update.tls_client_auth_san_dns.clear();
    managed_update.backchannel_logout_uri = None;
    managed_update.introspection_encrypted_response_alg = None;
    managed_update.introspection_encrypted_response_enc = None;
    managed_update.userinfo_signed_response_alg = None;

    let (left, right) = tokio::join!(
        repository.upsert(&managed_update, Some("new-secret")),
        repository.upsert(&managed_update, Some("new-secret")),
    );
    left.unwrap();
    right.unwrap();
    let stored = repository
        .by_client_id(original.tenant_id, &original.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.id, original.id,
        "conflict update must retain the row identity"
    );
    assert_eq!(stored.client_name, "Managed update");
    assert_eq!(stored.redirect_uris, managed_update.redirect_uris);
    assert_eq!(stored.scopes, managed_update.scopes);
    assert_eq!(stored.subject_type, original.subject_type);
    assert_eq!(stored.sector_identifier_uri, original.sector_identifier_uri);
    assert_eq!(
        stored.tls_client_auth_san_dns,
        original.tls_client_auth_san_dns
    );
    assert_eq!(
        stored.backchannel_logout_uri,
        original.backchannel_logout_uri
    );
    assert_eq!(
        stored.introspection_encrypted_response_alg,
        original.introspection_encrypted_response_alg
    );
    let mut connection = get_conn(&pool).await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct RegistrationToken {
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        value: Option<String>,
    }
    let token = sql_query(
        "SELECT registration_access_token_blake3 AS value FROM oauth_clients WHERE id = $1",
    )
    .bind::<SqlUuid, _>(original.id)
    .get_result::<RegistrationToken>(&mut connection)
    .await
    .unwrap();
    assert_eq!(token.value.as_deref(), Some("keep-registration-token"));

    let concurrent = oauth_client(tenant, format!("seed-concurrent-{}", Uuid::now_v7()));
    let (left, right) = tokio::join!(
        repository.upsert(&concurrent, None),
        repository.upsert(&concurrent, None),
    );
    left.expect("first concurrent seed upsert succeeds");
    right.expect("second concurrent seed upsert succeeds");
    assert!(
        repository
            .by_client_id(concurrent.tenant_id, &concurrent.client_id)
            .await
            .unwrap()
            .is_some()
    );

    cleanup_oauth_client(&pool, original.id).await;
    let concurrent_id = repository
        .by_client_id(concurrent.tenant_id, &concurrent.client_id)
        .await
        .unwrap()
        .unwrap()
        .id;
    cleanup_oauth_client(&pool, concurrent_id).await;
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn seed_upsert_persists_jarm_algorithm_on_insert_and_conflict_update() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = OAuthClientRepository::new(pool.clone());
    let mut client = oauth_client(tenant, format!("seed-jarm-{}", Uuid::now_v7()));
    client.authorization_signed_response_alg = Some("PS256".to_owned());

    repository
        .upsert(&client, None)
        .await
        .expect("fresh seed upsert should persist JARM metadata");
    let inserted = repository
        .by_client_id(client.tenant_id, &client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        inserted.authorization_signed_response_alg.as_deref(),
        Some("PS256")
    );

    client.authorization_signed_response_alg = Some("ES256".to_owned());
    repository
        .upsert(&client, None)
        .await
        .expect("conflict update should replace managed JARM metadata");
    let updated = repository
        .by_client_id(client.tenant_id, &client.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated.authorization_signed_response_alg.as_deref(),
        Some("ES256")
    );

    cleanup_oauth_client(&pool, inserted.id).await;
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn application_projection_filters_mixed_scope_elements() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = OAuthClientRepository::new(pool.clone());
    let client = oauth_client(tenant, format!("mixed-scopes-{}", Uuid::now_v7()));
    repository.insert(&client, None, None).await.unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO user_client_grants (tenant_id, user_id, client_id, first_authorized_at, last_authorized_at, last_scopes, last_resource_indicators, last_authorization_details, authorization_count) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $4, '[]'::jsonb, '[]'::jsonb, 1)")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<SqlUuid, _>(client.id)
        .bind::<Jsonb, _>(json!(["openid", 42, null, "profile", {"scope": "admin"}]))
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let applications = repository
        .applications_for_user(user_id.as_uuid())
        .await
        .unwrap();
    assert_eq!(applications.len(), 1);
    let valid_scopes = applications[0]
        .last_scopes
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(valid_scopes, vec!["openid", "profile"]);

    cleanup_oauth_client(&pool, client.id).await;
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn profile_update_persists_only_the_typed_profile_projection() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = UserRepository::new(pool.clone());
    let before = repository
        .public_account_by_id(tenant.tenant_id, user_id)
        .await
        .unwrap()
        .unwrap();
    let profile = UserProfile {
        display_name: Some("Persisted Profile".to_owned()),
        phone_number: Some("+15559999999".to_owned()),
        phone_number_verified: false,
        ..UserProfile::default()
    };

    let returned = repository
        .update_profile(
            tenant.tenant_id,
            user_id,
            ProfileUpdate {
                profile: profile.clone(),
            },
        )
        .await
        .unwrap();
    let reloaded = repository
        .public_account_by_id(tenant.tenant_id, user_id)
        .await
        .unwrap()
        .unwrap();

    for account in [&returned, &reloaded] {
        assert_eq!(account.account.email, before.account.email);
        assert_eq!(account.principal.role, before.principal.role);
        assert_eq!(account.profile, profile);
    }

    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn client_secret_comparison_returns_only_salt_and_database_equality() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = OAuthClientRepository::new(pool.clone());
    let client = oauth_client(tenant, format!("secret-equality-{}", Uuid::now_v7()));
    let stored = "client-secret-v1:c2FsdA:6lJn3EOo_fxJByZR75cMn9RtlGGznqcVi4V4OkrfNCw";
    repository
        .insert(&client, Some(stored), None)
        .await
        .unwrap();

    assert_eq!(
        repository
            .client_secret_salt(client.id)
            .await
            .unwrap()
            .as_deref(),
        Some("c2FsdA")
    );
    assert!(
        repository
            .client_secret_digest_matches(client.id, stored)
            .await
            .unwrap()
    );
    assert!(
        !repository
            .client_secret_digest_matches(
                client.id,
                "client-secret-v1:c2FsdA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .await
            .unwrap()
    );

    cleanup_oauth_client(&pool, client.id).await;
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn user_lookup_is_tenant_scoped() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let repository = UserRepository::new(pool.clone());
    assert!(
        repository
            .principal_by_id(tenant, user_id)
            .await
            .expect("lookup succeeds")
            .is_some()
    );
    let other_tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        ..tenant
    };
    assert!(
        repository
            .principal_by_id(other_tenant, user_id)
            .await
            .expect("lookup succeeds")
            .is_none()
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn totp_last_step_compare_and_set_has_one_concurrent_winner() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO user_totp_credentials (tenant_id,user_id,secret_base32,label,confirmed_at) VALUES ($1,$2,'JBSWY3DPEHPK3PXP','test',CURRENT_TIMESTAMP)").bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(user_id.as_uuid()).execute(&mut connection).await.unwrap();
    drop(connection);
    let repository = MfaRepository::new(pool.clone());
    let (left, right) = tokio::join!(
        repository.compare_and_set_totp_step(tenant.tenant_id, user_id, 42),
        repository.compare_and_set_totp_step(tenant.tenant_id, user_id, 42)
    );
    assert_ne!(left.unwrap(), right.unwrap());
    let events = identity_security_events(&pool, user_id).await;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.event_type == "mfa_totp_attempt")
    );
    assert!(
        events
            .iter()
            .any(|event| { event.outcome == "success" && event.reason_code == "totp_accepted" })
    );
    assert!(
        events
            .iter()
            .any(|event| event.outcome == "replay" && event.reason_code == "totp_replay")
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn totp_verification_classification_and_audit_are_atomic_and_replay_safe() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const STEP: i64 = 1_234_567;
    let timestamp = STEP * nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS;
    let code = nazo_identity::mfa::totp_for_step(b"12345678901234567890", STEP).unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO user_totp_credentials (tenant_id,user_id,secret_base32,label,confirmed_at) VALUES ($1,$2,$3,'test',CURRENT_TIMESTAMP)")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<Text, _>(SECRET)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let repository = MfaRepository::new(pool.clone());

    assert_eq!(
        repository
            .verify_and_consume_totp(tenant.tenant_id, user_id, "not-a-code", timestamp)
            .await
            .unwrap(),
        nazo_identity::ports::TotpVerificationOutcome::Invalid
    );
    assert_eq!(
        repository
            .verify_and_consume_totp(tenant.tenant_id, user_id, &code, timestamp)
            .await
            .unwrap(),
        nazo_identity::ports::TotpVerificationOutcome::Accepted
    );
    assert_eq!(
        repository
            .verify_and_consume_totp(tenant.tenant_id, user_id, &code, timestamp)
            .await
            .unwrap(),
        nazo_identity::ports::TotpVerificationOutcome::Replay
    );

    let events = identity_security_events(&pool, user_id).await;
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|event| {
        event.outcome == "invalid_credential" && event.reason_code == "totp_invalid"
    }));
    assert!(
        events
            .iter()
            .any(|event| { event.outcome == "success" && event.reason_code == "totp_accepted" })
    );
    assert!(
        events
            .iter()
            .any(|event| event.outcome == "replay" && event.reason_code == "totp_replay")
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn failed_totp_enrollment_confirmation_is_durably_audited_without_state_change() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let repository = MfaRepository::new(pool.clone());
    repository
        .begin_totp_enrollment(
            tenant.tenant_id,
            user_id,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned(),
            "test".to_owned(),
        )
        .await
        .unwrap();

    assert_eq!(
        repository
            .verify_and_confirm_totp(
                tenant.tenant_id,
                user_id,
                "invalid",
                1_234_567 * nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS,
                (0..nazo_identity::mfa::MFA_BACKUP_CODE_COUNT)
                    .map(|index| format!("unused-invalid-attempt-hash-{index}"))
                    .collect(),
            )
            .await
            .unwrap(),
        nazo_identity::ports::TotpVerificationOutcome::Invalid
    );
    let enrollment = repository
        .totp_enrollment(tenant.tenant_id, user_id)
        .await
        .unwrap()
        .expect("pending enrollment remains available");
    assert!(!enrollment.confirmed);
    assert!(enrollment.last_used_step.is_none());
    let events = identity_security_events(&pool, user_id).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "mfa_totp_attempt");
    assert_eq!(events[0].outcome, "invalid_credential");
    assert_eq!(events[0].reason_code, "totp_invalid");
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn concurrent_totp_enrollment_confirmation_has_one_audited_winner() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let repository = MfaRepository::new(pool.clone());
    repository
        .begin_totp_enrollment(
            tenant.tenant_id,
            user_id,
            SECRET.to_owned(),
            "concurrent enrollment".to_owned(),
        )
        .await
        .unwrap();
    let step = chrono::Utc::now().timestamp() / nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS;
    let timestamp = step * nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS;
    let code = nazo_identity::mfa::totp_for_step(b"12345678901234567890", step).unwrap();
    let hashes = |prefix: &str| {
        (0..nazo_identity::mfa::MFA_BACKUP_CODE_COUNT)
            .map(|index| format!("{prefix}-backup-hash-{index}"))
            .collect::<Vec<_>>()
    };

    let (left, right) = tokio::join!(
        repository.verify_and_confirm_totp(
            tenant.tenant_id,
            user_id,
            &code,
            timestamp,
            hashes("left"),
        ),
        repository.verify_and_confirm_totp(
            tenant.tenant_id,
            user_id,
            &code,
            timestamp,
            hashes("right"),
        )
    );
    let mut outcomes = [left.unwrap(), right.unwrap()];
    outcomes.sort_by_key(|outcome| match outcome {
        nazo_identity::ports::TotpVerificationOutcome::Accepted => 0,
        nazo_identity::ports::TotpVerificationOutcome::Replay => 1,
        nazo_identity::ports::TotpVerificationOutcome::Invalid => 2,
    });
    assert_eq!(
        outcomes,
        [
            nazo_identity::ports::TotpVerificationOutcome::Accepted,
            nazo_identity::ports::TotpVerificationOutcome::Replay,
        ]
    );
    let events = identity_security_events(&pool, user_id).await;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .any(|event| event.outcome == "success" && event.reason_code == "totp_accepted")
    );
    assert!(
        events
            .iter()
            .any(|event| event.outcome == "replay" && event.reason_code == "totp_replay")
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn backup_code_is_consumed_once_atomically() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let code = "ABCD-EFGH";
    let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
    let hash = Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let repository = MfaRepository::new(pool.clone());
    repository
        .replace_backup_code_hashes(tenant.tenant_id, user_id, vec![hash])
        .await
        .unwrap();
    let candidate_id = repository
        .backup_code_candidates(tenant.tenant_id, user_id)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .id;
    let (left, right) = tokio::join!(
        repository.consume_backup_code_candidate(tenant.tenant_id, user_id, candidate_id),
        repository.consume_backup_code_candidate(tenant.tenant_id, user_id, candidate_id)
    );
    assert_ne!(left.unwrap(), right.unwrap());
    let events = identity_security_events(&pool, user_id).await;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.event_type == "mfa_backup_code_attempt")
    );
    assert!(events.iter().any(|event| {
        event.outcome == "success" && event.reason_code == "backup_code_accepted"
    }));
    assert!(
        events.iter().any(|event| {
            event.outcome == "replay" && event.reason_code == "backup_code_replay"
        })
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn passkey_and_federation_uniqueness_are_typed_conflicts() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let passkeys = PasskeyRepository::new(pool.clone());
    passkeys
        .insert(
            tenant.tenant_id,
            user_id,
            "credential".into(),
            json!({}),
            "test".into(),
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        passkeys
            .insert(
                tenant.tenant_id,
                user_id,
                "credential".into(),
                json!({}),
                "test".into(),
                0
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    let federation = FederationRepository::new(pool.clone());
    let new_link = NewFederationLink {
        tenant_id: tenant.tenant_id,
        user_id,
        provider_type: "oidc".into(),
        provider_id: "provider".into(),
        subject: "subject".into(),
        email: "a@example.test".into(),
        claims: json!({}),
    };
    federation.insert(new_link.clone()).await.unwrap();
    assert_eq!(
        federation.insert(new_link).await.unwrap_err(),
        RepositoryError::Conflict
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn passkey_counter_update_is_monotonic_compare_and_set() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = PasskeyRepository::new(pool.clone());
    repository
        .insert(
            tenant.tenant_id,
            user_id,
            "counter-cas".into(),
            json!({"counter": 0}),
            "counter test".into(),
            0,
        )
        .await
        .unwrap();

    let (left, right) = tokio::join!(
        repository.update_counter(
            tenant.tenant_id,
            user_id,
            "counter-cas",
            0,
            1,
            json!({"counter": 1})
        ),
        repository.update_counter(
            tenant.tenant_id,
            user_id,
            "counter-cas",
            0,
            1,
            json!({"counter": 1})
        )
    );
    assert!(matches!(
        (&left, &right),
        (Ok(()), Err(RepositoryError::Conflict)) | (Err(RepositoryError::Conflict), Ok(()))
    ));
    assert_eq!(
        repository
            .update_counter(
                tenant.tenant_id,
                user_id,
                "counter-cas",
                0,
                2,
                json!({"counter": 2})
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    assert_eq!(
        repository
            .update_counter(
                tenant.tenant_id,
                user_id,
                "counter-cas",
                1,
                1,
                json!({"counter": 1})
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );

    repository
        .insert(
            tenant.tenant_id,
            user_id,
            "zero-counter".into(),
            json!({"counter": 0}),
            "zero counter".into(),
            0,
        )
        .await
        .unwrap();
    repository
        .update_counter(
            tenant.tenant_id,
            user_id,
            "zero-counter",
            0,
            0,
            json!({"counter": 0}),
        )
        .await
        .unwrap();
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn concurrent_federated_create_is_idempotent_and_tenant_scoped() {
    let Some((pool, tenant, fixture_user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = FederationRepository::new(pool.clone());
    let suffix = Uuid::now_v7();
    let login = FederationLogin {
        tenant,
        provider_type: "oidc".into(),
        provider_id: format!("provider-{suffix}"),
        subject: format!("subject-{suffix}"),
        email: Some(format!("federated-{suffix}@example.test")),
        claims: json!({"sub": format!("subject-{suffix}")}),
    };
    let new_identity = NewFederatedIdentity {
        login: login.clone(),
        email: login.email.clone().unwrap(),
        display_name: Some("Concurrent Federation".into()),
        password_hash: nazo_identity::ports::PasswordHashInput::new("test-only-bootstrap-hash")
            .unwrap(),
    };

    let (left, right) = tokio::join!(
        repository.create_federated(new_identity.clone()),
        repository.create_federated(new_identity)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.user_id(), right.user_id());

    let other_tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        ..tenant
    };
    assert!(
        repository
            .resolve_existing(FederationLogin {
                tenant: other_tenant,
                ..login
            })
            .await
            .unwrap()
            .is_none()
    );
    cleanup(&pool, left.user_id()).await;
    cleanup(&pool, fixture_user_id).await;
}

#[tokio::test]
async fn subject_claims_reject_invalid_persisted_role_invariant() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 0 WHERE id = $1")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let error = UserRepository::new(pool.clone())
        .subject_claims_by_id(tenant, user_id)
        .await
        .unwrap_err();
    assert!(matches!(error, RepositoryError::Consistency(_)));
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn inactive_account_has_no_issuable_subject_claims() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = false WHERE id = $1")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let claims = UserRepository::new(pool.clone())
        .active_subject_claims_by_tenant_id(tenant.tenant_id, user_id)
        .await
        .unwrap();

    assert!(claims.is_none());
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn mfa_backup_code_bounds_and_enrollment_conflict_are_explicit() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = MfaRepository::new(pool.clone());
    assert_eq!(
        repository
            .replace_backup_code_hashes(
                tenant.tenant_id,
                user_id,
                (0..=nazo_identity::mfa::MFA_BACKUP_CODE_COUNT)
                    .map(|index| format!("hash-{index}"))
                    .collect(),
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );

    let mut connection = get_conn(&pool).await.unwrap();
    for index in 0..=nazo_identity::mfa::MFA_BACKUP_CODE_COUNT {
        sql_query(
            "INSERT INTO user_mfa_backup_codes (tenant_id,user_id,code_hash) VALUES ($1,$2,$3)",
        )
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<Text, _>(format!("invalid-hash-{index}"))
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);
    assert!(matches!(
        repository
            .backup_code_candidates(tenant.tenant_id, user_id)
            .await,
        Err(RepositoryError::Consistency(_))
    ));

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM user_mfa_backup_codes WHERE tenant_id=$1 AND user_id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM user_totp_credentials WHERE tenant_id=$1 AND user_id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let (left, right) = tokio::join!(
        repository.begin_totp_enrollment(
            tenant.tenant_id,
            user_id,
            "JBSWY3DPEHPK3PXP".into(),
            "first".into()
        ),
        repository.begin_totp_enrollment(
            tenant.tenant_id,
            user_id,
            "GEZDGNBVGY3TQOJQ".into(),
            "second".into()
        )
    );
    assert!(
        left.is_ok() || right.is_ok(),
        "left={left:?}, right={right:?}"
    );
    assert!(matches!(left, Ok(()) | Err(RepositoryError::Conflict)));
    assert!(matches!(right, Ok(()) | Err(RepositoryError::Conflict)));
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn scim_replace_returns_domain_claims_from_one_transaction() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let user = ScimRepository::new(pool.clone())
        .replace(
            tenant,
            user_id,
            NormalizedScimUser {
                user_name: "replacement".into(),
                email: "replacement@example.test".into(),
                active: false,
                display_name: Some("Replacement".into()),
                given_name: None,
                family_name: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(user.user_id(), user_id);
    assert_eq!(user.account.username, "replacement");
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn admin_partial_update_validates_final_role_level_before_commit() {
    let Some((pool, tenant, actor_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let Some((_, _, user_id)) = database_fixture().await else {
        unreachable!("the same database environment was available above");
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 10 WHERE id = $1")
        .bind::<SqlUuid, _>(actor_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let repository = UserRepository::new(pool.clone());

    assert_eq!(
        repository
            .admin_update_authorized(
                tenant.tenant_id,
                actor_id,
                user_id,
                AdminUserUpdate {
                    role: Some("admin".into()),
                    admin_level: None,
                    active: None,
                },
            )
            .await
            .unwrap(),
        AdminUserUpdateOutcome::Denied(AdminPolicyError::InvalidRoleLevel)
    );
    let unchanged = repository
        .public_account_by_id(tenant.tenant_id, user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.role_name(), "user");
    assert_eq!(unchanged.admin_level(), 0);

    let promoted = repository
        .admin_update_authorized(
            tenant.tenant_id,
            actor_id,
            user_id,
            AdminUserUpdate {
                role: Some("admin".into()),
                admin_level: Some(5),
                active: None,
            },
        )
        .await
        .unwrap();
    let AdminUserUpdateOutcome::Updated(promoted) = promoted else {
        panic!("valid promotion should update");
    };
    assert_eq!(promoted.role_name(), "admin");
    assert_eq!(promoted.admin_level(), 5);

    let level_only = repository
        .admin_update_authorized(
            tenant.tenant_id,
            actor_id,
            user_id,
            AdminUserUpdate {
                role: None,
                admin_level: Some(7),
                active: None,
            },
        )
        .await
        .unwrap();
    let AdminUserUpdateOutcome::Updated(level_only) = level_only else {
        panic!("valid level update should update");
    };
    assert_eq!(level_only.role_name(), "admin");
    assert_eq!(level_only.admin_level(), 7);
    cleanup(&pool, user_id).await;
    cleanup(&pool, actor_id).await;
}

#[tokio::test]
async fn authorized_admin_update_serializes_hierarchy_and_audit_in_one_transaction() {
    let Some((pool, tenant, actor_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let Some((_, _, target_id)) = database_fixture().await else {
        unreachable!("the same database environment was available above");
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 10 WHERE id = $1")
        .bind::<SqlUuid, _>(actor_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let repository = UserRepository::new(pool.clone());
    let (foreign_tenant, foreign_user_id) = foreign_tenant_user_fixture(&pool).await;
    let cross_tenant = repository
        .admin_update_authorized(
            tenant.tenant_id,
            actor_id,
            foreign_user_id,
            AdminUserUpdate {
                role: Some("admin".into()),
                admin_level: Some(1),
                active: Some(false),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        cross_tenant,
        AdminUserUpdateOutcome::Denied(AdminPolicyError::CrossTenant)
    );
    let foreign = repository
        .public_account_by_id(foreign_tenant.tenant_id, foreign_user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(foreign.role_name(), "user");
    assert!(foreign.principal.active);

    let promoted = repository
        .admin_update_authorized(
            tenant.tenant_id,
            actor_id,
            target_id,
            AdminUserUpdate {
                role: Some("admin".into()),
                admin_level: Some(5),
                active: None,
            },
        )
        .await
        .unwrap();
    assert!(matches!(promoted, AdminUserUpdateOutcome::Updated(_)));

    let (higher_actor, lower_actor) = tokio::join!(
        repository.admin_update_authorized(
            tenant.tenant_id,
            actor_id,
            target_id,
            AdminUserUpdate {
                role: None,
                admin_level: Some(4),
                active: None,
            },
        ),
        repository.admin_update_authorized(
            tenant.tenant_id,
            target_id,
            actor_id,
            AdminUserUpdate {
                role: None,
                admin_level: None,
                active: Some(false),
            },
        )
    );
    assert!(matches!(
        higher_actor.unwrap(),
        AdminUserUpdateOutcome::Updated(_)
    ));
    assert_eq!(
        lower_actor.unwrap(),
        AdminUserUpdateOutcome::Denied(AdminPolicyError::TargetAtOrAboveActor)
    );

    let target = repository
        .public_account_by_id(tenant.tenant_id, target_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.admin_level(), 4);
    assert!(target.principal.active);
    let events = identity_security_events(&pool, target_id).await;
    assert_eq!(events.len(), 3);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.outcome == "success" && event.reason_code == "admin_updated")
            .count(),
        2
    );
    assert!(events.iter().any(|event| {
        event.outcome == "denied" && event.reason_code == "target_at_or_above_actor"
    }));
    let actor_events = identity_security_events(&pool, actor_id).await;
    assert!(
        actor_events
            .iter()
            .any(|event| event.outcome == "denied" && event.reason_code == "cross_tenant")
    );

    cleanup_foreign_tenant(&pool, foreign_tenant, foreign_user_id).await;
    cleanup(&pool, target_id).await;
    cleanup(&pool, actor_id).await;
}

#[test]
fn admin_user_page_is_tenant_scoped_at_the_query_boundary() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/repositories/users.rs"
    ))
    .expect("user repository source is readable");
    let page = source
        .split("pub async fn page(")
        .nth(1)
        .and_then(|source| source.split("pub async fn admin_update_authorized(").next())
        .expect("page repository function remains present");
    assert_eq!(
        page.matches(".filter(users::tenant_id.eq(tenant_id.as_uuid()))")
            .count(),
        2,
        "both count and page rows must be constrained to the authenticated tenant"
    );
}

#[test]
fn server_mfa_verification_does_not_query_migrated_tables_directly() {
    for path in [
        "/../authorization-server/src/domain/mfa_profile.rs",
        "/../identity/src/mfa_service.rs",
    ] {
        let source = std::fs::read_to_string(format!("{}{}", env!("CARGO_MANIFEST_DIR"), path))
            .expect("MFA service source is readable");
        assert!(!source.contains("user_totp_credentials"), "{path}");
        assert!(!source.contains("user_mfa_backup_codes"), "{path}");
    }
}

#[test]
fn totp_enrollment_orders_cross_store_changes_for_safe_recovery() {
    let provider_source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../authorization-server/src/domain/mfa_profile.rs"
    ))
    .expect("server MFA provider source is readable");
    let confirmation = provider_source
        .split("fn confirm_totp(")
        .nth(1)
        .and_then(|source| source.split("fn verify_challenge(").next())
        .expect("MFA confirmation operation remains present");
    let rate_limit = confirmation
        .find(".enforce_rate_limit(")
        .expect("rate limiting must fail closed before expensive MFA work");
    let preparation = confirmation
        .find(".prepare_totp_confirmation(")
        .expect("TOTP and backup-code preparation remains explicit");
    let session_rotation = confirmation
        .find(".rotate(")
        .expect("session and CSRF must rotate atomically before enabling MFA");
    let postgres_confirmation = confirmation
        .find(".confirm_totp(")
        .expect("PostgreSQL confirmation must reverify under row lock");
    let failed_rotation_discard = confirmation
        .find(".discard_unpublished_rotation(")
        .expect("a rejected PostgreSQL confirmation must discard the unpublished MFA session");
    assert!(rate_limit < preparation);
    assert!(preparation < session_rotation);
    assert!(session_rotation < postgres_confirmation);
    assert!(postgres_confirmation < failed_rotation_discard);

    let core_source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../identity/src/mfa_service.rs"
    ))
    .expect("identity MFA service source is readable");
    let preparation = core_source
        .split("pub async fn prepare_totp_confirmation(")
        .nth(1)
        .and_then(|source| source.split("pub async fn confirm_totp(").next())
        .expect("identity TOTP preparation remains present");
    let invalid_audit = preparation
        .find(".record_invalid_totp_attempt(")
        .expect("invalid enrollment verification must be durably audited");
    let backup_hashing = preparation
        .find(".hash_secrets(")
        .expect("backup-code hashes must use the bounded hash port");
    assert!(invalid_audit < backup_hashing);
}

#[test]
fn server_has_no_identity_rows_or_identity_diesel_queries() {
    const FORBIDDEN: &[&str] = &[
        "UserRow",
        "PasskeyCredentialRow",
        "ExternalIdentityLinkRow",
        "TotpCredentialRow",
        "crate::schema::users::",
        "nazo_postgres::schema::users::",
        "user_totp_credentials::",
        "user_mfa_backup_codes::",
        "user_mfa_remembered_devices::",
        "user_passkey_credentials::",
        "external_identity_links::",
        "users (id) {",
        "user_totp_credentials (id) {",
        "user_mfa_backup_codes (id) {",
        "user_mfa_remembered_devices (id) {",
        "user_passkey_credentials (id) {",
        "external_identity_links (id) {",
        "client_access_requests::",
        "UserAccessRequestRow",
        "PendingAccessRequestRow",
        "AccessRequestProjection",
    ];

    fn visit(path: &std::path::Path, violations: &mut Vec<String>) {
        for entry in std::fs::read_dir(path).expect("server source directory is readable") {
            let entry = entry.expect("server source entry is readable");
            let path = entry.path();
            if path.is_dir() {
                visit(&path, violations);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).expect("server source is UTF-8");
                for forbidden in FORBIDDEN {
                    if source.contains(forbidden) {
                        violations.push(format!("{} contains {forbidden}", path.display()));
                    }
                }
            }
        }
    }

    let mut violations = Vec::new();
    visit(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../authorization-server/src"),
        &mut violations,
    );
    assert!(
        violations.is_empty(),
        "server identity persistence leaked outside nazo-postgres:\n{}",
        violations.join("\n")
    );
}

#[test]
fn access_request_boundary_has_no_server_diesel_or_forwarding_support_layer() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let admin_path = manifest.join("../authorization-server/src/http/admin/access_requests.rs");
    let profile_path = manifest.join("../authorization-server/src/http/profile/access_requests.rs");
    let delivery_path = manifest.join("../authorization-server/src/http/profile/delivery.rs");
    let identity_profile_path = manifest.join("../identity/src/profile.rs");
    let support_path = manifest.join("../authorization-server/src/support/access_requests.rs");
    let forwarding_repositories_path =
        manifest.join("../authorization-server/src/support/repositories.rs");
    let admin = std::fs::read_to_string(admin_path).expect("admin access handler is readable");
    let profile =
        std::fs::read_to_string(profile_path).expect("profile access handler is readable");
    let delivery = std::fs::read_to_string(delivery_path).expect("delivery handler is readable");
    let identity_profile = std::fs::read_to_string(identity_profile_path)
        .expect("identity profile service is readable");

    for source in [&admin, &profile] {
        assert!(!source.contains("diesel::"));
        assert!(!source.contains("client_access_requests::"));
    }
    assert!(
        !support_path.exists(),
        "forwarding access-request support layer must stay deleted"
    );
    assert!(
        !forwarding_repositories_path.exists(),
        "forwarding repository helpers must not hide focused repository use"
    );
    assert!(admin.contains("RepositoryError::AlreadyProcessed"));
    assert!(
        admin
            .find(".store(")
            .expect("focused delivery storage must stage the payload")
            < admin.find(".approve(").unwrap(),
        "delivery must fail closed before the PostgreSQL approval transaction"
    );
    assert!(admin.contains("\"delivery_state\": \"staged\""));
    assert!(
        admin.find(".approve(").unwrap()
            < admin
                .find("committed_delivery_payload")
                .expect("approval must activate delivery only after commit")
    );
    assert!(delivery.contains("service.claim_delivery(&user, token)"));
    assert!(identity_profile.contains("approved_delivery_matches"));
    assert!(
        identity_profile.find("approved_delivery_matches").unwrap()
            < identity_profile
                .find(".consume(")
                .expect("focused delivery storage must consume atomically"),
        "delivery linkage must be validated before one-time consumption"
    );
    assert!(profile.contains("service.list(&user)"));
    assert!(identity_profile.contains(".load_many(&lookups)"));
    assert!(!identity_profile.contains("KEYS"));
    assert!(!identity_profile.contains("SCAN"));
    assert!(identity_profile.contains("delivery_payload_matches"));
    assert!(identity_profile.contains("delivery_candidate"));
    assert!(profile.contains("delivery_token"));
    assert!(!admin.contains("\"delivery_token\""));
}

#[test]
fn oauth_client_queries_use_the_focused_postgres_repository_without_a_server_facade() {
    fn function_bodies(source: &str) -> Vec<&str> {
        let mut bodies = Vec::new();
        let mut offset = 0;
        while let Some(relative) = source[offset..].find("fn ") {
            let start = offset + relative;
            let Some(open_relative) = source[start..].find('{') else {
                break;
            };
            let open = start + open_relative;
            let mut depth = 0usize;
            for (relative, byte) in source.as_bytes()[open..].iter().enumerate() {
                match byte {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            let end = open + relative + 1;
                            bodies.push(&source[start..end]);
                            offset = end;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if offset <= start {
                break;
            }
        }
        bodies
    }

    fn visit(
        path: &std::path::Path,
        support_root: &std::path::Path,
        violations: &mut Vec<String>,
        direct_repository_calls: &mut usize,
    ) {
        for entry in std::fs::read_dir(path).expect("server source directory is readable") {
            let path = entry.expect("server source entry is readable").path();
            if path.is_dir() {
                visit(&path, support_root, violations, direct_repository_calls);
                continue;
            }
            if !path.extension().is_some_and(|extension| extension == "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("server source is UTF-8");
            *direct_repository_calls += source.matches("OAuthClientRepository::new").count();
            if path.starts_with(support_root) {
                for body in function_bodies(&source) {
                    if body.contains("OAuthClientRepository::new")
                        && !body.contains("diesel::")
                        && !body.contains("sql_query")
                    {
                        violations.push(format!(
                            "{} hides an OAuth client repository forwarding wrapper",
                            path.display()
                        ));
                    }
                }
                if source.contains("oauth_clients::table")
                    || source.contains("select(ClientRow::as_select())")
                {
                    violations.push(format!(
                        "{} hides an OAuth client query in server support",
                        path.display()
                    ));
                }
            }
        }
    }

    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let server_root = manifest.join("../authorization-server/src");
    let support_root = server_root.join("support");
    let mut violations = Vec::new();
    let mut direct_repository_calls = 0;
    visit(
        &server_root,
        &support_root,
        &mut violations,
        &mut direct_repository_calls,
    );
    assert!(
        violations.is_empty(),
        "OAuth client query facades are forbidden:\n{}",
        violations.join("\n")
    );
    assert!(
        direct_repository_calls >= 10,
        "focused repository calls must remain at their actual callers"
    );
    let client_policy = std::fs::read_to_string(
        manifest.join("../authorization-server/src/domain/client_policy.rs"),
    )
    .unwrap();
    assert!(!client_policy.contains("oauth_clients::table"));
}

fn contains_oauth_clients_table_name(source: &str) -> bool {
    use syn::visit::Visit as _;

    let file =
        syn::parse_file(source).expect("contract fixtures and server sources are valid Rust");
    let mut visitor = OAuthClientTableVisitor::default();
    visitor.visit_file(&file);
    visitor.found
}

#[derive(Default)]
struct OAuthClientTableVisitor {
    found: bool,
}

impl OAuthClientTableVisitor {
    fn inspect(&mut self, source: &str) {
        const TABLE: &str = "oauth_clients";
        let source = source.to_ascii_lowercase();
        self.found |= source.match_indices(TABLE).any(|(offset, _)| {
            let before = source[..offset].bytes().next_back();
            let after = source[offset + TABLE.len()..].bytes().next();
            let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
            before.is_none_or(|byte| !is_identifier(byte))
                && after.is_none_or(|byte| !is_identifier(byte))
        });
    }
}

fn is_cfg_test(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg")
        && attribute
            .parse_args::<syn::Path>()
            .is_ok_and(|path| path.is_ident("test"))
}

fn attributes_have_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(is_cfg_test)
}

fn item_is_cfg_test(item: &syn::Item) -> bool {
    let attributes = match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Verbatim(_) => return false,
        _ => return false,
    };
    attributes_have_cfg_test(attributes)
}

fn impl_item_is_cfg_test(item: &syn::ImplItem) -> bool {
    let attributes = match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        syn::ImplItem::Verbatim(_) => return false,
        _ => return false,
    };
    attributes_have_cfg_test(attributes)
}

fn trait_item_is_cfg_test(item: &syn::TraitItem) -> bool {
    let attributes = match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        syn::TraitItem::Verbatim(_) => return false,
        _ => return false,
    };
    attributes_have_cfg_test(attributes)
}

fn foreign_item_is_cfg_test(item: &syn::ForeignItem) -> bool {
    let attributes = match item {
        syn::ForeignItem::Fn(item) => &item.attrs,
        syn::ForeignItem::Static(item) => &item.attrs,
        syn::ForeignItem::Type(item) => &item.attrs,
        syn::ForeignItem::Macro(item) => &item.attrs,
        syn::ForeignItem::Verbatim(_) => return false,
        _ => return false,
    };
    attributes_have_cfg_test(attributes)
}

impl<'ast> syn::visit::Visit<'ast> for OAuthClientTableVisitor {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !item_is_cfg_test(item) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !impl_item_is_cfg_test(item) {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !trait_item_is_cfg_test(item) {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        if !foreign_item_is_cfg_test(item) {
            syn::visit::visit_foreign_item(self, item);
        }
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if !attribute.path().is_ident("doc") {
            syn::visit::visit_attribute(self, attribute);
        }
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let ident = ident.to_string();
        if ident
            .strip_prefix("r#")
            .unwrap_or(&ident)
            .eq_ignore_ascii_case("oauth_clients")
        {
            self.found = true;
        }
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.inspect(&literal.value());
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.inspect(&mac.tokens.to_string());
        syn::visit::visit_macro(self, mac);
    }
}

#[test]
fn oauth_client_persistence_contract_rejects_aliases_declarations_imports_and_raw_sql() {
    let mutations = [
        (
            "local SQL-name alias",
            r#"diesel::table! { #[sql_name = "oauth_clients"] clients (id) { id -> Uuid, } } fn load() { clients::table; }"#,
        ),
        (
            "direct Diesel declaration",
            r#"diesel::table! { oauth_clients (id) { id -> diesel::sql_types::Uuid, } }"#,
        ),
        (
            "schema import alias",
            r#"use crate::schema::oauth_clients as clients; fn load() { clients::table; }"#,
        ),
        (
            "case-insensitive quoted raw SQL",
            r##"fn load() { sql_query(r#"SELECT * FROM \"OAUTH_CLIENTS\""#); }"##,
        ),
    ];

    for (name, mutation) in mutations {
        assert!(
            contains_oauth_clients_table_name(mutation),
            "{name} must not bypass the production ownership contract"
        );
    }
}

#[test]
fn oauth_client_persistence_contract_ignores_documentation_and_cfg_test_items() {
    let documentation = r#"
        /// The server must not query `oauth_clients::table` or declare
        /// `#[sql_name = "oauth_clients"]` in production.
        /* Raw SQL such as SELECT * FROM oauth_clients is also forbidden. */
        fn repository_boundary_documentation() {}
    "#;
    assert!(
        !contains_oauth_clients_table_name(documentation),
        "documentation must not be reported as production persistence"
    );
    let test_only_schema = r#"
        #[cfg(test)]
        pub(crate) use crate::schema::oauth_clients;
    "#;
    assert!(
        !contains_oauth_clients_table_name(test_only_schema),
        "cfg(test) schema imports must not be reported as production persistence"
    );

    let test_module = r##"
        #[cfg(test)]
        mod tests {
            const QUERY: &str = r#"SELECT * FROM oauth_clients"#;

            fn fixture() {
                // A closing brace in a comment must not end the test module: }
                let brace = "}";
                crate::schema::oauth_clients::table;
            }
        }
    "##;
    assert!(
        !contains_oauth_clients_table_name(test_module),
        "an entire cfg(test) module must be outside the production-source contract"
    );

    let stacked_attributes = r#"
        #[cfg(test)]
        #[allow(dead_code)]
        pub(crate) use crate::schema::oauth_clients;
    "#;
    assert!(
        !contains_oauth_clients_table_name(stacked_attributes),
        "attributes stacked after cfg(test) must remain attached to the gated item"
    );

    let associated_items = r#"
        struct Repository;

        impl Repository {
            #[cfg(test)]
            const QUERY: &str = "SELECT * FROM oauth_clients";

            #[cfg(test)]
            fn fixture() { crate::schema::oauth_clients::table; }
        }
    "#;
    assert!(
        !contains_oauth_clients_table_name(associated_items),
        "cfg(test) associated items must be outside the production-source contract"
    );
}

#[test]
fn oauth_client_persistence_contract_keeps_scanning_after_cfg_test_items() {
    let production_violations = [
        r#"
            #[cfg(test)]
            mod tests { const QUERY: &str = "SELECT * FROM oauth_clients"; }
            use crate::schema::oauth_clients as clients;
        "#,
        r#"
            #[cfg(test)]
            #[allow(dead_code)]
            fn fixture() { let query = "SELECT * FROM oauth_clients"; }
            diesel::table! { oauth_clients (id) { id -> Uuid, } }
        "#,
    ];

    for source in production_violations {
        assert!(
            contains_oauth_clients_table_name(source),
            "a real production violation after a cfg(test) item must still be detected"
        );
    }
}

#[test]
fn oauth_client_persistence_contract_distinguishes_lifetimes_from_character_literals() {
    let test_only_fixture = r#"
        fn marker<'connection>() {} #[cfg(test)] fn fixture() { crate::schema::oauth_clients::table; } const MARKER: char = 'x';
    "#;

    assert!(
        !contains_oauth_clients_table_name(test_only_fixture),
        "a lifetime before cfg(test) and a later character literal must not hide the gate"
    );
}

#[test]
fn oauth_client_persistence_contract_skips_cfg_test_items_with_const_generics() {
    let test_only_fixture = r#"
        #[cfg(test)]
        fn fixture<const CAPACITY: usize = { 1 }>() {
            crate::schema::oauth_clients::table;
        }
    "#;

    assert!(
        !contains_oauth_clients_table_name(test_only_fixture),
        "a const-generic expression must not truncate the cfg(test) item boundary"
    );
}

#[test]
fn oauth_client_repository_keeps_records_private_and_returns_domain_clients() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repository = std::fs::read_to_string(manifest.join("src/repositories/clients.rs"))
        .expect("OAuth client repository source is readable");
    let postgres_root = std::fs::read_to_string(manifest.join("src/lib.rs"))
        .expect("postgres crate root is readable");
    let server_rows =
        std::fs::read_to_string(manifest.join("../authorization-server/src/domain/rows.rs"))
            .expect("server rows source is readable");

    assert!(
        repository.contains("struct OAuthClientRecord"),
        "the Diesel OAuth client record must be explicitly private"
    );
    assert!(
        !repository.contains("pub struct OAuthClient {"),
        "postgres must not publish a Diesel OAuth client result row"
    );
    assert!(
        !repository.contains("pub client_secret_hash"),
        "client secret hashes must not be public repository result fields"
    );
    assert!(
        !postgres_root.contains("OAuthClient,"),
        "postgres must not re-export an OAuth client persistence row"
    );
    assert!(
        !server_rows.contains("impl From<nazo_postgres::"),
        "server must not reconstruct a duplicate full row from a postgres adapter result"
    );
    assert!(
        repository.contains("AdminClientRepositoryPort")
            && repository.contains("OAuthClient")
            && repository.contains(".map(OAuthClientRecord::into_domain)"),
        "repository lookups must return the auth-owned storage-independent client"
    );
    assert!(
        !repository.contains(".select(oauth_clients::client_secret_hash)"),
        "stored client-secret hashes must never be selected into Rust"
    );
    assert!(
        repository.contains("client_secret_hash.eq(candidate_digest)")
            && repository.contains("diesel::dsl::exists"),
        "candidate digests must be compared by PostgreSQL equality/EXISTS"
    );
    let auth_root =
        std::fs::read_to_string(manifest.join("../authorization-server-core/src/lib.rs"))
            .expect("auth crate root is readable");
    assert!(
        !auth_root.contains("verify_client_secret_hash"),
        "auth must not expose a public stored-hash verifier"
    );
    let server_schema =
        std::fs::read_to_string(manifest.join("../authorization-server/src/schema.rs"))
            .expect("server schema is readable");
    assert!(
        !server_schema.contains("oauth_clients"),
        "server production schema must not declare, join, or allow oauth_clients"
    );

    fn visit(path: &std::path::Path, violations: &mut Vec<String>) {
        for entry in std::fs::read_dir(path).expect("server source directory is readable") {
            let path = entry.expect("server source entry is readable").path();
            if path.is_dir() {
                visit(&path, violations);
                continue;
            }
            if !path.extension().is_some_and(|extension| extension == "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("server source is UTF-8");
            if contains_oauth_clients_table_name(&source) {
                violations.push(format!(
                    "{} references or declares the OAuth-client table",
                    path.display()
                ));
            }
            for body in source.split("struct ").skip(1) {
                let Some(body) = body.split_once('}').map(|(body, _)| body) else {
                    continue;
                };
                let persistence_sentinels = [
                    "client_id",
                    "client_secret_hash",
                    "redirect_uris",
                    "grant_types",
                ]
                .into_iter()
                .filter(|field| body.contains(field))
                .count();
                if persistence_sentinels == 4 {
                    violations.push(format!(
                        "{} defines a persistence-shaped OAuth client struct",
                        path.display()
                    ));
                }
            }
            if (source.contains("impl TryFrom<") || source.contains("impl From<"))
                && [
                    "client_id:",
                    "client_name:",
                    "client_type:",
                    "redirect_uris:",
                ]
                .into_iter()
                .all(|field| source.contains(field))
            {
                violations.push(format!(
                    "{} contains a field-copy OAuth client conversion",
                    path.display()
                ));
            }
        }
    }

    let mut violations = Vec::new();
    visit(
        &manifest.join("../authorization-server/src"),
        &mut violations,
    );
    assert!(
        violations.is_empty(),
        "server production code must not own OAuth-client persistence:\n{}",
        violations.join("\n")
    );
}

#[test]
fn identity_claim_boundaries_use_narrow_single_snapshot_reads() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let users = std::fs::read_to_string(manifest.join("src/repositories/users.rs"))
        .expect("user repository source is readable");
    let issue =
        std::fs::read_to_string(manifest.join("../authorization-server/src/http/token/issue.rs"))
            .expect("token issue source is readable");
    let userinfo =
        std::fs::read_to_string(manifest.join("../authorization-server/src/domain/userinfo.rs"))
            .expect("userinfo domain adapter source is readable");
    let token_issuance =
        std::fs::read_to_string(manifest.join("src/repositories/token_issuance.rs"))
            .expect("token issuance repository source is readable");

    assert!(users.contains("select(PrincipalRow::as_select())"));
    assert!(users.contains("select(SubjectClaimsRow::as_select())"));
    for source in [&issue, &userinfo] {
        assert!(source.contains(".active_subject_claims("));
        assert!(!source.contains(".principal_by_tenant_id("));
        assert!(!source.contains(".subject_claims_by_tenant_id("));
        assert!(!source.contains("UserRepository::new"));
    }
    assert!(token_issuance.contains(".active_subject_claims_by_tenant_id("));
}

#[test]
fn client_registration_keeps_plaintext_and_persistence_shape_out_of_core_and_postgres() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let auth_registration = std::fs::read_to_string(
        manifest.join("../authorization-server-core/src/client_registration.rs"),
    )
    .expect("auth client registration source is readable");
    let postgres_approval =
        std::fs::read_to_string(manifest.join("src/repositories/access_requests.rs"))
            .expect("postgres approval source is readable");

    assert!(!auth_registration.contains("PreparedClientRegistration"));
    assert!(!auth_registration.contains("issued_secret"));
    assert!(!auth_registration.contains("client_secret_hash"));
    assert!(!auth_registration.contains("registration_access_token_blake3"));
    assert!(!postgres_approval.contains("issued_secret"));
    assert!(postgres_approval.contains("struct ClientInsertCommand"));
}
