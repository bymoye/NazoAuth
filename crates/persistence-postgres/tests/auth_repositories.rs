use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    AccessTokenRevocation, AdminGrantRepositoryPort, NewRefreshToken,
    PendingBackchannelLogoutDelivery, RefreshTokenPersistResult, TokenRepositoryPort,
    TokenRevocation,
};
use nazo_postgres::{
    AuditRepository, AuthorizationRepository, GrantRepository, TokenIssuanceRepository,
    TokenRepository, create_pool,
};
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

// These tests exercise a deliberately global worker claim. Serialize only the
// claim-based cases so one test worker cannot consume the other's delivery.
static BACKCHANNEL_CLAIM_TEST_LOCK: Mutex<()> = Mutex::const_new(());

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI auth repository tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct FixtureIds {
    #[diesel(sql_type = SqlUuid)]
    user_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
    #[diesel(sql_type = Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn tagged_database_url(database_url: &str, application_name: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}application_name={application_name}")
}

async fn wait_for_blocked_query(
    connection: &mut AsyncPgConnection,
    application_name: &str,
    expected_query: &str,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let blocked = sql_query(
            r#"
            SELECT COUNT(*)::bigint AS count
            FROM pg_stat_activity
            WHERE application_name = $1
              AND wait_event_type = 'Lock'
              AND query ILIKE $2
            "#,
        )
        .bind::<Text, _>(application_name)
        .bind::<Text, _>(expected_query)
        .get_result::<CountRow>(connection)
        .await
        .expect("blocked PostgreSQL activity should be observable");
        if blocked.count > 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for blocked query {expected_query} from {application_name}");
}

fn family_lock_key(family_id: Uuid) -> i64 {
    let bytes = family_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    high ^ low
}

async fn install_rotation_insert_gate(
    connection: &mut AsyncPgConnection,
    family_id: Uuid,
    gate_key: i64,
) -> (String, String) {
    let suffix = Uuid::now_v7().simple().to_string();
    let function = format!("test_refresh_rotation_gate_{suffix}");
    let trigger = format!("test_refresh_rotation_gate_trigger_{suffix}");
    sql_query(format!(
        r#"
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.token_family_id = '{family_id}'::uuid
               AND NEW.rotated_from_id IS NOT NULL THEN
                PERFORM pg_advisory_xact_lock({gate_key});
            END IF;
            RETURN NEW;
        END
        $$
        "#
    ))
    .execute(&mut *connection)
    .await
    .expect("rotation insert gate function should install");
    sql_query(format!(
        r#"
        CREATE TRIGGER {trigger}
        BEFORE INSERT ON oauth_tokens
        FOR EACH ROW EXECUTE FUNCTION {function}()
        "#
    ))
    .execute(connection)
    .await
    .expect("rotation insert gate should install");
    (trigger, function)
}

async fn remove_rotation_insert_gate(
    connection: &mut AsyncPgConnection,
    trigger: &str,
    function: &str,
) {
    sql_query(format!("DROP TRIGGER {trigger} ON oauth_tokens"))
        .execute(&mut *connection)
        .await
        .expect("rotation insert gate trigger should be removed");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(&mut *connection)
        .await
        .expect("rotation insert gate should be removed");
}

fn refresh_token_fixture(
    fixture: &FixtureIds,
    tenant_id: Uuid,
    family_id: Uuid,
    raw_token: String,
    rotated_from_id: Option<Uuid>,
) -> NewRefreshToken {
    NewRefreshToken {
        raw_token,
        tenant_id,
        family_id,
        rotated_from_id,
        lost_response_retry: None,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        subject: fixture.user_id.to_string(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    }
}

async fn fixture(database_url: &str) -> FixtureIds {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("migrations should apply");
    let suffix = Uuid::now_v7().simple().to_string();
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    sql_query(format!(
        r#"
        WITH inserted_user AS (
            INSERT INTO users (username, email, password_hash)
            VALUES ('auth-repo-{suffix}', 'auth-repo-{suffix}@example.test', 'test-only-hash')
            RETURNING id
        ), inserted_client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method
            ) VALUES (
                'auth-repo-{suffix}', 'Auth Repository Test', 'confidential',
                '["https://client.example/callback"]'::jsonb,
                '["openid", "offline_access"]'::jsonb,
                '["authorization_code", "refresh_token"]'::jsonb,
                'client_secret_basic'
            ) RETURNING id, client_id
        )
        SELECT inserted_user.id AS user_id, inserted_client.id AS client_id,
               inserted_client.client_id AS client_public_id
        FROM inserted_user CROSS JOIN inserted_client
        "#
    ))
    .get_result::<FixtureIds>(&mut connection)
    .await
    .expect("auth repository fixture should insert")
}

#[tokio::test]
async fn grants_upsert_cover_and_revoke_tokens_atomically() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let repository = GrantRepository::new(create_pool(&database_url, 4).unwrap());
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    repository
        .upsert(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .expect("grant should insert");
    repository
        .upsert(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .expect("grant should update");
    let stored = repository
        .authorization(fixture.user_id, fixture.client_id)
        .await
        .expect("grant should load")
        .expect("grant should exist");
    assert_eq!(stored.authorization_count, 2);

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            issued_at, expires_at, subject
        ) VALUES (
            '{token_hash}', '{}', '{}', '{}', '["openid", "offline_access"]'::jsonb,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}'
        )
        "#,
        Uuid::now_v7(),
        fixture.client_id,
        fixture.user_id,
        fixture.user_id
    ))
    .execute(&mut connection)
    .await
    .expect("active refresh token fixture should insert");
    let revoked = repository
        .revoke_by_client_id(tenant_id, fixture.user_id, &fixture.client_public_id)
        .await
        .expect("grant revocation should commit");
    assert_eq!(revoked.revoked_refresh_tokens, 1);
    assert_eq!(revoked.removed_grants, 1);
}

#[tokio::test]
async fn grant_revoke_waits_for_concurrent_refresh_rotation_before_revoking_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let original_raw = format!("grant-race-original-{}", Uuid::now_v7());
    let successor_raw = format!("grant-race-successor-{}", Uuid::now_v7());
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    assert_eq!(
        tokens
            .persist_refresh_token(refresh_token_fixture(
                &fixture,
                tenant_id,
                family_id,
                original_raw.clone(),
                None,
            ))
            .await
            .expect("original refresh token should persist"),
        RefreshTokenPersistResult::Inserted
    );
    let original = tokens
        .by_raw_refresh_token(tenant_id, &original_raw)
        .await
        .expect("original refresh token should load")
        .expect("original refresh token should exist");

    let grants = GrantRepository::new(create_pool(&database_url, 4).unwrap());
    grants
        .upsert(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &[],
            &json!([]),
        )
        .await
        .expect("grant should insert");

    let gate_key = family_lock_key(family_id).wrapping_add(1);
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    let (trigger, function) =
        install_rotation_insert_gate(&mut coordinator, family_id, gate_key).await;
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold rotation insert gate");

    let rotation_application = format!("grant-rotation-{}", Uuid::now_v7().simple());
    let rotation_repository = TokenRepository::new(
        create_pool(tagged_database_url(&database_url, &rotation_application), 1).unwrap(),
    );
    let successor = refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        successor_raw,
        Some(original.id),
    );
    let rotation =
        tokio::spawn(async move { rotation_repository.persist_refresh_token(successor).await });
    wait_for_blocked_query(&mut coordinator, &rotation_application, "%oauth_tokens%").await;

    let revoke_application = format!("grant-revoke-{}", Uuid::now_v7().simple());
    let revoke_repository = GrantRepository::new(
        create_pool(tagged_database_url(&database_url, &revoke_application), 1).unwrap(),
    );
    let user_id = fixture.user_id;
    let client_public_id = fixture.client_public_id.clone();
    let revoke = tokio::spawn(async move {
        revoke_repository
            .revoke_by_client_id(tenant_id, user_id, &client_public_id)
            .await
    });
    wait_for_blocked_query(&mut coordinator, &revoke_application, "%").await;

    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release rotation insert gate");
    assert_eq!(
        rotation
            .await
            .expect("rotation task should join")
            .expect("rotation should commit"),
        RefreshTokenPersistResult::Inserted
    );
    let revoked = revoke
        .await
        .expect("grant revoke task should join")
        .expect("grant revoke should commit");
    assert_eq!(revoked.removed_grants, 1);
    assert!(
        grants
            .authorization(fixture.user_id, fixture.client_id)
            .await
            .expect("grant state should load")
            .is_none()
    );
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("refresh family state should load"),
        "grant revoke returned while a concurrently rotated successor remained active"
    );
    remove_rotation_insert_gate(&mut coordinator, &trigger, &function).await;
}

#[tokio::test]
async fn refresh_rotation_reuse_compromises_the_whole_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let suffix = Uuid::now_v7();
    let repository = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    let make = |label: &str, rotated_from_id| NewRefreshToken {
        raw_token: format!("auth-repo-{label}-{suffix}"),
        tenant_id,
        family_id,
        rotated_from_id,
        lost_response_retry: None,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        subject: fixture.user_id.to_string(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };
    assert_eq!(
        repository
            .persist_refresh_token(make("original", None))
            .await
            .expect("original token should persist"),
        RefreshTokenPersistResult::Inserted
    );
    let original = repository
        .by_raw_refresh_token(tenant_id, &format!("auth-repo-original-{suffix}"))
        .await
        .expect("original token should load")
        .expect("original token should exist");
    assert_eq!(
        repository
            .persist_refresh_token(make("successor", Some(original.id)))
            .await
            .expect("successor should rotate"),
        RefreshTokenPersistResult::Inserted
    );
    assert_eq!(
        repository
            .persist_refresh_token(make("reuse", Some(original.id)))
            .await
            .expect("reuse should be classified"),
        RefreshTokenPersistResult::RotationConflict
    );
    assert!(
        !repository
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("family state should load")
    );
}

#[tokio::test]
async fn authorization_code_replay_compensation_revokes_both_token_kinds() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    let access_jti = format!("authorization-replay-{}", Uuid::now_v7());
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            issued_at, expires_at, subject
        ) VALUES (
            '{token_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}'
        )
        "#,
        fixture.client_id, fixture.user_id, fixture.user_id
    ))
    .execute(&mut connection)
    .await
    .expect("authorization replay refresh fixture should insert");

    AuthorizationRepository::new(create_pool(&database_url, 4).unwrap())
        .revoke_issued_tokens(
            tenant_id,
            fixture.client_id,
            &access_jti,
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            Some(family_id),
        )
        .await
        .expect("authorization replay compensation should commit");
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    assert!(
        tokens
            .access_token_revoked(tenant_id, &access_jti)
            .await
            .unwrap()
    );
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn token_management_revocation_is_client_scoped_idempotent_and_serializes_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let owner = fixture(&database_url).await;
    let foreign = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let first = format!("revocation-first-{}", Uuid::now_v7());
    let second = format!("revocation-second-{}", Uuid::now_v7());
    let first_hash = blake3::hash(first.as_bytes()).to_hex().to_string();
    let second_hash = blake3::hash(second.as_bytes()).to_hex().to_string();
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            issued_at, expires_at, subject
        ) VALUES
            ('{first_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}'),
            ('{second_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}')
        "#,
        owner.client_id,
        owner.user_id,
        owner.user_id,
        owner.client_id,
        owner.user_id,
        owner.user_id,
    ))
    .execute(&mut connection)
    .await
    .expect("refresh family fixture should insert");

    let foreign_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let foreign_result = foreign_repository
        .revoke_token(TokenRevocation {
            tenant_id,
            client_id: foreign.client_id,
            raw_token: &first,
            access_token: None,
        })
        .await
        .expect("foreign revocation must remain non-disclosing");
    assert_eq!(foreign_result, 0);

    let first_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let second_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let (first_result, second_result) = tokio::join!(
        first_repository.revoke_token(TokenRevocation {
            tenant_id,
            client_id: owner.client_id,
            raw_token: &first,
            access_token: None,
        }),
        second_repository.revoke_token(TokenRevocation {
            tenant_id,
            client_id: owner.client_id,
            raw_token: &second,
            access_token: None,
        }),
    );
    assert_eq!(
        first_result.unwrap() + second_result.unwrap(),
        2,
        "one serialized revocation must revoke the complete active family"
    );

    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    assert_eq!(
        repository
            .revoke_token(TokenRevocation {
                tenant_id,
                client_id: owner.client_id,
                raw_token: &first,
                access_token: None,
            })
            .await
            .expect("repeat family revocation should be idempotent"),
        0
    );

    let access_jti = format!("revocation-access-{}", Uuid::now_v7());
    for _ in 0..2 {
        repository
            .revoke_token(TokenRevocation {
                tenant_id,
                client_id: owner.client_id,
                raw_token: "opaque-access-token",
                access_token: Some(AccessTokenRevocation {
                    jti: access_jti.clone(),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                }),
            })
            .await
            .expect("access-token revocation should be idempotent");
    }

    let active_family = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE token_family_id = $1 AND revoked_at IS NULL",
    )
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(active_family.count, 0);
    let access_revocations = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM access_token_revocations \
         WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(owner.client_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(access_revocations.count, 1);
}

#[tokio::test]
async fn authorization_replay_waits_for_concurrent_refresh_rotation_before_compensation() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let original_raw = format!("replay-race-original-{}", Uuid::now_v7());
    let successor_raw = format!("replay-race-successor-{}", Uuid::now_v7());
    let access_jti = format!("replay-race-access-{}", Uuid::now_v7());
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    assert_eq!(
        tokens
            .persist_refresh_token(refresh_token_fixture(
                &fixture,
                tenant_id,
                family_id,
                original_raw.clone(),
                None,
            ))
            .await
            .expect("original refresh token should persist"),
        RefreshTokenPersistResult::Inserted
    );
    let original = tokens
        .by_raw_refresh_token(tenant_id, &original_raw)
        .await
        .expect("original refresh token should load")
        .expect("original refresh token should exist");

    let gate_key = family_lock_key(family_id).wrapping_add(1);
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    let (trigger, function) =
        install_rotation_insert_gate(&mut coordinator, family_id, gate_key).await;
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold rotation insert gate");

    let rotation_application = format!("replay-rotation-{}", Uuid::now_v7().simple());
    let rotation_repository = TokenRepository::new(
        create_pool(tagged_database_url(&database_url, &rotation_application), 1).unwrap(),
    );
    let successor = refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        successor_raw,
        Some(original.id),
    );
    let rotation =
        tokio::spawn(async move { rotation_repository.persist_refresh_token(successor).await });
    wait_for_blocked_query(&mut coordinator, &rotation_application, "%oauth_tokens%").await;

    let compensation_application = format!("replay-compensation-{}", Uuid::now_v7().simple());
    let compensation_repository = AuthorizationRepository::new(
        create_pool(
            tagged_database_url(&database_url, &compensation_application),
            1,
        )
        .unwrap(),
    );
    let client_id = fixture.client_id;
    let access_jti_for_task = access_jti.clone();
    let compensation = tokio::spawn(async move {
        compensation_repository
            .revoke_issued_tokens(
                tenant_id,
                client_id,
                &access_jti_for_task,
                Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                Some(family_id),
            )
            .await
    });
    wait_for_blocked_query(&mut coordinator, &compensation_application, "%").await;

    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release rotation insert gate");
    assert_eq!(
        rotation
            .await
            .expect("rotation task should join")
            .expect("rotation should commit"),
        RefreshTokenPersistResult::Inserted
    );
    compensation
        .await
        .expect("compensation task should join")
        .expect("authorization replay compensation should commit");
    assert!(
        tokens
            .access_token_revoked(tenant_id, &access_jti)
            .await
            .expect("access token compensation should load")
    );
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("refresh family state should load"),
        "authorization replay compensation returned while a rotated successor remained active"
    );
    remove_rotation_insert_gate(&mut coordinator, &trigger, &function).await;
}

#[tokio::test]
async fn audit_repository_records_scim_use_and_drives_logout_outbox() {
    let _claim_guard = BACKCHANNEL_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(format!(
        "INSERT INTO scim_tokens (tenant_id, token_hash, label, scopes) VALUES ('{tenant_id}', '{token_hash}', 'audit repository test', '[\"scim:read\"]'::jsonb)"
    ))
    .execute(&mut connection)
    .await
    .expect("SCIM token fixture should insert");
    let repository = AuditRepository::new(create_pool(&database_url, 4).unwrap());
    let credential = repository
        .active_scim_credential(&token_hash)
        .await
        .expect("SCIM credential should load")
        .expect("SCIM credential should exist");
    repository
        .record_scim_token_use(
            credential.id,
            credential.tenant_id,
            &["scim:read".to_owned()],
            Some("a".repeat(64)),
            Some("b".repeat(64)),
        )
        .await
        .expect("SCIM use audit should commit");
    let count =
        sql_query("SELECT COUNT(*) AS count FROM scim_audit_events WHERE scim_token_id = $1")
            .bind::<SqlUuid, _>(credential.id)
            .get_result::<CountRow>(&mut connection)
            .await
            .expect("SCIM audit count should load");
    assert_eq!(count.count, 1);

    let logout_token = format!("logout-token-test-{}", Uuid::now_v7());
    repository
        .enqueue_backchannel_logout(
            tenant_id,
            fixture.client_id,
            "audit-repository-client",
            "https://client.example/backchannel-logout",
            &logout_token,
            chrono::Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("backchannel delivery should enqueue");
    let claimed = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("backchannel delivery should claim");
    let claimed = claimed
        .into_iter()
        .find(|delivery| delivery.logout_token == logout_token)
        .expect("the test delivery should be claimed");
    repository
        .complete_backchannel_logout(claimed.id, claimed.attempts)
        .await
        .expect("backchannel delivery should complete");
    let reclaimed = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("completed delivery should not reclaim");
    assert!(
        reclaimed.iter().all(|delivery| delivery.id != claimed.id),
        "the completed delivery must not be reclaimed"
    );
}

#[tokio::test]
async fn backchannel_logout_fanout_rolls_back_when_any_delivery_is_invalid() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = AuditRepository::new(create_pool(&database_url, 4).unwrap());
    let marker = format!("logout-atomic-{}", Uuid::now_v7());
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(2);
    let result = repository
        .enqueue_backchannel_logout_batch(&[
            PendingBackchannelLogoutDelivery {
                tenant_id,
                client_id: fixture.client_id,
                client_public_id: fixture.client_public_id,
                logout_uri: "https://client.example/backchannel-logout".to_owned(),
                logout_token: marker.clone(),
                expires_at,
            },
            PendingBackchannelLogoutDelivery {
                tenant_id,
                client_id: Uuid::now_v7(),
                client_public_id: "missing-client".to_owned(),
                logout_uri: "https://missing.example/backchannel-logout".to_owned(),
                logout_token: format!("{marker}-invalid"),
                expires_at,
            },
        ])
        .await;
    assert!(
        result.is_err(),
        "invalid fan-out member must fail the batch"
    );

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let count = sql_query(
        "SELECT COUNT(*) AS count FROM backchannel_logout_deliveries WHERE logout_token = $1",
    )
    .bind::<Text, _>(&marker)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("backchannel rollback count should load");
    assert_eq!(count.count, 0, "fan-out must commit all deliveries or none");
}

#[test]
fn server_auth_callers_do_not_query_diesel_or_auth_tables() {
    let server =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../authorization-server/src");
    for relative in [
        "domain/rows.rs",
        "http/admin/grants.rs",
        "http/authorization/request/prompt_none.rs",
        "http/scim/auth.rs",
        "http/token/issue/authorization_code_state.rs",
        "http/token/issue/refresh_persistence.rs",
        "http/token/native_sso.rs",
        "http/token/refresh.rs",
        "http/token/token_exchange.rs",
        "http/token/userinfo.rs",
        "domain/client_policy.rs",
        "http/views.rs",
    ] {
        let source = std::fs::read_to_string(server.join(relative))
            .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"));
        for forbidden in [
            "diesel::",
            "diesel_async",
            "oauth_tokens::",
            "user_client_grants::",
            "access_token_revocations::",
            "scim_tokens::",
            "scim_audit_events::",
            "backchannel_logout_deliveries::",
        ] {
            assert!(
                !source.contains(forbidden),
                "{relative} retained forbidden persistence token {forbidden}"
            );
        }
    }
    let schema = std::fs::read_to_string(server.join("schema.rs")).expect("server schema reads");
    assert_eq!(
        schema.matches("diesel::table!").count(),
        0,
        "server production schema must not define persistence tables"
    );
}

#[tokio::test]
async fn stale_logout_worker_cannot_complete_or_fail_a_reclaimed_delivery() {
    let _claim_guard = BACKCHANNEL_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = AuditRepository::new(create_pool(&database_url, 4).unwrap());
    let logout_token = format!("logout-reclaim-token-{}", Uuid::now_v7());
    repository
        .enqueue_backchannel_logout(
            tenant_id,
            fixture.client_id,
            &format!("logout-reclaim-{}", Uuid::now_v7()),
            "https://client.example/backchannel-logout",
            &logout_token,
            chrono::Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("delivery should enqueue");
    let first = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("first worker should claim")
        .into_iter()
        .find(|delivery| delivery.logout_token == logout_token)
        .expect("delivery should be due");
    assert_eq!(first.attempts, 1);

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(
        "UPDATE backchannel_logout_deliveries SET locked_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind::<SqlUuid, _>(first.id)
    .execute(&mut connection)
    .await
    .expect("test should expire first claim");
    let second = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("second worker should reclaim")
        .into_iter()
        .find(|delivery| delivery.id == first.id)
        .expect("expired delivery should reclaim");
    assert_eq!(second.id, first.id);
    assert_eq!(second.attempts, 2);

    let stale_complete = repository
        .complete_backchannel_logout(first.id, first.attempts)
        .await;
    assert!(
        matches!(
            stale_complete,
            Err(nazo_identity::ports::RepositoryError::Consistency(_))
        ),
        "first worker completion must be rejected after reclaim"
    );
    let stale_fail = repository
        .fail_backchannel_logout(
            first.id,
            first.attempts,
            Some(chrono::Utc::now() + chrono::Duration::seconds(5)),
            "stale failure",
        )
        .await;
    assert!(
        matches!(
            stale_fail,
            Err(nazo_identity::ports::RepositoryError::Consistency(_))
        ),
        "first worker failure must be rejected after reclaim"
    );

    repository
        .complete_backchannel_logout(second.id, second.attempts)
        .await
        .expect("current worker should complete");
    let stale_after_terminal = repository
        .fail_backchannel_logout(first.id, first.attempts, None, "late stale failure")
        .await;
    assert!(
        matches!(
            stale_after_terminal,
            Err(nazo_identity::ports::RepositoryError::Consistency(_))
        ),
        "stale worker must not overwrite terminal state"
    );
}
