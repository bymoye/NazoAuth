use chrono::{Duration, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as DieselUuid},
};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId, ports::PasswordHashInput};
use nazo_postgres::{
    InitialAdminBootstrapRepository, InitialAdminBootstrapState, InitialAdminClaimOutcome,
    create_pool,
};
use uuid::Uuid;

mod support;

use support::{run_isolated_application_migrations, schema_database_url};

const RECEIPT_MIGRATION_UP: &str =
    include_str!("../../../migrations/20260801000100_initial_admin_bootstrap_receipt/up.sql");
const RECEIPT_MIGRATION_DOWN: &str =
    include_str!("../../../migrations/20260801000100_initial_admin_bootstrap_receipt/down.sql");

#[derive(QueryableByName)]
struct AdminRoleRow {
    #[diesel(sql_type = Text)]
    role: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct TenantAssignmentRow {
    #[diesel(sql_type = DieselUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = DieselUuid)]
    realm_id: Uuid,
    #[diesel(sql_type = DieselUuid)]
    organization_id: Uuid,
}

#[derive(QueryableByName)]
struct TenantRow {
    #[diesel(sql_type = DieselUuid)]
    tenant_id: Uuid,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI initial-admin tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_admin_claim_has_one_concurrent_winner_and_idempotent_receipt() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("initial_admin_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .expect("isolated schema should create");
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    let repository = InitialAdminBootstrapRepository::new(
        create_pool(isolated_url.clone(), 4).expect("pool should create"),
        TenantContext::default_system(),
    );
    let token_hash = "a".repeat(64);
    assert!(matches!(
        repository
            .ensure_claim(&token_hash, Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::Ready { .. }
    ));
    assert!(matches!(
        repository
            .ensure_claim(&"b".repeat(64), Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::OwnedByAnotherInstance { .. }
    ));

    let first = {
        let repository = repository.clone();
        let token_hash = token_hash.clone();
        tokio::spawn(async move {
            repository
                .claim(
                    "bootstrap-admin-11111111111111111111111111111111",
                    &token_hash,
                    "first-admin@example.com",
                    PasswordHashInput::new("first-password-hash").unwrap(),
                )
                .await
                .unwrap()
        })
    };
    let second = {
        let repository = repository.clone();
        let token_hash = token_hash.clone();
        tokio::spawn(async move {
            repository
                .claim(
                    "bootstrap-admin-22222222222222222222222222222222",
                    &token_hash,
                    "second-admin@example.com",
                    PasswordHashInput::new("second-password-hash").unwrap(),
                )
                .await
                .unwrap()
        })
    };
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, InitialAdminClaimOutcome::Created { .. }))
            .count(),
        1
    );
    let (winning_request_id, winning_id, winning_email) = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            InitialAdminClaimOutcome::Created {
                request_id,
                id,
                email,
            } => Some((request_id.clone(), *id, email.clone())),
            _ => None,
        })
        .unwrap();
    let restarted = InitialAdminBootstrapRepository::new(
        create_pool(isolated_url.clone(), 2).expect("restart pool should create"),
        TenantContext::default_system(),
    );
    assert_eq!(
        restarted
            .claim(
                &winning_request_id,
                &token_hash,
                &winning_email,
                PasswordHashInput::new("retry-password-hash").unwrap(),
            )
            .await
            .unwrap(),
        InitialAdminClaimOutcome::Created {
            request_id: winning_request_id.clone(),
            id: winning_id,
            email: winning_email.clone(),
        }
    );
    let replay_one = restarted.claim(
        &winning_request_id,
        &token_hash,
        &winning_email,
        PasswordHashInput::new("retry-one-password-hash").unwrap(),
    );
    let replay_two = restarted.claim(
        &winning_request_id,
        &token_hash,
        &winning_email,
        PasswordHashInput::new("retry-two-password-hash").unwrap(),
    );
    let (replay_one, replay_two) = tokio::join!(replay_one, replay_two);
    assert_eq!(replay_one.unwrap(), replay_two.unwrap());

    let mut isolated = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    sql_query(
        "UPDATE initial_admin_bootstrap
         SET created_at = now() - interval '2 minutes',
             expires_at = now() - interval '1 minute'",
    )
    .execute(&mut isolated)
    .await
    .unwrap();
    sql_query("UPDATE users SET email = 'renamed@example.com' WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(winning_id)
        .execute(&mut isolated)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .claim(
                &winning_request_id,
                &token_hash,
                &winning_email,
                PasswordHashInput::new("expired-replay-password-hash").unwrap(),
            )
            .await
            .unwrap(),
        InitialAdminClaimOutcome::Created {
            request_id: winning_request_id.clone(),
            id: winning_id,
            email: winning_email.clone(),
        }
    );
    assert_eq!(
        restarted
            .claim(
                "bootstrap-admin-33333333333333333333333333333333",
                &token_hash,
                &winning_email,
                PasswordHashInput::new("conflict-password-hash").unwrap(),
            )
            .await
            .unwrap(),
        InitialAdminClaimOutcome::IdempotencyConflict
    );
    assert_eq!(
        restarted
            .claim(
                &winning_request_id,
                &token_hash,
                "different@example.com",
                PasswordHashInput::new("conflict-password-hash").unwrap(),
            )
            .await
            .unwrap(),
        InitialAdminClaimOutcome::IdempotencyConflict
    );
    assert_eq!(
        restarted
            .claim(
                &winning_request_id,
                &"c".repeat(64),
                &winning_email,
                PasswordHashInput::new("conflict-password-hash").unwrap(),
            )
            .await
            .unwrap(),
        InitialAdminClaimOutcome::InvalidOrExpired
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, InitialAdminClaimOutcome::IdempotencyConflict))
            .count(),
        1
    );
    assert!(matches!(
        repository
            .ensure_claim(&"b".repeat(64), Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::Claimed {
            expected_token_hash,
            ..
        } if expected_token_hash == token_hash
    ));

    let admins = sql_query("SELECT role FROM users WHERE role = 'admin'")
        .load::<AdminRoleRow>(&mut isolated)
        .await
        .unwrap();
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].role, "admin");
    let assignment =
        sql_query("SELECT tenant_id, realm_id, organization_id FROM users WHERE id = $1")
            .bind::<DieselUuid, _>(winning_id)
            .get_result::<TenantAssignmentRow>(&mut isolated)
            .await
            .unwrap();
    let default_tenant = TenantContext::default_system();
    assert_eq!(
        (
            assignment.tenant_id,
            assignment.realm_id,
            assignment.organization_id,
        ),
        (
            default_tenant.tenant_id.as_uuid(),
            default_tenant.realm_id.as_uuid(),
            default_tenant.organization_id.as_uuid(),
        )
    );
    let audit_count = sql_query(
        "SELECT count(*)::bigint AS count FROM identity_security_events WHERE event_type = 'initial_admin_bootstrap'",
    )
    .get_result::<CountRow>(&mut isolated)
    .await
    .unwrap();
    assert_eq!(audit_count.count, 1);
    let downgrade_error = isolated
        .batch_execute(RECEIPT_MIGRATION_DOWN)
        .await
        .unwrap_err();
    assert!(
        downgrade_error
            .to_string()
            .contains("cannot remove initial administrator receipts or audit evidence")
    );

    coordinator
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE;"))
        .await
        .expect("isolated schema should drop");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_admin_claim_respects_explicit_non_default_tenant_context() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("initial_admin_tenant_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .unwrap();
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    let mut isolated = AsyncPgConnection::establish(&isolated_url).await.unwrap();

    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let tenant = TenantContext {
        tenant_id: TenantId::new(tenant_id).unwrap(),
        realm_id: RealmId::new(realm_id).unwrap(),
        organization_id: OrganizationId::new(organization_id).unwrap(),
    };
    sql_query("INSERT INTO tenants (id, slug, display_name, status) VALUES ($1, $2, $3, 'active')")
        .bind::<DieselUuid, _>(tenant_id)
        .bind::<Text, _>(format!("tenant-{}", tenant_id.simple()))
        .bind::<Text, _>("Contract tenant")
        .execute(&mut isolated)
        .await
        .unwrap();
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'contract', 'Contract realm', 'active')",
    )
    .bind::<DieselUuid, _>(realm_id)
    .bind::<DieselUuid, _>(tenant_id)
    .execute(&mut isolated)
    .await
    .unwrap();
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'contract', 'Contract organization', 'active')",
    )
    .bind::<DieselUuid, _>(organization_id)
    .bind::<DieselUuid, _>(tenant_id)
    .execute(&mut isolated)
    .await
    .unwrap();

    let repository =
        InitialAdminBootstrapRepository::new(create_pool(isolated_url.clone(), 2).unwrap(), tenant);
    let token_hash = "f".repeat(64);
    assert!(matches!(
        repository
            .ensure_claim(&token_hash, Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::Ready { .. }
    ));
    let outcome = repository
        .claim(
            "bootstrap-admin-ffffffffffffffffffffffffffffffff",
            &token_hash,
            "tenant-admin@example.com",
            PasswordHashInput::new("tenant-password-hash").unwrap(),
        )
        .await
        .unwrap();
    let InitialAdminClaimOutcome::Created { id, .. } = outcome else {
        panic!("explicit tenant context must permit its own initial admin claim");
    };

    let assignment =
        sql_query("SELECT tenant_id, realm_id, organization_id FROM users WHERE id = $1")
            .bind::<DieselUuid, _>(id)
            .get_result::<TenantAssignmentRow>(&mut isolated)
            .await
            .unwrap();
    assert_eq!(
        (
            assignment.tenant_id,
            assignment.realm_id,
            assignment.organization_id,
        ),
        (tenant_id, realm_id, organization_id)
    );
    let audit = sql_query(
        "SELECT tenant_id
         FROM identity_security_events
         WHERE request_id = 'bootstrap-admin-ffffffffffffffffffffffffffffffff'
           AND event_type = 'initial_admin_bootstrap'",
    )
    .get_result::<TenantRow>(&mut isolated)
    .await
    .unwrap();
    assert_eq!(audit.tenant_id, tenant_id);
    let default_admins = sql_query(
        "SELECT count(*)::bigint AS count FROM users WHERE tenant_id = $1 AND role = 'admin'",
    )
    .bind::<DieselUuid, _>(TenantContext::default_system().tenant_id.as_uuid())
    .get_result::<CountRow>(&mut isolated)
    .await
    .unwrap();
    assert_eq!(default_admins.count, 0);

    coordinator
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE;"))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_consumed_claim_is_closed_without_becoming_replayable() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("initial_admin_legacy_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .unwrap();
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    let repository = InitialAdminBootstrapRepository::new(
        create_pool(isolated_url.clone(), 2).unwrap(),
        TenantContext::default_system(),
    );
    let mut isolated = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    sql_query(
        "INSERT INTO initial_admin_bootstrap
         (singleton, token_hash, expires_at, consumed_at, created_at, updated_at)
         VALUES (true, $1, now() + interval '30 minutes', now(), now(), now())",
    )
    .bind::<Text, _>("e".repeat(64))
    .execute(&mut isolated)
    .await
    .unwrap();

    assert_eq!(
        repository
            .ensure_claim(&"f".repeat(64), Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::Closed
    );
    isolated
        .batch_execute(RECEIPT_MIGRATION_DOWN)
        .await
        .unwrap();
    isolated.batch_execute(RECEIPT_MIGRATION_UP).await.unwrap();
    assert_eq!(
        repository
            .ensure_claim(&"f".repeat(64), Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::Closed
    );

    coordinator
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE;"))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_audit_failure_rolls_back_user_receipt_and_consumption() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("initial_admin_audit_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .unwrap();
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    let repository = InitialAdminBootstrapRepository::new(
        create_pool(isolated_url.clone(), 2).unwrap(),
        TenantContext::default_system(),
    );
    let token_hash = "d".repeat(64);
    repository
        .ensure_claim(&token_hash, Utc::now() + Duration::minutes(30))
        .await
        .unwrap();

    let mut isolated = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    isolated
        .batch_execute(
            "CREATE FUNCTION fail_initial_admin_audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
               IF NEW.event_type = 'initial_admin_bootstrap' THEN
                 RAISE EXCEPTION 'forced bootstrap audit failure';
               END IF;
               RETURN NEW;
             END $$;
             CREATE TRIGGER fail_initial_admin_audit
             BEFORE INSERT ON identity_security_events
             FOR EACH ROW EXECUTE FUNCTION fail_initial_admin_audit();",
        )
        .await
        .unwrap();

    assert!(
        repository
            .claim(
                "bootstrap-admin-44444444444444444444444444444444",
                &token_hash,
                "rollback@example.com",
                PasswordHashInput::new("rollback-password-hash").unwrap(),
            )
            .await
            .is_err()
    );
    let users = sql_query("SELECT count(*)::bigint AS count FROM users WHERE role = 'admin'")
        .get_result::<CountRow>(&mut isolated)
        .await
        .unwrap();
    assert_eq!(users.count, 0);
    let consumed = sql_query(
        "SELECT count(*)::bigint AS count FROM initial_admin_bootstrap WHERE consumed_at IS NOT NULL OR request_id IS NOT NULL",
    )
    .get_result::<CountRow>(&mut isolated)
    .await
    .unwrap();
    assert_eq!(consumed.count, 0);

    isolated
        .batch_execute("DROP TRIGGER fail_initial_admin_audit ON identity_security_events; DROP FUNCTION fail_initial_admin_audit();")
        .await
        .unwrap();
    assert!(matches!(
        repository
            .claim(
                "bootstrap-admin-44444444444444444444444444444444",
                &token_hash,
                "rollback@example.com",
                PasswordHashInput::new("rollback-password-hash").unwrap(),
            )
            .await
            .unwrap(),
        InitialAdminClaimOutcome::Created { .. }
    ));

    coordinator
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE;"))
        .await
        .unwrap();
}
