use chrono::{Duration, Utc};
use diesel::{QueryableByName, sql_query, sql_types::Text};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_identity::ports::PasswordHashInput;
use nazo_postgres::{
    InitialAdminBootstrapRepository, InitialAdminBootstrapState, InitialAdminClaimOutcome,
    create_pool, run_pending_migrations,
};
use uuid::Uuid;

#[derive(QueryableByName)]
struct AdminRoleRow {
    #[diesel(sql_type = Text)]
    role: String,
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

fn schema_database_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

#[tokio::test]
async fn initial_admin_claim_has_one_concurrent_winner_and_closes_permanently() {
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
    run_pending_migrations(&isolated_url)
        .await
        .expect("isolated schema migrations should apply");
    let repository = InitialAdminBootstrapRepository::new(
        create_pool(isolated_url.clone(), 4).expect("pool should create"),
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
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, InitialAdminClaimOutcome::Closed))
            .count(),
        1
    );
    assert_eq!(
        repository
            .ensure_claim(&"b".repeat(64), Utc::now() + Duration::minutes(30))
            .await
            .unwrap(),
        InitialAdminBootstrapState::Closed
    );

    let mut isolated = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    let admins = sql_query("SELECT role FROM users WHERE role = 'admin'")
        .load::<AdminRoleRow>(&mut isolated)
        .await
        .unwrap();
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0].role, "admin");

    coordinator
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE;"))
        .await
        .expect("isolated schema should drop");
}
