use diesel::{QueryableByName, sql_query};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};
use nazo_identity::{TenantContext, ports::PasswordHashInput};
use nazo_postgres::{
    AdminProvisionError, AdminProvisionRepository, AdminProvisionRequest, create_pool,
};
use uuid::Uuid;

mod support;

use support::{run_isolated_application_migrations, schema_database_url};

#[derive(QueryableByName)]
struct UserState {
    #[diesel(sql_type = diesel::sql_types::Text)]
    role: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    admin_level: i32,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    email_verified: bool,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI admin-provision tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn request(operation_id: &str, email: &str) -> AdminProvisionRequest {
    AdminProvisionRequest {
        tenant: TenantContext::default_system(),
        operation_id: operation_id.to_owned(),
        deployment_id: "deployment-test".to_owned(),
        email: email.to_owned(),
        password_hash: PasswordHashInput::new("provisioned-password-hash").unwrap(),
    }
}

async fn isolated_repository() -> Option<(AdminProvisionRepository, String)> {
    let database_url = database_url()?;
    let schema = format!("admin_provision_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .expect("isolated schema should create");
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    Some((
        AdminProvisionRepository::new(
            create_pool(isolated_url.clone(), 4).expect("pool should create"),
        ),
        isolated_url,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_is_atomic_and_retries_return_the_same_receipt() {
    let Some((repository, isolated_url)) = isolated_repository().await else {
        return;
    };
    let first = repository
        .provision(request("admin-provision-1", "Admin@Example.COM"))
        .await
        .unwrap();
    let retry = repository
        .provision(request("admin-provision-1", "admin@example.com"))
        .await
        .unwrap();
    assert_eq!(first, retry);

    let mut connection = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    let user = sql_query(
        "SELECT role, admin_level, email_verified
         FROM users WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(first.user_id)
    .get_result::<UserState>(&mut connection)
    .await
    .unwrap();
    assert_eq!(user.role, "admin");
    assert_eq!(user.admin_level, 1);
    assert!(user.email_verified);
    for (table, predicate) in [
        (
            "admin_provision_receipts",
            "operation_id = 'admin-provision-1'",
        ),
        (
            "identity_security_events",
            "request_id = 'admin-provision-1' AND event_type = 'admin_user_created'",
        ),
    ] {
        let row = sql_query(format!(
            "SELECT count(*)::bigint AS count FROM {table} WHERE {predicate}"
        ))
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
        assert_eq!(row.count, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operation_and_email_conflicts_are_rejected() {
    let Some((repository, _isolated_url)) = isolated_repository().await else {
        return;
    };
    repository
        .provision(request("admin-provision-2", "one@example.com"))
        .await
        .unwrap();
    assert_eq!(
        repository
            .provision(request("admin-provision-2", "two@example.com"))
            .await
            .unwrap_err(),
        AdminProvisionError::OperationConflict
    );
    assert_eq!(
        repository
            .provision(request("admin-provision-3", "ONE@example.com"))
            .await
            .unwrap_err(),
        AdminProvisionError::EmailConflict
    );
}
