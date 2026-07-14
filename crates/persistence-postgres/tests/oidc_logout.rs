use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::IdempotentBackchannelLogoutDelivery;
use nazo_postgres::{AuditRepository, OAuthClientRepository, create_pool};
use uuid::Uuid;

const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);
const DEFAULT_REALM_ID: Uuid = Uuid::from_u128(2);
const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(3);

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI OIDC logout repository tests require a PostgreSQL URL");
    }
    url
}

async fn insert_user(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    suffix: &str,
) -> Uuid {
    sql_query(
        "INSERT INTO users (tenant_id, realm_id, organization_id, username, email, password_hash) \
         VALUES ($1, $2, $3, $4, $5, 'test-only-hash') RETURNING id",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(format!("logout-{suffix}"))
    .bind::<Text, _>(format!("logout-{suffix}@example.test"))
    .get_result::<IdRow>(connection)
    .await
    .expect("logout user fixture should insert")
    .id
}

async fn insert_client(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    suffix: &str,
    active: bool,
) -> Uuid {
    sql_query(
        "INSERT INTO oauth_clients (\
             tenant_id, realm_id, organization_id, client_id, client_name, client_type,\
             redirect_uris, scopes, grant_types, token_endpoint_auth_method, is_active,\
             backchannel_logout_uri\
         ) VALUES (\
             $1, $2, $3, $4, 'OIDC Logout Contract', 'confidential',\
             '[\"https://client.example/callback\"]'::jsonb, '[\"openid\"]'::jsonb,\
             '[\"authorization_code\"]'::jsonb, 'client_secret_basic', $5,\
             'https://client.example/backchannel-logout'\
         ) RETURNING id",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(format!("logout-client-{suffix}"))
    .bind::<diesel::sql_types::Bool, _>(active)
    .get_result::<IdRow>(connection)
    .await
    .expect("logout client fixture should insert")
    .id
}

async fn insert_grant(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
) {
    sql_query(
        "INSERT INTO user_client_grants (\
             tenant_id, user_id, client_id, first_authorized_at, last_authorized_at,\
             last_scopes, last_resource_indicators, last_authorization_details, authorization_count\
         ) VALUES (\
             $1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '[\"openid\"]'::jsonb,\
             '[]'::jsonb, '[]'::jsonb, 1\
         )",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(client_id)
    .execute(connection)
    .await
    .expect("logout grant fixture should insert");
}

#[tokio::test]
async fn logout_fanout_is_tenant_scoped_idempotent_and_atomic() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("logout migration should apply");
    let pool = create_pool(&database_url, 4).expect("logout pool should create");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("logout test database should connect");
    let suffix = Uuid::now_v7().simple().to_string();
    let local_user = insert_user(
        &mut connection,
        DEFAULT_TENANT_ID,
        DEFAULT_REALM_ID,
        DEFAULT_ORGANIZATION_ID,
        &suffix,
    )
    .await;
    let local_client = insert_client(
        &mut connection,
        DEFAULT_TENANT_ID,
        DEFAULT_REALM_ID,
        DEFAULT_ORGANIZATION_ID,
        &format!("{suffix}-active"),
        true,
    )
    .await;
    let inactive_client = insert_client(
        &mut connection,
        DEFAULT_TENANT_ID,
        DEFAULT_REALM_ID,
        DEFAULT_ORGANIZATION_ID,
        &format!("{suffix}-inactive"),
        false,
    )
    .await;
    insert_grant(&mut connection, DEFAULT_TENANT_ID, local_user, local_client).await;
    insert_grant(
        &mut connection,
        DEFAULT_TENANT_ID,
        local_user,
        inactive_client,
    )
    .await;

    let foreign_tenant = Uuid::now_v7();
    let foreign_realm = Uuid::now_v7();
    let foreign_organization = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Logout foreign')")
        .bind::<SqlUuid, _>(foreign_tenant)
        .bind::<Text, _>(format!("logout-{suffix}"))
        .execute(&mut connection)
        .await
        .expect("foreign tenant should insert");
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name) \
         VALUES ($1, $2, 'default', 'Logout foreign realm')",
    )
    .bind::<SqlUuid, _>(foreign_realm)
    .bind::<SqlUuid, _>(foreign_tenant)
    .execute(&mut connection)
    .await
    .expect("foreign realm should insert");
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name) \
         VALUES ($1, $2, 'default', 'Logout foreign organization')",
    )
    .bind::<SqlUuid, _>(foreign_organization)
    .bind::<SqlUuid, _>(foreign_tenant)
    .execute(&mut connection)
    .await
    .expect("foreign organization should insert");
    let foreign_user = insert_user(
        &mut connection,
        foreign_tenant,
        foreign_realm,
        foreign_organization,
        &format!("{suffix}-foreign"),
    )
    .await;
    let foreign_client = insert_client(
        &mut connection,
        foreign_tenant,
        foreign_realm,
        foreign_organization,
        &format!("{suffix}-foreign"),
        true,
    )
    .await;
    insert_grant(
        &mut connection,
        foreign_tenant,
        foreign_user,
        foreign_client,
    )
    .await;

    let clients = OAuthClientRepository::new(pool.clone())
        .active_for_tenant_user(DEFAULT_TENANT_ID, local_user)
        .await
        .expect("tenant-scoped logout clients should load");
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].id, local_client);

    let outbox = AuditRepository::new(pool);
    let operation_key = format!("logout-operation-{suffix}");
    let delivery = IdempotentBackchannelLogoutDelivery {
        operation_key: operation_key.clone(),
        tenant_id: DEFAULT_TENANT_ID,
        client_id: local_client,
        client_public_id: format!("logout-client-{suffix}-active"),
        logout_uri: "https://client.example/backchannel-logout".to_owned(),
        logout_token: format!("logout-token-{suffix}"),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(2),
    };
    outbox
        .enqueue_idempotent_backchannel_logout_batch(std::slice::from_ref(&delivery))
        .await
        .expect("first logout operation should enqueue");
    outbox
        .enqueue_idempotent_backchannel_logout_batch(std::slice::from_ref(&delivery))
        .await
        .expect("retrying a committed logout operation should be idempotent");

    let count = sql_query(
        "SELECT COUNT(*) AS count FROM backchannel_logout_deliveries WHERE operation_key = $1",
    )
    .bind::<Text, _>(&operation_key)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("idempotent logout count should load");
    assert_eq!(count.count, 1);

    let rollback_key = format!("logout-rollback-{suffix}");
    let mut valid = delivery;
    valid.operation_key.clone_from(&rollback_key);
    valid.logout_token = format!("logout-rollback-token-{suffix}");
    let mut invalid = valid.clone();
    invalid.client_id = Uuid::now_v7();
    invalid.client_public_id = "missing-client".to_owned();
    assert!(
        outbox
            .enqueue_idempotent_backchannel_logout_batch(&[valid, invalid])
            .await
            .is_err(),
        "an invalid delivery must roll back the complete fan-out"
    );
    let rollback_count = sql_query(
        "SELECT COUNT(*) AS count FROM backchannel_logout_deliveries WHERE operation_key = $1",
    )
    .bind::<Text, _>(&rollback_key)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("rollback count should load");
    assert_eq!(rollback_count.count, 0);
}
