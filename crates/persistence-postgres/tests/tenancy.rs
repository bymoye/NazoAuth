use diesel::{sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId};
use nazo_postgres::{
    ActiveTenantBoundaryRepository, TenantDirectoryRepository, create_pool, get_conn,
};
use uuid::Uuid;

mod support;

use support::{run_isolated_application_migrations, schema_database_url};

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI active-tenant tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn context(tenant_id: Uuid, realm_id: Uuid, organization_id: Uuid) -> TenantContext {
    TenantContext {
        tenant_id: TenantId::new(tenant_id).expect("tenant id is non-nil"),
        realm_id: RealmId::new(realm_id).expect("realm id is non-nil"),
        organization_id: OrganizationId::new(organization_id).expect("organization id is non-nil"),
    }
}

async fn insert_tenant(connection: &mut nazo_postgres::DbConnection, tenant_id: Uuid, slug: &str) {
    sql_query("INSERT INTO tenants (id, slug, display_name, status) VALUES ($1, $2, $3, 'active')")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Text, _>(slug)
        .bind::<sql_types::Text, _>(format!("{slug} display"))
        .execute(connection)
        .await
        .expect("foreign tenant can be inserted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_tenant_boundary_preflight_is_fail_closed() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("tenancy_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .expect("isolated schema should create");
    drop(coordinator);

    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    let pool = create_pool(isolated_url, 4).expect("pool should create");
    let repository = ActiveTenantBoundaryRepository::new(pool.clone());
    let directory = TenantDirectoryRepository::new(pool.clone());
    let active = TenantContext::default_system();

    repository
        .preflight(active)
        .await
        .expect("default active boundary should pass");

    let mut connection = get_conn(&pool)
        .await
        .expect("pool should provide connection");
    sql_query(
        "INSERT INTO tenant_runtime_bindings
            (tenant_id, realm_id, organization_id, issuer, external_host)
         VALUES ($1, $2, $3, 'https://auth.example', 'auth.example')",
    )
    .bind::<sql_types::Uuid, _>(active.tenant_id.as_uuid())
    .bind::<sql_types::Uuid, _>(active.realm_id.as_uuid())
    .bind::<sql_types::Uuid, _>(active.organization_id.as_uuid())
    .execute(&mut connection)
    .await
    .expect("active tenant directory binding should insert");
    let initial_directory = directory
        .load_active()
        .await
        .expect("active directory should load");
    assert_eq!(initial_directory.revision, 1);
    assert_eq!(initial_directory.tenants.len(), 1);
    assert_eq!(initial_directory.tenants[0].tenant, active);
    assert_eq!(
        directory
            .current_revision()
            .await
            .expect("directory revision should load"),
        initial_directory.revision
    );

    sql_query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind::<sql_types::Uuid, _>(active.tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .expect("tenant status should update");
    drop(connection);
    assert!(matches!(
        repository.preflight(active).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));
    let suspended_directory = directory
        .load_active()
        .await
        .expect("suspended directory should load");
    assert_eq!(suspended_directory.revision, 2);
    assert!(suspended_directory.tenants.is_empty());

    let mut connection = get_conn(&pool)
        .await
        .expect("pool should provide connection");
    sql_query("UPDATE tenants SET status = 'active' WHERE id = $1")
        .bind::<sql_types::Uuid, _>(active.tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .expect("tenant status should restore");
    let restored_directory = directory
        .load_active()
        .await
        .expect("restored directory should load");
    assert_eq!(restored_directory.revision, 3);
    assert_eq!(restored_directory.tenants.len(), 1);

    let foreign_realm_tenant = Uuid::now_v7();
    let foreign_realm = Uuid::now_v7();
    insert_tenant(
        &mut connection,
        foreign_realm_tenant,
        &format!("foreign-realm-{}", foreign_realm.simple()),
    )
    .await;
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'default', 'Foreign realm', 'active')",
    )
    .bind::<sql_types::Uuid, _>(foreign_realm)
    .bind::<sql_types::Uuid, _>(foreign_realm_tenant)
    .execute(&mut connection)
    .await
    .expect("foreign realm can be inserted");
    drop(connection);
    let realm_mismatch = context(
        active.tenant_id.as_uuid(),
        foreign_realm,
        active.organization_id.as_uuid(),
    );
    assert!(matches!(
        repository.preflight(realm_mismatch).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));

    let mut connection = get_conn(&pool)
        .await
        .expect("pool should provide connection");
    let foreign_organization_tenant = Uuid::now_v7();
    let foreign_organization = Uuid::now_v7();
    insert_tenant(
        &mut connection,
        foreign_organization_tenant,
        &format!("foreign-organization-{}", foreign_organization.simple()),
    )
    .await;
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name, status)
         VALUES ($1, $2, 'default', 'Foreign organization', 'active')",
    )
    .bind::<sql_types::Uuid, _>(foreign_organization)
    .bind::<sql_types::Uuid, _>(foreign_organization_tenant)
    .execute(&mut connection)
    .await
    .expect("foreign organization can be inserted");
    drop(connection);
    let organization_mismatch = context(
        active.tenant_id.as_uuid(),
        active.realm_id.as_uuid(),
        foreign_organization,
    );
    assert!(matches!(
        repository.preflight(organization_mismatch).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));

    drop(repository);
    drop(pool);
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("database should accept cleanup connection");
    coordinator
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("isolated schema should be removed");
}
