use diesel::{sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId};
use nazo_postgres::{
    ActiveTenantBoundaryRepository, TenantDirectoryRepository, create_pool, get_conn,
};
use uuid::Uuid;

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
    let database_name = format!("tenancy_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database_name}\";"))
        .await
        .expect("isolated database should create");
    drop(coordinator);

    let mut isolated_url = url::Url::parse(&database_url).expect("test database URL is valid");
    isolated_url.set_path(&format!("/{database_name}"));
    let isolated_url = isolated_url.to_string();
    nazo_postgres::run_pending_migrations(&isolated_url)
        .await
        .expect("isolated database migrations should apply");
    let pool = create_pool(isolated_url, 4).expect("pool should create");
    let repository = ActiveTenantBoundaryRepository::new(pool.clone());
    let directory = TenantDirectoryRepository::new(pool.clone());
    let active = TenantContext::default_system();

    repository
        .preflight(active)
        .await
        .expect("default active boundary should pass");
    let fresh_directory = directory
        .load_active()
        .await
        .expect("fresh directory should load");
    assert_eq!(fresh_directory.revision, 0);
    assert!(fresh_directory.tenants.is_empty());

    let initial_binding = nazo_identity::TenantDirectoryBinding {
        tenant: active,
        runtime_revision: 1,
        issuer: "https://auth.example".to_owned(),
        external_host: "auth.example".to_owned(),
    };
    let first_directory = directory.clone();
    let second_directory = directory.clone();
    let (first, second) = tokio::join!(
        first_directory.initialize(initial_binding.clone()),
        second_directory.initialize(initial_binding)
    );
    let mut outcomes = [
        first.expect("first concurrent initialization should succeed"),
        second.expect("second concurrent initialization should succeed"),
    ];
    outcomes.sort_unstable();
    assert_eq!(outcomes, [false, true]);
    let conflicting = nazo_identity::TenantDirectoryBinding {
        tenant: active,
        runtime_revision: 1,
        issuer: "https://other.example".to_owned(),
        external_host: "other.example".to_owned(),
    };
    assert!(matches!(
        directory.initialize(conflicting).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));
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

    let mut connection = get_conn(&pool)
        .await
        .expect("pool should provide connection");
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
        .batch_execute(&format!("DROP DATABASE \"{database_name}\" WITH (FORCE);"))
        .await
        .expect("isolated database should be removed");
}
