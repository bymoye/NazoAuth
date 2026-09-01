//! Revision-fenced tenant directory mutation contract, exercised against a
//! real PostgreSQL database. Every test runs on an isolated database with the
//! full migration chain applied, so trigger and constraint behavior is the
//! production behavior.

use diesel::{sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantId,
    ports::RepositoryError,
};
use nazo_postgres::{
    RuntimeModuleRepository, TenantBoundaryDefinition, TenantDirectoryRepository,
    TenantProvisioningRequest, TenantRuntimeStatus, create_pool, run_pending_migrations,
};
use nazo_runtime_modules::{DesiredMode, ModuleId, ModuleStateRepository as _};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI tenant directory tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

struct IsolatedDirectory {
    pool: nazo_postgres::DbPool,
    repository: TenantDirectoryRepository,
}

async fn isolated_directory() -> Option<IsolatedDirectory> {
    let database_url = database_url()?;
    let database_name = format!("tenant_directory_{}", Uuid::now_v7().simple());
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
    run_pending_migrations(&isolated_url)
        .await
        .expect("isolated database migrations should apply");
    let pool = create_pool(isolated_url, 4).expect("pool should create");
    let repository = TenantDirectoryRepository::new(pool.clone());
    Some(IsolatedDirectory { pool, repository })
}

fn boundary_definition<Id>(id: Id, slug: &str) -> TenantBoundaryDefinition<Id> {
    TenantBoundaryDefinition {
        id,
        slug: slug.to_owned(),
        display_name: format!("{slug} display"),
    }
}

/// A complete provisioning request at directory revision `expected_revision`.
fn provisioning_request(
    expected_revision: u64,
    slug: &str,
    host: &str,
) -> (u64, TenantProvisioningRequest) {
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is non-nil");
    let realm_id = RealmId::new(Uuid::now_v7()).expect("realm id is non-nil");
    let organization_id = OrganizationId::new(Uuid::now_v7()).expect("organization id is non-nil");
    let request = TenantProvisioningRequest {
        tenant: boundary_definition(tenant_id, slug),
        realm: boundary_definition(realm_id, &format!("{slug}-realm")),
        organization: boundary_definition(organization_id, &format!("{slug}-org")),
        binding: TenantDirectoryBinding {
            tenant: TenantContext {
                tenant_id,
                realm_id,
                organization_id,
            },
            runtime_revision: 1,
            issuer: format!("https://{host}"),
            external_host: host.to_owned(),
        },
    };
    (expected_revision, request)
}

async fn current_revision(repository: &TenantDirectoryRepository) -> u64 {
    repository
        .current_revision()
        .await
        .expect("directory revision should read")
}

#[derive(Debug, diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_seeds_full_tenant_capabilities_without_overwriting_switches_on_replay() {
    let Some(IsolatedDirectory { pool, repository }) = isolated_directory().await else {
        return;
    };
    let (_, request) = provisioning_request(0, "capabilities", "capabilities.example");
    let tenant_id = request.tenant.id.as_uuid();
    let revision = repository
        .provision_tenant_binding(0, request.clone())
        .await
        .expect("tenant provisioning should apply");
    let (_, peer_request) = provisioning_request(0, "peer", "peer.example");
    let peer_tenant_id = peer_request.tenant.id.as_uuid();
    let revision = repository
        .provision_tenant_binding(revision, peer_request)
        .await
        .expect("peer tenant provisioning should apply");
    let mut connection = pool.get().await.expect("pool should connect");
    let enabled = sql_query(
        "SELECT COUNT(*) AS count FROM runtime_module_desired_states \
         WHERE tenant_id = $1 AND desired_mode = 'enabled'",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("tenant runtime capability baseline should load");
    assert_eq!(enabled.count, 16);

    sql_query(
        "UPDATE runtime_module_desired_states SET desired_mode = 'disabled', revision = revision + 1 \
         WHERE tenant_id = $1 AND module_id = 'dynamic_client_registration'",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .execute(&mut connection)
    .await
    .expect("tenant capability switch should update");
    drop(connection);

    let tenant_modules = RuntimeModuleRepository::for_tenant(pool.clone(), tenant_id);
    let peer_modules = RuntimeModuleRepository::for_tenant(pool.clone(), peer_tenant_id);
    assert_eq!(
        tenant_modules
            .read_desired(ModuleId::DynamicClientRegistration)
            .await
            .expect("tenant capability should load")
            .expect("tenant capability baseline should exist")
            .mode,
        DesiredMode::Disabled
    );
    assert_eq!(
        peer_modules
            .read_desired(ModuleId::DynamicClientRegistration)
            .await
            .expect("peer capability should load")
            .expect("peer capability baseline should exist")
            .mode,
        DesiredMode::Enabled
    );

    repository
        .provision_tenant_binding(revision, request)
        .await
        .expect("identical provisioning replay should succeed");
    let mut connection = pool.get().await.expect("pool should connect");
    let disabled = sql_query(
        "SELECT COUNT(*) AS count FROM runtime_module_desired_states \
         WHERE tenant_id = $1 AND module_id = 'dynamic_client_registration' \
           AND desired_mode = 'disabled'",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("tenant capability switch should load");
    assert_eq!(disabled.count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provision_advances_revision_and_replays_idempotently() {
    let Some(IsolatedDirectory { repository, .. }) = isolated_directory().await else {
        return;
    };
    let (expected, request) = provisioning_request(0, "alpha", "alpha.example");
    let revision = repository
        .provision_tenant_binding(expected, request.clone())
        .await
        .expect("first provisioning should apply");
    assert_eq!(revision, 1);
    let snapshot = repository
        .load_active()
        .await
        .expect("snapshot should load");
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.tenants.len(), 1);
    assert_eq!(snapshot.tenants[0], request.binding);

    // Identical replay succeeds without moving the revision.
    let replay = repository
        .provision_tenant_binding(revision, request.clone())
        .await
        .expect("identical replay should succeed");
    assert_eq!(replay, 1);
    assert_eq!(current_revision(&repository).await, 1);

    // A different binding for the same tenant fails closed.
    let mut conflicting = request.clone();
    conflicting.binding.issuer = "https://other.example".to_owned();
    let error = repository
        .provision_tenant_binding(revision, conflicting)
        .await
        .expect_err("conflicting binding should be rejected");
    assert!(matches!(error, RepositoryError::Consistency(_)));
    assert_eq!(current_revision(&repository).await, 1);

    // A different tenant with a stale expected revision fails closed.
    let (stale, stale_request) = provisioning_request(0, "beta", "beta.example");
    let error = repository
        .provision_tenant_binding(stale, stale_request)
        .await
        .expect_err("stale expected revision should be rejected");
    assert!(matches!(error, RepositoryError::Conflict));
    assert_eq!(current_revision(&repository).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_moves_binding_and_revision_without_replaying_effects() {
    let Some(IsolatedDirectory { repository, .. }) = isolated_directory().await else {
        return;
    };
    let (_, request) = provisioning_request(0, "alpha", "alpha.example");
    let revision = repository
        .provision_tenant_binding(0, request)
        .await
        .expect("provisioning should apply");

    let tenant = repository
        .load_active()
        .await
        .expect("snapshot should load")
        .tenants
        .remove(0);
    let updated = repository
        .update_tenant_binding(
            revision,
            tenant.tenant.tenant_id,
            "https://renamed.example".to_owned(),
            "renamed.example".to_owned(),
        )
        .await
        .expect("binding update should apply");
    assert_eq!(updated, revision + 1);
    let snapshot = repository
        .load_active()
        .await
        .expect("snapshot should load");
    assert_eq!(snapshot.tenants[0].external_host, "renamed.example");
    assert_eq!(snapshot.tenants[0].issuer, "https://renamed.example");

    // Identical update replay is a bounded no-op.
    let replay = repository
        .update_tenant_binding(
            updated,
            tenant.tenant.tenant_id,
            "https://renamed.example".to_owned(),
            "renamed.example".to_owned(),
        )
        .await
        .expect("identical update replay should succeed");
    assert_eq!(replay, updated);

    // Unknown tenants fail closed.
    let unknown = TenantId::new(Uuid::now_v7()).expect("tenant id is non-nil");
    let error = repository
        .update_tenant_binding(
            updated,
            unknown,
            "https://unknown.example".to_owned(),
            "unknown.example".to_owned(),
        )
        .await
        .expect_err("unknown tenant should be rejected");
    assert!(matches!(error, RepositoryError::NotFound));

    // Mismatched issuer/host routing identity fails closed.
    let error = repository
        .update_tenant_binding(
            updated,
            tenant.tenant.tenant_id,
            "https://mismatch.example".to_owned(),
            "other.example".to_owned(),
        )
        .await
        .expect_err("issuer/host mismatch should be rejected");
    assert!(matches!(error, RepositoryError::Consistency(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_transitions_require_a_binding_and_stay_replay_safe() {
    let Some(IsolatedDirectory { repository, .. }) = isolated_directory().await else {
        return;
    };
    let (_, request) = provisioning_request(0, "alpha", "alpha.example");
    let tenant_id = request.binding.tenant.tenant_id;
    let revision = repository
        .provision_tenant_binding(0, request)
        .await
        .expect("provisioning should apply");

    let suspended = repository
        .set_tenant_runtime_status(revision, tenant_id, TenantRuntimeStatus::Suspended)
        .await
        .expect("suspend should apply");
    assert_eq!(suspended, revision + 1);
    let snapshot = repository
        .load_active()
        .await
        .expect("snapshot should load");
    assert!(snapshot.tenants.is_empty());

    // Identical status replay is a bounded no-op.
    let replay = repository
        .set_tenant_runtime_status(suspended, tenant_id, TenantRuntimeStatus::Suspended)
        .await
        .expect("identical suspend replay should succeed");
    assert_eq!(replay, suspended);

    // Reactivation returns the tenant to the authoritative snapshot.
    let reactivated = repository
        .set_tenant_runtime_status(suspended, tenant_id, TenantRuntimeStatus::Active)
        .await
        .expect("reactivation should apply");
    assert_eq!(reactivated, suspended + 1);
    let snapshot = repository
        .load_active()
        .await
        .expect("snapshot should load");
    assert_eq!(snapshot.tenants.len(), 1);

    // A tenant without a binding has no directory status to change.
    let unbound = TenantId::new(Uuid::now_v7()).expect("tenant id is non-nil");
    let error = repository
        .set_tenant_runtime_status(reactivated, unbound, TenantRuntimeStatus::Suspended)
        .await
        .expect_err("unbound tenant should be rejected");
    assert!(matches!(error, RepositoryError::NotFound));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_removes_routing_and_replays_after_deletion() {
    let Some(IsolatedDirectory { pool, repository }) = isolated_directory().await else {
        return;
    };
    let (_, request) = provisioning_request(0, "alpha", "alpha.example");
    let tenant_id = request.binding.tenant.tenant_id;
    let revision = repository
        .provision_tenant_binding(0, request)
        .await
        .expect("provisioning should apply");

    let removed = repository
        .remove_tenant_binding(revision, tenant_id)
        .await
        .expect("finalize should apply");
    assert_eq!(removed, revision + 1);
    let snapshot = repository
        .load_active()
        .await
        .expect("snapshot should load");
    assert!(snapshot.tenants.is_empty());

    // Before the tenant row is deleted, a missing binding fails closed.
    let error = repository
        .remove_tenant_binding(removed, tenant_id)
        .await
        .expect_err("re-finalize before deletion should be rejected");
    assert!(matches!(error, RepositoryError::NotFound));

    // After the tenant row is deleted the replay is an idempotent no-op.
    let mut connection = pool.get().await.expect("pool should connect");
    sql_query("UPDATE tenants SET status = 'deleted' WHERE id = $1")
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .expect("tenant deletion should apply");
    drop(connection);
    let replay = repository
        .remove_tenant_binding(removed, tenant_id)
        .await
        .expect("re-finalize after deletion should succeed");
    assert_eq!(replay, removed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_writers_serialize_through_the_revision_fence() {
    let Some(IsolatedDirectory { repository, .. }) = isolated_directory().await else {
        return;
    };
    let (first, first_request) = provisioning_request(0, "alpha", "alpha.example");
    let (second, second_request) = provisioning_request(0, "beta", "beta.example");
    let repository_a = repository.clone();
    let repository_b = repository.clone();
    let (first_result, second_result) = tokio::join!(
        async move {
            repository_a
                .provision_tenant_binding(first, first_request)
                .await
        },
        async move {
            repository_b
                .provision_tenant_binding(second, second_request)
                .await
        }
    );
    let mut applied = 0;
    for outcome in [first_result, second_result] {
        match outcome {
            Ok(revision) => {
                applied += 1;
                assert_eq!(
                    revision, 1,
                    "the first committed writer observes revision 1"
                );
            }
            Err(error) => assert!(matches!(error, RepositoryError::Conflict)),
        }
    }
    assert_eq!(applied, 1, "exactly one writer may win the revision fence");
    assert_eq!(current_revision(&repository).await, 1);
    let snapshot = repository
        .load_active()
        .await
        .expect("snapshot should load");
    assert_eq!(snapshot.tenants.len(), 1);
}

#[derive(Debug, diesel::QueryableByName)]
struct CurrentDatabaseRow {
    #[diesel(sql_type = sql_types::Text)]
    name: String,
}

/// The directory revision is writable only through the SECURITY DEFINER
/// revision trigger: a role holding every runtime table grant still cannot
/// update the state row, while ordinary binding mutations keep working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limited_runtime_role_cannot_write_the_revision_state() {
    let Some(IsolatedDirectory { pool, repository }) = isolated_directory().await else {
        return;
    };
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("database url is present when the isolated directory exists");
    let mut coordinator = pool.get().await.expect("pool should connect");
    let database_name: String = sql_query("SELECT current_database() AS name")
        .get_result::<CurrentDatabaseRow>(&mut coordinator)
        .await
        .expect("current database should resolve")
        .name;
    drop(coordinator);

    let mut admin_url = url::Url::parse(&database_url).expect("test database URL is valid");
    admin_url.set_path(&format!("/{database_name}"));
    let mut admin = AsyncPgConnection::establish(admin_url.as_str())
        .await
        .expect("admin connection should establish");
    let role = format!("runtime_role_{}", Uuid::now_v7().simple());
    admin
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'test-only';
             GRANT CONNECT ON DATABASE {database_name} TO {role};
             GRANT USAGE ON SCHEMA public TO {role};
             GRANT SELECT, INSERT, UPDATE, DELETE
               ON tenants, realms, organizations, tenant_runtime_bindings TO {role};
             GRANT SELECT ON tenant_runtime_directory_state TO {role};"
        ))
        .await
        .expect("limited runtime role should create");
    drop(admin);

    let mut restricted_url = url::Url::parse(&database_url).expect("test database URL is valid");
    restricted_url.set_path(&format!("/{database_name}"));
    restricted_url
        .set_username(&role)
        .expect("role name should set");
    restricted_url
        .set_password(Some("test-only"))
        .expect("role password should set");
    let mut connection = AsyncPgConnection::establish(restricted_url.as_str())
        .await
        .expect("restricted connection should establish");

    // The revision state is writable only by the revision trigger.
    let error = sql_query("UPDATE tenant_runtime_directory_state SET revision = revision + 1")
        .execute(&mut connection)
        .await
        .expect_err("direct revision write must be denied");
    assert!(
        error.to_string().contains("permission denied"),
        "denial must be a permission error: {error}"
    );

    // A normal binding mutation through the granted tables still advances the
    // revision under the SECURITY DEFINER trigger.
    let (_, request) = provisioning_request(0, "alpha", "alpha.example");
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind::<sql_types::Uuid, _>(request.tenant.id.as_uuid())
        .bind::<sql_types::Text, _>(&request.tenant.slug)
        .bind::<sql_types::Text, _>(&request.tenant.display_name)
        .execute(&mut connection)
        .await
        .expect("tenant insert should apply");
    sql_query("INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, $3, $4)")
        .bind::<sql_types::Uuid, _>(request.realm.id.as_uuid())
        .bind::<sql_types::Uuid, _>(request.binding.tenant.tenant_id.as_uuid())
        .bind::<sql_types::Text, _>(&request.realm.slug)
        .bind::<sql_types::Text, _>(&request.realm.display_name)
        .execute(&mut connection)
        .await
        .expect("realm insert should apply");
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, $3, $4)",
    )
    .bind::<sql_types::Uuid, _>(request.organization.id.as_uuid())
    .bind::<sql_types::Uuid, _>(request.binding.tenant.tenant_id.as_uuid())
    .bind::<sql_types::Text, _>(&request.organization.slug)
    .bind::<sql_types::Text, _>(&request.organization.display_name)
    .execute(&mut connection)
    .await
    .expect("organization insert should apply");
    sql_query(
        "INSERT INTO tenant_runtime_bindings
            (tenant_id, realm_id, organization_id, issuer, external_host)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind::<sql_types::Uuid, _>(request.binding.tenant.tenant_id.as_uuid())
    .bind::<sql_types::Uuid, _>(request.binding.tenant.realm_id.as_uuid())
    .bind::<sql_types::Uuid, _>(request.binding.tenant.organization_id.as_uuid())
    .bind::<sql_types::Text, _>(&request.binding.issuer)
    .bind::<sql_types::Text, _>(&request.binding.external_host)
    .execute(&mut connection)
    .await
    .expect("binding insert should apply");
    drop(connection);
    assert_eq!(current_revision(&repository).await, 1);
}
