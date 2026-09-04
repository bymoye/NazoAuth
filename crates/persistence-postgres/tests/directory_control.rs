//! Control-plane directory lifecycle contract against a real database: the
//! mutation, its audit event, and its replay-safe outcome ledger commit
//! atomically, stale revisions fail closed, and operation-id conflicts are
//! permanent.

use diesel::{sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_identity::{
    OrganizationId, RealmId, TenantBoundaryDefinition, TenantContext, TenantDirectoryBinding,
    TenantId, TenantProvisioningRequest,
};
use nazo_persistence::directory_control::{
    DirectoryControlAction, DirectoryControlFrame, DirectoryControlOutcome,
};
use nazo_postgres::{TenantDirectoryControlRepository, create_pool, run_pending_migrations};
use serde_json::json;
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI directory control tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

async fn isolated_executor() -> Option<(
    TenantDirectoryControlRepository,
    TenantDirectoryRepositoryProbe,
)> {
    let database_url = database_url()?;
    let database_name = format!("directory_control_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database_name}\";"))
        .await
        .expect("isolated database should create");
    drop(coordinator);
    let separator = database_url.rfind('/').expect("database URL has a path");
    let isolated_url = format!("{}/{}", &database_url[..separator], database_name);
    run_pending_migrations(&isolated_url)
        .await
        .expect("isolated database migrations should apply");
    let pool = create_pool(isolated_url.clone(), 4).expect("pool should create");
    let probe = TenantDirectoryRepositoryProbe {
        pool: create_pool(isolated_url, 4).expect("probe pool should create"),
    };
    Some((TenantDirectoryControlRepository::new(pool), probe))
}

/// Read-side probe used by assertions (revision, ledger rows, audit rows).
struct TenantDirectoryRepositoryProbe {
    pool: nazo_postgres::DbPool,
}

#[derive(Debug, diesel::QueryableByName)]
struct ScalarRow {
    #[diesel(sql_type = sql_types::BigInt)]
    value: i64,
}

fn provisioning_request(slug: &str, host: &str) -> TenantProvisioningRequest {
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is non-nil");
    let realm_id = RealmId::new(Uuid::now_v7()).expect("realm id is non-nil");
    let organization_id = OrganizationId::new(Uuid::now_v7()).expect("organization id is non-nil");
    fn boundary<Id>(id: Id, slug: &str, suffix: &str) -> TenantBoundaryDefinition<Id> {
        TenantBoundaryDefinition {
            id,
            slug: format!("{slug}-{suffix}"),
            display_name: format!("{slug} {suffix}"),
        }
    }
    TenantProvisioningRequest {
        tenant: boundary(tenant_id, slug, "tenant"),
        realm: boundary(realm_id, slug, "realm"),
        organization: boundary(organization_id, slug, "organization"),
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
    }
}

const REQUEST_HASH: &str = "aa7a072a0ad2a4a11aa9a2ad2aa4a2a11aa9a2ad2aa4a2a11aa9a2ad2aa4a2a1";

struct OperationIdentity {
    jti: Uuid,
    jti_string: String,
    actor: serde_json::Value,
}

fn operation_identity() -> OperationIdentity {
    let jti = Uuid::now_v7();
    OperationIdentity {
        jti,
        jti_string: jti.to_string(),
        actor: json!({"kind": "controller", "controller_id": "controller-1", "kid": "kid-1"}),
    }
}

fn frame<'a>(
    action: DirectoryControlAction,
    identity: &'a OperationIdentity,
) -> DirectoryControlFrame<'a> {
    DirectoryControlFrame {
        deployment_id: "deployment-directory-test",
        jti: &identity.jti_string,
        request_sha256: REQUEST_HASH,
        actor: &identity.actor,
        action,
    }
}

async fn audit_rows_for(probe: &TenantDirectoryRepositoryProbe, jti: &Uuid) -> i64 {
    let sql = format!(
        "SELECT count(*)::bigint AS value FROM security_audit_events \
         WHERE event_type LIKE 'tenant_directory_%' \
           AND payload->>'jti' = '{}'",
        jti
    );
    let mut connection = probe.pool.get().await.expect("probe pool should connect");
    sql_query(&sql)
        .get_result::<ScalarRow>(&mut connection)
        .await
        .expect("audit probe query should return a row")
        .value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_commits_mutation_audit_and_ledger_atomically() {
    let Some((executor, probe)) = isolated_executor().await else {
        return;
    };
    let identity = operation_identity();
    let action = DirectoryControlAction::Create {
        expected_revision: 0,
        provisioning: Box::new(provisioning_request("alpha", "alpha.example")),
    };
    let outcome = executor
        .execute_control_operation(frame(action, &identity))
        .await
        .expect("create should apply");
    let DirectoryControlOutcome::Mutation(mutation) = &outcome else {
        panic!("create must report a mutation outcome");
    };
    assert_eq!(mutation.action, "create");
    assert_eq!(mutation.previous_revision, 0);
    assert_eq!(mutation.revision, 1);
    assert_eq!(probe_revision(&probe).await, 1);
    assert_eq!(audit_rows_for(&probe, &identity.jti).await, 1);
    assert_eq!(ledger_rows(&probe).await, 1);
}

async fn probe_revision(probe: &TenantDirectoryRepositoryProbe) -> u64 {
    let mut connection = probe.pool.get().await.expect("probe pool should connect");
    let row = sql_query("SELECT revision AS value FROM tenant_runtime_directory_state")
        .get_result::<ScalarRow>(&mut connection)
        .await
        .expect("directory revision should read");
    u64::try_from(row.value).expect("revision is non-negative")
}

async fn probe_runtime_revision(
    probe: &TenantDirectoryRepositoryProbe,
    tenant_id: TenantId,
) -> u64 {
    let mut connection = probe.pool.get().await.expect("probe pool should connect");
    let row = sql_query(
        "SELECT runtime_revision AS value FROM tenant_runtime_bindings WHERE tenant_id = $1",
    )
    .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
    .get_result::<ScalarRow>(&mut connection)
    .await
    .expect("tenant runtime revision should read");
    u64::try_from(row.value).expect("runtime revision is positive")
}

async fn ledger_rows(probe: &TenantDirectoryRepositoryProbe) -> i64 {
    let mut connection = probe.pool.get().await.expect("probe pool should connect");
    sql_query("SELECT count(*)::bigint AS value FROM tenant_directory_control_operations")
        .get_result::<ScalarRow>(&mut connection)
        .await
        .expect("ledger count should read")
        .value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replays_return_recorded_outcomes_without_new_effects() {
    let Some((executor, probe)) = isolated_executor().await else {
        return;
    };
    let identity = operation_identity();
    let action = DirectoryControlAction::Create {
        expected_revision: 0,
        provisioning: Box::new(provisioning_request("alpha", "alpha.example")),
    };
    let first = executor
        .execute_control_operation(frame(action.clone(), &identity))
        .await
        .expect("first execution should apply");

    // Identical replay: same recorded outcome, no new audit or ledger effects.
    let replay = executor
        .execute_control_operation(frame(action, &identity))
        .await
        .expect("identical replay should return the recorded outcome");
    assert_eq!(first, replay);
    assert_eq!(probe_revision(&probe).await, 1);
    assert_eq!(audit_rows_for(&probe, &identity.jti).await, 1);
    assert_eq!(ledger_rows(&probe).await, 1);

    // Same operation id with a different request hash is a permanent conflict.
    let different_hash = DirectoryControlFrame {
        deployment_id: "deployment-directory-test",
        jti: &identity.jti_string,
        request_sha256: "bb7a072a0ad2a4a11aa9a2ad2aa4a2a11aa9a2ad2aa4a2a11aa9a2ad2aa4a2a1",
        actor: &identity.actor,
        action: DirectoryControlAction::Describe,
    };
    let error = executor
        .execute_control_operation(different_hash)
        .await
        .expect_err("operation id reuse must conflict");
    assert!(matches!(
        error,
        nazo_persistence::directory_control::TenantDirectoryControlError::Conflict
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_revisions_are_rejected_without_ledger_side_effects() {
    let Some((executor, probe)) = isolated_executor().await else {
        return;
    };
    let identity = operation_identity();
    let action = DirectoryControlAction::Create {
        expected_revision: 7,
        provisioning: Box::new(provisioning_request("alpha", "alpha.example")),
    };
    let error = executor
        .execute_control_operation(frame(action, &identity))
        .await
        .expect_err("stale expected revision must fail closed");
    assert!(matches!(
        error,
        nazo_persistence::directory_control::TenantDirectoryControlError::Conflict
    ));
    assert_eq!(probe_revision(&probe).await, 0);
    assert_eq!(ledger_rows(&probe).await, 0);
    assert_eq!(audit_rows_for(&probe, &identity.jti).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_disable_finalize_and_describe_complete_the_lifecycle() {
    let Some((executor, probe)) = isolated_executor().await else {
        return;
    };
    let create_identity = operation_identity();
    let create_jti = create_identity.jti;
    let request = provisioning_request("alpha", "alpha.example");
    let tenant_id = request.binding.tenant.tenant_id;
    let outcome = executor
        .execute_control_operation(frame(
            DirectoryControlAction::Create {
                expected_revision: 0,
                provisioning: Box::new(request),
            },
            &create_identity,
        ))
        .await
        .expect("create should apply");

    let rename_identity = operation_identity();
    let rename_jti = rename_identity.jti;
    let outcome = executor
        .execute_control_operation(frame(
            DirectoryControlAction::Update {
                expected_revision: outcome.revision(),
                tenant_id,
                issuer: "https://renamed.example".to_owned(),
                external_host: "renamed.example".to_owned(),
            },
            &rename_identity,
        ))
        .await
        .expect("update should apply");
    assert_eq!(outcome.revision(), 2);

    let reload_identity = operation_identity();
    let reload_jti = reload_identity.jti;
    let outcome = executor
        .execute_control_operation(frame(
            DirectoryControlAction::Reload {
                expected_revision: 2,
                tenant_id,
            },
            &reload_identity,
        ))
        .await
        .expect("reload should advance the tenant material generation");
    assert_eq!(outcome.revision(), 3);
    assert_eq!(probe_runtime_revision(&probe, tenant_id).await, 2);

    let describe_identity = operation_identity();
    let pre_disable_describe_jti = describe_identity.jti;
    let outcome = executor
        .execute_control_operation(frame(DirectoryControlAction::Describe, &describe_identity))
        .await
        .expect("describe should read");
    let DirectoryControlOutcome::Describe(snapshot) = outcome else {
        panic!("describe must report a describe outcome");
    };
    assert_eq!(snapshot.revision, 3);
    assert_eq!(snapshot.tenants.len(), 1);
    assert_eq!(snapshot.tenants[0].external_host, "renamed.example");
    assert_eq!(snapshot.tenants[0].runtime_revision, 2);

    let disable_identity = operation_identity();
    let disable_jti = disable_identity.jti;
    let outcome = executor
        .execute_control_operation(frame(
            DirectoryControlAction::Disable {
                expected_revision: 3,
                tenant_id,
            },
            &disable_identity,
        ))
        .await
        .expect("disable should apply");
    assert_eq!(outcome.revision(), 4);

    let finalize_identity = operation_identity();
    let finalize_jti = finalize_identity.jti;
    let outcome = executor
        .execute_control_operation(frame(
            DirectoryControlAction::Finalize {
                expected_revision: 4,
                tenant_id,
            },
            &finalize_identity,
        ))
        .await
        .expect("finalize should apply");
    assert_eq!(outcome.revision(), 5);

    let describe_identity = operation_identity();
    let post_finalize_describe_jti = describe_identity.jti;
    let outcome = executor
        .execute_control_operation(frame(DirectoryControlAction::Describe, &describe_identity))
        .await
        .expect("post-finalize describe should read");
    let DirectoryControlOutcome::Describe(snapshot) = outcome else {
        panic!("describe must report a describe outcome");
    };
    assert!(snapshot.tenants.is_empty());
    assert_eq!(audit_rows_for(&probe, &create_jti).await, 1);
    assert_eq!(audit_rows_for(&probe, &rename_jti).await, 1);
    assert_eq!(audit_rows_for(&probe, &reload_jti).await, 1);
    assert_eq!(audit_rows_for(&probe, &pre_disable_describe_jti).await, 1);
    assert_eq!(audit_rows_for(&probe, &disable_jti).await, 1);
    assert_eq!(audit_rows_for(&probe, &finalize_jti).await, 1);
    assert_eq!(audit_rows_for(&probe, &post_finalize_describe_jti).await, 1);
    assert_eq!(ledger_rows(&probe).await, 7);
}
