//! Process-level evidence for tenant-directory lifecycle control operations:
//! a real `nazoauth operator-task` child executes a signed tenant-directory
//! create against an isolated database, the journal replays the durable
//! outcome after response loss, and stale revisions fail closed.
//!
//! Without `NAZO_TEST_DATABASE_URL` (or `DATABASE_URL`) every test skips so
//! the integration test stays hermetic; in CI their absence is a hard failure.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use chrono::Utc;
use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    CONTROL_OPERATION_SCHEMA, ControlOperation, ControlOperationPayload, ControlOutcome,
    ControlTenantBoundary, controller_key_id, decode_control_result, sign_control_operation,
};
use uuid::Uuid;

const MIGRATION_RUNTIME_ROLE: &str = "nazoauth_t1_convergence_runtime";
const DEPLOYMENT: &str = "deployment-directory-process";
const CONFIG_REVISION: &str = "config-revision-directory-process";

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI directory control process tests require a database URL");
    }
    url
}

fn temporary_directory(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazoauth-directory-process-{tag}-{}",
        Uuid::now_v7().simple()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

/// Fresh isolated database with the full migration chain and one enrolled
/// controller slot for the signing key.
async fn isolated_directory(tag: &str) -> Option<(String, ed25519_dalek::VerifyingKey, String)> {
    let base = database_url()?;
    let database_name = format!("directory_process_{}_{}", tag, Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&base)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database_name}\";"))
        .await
        .expect("isolated database should create");
    drop(coordinator);
    let separator = base.rfind('/').expect("database URL has a path");
    let url = format!("{}/{}", &base[..separator], database_name);
    {
        let mut role_coordinator = AsyncPgConnection::establish(&base)
            .await
            .expect("test database should connect for role preparation");
        role_coordinator
            .batch_execute(&format!(
                "SELECT pg_advisory_lock(564196923451771043);\
                 DO $$ BEGIN \
                   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATION_RUNTIME_ROLE}') THEN \
                     CREATE ROLE {MIGRATION_RUNTIME_ROLE} NOSUPERUSER NOBYPASSRLS NOINHERIT; \
                   END IF; \
                 END $$;\
                 SELECT pg_advisory_unlock(564196923451771043);"
            ))
            .await
            .expect("migration runtime role fixture should exist");
    }
    nazo_postgres::run_pending_migrations(&url)
        .await
        .expect("isolated application migrations should apply");

    let controller = SigningKey::from_bytes(&[13; 32]);
    let kid = controller_key_id(&controller.verifying_key());
    let registry = nazo_postgres::ControllerRegistryRepository::new(
        nazo_postgres::create_pool(&url, 2).expect("test pool"),
    );
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "primary".to_owned(),
                kid: kid.clone(),
                public_key: controller.verifying_key().to_bytes(),
            },
            Utc::now(),
        )
        .await
        .expect("controller slot should enroll");
    Some((url, controller.verifying_key(), kid))
}

fn write_runtime_fixtures(root: &Path) {
    fs::create_dir_all(root.join("state")).unwrap();
    fs::write(
        root.join("server.yaml"),
        format!("DATA_DIR: runtime\nDEPLOYMENT_ID: {DEPLOYMENT}\n"),
    )
    .unwrap();
    fs::create_dir_all(root.join("runtime/instance")).unwrap();
    fs::write(
        root.join("runtime/instance/deployment-id"),
        format!("{DEPLOYMENT}\n"),
    )
    .unwrap();
    fs::write(root.join("config-revision"), format!("{CONFIG_REVISION}\n")).unwrap();
    fs::create_dir_all(root.join("keys")).unwrap();
    fs::write(root.join("state/deployment-id"), format!("{DEPLOYMENT}\n")).unwrap();
}

fn run_operator_task(root: &Path, compact: &str, database_url: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nazoauth"));
    command
        .arg("operator-task")
        .current_dir(root)
        .env_clear()
        .env("NAZOAUTH_SERVER_CONFIG_FILE", root.join("server.yaml"))
        .env(
            "NAZOAUTH_OPERATOR_CONFIG_REVISION_FILE",
            root.join("config-revision"),
        )
        .env("NAZOAUTH_OPERATOR_STATE_DIRECTORY", root.join("state"))
        .env("JWK_KEYS_DIR", root.join("keys"))
        .env("NAZOAUTH_MIGRATION_RUNTIME_ROLE", MIGRATION_RUNTIME_ROLE)
        .env("DATABASE_URL", database_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    for name in ["PATH", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(compact.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn directory_operation(
    operation_id: &str,
    kid: &str,
    payload: ControlOperationPayload,
) -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: operation_id.to_owned(),
        kid: kid.to_owned(),
        deployment_id: DEPLOYMENT.to_owned(),
        config_revision: CONFIG_REVISION.to_owned(),
        operation: payload,
    }
}

fn directory_create_payload() -> ControlOperationPayload {
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let boundary = |id: Uuid, slug: &str| ControlTenantBoundary {
        id: id.to_string(),
        slug: slug.to_owned(),
        display_name: format!("{slug} display"),
    };
    ControlOperationPayload::TenantDirectoryCreate {
        expected_revision: 0,
        tenant: boundary(tenant_id, "alpha"),
        realm: boundary(realm_id, "alpha-realm"),
        organization: boundary(organization_id, "alpha-org"),
        issuer: "https://alpha.example".to_owned(),
        external_host: "alpha.example".to_owned(),
    }
}

#[tokio::test]
async fn signed_directory_create_executes_recovers_and_fails_closed() {
    let Some((database_url, verifying_key, kid)) = isolated_directory("lifecycle").await else {
        return;
    };
    let controller = SigningKey::from_bytes(&[13; 32]);
    assert_eq!(verifying_key, controller.verifying_key());

    let root = temporary_directory("lifecycle");
    write_runtime_fixtures(&root);
    let operation_id = "019c8ca2-30a6-7000-8000-00000000c001";
    let op = directory_operation(operation_id, &kid, directory_create_payload());
    let compact = sign_control_operation(&op, &controller).unwrap();

    let first = run_operator_task(&root, &compact, &database_url);
    assert!(
        first.status.success(),
        "status={} stdout={} stderr={}",
        first.status,
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let result =
        decode_control_result(&first.stdout).expect("stdout must be a typed ControlResult");
    assert_eq!(result.operation_id, operation_id);
    assert_eq!(result.outcome, ControlOutcome::Succeeded);
    assert!(matches!(
        result.result,
        Some(nazo_operator_protocol::ControlResultData::TenantDirectoryMutation { ref action, revision, previous_revision, .. })
            if action == "create" && previous_revision == 0 && revision == 1
    ));

    // The journal owns recovery: rerun with a dead database URL and the same
    // compact operation must return the identical durable result.
    let replay = run_operator_task(&root, &compact, "postgres://127.0.0.1:1/none");
    assert!(
        replay.status.success(),
        "journal replay must succeed without the database: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(replay.stdout, first.stdout);

    // A stale expected revision fails closed with a typed rejection.
    let stale_payload = match directory_create_payload() {
        ControlOperationPayload::TenantDirectoryCreate {
            tenant,
            realm,
            organization,
            issuer,
            external_host,
            ..
        } => ControlOperationPayload::TenantDirectoryCreate {
            expected_revision: 99,
            tenant,
            realm,
            organization,
            issuer,
            external_host,
        },
        other => unreachable!("{other:?}"),
    };
    let stale = directory_operation("019c8ca2-30a6-7000-8000-00000000c002", &kid, stale_payload);
    let stale_compact = sign_control_operation(&stale, &controller).unwrap();
    let stale_output = run_operator_task(&root, &stale_compact, &database_url);
    assert!(
        stale_output.status.success(),
        "the journal must record the typed rejection: {}",
        String::from_utf8_lossy(&stale_output.stderr)
    );
    let stale_result =
        decode_control_result(&stale_output.stdout).expect("stdout must be a typed ControlResult");
    assert_eq!(stale_result.outcome, ControlOutcome::Failed);
    assert!(stale_result.result.is_none());

    fs::remove_dir_all(root).unwrap();
}
