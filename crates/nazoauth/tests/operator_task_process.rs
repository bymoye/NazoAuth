//! Process-level evidence for the reworked one-shot operator entry (E04/E05):
//! real `nazauth operator-task` child processes against an isolated
//! PostgreSQL schema backing the Controller Registry.
//!
//! Without `NAZO_TEST_DATABASE_URL` (or `DATABASE_URL`) every test skips so
//! the integration test stays hermetic; in CI their absence is a hard failure.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use diesel::migration::CREATE_MIGRATIONS_TABLE;
use diesel::{
    sql_query,
    sql_types::{Bool, Text},
};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    CONTROL_OPERATION_SCHEMA, ControlOperation, ControlOperationPayload, ControlOutcome,
    controller_key_id, decode_control_result, sign_control_operation,
};

const DEPLOYMENT: &str = "deployment-process";
const CONFIG_REVISION: &str = "config-revision-process";
const MIGRATION_RUNTIME_ROLE: &str = "nazoauth_operator_process_runtime";
const SIGNING_KEY_ENCRYPTION_KEY_ID: &str = "operator-process-test";
const SIGNING_KEY_ENCRYPTION_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

#[derive(diesel::QueryableByName)]
struct ExistsRow {
    #[diesel(sql_type = Bool)]
    exists: bool,
}

/// Mirror of the persistence-layer isolated-schema fixture: the public
/// security-audit migration is pre-marked applied because its state table is
/// shared across schemas and must never be recreated per test.
async fn isolated_registry(
    case: &str,
) -> Option<(String, nazo_postgres::ControllerRegistryRepository)> {
    const PUBLIC_SECURITY_AUDIT_MIGRATION_VERSION: &str = "20260805000100";

    let base = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    nazo_postgres::run_pending_migrations(&base)
        .await
        .expect("public application migrations should apply");
    let mut role_coordinator = AsyncPgConnection::establish(&base)
        .await
        .expect("test database should connect for role preparation");
    role_coordinator
        .batch_execute(&format!(
            "SELECT pg_advisory_lock(564196923451771042);\
             DO $$ BEGIN \
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATION_RUNTIME_ROLE}') THEN \
                 CREATE ROLE {MIGRATION_RUNTIME_ROLE} NOSUPERUSER NOBYPASSRLS NOINHERIT; \
               END IF; \
             END $$;\
             SELECT pg_advisory_unlock(564196923451771042);"
        ))
        .await
        .expect("runtime role fixture should exist");
    let schema = format!(
        "operator_process_{}_{}",
        case,
        uuid::Uuid::now_v7().simple()
    );
    let mut coordinator = AsyncPgConnection::establish(&base)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .expect("isolated schema should create");
    drop(coordinator);
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}%2Cpublic");
    {
        let mut connection = AsyncPgConnection::establish(&url)
            .await
            .expect("isolated migration database should connect");
        connection
            .batch_execute(CREATE_MIGRATIONS_TABLE)
            .await
            .expect("isolated migration ledger should create");
        sql_query(
            "INSERT INTO __diesel_schema_migrations (version)
             VALUES ($1)
             ON CONFLICT (version) DO NOTHING",
        )
        .bind::<Text, _>(PUBLIC_SECURITY_AUDIT_MIGRATION_VERSION)
        .execute(&mut connection)
        .await
        .expect("public-only migration should be excluded from this fixture");
    }
    nazo_postgres::run_pending_migrations(&url)
        .await
        .expect("isolated application migrations should apply");
    let repository = nazo_postgres::ControllerRegistryRepository::new(
        nazo_postgres::create_pool(&url, 4).expect("test pool"),
    );
    Some((url, repository))
}

fn temporary_directory(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazauth-operator-process-{tag}-{}",
        rand::random::<u64>()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_runtime_fixtures(root: &Path) {
    fs::create_dir_all(root.join("state")).unwrap();
    fs::write(
        root.join("server.yaml"),
        format!(
            "DATA_DIR: runtime\nDEPLOYMENT_ID: {DEPLOYMENT}\nSIGNING_KEY_ENCRYPTION_KEY_ID: {SIGNING_KEY_ENCRYPTION_KEY_ID}\nSIGNING_KEY_ENCRYPTION_KEY: {SIGNING_KEY_ENCRYPTION_KEY}\n"
        ),
    )
    .unwrap();
    fs::create_dir_all(root.join("runtime/instance")).unwrap();
    fs::write(
        root.join("runtime/instance/deployment-id"),
        format!("{DEPLOYMENT}\n"),
    )
    .unwrap();
    fs::write(root.join("config-revision"), format!("{CONFIG_REVISION}\n")).unwrap();
    // Operator-state deployment anchor: non-bootstrap tasks require it, and
    // persist_operator_state_identity would write the same value on first use.
    fs::write(root.join("state/deployment-id"), format!("{DEPLOYMENT}\n")).unwrap();
}

struct SpawnOptions<'a> {
    extra_env: Vec<(&'a str, String)>,
    failpoint: Option<(&'a str, PathBuf)>,
}

fn spawn_operator_task(root: &Path, compact: &str, options: SpawnOptions<'_>) -> Child {
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
        .env("NAZOAUTH_MIGRATION_RUNTIME_ROLE", MIGRATION_RUNTIME_ROLE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in options.extra_env {
        command.env(name, value);
    }
    if let Some((name, marker)) = options.failpoint {
        command
            .env("NAZOAUTH_OPERATOR_TEST_FAILPOINT", name)
            .env("NAZOAUTH_OPERATOR_TEST_FAILPOINT_MARKER", marker);
    }
    #[cfg(windows)]
    for name in ["PATH", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(value) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", value);
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(compact.as_bytes())
        .unwrap();
    child
}

fn run_operator_task(root: &Path, compact: &str, extra_env: Vec<(&str, String)>) -> Output {
    spawn_operator_task(
        root,
        compact,
        SpawnOptions {
            extra_env,
            failpoint: None,
        },
    )
    .wait_with_output()
    .unwrap()
}

fn wait_for_marker(mut child: Child, path: &Path) -> Child {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if path.is_file() {
            return child;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "operator test process exited before reaching failpoint {}: {status}; stdout: {}; stderr: {}",
                    path.display(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "operator test process status failed before reaching failpoint {}: {error}",
                    path.display()
                );
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "operator test failpoint was not reached before the 30-second deadline: {}; stdout: {}; stderr: {}",
                path.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn operation(operation_id: &str, kid: &str, payload: ControlOperationPayload) -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: operation_id.to_owned(),
        kid: kid.to_owned(),
        deployment_id: DEPLOYMENT.to_owned(),
        config_revision: CONFIG_REVISION.to_owned(),
        operation: payload,
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn assert_rejection(output: &Output, class: &str) {
    assert!(
        !output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("nazoauth-operator-rejection={class}")),
        "expected rejection class {class} in stderr: {stderr}"
    );
}

/// Happy path plus the journal guarantees that matter most at process level:
/// response-loss recovery returns the identical durable result without
/// touching the registry again, and a conflicting request under the same id is
/// permanently refused.
#[tokio::test]
async fn signed_control_operation_executes_once_and_recovers_from_the_journal() {
    let Some((database_url, registry)) = isolated_registry("happy").await else {
        return;
    };
    let controller = SigningKey::from_bytes(&[11; 32]);
    let public_key = controller.verifying_key().to_bytes();
    let kid = controller_key_id(&controller.verifying_key());
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "primary".to_owned(),
                kid: kid.clone(),
                public_key,
            },
            Utc::now(),
        )
        .await
        .expect("controller slot should enroll");

    let root = temporary_directory("happy");
    write_runtime_fixtures(&root);
    let operation_id = "019c8ca2-30a6-7000-8000-00000000b001";
    let op = operation(operation_id, &kid, ControlOperationPayload::MigrateApply);
    let compact = sign_control_operation(&op, &controller).unwrap();

    let first = run_operator_task(
        &root,
        &compact,
        vec![("DATABASE_URL", database_url.clone())],
    );
    assert_success(&first);
    let first_result =
        decode_control_result(&first.stdout).expect("stdout must be a typed ControlResult");
    assert_eq!(first_result.operation_id, operation_id);
    assert_eq!(first_result.outcome, ControlOutcome::Succeeded);

    // The journal owns recovery: rerun with a dead database URL — the resume
    // path must not consult the Controller Registry at all.
    let replay = run_operator_task(
        &root,
        &compact,
        vec![("DATABASE_URL", "postgres://127.0.0.1:1/none".to_owned())],
    );
    assert_success(&replay);
    assert_eq!(replay.stdout, first.stdout);

    // Same id, different canonical request: permanent conflict.
    let mut conflicting = op.clone();
    conflicting.config_revision = "different-revision".to_owned();
    let conflicting_compact = sign_control_operation(&conflicting, &controller).unwrap();
    let conflict = run_operator_task(
        &root,
        &conflicting_compact,
        vec![("DATABASE_URL", database_url)],
    );
    assert_rejection(&conflict, "conflict");
    fs::remove_dir_all(root).unwrap();
}

/// SIGKILL between journal accept and the side effect; restart completes the
/// operation exactly once through the owner-ledger semantics.
#[tokio::test]
async fn killed_before_side_effect_resumes_without_duplicating_the_mutation() {
    let Some((database_url, registry)) = isolated_registry("kill").await else {
        return;
    };
    let controller = SigningKey::from_bytes(&[12; 32]);
    let public_key = controller.verifying_key().to_bytes();
    let kid = controller_key_id(&controller.verifying_key());
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "primary".to_owned(),
                kid: kid.clone(),
                public_key,
            },
            Utc::now(),
        )
        .await
        .expect("controller slot should enroll");

    let root = temporary_directory("kill");
    write_runtime_fixtures(&root);
    let operation_id = "019c8ca2-30a6-7000-8000-00000000b002";
    let op = operation(operation_id, &kid, ControlOperationPayload::MigrateApply);
    let compact = sign_control_operation(&op, &controller).unwrap();

    let marker = root.join("before-side-effect.marker");
    let killed = spawn_operator_task(
        &root,
        &compact,
        SpawnOptions {
            extra_env: vec![("DATABASE_URL", database_url.clone())],
            failpoint: Some(("control-journal-before-side-effect", marker.clone())),
        },
    );
    let mut killed = wait_for_marker(killed, &marker);
    killed.kill().unwrap();
    assert!(!killed.wait().unwrap().success());

    // The operation was durably journaled before any side effect: at the
    // before-side-effect failpoint the record has already crossed accepted ->
    // executing, which is exactly what makes the restart resume (never
    // duplicate) the mutation.
    let journal = root
        .join("state/control-journal")
        .join(format!("{operation_id}.journal.json"));
    assert!(journal.is_file());
    assert!(
        fs::read_to_string(&journal)
            .unwrap()
            .contains("\"executing\"")
    );

    let restarted = run_operator_task(&root, &compact, vec![("DATABASE_URL", database_url)]);
    assert_success(&restarted);
    let result = decode_control_result(&restarted.stdout).unwrap();
    assert_eq!(result.outcome, ControlOutcome::Succeeded);
    // Terminal phase proves the restart drove the record monotonically
    // forward instead of re-executing a fresh mutation.
    assert!(
        fs::read_to_string(&journal)
            .unwrap()
            .contains("\"completed\""),
        "{}",
        fs::read_to_string(&journal).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

/// Admission failures against real registry state: expired, revoked, unknown,
/// cross-deployment, forged signature, wrong revision, and the refused
/// tenant-resource mutations.
#[tokio::test]
async fn admission_refuses_every_forged_or_unservicable_operation_class() {
    let Some((database_url, registry)) = isolated_registry("admission").await else {
        return;
    };
    let controller = SigningKey::from_bytes(&[13; 32]);
    let primary_public_key = controller.verifying_key().to_bytes();
    let kid = controller_key_id(&controller.verifying_key());
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "primary".to_owned(),
                kid: kid.clone(),
                public_key: primary_public_key,
            },
            Utc::now(),
        )
        .await
        .expect("controller slot should enroll");

    // An expired key: enrolled 31 days ago under the fixed 30-day TTL.
    let expired_key = SigningKey::from_bytes(&[14; 32]);
    let expired_public_key = expired_key.verifying_key().to_bytes();
    let expired_kid = controller_key_id(&expired_key.verifying_key());
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "stale".to_owned(),
                kid: expired_kid.clone(),
                public_key: expired_public_key,
            },
            Utc::now() - ChronoDuration::days(31),
        )
        .await
        .expect("expired-slot fixture should enroll");

    // A revoked key, revoked through its exact authoritative controller_id.
    let revoked_key = SigningKey::from_bytes(&[15; 32]);
    let revoked_public_key = revoked_key.verifying_key().to_bytes();
    let revoked_kid = controller_key_id(&revoked_key.verifying_key());
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "doomed".to_owned(),
                kid: revoked_kid.clone(),
                public_key: revoked_public_key,
            },
            Utc::now(),
        )
        .await
        .expect("revoked-slot fixture should enroll");
    let revoked_controller_id = registry
        .list_slots(DEPLOYMENT)
        .await
        .unwrap()
        .into_iter()
        .find(|slot| slot.kid == revoked_kid)
        .map(|slot| slot.controller_id)
        .expect("revoked fixture slot");
    registry
        .revoke_slot(DEPLOYMENT, &revoked_controller_id, Utc::now())
        .await
        .expect("revocation should succeed");

    let root = temporary_directory("admission");
    write_runtime_fixtures(&root);
    let env = || vec![("DATABASE_URL", database_url.clone())];
    let signed = |operation: &ControlOperation, key: &SigningKey| {
        sign_control_operation(operation, key).unwrap()
    };
    let run = |compact: String, env: Vec<(&str, String)>| run_operator_task(&root, &compact, env);

    // Unknown kid for this deployment.
    let stranger = SigningKey::from_bytes(&[16; 32]);
    let stranger_kid = controller_key_id(&stranger.verifying_key());
    assert_rejection(
        &run(
            signed(
                &operation(
                    "019c8ca2-30a6-7000-8000-00000000b003",
                    &stranger_kid,
                    ControlOperationPayload::KeysValidate,
                ),
                &stranger,
            ),
            env(),
        ),
        "authorization",
    );

    // Expired keys are the same authorization rejection as unknown and revoked
    // keys; the operator entry does not perform a second registry read merely
    // to expose an internal lifecycle distinction.
    assert_rejection(
        &run(
            signed(
                &operation(
                    "019c8ca2-30a6-7000-8000-00000000b004",
                    &expired_kid,
                    ControlOperationPayload::KeysValidate,
                ),
                &expired_key,
            ),
            env(),
        ),
        "authorization",
    );

    // Revoked key.
    assert_rejection(
        &run(
            signed(
                &operation(
                    "019c8ca2-30a6-7000-8000-00000000b005",
                    &revoked_kid,
                    ControlOperationPayload::KeysValidate,
                ),
                &revoked_key,
            ),
            env(),
        ),
        "authorization",
    );

    // Wrong deployment: the registered kid does not exist there.
    let mut cross_deployment = operation(
        "019c8ca2-30a6-7000-8000-00000000b006",
        &kid,
        ControlOperationPayload::KeysValidate,
    );
    cross_deployment.deployment_id = "deployment-other".to_owned();
    assert_rejection(
        &run(signed(&cross_deployment, &controller), env()),
        "authorization",
    );

    // Forged signature under a trusted kid: NazoAuth holds no private key and
    // cannot mint operations, and a forged one never admits.
    let forged = operation(
        "019c8ca2-30a6-7000-8000-00000000b007",
        &kid,
        ControlOperationPayload::KeysValidate,
    );
    // Build the forged envelope by keeping the trusted kid in the header and
    // re-signing the same signing input with the stranger key: structurally
    // valid, cryptographically foreign.
    let valid_for_kid = signed(&forged, &controller);
    let mut segments = valid_for_kid.split('.');
    let (protected, payload) = match (segments.next(), segments.next()) {
        (Some(a), Some(b)) => (a, b),
        _ => panic!("compact JWS shape"),
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as FORGED_B64};
    use ed25519_dalek::Signer as _;
    let signing_input = format!("{protected}.{payload}");
    let forged_signature = FORGED_B64.encode(stranger.sign(signing_input.as_bytes()).to_bytes());
    let forged_compact = format!("{signing_input}.{forged_signature}");
    assert_rejection(&run(forged_compact, env()), "authorization");

    // Stale configuration revision.
    let mut stale_revision = operation(
        "019c8ca2-30a6-7000-8000-00000000b009",
        &kid,
        ControlOperationPayload::MigrateApply,
    );
    stale_revision.config_revision = "rotated-revision".to_owned();
    assert_rejection(
        &run(signed(&stale_revision, &controller), env()),
        "revision",
    );

    // Tenant-resource mutations are serviced since H07: a signed apply is
    // admitted and journaled like any other operation, then dispatched onto
    // the shared CAS engine.  Without mounted change-set material the frame
    // ends as a durable failed result — an execution outcome, never an
    // admission rejection.
    let output = run(
        signed(
            &operation(
                "019c8ca2-30a6-7000-8000-00000000b00a",
                &kid,
                ControlOperationPayload::TenantResourceApply {
                    tenant_id: uuid::Uuid::now_v7().to_string(),
                    resources: vec![nazo_operator_protocol::TenantResourceIdentity {
                        kind: nazo_operator_protocol::TenantResourceKind::User,
                        resource_id: "user-1".to_owned(),
                        digest: "d".repeat(64),
                    }],
                },
            ),
            &controller,
        ),
        env(),
    );
    assert_success(&output);
    let result = decode_control_result(&output.stdout).expect("durable result");
    assert_eq!(result.outcome, ControlOutcome::Failed);
    assert_eq!(
        result.error,
        Some(nazo_operator_protocol::ControlErrorCode::ExecutionFailed)
    );
    fs::remove_dir_all(root).unwrap();
}

/// The keys family executes through the real key-management engine, proving
/// the E05 dispatch end to end; the database-backed keyset makes a subsequent
/// keys-validate succeed on its own journaled operation.
#[tokio::test]
async fn keys_family_runs_through_the_real_engine_and_journals_the_outcome() {
    let Some((database_url, registry)) = isolated_registry("keys").await else {
        return;
    };
    let controller = SigningKey::from_bytes(&[17; 32]);
    let public_key = controller.verifying_key().to_bytes();
    let kid = controller_key_id(&controller.verifying_key());
    registry
        .create_slot(
            nazo_postgres::NewControllerSlot {
                deployment_id: DEPLOYMENT.to_owned(),
                label: "primary".to_owned(),
                kid: kid.clone(),
                public_key,
            },
            Utc::now(),
        )
        .await
        .expect("controller slot should enroll");

    let root = temporary_directory("keys");
    write_runtime_fixtures(&root);
    let initialize = run_operator_task(
        &root,
        &sign_control_operation(
            &operation(
                "019c8ca2-30a6-7000-8000-00000000b00a",
                &kid,
                ControlOperationPayload::MigrateApply,
            ),
            &controller,
        )
        .unwrap(),
        vec![("DATABASE_URL", database_url.clone())],
    );
    assert_success(&initialize);
    assert_eq!(
        decode_control_result(&initialize.stdout).unwrap().outcome,
        ControlOutcome::Succeeded,
        "stderr: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );
    let generate_compact = sign_control_operation(
        &operation(
            "019c8ca2-30a6-7000-8000-00000000b00b",
            &kid,
            ControlOperationPayload::KeysGenerateLocal {
                alg: "ES256".to_owned(),
                purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
            },
        ),
        &controller,
    )
    .unwrap();

    let first = run_operator_task(
        &root,
        &generate_compact,
        vec![("DATABASE_URL", database_url.clone())],
    );
    assert_success(&first);
    let result = decode_control_result(&first.stdout).unwrap();
    assert_eq!(
        result.outcome,
        ControlOutcome::Succeeded,
        "result: {result:?}; stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!root.join("keys").exists());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect for signing-key assertion");
    let keyset = sql_query("SELECT EXISTS (SELECT 1 FROM tenant_signing_keysets) AS exists")
        .get_result::<ExistsRow>(&mut connection)
        .await
        .expect("database signing keyset should be queryable");
    assert!(
        keyset.exists,
        "key generation must persist its authority in PostgreSQL"
    );

    // Replay returns the identical durable result and never regenerates.
    let replay = run_operator_task(
        &root,
        &generate_compact,
        vec![("DATABASE_URL", "postgres://127.0.0.1:1/none".to_owned())],
    );
    assert_success(&replay);
    assert_eq!(replay.stdout, first.stdout);

    // keys-validate over the generated keyset succeeds as its own operation.
    let validate = run_operator_task(
        &root,
        &sign_control_operation(
            &operation(
                "019c8ca2-30a6-7000-8000-00000000b00c",
                &kid,
                ControlOperationPayload::KeysValidate,
            ),
            &controller,
        )
        .unwrap(),
        vec![("DATABASE_URL", database_url)],
    );
    assert_success(&validate);
    assert_eq!(
        decode_control_result(&validate.stdout).unwrap().outcome,
        ControlOutcome::Succeeded
    );
    fs::remove_dir_all(root).unwrap();
}
