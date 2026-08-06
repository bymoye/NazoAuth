fn function_source<'a>(source: &'a str, name: &str, next_name: Option<&str>) -> &'a str {
    let start = source
        .find(&format!("pub async fn {name}"))
        .unwrap_or_else(|| panic!("{name} must remain a public async function"));
    let source = &source[start..];
    next_name
        .and_then(|next| source.find(&format!("pub async fn {next}")))
        .map_or(source, |end| &source[..end])
}

#[test]
fn pool_admin_operations_keep_async_rustls_and_isolate_the_migration_harness() {
    let source = include_str!("../src/pool.rs");
    let migrations = function_source(
        source,
        "run_pending_migrations",
        Some("cleanup_expired_security_state"),
    );
    let cleanup = function_source(source, "cleanup_expired_security_state", None);

    for (name, operation) in [
        ("run_pending_migrations", migrations),
        ("cleanup_expired_security_state", cleanup),
    ] {
        assert!(
            operation.contains("establish_connection(database_url).await?"),
            "{name} must use the shared async PostgreSQL TLS connection path"
        );
        for synchronous_connection in ["diesel::PgConnection", "diesel::pg::PgConnection"] {
            assert!(
                !operation.contains(synchronous_connection),
                "{name} must not reintroduce the synchronous libpq connection path"
            );
        }
    }

    assert!(source.contains("MakeRustlsConnect::with_native_certs"));
    assert!(source.contains("AsyncPgConnection::try_from_client_and_connection"));
    assert!(migrations.contains("tokio::task::spawn_blocking"));
    assert!(migrations.contains("tokio::runtime::Builder::new_multi_thread"));
    assert!(migrations.contains(".worker_threads(1)"));
    assert!(migrations.contains("runtime.block_on(run_pending_migrations_inner(&database_url))"));
    assert!(migrations.contains("AsyncMigrationHarness::new(connection)"));
    assert!(!cleanup.contains("spawn_blocking"));
    assert!(migrations.contains("SET SESSION lock_timeout"));
    assert!(migrations.contains("SET SESSION statement_timeout"));
    assert!(migrations.contains("pg_try_advisory_lock"));
    assert!(migrations.contains("pg_advisory_unlock"));
    assert!(migrations.contains("!applied.is_empty()"));
    assert!(cleanup.contains("SET SESSION statement_timeout"));
}

#[tokio::test(flavor = "current_thread")]
async fn migrations_run_from_a_current_thread_runtime() {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if database_url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI migration runtime tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    let Some(database_url) = database_url else {
        return;
    };

    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("the isolated migration harness should run from a current-thread Tokio runtime");
}

#[tokio::test(flavor = "current_thread")]
async fn pool_admin_operation_errors_remain_typed_across_runtime_boundaries() {
    let invalid_url = "postgres://127.0.0.1:not-a-port/database";

    let migration_error = nazo_postgres::run_pending_migrations(invalid_url)
        .await
        .expect_err("an invalid URL must fail migration connection setup");
    assert!(
        migration_error
            .downcast_ref::<diesel::ConnectionError>()
            .is_some(),
        "the migration operation error must not be replaced by a task-join error"
    );

    let cleanup_error = nazo_postgres::cleanup_expired_security_state(invalid_url)
        .await
        .expect_err("an invalid URL must fail cleanup connection setup");
    assert!(
        cleanup_error
            .downcast_ref::<diesel::ConnectionError>()
            .is_some(),
        "the cleanup operation error must not be replaced by a task-join error"
    );
}
