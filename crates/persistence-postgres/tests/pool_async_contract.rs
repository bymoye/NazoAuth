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
fn synchronous_pool_admin_operations_run_on_blocking_workers() {
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
        let copied_url = operation
            .find("database_url.to_owned()")
            .unwrap_or_else(|| panic!("{name} must own its URL before spawning"));
        let blocking_worker = operation
            .find("tokio::task::spawn_blocking")
            .unwrap_or_else(|| panic!("{name} must offload synchronous Diesel work"));
        let sync_connection = operation
            .find("diesel::PgConnection::establish")
            .unwrap_or_else(|| panic!("{name} must retain its synchronous Diesel operation"));

        assert!(copied_url < blocking_worker);
        assert!(blocking_worker < sync_connection);
        assert!(
            operation.contains(".await??"),
            "{name} must flatten both the blocking-task and operation results"
        );
    }
}

#[tokio::test]
async fn pool_admin_operation_errors_survive_the_blocking_task_boundary() {
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
