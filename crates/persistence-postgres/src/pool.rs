use diesel::ConnectionError;
use diesel_async::{
    AsyncMigrationHarness, AsyncPgConnection,
    pooled_connection::{
        AsyncDieselConnectionManager, ManagerConfig, deadpool::Object, deadpool::Pool,
    },
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use futures_util::FutureExt as _;
use serde::Serialize;
use std::{
    str::FromStr as _,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

pub type DbPool = Pool<AsyncPgConnection>;
pub type DbConnection = Object<AsyncPgConnection>;

static DB_POOL_ACQUIRE_COUNT: AtomicU64 = AtomicU64::new(0);
static DB_POOL_WAIT_NANOS_TOTAL: AtomicU64 = AtomicU64::new(0);
static DB_POOL_WAIT_NANOS_MAX: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
pub struct DbPoolMetrics {
    pub acquire_count: u64,
    pub wait_nanos_total: u64,
    pub wait_nanos_max: u64,
}

pub fn create_pool(
    database_url: impl Into<String>,
    max_connections: usize,
) -> anyhow::Result<DbPool> {
    let manager = connection_manager(database_url.into());
    Ok(Pool::builder(manager).max_size(max_connections).build()?)
}

fn connection_manager(database_url: String) -> AsyncDieselConnectionManager<AsyncPgConnection> {
    let mut config = ManagerConfig::default();
    config.custom_setup = Box::new(|url| {
        let url = url.to_owned();
        async move { establish_connection(&url).await }.boxed()
    });
    AsyncDieselConnectionManager::new_with_config(database_url, config)
}

async fn establish_connection(database_url: &str) -> diesel::ConnectionResult<AsyncPgConnection> {
    let config = tokio_postgres::Config::from_str(database_url)
        .map_err(|error| ConnectionError::InvalidConnectionUrl(error.to_string()))?;
    if config.get_ssl_mode() == tokio_postgres::config::SslMode::Disable {
        let (client, connection) = config
            .connect(tokio_postgres::NoTls)
            .await
            .map_err(|error| ConnectionError::BadConnection(error.to_string()))?;
        return AsyncPgConnection::try_from_client_and_connection(client, connection).await;
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let tls = match tokio_postgres_rustls::MakeRustlsConnect::with_native_certs() {
        Ok((tls, certificate_errors)) => {
            if !certificate_errors.is_empty() {
                tracing::warn!(
                    error_count = certificate_errors.len(),
                    "some platform TLS trust roots could not be loaded"
                );
            }
            tls
        }
        Err(certificate_errors) => {
            tracing::warn!(
                error_count = certificate_errors.len(),
                "platform TLS trust store is empty; using bundled WebPKI roots for PostgreSQL"
            );
            tokio_postgres_rustls::MakeRustlsConnect::with_webpki_roots()
        }
    };
    let (client, connection) = config
        .connect(tls)
        .await
        .map_err(|error| ConnectionError::BadConnection(error.to_string()))?;
    AsyncPgConnection::try_from_client_and_connection(client, connection).await
}

pub async fn get_conn(pool: &DbPool) -> anyhow::Result<DbConnection> {
    let started = Instant::now();
    let connection = pool.get().await;
    let wait_nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    DB_POOL_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);
    DB_POOL_WAIT_NANOS_TOTAL.fetch_add(wait_nanos, Ordering::Relaxed);
    let _ = DB_POOL_WAIT_NANOS_MAX.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (wait_nanos > current).then_some(wait_nanos)
    });
    Ok(connection?)
}

/// Performs a real database round trip used by readiness probes.
pub async fn health_check(pool: &DbPool) -> anyhow::Result<()> {
    use diesel_async::RunQueryDsl as _;

    let mut connection = get_conn(pool).await?;
    diesel::sql_query("SELECT 1")
        .execute(&mut connection)
        .await?;
    Ok(())
}

#[must_use]
pub fn db_pool_metrics() -> DbPoolMetrics {
    DbPoolMetrics {
        acquire_count: DB_POOL_ACQUIRE_COUNT.load(Ordering::Relaxed),
        wait_nanos_total: DB_POOL_WAIT_NANOS_TOTAL.load(Ordering::Relaxed),
        wait_nanos_max: DB_POOL_WAIT_NANOS_MAX.load(Ordering::Relaxed),
    }
}

pub async fn run_pending_migrations(database_url: &str) -> anyhow::Result<()> {
    use diesel_async::RunQueryDsl as _;

    let mut connection = establish_connection(database_url).await?;
    // Serialize application-managed migrations across concurrent first
    // starts. PostgreSQL releases this session lock if the process exits.
    diesel::sql_query("SELECT pg_advisory_lock(564196923451771041)")
        .execute(&mut connection)
        .await?;
    AsyncMigrationHarness::new(connection)
        .run_pending_migrations(MIGRATIONS)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}

pub async fn cleanup_expired_security_state(database_url: &str) -> anyhow::Result<()> {
    use diesel_async::RunQueryDsl as _;

    let mut connection = establish_connection(database_url).await?;
    diesel::sql_query("SELECT * FROM nazo_oauth_cleanup_expired_security_state()")
        .execute(&mut connection)
        .await?;
    Ok(())
}
