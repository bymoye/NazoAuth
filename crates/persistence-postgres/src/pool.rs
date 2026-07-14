use diesel::Connection;
use diesel_async::{
    AsyncPgConnection,
    pooled_connection::{AsyncDieselConnectionManager, deadpool::Object, deadpool::Pool},
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use serde::Serialize;
use std::{
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
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url.into());
    Ok(Pool::builder(manager).max_size(max_connections).build()?)
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

#[must_use]
pub fn db_pool_metrics() -> DbPoolMetrics {
    DbPoolMetrics {
        acquire_count: DB_POOL_ACQUIRE_COUNT.load(Ordering::Relaxed),
        wait_nanos_total: DB_POOL_WAIT_NANOS_TOTAL.load(Ordering::Relaxed),
        wait_nanos_max: DB_POOL_WAIT_NANOS_MAX.load(Ordering::Relaxed),
    }
}

pub async fn run_pending_migrations(database_url: &str) -> anyhow::Result<()> {
    let database_url = database_url.to_owned();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut connection = diesel::PgConnection::establish(&database_url)?;
        connection
            .run_pending_migrations(MIGRATIONS)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(())
    })
    .await??;
    Ok(())
}

pub async fn cleanup_expired_security_state(database_url: &str) -> anyhow::Result<()> {
    let database_url = database_url.to_owned();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use diesel::RunQueryDsl;

        let mut connection = diesel::PgConnection::establish(&database_url)?;
        diesel::sql_query("SELECT * FROM nazo_oauth_cleanup_expired_security_state()")
            .execute(&mut connection)?;
        Ok(())
    })
    .await??;
    Ok(())
}
