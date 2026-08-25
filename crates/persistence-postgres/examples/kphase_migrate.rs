//! K-phase helper: apply the embedded application migrations to a database
//! once, so DB-gated integration suites have their schema in place.
use anyhow::Context as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .context("set NAZO_TEST_DATABASE_URL")?;
    let applied = nazo_postgres::run_pending_migrations(&url).await?;
    println!("migrations applied: {applied}");
    Ok(())
}
