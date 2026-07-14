#![forbid(unsafe_code)]

use nazo_oauth_server::config::{ConfigSource, database_url};

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let database_url = database_url(&config);
    nazo_postgres::run_pending_migrations(&database_url).await?;
    nazo_postgres::cleanup_expired_security_state(&database_url).await?;
    Ok(())
}
