#![forbid(unsafe_code)]

use std::sync::Arc;

use nazo_oauth_server_postgres::PostgresLauncher;
use nazo_oauth_server_valkey::ValkeyTransientStateLauncher;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazo_oauth_server::cli::run(
        std::env::args(),
        Arc::new(PostgresLauncher),
        Arc::new(ValkeyTransientStateLauncher),
    )
    .await
}
