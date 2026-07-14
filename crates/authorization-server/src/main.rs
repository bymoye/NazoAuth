#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazo_oauth_server::bootstrap::run().await
}
