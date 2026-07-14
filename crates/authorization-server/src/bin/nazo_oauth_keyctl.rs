#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazo_oauth_server::keyctl::run(std::env::args()).await
}
