use std::fs;

use super::*;

#[test]
fn providers_split_secrets_from_non_secret_connection_parameters() {
    let work = PrivateTempDir::new("nazoauth-provider-test").unwrap();
    let postgres = work.path().join("postgres");
    fs::write(
        &postgres,
        "postgresql://alice:p%40ss@db.example:5544/oauth?sslmode=require",
    )
    .unwrap();
    let provider = PostgresProvider::from_url_file(&postgres).unwrap();
    let service = fs::read_to_string(provider.service_file()).unwrap();
    let pass = fs::read_to_string(provider.password_file()).unwrap();
    assert!(!service.contains("p@ss"));
    assert!(service.contains("sslmode='require'"));
    assert!(pass.ends_with(":p@ss\n"));

    let valkey = work.path().join("valkey");
    fs::write(&valkey, "rediss://default:s%3Aecret@cache.example:6380/2").unwrap();
    let provider = ValkeyProvider::from_url_file(&valkey).unwrap();
    assert_eq!(provider.host, "cache.example");
    assert_eq!(provider.password_stdin(), b"s:ecret\n");
    assert!(provider.tls);
}
