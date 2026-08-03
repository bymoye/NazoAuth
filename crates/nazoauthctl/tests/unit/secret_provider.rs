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
    assert!(service.contains("host=db.example\n"));
    assert!(service.contains("port=5544\n"));
    assert!(service.contains("dbname=oauth\n"));
    assert!(service.contains("user=alice\n"));
    assert!(service.contains("sslmode=require\n"));
    assert!(pass.ends_with(":p@ss\n"));

    let valkey = work.path().join("valkey");
    fs::write(&valkey, "rediss://default:s%3Aecret@cache.example:6380/2").unwrap();
    let provider = ValkeyProvider::from_url_file(&valkey).unwrap();
    assert_eq!(provider.host, "cache.example");
    assert_eq!(provider.password_stdin(), b"s:ecret\n");
    assert!(provider.tls);
}

#[test]
fn postgres_provider_rejects_values_service_files_cannot_represent() {
    let work = PrivateTempDir::new("nazoauth-provider-invalid-service-test").unwrap();
    for (name, url) in [
        (
            "newline",
            "postgresql://alice:p%40ss@db.example/oauth?application_name=line%0Abreak",
        ),
        (
            "trailing-space",
            "postgresql://alice%20:p%40ss@db.example/oauth",
        ),
        (
            "nul",
            "postgresql://alice:p%40ss@db.example/oauth?application_name=a%00b",
        ),
    ] {
        let path = work.path().join(name);
        fs::write(&path, url).unwrap();
        let error = PostgresProvider::from_url_file(&path).err().unwrap();
        assert!(error.to_string().contains("cannot be represented safely"));
    }
}
