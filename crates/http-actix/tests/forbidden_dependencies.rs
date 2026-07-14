use std::{fs, path::PathBuf};

#[test]
fn transport_crate_has_no_infrastructure_or_configuration_dependencies() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let sources = fs::read_dir(root.join("src"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect::<String>();
    let forbidden = [
        "diesel",
        "diesel_async",
        "fred",
        "nazo-postgres",
        "nazo-valkey",
        "DbPool",
        "AppState",
        "ConfigSource",
        "std::env",
    ];
    for token in forbidden {
        assert!(
            !manifest.contains(token) && !sources.contains(token),
            "transport boundary contains forbidden token {token}"
        );
    }
}
