use std::{
    fs,
    path::{Path, PathBuf},
};

fn append_rust_sources(path: &Path, sources: &mut String) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            append_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push_str(&fs::read_to_string(path).unwrap());
        }
    }
}

#[test]
fn transport_crate_has_no_infrastructure_or_configuration_dependencies() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let mut sources = String::new();
    append_rust_sources(&root.join("src"), &mut sources);
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
