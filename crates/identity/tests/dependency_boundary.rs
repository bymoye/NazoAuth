use std::{path::Path, process::Command};

use serde_json::Value;

#[test]
fn identity_has_no_auth_framework_or_storage_dependencies() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_manifest = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("identity crate must be nested under the workspace crates directory")
        .join("Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(workspace_manifest)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must emit valid JSON");
    let package = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package["name"] == "nazo-identity")
        })
        .expect("cargo metadata must contain nazo-identity");
    let dependencies = package["dependencies"]
        .as_array()
        .expect("package dependencies must be an array");
    let forbidden = [
        "actix-web",
        "diesel",
        "diesel-async",
        "fred",
        "nazo-auth",
        "nazo-oauth-server",
    ];

    for dependency in dependencies {
        let name = dependency["name"]
            .as_str()
            .expect("dependency name must be a string");
        assert!(
            !forbidden.contains(&name),
            "nazo-identity must not depend on {name}"
        );
    }
}
