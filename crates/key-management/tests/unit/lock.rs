use std::{collections::BTreeSet, time::Duration};

use nazo_auth::SigningPurpose;

use super::*;
use crate::{KeyManager, KeySettings, LocalKeyRegistration};

#[tokio::test]
async fn lifecycle_and_registration_share_the_keyset_write_lock() {
    let keys_dir = std::env::temp_dir().join(format!("nazo-keyset-lock-{}", uuid::Uuid::now_v7()));
    let settings = KeySettings {
        keys_dir: keys_dir.clone(),
        external_command: Vec::new(),
        external_timeout: Duration::from_secs(2),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    KeyManager::load_or_create(settings.clone())
        .await
        .expect("initial keyset should be created");

    let keyset_path = keys_dir.join("keyset.json");
    let mut keyset: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&keyset_path)
            .await
            .expect("keyset should be readable"),
    )
    .expect("keyset should be valid JSON");
    keyset["keys"]
        .as_array_mut()
        .expect("keyset should contain keys")
        .retain(|key| key.get("alg").and_then(serde_json::Value::as_str) != Some("PS256"));
    crate::serialization::write_json_atomic(&keyset_path, &keyset)
        .await
        .expect("test should remove the PS256 key");

    let lock = acquire_keyset_lock(&keys_dir)
        .await
        .expect("test should acquire the keyset lock");
    let lifecycle_settings = settings.clone();
    let mut lifecycle =
        tokio::spawn(async move { KeyManager::load_or_create(lifecycle_settings).await });
    let registration_settings = settings.clone();
    let mut registration = tokio::spawn(async move {
        KeyManager::register_local(
            &registration_settings,
            LocalKeyRegistration {
                algorithm: jsonwebtoken::Algorithm::ES256,
                purposes: BTreeSet::from([
                    SigningPurpose::Credential,
                    SigningPurpose::PresentationRequest,
                ]),
            },
        )
        .await
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut lifecycle)
            .await
            .is_err(),
        "lifecycle must wait for the keyset lock"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut registration)
            .await
            .is_err(),
        "registration must wait for the same keyset lock"
    );
    drop(lock);

    lifecycle
        .await
        .expect("lifecycle task should finish")
        .expect("lifecycle should restore PS256");
    registration
        .await
        .expect("registration task should finish")
        .expect("registration should add ES256");

    let keyset: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&keyset_path)
            .await
            .expect("keyset should remain readable"),
    )
    .expect("keyset should remain valid JSON");
    let keys = keyset["keys"]
        .as_array()
        .expect("keyset should contain keys");
    assert!(
        keys.iter()
            .any(|key| key.get("alg").and_then(serde_json::Value::as_str) == Some("PS256"))
    );
    assert!(keys.iter().any(|key| {
        key.get("alg").and_then(serde_json::Value::as_str) == Some("ES256")
            && key
                .get("purposes")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|purposes| {
                    purposes.iter().any(|purpose| purpose == "credential")
                        && purposes
                            .iter()
                            .any(|purpose| purpose == "presentation_request")
                })
    }));

    tokio::fs::remove_dir_all(keys_dir)
        .await
        .expect("test key directory should be removable");
}
