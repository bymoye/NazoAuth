use std::{collections::BTreeSet, time::Duration};

use nazo_auth::{SignError, SignRequest, Signer, SigningPurpose};
use nazo_key_management::{KeyManager, KeyRecordStatus, KeySettings, LocalKeyRegistration};
use serde_json::Value;
use uuid::Uuid;

fn settings(keys_dir: std::path::PathBuf) -> KeySettings {
    KeySettings {
        keys_dir,
        external_command: Vec::new(),
        external_timeout: Duration::from_secs(2),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    }
}

#[tokio::test]
async fn purpose_scoped_key_signs_only_declared_openid4vc_purposes() {
    let directory =
        std::env::temp_dir().join(format!("nazo-purpose-scoped-key-{}", Uuid::now_v7()));
    let settings = settings(directory.clone());
    let initial = KeyManager::load_or_create(settings.clone()).await.unwrap();
    let active_kid = initial.snapshot().active_kid.clone();
    drop(initial);

    let purposes = [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let scoped_kid = KeyManager::register_local(
        &settings,
        LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes,
        },
    )
    .await
    .unwrap();
    let retried_kid = KeyManager::register_local(
        &settings,
        LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [
                SigningPurpose::Credential,
                SigningPurpose::PresentationRequest,
            ]
            .into_iter()
            .collect(),
        },
    )
    .await
    .expect("an exact purpose-scoped registration retry must be idempotent");
    assert_eq!(retried_kid, scoped_kid);
    let manager = KeyManager::load_or_create(settings.clone()).await.unwrap();

    for purpose in [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ] {
        assert!(
            manager
                .sign(SignRequest {
                    purpose,
                    algorithm: "ES256",
                    signing_input: b"header.payload",
                })
                .await
                .is_ok()
        );
    }
    for purpose in [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
    ] {
        assert_eq!(
            manager
                .sign(SignRequest {
                    purpose,
                    algorithm: "ES256",
                    signing_input: b"header.payload",
                })
                .await,
            Err(SignError::KeyUnavailable)
        );
    }
    assert_eq!(manager.snapshot().active_kid, active_kid);
    let snapshot = manager.snapshot();
    let scoped = snapshot.verification_key(&scoped_kid).unwrap();
    assert!(scoped.can_sign(SigningPurpose::Credential));
    assert!(!scoped.can_sign(SigningPurpose::IdToken));
    assert_eq!(
        KeyManager::list_keys(&settings)
            .await
            .unwrap()
            .into_iter()
            .find(|key| key.kid == scoped_kid)
            .unwrap()
            .status,
        KeyRecordStatus::PurposeScoped
    );

    let payload: Value = serde_json::from_slice(
        &tokio::fs::read(directory.join("keyset.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let entry = payload["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kid"] == scoped_kid)
        .unwrap();
    assert_eq!(
        entry["purposes"],
        serde_json::json!(["credential", "presentation_request"])
    );

    let mut rotation_due = payload;
    rotation_due["keys"][0]["created_at"] =
        serde_json::json!((chrono::Utc::now() - chrono::Duration::days(180)).to_rfc3339());
    tokio::fs::write(
        directory.join("keyset.json"),
        serde_json::to_vec_pretty(&rotation_due).unwrap(),
    )
    .await
    .unwrap();
    let mut due_settings = settings.clone();
    due_settings.rotation_interval = chrono::Duration::days(90);
    let reloaded = KeyManager::load_or_create(due_settings).await.unwrap();
    assert_eq!(
        reloaded.snapshot().active_kid,
        active_kid,
        "purpose-scoped keys must never be promoted into the OIDC rotation slot"
    );

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn overlapping_purpose_scoped_keys_are_rejected() {
    let directory =
        std::env::temp_dir().join(format!("nazo-purpose-scoped-duplicate-{}", Uuid::now_v7()));
    let settings = settings(directory.clone());
    KeyManager::load_or_create(settings.clone()).await.unwrap();
    KeyManager::register_local(
        &settings,
        LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [SigningPurpose::Credential].into_iter().collect(),
        },
    )
    .await
    .unwrap();

    let error = KeyManager::register_local(
        &settings,
        LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [
                SigningPurpose::Credential,
                SigningPurpose::PresentationRequest,
            ]
            .into_iter()
            .collect(),
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("already covers"));

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn purpose_scoped_registration_rejects_oidc_signing_purposes() {
    let directory = std::env::temp_dir().join(format!(
        "nazo-purpose-scoped-oidc-rejected-{}",
        Uuid::now_v7()
    ));
    let settings = settings(directory.clone());
    KeyManager::load_or_create(settings.clone()).await.unwrap();

    let error = KeyManager::register_local(
        &settings,
        LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [SigningPurpose::IdToken].into_iter().collect(),
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("restricted"));

    tokio::fs::remove_dir_all(directory).await.unwrap();
}
