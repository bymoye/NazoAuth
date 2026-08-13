use super::*;

#[test]
fn refresh_interval_is_bounded_by_prepublish_window() {
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(86_400)),
        Duration::from_secs(3_600)
    );
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(30)),
        Duration::from_secs(15)
    );
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(1)),
        Duration::from_secs(1)
    );
}

#[test]
fn refresh_failure_backoff_is_bounded() {
    assert_eq!(
        next_failure_backoff(Duration::from_secs(1)),
        Duration::from_secs(2)
    );
    assert_eq!(
        next_failure_backoff(Duration::from_secs(32)),
        Duration::from_secs(60)
    );
    assert_eq!(
        next_failure_backoff(Duration::from_secs(60)),
        Duration::from_secs(60)
    );
}

#[tokio::test]
async fn lifecycle_stops_when_requested() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let task = tokio::spawn(manager.clone().run_lifecycle());

    manager.stop_lifecycle();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("lifecycle should observe shutdown")
        .expect("lifecycle task should stop cleanly");
}

#[tokio::test]
async fn refresh_failure_keeps_last_generation_and_recovers() {
    let directory =
        std::env::temp_dir().join(format!("nazo-key-lifecycle-{}", uuid::Uuid::now_v7()));
    let settings = KeySettings {
        keys_dir: directory.clone(),
        external_command: Vec::new(),
        external_timeout: Duration::from_secs(2),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let manager = KeyManager::load_or_create(settings)
        .await
        .expect("test keyset should load");
    let keyset_path = directory.join("keyset.json");
    let original = tokio::fs::read(&keyset_path)
        .await
        .expect("test keyset should be readable");
    let previous_kid = manager.snapshot().active_kid.clone();

    tokio::fs::write(&keyset_path, b"not-json")
        .await
        .expect("test keyset should be corruptible");
    assert!(manager.refresh().await.is_err());
    assert_eq!(manager.health().status, KeyHealthStatus::Unhealthy);
    assert_eq!(manager.snapshot().active_kid, previous_kid);
    assert!(
        manager
            .sign(SignRequest {
                purpose: SigningPurpose::AccessToken,
                algorithm: "RS256",
                signing_input: b"must-fail-closed",
            })
            .await
            .is_err()
    );

    tokio::fs::write(&keyset_path, original)
        .await
        .expect("test keyset should be restorable");
    manager.refresh().await.expect("refresh should recover");
    assert_eq!(manager.health(), KeyHealth::healthy());
    assert!(
        manager
            .sign(SignRequest {
                purpose: SigningPurpose::AccessToken,
                algorithm: "RS256",
                signing_input: b"must-sign-after-recovery",
            })
            .await
            .is_ok()
    );

    tokio::fs::remove_dir_all(directory)
        .await
        .expect("test keyset directory should be removable");
}
