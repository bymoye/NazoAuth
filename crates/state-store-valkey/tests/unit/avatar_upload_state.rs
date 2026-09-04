use super::*;
use crate::ErrorKind;
use std::time::Duration;

fn authorization() -> AvatarUploadAuthorization {
    AvatarUploadAuthorization {
        upload_id: Uuid::now_v7().to_string(),
        tenant_id: TenantId::new(Uuid::from_u128(1)).unwrap(),
        user_id: UserId::new(Uuid::now_v7()).unwrap(),
        expected_avatar_url: None,
        staging_object_id: Uuid::now_v7().to_string(),
        expires_at: Utc::now() + chrono::Duration::minutes(1),
    }
}

#[test]
fn persisted_authorization_rejects_invalid_identity_and_expiry() {
    let original = serde_json::to_value(AvatarUploadWireState::from(&authorization())).unwrap();
    for (field, value) in [
        ("tenant_id", serde_json::json!(Uuid::nil())),
        ("user_id", serde_json::json!(Uuid::nil())),
        ("expires_at", serde_json::json!(i64::MAX)),
    ] {
        let mut malformed = original.clone();
        malformed[field] = value;
        let wire: AvatarUploadAuthorizationWire = serde_json::from_value(malformed).unwrap();
        assert_eq!(
            AvatarUploadAuthorization::try_from(wire)
                .unwrap_err()
                .kind(),
            ErrorKind::CorruptData
        );
    }
}

#[tokio::test]
async fn malformed_upload_state_cannot_be_claimed_or_published() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let connection = crate::test_support::scoped_connect(&url, Duration::from_secs(5))
        .await
        .expect("configured Valkey must be available");
    let store = AvatarUploadStateStore::new(&connection);
    let authorization = authorization();
    let key = AvatarUploadStateStore::key(&authorization.upload_id);
    command::set_ex_string(&connection, key.clone(), "not-json".to_owned(), 60)
        .await
        .unwrap();
    let lease = Utc::now() + chrono::Duration::seconds(30);
    assert_eq!(
        store
            .claim(authorization.user_id, &authorization.upload_id, lease)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::CorruptData
    );
    assert_eq!(
        store
            .record_candidate(
                authorization.user_id,
                &authorization.upload_id,
                "1",
                "etag",
                "final"
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::CorruptData
    );
    assert_eq!(
        store
            .transition(
                COMPLETE_SCRIPT,
                authorization.user_id,
                &authorization.upload_id,
                "1",
                Some("final")
            )
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::CorruptData
    );
    let mut malformed = serde_json::to_value(AvatarUploadWireState::from(&authorization)).unwrap();
    malformed["tenant_id"] = serde_json::json!(Uuid::nil());
    command::set_ex_string(&connection, key, malformed.to_string(), 60)
        .await
        .unwrap();
    assert_eq!(
        store
            .claim(authorization.user_id, &authorization.upload_id, lease)
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::CorruptData
    );
}

#[tokio::test]
async fn upload_authorization_is_create_once_and_expiry_is_authoritative() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let connection = crate::test_support::scoped_connect(&url, Duration::from_secs(5))
        .await
        .expect("configured Valkey must be available");
    let store = AvatarUploadStateStore::new(&connection);
    let mut authorization = authorization();
    authorization.expires_at = Utc::now() - chrono::Duration::seconds(1);
    AvatarUploadStatePort::create(&store, &authorization, 60)
        .await
        .unwrap();
    assert!(matches!(
        AvatarUploadStatePort::create(&store, &authorization, 60).await,
        Err(RepositoryError::Conflict)
    ));
    assert_eq!(
        store
            .claim(authorization.user_id, &authorization.upload_id, Utc::now())
            .await
            .unwrap(),
        AvatarUploadClaim::Missing
    );
    assert!(
        !AvatarUploadStatePort::complete(
            &store,
            authorization.user_id,
            &authorization.upload_id,
            "1",
            "final"
        )
        .await
        .unwrap()
    );
}
