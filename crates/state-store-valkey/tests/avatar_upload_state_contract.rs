use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use nazo_identity::{
    AvatarUploadAuthorization, AvatarUploadClaim, TenantId, UserId, ports::AvatarUploadStatePort,
};
use nazo_valkey::AvatarUploadStateStore;
use uuid::Uuid;

async fn setup() -> Option<AvatarUploadStateStore> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    Some(AvatarUploadStateStore::new(&connection))
}

fn tenant(value: u128) -> TenantId {
    TenantId::new(Uuid::from_u128(value)).expect("test tenant")
}

fn user(value: u128) -> UserId {
    UserId::new(Uuid::from_u128(value)).expect("test user")
}

fn authorization(upload_id: String, user_id: UserId) -> AvatarUploadAuthorization {
    AvatarUploadAuthorization {
        upload_id: upload_id.clone(),
        tenant_id: tenant(1),
        user_id,
        expected_avatar_url: Some(format!("https://images.example.test/{upload_id}")),
        staging_object_id: format!("staging/{upload_id}"),
        expires_at: Utc::now() + ChronoDuration::seconds(60),
    }
}

#[tokio::test]
async fn avatar_upload_claims_are_leased_and_owner_fenced() {
    let Some(store) = setup().await else {
        return;
    };
    let user_id = user(2);
    let authorization = authorization(format!("upload-{}", Uuid::now_v7()), user_id);
    AvatarUploadStatePort::create(&store, &authorization, 60)
        .await
        .expect("create upload authorization");

    let AvatarUploadClaim::Pending {
        authorization: claimed,
        ownership_token,
    } = AvatarUploadStatePort::claim(
        &store,
        user_id,
        &authorization.upload_id,
        Utc::now() + ChronoDuration::seconds(60),
    )
    .await
    .expect("claim upload authorization")
    else {
        panic!("first owner must obtain the pending authorization");
    };
    assert_eq!(claimed, authorization);
    assert!(!ownership_token.is_empty());

    assert_eq!(
        AvatarUploadStatePort::claim(
            &store,
            user_id,
            &authorization.upload_id,
            Utc::now() + ChronoDuration::seconds(60),
        )
        .await
        .expect("concurrent claim"),
        AvatarUploadClaim::Busy
    );
    assert!(
        !AvatarUploadStatePort::record_candidate(
            &store,
            user_id,
            &authorization.upload_id,
            "stale-owner",
            "version-first",
            "final/first",
        )
        .await
        .expect("stale owner must be rejected")
    );
    assert!(
        AvatarUploadStatePort::record_candidate(
            &store,
            user_id,
            &authorization.upload_id,
            &ownership_token,
            "version-first",
            "final/first",
        )
        .await
        .expect("owner records immutable candidate")
    );
    assert!(
        AvatarUploadStatePort::release(
            &store,
            user_id,
            &authorization.upload_id,
            &ownership_token,
        )
        .await
        .expect("owner releases publishing lease")
    );
    let AvatarUploadClaim::Publishing {
        authorization: resumed,
        ownership_token: resumed_owner,
        staged_version,
        final_object_id,
    } = AvatarUploadStatePort::claim(
        &store,
        user_id,
        &authorization.upload_id,
        Utc::now() + ChronoDuration::seconds(60),
    )
    .await
    .expect("reclaim publishing candidate")
    else {
        panic!("released candidate must be resumable");
    };
    assert_eq!(resumed, authorization);
    assert_eq!(staged_version, "version-first");
    assert_eq!(final_object_id, "final/first");
    assert_ne!(resumed_owner, ownership_token);
    assert!(
        !AvatarUploadStatePort::complete(
            &store,
            user_id,
            &authorization.upload_id,
            &ownership_token,
            "final/first",
        )
        .await
        .expect("released owner must be fenced")
    );
    assert!(
        AvatarUploadStatePort::complete(
            &store,
            user_id,
            &authorization.upload_id,
            &resumed_owner,
            "final/first",
        )
        .await
        .expect("resumed owner completes")
    );
    assert_eq!(
        AvatarUploadStatePort::claim(
            &store,
            user_id,
            &authorization.upload_id,
            Utc::now() + ChronoDuration::seconds(60),
        )
        .await
        .expect("completed claim"),
        AvatarUploadClaim::Completed {
            final_object_id: "final/first".to_owned(),
        }
    );
    assert!(
        AvatarUploadStatePort::complete(
            &store,
            user_id,
            &authorization.upload_id,
            &resumed_owner,
            "final/first",
        )
        .await
        .expect("matching completion retry")
    );
    assert!(
        !AvatarUploadStatePort::complete(
            &store,
            user_id,
            &authorization.upload_id,
            &resumed_owner,
            "final/different",
        )
        .await
        .expect("different completion retry must be rejected")
    );
}

#[tokio::test]
async fn avatar_upload_release_and_expired_lease_allow_a_new_owner() {
    let Some(store) = setup().await else {
        return;
    };
    let user_id = user(3);
    let authorization = authorization(format!("upload-{}", Uuid::now_v7()), user_id);
    AvatarUploadStatePort::create(&store, &authorization, 60)
        .await
        .expect("create upload authorization");

    let AvatarUploadClaim::Pending {
        ownership_token: first_owner,
        ..
    } = AvatarUploadStatePort::claim(
        &store,
        user_id,
        &authorization.upload_id,
        Utc::now() - ChronoDuration::seconds(1),
    )
    .await
    .expect("first claim")
    else {
        panic!("first claim must obtain a lease");
    };
    let AvatarUploadClaim::Pending {
        ownership_token: second_owner,
        ..
    } = AvatarUploadStatePort::claim(
        &store,
        user_id,
        &authorization.upload_id,
        Utc::now() + ChronoDuration::seconds(60),
    )
    .await
    .expect("expired lease claim")
    else {
        panic!("expired lease must be reclaimed");
    };
    assert_ne!(first_owner, second_owner);
    assert!(
        !AvatarUploadStatePort::release(&store, user_id, &authorization.upload_id, &first_owner,)
            .await
            .expect("stale release must be fenced")
    );
    assert!(
        AvatarUploadStatePort::release(&store, user_id, &authorization.upload_id, &second_owner,)
            .await
            .expect("owner releases")
    );
    assert_eq!(
        AvatarUploadStatePort::claim(
            &store,
            user(4),
            &authorization.upload_id,
            Utc::now() + ChronoDuration::seconds(60),
        )
        .await
        .expect("other user claim"),
        AvatarUploadClaim::Missing
    );
}
