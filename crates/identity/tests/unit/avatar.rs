use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::ports::{
    AvatarDirectUploadPort, AvatarRepositoryPort, AvatarStagedObject, AvatarStorageFuture,
    AvatarUploadAuthorization, AvatarUploadClaim, AvatarUploadStatePort, AvatarUploadTarget,
    GrantSummaryRepositoryPort, RepositoryFuture,
};
use crate::{AccountIdentity, Principal, TenantContext, UserId, UserProfile, UserRole};
use uuid::Uuid;

#[test]
fn avatar_reference_rejects_extra_query_or_path_components() {
    assert_eq!(avatar_url_version("/auth/me/avatar?v=v1"), Ok("v1"));
    assert!(avatar_url_version("/auth/me/avatar?v=v1&x=1").is_err());
    assert!(avatar_url_version("/auth/me/avatar?v=../x").is_err());
    assert!(avatar_url_version("https://example.com/avatar?v=v1").is_err());
}

#[test]
fn content_detection_uses_file_signatures() {
    fn encode(format: image::ImageFormat) -> Vec<u8> {
        let mut encoded = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(1, 1)
            .write_to(&mut encoded, format)
            .expect("fixture image should encode");
        encoded.into_inner()
    }

    let png = encode(image::ImageFormat::Png);
    let jpeg = encode(image::ImageFormat::Jpeg);
    let webp = encode(image::ImageFormat::WebP);
    assert_eq!(
        AvatarContentType::detect(&png),
        Some(AvatarContentType::Png)
    );
    assert_eq!(
        AvatarContentType::detect(&jpeg),
        Some(AvatarContentType::Jpeg)
    );
    assert_eq!(
        AvatarContentType::detect(&webp),
        Some(AvatarContentType::Webp)
    );
    assert_eq!(
        AvatarContentType::detect(b"\x89PNG\r\n\x1a\nnot-an-image"),
        None
    );
    assert_eq!(AvatarContentType::detect(b"not-an-image"), None);
}

#[test]
fn final_object_identifier_binds_upload_and_exact_bytes() {
    assert_eq!(
        final_object_id("018f-1", b"first"),
        "018f-1-a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e"
    );
    assert_ne!(
        final_object_id("018f-1", b"first"),
        final_object_id("018f-1", b"second")
    );
    assert_ne!(
        final_object_id("018f-1", b"first"),
        final_object_id("018f-2", b"first")
    );
}

#[derive(Clone)]
struct DirectStorage {
    staged: AvatarStagedObject,
    published: Arc<Mutex<Vec<(String, String)>>>,
    authorization_calls: Arc<AtomicUsize>,
}

impl AvatarDirectUploadPort for DirectStorage {
    fn authorize_upload<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _content_length: usize,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AvatarStorageFuture<'a, AvatarUploadTarget> {
        self.authorization_calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async {
            Ok(AvatarUploadTarget {
                url: "https://object-store.test/upload".to_owned(),
                method: "POST".to_owned(),
                headers: Default::default(),
            })
        })
    }

    fn read_staged<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _max_bytes: usize,
    ) -> AvatarStorageFuture<'a, AvatarStagedObject> {
        let staged = self.staged.clone();
        Box::pin(async move { Ok(staged) })
    }

    fn publish_staged<'a>(
        &'a self,
        _staging_object_id: &'a str,
        expected_version: &'a str,
        final_object_id: &'a str,
        _content_type: AvatarContentType,
    ) -> AvatarStorageFuture<'a, ()> {
        let published = self.published.clone();
        let version = expected_version.to_owned();
        let candidate = final_object_id.to_owned();
        Box::pin(async move {
            published.lock().unwrap().push((version, candidate));
            Ok(())
        })
    }

    fn read_final<'a>(
        &'a self,
        _final_object_id: &'a str,
    ) -> AvatarStorageFuture<'a, AvatarObject> {
        let staged = self.staged.clone();
        Box::pin(async move {
            Ok(AvatarObject {
                bytes: staged.bytes,
                content_type: AvatarContentType::Png,
                version: "final".to_owned(),
            })
        })
    }

    fn delete_staging<'a>(&'a self, _staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn delete_final<'a>(&'a self, _final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Default)]
struct DirectState {
    authorization: Arc<Mutex<Option<AvatarUploadAuthorization>>>,
    candidate: Arc<Mutex<Option<(String, String)>>>,
    releases: Arc<AtomicUsize>,
    completed: Arc<Mutex<Option<String>>>,
}

impl AvatarUploadStatePort for DirectState {
    fn create<'a>(
        &'a self,
        authorization: &'a AvatarUploadAuthorization,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        *self.authorization.lock().unwrap() = Some(authorization.clone());
        Box::pin(async { Ok(()) })
    }

    fn claim<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _lease_until: chrono::DateTime<chrono::Utc>,
    ) -> RepositoryFuture<'a, AvatarUploadClaim> {
        let authorization = self.authorization.lock().unwrap().clone();
        let completed = self.completed.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(final_object_id) = completed {
                return Ok(AvatarUploadClaim::Completed { final_object_id });
            }
            Ok(AvatarUploadClaim::Pending {
                authorization: authorization.expect("created authorization"),
                ownership_token: "lease-1".to_owned(),
            })
        })
    }

    fn record_candidate<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        staged_version: &'a str,
        final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        *self.candidate.lock().unwrap() =
            Some((staged_version.to_owned(), final_object_id.to_owned()));
        Box::pin(async { Ok(true) })
    }

    fn complete<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        *self.completed.lock().unwrap() = Some(final_object_id.to_owned());
        Box::pin(async { Ok(true) })
    }

    fn release<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        self.releases.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(true) })
    }
}

#[derive(Clone)]
struct AvatarRepository(Arc<Mutex<PublicAccount>>);

impl AvatarRepositoryPort for AvatarRepository {
    fn compare_and_set_avatar<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        let mut account = self.0.lock().unwrap();
        let result = if account.profile.avatar_url.as_deref() == expected_avatar_url {
            account.profile.avatar_url = avatar_url;
            Some(account.clone())
        } else {
            None
        };
        Box::pin(async move { Ok(result) })
    }
}

struct NoGrants;

impl GrantSummaryRepositoryPort for NoGrants {
    fn authorized_client_count(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        Box::pin(async { Ok(0) })
    }
}

fn direct_account() -> PublicAccount {
    let now = chrono::Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::now_v7()).expect("test user"),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "avatar".to_owned(),
            email: "avatar@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: false,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}

fn direct_service_for_length_test(
    authorization_calls: Arc<AtomicUsize>,
) -> AvatarDirectUploadService {
    let storage = Arc::new(DirectStorage {
        staged: AvatarStagedObject {
            bytes: b"unused until completion".to_vec(),
            version: "etag-length".to_owned(),
        },
        published: Arc::new(Mutex::new(Vec::new())),
        authorization_calls,
    });
    AvatarDirectUploadService::from_ports(
        Arc::new(AvatarRepository(Arc::new(Mutex::new(direct_account())))),
        Arc::new(NoGrants),
        storage,
        Arc::new(DirectState::default()),
        1024,
        300,
        30,
    )
}

#[tokio::test]
async fn direct_upload_rejects_empty_declared_length_before_storage_authorization() {
    let authorization_calls = Arc::new(AtomicUsize::new(0));
    let service = direct_service_for_length_test(authorization_calls.clone());

    assert_eq!(
        service.begin_upload(&direct_account(), 0).await,
        Err(DirectAvatarUploadError::InvalidContentLength)
    );
    assert_eq!(authorization_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn direct_upload_rejects_oversized_declared_length_before_storage_authorization() {
    let authorization_calls = Arc::new(AtomicUsize::new(0));
    let service = direct_service_for_length_test(authorization_calls.clone());

    assert_eq!(
        service.begin_upload(&direct_account(), 1025).await,
        Err(DirectAvatarUploadError::TooLarge)
    );
    assert_eq!(authorization_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn direct_upload_fixes_validated_snapshot_before_database_cas() {
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(1, 1)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .expect("fixture image");
    let account = direct_account();
    let account_store = Arc::new(Mutex::new(account.clone()));
    let published = Arc::new(Mutex::new(Vec::new()));
    let bytes = encoded.into_inner();
    let storage = Arc::new(DirectStorage {
        staged: AvatarStagedObject {
            bytes: bytes.clone(),
            version: "etag-1".to_owned(),
        },
        published: published.clone(),
        authorization_calls: Arc::new(AtomicUsize::new(0)),
    });
    let state = Arc::new(DirectState::default());
    let service = AvatarDirectUploadService::from_ports(
        Arc::new(AvatarRepository(account_store.clone())),
        Arc::new(NoGrants),
        storage,
        state.clone(),
        1024,
        300,
        30,
    );

    let start = service
        .begin_upload(&account, bytes.len())
        .await
        .expect("authorization");
    let overview = service
        .complete_upload(&account, &start.upload_id)
        .await
        .expect("completion");
    let (_, candidate) = state
        .candidate
        .lock()
        .unwrap()
        .clone()
        .expect("fixed candidate");
    assert_eq!(
        published.lock().unwrap().as_slice(),
        &[("etag-1".to_owned(), candidate.clone())]
    );
    assert_eq!(
        overview.account.profile.avatar_url,
        Some(avatar_url(&candidate))
    );
    assert_eq!(
        account_store.lock().unwrap().profile.avatar_url,
        Some(avatar_url(&candidate))
    );
}

#[tokio::test]
async fn direct_upload_releases_pending_claim_after_invalid_staged_bytes() {
    let account = direct_account();
    let published = Arc::new(Mutex::new(Vec::new()));
    let storage = Arc::new(DirectStorage {
        staged: AvatarStagedObject {
            bytes: b"not an image".to_vec(),
            version: "etag-1".to_owned(),
        },
        published: published.clone(),
        authorization_calls: Arc::new(AtomicUsize::new(0)),
    });
    let state = Arc::new(DirectState::default());
    let service = AvatarDirectUploadService::from_ports(
        Arc::new(AvatarRepository(Arc::new(Mutex::new(account.clone())))),
        Arc::new(NoGrants),
        storage,
        state.clone(),
        1024,
        300,
        30,
    );
    let start = service
        .begin_upload(&account, b"not an image".len())
        .await
        .expect("authorization");

    assert_eq!(
        service.complete_upload(&account, &start.upload_id).await,
        Err(DirectAvatarUploadError::UnsupportedContent)
    );
    assert_eq!(state.releases.load(Ordering::Relaxed), 1);
    assert!(published.lock().unwrap().is_empty());
}

#[tokio::test]
async fn direct_upload_retry_from_another_service_returns_the_selected_candidate() {
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(1, 1)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .expect("fixture image");
    let account = direct_account();
    let account_store = Arc::new(Mutex::new(account.clone()));
    let bytes = encoded.into_inner();
    let storage = Arc::new(DirectStorage {
        staged: AvatarStagedObject {
            bytes: bytes.clone(),
            version: "etag-1".to_owned(),
        },
        published: Arc::new(Mutex::new(Vec::new())),
        authorization_calls: Arc::new(AtomicUsize::new(0)),
    });
    let state = Arc::new(DirectState::default());
    let repository = Arc::new(AvatarRepository(account_store.clone()));
    let first = AvatarDirectUploadService::from_ports(
        repository.clone(),
        Arc::new(NoGrants),
        storage.clone(),
        state.clone(),
        1024,
        300,
        30,
    );
    let second = AvatarDirectUploadService::from_ports(
        repository,
        Arc::new(NoGrants),
        storage,
        state,
        1024,
        300,
        30,
    );
    let start = first
        .begin_upload(&account, bytes.len())
        .await
        .expect("authorization");
    let accepted = second
        .complete_upload(&account, &start.upload_id)
        .await
        .expect("second instance completion");
    assert_eq!(
        second
            .read(&accepted.account)
            .await
            .expect("second instance reads final")
            .bytes,
        bytes
    );
    let refreshed = account_store.lock().unwrap().clone();

    let retry = first
        .complete_upload(&refreshed, &start.upload_id)
        .await
        .expect("first instance retry recognizes completed candidate");
    assert_eq!(
        retry.account.profile.avatar_url,
        accepted.account.profile.avatar_url
    );
}
