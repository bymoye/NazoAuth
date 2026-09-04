use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::ports::{
    AvatarDirectUploadPort, AvatarRepositoryPort, AvatarStagedObject, AvatarStorageError,
    AvatarStorageFuture, AvatarUploadAuthorization, AvatarUploadClaim, AvatarUploadStatePort,
    AvatarUploadTarget, GrantSummaryRepositoryPort, RepositoryError, RepositoryFuture,
};
use crate::{AccountIdentity, Principal, TenantContext, UserId, UserProfile, UserRole};
use uuid::Uuid;

fn valid_png() -> Vec<u8> {
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgba8(1, 1)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .expect("fixture image should encode");
    encoded.into_inner()
}

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
    let gif = b"GIF89a";
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
    assert_eq!(AvatarContentType::detect(gif), None);
    assert_eq!(
        AvatarContentType::detect(b"\x89PNG\r\n\x1a\nnot-an-image"),
        None
    );
    assert_eq!(AvatarContentType::detect(b"not-an-image"), None);
    assert_eq!(AvatarContentType::Png.as_str(), "image/png");
    assert_eq!(AvatarContentType::Jpeg.as_str(), "image/jpeg");
    assert_eq!(AvatarContentType::Webp.as_str(), "image/webp");
    assert_eq!(
        AvatarContentType::parse("image/png"),
        Some(AvatarContentType::Png)
    );
    assert_eq!(
        AvatarContentType::parse("image/jpeg"),
        Some(AvatarContentType::Jpeg)
    );
    assert_eq!(
        AvatarContentType::parse("image/webp"),
        Some(AvatarContentType::Webp)
    );
    assert_eq!(AvatarContentType::parse("image/gif"), None);
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

#[derive(Clone)]
struct ScriptedDirectStorage {
    authorize: Result<AvatarUploadTarget, AvatarStorageError>,
    staged: Result<AvatarStagedObject, AvatarStorageError>,
    publish: Result<(), AvatarStorageError>,
    final_object: Result<AvatarObject, AvatarStorageError>,
    delete_staging: Result<(), AvatarStorageError>,
    delete_final: Result<(), AvatarStorageError>,
    publish_calls: Arc<AtomicUsize>,
    delete_staging_calls: Arc<AtomicUsize>,
}

impl Default for ScriptedDirectStorage {
    fn default() -> Self {
        Self {
            authorize: Ok(AvatarUploadTarget {
                url: "https://object-store.test/upload".to_owned(),
                method: "PUT".to_owned(),
                headers: Default::default(),
            }),
            staged: Ok(AvatarStagedObject {
                bytes: valid_png(),
                version: "etag-scripted".to_owned(),
            }),
            publish: Ok(()),
            final_object: Ok(AvatarObject {
                bytes: valid_png(),
                content_type: AvatarContentType::Png,
                version: "final".to_owned(),
            }),
            delete_staging: Ok(()),
            delete_final: Ok(()),
            publish_calls: Arc::new(AtomicUsize::new(0)),
            delete_staging_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AvatarDirectUploadPort for ScriptedDirectStorage {
    fn authorize_upload<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _content_length: usize,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AvatarStorageFuture<'a, AvatarUploadTarget> {
        let result = self.authorize.clone();
        Box::pin(async move { result })
    }

    fn read_staged<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _max_bytes: usize,
    ) -> AvatarStorageFuture<'a, AvatarStagedObject> {
        let result = self.staged.clone();
        Box::pin(async move { result })
    }

    fn publish_staged<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _expected_version: &'a str,
        _final_object_id: &'a str,
        _content_type: AvatarContentType,
    ) -> AvatarStorageFuture<'a, ()> {
        self.publish_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.publish.clone();
        Box::pin(async move { result })
    }

    fn read_final<'a>(
        &'a self,
        _final_object_id: &'a str,
    ) -> AvatarStorageFuture<'a, AvatarObject> {
        let result = self.final_object.clone();
        Box::pin(async move { result })
    }

    fn delete_staging<'a>(&'a self, _staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        self.delete_staging_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.delete_staging.clone();
        Box::pin(async move { result })
    }

    fn delete_final<'a>(&'a self, _final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        let result = self.delete_final.clone();
        Box::pin(async move { result })
    }
}

#[derive(Clone)]
struct ScriptedDirectState {
    claim: Arc<Mutex<AvatarUploadClaim>>,
    claim_error: Option<RepositoryError>,
    create: Result<(), RepositoryError>,
    record_candidate: Result<bool, RepositoryError>,
    complete: Result<bool, RepositoryError>,
    release: Result<bool, RepositoryError>,
    releases: Arc<AtomicUsize>,
}

impl ScriptedDirectState {
    fn pending(authorization: AvatarUploadAuthorization) -> Self {
        Self {
            claim: Arc::new(Mutex::new(AvatarUploadClaim::Pending {
                authorization,
                ownership_token: "owner-scripted".to_owned(),
            })),
            claim_error: None,
            create: Ok(()),
            record_candidate: Ok(true),
            complete: Ok(true),
            release: Ok(true),
            releases: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AvatarUploadStatePort for ScriptedDirectState {
    fn create<'a>(
        &'a self,
        _authorization: &'a AvatarUploadAuthorization,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        let result = self.create.clone();
        Box::pin(async move { result })
    }

    fn claim<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _lease_until: chrono::DateTime<chrono::Utc>,
    ) -> RepositoryFuture<'a, AvatarUploadClaim> {
        let claim = self.claim.lock().unwrap().clone();
        let error = self.claim_error.clone();
        Box::pin(async move { error.map_or(Ok(claim), Err) })
    }

    fn record_candidate<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _staged_version: &'a str,
        _final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        let result = self.record_candidate.clone();
        Box::pin(async move { result })
    }

    fn complete<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        let result = self.complete.clone();
        Box::pin(async move { result })
    }

    fn release<'a>(
        &'a self,
        _user_id: UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        self.releases.fetch_add(1, Ordering::Relaxed);
        let result = self.release.clone();
        Box::pin(async move { result })
    }
}

#[derive(Clone)]
enum AvatarRepositoryResult {
    Update,
    Conflict,
    Error(RepositoryError),
}

#[derive(Clone)]
struct ScriptedAvatarRepository {
    account: Arc<Mutex<PublicAccount>>,
    result: AvatarRepositoryResult,
}

impl AvatarRepositoryPort for ScriptedAvatarRepository {
    fn compare_and_set_avatar<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        let result = self.result.clone();
        let account = Arc::clone(&self.account);
        let expected = expected_avatar_url.map(ToOwned::to_owned);
        Box::pin(async move {
            match result {
                AvatarRepositoryResult::Update => {
                    let mut account = account.lock().unwrap();
                    if account.profile.avatar_url.as_deref() != expected.as_deref() {
                        return Ok(None);
                    }
                    account.profile.avatar_url = avatar_url;
                    Ok(Some(account.clone()))
                }
                AvatarRepositoryResult::Conflict => Ok(None),
                AvatarRepositoryResult::Error(error) => Err(error),
            }
        })
    }
}

#[derive(Clone)]
struct ScriptedGrants(Result<i64, RepositoryError>);

impl GrantSummaryRepositoryPort for ScriptedGrants {
    fn authorized_client_count(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        let result = self.0.clone();
        Box::pin(async move { result })
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

fn upload_authorization(
    account: &PublicAccount,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> AvatarUploadAuthorization {
    AvatarUploadAuthorization {
        upload_id: "upload-scripted".to_owned(),
        tenant_id: account.tenant().tenant_id,
        user_id: account.user_id(),
        expected_avatar_url: account.profile.avatar_url.clone(),
        staging_object_id: "staging-scripted".to_owned(),
        expires_at,
    }
}

fn scripted_direct_service(
    account: &PublicAccount,
    storage: ScriptedDirectStorage,
    state: ScriptedDirectState,
    grants: Result<i64, RepositoryError>,
    repository_result: AvatarRepositoryResult,
) -> AvatarDirectUploadService {
    AvatarDirectUploadService::from_ports(
        Arc::new(ScriptedAvatarRepository {
            account: Arc::new(Mutex::new(account.clone())),
            result: repository_result,
        }),
        Arc::new(ScriptedGrants(grants)),
        Arc::new(storage),
        Arc::new(state),
        1024,
        300,
        30,
    )
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

#[tokio::test]
async fn direct_upload_begin_rejects_invalid_references_and_provider_failures() {
    let account = direct_account();
    let mut invalid_reference = account.clone();
    invalid_reference.profile.avatar_url = Some("/auth/me/avatar?v=bad/path".to_owned());
    let service = scripted_direct_service(
        &invalid_reference,
        ScriptedDirectStorage::default(),
        ScriptedDirectState::pending(upload_authorization(
            &invalid_reference,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.begin_upload(&invalid_reference, 1).await,
        Err(DirectAvatarUploadError::InvalidCurrentReference)
    );

    let storage_failure = ScriptedDirectStorage {
        authorize: Err(AvatarStorageError::Unavailable("signed URL".to_owned())),
        ..Default::default()
    };
    let service = scripted_direct_service(
        &account,
        storage_failure,
        ScriptedDirectState::pending(upload_authorization(
            &account,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.begin_upload(&account, 1).await,
        Err(DirectAvatarUploadError::Storage(
            AvatarStorageError::Unavailable("signed URL".to_owned())
        ))
    );

    let mut state_failure = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state_failure.create = Err(RepositoryError::Unavailable);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state_failure,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.begin_upload(&account, 1).await,
        Err(DirectAvatarUploadError::State(RepositoryError::Unavailable))
    );

    let mut overflow_ttl_state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    overflow_ttl_state.create = Ok(());
    let service = AvatarDirectUploadService::from_ports(
        Arc::new(ScriptedAvatarRepository {
            account: Arc::new(Mutex::new(account.clone())),
            result: AvatarRepositoryResult::Update,
        }),
        Arc::new(NoGrants),
        Arc::new(ScriptedDirectStorage::default()),
        Arc::new(overflow_ttl_state),
        1024,
        u64::MAX,
        30,
    );
    assert_eq!(
        service.begin_upload(&account, 1).await,
        Err(DirectAvatarUploadError::Expired)
    );
}

#[tokio::test]
async fn direct_upload_claim_states_fail_closed_and_release_invalid_pending_claims() {
    let account = direct_account();
    for claim in [AvatarUploadClaim::Busy, AvatarUploadClaim::Missing] {
        let mut state = ScriptedDirectState::pending(upload_authorization(
            &account,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        ));
        state.claim = Arc::new(Mutex::new(claim.clone()));
        let service = scripted_direct_service(
            &account,
            ScriptedDirectStorage::default(),
            state,
            Ok(0),
            AvatarRepositoryResult::Update,
        );
        let expected = match claim {
            AvatarUploadClaim::Busy => DirectAvatarUploadError::Busy,
            AvatarUploadClaim::Missing => DirectAvatarUploadError::Missing,
            _ => unreachable!(),
        };
        assert_eq!(
            service.complete_upload(&account, "upload-scripted").await,
            Err(expected)
        );
    }

    let mut wrong_account =
        upload_authorization(&account, chrono::Utc::now() + chrono::Duration::minutes(5));
    wrong_account.user_id = UserId::new(Uuid::now_v7()).unwrap();
    let state = ScriptedDirectState::pending(wrong_account);
    let releases = Arc::clone(&state.releases);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::Missing)
    );
    assert_eq!(releases.load(Ordering::Relaxed), 1);

    let expired = upload_authorization(&account, chrono::Utc::now() - chrono::Duration::seconds(1));
    let state = ScriptedDirectState::pending(expired);
    let releases = Arc::clone(&state.releases);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::Expired)
    );
    assert_eq!(releases.load(Ordering::Relaxed), 1);

    let mut state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state.claim_error = Some(RepositoryError::Unavailable);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::State(RepositoryError::Unavailable))
    );
}

#[tokio::test]
async fn direct_upload_validates_staged_snapshots_and_storage_transitions() {
    let account = direct_account();
    let storage = ScriptedDirectStorage {
        staged: Err(AvatarStorageError::Missing),
        ..Default::default()
    };
    let state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    let releases = Arc::clone(&state.releases);
    let service = scripted_direct_service(
        &account,
        storage,
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::Storage(
            AvatarStorageError::Missing
        ))
    );
    assert_eq!(releases.load(Ordering::Relaxed), 1);

    let mut state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state.record_candidate = Ok(false);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::ConcurrentChange)
    );

    let bytes = valid_png();
    let authorization =
        upload_authorization(&account, chrono::Utc::now() + chrono::Duration::minutes(5));
    let mut publishing_state = ScriptedDirectState::pending(authorization.clone());
    publishing_state.claim = Arc::new(Mutex::new(AvatarUploadClaim::Publishing {
        authorization: authorization.clone(),
        ownership_token: "owner-scripted".to_owned(),
        staged_version: "etag-scripted".to_owned(),
        final_object_id: "wrong-candidate".to_owned(),
    }));
    let storage = ScriptedDirectStorage {
        staged: Ok(AvatarStagedObject {
            bytes: bytes.clone(),
            version: "etag-scripted".to_owned(),
        }),
        ..Default::default()
    };
    let service = scripted_direct_service(
        &account,
        storage,
        publishing_state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::ConcurrentChange)
    );

    let mut publishing_state = ScriptedDirectState::pending(authorization.clone());
    publishing_state.claim = Arc::new(Mutex::new(AvatarUploadClaim::Publishing {
        authorization: authorization.clone(),
        ownership_token: "owner-scripted".to_owned(),
        staged_version: "expected-etag".to_owned(),
        final_object_id: final_object_id("upload-scripted", &bytes),
    }));
    let storage = ScriptedDirectStorage {
        staged: Ok(AvatarStagedObject {
            bytes: bytes.clone(),
            version: "actual-etag".to_owned(),
        }),
        ..Default::default()
    };
    let service = scripted_direct_service(
        &account,
        storage,
        publishing_state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::ConcurrentChange)
    );

    let mut publishing_state = ScriptedDirectState::pending(authorization.clone());
    publishing_state.claim = Arc::new(Mutex::new(AvatarUploadClaim::Publishing {
        authorization,
        ownership_token: "owner-scripted".to_owned(),
        staged_version: "etag-scripted".to_owned(),
        final_object_id: final_object_id("upload-scripted", b"not-an-image"),
    }));
    let storage = ScriptedDirectStorage {
        staged: Ok(AvatarStagedObject {
            bytes: b"not-an-image".to_vec(),
            version: "etag-scripted".to_owned(),
        }),
        ..Default::default()
    };
    let service = scripted_direct_service(
        &account,
        storage,
        publishing_state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::UnsupportedContent)
    );
}

#[tokio::test]
async fn direct_upload_handles_retries_repository_failures_and_overview_failures() {
    let account = direct_account();
    let authorization =
        upload_authorization(&account, chrono::Utc::now() + chrono::Duration::minutes(5));
    let mut state = ScriptedDirectState::pending(authorization.clone());
    state.claim = Arc::new(Mutex::new(AvatarUploadClaim::Publishing {
        authorization,
        ownership_token: "owner-scripted".to_owned(),
        staged_version: "etag-scripted".to_owned(),
        final_object_id: final_object_id("upload-scripted", &valid_png()),
    }));
    let storage = ScriptedDirectStorage {
        publish: Err(AvatarStorageError::Unavailable("publish".to_owned())),
        ..Default::default()
    };
    let service = scripted_direct_service(
        &account,
        storage,
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::Storage(
            AvatarStorageError::Unavailable("publish".to_owned())
        ))
    );

    for repository_result in [
        AvatarRepositoryResult::Conflict,
        AvatarRepositoryResult::Error(RepositoryError::Unavailable),
    ] {
        let state = ScriptedDirectState::pending(upload_authorization(
            &account,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        ));
        let service = scripted_direct_service(
            &account,
            ScriptedDirectStorage::default(),
            state,
            Ok(0),
            repository_result.clone(),
        );
        let error = service
            .complete_upload(&account, "upload-scripted")
            .await
            .expect_err("repository result must stop completion");
        assert!(matches!(
            (repository_result, error),
            (
                AvatarRepositoryResult::Conflict,
                DirectAvatarUploadError::ConcurrentChange
            ) | (
                AvatarRepositoryResult::Error(RepositoryError::Unavailable),
                DirectAvatarUploadError::Repository(RepositoryError::Unavailable)
            )
        ));
    }

    let mut state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state.complete = Err(RepositoryError::Unavailable);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::State(RepositoryError::Unavailable))
    );

    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        ScriptedDirectState::pending(upload_authorization(
            &account,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Err(RepositoryError::Unavailable),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::Overview(
            RepositoryError::Unavailable
        ))
    );
}

#[tokio::test]
async fn direct_upload_recognizes_completed_and_already_recorded_candidates() {
    let bytes = valid_png();
    let candidate = final_object_id("upload-scripted", &bytes);
    let mut account = direct_account();
    account.profile.avatar_url = Some(avatar_url(&candidate));
    let mut state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state.complete = Ok(false);
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.complete_upload(&account, "upload-scripted").await,
        Err(DirectAvatarUploadError::ConcurrentChange)
    );

    let mut state = ScriptedDirectState::pending(upload_authorization(
        &account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state.claim = Arc::new(Mutex::new(AvatarUploadClaim::Completed {
        final_object_id: candidate.clone(),
    }));
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert!(
        service
            .complete_upload(&account, "upload-scripted")
            .await
            .is_ok()
    );

    let mut mismatched_account = direct_account();
    mismatched_account.profile.avatar_url = Some(avatar_url("different"));
    let mut state = ScriptedDirectState::pending(upload_authorization(
        &mismatched_account,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    ));
    state.claim = Arc::new(Mutex::new(AvatarUploadClaim::Completed {
        final_object_id: candidate,
    }));
    let service = scripted_direct_service(
        &mismatched_account,
        ScriptedDirectStorage::default(),
        state,
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service
            .complete_upload(&mismatched_account, "upload-scripted")
            .await,
        Err(DirectAvatarUploadError::ConcurrentChange)
    );
}

#[tokio::test]
async fn direct_avatar_read_and_delete_preserve_repository_and_storage_boundaries() {
    let account = direct_account();
    let service = scripted_direct_service(
        &account,
        ScriptedDirectStorage::default(),
        ScriptedDirectState::pending(upload_authorization(
            &account,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.read(&account).await,
        Err(ReadAvatarError::NotUploaded)
    );

    let mut invalid = account.clone();
    invalid.profile.avatar_url = Some("/auth/me/avatar?v=bad/path".to_owned());
    assert_eq!(
        service.read(&invalid).await,
        Err(ReadAvatarError::InvalidReference)
    );

    let storage_failure = ScriptedDirectStorage {
        final_object: Err(AvatarStorageError::Missing),
        ..Default::default()
    };
    let with_avatar = {
        let mut account = account.clone();
        account.profile.avatar_url = Some(avatar_url("final"));
        account
    };
    let service = scripted_direct_service(
        &with_avatar,
        storage_failure,
        ScriptedDirectState::pending(upload_authorization(
            &with_avatar,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.read(&with_avatar).await,
        Err(ReadAvatarError::Storage(AvatarStorageError::Missing))
    );

    for repository_result in [
        AvatarRepositoryResult::Conflict,
        AvatarRepositoryResult::Error(RepositoryError::Unavailable),
    ] {
        let service = scripted_direct_service(
            &with_avatar,
            ScriptedDirectStorage::default(),
            ScriptedDirectState::pending(upload_authorization(
                &with_avatar,
                chrono::Utc::now() + chrono::Duration::minutes(5),
            )),
            Ok(0),
            repository_result.clone(),
        );
        let error = service
            .delete(&with_avatar)
            .await
            .expect_err("delete must stop on a stale repository reference");
        assert!(matches!(
            (repository_result, error),
            (
                AvatarRepositoryResult::Conflict,
                DeleteAvatarError::ConcurrentChange
            ) | (
                AvatarRepositoryResult::Error(RepositoryError::Unavailable),
                DeleteAvatarError::Repository(RepositoryError::Unavailable)
            )
        ));
    }

    let mut invalid_delete = with_avatar.clone();
    invalid_delete.profile.avatar_url = Some("/auth/me/avatar?v=bad/path".to_owned());
    let service = scripted_direct_service(
        &invalid_delete,
        ScriptedDirectStorage::default(),
        ScriptedDirectState::pending(upload_authorization(
            &invalid_delete,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.delete(&invalid_delete).await,
        Err(DeleteAvatarError::InvalidCurrentReference)
    );

    let storage_failure = ScriptedDirectStorage {
        delete_final: Err(AvatarStorageError::Unavailable("delete".to_owned())),
        ..Default::default()
    };
    let service = scripted_direct_service(
        &with_avatar,
        storage_failure,
        ScriptedDirectState::pending(upload_authorization(
            &with_avatar,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Ok(0),
        AvatarRepositoryResult::Update,
    );
    assert!(service.delete(&with_avatar).await.is_ok());

    let service = scripted_direct_service(
        &with_avatar,
        ScriptedDirectStorage::default(),
        ScriptedDirectState::pending(upload_authorization(
            &with_avatar,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )),
        Err(RepositoryError::Unavailable),
        AvatarRepositoryResult::Update,
    );
    assert_eq!(
        service.delete(&with_avatar).await,
        Err(DeleteAvatarError::Overview(RepositoryError::Unavailable))
    );
}
