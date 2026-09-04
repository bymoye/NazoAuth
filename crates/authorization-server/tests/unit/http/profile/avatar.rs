use super::*;
use std::{collections::BTreeMap, io, path::PathBuf, sync::Arc, time::Duration as StdDuration};

use crate::adapters::avatar_files::{
    AvatarPromotion, cleanup_avatar_temps, finish_avatar_promotion, promote_avatar_files,
    remove_avatar_file_if_exists, rename_avatar_file_if_exists, rollback_avatar_promotion,
};
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::http::sessions::SessionPayload;
use crate::schema::users;
use crate::settings::Settings;
use crate::test_support::valkey::valkey_set_ex;
use crate::test_support::{DatabaseUserFixture, TestInfrastructure};

use actix_web::error::PayloadError;
use actix_web::{
    cookie::Cookie,
    http::{header, header::HeaderMap},
    web::{Bytes, Data, Json, Path},
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Bool, Nullable, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use futures_util::stream;
use serde_json::Value;
use uuid::Uuid;

use crate::config::ConfigSource;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::ports::{
    AvatarDirectUploadPort, AvatarStagedObject, AvatarStorageError, AvatarStorageFuture,
    AvatarUploadAuthorization, AvatarUploadClaim, AvatarUploadStatePort, AvatarUploadTarget,
    GrantSummaryRepositoryPort, RepositoryError, RepositoryFuture,
};
use nazo_postgres::create_pool;
use nazo_postgres::get_conn;

fn valid_png() -> Vec<u8> {
    STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==")
        .expect("static PNG fixture should decode")
}

fn avatar_url_version(avatar_url: &str) -> Option<&str> {
    avatar_url
        .strip_prefix("/auth/me/avatar?v=")
        .filter(|version| !version.is_empty())
}

fn avatar_user_dir(state: &TestInfrastructure, user_id: Uuid) -> PathBuf {
    state
        .settings
        .storage
        .avatar_storage_dir
        .join(user_id.to_string())
}

fn avatar_path(state: &TestInfrastructure, user_id: Uuid) -> PathBuf {
    avatar_user_dir(state, user_id).join("avatar.bin")
}

fn avatar_meta_path(state: &TestInfrastructure, user_id: Uuid) -> PathBuf {
    avatar_user_dir(state, user_id).join("meta.json")
}

async fn read_avatar_meta(
    state: &TestInfrastructure,
    user_id: Uuid,
) -> anyhow::Result<Option<Value>> {
    let raw = match tokio::fs::read_to_string(avatar_meta_path(state, user_id)).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(serde_json::from_str(&raw)?))
}

async fn upload_avatar(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    multipart: Multipart,
) -> HttpResponse {
    super::upload_avatar(
        crate::test_support::profile_sessions(&state),
        crate::test_support::avatar_profiles(&state),
        req,
        multipart,
    )
    .await
}

fn disabled_avatar_profiles() -> Data<crate::bootstrap::AvatarProfileService> {
    Data::new(crate::bootstrap::AvatarProfileService::Disabled)
}

async fn begin_direct_avatar_upload(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    content_length: usize,
) -> HttpResponse {
    begin_direct_avatar_upload_with_profiles(
        state.clone(),
        crate::test_support::avatar_profiles(&state),
        req,
        content_length,
    )
    .await
}

async fn begin_direct_avatar_upload_with_profiles(
    state: Data<TestInfrastructure>,
    avatars: Data<crate::bootstrap::AvatarProfileService>,
    req: HttpRequest,
    content_length: usize,
) -> HttpResponse {
    super::begin_direct_avatar_upload(
        crate::test_support::profile_sessions(&state),
        avatars,
        req,
        Json(super::AvatarUploadBeginRequest { content_length }),
    )
    .await
}

async fn complete_direct_avatar_upload_with_profiles(
    state: Data<TestInfrastructure>,
    avatars: Data<crate::bootstrap::AvatarProfileService>,
    req: HttpRequest,
    upload_id: impl Into<String>,
) -> HttpResponse {
    super::complete_direct_avatar_upload(
        crate::test_support::profile_sessions(&state),
        avatars,
        req,
        Path::from(upload_id.into()),
    )
    .await
}

async fn get_avatar(state: Data<TestInfrastructure>, req: HttpRequest) -> HttpResponse {
    super::get_avatar(
        crate::test_support::profile_sessions(&state),
        crate::test_support::avatar_profiles(&state),
        req,
    )
    .await
}

async fn delete_avatar(state: Data<TestInfrastructure>, req: HttpRequest) -> HttpResponse {
    super::delete_avatar(
        crate::test_support::profile_sessions(&state),
        crate::test_support::avatar_profiles(&state),
        req,
    )
    .await
}

fn build_test_state(settings: Settings) -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_avatar_test_invalid:nazo_avatar_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn test_state() -> TestInfrastructure {
    build_test_state(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn test_state_with_avatar_dir(avatar_storage_dir: PathBuf) -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.storage.avatar_storage_dir = avatar_storage_dir;
    build_test_state(settings)
}

fn request_with_session_but_no_csrf(state: &TestInfrastructure) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "active-session",
        ))
        .to_http_request()
}

fn request_with_session_and_csrf(state: &TestInfrastructure, sid: &str, csrf: &str) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            sid.to_owned(),
        ))
        .cookie(Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            csrf.to_owned(),
        ))
        .insert_header(("x-csrf-token", csrf))
        .to_http_request()
}

fn multipart_payload(boundary: &str, field_name: &str, body: impl AsRef<[u8]>) -> Multipart {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={boundary}")
            .parse()
            .expect("content type should parse"),
    );
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    payload.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"avatar.bin\"\r\n"
        )
        .as_bytes(),
    );
    payload.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    payload.extend_from_slice(body.as_ref());
    payload.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    actix_multipart::Multipart::new(
        &headers,
        stream::once(async move { Ok::<Bytes, PayloadError>(Bytes::from(payload)) }),
    )
}

fn multipart_payload_with_stream_error(boundary: &str, field_name: &str) -> Multipart {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={boundary}")
            .parse()
            .expect("content type should parse"),
    );
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    payload.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"avatar.bin\"\r\n"
        )
        .as_bytes(),
    );
    payload.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    payload.extend_from_slice(b"\x89PNG\r\n\x1a\npartial-avatar");
    actix_multipart::Multipart::new(
        &headers,
        stream::iter(vec![
            Ok::<Bytes, PayloadError>(Bytes::from(payload)),
            Err(PayloadError::Incomplete(None)),
        ]),
    )
}

struct LiveAvatarFixture {
    state: Data<TestInfrastructure>,
    avatar_dir: PathBuf,
}

impl LiveAvatarFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            ("TRANSPORT_MODE", "direct-tls"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_avatar_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_avatar_test"),
        ]);
        let mut settings = Settings::from_config(&config).expect("test settings should load");
        let avatar_dir = temp_avatar_dir("live");
        settings.storage.avatar_storage_dir = avatar_dir.clone();
        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(1000);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(1000);
            connection.internal_command_timeout = StdDuration::from_millis(1000);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");

        Some(Self {
            state: Data::new(TestInfrastructure {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: crate::test_support::test_key_manager(),
            }),
            avatar_dir,
        })
    }

    async fn create_user(&self, suffix: &str, avatar_url: Option<&str>) -> DatabaseUserFixture {
        let email = format!("avatar-{suffix}@example.com");
        let username = format!("avatar-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level, avatar_url
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-avatar-test-hash', $6, false, true, 'user', 0, $7)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Bool, _>(true)
        .bind::<Nullable<Text>, _>(avatar_url.map(str::to_owned))
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        valkey_set_ex(
            &self.state.valkey,
            nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
            serde_json::to_string(&payload).expect("session should serialize"),
            self.state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("session should store");
    }

    fn request(&self, sid: &str, csrf: &str) -> HttpRequest {
        request_with_session_and_csrf(&self.state, sid, csrf)
    }

    async fn set_avatar_url(&self, user: &DatabaseUserFixture, avatar_url: Option<&str>) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::update(users::table.find(user.id))
            .set(users::avatar_url.eq(avatar_url.map(str::to_owned)))
            .execute(&mut conn)
            .await
            .expect("avatar url should update");
    }

    async fn fresh_user(&self, user_id: Uuid) -> DatabaseUserFixture {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        users::table
            .find(user_id)
            .select(DatabaseUserFixture::as_select())
            .first::<DatabaseUserFixture>(&mut conn)
            .await
            .expect("user should reload")
    }
}

impl Drop for LiveAvatarFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.avatar_dir);
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value, bool) {
    let status = response.status();
    let has_set_cookie = response.headers().contains_key(header::SET_COOKIE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json, has_set_cookie)
}

#[derive(Clone)]
struct HttpDirectStorage {
    authorize: Result<AvatarUploadTarget, AvatarStorageError>,
    staged: Result<AvatarStagedObject, AvatarStorageError>,
    publish: Result<(), AvatarStorageError>,
    final_object: Result<nazo_identity::AvatarObject, AvatarStorageError>,
    delete_staging: Result<(), AvatarStorageError>,
    delete_final: Result<(), AvatarStorageError>,
}

impl Default for HttpDirectStorage {
    fn default() -> Self {
        Self {
            authorize: Ok(AvatarUploadTarget {
                url: "https://object-store.test/avatar".to_owned(),
                method: "PUT".to_owned(),
                headers: BTreeMap::new(),
            }),
            staged: Ok(AvatarStagedObject {
                bytes: valid_png(),
                version: "etag-http-test".to_owned(),
            }),
            publish: Ok(()),
            final_object: Ok(nazo_identity::AvatarObject {
                bytes: valid_png(),
                content_type: nazo_identity::AvatarContentType::Png,
                version: "final-http-test".to_owned(),
            }),
            delete_staging: Ok(()),
            delete_final: Ok(()),
        }
    }
}

impl AvatarDirectUploadPort for HttpDirectStorage {
    fn authorize_upload<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _content_length: usize,
        _expires_at: DateTime<Utc>,
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
        _content_type: nazo_identity::AvatarContentType,
    ) -> AvatarStorageFuture<'a, ()> {
        let result = self.publish.clone();
        Box::pin(async move { result })
    }

    fn read_final<'a>(
        &'a self,
        _final_object_id: &'a str,
    ) -> AvatarStorageFuture<'a, nazo_identity::AvatarObject> {
        let result = self.final_object.clone();
        Box::pin(async move { result })
    }

    fn delete_staging<'a>(&'a self, _staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        let result = self.delete_staging.clone();
        Box::pin(async move { result })
    }

    fn delete_final<'a>(&'a self, _final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        let result = self.delete_final.clone();
        Box::pin(async move { result })
    }
}

#[derive(Clone)]
struct HttpDirectState {
    create: Result<(), RepositoryError>,
    claim: Result<AvatarUploadClaim, RepositoryError>,
    record_candidate: Result<bool, RepositoryError>,
    complete: Result<bool, RepositoryError>,
    release: Result<bool, RepositoryError>,
}

impl Default for HttpDirectState {
    fn default() -> Self {
        Self {
            create: Ok(()),
            claim: Ok(AvatarUploadClaim::Missing),
            record_candidate: Ok(true),
            complete: Ok(true),
            release: Ok(true),
        }
    }
}

impl HttpDirectState {
    fn with_claim(claim: AvatarUploadClaim) -> Self {
        Self {
            claim: Ok(claim),
            ..Self::default()
        }
    }
}

impl AvatarUploadStatePort for HttpDirectState {
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
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _lease_until: DateTime<Utc>,
    ) -> RepositoryFuture<'a, AvatarUploadClaim> {
        let result = self.claim.clone();
        Box::pin(async move { result })
    }

    fn record_candidate<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
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
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        let result = self.complete.clone();
        Box::pin(async move { result })
    }

    fn release<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        let result = self.release.clone();
        Box::pin(async move { result })
    }
}

fn direct_avatar_profiles_for_http(
    state: &TestInfrastructure,
    storage: HttpDirectStorage,
    upload_state: HttpDirectState,
    max_bytes: usize,
) -> Data<crate::bootstrap::AvatarProfileService> {
    Data::new(crate::bootstrap::AvatarProfileService::Direct(
        nazo_identity::AvatarDirectUploadService::from_ports(
            Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            Arc::new(nazo_postgres::GrantRepository::new(state.diesel_db.clone())),
            Arc::new(storage),
            Arc::new(upload_state),
            max_bytes,
            300,
            30,
        ),
    ))
}

fn pending_direct_claim(
    user: &DatabaseUserFixture,
    upload_id: &str,
    expires_at: DateTime<Utc>,
) -> AvatarUploadClaim {
    AvatarUploadClaim::Pending {
        authorization: AvatarUploadAuthorization {
            upload_id: upload_id.to_owned(),
            tenant_id: nazo_identity::TenantId::new(DEFAULT_TENANT_ID)
                .expect("default tenant ID should be valid"),
            user_id: nazo_identity::UserId::new(user.id).expect("fixture user ID should be valid"),
            expected_avatar_url: None,
            staging_object_id: upload_id.to_owned(),
            expires_at,
        },
        ownership_token: "http-test-ownership".to_owned(),
    }
}

#[derive(Clone, Copy)]
struct UnavailableAvatarGrants;

impl GrantSummaryRepositoryPort for UnavailableAvatarGrants {
    fn authorized_client_count(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

#[actix_web::test]
async fn avatar_upload_capability_requires_login() {
    let state = Data::new(test_state());
    let response = super::avatar_upload_capability(
        crate::test_support::profile_sessions(&state),
        disabled_avatar_profiles(),
        actix_web::test::TestRequest::get().to_http_request(),
    )
    .await;
    let (status, body, _) = response_json(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert!(body.get("upload_mode").is_none());
}

#[actix_web::test]
async fn avatar_upload_capability_reports_the_selected_tenant_service_without_csrf() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-capability-{suffix}");
    fixture.store_session(&user, &sid).await;
    for (avatars, expected) in [
        (disabled_avatar_profiles(), "disabled"),
        (
            crate::test_support::avatar_profiles(&fixture.state),
            "multipart",
        ),
        (
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::default(),
                1024,
            ),
            "direct",
        ),
    ] {
        let app = actix_web::test::init_service(
            actix_web::App::new()
                .app_data(crate::test_support::profile_sessions(&fixture.state))
                .app_data(avatars)
                .route(
                    "/auth/me/avatar/uploads",
                    actix_web::web::get().to(super::avatar_upload_capability),
                ),
        )
        .await;
        let request = actix_web::test::TestRequest::get()
            .uri("/auth/me/avatar/uploads")
            .cookie(Cookie::new(
                fixture.state.settings.session.session_cookie_name.clone(),
                sid.clone(),
            ))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body: Value = actix_web::test::read_body_json(response).await;
        assert_eq!(body, serde_json::json!({"upload_mode": expected}));
    }
}

#[tokio::test]
async fn disabled_avatar_storage_returns_forbidden_after_auth_without_consuming_or_mutating() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=existing"))
        .await;
    let sid = format!("avatar-disabled-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let avatars = disabled_avatar_profiles();

    let upload_response = super::upload_avatar(
        crate::test_support::profile_sessions(&fixture.state),
        avatars.clone(),
        fixture.request(&sid, &csrf),
        multipart_payload_with_stream_error("disabled-avatar-boundary", "avatar"),
    )
    .await;
    let (status, body, _) = response_json(upload_response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], AVATAR_STORAGE_DISABLED_MESSAGE);
    assert!(
        !tokio::fs::try_exists(avatar_user_dir(&fixture.state, user.id))
            .await
            .unwrap()
    );

    let begin_response = super::begin_direct_avatar_upload(
        crate::test_support::profile_sessions(&fixture.state),
        avatars.clone(),
        fixture.request(&sid, &csrf),
        Json(super::AvatarUploadBeginRequest { content_length: 1 }),
    )
    .await;
    let (status, body, _) = response_json(begin_response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], AVATAR_STORAGE_DISABLED_MESSAGE);

    let complete_response = super::complete_direct_avatar_upload(
        crate::test_support::profile_sessions(&fixture.state),
        avatars.clone(),
        fixture.request(&sid, &csrf),
        Path::from(Uuid::now_v7().to_string()),
    )
    .await;
    let (status, body, _) = response_json(complete_response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], AVATAR_STORAGE_DISABLED_MESSAGE);

    let get_response = super::get_avatar(
        crate::test_support::profile_sessions(&fixture.state),
        avatars.clone(),
        fixture.request(&sid, &csrf),
    )
    .await;
    let (status, body, _) = response_json(get_response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], AVATAR_STORAGE_DISABLED_MESSAGE);

    let delete_response = super::delete_avatar(
        crate::test_support::profile_sessions(&fixture.state),
        avatars,
        fixture.request(&sid, &csrf),
    )
    .await;
    let (status, body, _) = response_json(delete_response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], AVATAR_STORAGE_DISABLED_MESSAGE);
    assert_eq!(
        fixture.fresh_user(user.id).await.avatar_url.as_deref(),
        Some("/auth/me/avatar?v=existing")
    );
}

#[tokio::test]
async fn disabled_avatar_storage_keeps_csrf_and_login_guards() {
    let state = test_state();
    let avatars = disabled_avatar_profiles();
    let missing_csrf = super::upload_avatar(
        crate::test_support::profile_sessions(&state),
        avatars.clone(),
        request_with_session_but_no_csrf(&state),
        multipart_payload("disabled-csrf-boundary", "avatar", valid_png()),
    )
    .await;
    let (status, body, _) = response_json(missing_csrf).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");

    let unauthenticated = super::get_avatar(
        crate::test_support::profile_sessions(&state),
        avatars,
        actix_web::test::TestRequest::default().to_http_request(),
    )
    .await;
    let (status, body, _) = response_json(unauthenticated).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
}

async fn assert_avatar_write_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("avatar_url").is_none());
    assert!(body.get("email").is_none());
    assert!(body.get("sub").is_none());
    assert!(!has_set_cookie);
}

#[test]
fn avatar_url_version_accepts_only_expected_query_shape() {
    assert_eq!(
        avatar_url_version("/auth/me/avatar?v=019789ad-1f5a-7c0d-b9b5-d9d74376d6fc"),
        Some("019789ad-1f5a-7c0d-b9b5-d9d74376d6fc")
    );

    for invalid_url in [
        "",
        "/auth/me/avatar",
        "/auth/me/avatar?v=",
        "/auth/me/avatar?version=abc",
        "/profile/avatar?v=abc",
    ] {
        assert_eq!(
            avatar_url_version(invalid_url),
            None,
            "unexpected avatar URL shape should not be parsed as a version"
        );
    }
}

#[tokio::test]
async fn remove_avatar_file_if_exists_removes_existing_file_and_ignores_missing_path() {
    let dir = temp_avatar_dir("remove");
    let avatar = dir.join("avatar.bin");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(&avatar, b"avatar-bytes").await.unwrap();

    remove_avatar_file_if_exists(avatar.clone()).await.unwrap();
    assert!(!tokio::fs::try_exists(&avatar).await.unwrap());

    remove_avatar_file_if_exists(avatar.clone()).await.unwrap();
    assert!(!tokio::fs::try_exists(&avatar).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn remove_avatar_file_if_exists_reports_non_file_paths() {
    let dir = temp_avatar_dir("remove-dir-error");
    tokio::fs::create_dir_all(&dir).await.unwrap();

    let error = remove_avatar_file_if_exists(dir.clone())
        .await
        .expect_err("directory removal through file helper must not be hidden");

    assert_ne!(error.kind(), io::ErrorKind::NotFound);
    assert!(tokio::fs::try_exists(&dir).await.unwrap());
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn rename_avatar_file_if_exists_moves_existing_file_and_reports_missing_source() {
    let dir = temp_avatar_dir("rename");
    let source = dir.join("avatar.tmp");
    let target = dir.join("avatar.bin");
    let missing_source = dir.join("missing.tmp");
    let missing_target = dir.join("missing.bin");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(&source, b"new-avatar").await.unwrap();

    assert!(
        rename_avatar_file_if_exists(&source, &target)
            .await
            .unwrap()
    );
    assert!(!tokio::fs::try_exists(&source).await.unwrap());
    assert_eq!(tokio::fs::read(&target).await.unwrap(), b"new-avatar");

    assert!(
        !rename_avatar_file_if_exists(&missing_source, &missing_target)
            .await
            .unwrap()
    );
    assert!(!tokio::fs::try_exists(&missing_target).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn rename_avatar_file_if_exists_reports_non_not_found_errors() {
    let dir = temp_avatar_dir("rename-dir-target-error");
    let source = dir.join("avatar.tmp");
    let target = dir.join("existing-directory");
    tokio::fs::create_dir_all(&target).await.unwrap();
    tokio::fs::write(&source, b"avatar").await.unwrap();

    let error = rename_avatar_file_if_exists(&source, &target)
        .await
        .expect_err("renaming a file over a directory must fail explicitly");

    assert_ne!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(tokio::fs::read(&source).await.unwrap(), b"avatar");
    assert!(tokio::fs::try_exists(&target).await.unwrap());
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn cleanup_avatar_temps_removes_existing_files_and_is_idempotent() {
    let dir = temp_avatar_dir("cleanup");
    let avatar_tmp = dir.join("avatar.tmp");
    let avatar_meta_tmp = dir.join("meta.tmp");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&avatar_meta_tmp, b"new-meta")
        .await
        .unwrap();

    cleanup_avatar_temps(&avatar_tmp, &avatar_meta_tmp).await;
    cleanup_avatar_temps(&avatar_tmp, &avatar_meta_tmp).await;

    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&avatar_meta_tmp).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_can_restore_previous_files() {
    let dir = temp_avatar_dir("rollback");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"new-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"new-meta");

    rollback_avatar_promotion(&promotion).await;
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_finish_removes_backup_files() {
    let dir = temp_avatar_dir("finish");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    finish_avatar_promotion(&promotion).await;
    let avatar_backup_exists = tokio::fs::try_exists(&promotion.avatar_backup_path)
        .await
        .unwrap();
    let meta_backup_exists = tokio::fs::try_exists(&promotion.avatar_meta_backup_path)
        .await
        .unwrap();
    let _ = tokio::fs::remove_dir_all(&dir).await;

    assert!(!avatar_backup_exists);
    assert!(!meta_backup_exists);
}

#[tokio::test]
async fn avatar_promotion_without_previous_files_can_roll_back_to_empty_state() {
    let dir = temp_avatar_dir("rollback-empty");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"{\"content_type\":\"image/png\"}")
        .await
        .unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    assert!(!promotion.avatar_backup_exists);
    assert!(!promotion.avatar_meta_backup_exists);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"new-avatar");
    assert_eq!(
        tokio::fs::read(&meta).await.unwrap(),
        b"{\"content_type\":\"image/png\"}"
    );

    rollback_avatar_promotion(&promotion).await;

    assert!(!tokio::fs::try_exists(&avatar).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta).await.unwrap());
    assert!(
        !tokio::fs::try_exists(&promotion.avatar_backup_path)
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(&promotion.avatar_meta_backup_path)
            .await
            .unwrap()
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_restores_previous_files_when_avatar_temp_is_missing() {
    let dir = temp_avatar_dir("rollback-missing-avatar-tmp");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let error = match promote_avatar_files(
        &avatar_tmp,
        &meta_tmp,
        avatar.clone(),
        meta.clone(),
        "v1",
    )
    .await
    {
        Ok(_) => panic!("missing avatar temp should fail promotion"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta_tmp).await.unwrap());
    assert!(
        !tokio::fs::try_exists(dir.join("avatar-v1.bak"))
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(dir.join("meta-v1.bak"))
            .await
            .unwrap()
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_restores_avatar_when_metadata_backup_cannot_be_created() {
    let dir = temp_avatar_dir("rollback-meta-backup-error");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    let meta_backup_blocker = dir.join("meta-v1.bak");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();
    tokio::fs::create_dir(&meta_backup_blocker).await.unwrap();

    let error = match promote_avatar_files(
        &avatar_tmp,
        &meta_tmp,
        avatar.clone(),
        meta.clone(),
        "v1",
    )
    .await
    {
        Ok(_) => panic!("metadata backup failure must abort promotion"),
        Err(error) => error,
    };

    assert_ne!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta_tmp).await.unwrap());
    assert!(
        !tokio::fs::try_exists(dir.join("avatar-v1.bak"))
            .await
            .unwrap()
    );
    assert!(tokio::fs::try_exists(&meta_backup_blocker).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_restores_previous_files_when_metadata_temp_is_missing_after_avatar_move()
{
    let dir = temp_avatar_dir("rollback-missing-meta-tmp");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();

    let error = match promote_avatar_files(
        &avatar_tmp,
        &meta_tmp,
        avatar.clone(),
        meta.clone(),
        "v1",
    )
    .await
    {
        Ok(_) => panic!("missing metadata temp should fail promotion"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    assert!(!tokio::fs::try_exists(&avatar_tmp).await.unwrap());
    assert!(!tokio::fs::try_exists(&meta_tmp).await.unwrap());
    assert!(
        !tokio::fs::try_exists(dir.join("avatar-v1.bak"))
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(dir.join("meta-v1.bak"))
            .await
            .unwrap()
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

fn temp_avatar_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_avatar_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[tokio::test]
async fn read_avatar_meta_distinguishes_missing_valid_and_invalid_metadata() {
    let dir = temp_avatar_dir("read-meta");
    let state = test_state_with_avatar_dir(dir.clone());
    let user_id = Uuid::now_v7();

    assert!(read_avatar_meta(&state, user_id).await.unwrap().is_none());

    let user_dir = avatar_user_dir(&state, user_id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    tokio::fs::write(
        avatar_meta_path(&state, user_id),
        r#"{"content_type":"image/webp","version":"v1"}"#,
    )
    .await
    .unwrap();

    let meta = read_avatar_meta(&state, user_id)
        .await
        .unwrap()
        .expect("metadata should be present after write");
    assert_eq!(meta["content_type"], "image/webp");
    assert_eq!(meta["version"], "v1");

    tokio::fs::write(avatar_meta_path(&state, user_id), b"{not-json")
        .await
        .unwrap();
    let error = read_avatar_meta(&state, user_id)
        .await
        .expect_err("invalid metadata JSON should fail");
    assert!(error.downcast_ref::<serde_json::Error>().is_some());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[actix_web::test]
async fn upload_avatar_rejects_session_request_without_csrf_before_file_or_profile_write() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);
    let headers = HeaderMap::new();
    let payload =
        actix_multipart::Multipart::new(&headers, stream::empty::<Result<Bytes, PayloadError>>());

    assert_avatar_write_rejects_missing_csrf(upload_avatar(state, req, payload).await).await;
}

#[actix_web::test]
async fn direct_avatar_authorization_rejects_session_request_without_csrf() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);
    assert_avatar_write_rejects_missing_csrf(begin_direct_avatar_upload(state, req, 1).await).await;
}

#[test]
fn direct_avatar_begin_payload_requires_a_declared_length() {
    assert!(
        serde_json::from_value::<super::AvatarUploadBeginRequest>(serde_json::json!({})).is_err()
    );
    assert_eq!(
        serde_json::from_value::<super::AvatarUploadBeginRequest>(serde_json::json!({
            "content_length": 0
        }))
        .expect("zero is syntactically valid JSON")
        .content_length,
        0
    );
}

#[actix_web::test]
async fn begin_direct_avatar_upload_maps_validation_storage_and_success() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-direct-begin-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;

    let (status, body, has_set_cookie) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::default(),
                1024,
            ),
            fixture.request(&sid, &csrf),
            0,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Avatar file size must be greater than zero."
    );
    assert!(!has_set_cookie);

    let (status, body, _) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::default(),
                8,
            ),
            fixture.request(&sid, &csrf),
            9,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "invalid_request");

    let (status, body, _) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            crate::test_support::avatar_profiles(&fixture.state),
            fixture.request(&sid, &csrf),
            1,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Direct avatar upload is not supported by the configured storage."
    );

    let (status, body, has_set_cookie) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::default(),
                1024,
            ),
            fixture.request(&sid, &csrf),
            12,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert!(body["upload_id"].as_str().is_some());
    assert!(body["expires_at"].as_str().is_some());
    assert_eq!(body["upload"]["url"], "https://object-store.test/avatar");
    assert_eq!(body["upload"]["method"], "PUT");
    assert_eq!(body["upload"]["headers"], serde_json::json!({}));

    fixture
        .set_avatar_url(&user, Some("/auth/me/avatar?v=broken&unexpected=1"))
        .await;
    let (status, body, _) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::default(),
                1024,
            ),
            fixture.request(&sid, &csrf),
            12,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    fixture.set_avatar_url(&user, None).await;

    let storage = HttpDirectStorage {
        authorize: Err(AvatarStorageError::Unavailable(
            "object store unavailable".to_owned(),
        )),
        ..HttpDirectStorage::default()
    };
    let (status, body, _) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                storage,
                HttpDirectState::default(),
                1024,
            ),
            fixture.request(&sid, &csrf),
            12,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");

    let upload_state = HttpDirectState {
        create: Err(RepositoryError::Unavailable),
        ..HttpDirectState::default()
    };
    let (status, body, _) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                upload_state,
                1024,
            ),
            fixture.request(&sid, &csrf),
            12,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn direct_avatar_upload_endpoints_require_login_after_csrf_validation() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let sid = format!("avatar-direct-missing-session-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let avatars = disabled_avatar_profiles();

    let (status, body, _) = response_json(
        begin_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            avatars.clone(),
            fixture.request(&sid, &csrf),
            1,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");

    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            avatars,
            fixture.request(&sid, &csrf),
            Uuid::now_v7().to_string(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
}

#[actix_web::test]
async fn complete_direct_avatar_upload_maps_validation_storage_and_success() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-direct-complete-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let request = || fixture.request(&sid, &csrf);

    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            disabled_avatar_profiles(),
            request(),
            "not-a-uuid",
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Avatar upload ID is invalid.");

    let upload_id = Uuid::now_v7().to_string();
    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            crate::test_support::avatar_profiles(&fixture.state),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Direct avatar upload is not supported by the configured storage."
    );

    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::with_claim(AvatarUploadClaim::Missing),
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Avatar upload has expired.");

    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::with_claim(AvatarUploadClaim::Busy),
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Avatar upload is being completed."
    );

    let expired_claim =
        pending_direct_claim(&user, &upload_id, Utc::now() - chrono::Duration::seconds(1));
    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::with_claim(expired_claim),
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Avatar upload has expired.");

    let pending_claim =
        pending_direct_claim(&user, &upload_id, Utc::now() + chrono::Duration::minutes(5));
    let invalid_storage = HttpDirectStorage {
        staged: Ok(AvatarStagedObject {
            bytes: b"not-an-image".to_vec(),
            version: "etag-invalid".to_owned(),
        }),
        ..HttpDirectStorage::default()
    };
    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                invalid_storage,
                HttpDirectState::with_claim(pending_claim.clone()),
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Avatar must be PNG, JPEG, or WebP."
    );

    let unavailable_storage = HttpDirectStorage {
        staged: Err(AvatarStorageError::Unavailable(
            "object store unavailable".to_owned(),
        )),
        ..HttpDirectStorage::default()
    };
    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                unavailable_storage,
                HttpDirectState::with_claim(pending_claim.clone()),
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Failed to save avatar.");

    let mut concurrent_state = HttpDirectState::with_claim(pending_claim.clone());
    concurrent_state.record_candidate = Ok(false);
    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                concurrent_state,
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Avatar was updated by another request."
    );

    let state_error = HttpDirectState {
        claim: Err(RepositoryError::Unavailable),
        ..HttpDirectState::default()
    };
    let (status, body, _) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                state_error,
                1024,
            ),
            request(),
            upload_id.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");

    let (status, body, has_set_cookie) = response_json(
        complete_direct_avatar_upload_with_profiles(
            fixture.state.clone(),
            direct_avatar_profiles_for_http(
                &fixture.state,
                HttpDirectStorage::default(),
                HttpDirectState::with_claim(pending_claim),
                1024,
            ),
            request(),
            upload_id,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    let avatar_url = body["avatar_url"]
        .as_str()
        .expect("direct completion should return avatar_url");
    assert!(avatar_url.starts_with("/auth/me/avatar?v="));
    assert_eq!(
        fixture.fresh_user(user.id).await.avatar_url.as_deref(),
        Some(avatar_url)
    );
}

fn malformed_multipart_payload(boundary: &str) -> Multipart {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={boundary}")
            .parse()
            .expect("content type should parse"),
    );
    actix_multipart::Multipart::new(
        &headers,
        stream::once(async { Ok::<Bytes, PayloadError>(Bytes::from_static(b"malformed")) }),
    )
}

#[actix_web::test]
async fn upload_avatar_maps_multipart_parse_and_profile_overview_failures() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let parse_user = fixture.create_user(&format!("{suffix}-parse"), None).await;
    let parse_sid = format!("avatar-multipart-parse-{suffix}");
    let parse_csrf = format!("csrf-parse-{suffix}");
    fixture.store_session(&parse_user, &parse_sid).await;

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            fixture.state.clone(),
            fixture.request(&parse_sid, &parse_csrf),
            malformed_multipart_payload("malformed-avatar-boundary"),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Failed to read avatar file.");
    assert!(!has_set_cookie);
    assert!(fixture.fresh_user(parse_user.id).await.avatar_url.is_none());

    let invalid_reference_user = fixture
        .create_user(
            &format!("{suffix}-reference"),
            Some("/auth/me/avatar?v=broken&unexpected=1"),
        )
        .await;
    let invalid_reference_sid = format!("avatar-invalid-reference-{suffix}");
    let invalid_reference_csrf = format!("csrf-reference-{suffix}");
    fixture
        .store_session(&invalid_reference_user, &invalid_reference_sid)
        .await;
    let (status, body, _) = response_json(
        upload_avatar(
            fixture.state.clone(),
            fixture.request(&invalid_reference_sid, &invalid_reference_csrf),
            multipart_payload("invalid-reference-boundary", "avatar", valid_png()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Failed to save avatar.");

    let overview_user = fixture
        .create_user(&format!("{suffix}-overview"), None)
        .await;
    let overview_sid = format!("avatar-overview-{suffix}");
    let overview_csrf = format!("csrf-overview-{suffix}");
    fixture.store_session(&overview_user, &overview_sid).await;
    let service = nazo_identity::AvatarService::from_ports(
        Arc::new(nazo_postgres::UserRepository::new(
            fixture.state.diesel_db.clone(),
        )),
        Arc::new(UnavailableAvatarGrants),
        crate::adapters::avatar_files::LocalAvatarStorage::new(fixture.avatar_dir.clone()),
        fixture.state.settings.storage.avatar_max_bytes,
    );
    let avatars = Data::new(crate::bootstrap::AvatarProfileService::Local(service));
    let (status, body, _) = response_json(
        super::upload_avatar(
            crate::test_support::profile_sessions(&fixture.state),
            avatars,
            fixture.request(&overview_sid, &overview_csrf),
            multipart_payload("overview-boundary", "avatar", valid_png()),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        body["error_description"],
        "Failed to load current user profile."
    );
    assert!(
        fixture
            .fresh_user(overview_user.id)
            .await
            .avatar_url
            .is_some()
    );
}

#[actix_web::test]
async fn delete_avatar_rejects_session_request_without_csrf_before_profile_write() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_avatar_write_rejects_missing_csrf(delete_avatar(state, req).await).await;
}

#[actix_web::test]
async fn get_avatar_requires_login_before_cross_site_or_file_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default()
        .insert_header(("sec-fetch-site", "cross-site"))
        .to_http_request();

    let (status, body, has_set_cookie) = response_json(get_avatar(state, req).await).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert!(body.get("content_type").is_none());
    assert!(has_set_cookie);
}

#[actix_web::test]
async fn get_avatar_rejects_cross_site_request_before_metadata_or_file_lookup() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let sid = format!("avatar-cross-site-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let req = actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            fixture.state.settings.session.session_cookie_name.clone(),
            sid,
        ))
        .cookie(Cookie::new(
            fixture.state.settings.session.csrf_cookie_name.clone(),
            csrf.clone(),
        ))
        .insert_header(("x-csrf-token", csrf))
        .insert_header(("sec-fetch-site", "cross-site"))
        .to_http_request();

    let (status, body, has_set_cookie) =
        response_json(get_avatar(fixture.state.clone(), req).await).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
}

#[tokio::test]
async fn rollback_avatar_promotion_continues_when_one_backup_restore_fails() {
    let dir = temp_avatar_dir("rollback-restore-error");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_backup = dir.join("avatar-v1.bak");
    let meta_backup = dir.join("meta-v1.bak");
    tokio::fs::create_dir(&avatar).await.unwrap();
    tokio::fs::write(&meta, b"new-meta").await.unwrap();
    tokio::fs::write(&avatar_backup, b"old-avatar")
        .await
        .unwrap();
    tokio::fs::write(&meta_backup, b"old-meta").await.unwrap();
    let promotion = AvatarPromotion {
        avatar_file_path: avatar.clone(),
        avatar_meta_file_path: meta.clone(),
        avatar_backup_path: avatar_backup.clone(),
        avatar_meta_backup_path: meta_backup.clone(),
        avatar_backup_exists: true,
        avatar_meta_backup_exists: true,
    };

    rollback_avatar_promotion(&promotion).await;

    assert!(
        tokio::fs::metadata(&avatar)
            .await
            .expect("restore blocker should remain")
            .is_dir()
    );
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    assert!(
        tokio::fs::try_exists(&avatar_backup).await.unwrap(),
        "a failed restore must be surfaced by leaving the backup in place"
    );
    assert!(!tokio::fs::try_exists(&meta_backup).await.unwrap());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[actix_web::test]
async fn upload_avatar_reports_session_lookup_failure_after_valid_csrf_before_reading_multipart() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let sid = format!("avatar-session-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-{}", Uuid::now_v7().simple());
    let state = Data::new(TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_avatar_session_lookup_invalid:nazo_avatar_session_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let payload = SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
        serde_json::to_string(&payload).expect("session should serialize"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("session should store");
    let headers = HeaderMap::new();
    let multipart =
        actix_multipart::Multipart::new(&headers, stream::empty::<Result<Bytes, PayloadError>>());

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            state,
            request_with_session_and_csrf(&fixture.state, &sid, &csrf),
            multipart,
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn delete_avatar_reports_session_lookup_failure_after_valid_csrf_before_profile_write() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let sid = format!("avatar-delete-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-{}", Uuid::now_v7().simple());
    let state = Data::new(TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_avatar_delete_lookup_invalid:nazo_avatar_delete_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let payload = SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
        serde_json::to_string(&payload).expect("session should serialize"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("session should store");

    let (status, body, has_set_cookie) = response_json(
        delete_avatar(
            state,
            request_with_session_and_csrf(&fixture.state, &sid, &csrf),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn upload_avatar_rejects_missing_avatar_field_without_profile_or_file_write() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-missing-field-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            multipart_payload(
                "missing-avatar-boundary",
                "not_avatar",
                b"\x89PNG\r\n\x1a\n",
            ),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
    assert!(fixture.fresh_user(user.id).await.avatar_url.is_none());
    assert!(
        !tokio::fs::try_exists(avatar_user_dir(&fixture.state, user.id))
            .await
            .unwrap()
    );
}

#[actix_web::test]
async fn upload_avatar_rejects_unsupported_content_before_persisting_profile() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-unsupported-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            multipart_payload("unsupported-avatar-boundary", "avatar", b"not-an-image"),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
    assert!(fixture.fresh_user(user.id).await.avatar_url.is_none());
    assert!(
        !tokio::fs::try_exists(avatar_user_dir(&fixture.state, user.id))
            .await
            .unwrap()
    );
}

#[actix_web::test]
async fn upload_avatar_enforces_the_configured_limit_before_extending_the_buffer() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-oversized-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let mut settings = fixture.state.settings.as_ref().clone();
    settings.storage.avatar_max_bytes = 8;
    let limited_state = Data::new(TestInfrastructure {
        diesel_db: fixture.state.diesel_db.clone(),
        valkey: fixture.state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: fixture.state.keyset.clone(),
    });

    let (status, body, _) = response_json(
        upload_avatar(
            limited_state,
            fixture.request(&sid, &csrf),
            multipart_payload("oversized-avatar-boundary", "avatar", b"\x89PNG\r\n\x1a\nX"),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "invalid_request");
    assert!(fixture.fresh_user(user.id).await.avatar_url.is_none());
    assert!(
        !tokio::fs::try_exists(avatar_user_dir(&fixture.state, user.id))
            .await
            .unwrap()
    );
}

#[actix_web::test]
async fn upload_avatar_persists_versioned_file_and_metadata() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-upload-success-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let png = valid_png();

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            multipart_payload("success-avatar-boundary", "avatar", &png),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    let avatar_url = body["avatar_url"]
        .as_str()
        .expect("upload response should include avatar_url");
    let version = avatar_url_version(avatar_url).expect("avatar URL should carry a version");
    assert_eq!(
        fixture.fresh_user(user.id).await.avatar_url.as_deref(),
        Some(avatar_url)
    );
    assert_eq!(
        tokio::fs::read(avatar_path(&fixture.state, user.id))
            .await
            .unwrap(),
        png
    );
    let meta = read_avatar_meta(&fixture.state, user.id)
        .await
        .unwrap()
        .expect("metadata should be present after upload");
    assert_eq!(meta["content_type"], "image/png");
    assert_eq!(meta["version"], version);
}

#[actix_web::test]
async fn upload_avatar_rejects_stream_failure_without_persisting_profile_or_temp_files() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-stream-error-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            multipart_payload_with_stream_error("error-avatar-boundary", "avatar"),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
    assert!(fixture.fresh_user(user.id).await.avatar_url.is_none());
    assert!(
        !tokio::fs::try_exists(avatar_user_dir(&fixture.state, user.id))
            .await
            .unwrap()
    );
}

#[actix_web::test]
async fn upload_avatar_fails_closed_when_storage_root_cannot_be_created() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-storage-blocked-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let blocked_root = temp_avatar_dir("blocked-root");
    tokio::fs::write(&blocked_root, b"not-a-directory")
        .await
        .expect("blocked root marker should write");
    let mut settings = fixture.state.settings.as_ref().clone();
    settings.storage.avatar_storage_dir = blocked_root.clone();
    let blocked_state = Data::new(TestInfrastructure {
        diesel_db: fixture.state.diesel_db.clone(),
        valkey: fixture.state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: fixture.state.keyset.clone(),
    });

    let (status, body, has_set_cookie) = response_json(
        upload_avatar(
            blocked_state,
            fixture.request(&sid, &csrf),
            multipart_payload("blocked-avatar-boundary", "avatar", valid_png()),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], "server_error");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
    assert!(fixture.fresh_user(user.id).await.avatar_url.is_none());
    assert!(tokio::fs::metadata(&blocked_root).await.unwrap().is_file());
    let _ = tokio::fs::remove_file(&blocked_root).await;
}

#[actix_web::test]
async fn get_avatar_rejects_missing_and_inconsistent_persisted_avatar_state() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None).await;
    let sid = format!("avatar-get-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let req = fixture.request(&sid, &csrf);

    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), req.clone()).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error_description"].is_string());

    fixture
        .set_avatar_url(&user, Some("/profile/avatar?v=broken"))
        .await;
    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), req.clone()).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());

    fixture
        .set_avatar_url(&user, Some("/auth/me/avatar?v=v1"))
        .await;
    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), req.clone()).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());

    let user_dir = avatar_user_dir(&fixture.state, user.id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    tokio::fs::write(avatar_meta_path(&fixture.state, user.id), b"{broken")
        .await
        .unwrap();
    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), req.clone()).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());

    tokio::fs::write(
        avatar_meta_path(&fixture.state, user.id),
        r#"{"content_type":"image/png","version":"wrong"}"#,
    )
    .await
    .unwrap();
    let (status, body, _) = response_json(get_avatar(fixture.state.clone(), req).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());
}

#[actix_web::test]
async fn get_avatar_uses_detected_content_type_and_sets_security_headers() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let sid = format!("avatar-detect-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let user_dir = avatar_user_dir(&fixture.state, user.id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    tokio::fs::write(
        avatar_meta_path(&fixture.state, user.id),
        r#"{"content_type":"text/plain","version":"v1"}"#,
    )
    .await
    .unwrap();
    let png = valid_png();
    tokio::fs::write(avatar_path(&fixture.state, user.id), &png)
        .await
        .unwrap();

    let response = get_avatar(fixture.state.clone(), fixture.request(&sid, &csrf)).await;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let pragma = response
        .headers()
        .get(header::PRAGMA)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let nosniff = response
        .headers()
        .get(header::X_CONTENT_TYPE_OPTIONS)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should read");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, png);
    assert_eq!(content_type.as_deref(), Some("image/png"));
    assert_eq!(
        cache_control.as_deref(),
        Some("private, no-store, no-cache, must-revalidate")
    );
    assert_eq!(pragma.as_deref(), Some("no-cache"));
    assert_eq!(nosniff.as_deref(), Some("nosniff"));
    assert_eq!(csp.as_deref(), Some("default-src 'none'"));
}

#[actix_web::test]
async fn get_avatar_rejects_metadata_that_declares_a_different_supported_image_type() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let sid = format!("avatar-mime-mismatch-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let user_dir = avatar_user_dir(&fixture.state, user.id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    tokio::fs::write(
        avatar_meta_path(&fixture.state, user.id),
        r#"{"content_type":"image/jpeg","version":"v1"}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(avatar_path(&fixture.state, user.id), valid_png())
        .await
        .unwrap();

    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), fixture.request(&sid, &csrf)).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn get_avatar_serves_the_committed_version_while_a_file_replacement_is_in_flight() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let sid = format!("avatar-in-flight-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let user_dir = avatar_user_dir(&fixture.state, user.id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    let old_avatar = valid_png();
    tokio::fs::write(avatar_path(&fixture.state, user.id), &old_avatar)
        .await
        .unwrap();
    tokio::fs::write(
        avatar_meta_path(&fixture.state, user.id),
        r#"{"content_type":"image/png","version":"v1"}"#,
    )
    .await
    .unwrap();
    let avatar_tmp = user_dir.join("avatar-v2.tmp");
    let metadata_tmp = user_dir.join("meta-v2.tmp");
    tokio::fs::write(&avatar_tmp, b"\xff\xd8\xffnew-avatar")
        .await
        .unwrap();
    tokio::fs::write(
        &metadata_tmp,
        r#"{"content_type":"image/jpeg","version":"v2"}"#,
    )
    .await
    .unwrap();
    let promotion = promote_avatar_files(
        &avatar_tmp,
        &metadata_tmp,
        avatar_path(&fixture.state, user.id),
        avatar_meta_path(&fixture.state, user.id),
        "v2",
    )
    .await
    .unwrap();

    let response = get_avatar(fixture.state.clone(), fixture.request(&sid, &csrf)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap(),
        old_avatar.as_slice()
    );

    rollback_avatar_promotion(&promotion).await;
}

#[cfg(unix)]
#[actix_web::test]
async fn get_avatar_rejects_a_symlinked_user_directory() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let sid = format!("avatar-symlink-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    tokio::fs::create_dir_all(&fixture.avatar_dir)
        .await
        .unwrap();
    let outside = temp_avatar_dir("symlink-outside");
    tokio::fs::create_dir_all(&outside).await.unwrap();
    tokio::fs::write(outside.join("avatar.bin"), b"\x89PNG\r\n\x1a\noutside")
        .await
        .unwrap();
    tokio::fs::write(
        outside.join("meta.json"),
        r#"{"content_type":"image/png","version":"v1"}"#,
    )
    .await
    .unwrap();
    let user_dir = avatar_user_dir(&fixture.state, user.id);
    let source = outside.clone();
    let target = user_dir.clone();
    tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(source, target))
        .await
        .unwrap()
        .unwrap();

    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), fixture.request(&sid, &csrf)).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    tokio::fs::remove_file(user_dir).await.unwrap();
    tokio::fs::remove_dir_all(outside).await.unwrap();
}

#[actix_web::test]
async fn get_avatar_rejects_unsupported_missing_and_unreadable_avatar_file_after_metadata_lookup() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let sid = format!("avatar-file-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let req = fixture.request(&sid, &csrf);
    let user_dir = avatar_user_dir(&fixture.state, user.id);
    tokio::fs::create_dir_all(&user_dir).await.unwrap();
    tokio::fs::write(
        avatar_meta_path(&fixture.state, user.id),
        r#"{"content_type":"text/plain","version":"v1"}"#,
    )
    .await
    .unwrap();

    tokio::fs::write(avatar_path(&fixture.state, user.id), b"plain-text-avatar")
        .await
        .unwrap();
    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), req.clone()).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());

    tokio::fs::remove_file(avatar_path(&fixture.state, user.id))
        .await
        .unwrap();
    let (status, body, _) =
        response_json(get_avatar(fixture.state.clone(), req.clone()).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());

    tokio::fs::create_dir(avatar_path(&fixture.state, user.id))
        .await
        .unwrap();
    let (status, body, _) = response_json(get_avatar(fixture.state.clone(), req).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());
}

#[actix_web::test]
async fn delete_avatar_removes_avatar_successfully_and_surfaces_file_removal_failures() {
    let Some(fixture) = LiveAvatarFixture::new().await else {
        return;
    };
    let success_suffix = Uuid::now_v7().simple().to_string();
    let success_user = fixture
        .create_user(&success_suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let success_sid = format!("avatar-delete-success-{success_suffix}");
    let success_csrf = format!("csrf-{success_suffix}");
    fixture.store_session(&success_user, &success_sid).await;
    let success_dir = avatar_user_dir(&fixture.state, success_user.id);
    tokio::fs::create_dir_all(&success_dir).await.unwrap();
    tokio::fs::write(avatar_path(&fixture.state, success_user.id), valid_png())
        .await
        .unwrap();
    tokio::fs::write(
        avatar_meta_path(&fixture.state, success_user.id),
        r#"{"content_type":"image/png","version":"v1"}"#,
    )
    .await
    .unwrap();

    let (status, body, has_set_cookie) = response_json(
        delete_avatar(
            fixture.state.clone(),
            fixture.request(&success_sid, &success_csrf),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert!(body["avatar_url"].is_null());
    assert!(
        fixture
            .fresh_user(success_user.id)
            .await
            .avatar_url
            .is_none()
    );
    assert!(
        !tokio::fs::try_exists(avatar_path(&fixture.state, success_user.id))
            .await
            .unwrap()
    );
    assert!(
        !tokio::fs::try_exists(avatar_meta_path(&fixture.state, success_user.id))
            .await
            .unwrap()
    );

    let avatar_error_suffix = format!("{success_suffix}-avatar-error");
    let avatar_error_user = fixture
        .create_user(&avatar_error_suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let avatar_error_sid = format!("avatar-delete-avatar-error-{avatar_error_suffix}");
    let avatar_error_csrf = format!("csrf-{avatar_error_suffix}");
    fixture
        .store_session(&avatar_error_user, &avatar_error_sid)
        .await;
    let avatar_error_dir = avatar_user_dir(&fixture.state, avatar_error_user.id);
    tokio::fs::create_dir_all(&avatar_error_dir).await.unwrap();
    tokio::fs::create_dir(avatar_path(&fixture.state, avatar_error_user.id))
        .await
        .unwrap();
    tokio::fs::write(
        avatar_meta_path(&fixture.state, avatar_error_user.id),
        r#"{"content_type":"image/png","version":"v1"}"#,
    )
    .await
    .unwrap();

    let (status, body, _) = response_json(
        delete_avatar(
            fixture.state.clone(),
            fixture.request(&avatar_error_sid, &avatar_error_csrf),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());
    assert_eq!(
        fixture
            .fresh_user(avatar_error_user.id)
            .await
            .avatar_url
            .as_deref(),
        Some("/auth/me/avatar?v=v1"),
        "a filesystem consistency failure must not clear persisted metadata"
    );

    let meta_error_suffix = format!("{success_suffix}-meta-error");
    let meta_error_user = fixture
        .create_user(&meta_error_suffix, Some("/auth/me/avatar?v=v1"))
        .await;
    let meta_error_sid = format!("avatar-delete-meta-error-{meta_error_suffix}");
    let meta_error_csrf = format!("csrf-{meta_error_suffix}");
    fixture
        .store_session(&meta_error_user, &meta_error_sid)
        .await;
    let meta_error_dir = avatar_user_dir(&fixture.state, meta_error_user.id);
    tokio::fs::create_dir_all(&meta_error_dir).await.unwrap();
    tokio::fs::write(
        avatar_path(&fixture.state, meta_error_user.id),
        b"\x89PNG\r\n\x1a\n",
    )
    .await
    .unwrap();
    tokio::fs::create_dir(avatar_meta_path(&fixture.state, meta_error_user.id))
        .await
        .unwrap();

    let (status, body, _) = response_json(
        delete_avatar(
            fixture.state.clone(),
            fixture.request(&meta_error_sid, &meta_error_csrf),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error_description"].is_string());
    assert_eq!(
        fixture
            .fresh_user(meta_error_user.id)
            .await
            .avatar_url
            .as_deref(),
        Some("/auth/me/avatar?v=v1"),
        "a filesystem consistency failure must not clear persisted metadata"
    );
}
