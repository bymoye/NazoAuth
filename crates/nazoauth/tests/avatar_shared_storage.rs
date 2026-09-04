//! Cross-instance proof for the provider-neutral direct avatar flow.
//!
//! The test deliberately composes the identity service from the production
//! PostgreSQL, Valkey, and object-store adapters.  It does not start an HTTP
//! server: the browser leg is the real signed PUT to MinIO, while the
//! application legs exercise the same service that the HTTP handlers call.
//!
//! Without the three `NAZO_TEST_*` backends this test skips locally so a plain
//! checkout remains hermetic.  CI must provide all of them.

use std::{env, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    AvatarContentType, AvatarDirectUploadService, TenantId, UserId,
    ports::{
        AvatarDirectUploadPort, AvatarRepositoryPort, AvatarUploadStatePort,
        GrantSummaryRepositoryPort,
    },
};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};
use nazo_postgres::{
    GrantRepository, UserRepository, create_pool, get_conn, run_pending_migrations,
};
use nazo_valkey::{AvatarUploadStateStore, ValkeyConnection};
use uuid::Uuid;

const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);
const DEFAULT_REALM_ID: Uuid = Uuid::from_u128(2);
const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(3);
const DEPLOYMENT_ID: &str = "avatar-shared-storage";
const MAX_BYTES: usize = 1_024 * 1_024;
const UPLOAD_TTL_SECONDS: u64 = 300;
const CLAIM_LEASE_SECONDS: u64 = 30;

const S3_ENDPOINT: &str = "NAZO_TEST_S3_ENDPOINT";
const S3_BUCKET: &str = "NAZO_TEST_S3_BUCKET";
const S3_ACCESS_KEY: &str = "NAZO_TEST_S3_ACCESS_KEY";
const S3_SECRET_KEY: &str = "NAZO_TEST_S3_SECRET_KEY";
const S3_REGION: &str = "NAZO_TEST_S3_REGION";

struct TestConfig {
    database_url: String,
    valkey_url: String,
    s3: S3AvatarObjectStoreConfig,
}

fn test_config() -> Option<TestConfig> {
    let database_url = env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .ok();
    let valkey_url = env::var("NAZO_TEST_VALKEY_URL")
        .or_else(|_| env::var("VALKEY_URL"))
        .ok();
    let s3 = s3_config();
    if database_url.is_none() || valkey_url.is_none() || s3.is_none() {
        if env::var_os("CI").is_some() {
            panic!(
                "avatar shared-storage integration requires database, Valkey, and all NAZO_TEST_S3_* variables"
            );
        }
        return None;
    }
    Some(TestConfig {
        database_url: database_url.expect("database URL checked above"),
        valkey_url: valkey_url.expect("Valkey URL checked above"),
        s3: s3.expect("S3 configuration checked above"),
    })
}

fn s3_config() -> Option<S3AvatarObjectStoreConfig> {
    let values = [
        S3_ENDPOINT,
        S3_BUCKET,
        S3_ACCESS_KEY,
        S3_SECRET_KEY,
        S3_REGION,
    ]
    .into_iter()
    .map(|key| (key, env::var(key).ok()))
    .collect::<Vec<_>>();
    if values.iter().all(|(_, value)| value.is_none()) {
        return None;
    }
    let value = |key| {
        values
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .and_then(|(_, value)| value.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| panic!("{key} must be set when any MinIO test variable is set"))
    };
    Some(S3AvatarObjectStoreConfig {
        endpoint: value(S3_ENDPOINT),
        region: value(S3_REGION),
        bucket: value(S3_BUCKET),
        access_key: value(S3_ACCESS_KEY),
        secret_key: value(S3_SECRET_KEY),
        path_style: true,
    })
}

async fn insert_test_user(pool: &nazo_postgres::DbPool, user_id: Uuid) {
    let mut connection = get_conn(pool)
        .await
        .expect("test database connection should be available");
    sql_query(
        r#"
        INSERT INTO users (
            id, tenant_id, realm_id, organization_id, username, email,
            password_hash, is_active, mfa_enabled, email_verified, role,
            admin_level, avatar_url
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, 'avatar-shared-storage-test-hash',
            TRUE, FALSE, TRUE, 'user', 0, NULL
        )
        "#,
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<diesel::sql_types::Text, _>(format!("avatar-shared-{user_id}"))
    .bind::<diesel::sql_types::Text, _>(format!("avatar-shared-{user_id}@example.test"))
    .execute(&mut connection)
    .await
    .expect("test user should insert");
}

async fn delete_test_user(pool: &nazo_postgres::DbPool, user_id: Uuid) -> anyhow::Result<()> {
    let mut connection = get_conn(pool).await?;
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await?;
    Ok(())
}

fn valid_png() -> Vec<u8> {
    STANDARD
        .decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==",
        )
        .expect("static PNG fixture should decode")
}

async fn browser_put(
    target: &nazo_identity::ports::AvatarUploadTarget,
    bytes: &[u8],
) -> Result<(), String> {
    let method = reqwest::Method::from_bytes(target.method.as_bytes())
        .map_err(|error| format!("invalid upload method: {error}"))?;
    let client = reqwest::Client::new();
    let mut request = client.request(method, &target.url);
    for (name, value) in &target.headers {
        request = request.header(name, value);
    }
    let response = request
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "object store returned HTTP {status}: {}",
            response.text().await.unwrap_or_default()
        ))
    }
}

#[tokio::test]
async fn avatar_direct_upload_converges_across_real_instances() {
    let Some(config) = test_config() else {
        return;
    };
    run_avatar_flow(config).await;
}

async fn run_avatar_flow(config: TestConfig) {
    run_pending_migrations(&config.database_url)
        .await
        .expect("application migrations should be applied");

    let tenant_id = TenantId::new(DEFAULT_TENANT_ID).expect("default tenant is non-nil");
    let user_id = Uuid::now_v7();

    let database_a = create_pool(&config.database_url, 2).expect("instance A database pool");
    let database_b = create_pool(&config.database_url, 2).expect("instance B database pool");
    insert_test_user(&database_a, user_id).await;
    let cleanup_database = database_a.clone();

    let users_a = Arc::new(UserRepository::new(database_a.clone()));
    let users_b = Arc::new(UserRepository::new(database_b.clone()));
    let grants_a = Arc::new(GrantRepository::new(database_a));
    let grants_b = Arc::new(GrantRepository::new(database_b));

    let state_epoch = Uuid::now_v7();
    let valkey_a = ValkeyConnection::connect(
        &config.valkey_url,
        Duration::from_secs(5),
        DEPLOYMENT_ID,
        state_epoch,
        tenant_id,
    )
    .await
    .expect("instance A Valkey connection");
    let valkey_b = ValkeyConnection::connect(
        &config.valkey_url,
        Duration::from_secs(5),
        DEPLOYMENT_ID,
        state_epoch,
        tenant_id,
    )
    .await
    .expect("instance B Valkey connection");

    let storage_a = Arc::new(
        S3AvatarObjectStore::new(config.s3.clone(), tenant_id)
            .expect("instance A object-store adapter"),
    );
    let storage_b = Arc::new(
        S3AvatarObjectStore::new(config.s3, tenant_id).expect("instance B object-store adapter"),
    );
    let avatar_repo_a: Arc<dyn AvatarRepositoryPort> = users_a.clone();
    let avatar_repo_b: Arc<dyn AvatarRepositoryPort> = users_b.clone();
    let grant_repo_a: Arc<dyn GrantSummaryRepositoryPort> = grants_a;
    let grant_repo_b: Arc<dyn GrantSummaryRepositoryPort> = grants_b;
    let storage_port_a: Arc<dyn AvatarDirectUploadPort> = storage_a.clone();
    let storage_port_b: Arc<dyn AvatarDirectUploadPort> = storage_b.clone();
    let state_port_a: Arc<dyn AvatarUploadStatePort> =
        Arc::new(AvatarUploadStateStore::new(&valkey_a));
    let state_port_b: Arc<dyn AvatarUploadStatePort> =
        Arc::new(AvatarUploadStateStore::new(&valkey_b));
    let service_a = AvatarDirectUploadService::from_ports(
        avatar_repo_a,
        grant_repo_a,
        storage_port_a,
        state_port_a,
        MAX_BYTES,
        UPLOAD_TTL_SECONDS,
        CLAIM_LEASE_SECONDS,
    );
    let service_b = AvatarDirectUploadService::from_ports(
        avatar_repo_b,
        grant_repo_b,
        storage_port_b,
        state_port_b,
        MAX_BYTES,
        UPLOAD_TTL_SECONDS,
        CLAIM_LEASE_SECONDS,
    );

    let account_a = users_a
        .public_account_by_id(tenant_id, UserId::new(user_id).unwrap())
        .await
        .expect("instance A account lookup")
        .expect("test account should exist");
    let original = valid_png();
    let start = service_a
        .begin_upload(&account_a, original.len())
        .await
        .expect("instance A should authorize the upload");
    println!("avatar integration upload={}", start.upload_id);
    browser_put(&start.target, &original)
        .await
        .expect("browser should PUT the image directly to MinIO");

    let account_b = users_b
        .public_account_by_id(tenant_id, UserId::new(user_id).unwrap())
        .await
        .expect("instance B account lookup")
        .expect("test account should exist for instance B");
    let completed_b = service_b
        .complete_upload(&account_b, &start.upload_id)
        .await
        .expect("instance B should finalize instance A's upload");
    let final_url = completed_b
        .account
        .profile
        .avatar_url
        .clone()
        .expect("final avatar URL should be persisted");
    assert!(final_url.starts_with("/auth/me/avatar?v="));
    println!("avatar integration final={final_url}");
    let read_b = service_b
        .read(&completed_b.account)
        .await
        .expect("instance B should read the final object");
    assert_eq!(read_b.bytes, original);
    assert_eq!(read_b.content_type, AvatarContentType::Png);

    // The original signed staging target may be replayed, but the accepted
    // final object is immutable and the completed state fixes its candidate.
    let replay = vec![b'R'; original.len()];
    browser_put(&start.target, &replay)
        .await
        .expect("the still-valid staging target should accept a replay");
    let account_a_after = users_a
        .public_account_by_id(tenant_id, UserId::new(user_id).unwrap())
        .await
        .expect("instance A retry account lookup")
        .expect("test account should still exist");
    let retried_a = service_a
        .complete_upload(&account_a_after, &start.upload_id)
        .await
        .expect("instance A retry should return the completed result");
    assert_eq!(
        retried_a.account.profile.avatar_url.as_deref(),
        Some(final_url.as_str())
    );
    let read_a = service_a
        .read(&retried_a.account)
        .await
        .expect("instance A should read the immutable final object");
    assert_eq!(read_a.bytes, original);
    assert_eq!(read_a.content_type, AvatarContentType::Png);

    service_a
        .delete(&retried_a.account)
        .await
        .expect("avatar delete should clear the database reference before storage cleanup");
    storage_a
        .delete_staging(&start.upload_id)
        .await
        .expect("staging cleanup should succeed");
    delete_test_user(&cleanup_database, user_id)
        .await
        .expect("test user cleanup should succeed");
}
