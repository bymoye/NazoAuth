use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use futures_util::future::join_all;
use nazo_auth::AuthorizationStateStorePort;
use nazo_identity::TenantId;
use nazo_resource_server::{DpopNonceStorage, DpopNonceValidationResult};
use nazo_valkey::{AuthorizationStateAdapter, ErrorKind, ReplayStore, ValkeyConnection};

fn explicit_valkey_url() -> Option<String> {
    std::env::var("VALKEY_URL").ok()
}

async fn inspection_client(url: &str) -> fred::prelude::Client {
    let client = Builder::from_config(Config::from_url(url).expect("VALKEY_URL should parse"))
        .build()
        .expect("inspection client should build");
    client
        .init()
        .await
        .expect("an explicitly configured Valkey must be available");
    client
}

fn tenant(value: u128) -> TenantId {
    TenantId::new(uuid::Uuid::from_u128(value)).expect("test tenant must be non-nil")
}

#[tokio::test]
async fn fapi_http_signature_replay_preserves_exact_key_value_and_ttl_contract() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let tenant_id = tenant(10);
    let fingerprint = [0xa5; 32];
    let key = nazo_valkey::test_support::state_storage_key(format!(
        "fapi_http_signature_replay:{}:{}",
        tenant_id.as_uuid(),
        blake3::Hash::from_bytes(fingerprint).to_hex()
    ));
    let _: i64 = inspector.del(&key).await.unwrap();

    assert!(
        store
            .consume_fapi_http_signature(tenant_id, &fingerprint, 10)
            .await
            .unwrap()
    );
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "1");
    let ttl = inspector.ttl::<i64, _>(&key).await.unwrap();
    assert!(ttl > 0 && ttl <= 15, "expected max-age + 5s TTL, got {ttl}");
    assert!(
        !store
            .consume_fapi_http_signature(tenant_id, &fingerprint, 10)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn fapi_http_signature_replay_isolated_by_tenant_after_cutover() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let first_tenant = tenant(101);
    let second_tenant = tenant(202);
    let fingerprint = *blake3::hash(uuid::Uuid::now_v7().as_bytes()).as_bytes();
    let digest = blake3::Hash::from_bytes(fingerprint).to_hex();
    let first_key = nazo_valkey::test_support::state_storage_key(format!(
        "fapi_http_signature_replay:{}:{digest}",
        first_tenant.as_uuid()
    ));
    let second_key = nazo_valkey::test_support::state_storage_key(format!(
        "fapi_http_signature_replay:{}:{digest}",
        second_tenant.as_uuid()
    ));
    let _: i64 = inspector
        .del(vec![first_key.clone(), second_key.clone()])
        .await
        .unwrap();

    assert!(
        store
            .consume_fapi_http_signature(first_tenant, &fingerprint, 10)
            .await
            .unwrap(),
        "the first reservation in a tenant must succeed"
    );
    assert!(
        store
            .consume_fapi_http_signature(second_tenant, &fingerprint, 10)
            .await
            .unwrap(),
        "the same fingerprint in another tenant must have an independent replay boundary"
    );
    assert!(
        !store
            .consume_fapi_http_signature(first_tenant, &fingerprint, 10)
            .await
            .unwrap(),
        "a replay in the same tenant must still fail closed"
    );
    assert_eq!(inspector.get::<String, _>(&first_key).await.unwrap(), "1");
    assert_eq!(inspector.get::<String, _>(&second_key).await.unwrap(), "1");
}

#[tokio::test]
async fn replay_store_distinguishes_unavailable_dependency() {
    let error = nazo_valkey::test_support::scoped_connect(
        "redis://127.0.0.1:1/0",
        Duration::from_millis(50),
    )
    .await
    .expect_err("closed local port must not connect");

    assert!(matches!(
        error.kind(),
        ErrorKind::Unavailable | ErrorKind::Timeout
    ));
}

#[tokio::test]
async fn replay_ttl_overflow_fails_before_storage() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);

    let error = store
        .consume_fapi_http_signature(tenant(10), &[0x5a; 32], i64::MAX)
        .await
        .expect_err("max-age + future skew overflow must fail closed");
    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
}

#[tokio::test]
async fn connection_rejects_cluster_topology_before_connecting() {
    let error = ValkeyConnection::connect(
        "redis-cluster://127.0.0.1:16384/0",
        Duration::from_secs(1),
        "test",
        uuid::Uuid::now_v7(),
        tenant(1),
    )
    .await
    .expect_err("multi-key scripts require an explicitly standalone topology");

    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
}

#[tokio::test]
async fn protocol_replay_keys_preserve_hashing_prefix_and_one_time_semantics() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let jkt = "thumbprint";
    let client_id = "client-a";
    let jti = "opaque-jti";
    let digest = blake3::hash(jti.as_bytes()).to_hex();
    let client_digest = blake3::hash(client_id.as_bytes()).to_hex();
    let keys = [
        format!("oauth:dpop:jti:{jkt}:{digest}"),
        format!("oauth:client_assertion:jti:{client_digest}:{digest}"),
        format!("oauth:jar:jti:{client_digest}:{digest}"),
        format!("oauth:jwt_bearer:jti:{client_digest}:{digest}"),
        format!("oauth:ciba:request_object:jti:{client_digest}:{digest}"),
    ]
    .map(nazo_valkey::test_support::state_storage_key);
    let _: i64 = inspector.del(keys.to_vec()).await.unwrap();

    assert!(store.consume_dpop(jkt, jti, 30).await.unwrap());
    assert!(
        store
            .consume_private_key_jwt(client_id, jti, 30)
            .await
            .unwrap()
    );
    assert!(store.consume_jar(client_id, jti, 30).await.unwrap());
    assert!(store.consume_jwt_bearer(client_id, jti, 30).await.unwrap());
    assert!(
        store
            .consume_ciba_request_object(client_id, jti, 30)
            .await
            .unwrap()
    );
    for key in &keys {
        assert_eq!(inspector.get::<String, _>(key).await.unwrap(), "1");
        assert!((1..=30).contains(&inspector.ttl::<i64, _>(key).await.unwrap()));
    }
    assert!(!store.consume_dpop(jkt, jti, 30).await.unwrap());
    assert!(
        !store
            .consume_private_key_jwt(client_id, jti, 30)
            .await
            .unwrap()
    );
    assert!(!store.consume_jar(client_id, jti, 30).await.unwrap());
    assert!(!store.consume_jwt_bearer(client_id, jti, 30).await.unwrap());
    assert!(
        !store
            .consume_ciba_request_object(client_id, jti, 30)
            .await
            .unwrap()
    );

    let adapter = AuthorizationStateAdapter::new(&connection);
    let adapter_jti = "adapter-jti";
    assert!(
        adapter
            .consume_ciba_request_object(client_id, adapter_jti, 30)
            .await
            .unwrap()
    );
    assert!(
        !adapter
            .consume_ciba_request_object(client_id, adapter_jti, 30)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn concurrent_private_key_jwt_consumers_have_exactly_one_winner() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let client_id = format!("concurrent-client-{}", uuid::Uuid::now_v7());
    let jti = format!("concurrent-jti-{}", uuid::Uuid::now_v7());
    let attempts = (0..32).map(|_| {
        let store = store.clone();
        let client_id = client_id.clone();
        let jti = jti.clone();
        async move {
            store
                .consume_private_key_jwt(&client_id, &jti, 30)
                .await
                .expect("Valkey replay consumption should succeed")
        }
    });

    let winners = join_all(attempts)
        .await
        .into_iter()
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(winners, 1, "SET NX must admit exactly one assertion");
}

#[tokio::test]
async fn concurrent_dpop_replay_consumers_have_exactly_one_winner() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let jkt = format!("concurrent-jkt-{}", uuid::Uuid::now_v7());
    let jti = format!("concurrent-jti-{}", uuid::Uuid::now_v7());
    let attempts = (0..32).map(|_| {
        let store = store.clone();
        let jkt = jkt.clone();
        let jti = jti.clone();
        async move {
            store
                .consume_dpop(&jkt, &jti, 300)
                .await
                .expect("Valkey DPoP replay consumption should succeed")
        }
    });

    let winners = join_all(attempts)
        .await
        .into_iter()
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(winners, 1, "SET NX must admit exactly one DPoP proof");
}

#[tokio::test]
async fn dpop_nonce_preserves_exact_key_and_remains_valid_until_expiry() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;
    let nonce = uuid::Uuid::now_v7().to_string();
    let key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:dpop:nonce:{}",
        blake3::hash(nonce.as_bytes()).to_hex()
    ));
    let _: i64 = inspector.del(&key).await.unwrap();

    store.issue_dpop_nonce(&nonce, 30).await.unwrap();
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "1");
    assert!(store.validate_dpop_nonce(&nonce).await.unwrap());
    assert!(store.validate_dpop_nonce(&nonce).await.unwrap());
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "1");
}

#[tokio::test]
async fn authorization_and_resource_server_share_the_nonce_key_and_ttl_contract() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let inspector = inspection_client(&url).await;

    let authorization_nonce = format!("as-{}", uuid::Uuid::now_v7());
    store
        .issue_dpop_nonce(&authorization_nonce, 30)
        .await
        .unwrap();
    assert_eq!(
        DpopNonceStorage::validate_nonce(&store, &authorization_nonce)
            .await
            .unwrap(),
        DpopNonceValidationResult::Accepted,
        "the resource-server endpoint must validate authorization-server nonce state"
    );

    let resource_nonce = format!("rs-{}", uuid::Uuid::now_v7());
    let key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:dpop:nonce:{}",
        blake3::hash(resource_nonce.as_bytes()).to_hex()
    ));
    let now = chrono::Utc::now().timestamp();
    DpopNonceStorage::issue_nonce(&store, &resource_nonce, now + 30)
        .await
        .unwrap();
    assert_eq!(inspector.get::<String, _>(&key).await.unwrap(), "1");
    let ttl: i64 = inspector.ttl(&key).await.unwrap();
    assert!(
        (1..=30).contains(&ttl),
        "resource-server expiry must map to the existing Valkey nonce TTL: {ttl}"
    );
    assert!(
        store.validate_dpop_nonce(&resource_nonce).await.unwrap(),
        "the authorization-server endpoint must validate resource-server nonce state"
    );
}

#[tokio::test]
async fn concurrent_resource_server_nonce_validations_share_the_validity_window() {
    let Some(url) = explicit_valkey_url() else {
        return;
    };
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let store = ReplayStore::new(&connection);
    let nonce = format!("rs-concurrent-{}", uuid::Uuid::now_v7());
    DpopNonceStorage::issue_nonce(
        &store,
        &nonce,
        chrono::Utc::now().timestamp().saturating_add(300),
    )
    .await
    .unwrap();

    let attempts = (0..32).map(|_| {
        let store = store.clone();
        let nonce = nonce.clone();
        async move {
            DpopNonceStorage::validate_nonce(&store, &nonce)
                .await
                .unwrap()
        }
    });
    let winners = join_all(attempts)
        .await
        .into_iter()
        .filter(|result| *result == DpopNonceValidationResult::Accepted)
        .count();
    assert_eq!(
        winners, 32,
        "RFC 9449 permits concurrent proofs with distinct jti values to share a valid nonce"
    );
}
