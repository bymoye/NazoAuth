use std::time::Duration;

use fred::interfaces::LuaInterface;
use nazo_auth::{
    CibaAuthenticationContext, CibaDecision, CibaPingNotification, CibaPingNotificationStatus,
    CibaRequestState, CibaService, CibaStatus,
};
use nazo_identity::{TenantId, UserId, session::SessionRecord};
use nazo_valkey::{
    CibaPingFinishOutcome, CibaPingFinishResult, CibaStore, SessionStore, ValkeyClient,
    ValkeyConnection,
};
use uuid::Uuid;

fn tenant(value: u128) -> TenantId {
    TenantId::new(Uuid::from_u128(value)).expect("test tenant must be non-nil")
}

async fn server_time(client: &fred::prelude::Client) -> i64 {
    client
        .eval::<String, _, _, _>(
            "return tostring(redis.call('TIME')[1])",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await
        .expect("read Valkey server time")
        .parse()
        .expect("Valkey server time is an integer")
}

#[test]
fn tenant_is_part_of_every_physical_state_key() {
    let epoch = Uuid::from_u128(0x301);
    let business_key = "oauth:session:same-session";
    let first =
        nazo_valkey::test_support::storage_key("deployment", epoch, tenant(0x100), business_key)
            .expect("valid first physical key");
    let second =
        nazo_valkey::test_support::storage_key("deployment", epoch, tenant(0x101), business_key)
            .expect("valid second physical key");

    assert_ne!(first, second);
    assert!(
        first.ends_with(":tenant:00000000-0000-0000-0000-000000000100:oauth:session:same-session")
    );
    assert!(
        second.ends_with(":tenant:00000000-0000-0000-0000-000000000101:oauth:session:same-session")
    );
}

#[tokio::test]
async fn two_tenants_can_store_the_same_logical_key_without_conflict() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let client = nazo_valkey::test_support::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let first_connection =
        nazo_valkey::test_support::tenant_scoped_connection(client.clone(), tenant(0x200));
    let second_connection =
        nazo_valkey::test_support::tenant_scoped_connection(client, tenant(0x201));
    let first_store = SessionStore::new(&first_connection);
    let second_store = SessionStore::new(&second_connection);
    let session_id = format!("shared-{}", Uuid::now_v7());
    let first_record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x300)).expect("user id"),
        1_000,
        vec!["first".to_owned()],
        false,
        None,
    );
    let second_record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x301)).expect("user id"),
        2_000,
        vec!["second".to_owned()],
        false,
        None,
    );

    first_store
        .store(&session_id, &first_record, 30)
        .await
        .expect("store first tenant state");
    second_store
        .store(&session_id, &second_record, 30)
        .await
        .expect("store second tenant state");

    assert_eq!(
        first_store
            .load(&session_id)
            .await
            .expect("load first tenant state")
            .expect("first tenant state exists")
            .value(),
        &first_record
    );
    assert_eq!(
        second_store
            .load(&session_id)
            .await
            .expect("load second tenant state")
            .expect("second tenant state exists")
            .value(),
        &second_record
    );

    first_store
        .delete(&session_id)
        .await
        .expect("remove first fixture");
    second_store
        .delete(&session_id)
        .await
        .expect("remove second fixture");
}

#[tokio::test]
async fn ciba_ping_queue_is_isolated_between_tenants_with_the_same_auth_req_id() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let client = nazo_valkey::test_support::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let now = server_time(&client).await;
    let deployment_id = format!("ciba-isolation-{}", Uuid::now_v7());
    let state_epoch = Uuid::now_v7();
    let tenant_a = tenant(0x500);
    let tenant_b = tenant(0x501);
    let valkey = ValkeyClient::from_existing_client(client, &deployment_id, state_epoch)
        .expect("valid shared deployment namespace");
    let store_a = CibaStore::new(&valkey.for_tenant(tenant_a));
    let store_b = CibaStore::new(&valkey.for_tenant(tenant_b));
    let auth_req_id = format!("shared-ciba-{}", Uuid::now_v7());
    let endpoint_a = "https://tenant-a.example/ciba";
    let endpoint_b = "https://tenant-b.example/ciba";
    let token_a = "tenant-a-notification-token";
    let token_b = "tenant-b-notification-token";
    let user_a = Uuid::from_u128(0x502);
    let user_b = Uuid::from_u128(0x503);
    let pending_state = |client_id: &str, user_id, endpoint: &str, token: &str| CibaRequestState {
        client_id: client_id.to_owned(),
        user_id,
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        acr: None,
        authentication_context: None,
        binding_message: None,
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
        ping_notification: Some(CibaPingNotification {
            auth_req_id: None,
            endpoint: endpoint.to_owned(),
            client_notification_token: Some(token.to_owned()),
            status: CibaPingNotificationStatus::AwaitingDecision,
            attempts: 0,
            next_attempt_at: None,
        }),
    };

    for (store, client_id, user_id, endpoint, token) in [
        (&store_a, "client-a", user_a, endpoint_a, token_a),
        (&store_b, "client-b", user_b, endpoint_b, token_b),
    ] {
        let generated_auth_req_id = auth_req_id.clone();
        assert_eq!(
            CibaService::new(store.clone())
                .create_unique(&pending_state(client_id, user_id, endpoint, token), || {
                    generated_auth_req_id.clone()
                },)
                .await
                .expect("create tenant CIBA state"),
            auth_req_id
        );
        CibaService::new(store.clone())
            .decide(
                &auth_req_id,
                CibaDecision::Approve(CibaAuthenticationContext {
                    auth_time: now,
                    amr: vec!["pwd".to_owned()],
                    oidc_sid: None,
                }),
                Some(user_id),
                || now,
            )
            .await
            .expect("schedule tenant ping delivery");
    }

    let delivery_a = store_a
        .claim_due_ping(now, now + 15, 10)
        .await
        .expect("claim tenant A ping");
    assert_eq!(delivery_a.len(), 1);
    assert_eq!(delivery_a[0].auth_req_id, auth_req_id);
    assert_eq!(delivery_a[0].endpoint, endpoint_a);
    assert_eq!(delivery_a[0].client_notification_token, token_a);

    assert_eq!(
        store_a
            .finish_ping(&delivery_a[0], CibaPingFinishOutcome::Delivered)
            .await
            .expect("finish tenant A ping"),
        CibaPingFinishResult::Applied
    );
    let stored_b = store_b
        .load(&auth_req_id)
        .await
        .expect("load tenant B CIBA state")
        .expect("tenant B CIBA state remains");
    let notification_b = stored_b
        .state()
        .ping_notification
        .as_ref()
        .expect("tenant B ping state remains");
    assert_eq!(notification_b.status, CibaPingNotificationStatus::Pending);
    assert_eq!(notification_b.endpoint, endpoint_b);
    assert_eq!(
        notification_b.client_notification_token.as_deref(),
        Some(token_b)
    );
    let delivery_b = store_b
        .claim_due_ping(now, now + 15, 10)
        .await
        .expect("claim tenant B ping after tenant A completes");
    assert_eq!(delivery_b.len(), 1);
    assert_eq!(delivery_b[0].auth_req_id, auth_req_id);
    assert_eq!(delivery_b[0].endpoint, endpoint_b);
    assert_eq!(delivery_b[0].client_notification_token, token_b);

    assert_eq!(
        store_b
            .finish_ping(&delivery_b[0], CibaPingFinishOutcome::Delivered)
            .await
            .expect("finish tenant B ping"),
        CibaPingFinishResult::Applied
    );
    let stored_a = store_a
        .load(&auth_req_id)
        .await
        .expect("load tenant A cleanup state")
        .expect("tenant A cleanup state exists");
    let stored_b = store_b
        .load(&auth_req_id)
        .await
        .expect("load tenant B cleanup state")
        .expect("tenant B cleanup state exists");
    store_a
        .delete(&auth_req_id, stored_a.version())
        .await
        .expect("remove tenant A fixture");
    store_b
        .delete(&auth_req_id, stored_b.version())
        .await
        .expect("remove tenant B fixture");
}

#[tokio::test]
async fn deployment_and_epoch_remain_physical_key_boundaries() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let epoch_a = Uuid::from_u128(0x401);
    let epoch_b = Uuid::from_u128(0x402);
    let tenant_id = tenant(0x403);
    let connection_a = ValkeyConnection::connect(
        &url,
        Duration::from_secs(1),
        "deployment-a",
        epoch_a,
        tenant_id,
    )
    .await
    .expect("connect first namespace");
    let connection_b = ValkeyConnection::connect(
        &url,
        Duration::from_secs(1),
        "deployment-b",
        epoch_b,
        tenant_id,
    )
    .await
    .expect("connect second namespace");
    let session_id = format!("namespace-{}", Uuid::now_v7());
    let record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x404)).expect("user id"),
        1_000,
        vec!["password".to_owned()],
        false,
        None,
    );

    SessionStore::new(&connection_a)
        .store(&session_id, &record, 30)
        .await
        .expect("store in first explicit namespace");
    assert!(
        SessionStore::new(&connection_b)
            .load(&session_id)
            .await
            .expect("load second namespace")
            .is_none()
    );
    SessionStore::new(&connection_a)
        .delete(&session_id)
        .await
        .expect("remove fixture");
}
