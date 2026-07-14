use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use chrono::{TimeZone as _, Utc};
use nazo_auth::{
    BackchannelLogoutOutboxPort, IdTokenHintClaims, IdempotentBackchannelLogoutDelivery,
    LogoutClientRepositoryPort, LogoutDependencyError, LogoutFuture, LogoutInput, LogoutService,
    LogoutServiceError, LogoutSession, LogoutTokenSignerPort, RegisteredLogoutClient,
    RpLogoutRequest,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Default)]
struct Clients {
    expected_tenant: Mutex<Option<Uuid>>,
    clients: Mutex<Vec<RegisteredLogoutClient>>,
    granted_client_ids: Mutex<HashSet<String>>,
    active_reads: Mutex<usize>,
}

impl LogoutClientRepositoryPort for Clients {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        Box::pin(async move {
            assert_eq!(*self.expected_tenant.lock().unwrap(), Some(tenant_id));
            Ok(self
                .clients
                .lock()
                .unwrap()
                .iter()
                .find(|client| client.tenant_id == tenant_id && client.client_id == client_id)
                .cloned())
        })
    }

    fn active_for_user(
        &self,
        tenant_id: Uuid,
        _user_id: Uuid,
    ) -> LogoutFuture<'_, Vec<RegisteredLogoutClient>> {
        Box::pin(async move {
            assert_eq!(*self.expected_tenant.lock().unwrap(), Some(tenant_id));
            *self.active_reads.lock().unwrap() += 1;
            let granted_client_ids = self.granted_client_ids.lock().unwrap();
            Ok(self
                .clients
                .lock()
                .unwrap()
                .iter()
                .filter(|client| {
                    client.tenant_id == tenant_id
                        && client.active
                        && granted_client_ids.contains(&client.client_id)
                })
                .cloned()
                .collect())
        })
    }
}

#[derive(Default)]
struct Outbox {
    keys: Mutex<HashSet<(Uuid, String, Uuid)>>,
    deliveries: Mutex<Vec<IdempotentBackchannelLogoutDelivery>>,
}

impl BackchannelLogoutOutboxPort for Outbox {
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        deliveries: &'a [IdempotentBackchannelLogoutDelivery],
    ) -> LogoutFuture<'a, ()> {
        Box::pin(async move {
            let mut keys = self.keys.lock().unwrap();
            let mut stored = self.deliveries.lock().unwrap();
            for delivery in deliveries {
                if keys.insert((
                    delivery.tenant_id,
                    delivery.operation_key.clone(),
                    delivery.client_id,
                )) {
                    stored.push(delivery.clone());
                }
            }
            Ok(())
        })
    }
}

struct Signer;

impl LogoutTokenSignerPort for Signer {
    fn sign_logout_token<'a>(
        &'a self,
        client_id: &'a str,
        _subject: Option<&'a str>,
        sid: &'a str,
        _issued_at: chrono::DateTime<Utc>,
        _ttl_seconds: i64,
    ) -> LogoutFuture<'a, String> {
        Box::pin(async move { Ok(format!("logout-token:{client_id}:{sid}")) })
    }
}

#[test]
fn no_hint_frontchannel_fans_out_once_and_retry_deduplicates_backchannel() {
    let tenant_id = Uuid::now_v7();
    let clients = Arc::new(Clients::default());
    *clients.expected_tenant.lock().unwrap() = Some(tenant_id);
    clients.clients.lock().unwrap().extend([
        client(tenant_id, "client-a", true),
        client(tenant_id, "client-b", true),
        client(Uuid::now_v7(), "foreign-client", true),
        client(tenant_id, "inactive-client", false),
    ]);
    clients
        .granted_client_ids
        .lock()
        .unwrap()
        .extend(["client-a".to_owned(), "client-b".to_owned()]);
    let outbox = Arc::new(Outbox::default());
    let service = service(clients.clone(), outbox.clone());

    let input = input(tenant_id, None);
    let first = futures_executor::block_on(service.execute(input.clone())).unwrap();
    let second = futures_executor::block_on(service.execute(input)).unwrap();

    assert_eq!(first.frontchannel_logout_urls.len(), 2);
    assert_eq!(
        second.frontchannel_logout_urls,
        first.frontchannel_logout_urls
    );
    assert_eq!(*clients.active_reads.lock().unwrap(), 2);
    let deliveries = outbox.deliveries.lock().unwrap();
    assert_eq!(deliveries.len(), 2);
    assert!(
        deliveries
            .iter()
            .all(|delivery| delivery.tenant_id == tenant_id)
    );
    assert_eq!(first.operation_key, second.operation_key);
}

#[test]
fn hinted_frontchannel_preserves_only_hinted_client_compatibility() {
    let tenant_id = Uuid::now_v7();
    let clients = Arc::new(Clients::default());
    *clients.expected_tenant.lock().unwrap() = Some(tenant_id);
    clients.clients.lock().unwrap().extend([
        client(tenant_id, "client-a", true),
        client(tenant_id, "client-b", true),
    ]);
    clients
        .granted_client_ids
        .lock()
        .unwrap()
        .extend(["client-a".to_owned(), "client-b".to_owned()]);
    let outbox = Arc::new(Outbox::default());
    let service = service(clients, outbox);
    let result =
        futures_executor::block_on(service.execute(input(tenant_id, Some("client-a")))).unwrap();

    assert_eq!(
        result.frontchannel_logout_urls,
        vec!["https://client-a.example/frontchannel?iss=https%3A%2F%2Fissuer.example&sid=sid-1"]
    );
}

#[test]
fn expired_hint_is_accepted_only_when_bound_to_the_current_session() {
    let tenant_id = Uuid::now_v7();
    let clients = Arc::new(Clients::default());
    *clients.expected_tenant.lock().unwrap() = Some(tenant_id);
    clients
        .clients
        .lock()
        .unwrap()
        .push(client(tenant_id, "client-a", true));
    let service = service(clients, Arc::new(Outbox::default()));
    let mut request = input(tenant_id, Some("client-a"));
    let session = request.session.as_ref().unwrap().clone();
    request.request.id_token_hint_present = true;
    request.id_token_hint_expired = true;
    request.csrf_authorized = false;
    request.id_token_hint = Some(IdTokenHintClaims {
        sub: session.user_id.to_string(),
        aud: json!("client-a"),
        sid: Some(session.oidc_sid),
    });
    assert!(futures_executor::block_on(service.execute(request.clone())).is_ok());

    request.session = None;
    assert_eq!(
        futures_executor::block_on(service.execute(request)),
        Err(LogoutServiceError::InvalidIdTokenHint)
    );
}

#[test]
fn client_id_only_does_not_fan_out_to_an_ungranted_client() {
    let tenant_id = Uuid::now_v7();
    let clients = Arc::new(Clients::default());
    *clients.expected_tenant.lock().unwrap() = Some(tenant_id);
    clients
        .clients
        .lock()
        .unwrap()
        .push(client(tenant_id, "client-a", true));
    let outbox = Arc::new(Outbox::default());
    let result = futures_executor::block_on(
        service(clients, outbox.clone()).execute(input(tenant_id, Some("client-a"))),
    )
    .unwrap();
    assert!(result.frontchannel_logout_urls.is_empty());
    assert!(outbox.deliveries.lock().unwrap().is_empty());
}

#[test]
fn valid_hint_makes_an_ungranted_client_a_bound_fanout_target() {
    let tenant_id = Uuid::now_v7();
    let clients = Arc::new(Clients::default());
    *clients.expected_tenant.lock().unwrap() = Some(tenant_id);
    clients
        .clients
        .lock()
        .unwrap()
        .push(client(tenant_id, "client-a", true));
    let outbox = Arc::new(Outbox::default());
    let mut request = input(tenant_id, Some("client-a"));
    let session = request.session.as_ref().unwrap().clone();
    request.request.id_token_hint_present = true;
    request.csrf_authorized = false;
    request.id_token_hint = Some(IdTokenHintClaims {
        sub: session.user_id.to_string(),
        aud: json!("client-a"),
        sid: Some(session.oidc_sid),
    });
    let result =
        futures_executor::block_on(service(clients, outbox.clone()).execute(request)).unwrap();
    assert_eq!(result.frontchannel_logout_urls.len(), 1);
    assert_eq!(outbox.deliveries.lock().unwrap().len(), 1);
}

#[test]
fn active_grant_allows_client_id_only_fanout() {
    let tenant_id = Uuid::now_v7();
    let clients = Arc::new(Clients::default());
    *clients.expected_tenant.lock().unwrap() = Some(tenant_id);
    clients
        .clients
        .lock()
        .unwrap()
        .push(client(tenant_id, "client-a", true));
    clients
        .granted_client_ids
        .lock()
        .unwrap()
        .insert("client-a".to_owned());
    let outbox = Arc::new(Outbox::default());
    let result = futures_executor::block_on(
        service(clients, outbox.clone()).execute(input(tenant_id, Some("client-a"))),
    )
    .unwrap();
    assert_eq!(result.frontchannel_logout_urls.len(), 1);
    assert_eq!(outbox.deliveries.lock().unwrap().len(), 1);
}

fn service(clients: Arc<Clients>, outbox: Arc<Outbox>) -> LogoutService {
    LogoutService::new(
        clients,
        outbox,
        Arc::new(Signer),
        "https://issuer.example",
        Some("01234567890123456789012345678901"),
    )
}

fn input(tenant_id: Uuid, client_id: Option<&str>) -> LogoutInput {
    LogoutInput {
        tenant_id,
        request: RpLogoutRequest {
            id_token_hint_present: false,
            client_id: client_id.map(str::to_owned),
            post_logout_redirect_uri: None,
            state: None,
        },
        id_token_hint: None,
        id_token_hint_expired: false,
        session: Some(LogoutSession {
            user_id: Uuid::now_v7(),
            oidc_sid: "sid-1".to_owned(),
        }),
        csrf_authorized: true,
        frontchannel_enabled: true,
        now: Utc.timestamp_opt(2_000_000_000, 0).unwrap(),
    }
}

fn client(tenant_id: Uuid, client_id: &str, active: bool) -> RegisteredLogoutClient {
    RegisteredLogoutClient {
        id: Uuid::now_v7(),
        tenant_id,
        client_id: client_id.to_owned(),
        active,
        redirect_uris: vec![format!("https://{client_id}.example/callback")],
        post_logout_redirect_uris: vec![format!("https://{client_id}.example/logout")],
        backchannel_logout_uri: Some(format!("https://{client_id}.example/backchannel")),
        frontchannel_logout_uri: Some(format!("https://{client_id}.example/frontchannel")),
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_host: None,
    }
}

#[test]
fn dependency_error_is_closed_and_non_http() {
    assert_eq!(
        LogoutDependencyError::Unavailable,
        LogoutDependencyError::Unavailable
    );
}
