use futures_executor::block_on;
use nazo_auth::{
    CibaAtomicResult, CibaPingNotification, CibaPingNotificationStatus, CibaRequestState,
    CibaService, CibaStateFuture, CibaStateStorePort, CibaStatus, CibaStoredRequest,
};
use uuid::Uuid;

struct CreateStore;

impl CibaStateStorePort for CreateStore {
    type Version = ();

    fn load<'a>(
        &'a self,
        _auth_req_id: &'a str,
    ) -> CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>> {
        Box::pin(async { Ok(None) })
    }

    fn create<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        assert_eq!(auth_req_id, "generated-auth-req-id");
        let notification = state
            .ping_notification
            .as_ref()
            .expect("ping state must reach the adapter");
        assert_eq!(notification.auth_req_id, None);
        assert_eq!(
            notification.status,
            CibaPingNotificationStatus::AwaitingDecision
        );
        Box::pin(async { Ok(CibaAtomicResult::Applied) })
    }

    fn replace<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
        _state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        unreachable!("creation does not replace state")
    }

    fn delete<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        unreachable!("creation does not delete state")
    }
}

#[test]
fn ping_creation_allows_the_adapter_to_atomically_bind_auth_req_id() {
    let state = CibaRequestState {
        client_id: "ping-client".to_owned(),
        user_id: Uuid::from_u128(7),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        acr: None,
        authentication_context: None,
        binding_message: None,
        issued_at: 100,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: 200,
        retention_expires_at: 320,
        last_poll_at: None,
        ping_notification: Some(CibaPingNotification {
            auth_req_id: None,
            endpoint: "https://client.example/ciba-notification".to_owned(),
            client_notification_token: Some("notification-token".to_owned()),
            status: CibaPingNotificationStatus::AwaitingDecision,
            attempts: 0,
            next_attempt_at: None,
        }),
    };

    let auth_req_id = block_on(
        CibaService::new(CreateStore).create_unique(&state, || "generated-auth-req-id".to_owned()),
    )
    .expect("valid pre-persistence ping state must be accepted");

    assert_eq!(auth_req_id, "generated-auth-req-id");
}
