use futures_executor::block_on;
use nazo_auth::{
    CibaAtomicResult, CibaAuthenticationContext, CibaCreateFailure, CibaDecision,
    CibaDecisionEvaluation, CibaPingNotification, CibaPingNotificationStatus, CibaRequestState,
    CibaService, CibaStateFuture, CibaStateStorePort, CibaStatus, CibaStoredRequest,
    evaluate_ciba_decision_with_authentication_context,
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
        Box::pin(async { Ok(CibaAtomicResult::Applied) })
    }

    fn delete<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        Box::pin(async { Ok(CibaAtomicResult::Applied) })
    }
}

#[test]
fn lease_deadline_defaults_delegate_to_the_atomic_store_operations() {
    let state = CibaRequestState {
        client_id: "lease-client".to_owned(),
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
            endpoint: "https://client.example/ciba".to_owned(),
            client_notification_token: None,
            status: CibaPingNotificationStatus::AwaitingDecision,
            attempts: 0,
            next_attempt_at: None,
        }),
    };
    let store = CreateStore;
    assert_eq!(
        block_on(store.create_with_lease_deadline("generated-auth-req-id", &state, Some(150),))
            .unwrap(),
        CibaAtomicResult::Applied
    );
    assert_eq!(
        block_on(store.replace_with_lease_deadline("auth-req-id", &(), &state, Some(150))).unwrap(),
        CibaAtomicResult::Applied
    );
    assert_eq!(
        block_on(store.delete_with_lease_deadline("auth-req-id", &(), Some(150))).unwrap(),
        CibaAtomicResult::Applied
    );
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

#[test]
fn authentication_context_is_bound_on_approval_and_invalid_context_is_rejected() {
    let user_id = Uuid::from_u128(7);
    let context = CibaAuthenticationContext {
        auth_time: 100,
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        oidc_sid: Some("session-1".to_owned()),
    };
    let state = CibaRequestState {
        client_id: "context-client".to_owned(),
        user_id,
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
        ping_notification: None,
    };

    let evaluation = evaluate_ciba_decision_with_authentication_context(
        &state,
        Some(user_id),
        CibaDecision::Approve,
        Some(context.clone()),
        150,
    );
    let CibaDecisionEvaluation::Commit(next) = evaluation else {
        panic!("approval should commit");
    };
    assert_eq!(next.authentication_context, Some(context));
    assert_eq!(next.status, CibaStatus::Approved);

    for invalid in [
        CibaAuthenticationContext {
            auth_time: 0,
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
        },
        CibaAuthenticationContext {
            auth_time: 100,
            amr: Vec::new(),
            oidc_sid: None,
        },
        CibaAuthenticationContext {
            auth_time: 100,
            amr: vec![" ".to_owned()],
            oidc_sid: None,
        },
        CibaAuthenticationContext {
            auth_time: 100,
            amr: vec!["pwd".to_owned()],
            oidc_sid: Some(String::new()),
        },
    ] {
        let invalid_state = CibaRequestState {
            authentication_context: Some(invalid),
            ..state.clone()
        };
        let result = futures_executor::block_on(
            CibaService::new(CreateStore)
                .create_unique(&invalid_state, || "invalid-context-id".to_owned()),
        );
        assert_eq!(
            result,
            Err(CibaCreateFailure::Storage(
                nazo_auth::CibaStatePortError::CorruptData
            ))
        );
    }
}
