use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use chrono::TimeZone as _;

use super::*;

fn committed_execution(operation_key: &str) -> nazo_auth::LogoutExecution {
    nazo_auth::LogoutExecution {
        redirect_uri: None,
        frontchannel_logout_urls: Vec::new(),
        operation_key: Some(operation_key.to_owned()),
    }
}

#[test]
fn id_token_hint_expires_at_the_exact_exp_boundary() {
    let now = Utc.timestamp_opt(2_000_000_000, 0).unwrap();
    assert!(!id_token_hint_expired(2_000_000_001, now));
    assert!(id_token_hint_expired(2_000_000_000, now));
    assert!(id_token_hint_expired(1_999_999_999, now));
}

#[tokio::test]
async fn postgres_outbox_failure_never_deletes_the_valkey_session() {
    let delete_calls = Arc::new(AtomicUsize::new(0));
    let observed = delete_calls.clone();
    let result = finalize_logout_execution(
        Err(LogoutServiceError::OutboxUnavailable),
        Some("session-cookie".to_owned()),
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        },
    )
    .await;
    assert_eq!(result, Err(OidcLogoutError::OutboxUnavailable));
    assert_eq!(delete_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn valkey_failure_keeps_the_committed_operation_retryable() {
    let operation_key = "same-user-and-oidc-session";
    let first = finalize_logout_execution(
        Ok(committed_execution(operation_key)),
        Some("session-cookie".to_owned()),
        |_| async { Err(()) },
    )
    .await;
    assert_eq!(first, Err(OidcLogoutError::SessionDeleteUnavailable));

    let second = finalize_logout_execution(
        Ok(committed_execution(operation_key)),
        Some("session-cookie".to_owned()),
        |_| async { Ok(()) },
    )
    .await;
    assert_eq!(
        second,
        Ok(OidcLogoutSuccess {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
        })
    );
}
