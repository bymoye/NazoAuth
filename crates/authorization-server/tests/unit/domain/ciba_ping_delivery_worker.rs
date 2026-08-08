use super::*;

fn disconnected_store() -> CibaStore {
    let client = fred::prelude::Builder::default_centralized()
        .build()
        .expect("disconnected Valkey client should build");
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(client);
    CibaStore::new(&connection)
}

#[test]
fn ciba_ping_worker_entrypoints_remain_reachable_in_test_builds() {
    let _process_due_batch = CibaPingDeliveryWorker::process_due_batch;
    let _spawn_worker: fn(CibaPingDeliveryWorker) = spawn_ciba_ping_delivery_worker;
}

#[test]
fn ciba_ping_worker_accepts_only_https_origin_allowlist_entries() {
    assert!(CibaPingDeliveryWorker::new(disconnected_store(), &[]).is_ok());
    assert!(
        CibaPingDeliveryWorker::new(disconnected_store(), &["https://notify.example".to_owned()],)
            .is_ok()
    );

    for invalid in [
        "http://notify.example",
        "https://notify.example/path",
        "https://notify.example?query=1",
    ] {
        assert!(
            CibaPingDeliveryWorker::new(disconnected_store(), &[invalid.to_owned()]).is_err(),
            "{invalid} must not be accepted as a private-network origin"
        );
    }
}

#[test]
fn ciba_ping_log_origin_and_idempotency_key_are_stable_and_safe() {
    assert_eq!(
        endpoint_origin_for_log("https://notify.example/ciba?request=1"),
        "https://notify.example"
    );
    assert_eq!(endpoint_origin_for_log("not-a-url"), "<invalid>");
    assert_eq!(
        ciba_ping_idempotency_key("auth-request-hash"),
        "nazo-ciba-ping-auth-request-hash"
    );
}
