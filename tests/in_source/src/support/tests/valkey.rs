use super::*;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::time::Duration as StdDuration;

async fn live_valkey() -> Option<ValkeyClient> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_secs(1);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_secs(1);
        connection.internal_command_timeout = StdDuration::from_secs(1);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("Valkey client should build");
    valkey.init().await.expect("Valkey should connect");
    Some(valkey)
}

async fn valkey_server_time(valkey: &ValkeyClient) -> i64 {
    valkey_eval_string(
        valkey,
        "return tostring(redis.call('TIME')[1])",
        Vec::new(),
        Vec::new(),
    )
    .await
    .expect("Valkey TIME should be readable")
    .parse()
    .expect("Valkey TIME should be an integer")
}

#[test]
fn valkey_atomic_result_parser_accepts_only_declared_states() {
    assert_eq!(
        parse_valkey_atomic_result("applied").unwrap(),
        ValkeyAtomicResult::Applied
    );
    assert_eq!(
        parse_valkey_atomic_result("conflict").unwrap(),
        ValkeyAtomicResult::Conflict
    );
    assert_eq!(
        parse_valkey_atomic_result("deadline_elapsed").unwrap(),
        ValkeyAtomicResult::DeadlineElapsed
    );
    assert!(parse_valkey_atomic_result("ok").is_err());
}

#[actix_web::test]
async fn valkey_atomic_primitives_compare_exact_raw_value_and_preserve_deadline() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let key = format!("test:valkey:atomic:{}", Uuid::now_v7());
    let now = valkey_server_time(&valkey).await;
    let deadline = now + 30;

    assert_eq!(
        valkey_set_nx_at_deadline(&valkey, &key, "v1", deadline)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    assert_eq!(
        valkey_set_nx_at_deadline(&valkey, &key, "other", deadline)
            .await
            .unwrap(),
        ValkeyAtomicResult::Conflict
    );
    let first = valkey_atomic_snapshot(&valkey, &key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.raw, "v1");
    assert_eq!(first.expire_at, deadline);

    assert_eq!(
        valkey_compare_set_at_deadline(&valkey, &key, "wrong", "v2", deadline)
            .await
            .unwrap(),
        ValkeyAtomicResult::Conflict
    );
    assert_eq!(
        valkey_compare_set_at_deadline(&valkey, &key, "v1", "v2", deadline)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    assert_eq!(
        valkey_atomic_snapshot(&valkey, &key)
            .await
            .unwrap()
            .unwrap()
            .expire_at,
        deadline
    );
    assert_eq!(
        valkey_compare_delete_at_deadline(&valkey, &key, "wrong", deadline)
            .await
            .unwrap(),
        ValkeyAtomicResult::Conflict
    );
    assert_eq!(
        valkey_compare_delete_at_deadline(&valkey, &key, "v2", deadline)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    assert!(
        valkey_atomic_snapshot(&valkey, &key)
            .await
            .unwrap()
            .is_none()
    );
}

#[actix_web::test]
async fn valkey_atomic_primitives_report_deadline_elapsed_instead_of_applied() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let key = format!("test:valkey:deadline:{}", Uuid::now_v7());
    let now = valkey_server_time(&valkey).await;

    assert_eq!(
        valkey_set_nx_at_deadline(&valkey, &key, "new", now)
            .await
            .unwrap(),
        ValkeyAtomicResult::DeadlineElapsed
    );

    valkey_set_ex(&valkey, &key, "existing", 30).await.unwrap();
    assert_eq!(
        valkey_compare_set_at_deadline(&valkey, &key, "existing", "replacement", now)
            .await
            .unwrap(),
        ValkeyAtomicResult::DeadlineElapsed
    );
    assert!(
        valkey_atomic_snapshot(&valkey, &key)
            .await
            .unwrap()
            .is_none()
    );
}
