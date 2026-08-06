use chrono::{Duration, Utc};
use diesel::{QueryableByName, sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_postgres::{
    AuditLedgerRepository, MAX_SECURITY_AUDIT_PAYLOAD_BYTES, SecurityAuditEvent, create_pool,
    run_pending_migrations,
};
use serde_json::json;
use uuid::Uuid;

static AUDIT_LEDGER_CLAIM_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const AUDIT_LEDGER_UP: &str =
    include_str!("../../../migrations/20260805000100_security_audit_ledger/up.sql");
const AUDIT_LEDGER_DOWN: &str =
    include_str!("../../../migrations/20260805000100_security_audit_ledger/down.sql");

#[test]
fn audit_ledger_migration_is_append_only_and_has_durable_outbox() {
    for required in [
        "security_audit_chain_state",
        "security_audit_events",
        "security_audit_event_outbox",
        "security_audit_events_append_only",
        "security_audit_events_no_truncate",
        "octet_length(event_hash) = 32",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
        "nazo_append_security_audit_event",
        "nazo_claim_security_audit_events",
        "nazo_ack_security_audit_event",
        "nazo_reschedule_security_audit_event",
        "nazo_security_audit_privilege_preflight",
        "nazo_security_audit_anchor_freshness",
        "nazo_security_audit_anchor_health",
        "REVOKE ALL ON TABLE",
        "FROM PUBLIC",
    ] {
        assert!(AUDIT_LEDGER_UP.contains(required), "missing {required}");
    }
    for required in [
        "DROP TRIGGER IF EXISTS security_audit_events_append_only",
        "DROP FUNCTION IF EXISTS public.nazo_append_security_audit_event",
        "DROP FUNCTION IF EXISTS public.nazo_claim_security_audit_events",
        "DROP FUNCTION IF EXISTS public.nazo_ack_security_audit_event",
        "DROP FUNCTION IF EXISTS public.nazo_reschedule_security_audit_event",
        "DROP FUNCTION IF EXISTS public.nazo_security_audit_privilege_preflight",
        "DROP FUNCTION IF EXISTS public.nazo_security_audit_anchor_health",
        "DROP TABLE IF EXISTS public.security_audit_event_outbox",
        "DROP TABLE IF EXISTS public.security_audit_events",
        "DROP TABLE IF EXISTS public.security_audit_chain_state",
    ] {
        assert!(AUDIT_LEDGER_DOWN.contains(required), "missing {required}");
    }
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI audit ledger tests require an isolated NAZO_AUDIT_TEST_DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct EventHashRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    event_hash: Vec<u8>,
}

#[tokio::test]
async fn audit_ledger_append_is_chained_and_outboxed() {
    let _claim_guard = AUDIT_LEDGER_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("audit ledger migration should apply");
    let pool = create_pool(database_url.clone(), 4).expect("audit pool should create");
    let repository = AuditLedgerRepository::new(pool);
    loop {
        let existing = repository
            .claim_due(256, 60)
            .await
            .expect("existing audit deliveries should be claimable");
        if existing.is_empty() {
            break;
        }
        for delivery in existing {
            repository
                .mark_exported(delivery.event_id, delivery.attempts)
                .await
                .expect("existing audit delivery should be drainable");
        }
    }
    let first_id = Uuid::now_v7();
    let second_id = Uuid::now_v7();
    let first = repository
        .append(SecurityAuditEvent {
            event_id: first_id,
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": "first"}),
            occurred_at: Utc::now(),
        })
        .await
        .expect("first audit event should append");
    let second = repository
        .append(SecurityAuditEvent {
            event_id: second_id,
            event_type: "token_revoked".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": "second"}),
            occurred_at: Utc::now(),
        })
        .await
        .expect("second audit event should append");
    assert_eq!(second.sequence, first.sequence + 1);

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("audit test database should connect");
    let previous = sql_query("SELECT event_hash FROM security_audit_events WHERE event_id = $1")
        .bind::<SqlUuid, _>(first_id)
        .get_result::<EventHashRow>(&mut connection)
        .await
        .expect("first audit hash should be readable");
    let second_previous = sql_query(
        "SELECT previous_hash AS event_hash FROM security_audit_events WHERE event_id = $1",
    )
    .bind::<SqlUuid, _>(second_id)
    .get_result::<EventHashRow>(&mut connection)
    .await
    .expect("second audit previous hash should be readable");
    assert_eq!(second_previous.event_hash, previous.event_hash);

    let claimed = repository
        .claim_due(10, 60)
        .await
        .expect("audit outbox should claim");
    let first_delivery = claimed
        .iter()
        .find(|delivery| delivery.event_id == first_id)
        .expect("first event should have an outbox row");
    assert_eq!(first_delivery.event_id, first_id);
    for delivery in claimed {
        repository
            .mark_exported(delivery.event_id, delivery.attempts)
            .await
            .expect("every claimed audit event should be marked as exported");
    }

    let health = repository
        .anchor_health()
        .await
        .expect("audit anchor health should be readable through its function");
    assert!(health.head_sequence >= second.sequence);
    assert_eq!(health.head_hash.len(), 32);

    let mutation =
        sql_query("UPDATE security_audit_events SET event_type = event_type WHERE event_id = $1")
            .bind::<SqlUuid, _>(first_id)
            .execute(&mut connection)
            .await;
    assert!(
        mutation.is_err(),
        "ledger mutation must be rejected by trigger"
    );
}

#[tokio::test]
async fn audit_ledger_rejects_invalid_events_and_enforces_claim_fencing() {
    let _claim_guard = AUDIT_LEDGER_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("audit ledger migration should apply");
    let pool = create_pool(database_url.clone(), 2).expect("audit pool should create");
    let repository = AuditLedgerRepository::new(pool);
    loop {
        let existing = repository
            .claim_due(256, 60)
            .await
            .expect("existing audit deliveries should be claimable");
        if existing.is_empty() {
            break;
        }
        for delivery in existing {
            repository
                .mark_exported(delivery.event_id, delivery.attempts)
                .await
                .expect("existing audit delivery should be drainable");
        }
    }

    for event in [
        SecurityAuditEvent {
            event_id: uuid::Uuid::nil(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({}),
            occurred_at: Utc::now(),
        },
        SecurityAuditEvent {
            event_id: uuid::Uuid::now_v7(),
            event_type: "Token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({}),
            occurred_at: Utc::now(),
        },
        SecurityAuditEvent {
            event_id: uuid::Uuid::now_v7(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!("not-an-object"),
            occurred_at: Utc::now(),
        },
    ] {
        assert!(matches!(
            repository.append(event).await,
            Err(RepositoryError::Unexpected(_))
        ));
    }
    assert!(matches!(
        repository
            .append(SecurityAuditEvent {
                event_id: uuid::Uuid::now_v7(),
                event_type: "a".repeat(65),
                event_category: "token_lifecycle".to_owned(),
                payload: json!({}),
                occurred_at: Utc::now(),
            })
            .await,
        Err(RepositoryError::Unexpected(_))
    ));
    assert!(matches!(
        repository
            .append(SecurityAuditEvent {
                event_id: uuid::Uuid::now_v7(),
                event_type: "token_issued".to_owned(),
                event_category: "token_lifecycle".to_owned(),
                payload: json!({"body": "x".repeat(MAX_SECURITY_AUDIT_PAYLOAD_BYTES)}),
                occurred_at: Utc::now(),
            })
            .await,
        Err(RepositoryError::Unexpected(_))
    ));
    for (limit, lock_timeout_seconds) in [(0, 60), (257, 60), (1, 0), (1, 3_601)] {
        assert!(matches!(
            repository.claim_due(limit, lock_timeout_seconds).await,
            Err(RepositoryError::Unexpected(_))
        ));
    }

    let event = SecurityAuditEvent {
        event_id: uuid::Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: json!({"subject_hash": "idempotent"}),
        occurred_at: Utc::now(),
    };
    let receipt = repository
        .append(event.clone())
        .await
        .expect("a valid audit event should append");
    let duplicate = repository
        .append(event.clone())
        .await
        .expect("repeating an identical audit event should be idempotent");
    assert_eq!(duplicate, receipt);
    let mut collision = event;
    collision.payload = json!({"subject_hash": "collision"});
    assert!(matches!(
        repository.append(collision).await,
        Err(RepositoryError::Unexpected(_))
    ));

    let first_delivery = repository
        .claim_due(10, 60)
        .await
        .expect("the appended audit event should be claimable")
        .into_iter()
        .find(|delivery| delivery.event_id == receipt.event_id)
        .expect("the appended audit event should have an outbox claim");
    assert!(matches!(
        repository
            .mark_exported(receipt.event_id, first_delivery.attempts + 1)
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    repository
        .reschedule(
            receipt.event_id,
            first_delivery.attempts,
            Utc::now() - Duration::seconds(1),
            "temporary exporter failure",
        )
        .await
        .expect("a current claim should be reschedulable");
    let second_delivery = repository
        .claim_due(10, 60)
        .await
        .expect("a rescheduled event should be claimable again")
        .into_iter()
        .find(|delivery| delivery.event_id == receipt.event_id)
        .expect("the rescheduled event should be reclaimed");
    assert_eq!(second_delivery.attempts, first_delivery.attempts + 1);
    repository
        .mark_exported(receipt.event_id, second_delivery.attempts)
        .await
        .expect("the current claim should be acknowledged");
    assert!(matches!(
        repository
            .mark_exported(receipt.event_id, second_delivery.attempts)
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .reschedule(
                receipt.event_id,
                second_delivery.attempts,
                Utc::now(),
                "late exporter failure",
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    let freshness = repository
        .anchor_freshness()
        .await
        .expect("the immutable chain head should remain fresh");
    assert_eq!(freshness.head_hash.len(), 32);
    repository
        .check_available_with_policy(false)
        .await
        .expect("writer preflight should accept the isolated test database");
    repository
        .check_exporter_available_with_policy(false)
        .await
        .expect("exporter preflight should accept the isolated test database");
}
