use super::{
    config::{AuditAnchorMode, AuditAnchorPreflightConfig, AuditAnchorWorkerConfig},
    preflight::{AuditAnchorPreflight, validate_health},
    protocol::{
        AnchorCheckpointEnvelope, CHECKPOINT_SCHEMA_VERSION, checkpoint_body, encode_hash,
        genesis_body, sign_body,
    },
    status::{AnchorCheckpoint, age_seconds, duration_seconds},
    transport::{AnchorPushError, send_checkpoint, send_genesis_checkpoint},
    worker::{
        AuditAnchorRepository, IterationOutcome, delivery_lag_seconds, retry_delay, run_iteration,
    },
};
use chrono::{Duration as ChronoDuration, Utc};
use nazo_identity::ports::{RepositoryError, RepositoryFuture};
use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditOutboxDelivery};
use nazo_postgres::AuditLedgerRepository;
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;
use uuid::Uuid;

fn valid_worker_config(endpoint: Url) -> AuditAnchorWorkerConfig {
    AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint,
        auth_secret: b"anchor-secret-that-is-long-enough".to_vec(),
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        lock_timeout_seconds: 1,
    }
}

fn health_snapshot() -> SecurityAuditAnchorHealth {
    SecurityAuditAnchorHealth {
        head_sequence: 7,
        head_hash: vec![2; 32],
        pending_count: 0,
        oldest_pending_occurred_at: None,
        last_exported_sequence: Some(7),
        last_exported_hash: Some(vec![2; 32]),
        last_exported_occurred_at: Some(Utc::now() - ChronoDuration::seconds(2)),
        last_exported_at: Some(Utc::now() - ChronoDuration::seconds(1)),
        deployment_id: Some("deployment-1".to_owned()),
        observed_at: Some(Utc::now()),
    }
}

fn delivery() -> SecurityAuditOutboxDelivery {
    SecurityAuditOutboxDelivery {
        event_id: Uuid::nil(),
        sequence: 7,
        event_type: "admin_user_updated".to_owned(),
        event_category: "administration".to_owned(),
        payload: json!({"user_id": "user-1"}),
        occurred_at: Utc::now() - ChronoDuration::seconds(4),
        previous_hash: vec![1; 32],
        event_hash: vec![2; 32],
        attempts: 1,
    }
}

#[derive(Default)]
struct ScriptedRepository {
    health: Mutex<VecDeque<Result<SecurityAuditAnchorHealth, RepositoryError>>>,
    claims: Mutex<VecDeque<Result<Vec<SecurityAuditOutboxDelivery>, RepositoryError>>>,
    acknowledgements: Mutex<VecDeque<Result<(), RepositoryError>>>,
    reschedules: Mutex<Vec<(Uuid, i32, String)>>,
    marked: Mutex<Vec<(Uuid, i32)>>,
    reschedule_failure: bool,
}

impl ScriptedRepository {
    fn with_health(
        health: Result<SecurityAuditAnchorHealth, RepositoryError>,
        claims: Result<Vec<SecurityAuditOutboxDelivery>, RepositoryError>,
    ) -> Self {
        Self {
            health: Mutex::new(VecDeque::from([health])),
            claims: Mutex::new(VecDeque::from([claims])),
            ..Self::default()
        }
    }

    fn with_acknowledgement(self, acknowledgement: Result<(), RepositoryError>) -> Self {
        {
            let mut acknowledgements = self
                .acknowledgements
                .lock()
                .expect("scripted repository mutex is not poisoned");
            acknowledgements.push_back(acknowledgement);
        }
        self
    }

    fn with_reschedule_failure(mut self) -> Self {
        self.reschedule_failure = true;
        self
    }

    fn reschedules(&self) -> Vec<(Uuid, i32, String)> {
        self.reschedules
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .clone()
    }

    fn marked(&self) -> Vec<(Uuid, i32)> {
        self.marked
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .clone()
    }
}

impl AuditAnchorRepository for ScriptedRepository {
    fn check_available(&self) -> RepositoryFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn anchor_health(&self) -> RepositoryFuture<'_, SecurityAuditAnchorHealth> {
        Box::pin(async move {
            self.health
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RepositoryError::Unexpected(
                        "health script exhausted".to_owned(),
                    ))
                })
        })
    }

    fn observe_anchor<'a>(&'a self, _deployment_id: &'a str) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn record_genesis<'a>(
        &'a self,
        _deployment_id: &'a str,
        _head_hash: &'a [u8],
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn claim_due(
        &self,
        _limit: i64,
        _lock_timeout_seconds: i32,
    ) -> RepositoryFuture<'_, Vec<SecurityAuditOutboxDelivery>> {
        Box::pin(async move {
            self.claims
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RepositoryError::Unexpected(
                        "claim script exhausted".to_owned(),
                    ))
                })
        })
    }

    fn mark_exported<'a>(
        &'a self,
        event_id: Uuid,
        expected_attempts: i32,
        _deployment_id: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let result = self
                .acknowledgements
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or(Ok(()));
            if result.is_ok() {
                self.marked
                    .lock()
                    .expect("scripted repository mutex is not poisoned")
                    .push((event_id, expected_attempts));
            }
            result
        })
    }

    fn reschedule(
        &self,
        event_id: Uuid,
        expected_attempts: i32,
        _available_at: chrono::DateTime<Utc>,
        last_error: &str,
    ) -> RepositoryFuture<'_, ()> {
        let last_error = last_error.to_owned();
        Box::pin(async move {
            self.reschedules
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .push((event_id, expected_attempts, last_error));
            if self.reschedule_failure {
                Err(RepositoryError::Unexpected("reschedule failed".to_owned()))
            } else {
                Ok(())
            }
        })
    }
}

fn iteration_config(endpoint: Url) -> AuditAnchorWorkerConfig {
    let mut config = valid_worker_config(endpoint);
    config.poll_interval = Duration::from_millis(1);
    config
}

fn genesis_snapshot() -> SecurityAuditAnchorHealth {
    let mut snapshot = health_snapshot();
    snapshot.head_sequence = 0;
    snapshot.head_hash = vec![9; 32];
    snapshot.last_exported_sequence = None;
    snapshot.last_exported_hash = None;
    snapshot.last_exported_occurred_at = None;
    snapshot.last_exported_at = None;
    snapshot
}

fn repository_error(message: &str) -> RepositoryError {
    RepositoryError::Unexpected(message.to_owned())
}

#[tokio::test]
async fn worker_iteration_anchors_genesis_before_polling_empty_outbox() {
    let (endpoint, server) = local_anchor_endpoint(202).await;
    let config = iteration_config(endpoint);
    let repository = ScriptedRepository::with_health(Ok(genesis_snapshot()), Ok(Vec::new()));
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Poll(config.poll_interval));
    let checkpoint = last_anchored.expect("genesis checkpoint is retained");
    assert_eq!(checkpoint.sequence, 0);
    assert_eq!(checkpoint.hash, encode_hash(&[9; 32]));
    let request = server.await.expect("genesis endpoint completes");
    let header_end = request
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .expect("request has headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body: Value = serde_json::from_slice(&request[header_end + 4..]).unwrap();
    assert_eq!(
        header_value(&headers, "idempotency-key"),
        Some("genesis:deployment-1")
    );
    assert_eq!(body["checkpoint_kind"], "genesis");
    assert_eq!(body["sequence"], 0);
}

#[tokio::test]
async fn worker_iteration_retries_failed_genesis_without_claiming_deliveries() {
    let (endpoint, server) = local_anchor_endpoint(503).await;
    let config = iteration_config(endpoint);
    let repository = ScriptedRepository::with_health(Ok(genesis_snapshot()), Ok(Vec::new()));
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &test_client(), &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert!(last_anchored.is_none());
    assert_eq!(
        repository
            .claims
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .len(),
        1,
        "failed genesis must not claim durable deliveries"
    );
    server.await.expect("failed genesis endpoint completes");
}

#[tokio::test]
async fn worker_iteration_reuses_current_genesis_and_tolerates_health_publish_failure() {
    let config =
        iteration_config(Url::parse("https://unused-anchor.example.test/checkpoint").unwrap());
    let snapshot = genesis_snapshot();
    let expected = AnchorCheckpoint::genesis(encode_hash(&snapshot.head_hash));
    let repository = ScriptedRepository::with_health(Ok(snapshot), Ok(Vec::new()));
    let mut last_anchored = Some(expected.clone());

    let outcome = run_iteration(&repository, &test_client(), &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Poll(config.poll_interval));
    assert_eq!(last_anchored, Some(expected));
}

#[tokio::test]
async fn worker_iteration_pushes_checkpoint_and_acknowledges_it() {
    let (endpoint, server) = local_anchor_endpoint(202).await;
    let config = iteration_config(endpoint);
    let delivery = delivery();
    let repository =
        ScriptedRepository::with_health(Ok(health_snapshot()), Ok(vec![delivery.clone()]))
            .with_acknowledgement(Ok(()));
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Continue);
    assert_eq!(
        repository.marked(),
        vec![(delivery.event_id, delivery.attempts)]
    );
    assert!(repository.reschedules().is_empty());
    let checkpoint = last_anchored.expect("acknowledged checkpoint is retained");
    assert_eq!(checkpoint.sequence, delivery.sequence);
    server.await.expect("checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_anchors_each_delivery_in_order() {
    let (endpoint, server) = local_anchor_replay_endpoint(202).await;
    let mut config = iteration_config(endpoint);
    config.batch_size = 2;
    let mut first = delivery();
    first.event_id = Uuid::from_u128(1);
    let mut second = delivery();
    second.event_id = Uuid::from_u128(2);
    second.sequence = 8;
    second.event_hash = vec![3; 32];
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(vec![first.clone(), second.clone()]),
    )
    .with_acknowledgement(Ok(()))
    .with_acknowledgement(Ok(()));
    let mut last_anchored = None;

    assert_eq!(
        run_iteration(&repository, &test_client(), &config, &mut last_anchored).await,
        IterationOutcome::Continue
    );
    assert_eq!(
        repository.marked(),
        vec![
            (first.event_id, first.attempts),
            (second.event_id, second.attempts)
        ]
    );
    assert_eq!(last_anchored.unwrap().sequence, second.sequence);
    assert_eq!(
        server.await.expect("checkpoint endpoints complete").len(),
        2
    );
}

#[tokio::test]
async fn worker_iteration_reschedules_http_failures() {
    let (endpoint, server) = local_anchor_endpoint(503).await;
    let config = iteration_config(endpoint);
    let delivery = delivery();
    let repository =
        ScriptedRepository::with_health(Ok(health_snapshot()), Ok(vec![delivery.clone()]));
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Continue);
    assert!(repository.marked().is_empty());
    assert_eq!(
        repository.reschedules(),
        vec![(delivery.event_id, delivery.attempts, "http_5xx".to_owned())]
    );
    server.await.expect("failed checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_keeps_retrying_when_reschedule_persistence_fails() {
    let (endpoint, server) = local_anchor_endpoint(503).await;
    let config = iteration_config(endpoint);
    let delivery = delivery();
    let repository =
        ScriptedRepository::with_health(Ok(health_snapshot()), Ok(vec![delivery.clone()]))
            .with_reschedule_failure();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &test_client(), &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Continue);
    assert_eq!(
        repository.reschedules(),
        vec![(delivery.event_id, delivery.attempts, "http_5xx".to_owned())]
    );
    server.await.expect("failed checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_reschedules_ack_failure_and_remaining_claims() {
    let (endpoint, server) = local_anchor_endpoint(202).await;
    let config = iteration_config(endpoint);
    let mut first = delivery();
    first.event_id = Uuid::from_u128(1);
    let mut second = delivery();
    second.event_id = Uuid::from_u128(2);
    second.sequence = 8;
    second.event_hash = vec![3; 32];
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(vec![first.clone(), second.clone()]),
    )
    .with_acknowledgement(Err(repository_error("ack failed")));
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored).await;

    assert_eq!(outcome, IterationOutcome::Continue);
    assert!(repository.marked().is_empty());
    assert_eq!(
        repository.reschedules(),
        vec![
            (
                first.event_id,
                first.attempts,
                "ack_database_error".to_owned()
            ),
            (
                second.event_id,
                second.attempts,
                "ack_database_error".to_owned()
            ),
        ]
    );
    server.await.expect("checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_retries_health_and_claim_failures() {
    let config = iteration_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    let client = test_client();
    let mut last_anchored = None;
    let health_failure =
        ScriptedRepository::with_health(Err(repository_error("health failed")), Ok(Vec::new()));
    assert_eq!(
        run_iteration(&health_failure, &client, &config, &mut last_anchored,).await,
        IterationOutcome::Retry(Duration::from_secs(1))
    );

    let claim_failure = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Err(repository_error("claim failed")),
    );
    assert_eq!(
        run_iteration(&claim_failure, &client, &config, &mut last_anchored,).await,
        IterationOutcome::Retry(Duration::from_secs(1))
    );
}

#[tokio::test]
async fn worker_outer_rejects_invalid_config_before_repository_preflight() {
    let pool = nazo_postgres::create_pool("not a postgres url", 1).unwrap();
    let repository = AuditLedgerRepository::new(pool);
    let config = AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint: Url::parse("http://anchor.example.test/checkpoint").unwrap(),
        auth_secret: vec![0; 15],
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        lock_timeout_seconds: 1,
    };

    let error = super::worker::run_worker(repository, config)
        .await
        .expect_err("invalid worker configuration must fail before preflight");
    assert!(error.to_string().contains("HTTPS"));
}

#[tokio::test]
async fn worker_outer_rejects_repository_preflight_failure() {
    let pool = nazo_postgres::create_pool("not a postgres url", 1).unwrap();
    let repository = AuditLedgerRepository::new(pool);
    let config = iteration_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());

    let error = super::worker::run_worker(repository, config)
        .await
        .expect_err("repository preflight failure must stop the worker");
    assert_eq!(
        error.to_string(),
        "audit anchor exporter capability preflight failed"
    );
}

#[test]
fn checkpoint_signature_is_deterministic_and_url_safe() {
    let body = br#"{"sequence":7,"event_hash":"abc"}"#;
    let first = sign_body(b"anchor-secret-that-is-long-enough", body);
    let second = sign_body(b"anchor-secret-that-is-long-enough", body);

    assert_eq!(first, second);
    assert!(!first.is_empty());
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

#[test]
fn retry_backoff_is_bounded() {
    assert_eq!(retry_delay(1), Duration::from_secs(1));
    assert_eq!(retry_delay(2), Duration::from_secs(2));
    assert_eq!(retry_delay(9), Duration::from_secs(256));
    assert_eq!(retry_delay(i32::MAX), Duration::from_secs(300));
}

#[test]
fn mode_parser_and_preflight_configuration_reject_invalid_values() {
    assert_eq!(
        AuditAnchorMode::parse("disabled").unwrap(),
        AuditAnchorMode::Disabled
    );
    assert_eq!(
        AuditAnchorMode::parse("optional").unwrap(),
        AuditAnchorMode::Optional
    );
    assert_eq!(
        AuditAnchorMode::parse("required").unwrap(),
        AuditAnchorMode::Required
    );
    assert!(AuditAnchorMode::parse("unexpected").is_err());

    let invalid_identity = AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment/with-slash".to_owned(),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    };
    assert!(invalid_identity.validate().is_err());
}

#[test]
fn worker_configuration_rejects_non_https_and_weak_secret() {
    let config = AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint: Url::parse("http://anchor.example.test").unwrap(),
        auth_secret: vec![0; 15],
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        lock_timeout_seconds: 1,
    };
    assert!(config.validate().is_err());
}

#[test]
fn mode_helpers_and_deployment_id_boundaries_are_explicit() {
    assert!(!AuditAnchorMode::Disabled.is_enabled());
    assert!(AuditAnchorMode::Optional.is_enabled());
    assert!(AuditAnchorMode::Required.is_enabled());
    assert!(!AuditAnchorMode::Disabled.is_required());
    assert!(!AuditAnchorMode::Optional.is_required());
    assert!(AuditAnchorMode::Required.is_required());

    for value in ["a", "deployment-1", "a.b_c-9"] {
        super::config::validate_deployment_id(value).unwrap();
    }
    let valid_max = "a".repeat(255);
    super::config::validate_deployment_id(&valid_max).unwrap();
    for value in [
        "",
        "deployment/with-slash",
        "deployment with spaces",
        "部署-1",
    ] {
        assert!(
            super::config::validate_deployment_id(value).is_err(),
            "{value:?}"
        );
    }
    let invalid_max = "a".repeat(256);
    assert!(super::config::validate_deployment_id(&invalid_max).is_err());
}

#[test]
fn preflight_source_uses_safe_defaults_and_requires_identity_when_enabled() {
    let disabled = crate::config::ConfigSource::default();
    let disabled_config = super::config::preflight_config_from_source(&disabled)
        .expect("disabled mode has a safe default identity");
    assert_eq!(disabled_config.mode, AuditAnchorMode::Disabled);
    assert_eq!(disabled_config.deployment_id, "audit-anchor-disabled");

    let source = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "optional"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_FRESHNESS_SECONDS", "9"),
        ("AUDIT_ANCHOR_MAX_LAG_SECONDS", "11"),
    ]);
    let config = super::config::preflight_config_from_source(&source)
        .expect("explicit preflight values should parse");
    assert_eq!(config.mode, AuditAnchorMode::Optional);
    assert_eq!(config.deployment_id, "deployment-test");
    assert_eq!(config.freshness, Duration::from_secs(9));
    assert_eq!(config.max_lag, Duration::from_secs(11));

    let missing_identity =
        crate::config::ConfigSource::from_pairs_for_test([("AUDIT_ANCHOR_MODE", "required")]);
    assert!(super::config::preflight_config_from_source(&missing_identity).is_err());
    let invalid_freshness = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_FRESHNESS_SECONDS", "0"),
    ]);
    assert!(super::config::preflight_config_from_source(&invalid_freshness).is_err());
}

#[test]
fn worker_source_loads_sidecar_only_values_and_rejects_invalid_inputs() {
    let source = crate::config::ConfigSource::from_pairs_for_test([
        ("DATA_DIR", "runtime"),
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_POLL_INTERVAL_SECONDS", "2"),
        ("AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS", "3"),
        ("AUDIT_ANCHOR_BATCH_SIZE", "5"),
        ("AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS", "7"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
        ("AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS", "8"),
    ]);
    let (database_url, max_connections, config) =
        super::config::worker_config_from_source(&source).expect("worker source should parse");
    assert_eq!(database_url, "postgres://exporter@db/audit");
    assert_eq!(max_connections, 8);
    assert_eq!(config.batch_size, 5);
    assert_eq!(config.lock_timeout_seconds, 7);

    let invalid_url = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "not a url"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
    ]);
    assert!(super::config::worker_config_from_source(&invalid_url).is_err());

    let no_database = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
    ]);
    assert!(super::config::worker_config_from_source(&no_database).is_err());

    let zero_connections = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
        ("AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS", "0"),
    ]);
    assert!(super::config::worker_config_from_source(&zero_connections).is_err());
}

#[test]
fn worker_configuration_validates_each_boundary_without_combining_errors() {
    let mut config =
        valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());

    config.preflight.mode = AuditAnchorMode::Disabled;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());

    config.endpoint = Url::parse("https://user:pass@anchor.example.test/checkpoint").unwrap();
    assert!(config.validate().is_err());
    config.endpoint = Url::parse("https://anchor.example.test/checkpoint?tenant=1").unwrap();
    assert!(config.validate().is_err());
    config.endpoint = Url::parse("https://anchor.example.test/checkpoint#fragment").unwrap();
    assert!(config.validate().is_err());
    config.endpoint = Url::parse("http://anchor.example.test/checkpoint").unwrap();
    assert!(config.validate().is_err());

    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.auth_secret.clear();
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.poll_interval = Duration::ZERO;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.request_timeout = Duration::ZERO;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.batch_size = 0;
    assert!(config.validate().is_err());
    config.batch_size = 257;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.lock_timeout_seconds = 0;
    assert!(config.validate().is_err());
    config.lock_timeout_seconds = 3_601;
    assert!(config.validate().is_err());
    assert!(
        valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap())
            .validate()
            .is_ok()
    );
}

#[test]
fn checkpoint_body_is_stable_across_retries_and_contains_recomputable_event() {
    let delivery = SecurityAuditOutboxDelivery {
        event_id: Uuid::nil(),
        sequence: 7,
        event_type: "admin_user_updated".to_owned(),
        event_category: "administration".to_owned(),
        payload: json!({"user_id": "user-1"}),
        occurred_at: Utc::now(),
        previous_hash: vec![1; 32],
        event_hash: vec![2; 32],
        attempts: 1,
    };
    let first = checkpoint_body("deployment-1", &delivery).unwrap();
    let second = checkpoint_body("deployment-1", &delivery).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        sign_body(b"anchor-secret-that-is-long-enough", &first),
        sign_body(b"anchor-secret-that-is-long-enough", &second)
    );

    let Value::Object(fields) = serde_json::from_slice(&first).unwrap() else {
        panic!("checkpoint must be a JSON object");
    };
    assert_eq!(fields["event_type"], "admin_user_updated");
    assert_eq!(fields["event_category"], "administration");
    assert_eq!(fields["payload"]["user_id"], "user-1");
    assert!(!fields.contains_key("anchored_at"));
}

#[test]
fn genesis_body_is_stable_and_has_explicit_kind() {
    let first = genesis_body("deployment-1", &[0; 32]).unwrap();
    let second = genesis_body("deployment-1", &[0; 32]).unwrap();
    assert_eq!(first, second);
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["checkpoint_kind"], "genesis");
    assert_eq!(value["sequence"], 0);
}

#[test]
fn checkpoint_envelope_contains_identity_chain_and_event_content() {
    let envelope = AnchorCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        event_id: Uuid::nil(),
        deployment_id: "deployment-1",
        sequence: 7,
        previous_hash: encode_hash(&[1; 32]),
        event_hash: encode_hash(&[2; 32]),
        event_type: "admin_user_updated",
        event_category: "administration",
        payload: json!({"user_id": "user-1"}),
        occurred_at: Utc::now(),
    };
    let Value::Object(fields) =
        serde_json::to_value(envelope).expect("checkpoint should serialize")
    else {
        panic!("checkpoint must be a JSON object");
    };
    assert_eq!(fields["deployment_id"], "deployment-1");
    assert_eq!(fields["sequence"], 7);
    assert!(fields.contains_key("previous_hash"));
    assert!(fields.contains_key("event_hash"));
    assert!(fields.contains_key("occurred_at"));
    assert!(fields.contains_key("event_type"));
    assert!(fields.contains_key("event_category"));
    assert!(fields.contains_key("payload"));
}

#[test]
fn preflight_accepts_shared_health_and_rejects_stale_or_unanchored_state() {
    let now = Utc::now();
    let config = required_config();
    let current = health_snapshot();
    assert!(validate_health(&config, &current, now).is_ok());

    let mut stale = current.clone();
    stale.observed_at = Some(now - ChronoDuration::seconds(121));
    assert!(validate_health(&config, &stale, now).is_err());

    let mut wrong_deployment = current.clone();
    wrong_deployment.deployment_id = Some("other".to_owned());
    assert!(validate_health(&config, &wrong_deployment, now).is_err());

    let mut pending = current.clone();
    pending.pending_count = 1;
    assert!(validate_health(&config, &pending, now).is_err());

    let mut behind = current;
    behind.last_exported_sequence = Some(6);
    assert!(validate_health(&config, &behind, now).is_err());
}

#[test]
fn preflight_mode_controls_the_shared_database_gate() {
    let current = health_snapshot();
    let required = AuditAnchorPreflight::new(required_config()).unwrap();
    assert!(required.ensure_fresh(&current).is_ok());
    let mut disabled = required_config();
    disabled.mode = AuditAnchorMode::Disabled;
    let mut unavailable = current;
    unavailable.deployment_id = None;
    assert!(
        AuditAnchorPreflight::new(disabled)
            .unwrap()
            .ensure_fresh(&unavailable)
            .is_ok()
    );
}

#[test]
fn health_time_helpers_reject_future_timestamps_and_bound_durations() {
    let now = Utc::now();
    assert_eq!(
        age_seconds(now, now - ChronoDuration::seconds(4)).unwrap(),
        4
    );
    assert!(age_seconds(now, now + ChronoDuration::seconds(1)).is_err());
    assert_eq!(duration_seconds(Duration::from_secs(17)), 17);
    assert_eq!(duration_seconds(Duration::from_secs(u64::MAX)), i64::MAX);
}

async fn local_anchor_endpoint(status: u16) -> (Url, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request arrives");
        let request = read_anchor_request(&mut stream).await;
        stream
            .write_all(
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("response is writable");
        request
    });
    (
        Url::parse(&format!("http://{address}/checkpoint")).unwrap(),
        task,
    )
}

async fn local_anchor_replay_endpoint(status: u16) -> (Url, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("request arrives");
            let request = read_anchor_request(&mut stream).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("response is writable");
            requests.push(request);
        }
        requests
    });
    (
        Url::parse(&format!("http://{address}/checkpoint")).unwrap(),
        task,
    )
}

async fn local_disconnect_endpoint() -> (Url, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request arrives");
        stream
            .shutdown()
            .await
            .expect("connection can close without an HTTP response");
    });
    (
        Url::parse(&format!("http://{address}/checkpoint")).unwrap(),
        task,
    )
}

async fn read_anchor_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    loop {
        let mut chunk = [0_u8; 256];
        let size = stream.read(&mut chunk).await.expect("request is readable");
        if size == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..size]);
        let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim().to_owned())
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        if request.len() >= header_end + 4 + content_length {
            break;
        }
    }
    request
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("test HTTP client builds")
}

#[test]
fn anchor_push_error_codes_cover_transport_serialization_and_http_classes() {
    assert_eq!(AnchorPushError::Transport.code(), "transport_error");
    assert_eq!(AnchorPushError::Serialize.code(), "serialization_error");
    assert_eq!(AnchorPushError::Http(429).code(), "http_429");
    assert_eq!(AnchorPushError::Http(400).code(), "http_4xx");
    assert_eq!(AnchorPushError::Http(499).code(), "http_4xx");
    assert_eq!(AnchorPushError::Http(500).code(), "http_5xx");
    assert_eq!(AnchorPushError::Http(599).code(), "http_5xx");
    assert_eq!(AnchorPushError::Http(300).code(), "http_other");
}

#[tokio::test]
async fn checkpoint_transport_sends_stable_body_signature_and_protocol_headers() {
    let (endpoint, server) = local_anchor_endpoint(202).await;
    let config = valid_worker_config(endpoint);
    let delivery = delivery();
    let expected_body = checkpoint_body(&config.preflight.deployment_id, &delivery).unwrap();
    let result = send_checkpoint(&test_client(), &config, &delivery).await;
    assert!(result.is_ok());
    let request = server.await.expect("local endpoint completes");
    let header_end = request
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .expect("request has headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body = &request[header_end + 4..];
    let expected_signature = format!("sha256={}", sign_body(&config.auth_secret, &expected_body));
    let expected_idempotency_key = delivery.event_id.to_string();
    assert!(headers.starts_with("POST /checkpoint HTTP/1.1"));
    assert_eq!(
        header_value(&headers, "content-type"),
        Some("application/json")
    );
    assert_eq!(
        header_value(&headers, "idempotency-key"),
        Some(expected_idempotency_key.as_str())
    );
    assert_eq!(
        header_value(&headers, "x-nazo-audit-schema"),
        Some(CHECKPOINT_SCHEMA_VERSION)
    );
    assert_eq!(
        header_value(&headers, "x-nazo-audit-deployment"),
        Some("deployment-1")
    );
    assert_eq!(
        header_value(&headers, "x-nazo-audit-signature"),
        Some(expected_signature.as_str())
    );
    assert!(header_value(&headers, "x-nazo-audit-sent-at").is_some());
    assert_eq!(body, expected_body.as_slice());
}

#[tokio::test]
async fn checkpoint_transport_classifies_http_statuses_and_disconnects() {
    let client = test_client();
    for (status, expected_code) in [
        (429, "http_429"),
        (400, "http_4xx"),
        (499, "http_4xx"),
        (500, "http_5xx"),
        (599, "http_5xx"),
        (300, "http_other"),
    ] {
        let (endpoint, server) = local_anchor_endpoint(status).await;
        let result = send_checkpoint(&client, &valid_worker_config(endpoint), &delivery())
            .await
            .expect_err("non-success response is an error");
        assert_eq!(result.code(), expected_code, "status {status}");
        server.await.expect("local endpoint completes");
    }

    let (endpoint, server) = local_disconnect_endpoint().await;
    let result = send_checkpoint(&client, &valid_worker_config(endpoint), &delivery())
        .await
        .expect_err("closed endpoint is a transport error");
    assert_eq!(result.code(), "transport_error");
    server.await.expect("disconnect endpoint completes");
}

#[tokio::test]
async fn repeated_genesis_calls_emit_stable_body_signature_and_idempotency_key() {
    let (endpoint, server) = local_anchor_replay_endpoint(200).await;
    let config = valid_worker_config(endpoint);
    let client = test_client();
    let first = send_genesis_checkpoint(&client, &config, &[9; 32])
        .await
        .expect("genesis request succeeds");
    let second = send_genesis_checkpoint(&client, &config, &[9; 32])
        .await
        .expect("replayed genesis request succeeds");
    assert_eq!(first.sequence, 0);
    assert_eq!(first.hash, encode_hash(&[9; 32]));
    assert_eq!(second.sequence, 0);
    assert_eq!(second.hash, encode_hash(&[9; 32]));
    let requests = server.await.expect("genesis endpoint completes twice");
    assert_eq!(requests.len(), 2);
    let expected_body = genesis_body("deployment-1", &[9; 32]).unwrap();
    let expected_signature = format!("sha256={}", sign_body(&config.auth_secret, &expected_body));
    for request in requests {
        let header_end = request
            .windows(4)
            .position(|value| value == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let body = &request[header_end + 4..];
        assert_eq!(
            header_value(&headers, "idempotency-key"),
            Some("genesis:deployment-1")
        );
        assert_eq!(
            header_value(&headers, "x-nazo-audit-signature"),
            Some(expected_signature.as_str())
        );
        assert_eq!(body, expected_body.as_slice());
    }

    let (endpoint, server) = local_anchor_endpoint(503).await;
    let error = send_genesis_checkpoint(&test_client(), &valid_worker_config(endpoint), &[9; 32])
        .await
        .expect_err("failed genesis response is classified");
    assert_eq!(error.code(), "http_5xx");
    server.await.expect("failed genesis endpoint completes");
}

#[test]
fn retry_delay_and_delivery_lag_are_monotonic_and_bounded() {
    assert_eq!(retry_delay(-1), Duration::from_secs(1));
    assert_eq!(retry_delay(0), Duration::from_secs(1));
    assert_eq!(retry_delay(1), Duration::from_secs(1));
    assert_eq!(retry_delay(2), Duration::from_secs(2));
    assert_eq!(retry_delay(3), Duration::from_secs(4));
    assert_eq!(retry_delay(9), Duration::from_secs(256));
    assert_eq!(retry_delay(10), Duration::from_secs(300));
    assert_eq!(retry_delay(i32::MAX), Duration::from_secs(300));

    let mut recent = delivery();
    recent.occurred_at = Utc::now() - ChronoDuration::seconds(3);
    assert!(delivery_lag_seconds(&recent) >= 2);
    recent.occurred_at = Utc::now() + ChronoDuration::seconds(30);
    assert_eq!(delivery_lag_seconds(&recent), 0);
}

#[tokio::test]
async fn repository_adapter_forwards_invalid_pool_calls_without_panicking() {
    let pool = nazo_postgres::create_pool("not a postgres url", 1).unwrap();
    let repository = AuditLedgerRepository::new(pool);

    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::anchor_health(&repository)
            .await
            .is_err()
    );
    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::claim_due(&repository, 0, 1)
            .await
            .is_err()
    );
    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::mark_exported(
            &repository,
            Uuid::nil(),
            1,
            "deployment-1",
        )
        .await
        .is_err()
    );
    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::reschedule(
            &repository,
            Uuid::nil(),
            1,
            Utc::now(),
            "typed-test-error",
        )
        .await
        .is_err()
    );
}

fn required_config() -> AuditAnchorPreflightConfig {
    AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment-1".to_owned(),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    }
}
