use std::time::Duration;

use anyhow::Context as _;
use chrono::{Duration as ChronoDuration, Utc};
use nazo_identity::ports::RepositoryFuture;
use nazo_postgres::{
    AuditLedgerRepository, SecurityAuditAnchorHealth, SecurityAuditOutboxDelivery,
};

use super::{
    AuditAnchorWorkerConfig,
    status::{AnchorCheckpoint, read_health_optional, write_health},
    transport::{send_checkpoint, send_genesis_checkpoint},
};

const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);

/// The exporter-facing repository boundary. Keeping this port private to the
/// adapter lets the worker state machine be exercised without a live database,
/// while the production command still uses the concrete repository below.
pub(super) trait AuditAnchorRepository: Send + Sync {
    fn anchor_health(&self) -> RepositoryFuture<'_, SecurityAuditAnchorHealth>;

    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> RepositoryFuture<'_, Vec<SecurityAuditOutboxDelivery>>;

    fn mark_exported(
        &self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
    ) -> RepositoryFuture<'_, ()>;

    fn reschedule(
        &self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        available_at: chrono::DateTime<Utc>,
        last_error: &str,
    ) -> RepositoryFuture<'_, ()>;
}

impl AuditAnchorRepository for AuditLedgerRepository {
    fn anchor_health(&self) -> RepositoryFuture<'_, SecurityAuditAnchorHealth> {
        Box::pin(async move { AuditLedgerRepository::anchor_health(self).await })
    }

    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> RepositoryFuture<'_, Vec<SecurityAuditOutboxDelivery>> {
        Box::pin(async move {
            AuditLedgerRepository::claim_due(self, limit, lock_timeout_seconds).await
        })
    }

    fn mark_exported(
        &self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            AuditLedgerRepository::mark_exported(self, event_id, expected_attempts).await
        })
    }

    fn reschedule(
        &self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        available_at: chrono::DateTime<Utc>,
        last_error: &str,
    ) -> RepositoryFuture<'_, ()> {
        let last_error = last_error.to_owned();
        Box::pin(async move {
            AuditLedgerRepository::reschedule(
                self,
                event_id,
                expected_attempts,
                available_at,
                &last_error,
            )
            .await
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum IterationOutcome {
    Retry(Duration),
    Poll(Duration),
    Continue,
}

/// Run the exporter until cancellation. The repository must use the
/// independent exporter database role and the config must be worker-only.
pub(crate) async fn run_worker(
    repository: AuditLedgerRepository,
    config: AuditAnchorWorkerConfig,
) -> anyhow::Result<()> {
    config.validate()?;
    repository
        .check_exporter_available()
        .await
        .map_err(|_| anyhow::anyhow!("audit anchor exporter capability preflight failed"))?;
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build audit anchor HTTP client")?;
    tracing::info!(
        target: "audit.anchor",
        endpoint_host = config.endpoint.host_str().unwrap_or("unknown"),
        deployment_id = %config.preflight.deployment_id,
        mode = ?config.preflight.mode,
        "starting independent audit anchor worker"
    );

    let mut last_anchored = match read_health_optional(&config.preflight.status_file).await {
        Ok(Some(health)) => AnchorCheckpoint::from_health(&health),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(
                target: "audit.anchor",
                error_kind = %error_kind(&error),
                "existing audit anchor health could not be read; genesis will be retried idempotently"
            );
            None
        }
    };

    loop {
        match run_iteration(&repository, &client, &config, &mut last_anchored).await {
            IterationOutcome::Retry(delay) | IterationOutcome::Poll(delay) => {
                tokio::time::sleep(delay).await;
            }
            IterationOutcome::Continue => {}
        }
    }
}

/// Execute one exporter iteration. The caller owns the loop and decides when
/// to sleep from the returned outcome; this function owns only the checkpoint
/// state transition and durable delivery decisions.
pub(super) async fn run_iteration<R: AuditAnchorRepository + ?Sized>(
    repository: &R,
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    last_anchored: &mut Option<AnchorCheckpoint>,
) -> IterationOutcome {
    let snapshot = match repository.anchor_health().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(
                target: "audit.anchor",
                error_kind = %error_kind(&error),
                "audit anchor ledger health query failed"
            );
            return IterationOutcome::Retry(retry_delay(1));
        }
    };

    if let Some(exported) = AnchorCheckpoint::from_snapshot(&snapshot) {
        *last_anchored = Some(exported);
    } else if snapshot.head_sequence == 0 {
        let expected_hash = super::protocol::encode_hash(&snapshot.head_hash);
        let genesis_is_current = last_anchored
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.sequence == 0 && checkpoint.hash == expected_hash);
        if !genesis_is_current {
            match send_genesis_checkpoint(client, config, &snapshot.head_hash).await {
                Ok(checkpoint) => *last_anchored = Some(checkpoint),
                Err(error) => {
                    tracing::warn!(
                        target: "audit.anchor",
                        error_kind = error.code(),
                        "audit anchor genesis checkpoint failed"
                    );
                    return IterationOutcome::Retry(retry_delay(1));
                }
            }
        }
    }

    if let Err(error) = write_health(
        &config.preflight,
        &snapshot,
        last_anchored.as_ref(),
        Utc::now(),
    )
    .await
    {
        tracing::error!(
            target: "audit.anchor",
            error_kind = %error_kind(&error),
            "failed to publish audit anchor health"
        );
    }

    let deliveries = match repository
        .claim_due(config.batch_size, config.lock_timeout_seconds)
        .await
    {
        Ok(deliveries) => deliveries,
        Err(error) => {
            tracing::warn!(
                target: "audit.anchor",
                error_kind = %error_kind(&error),
                "audit anchor outbox claim failed"
            );
            return IterationOutcome::Retry(retry_delay(1));
        }
    };
    if deliveries.is_empty() {
        return IterationOutcome::Poll(config.poll_interval);
    }

    for (index, delivery) in deliveries.iter().enumerate() {
        match send_checkpoint(client, config, delivery).await {
            Ok(()) => match repository
                .mark_exported(delivery.event_id, delivery.attempts)
                .await
            {
                Ok(()) => {
                    *last_anchored = Some(AnchorCheckpoint::from_delivery(delivery));
                    tracing::info!(
                        target: "audit.anchor",
                        event_id = %delivery.event_id,
                        sequence = delivery.sequence,
                        anchor_lag_seconds = delivery_lag_seconds(delivery),
                        status = "anchored",
                        "audit ledger checkpoint accepted by independent sink"
                    );
                }
                Err(error) => {
                    let delay = retry_delay(delivery.attempts);
                    reschedule_claimed(
                        repository,
                        &deliveries[index..],
                        delay,
                        "ack_database_error",
                    )
                    .await;
                    tracing::warn!(
                        target: "audit.anchor",
                        event_id = %delivery.event_id,
                        sequence = delivery.sequence,
                        error_kind = %error_kind(&error),
                        "audit anchor acknowledgement failed; retrying idempotently"
                    );
                    break;
                }
            },
            Err(error) => {
                let delay = retry_delay(delivery.attempts);
                reschedule_claimed(repository, &deliveries[index..], delay, error.code()).await;
                tracing::warn!(
                    target: "audit.anchor",
                    event_id = %delivery.event_id,
                    sequence = delivery.sequence,
                    error_kind = error.code(),
                    retry_after_seconds = delay.as_secs(),
                    "audit checkpoint push failed; durable retry scheduled"
                );
                break;
            }
        }
    }

    IterationOutcome::Continue
}

async fn reschedule_claimed<R: AuditAnchorRepository + ?Sized>(
    repository: &R,
    deliveries: &[SecurityAuditOutboxDelivery],
    delay: Duration,
    reason: &str,
) {
    let available_at = Utc::now()
        + ChronoDuration::from_std(delay).unwrap_or_else(|_| ChronoDuration::seconds(300));
    for delivery in deliveries {
        if let Err(error) = repository
            .reschedule(delivery.event_id, delivery.attempts, available_at, reason)
            .await
        {
            tracing::error!(
                target: "audit.anchor",
                event_id = %delivery.event_id,
                sequence = delivery.sequence,
                error_kind = %error_kind(&error),
                "failed to reschedule audit anchor delivery"
            );
        }
    }
}

pub(super) fn retry_delay(attempts: i32) -> Duration {
    let exponent = attempts.saturating_sub(1).clamp(0, 63) as u32;
    let seconds = 2_u64
        .saturating_pow(exponent)
        .min(MAX_RETRY_DELAY.as_secs());
    Duration::from_secs(seconds)
}

pub(super) fn delivery_lag_seconds(delivery: &SecurityAuditOutboxDelivery) -> i64 {
    (Utc::now() - delivery.occurred_at).num_seconds().max(0)
}

fn error_kind<T>(_error: &T) -> &'static str {
    "external_error"
}
