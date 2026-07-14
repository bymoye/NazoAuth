#[cfg(not(test))]
use std::time::Duration as StdDuration;

#[cfg(not(test))]
use anyhow::Context as _;
use chrono::{DateTime, Duration, Utc};
#[cfg(not(test))]
use futures_util::{StreamExt as _, stream};
#[cfg(not(test))]
use nazo_auth::BackchannelLogoutDelivery;
#[cfg(not(test))]
use nazo_postgres::AuditRepository;

#[cfg(not(test))]
const DELIVERY_BATCH_SIZE: i64 = 20;
#[cfg(not(test))]
const DELIVERY_CONCURRENCY: usize = 8;
#[cfg(not(test))]
const LOCK_TIMEOUT_SECONDS: i32 = 300;
const ERROR_MAX_CHARS: usize = 512;

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct BackchannelLogoutWorker {
    deliveries: AuditRepository,
    http: reqwest::Client,
}

#[cfg(not(test))]
impl BackchannelLogoutWorker {
    pub(crate) fn new(deliveries: AuditRepository) -> anyhow::Result<Self> {
        Ok(Self {
            deliveries,
            http: reqwest::Client::builder()
                .timeout(StdDuration::from_secs(3))
                .build()
                .context("failed to build back-channel logout HTTP client")?,
        })
    }

    pub(crate) async fn process_due_batch(&self) -> anyhow::Result<usize> {
        let deliveries = self
            .deliveries
            .claim_due_backchannel_logout(DELIVERY_BATCH_SIZE, LOCK_TIMEOUT_SECONDS)
            .await
            .context("failed to claim back-channel logout deliveries")?;
        let processed = deliveries.len();
        let results = stream::iter(deliveries)
            .map(|delivery| async move { self.process_delivery(delivery).await })
            .buffer_unordered(DELIVERY_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        if let Some(error) = results.into_iter().find_map(Result::err) {
            return Err(error);
        }
        Ok(processed)
    }

    async fn process_delivery(&self, delivery: BackchannelLogoutDelivery) -> anyhow::Result<()> {
        match self.post(&delivery).await {
            Ok(()) => self
                .deliveries
                .complete_backchannel_logout(delivery.id, delivery.attempts)
                .await
                .context("failed to complete back-channel logout delivery"),
            Err(delivery_error) => {
                let now = Utc::now();
                let next_attempt_at =
                    next_retry_at(delivery.attempts - 1, now, delivery.expires_at);
                let last_error = truncate_error(&delivery_error.to_string());
                tracing::warn!(
                    error = %last_error,
                    backchannel_logout_uri = %delivery.logout_uri,
                    "back-channel logout delivery failed"
                );
                self.deliveries
                    .fail_backchannel_logout(
                        delivery.id,
                        delivery.attempts,
                        next_attempt_at,
                        &last_error,
                    )
                    .await
                    .context("failed to record back-channel logout delivery failure")
            }
        }
    }

    async fn post(&self, delivery: &BackchannelLogoutDelivery) -> anyhow::Result<()> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", &delivery.logout_token)
            .finish();
        let response = self
            .http
            .post(&delivery.logout_uri)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .context("back-channel logout request failed")?;
        if !response.status().is_success() {
            anyhow::bail!(
                "back-channel logout endpoint returned {}",
                response.status()
            );
        }
        Ok(())
    }
}

#[cfg(not(test))]
pub(crate) fn spawn_backchannel_logout_delivery_worker(worker: BackchannelLogoutWorker) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = worker.process_due_batch().await {
                tracing::warn!(%error, "back-channel logout delivery worker failed");
            }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
}

fn next_retry_at(
    attempt_index: i32,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let delay_seconds = match attempt_index {
        0 => 5,
        1 => 15,
        2 => 45,
        _ => return None,
    };
    let next_attempt_at = now + Duration::seconds(delay_seconds);
    (next_attempt_at < expires_at).then_some(next_attempt_at)
}

fn truncate_error(error: &str) -> String {
    error.chars().take(ERROR_MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_are_bounded_and_never_scheduled_after_expiry() {
        let now = Utc::now();
        assert_eq!(
            next_retry_at(0, now, now + Duration::seconds(60)),
            Some(now + Duration::seconds(5))
        );
        assert_eq!(
            next_retry_at(1, now, now + Duration::seconds(60)),
            Some(now + Duration::seconds(15))
        );
        assert_eq!(
            next_retry_at(2, now, now + Duration::seconds(60)),
            Some(now + Duration::seconds(45))
        );
        assert_eq!(next_retry_at(3, now, now + Duration::seconds(60)), None);
        assert_eq!(next_retry_at(2, now, now + Duration::seconds(45)), None);
    }

    #[test]
    fn persisted_delivery_errors_are_unicode_safe_and_bounded() {
        let error = "失".repeat(ERROR_MAX_CHARS + 10);
        let truncated = truncate_error(&error);
        assert_eq!(truncated.chars().count(), ERROR_MAX_CHARS);
        assert!(truncated.is_char_boundary(truncated.len()));
    }
}
