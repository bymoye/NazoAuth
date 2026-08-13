use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context as _;
use chrono::Utc;
use futures_util::{StreamExt as _, stream};
use nazo_auth::{
    CibaPingResponseAction, classify_ciba_ping_status, next_ciba_ping_retry_at,
    validate_ciba_notification_endpoint,
};
use nazo_valkey::{CibaPingDelivery, CibaPingFinishOutcome, CibaPingFinishResult, CibaStore};
use reqwest::{StatusCode, header};
use serde_json::json;

use super::{ciba_ping_tls::apply_ciba_ping_tls_policy, sector_identifier::is_blocked_ip};

const DELIVERY_CONCURRENCY: usize = 8;
// One claim is processed in a single concurrency wave.  Keeping the batch at
// the concurrency limit ensures the 15-second Valkey claim lease covers the
// worst case request timeout instead of allowing a later wave to outlive it.
const DELIVERY_BATCH_SIZE: usize = DELIVERY_CONCURRENCY;
const DELIVERY_LOCK_SECONDS: i64 = 15;
const LOOP_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub(crate) struct CibaPingDeliveryWorker {
    store: CibaStore,
    private_network_origins: Arc<HashSet<String>>,
}

impl CibaPingDeliveryWorker {
    pub(crate) fn new(
        store: CibaStore,
        private_network_origins: &[String],
    ) -> anyhow::Result<Self> {
        let mut origins = HashSet::new();
        for value in private_network_origins {
            let parsed = validate_ciba_notification_endpoint(value)
                .map_err(anyhow::Error::msg)
                .with_context(|| {
                    format!("invalid CIBA_NOTIFICATION_PRIVATE_ORIGINS entry {value}")
                })?;
            if parsed.path() != "/" || parsed.query().is_some() {
                anyhow::bail!(
                    "CIBA_NOTIFICATION_PRIVATE_ORIGINS entries must be HTTPS origins: {value}"
                );
            }
            origins.insert(parsed.origin().ascii_serialization());
        }
        Ok(Self {
            store,
            private_network_origins: Arc::new(origins),
        })
    }

    pub(crate) async fn process_due_batch(&self) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();
        let deliveries = self
            .store
            .claim_due_ping(
                now,
                now.saturating_add(DELIVERY_LOCK_SECONDS),
                DELIVERY_BATCH_SIZE,
            )
            .await
            .context("failed to claim CIBA ping deliveries")?;
        let count = deliveries.len();
        let outcomes = stream::iter(deliveries)
            .map(|delivery| async move { self.process_delivery(delivery).await })
            .buffer_unordered(DELIVERY_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        if let Some(error) = outcomes.into_iter().find_map(Result::err) {
            return Err(error);
        }
        Ok(count)
    }

    async fn process_delivery(&self, delivery: CibaPingDelivery) -> anyhow::Result<()> {
        let outcome = match self.post(&delivery).await {
            Ok(PingPostOutcome::Delivered) => CibaPingFinishOutcome::Delivered,
            Ok(PingPostOutcome::Terminal(status)) => {
                tracing::warn!(
                    %status,
                    endpoint_origin = %endpoint_origin_for_log(&delivery.endpoint),
                    "CIBA ping endpoint rejected the notification; delivery is terminal"
                );
                CibaPingFinishOutcome::Failed
            }
            Err(_) => {
                tracing::warn!(
                    endpoint_origin = %endpoint_origin_for_log(&delivery.endpoint),
                    attempts = delivery.attempts,
                    "CIBA ping notification transport failed"
                );
                next_ciba_ping_retry_at(
                    delivery.attempts,
                    Utc::now().timestamp(),
                    delivery.expires_at,
                )
                .map_or(
                    CibaPingFinishOutcome::Failed,
                    CibaPingFinishOutcome::RetryAt,
                )
            }
        };
        let finish_result = self
            .store
            .finish_ping(&delivery, outcome)
            .await
            .context("failed to record CIBA ping delivery outcome")?;
        match finish_result {
            CibaPingFinishResult::Applied => {}
            CibaPingFinishResult::Missing | CibaPingFinishResult::Conflict => {
                tracing::debug!(
                    attempts = delivery.attempts,
                    "CIBA ping finish skipped because the delivery claim is stale"
                );
            }
        }
        Ok(())
    }

    async fn post(&self, delivery: &CibaPingDelivery) -> anyhow::Result<PingPostOutcome> {
        let endpoint =
            validate_ciba_notification_endpoint(&delivery.endpoint).map_err(anyhow::Error::msg)?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("CIBA ping endpoint has no host"))?;
        let port = endpoint.port_or_known_default().unwrap_or(443);
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .context("CIBA ping DNS resolution failed")?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            anyhow::bail!("CIBA ping DNS returned no addresses");
        }
        let allow_private = self
            .private_network_origins
            .contains(&endpoint.origin().ascii_serialization());
        if !allow_private && addresses.iter().any(|address| is_blocked_ip(address.ip())) {
            anyhow::bail!("CIBA ping endpoint resolved to a blocked network");
        }
        let client = apply_ciba_ping_tls_policy(reqwest::Client::builder().no_proxy())?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
            .context("failed to build CIBA ping HTTP client")?;
        let response = client
            .post(endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::HeaderName::from_static("idempotency-key"),
                ciba_ping_idempotency_key(&delivery.auth_req_id_hash),
            )
            .bearer_auth(&delivery.client_notification_token)
            .json(&json!({"auth_req_id": delivery.auth_req_id}))
            .send()
            .await
            .context("CIBA ping request failed")?;
        match classify_ciba_ping_status(response.status().as_u16()) {
            CibaPingResponseAction::Delivered => Ok(PingPostOutcome::Delivered),
            CibaPingResponseAction::TerminalFailure => {
                Ok(PingPostOutcome::Terminal(response.status()))
            }
            CibaPingResponseAction::Retry => {
                anyhow::bail!("CIBA ping endpoint returned {}", response.status())
            }
        }
    }
}

fn endpoint_origin_for_log(raw: &str) -> String {
    validate_ciba_notification_endpoint(raw)
        .map(|endpoint| endpoint.origin().ascii_serialization())
        .unwrap_or_else(|_| "<invalid>".to_owned())
}

fn ciba_ping_idempotency_key(auth_req_id_hash: &str) -> String {
    format!("nazo-ciba-ping-{auth_req_id_hash}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PingPostOutcome {
    Delivered,
    Terminal(StatusCode),
}

pub(crate) fn spawn_ciba_ping_delivery_worker(worker: CibaPingDeliveryWorker) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = worker.process_due_batch().await {
                tracing::warn!(%error, "CIBA ping delivery worker failed");
            }
            tokio::time::sleep(LOOP_INTERVAL).await;
        }
    });
}
