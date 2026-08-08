use std::{collections::HashSet, net::SocketAddr, time::Duration as StdDuration};

#[cfg(not(test))]
use std::sync::Arc;

use anyhow::Context as _;
use chrono::{DateTime, Duration, Utc};
#[cfg(not(test))]
use futures_util::{StreamExt as _, stream};
#[cfg(not(test))]
use nazo_auth::BackchannelLogoutDelivery;
use nazo_auth::MAX_CIBA_LOGOUT_URI_BYTES;
#[cfg(not(test))]
use nazo_postgres::AuditRepository;
use url::Url;

use super::sector_identifier::is_blocked_ip;

#[cfg(not(test))]
const DELIVERY_BATCH_SIZE: i64 = 20;
#[cfg(not(test))]
const DELIVERY_CONCURRENCY: usize = 8;
#[cfg(not(test))]
const LOCK_TIMEOUT_SECONDS: i32 = 300;
const ERROR_MAX_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackchannelResponseAction {
    Delivered,
    Retry,
    TerminalFailure,
}

#[derive(Debug, Eq, PartialEq)]
enum BackchannelPostOutcome {
    Delivered,
    TerminalFailure(u16),
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct BackchannelLogoutWorker {
    deliveries: AuditRepository,
    private_network_origins: Arc<HashSet<String>>,
}

#[cfg(not(test))]
impl BackchannelLogoutWorker {
    pub(crate) fn new(
        deliveries: AuditRepository,
        private_network_origins: &[String],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            deliveries,
            private_network_origins: Arc::new(parse_private_network_origins(
                private_network_origins,
            )?),
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
        match post_logout_token(
            &self.private_network_origins,
            &delivery.logout_uri,
            &delivery.logout_token,
        )
        .await
        {
            Ok(BackchannelPostOutcome::Delivered) => self
                .deliveries
                .complete_backchannel_logout(delivery.id, delivery.attempts)
                .await
                .context("failed to complete back-channel logout delivery"),
            outcome => {
                let now = Utc::now();
                let (next_attempt_at, delivery_error) =
                    delivery_failure_state(outcome, delivery.attempts, now, delivery.expires_at);
                let last_error = truncate_error(&delivery_error.to_string());
                tracing::warn!(
                    retry_scheduled = next_attempt_at.is_some(),
                    failure_recorded_at = %now,
                    endpoint_origin = %validate_backchannel_endpoint(&delivery.logout_uri)
                        .map(|endpoint| endpoint.origin().ascii_serialization())
                        .unwrap_or_else(|_| "<invalid>".to_owned()),
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
}

fn parse_private_network_origins(values: &[String]) -> anyhow::Result<HashSet<String>> {
    let mut origins = HashSet::new();
    for value in values {
        let endpoint = validate_backchannel_endpoint(value)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("invalid BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS entry {value}"))?;
        if endpoint.path() != "/" || endpoint.query().is_some() {
            anyhow::bail!("BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS entries must be origins: {value}");
        }
        origins.insert(endpoint.origin().ascii_serialization());
    }
    Ok(origins)
}

fn delivery_failure_state(
    outcome: anyhow::Result<BackchannelPostOutcome>,
    attempts: i32,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> (Option<DateTime<Utc>>, anyhow::Error) {
    match outcome {
        Ok(BackchannelPostOutcome::TerminalFailure(status)) => (
            None,
            anyhow::anyhow!("back-channel logout endpoint returned terminal status {status}"),
        ),
        Err(error) => (next_retry_at(attempts - 1, now, expires_at), error),
        Ok(BackchannelPostOutcome::Delivered) => unreachable!(),
    }
}

async fn post_logout_token(
    private_network_origins: &HashSet<String>,
    logout_uri: &str,
    logout_token: &str,
) -> anyhow::Result<BackchannelPostOutcome> {
    let endpoint = validate_backchannel_endpoint(logout_uri)
        .map_err(anyhow::Error::msg)
        .context("invalid stored back-channel logout endpoint")?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("back-channel logout endpoint has no host"))?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("back-channel logout endpoint has no port"))?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .context("back-channel logout DNS resolution failed")?
        .collect::<Vec<SocketAddr>>();
    if addresses.is_empty() {
        anyhow::bail!("back-channel logout DNS returned no addresses");
    }
    let allow_private = private_network_origins.contains(&endpoint.origin().ascii_serialization());
    if !allow_private && addresses.iter().any(|address| is_blocked_ip(address.ip())) {
        anyhow::bail!("back-channel logout endpoint resolved to a blocked network");
    }
    let http = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(StdDuration::from_secs(3))
        .timeout(StdDuration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
        .context("failed to build back-channel logout HTTP client")?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", logout_token)
        .finish();
    let response = http
        .post(logout_uri)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(
            reqwest::header::HeaderName::from_static("idempotency-key"),
            backchannel_idempotency_key(logout_token),
        )
        .body(body)
        .send()
        .await
        .context("back-channel logout request failed")?;
    let status = response.status().as_u16();
    match classify_backchannel_status(status) {
        BackchannelResponseAction::Delivered => Ok(BackchannelPostOutcome::Delivered),
        BackchannelResponseAction::TerminalFailure => {
            Ok(BackchannelPostOutcome::TerminalFailure(status))
        }
        BackchannelResponseAction::Retry => {
            anyhow::bail!("back-channel logout endpoint returned retryable status {status}")
        }
    }
}

fn validate_backchannel_endpoint(raw: &str) -> Result<Url, &'static str> {
    if raw.len() > MAX_CIBA_LOGOUT_URI_BYTES {
        return Err("back-channel logout endpoint exceeds the maximum URI length");
    }
    let endpoint = Url::parse(raw).map_err(|_| "back-channel logout endpoint is not a URI")?;
    let host = endpoint
        .host_str()
        .ok_or("back-channel logout endpoint has no host")?;
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("back-channel logout endpoint contains forbidden URI components");
    }
    match endpoint.scheme() {
        "https" => {}
        "http"
            if matches!(host, "localhost" | "127.0.0.1" | "::1")
                || host.ends_with(".localhost") => {}
        _ => return Err("back-channel logout endpoint must use HTTPS or loopback HTTP"),
    }
    Ok(endpoint)
}

fn backchannel_idempotency_key(logout_token: &str) -> String {
    format!(
        "nazo-backchannel-logout-{}",
        blake3::hash(logout_token.as_bytes()).to_hex()
    )
}

fn classify_backchannel_status(status: u16) -> BackchannelResponseAction {
    match status {
        200 | 204 => BackchannelResponseAction::Delivered,
        408 | 425 | 429 | 500..=599 => BackchannelResponseAction::Retry,
        _ => BackchannelResponseAction::TerminalFailure,
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
#[path = "../../tests/unit/domain/backchannel_logout_worker.rs"]
mod tests;
