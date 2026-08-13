use chrono::Utc;
use nazo_postgres::SecurityAuditOutboxDelivery;

use super::{
    AuditAnchorWorkerConfig,
    protocol::{CHECKPOINT_SCHEMA_VERSION, checkpoint_body, genesis_body, sign_body},
    status::AnchorCheckpoint,
};

#[derive(Debug)]
pub(super) enum AnchorPushError {
    Transport,
    Serialize,
    Http(u16),
}

impl AnchorPushError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::Transport => "transport_error",
            Self::Serialize => "serialization_error",
            Self::Http(429) => "http_429",
            Self::Http(400..=499) => "http_4xx",
            Self::Http(500..=599) => "http_5xx",
            Self::Http(_) => "http_other",
        }
    }
}

pub(super) async fn send_checkpoint(
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    delivery: &SecurityAuditOutboxDelivery,
) -> Result<(), AnchorPushError> {
    let body = checkpoint_body(&config.preflight.deployment_id, delivery)
        .map_err(|_| AnchorPushError::Serialize)?;
    let signature = sign_body(&config.auth_secret, &body);
    let sent_at = Utc::now().to_rfc3339();
    let response = client
        .post(config.endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", delivery.event_id.to_string())
        .header("X-Nazo-Audit-Schema", CHECKPOINT_SCHEMA_VERSION)
        .header("X-Nazo-Audit-Deployment", &config.preflight.deployment_id)
        .header("X-Nazo-Audit-Sent-At", sent_at)
        .header("X-Nazo-Audit-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(AnchorPushError::Http(status.as_u16()))
    }
}

pub(super) async fn send_genesis_checkpoint(
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    head_hash: &[u8],
) -> Result<AnchorCheckpoint, AnchorPushError> {
    let body = genesis_body(&config.preflight.deployment_id, head_hash)
        .map_err(|_| AnchorPushError::Serialize)?;
    let signature = sign_body(&config.auth_secret, &body);
    let sent_at = Utc::now().to_rfc3339();
    let response = client
        .post(config.endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            "Idempotency-Key",
            format!("genesis:{}", config.preflight.deployment_id),
        )
        .header("X-Nazo-Audit-Schema", CHECKPOINT_SCHEMA_VERSION)
        .header("X-Nazo-Audit-Deployment", &config.preflight.deployment_id)
        .header("X-Nazo-Audit-Sent-At", sent_at)
        .header("X-Nazo-Audit-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    if !response.status().is_success() {
        return Err(AnchorPushError::Http(response.status().as_u16()));
    }
    Ok(AnchorCheckpoint::genesis(super::protocol::encode_hash(
        head_hash,
    )))
}
