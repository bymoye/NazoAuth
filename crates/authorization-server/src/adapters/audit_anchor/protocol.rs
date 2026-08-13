use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use nazo_postgres::SecurityAuditOutboxDelivery;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

pub(super) const CHECKPOINT_SCHEMA_VERSION: &str = "nazo.audit.anchor.v1";
pub(super) const GENESIS_EVENT_ID: Uuid = Uuid::from_u128(0);

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
pub(super) struct AnchorCheckpointEnvelope<'a> {
    pub(super) schema_version: &'static str,
    pub(super) event_id: Uuid,
    pub(super) deployment_id: &'a str,
    pub(super) sequence: i64,
    pub(super) previous_hash: String,
    pub(super) event_hash: String,
    pub(super) event_type: &'a str,
    pub(super) event_category: &'a str,
    pub(super) payload: Value,
    pub(super) occurred_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub(super) struct GenesisCheckpointEnvelope<'a> {
    pub(super) schema_version: &'static str,
    pub(super) checkpoint_kind: &'static str,
    pub(super) event_id: Uuid,
    pub(super) deployment_id: &'a str,
    pub(super) sequence: i64,
    pub(super) previous_hash: String,
    pub(super) event_hash: String,
    pub(super) occurred_at: DateTime<Utc>,
}

pub(super) fn checkpoint_body(
    deployment_id: &str,
    delivery: &SecurityAuditOutboxDelivery,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&AnchorCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        event_id: delivery.event_id,
        deployment_id,
        sequence: delivery.sequence,
        previous_hash: encode_hash(&delivery.previous_hash),
        event_hash: encode_hash(&delivery.event_hash),
        event_type: &delivery.event_type,
        event_category: &delivery.event_category,
        payload: delivery.payload.clone(),
        occurred_at: delivery.occurred_at,
    })
}

pub(super) fn genesis_body(
    deployment_id: &str,
    head_hash: &[u8],
) -> Result<Vec<u8>, serde_json::Error> {
    let hash = encode_hash(head_hash);
    serde_json::to_vec(&GenesisCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        checkpoint_kind: "genesis",
        event_id: GENESIS_EVENT_ID,
        deployment_id,
        sequence: 0,
        previous_hash: hash.clone(),
        event_hash: hash,
        occurred_at: DateTime::<Utc>::UNIX_EPOCH,
    })
}

pub(super) fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(body);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub(super) fn encode_hash(hash: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}
