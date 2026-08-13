//! 结构化安全审计日志。

use std::{sync::OnceLock, time::Duration};

use chrono::Utc;
use tokio::sync::mpsc;
use uuid::Uuid;

use nazo_postgres::{AuditLedgerRepository, SecurityAuditEvent};

use super::audit_anchor::AuditAnchorPreflight;

pub(crate) const AUDIT_SCHEMA_VERSION: &str = "nazo.audit.v1";

const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "authorization_code",
    "client_secret",
    "dpop_proof",
    "client_assertion",
];

const AUDIT_EVENT_DEFINITIONS: &[(&str, &str)] = &[
    ("admin_mutation_intent", "administration"),
    ("admin_user_created", "administration"),
    ("admin_user_updated", "administration"),
    ("admin_grant_revoked", "administration"),
    ("admin_access_request_rejected", "administration"),
    ("authorization_approved", "authorization"),
    ("authorization_denied", "authorization"),
    ("authorization_decision_intent", "authorization"),
    ("authorization_prompt_none_approved", "authorization"),
    ("ciba_authorization_approved", "authorization"),
    ("ciba_authorization_denied", "authorization"),
    ("ciba_authorization_started", "authorization"),
    ("ciba_authorization_intent", "authorization"),
    ("ciba_decision_intent", "authorization"),
    ("device_authorization_approved", "authorization"),
    ("device_authorization_denied", "authorization"),
    ("device_authorization_started", "authorization"),
    ("device_decision_intent", "authorization"),
    ("client_assertion_replay_detected", "credential_replay"),
    ("client_created", "client_lifecycle"),
    ("client_updated", "client_lifecycle"),
    ("dynamic_client_configuration_read", "client_lifecycle"),
    ("dynamic_client_configuration_updated", "client_lifecycle"),
    ("dynamic_client_deleted", "client_lifecycle"),
    ("dynamic_client_registered", "client_lifecycle"),
    ("dpop_replay_detected", "credential_replay"),
    ("external_identity_linked", "identity_lifecycle"),
    ("external_identity_relink_denied", "identity_lifecycle"),
    ("external_identity_unlinked", "identity_lifecycle"),
    ("federation_login_success", "authentication"),
    ("federation_provider_mismatch_rejected", "credential_replay"),
    ("federation_saml_replay_rejected", "credential_replay"),
    ("login_failure", "authentication"),
    ("login_success", "authentication"),
    ("mfa_backup_codes_regenerated", "authentication"),
    ("mfa_challenge_failure", "authentication"),
    ("mfa_challenge_success", "authentication"),
    ("mfa_disabled", "authentication"),
    ("mfa_step_up_success", "authentication"),
    ("mfa_totp_enabled", "authentication"),
    ("oidc_logout", "session_lifecycle"),
    (
        "openid4vci_credential_dataset_deleted",
        "credential_lifecycle",
    ),
    (
        "openid4vci_credential_dataset_updated",
        "credential_lifecycle",
    ),
    ("mtls_trust_anchor_approved", "trust_lifecycle"),
    ("mtls_trust_bundle_exported", "trust_lifecycle"),
    ("mtls_trust_anchor_rejected", "trust_lifecycle"),
    ("mtls_trust_anchor_requested", "trust_lifecycle"),
    ("mtls_trust_anchor_revoked", "trust_lifecycle"),
    ("passkey_login_failure", "authentication"),
    ("passkey_login_success", "authentication"),
    ("passkey_registered", "authentication"),
    ("passkey_registration_rejected", "authentication"),
    ("refresh_reuse_detected", "token_replay"),
    ("refresh_rotated", "token_lifecycle"),
    ("scim_token_denied", "provisioning"),
    ("scim_token_used", "provisioning"),
    ("token_issued", "token_lifecycle"),
    ("token_issuance_intent", "token_lifecycle"),
    ("token_revoked", "token_lifecycle"),
];

const AUDIT_QUEUE_CAPACITY: usize = 4096;
// These are process-lifetime handles: the request path currently resolves the
// durable sink through `ensure_audit_storage`, so bootstrap must install them
// exactly once before handlers start accepting traffic.
static PERSISTENT_AUDIT_SINK: OnceLock<mpsc::Sender<QueuedAuditEvent>> = OnceLock::new();
static REQUIRED_AUDIT_REPOSITORY: OnceLock<RequiredAuditRepository> = OnceLock::new();

struct RequiredAuditRepository {
    repository: AuditLedgerRepository,
    require_least_privilege: bool,
    preflight: AuditAnchorPreflight,
}

#[derive(Clone, Debug)]
struct QueuedAuditEvent {
    event_id: Uuid,
    event_type: String,
    event_category: String,
    payload: serde_json::Value,
    occurred_at: chrono::DateTime<Utc>,
}

/// Install the durable audit sink once during application bootstrap.
///
/// The request path remains synchronous: it writes the structured event to
/// tracing and performs a bounded `try_send` into a worker. The worker retries
/// database failures indefinitely, preserving the event after it has entered
/// the queue. Queue saturation/disconnection is reported as a distinct,
/// machine-searchable failure instead of being silently swallowed. Actions
/// that already have a transactional security repository retain their own
/// fail-closed semantics; this sink is the durable evidence/export path for
/// the broader application audit vocabulary.
pub(crate) fn install_persistent_audit_sink(
    repository: AuditLedgerRepository,
    require_least_privilege: bool,
    preflight: AuditAnchorPreflight,
) -> anyhow::Result<()> {
    if PERSISTENT_AUDIT_SINK.get().is_some() {
        let Some(existing) = REQUIRED_AUDIT_REPOSITORY.get() else {
            anyhow::bail!("durable security audit sink is partially installed");
        };
        if existing.require_least_privilege != require_least_privilege
            || existing.preflight != preflight
        {
            anyhow::bail!(
                "durable security audit sink was already installed with different configuration"
            );
        }
        return Ok(());
    }
    let candidate = RequiredAuditRepository {
        repository: repository.clone(),
        require_least_privilege,
        preflight: preflight.clone(),
    };
    if let Err(candidate) = REQUIRED_AUDIT_REPOSITORY.set(candidate) {
        let Some(existing) = REQUIRED_AUDIT_REPOSITORY.get() else {
            anyhow::bail!("durable security audit repository installation raced bootstrap");
        };
        if existing.require_least_privilege != candidate.require_least_privilege
            || existing.preflight != candidate.preflight
        {
            anyhow::bail!(
                "durable security audit repository was already installed with different configuration"
            );
        }
    }
    let (sender, mut receiver) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
    if PERSISTENT_AUDIT_SINK.set(sender).is_err() {
        return Ok(());
    }

    tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let mut retry_delay = Duration::from_millis(100);
            loop {
                let persistence = repository
                    .append(SecurityAuditEvent {
                        event_id: event.event_id,
                        event_type: event.event_type.clone(),
                        event_category: event.event_category.clone(),
                        payload: event.payload.clone(),
                        occurred_at: event.occurred_at,
                    })
                    .await;
                match persistence {
                    Ok(receipt) => {
                        tracing::debug!(
                            target: "audit.persistence",
                            event_id = %receipt.event_id,
                            sequence = receipt.sequence,
                            persistence_status = "durable",
                            "security audit event appended"
                        );
                        break;
                    }
                    Err(error) => {
                        tracing::error!(
                            target: "audit.persistence",
                            event = %event.event_type,
                            %error,
                            persistence_status = "retrying",
                            "security audit event persistence failed"
                        );
                        tokio::time::sleep(retry_delay).await;
                        retry_delay =
                            std::cmp::min(retry_delay + retry_delay, Duration::from_secs(5));
                    }
                }
            }
        }
    });
    Ok(())
}

/// Preflight the durable ledger before a high-impact mutation.
///
/// When the mutation and this ledger do not share a transaction boundary,
/// callers should append a required `*_intent` event after this check and
/// before changing state. The committed outcome can then be emitted through
/// [`audit_event`] (or, where the stores are atomic, through
/// [`audit_event_required`]).
pub(crate) async fn ensure_audit_storage() -> anyhow::Result<()> {
    let Some(required) = REQUIRED_AUDIT_REPOSITORY.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    required
        .repository
        .check_available_with_policy(required.require_least_privilege)
        .await
        .map_err(|error| {
            anyhow::anyhow!("durable security audit repository unavailable: {error}")
        })?;
    let head = required
        .repository
        .anchor_freshness()
        .await
        .map_err(|error| anyhow::anyhow!("durable security audit head unavailable: {error}"))?;
    required
        .preflight
        .ensure_fresh(head.head_sequence, &head.head_hash)
        .await
}

/// Append a high-impact audit outcome synchronously. Unlike [`audit_event`],
/// this path never drops an event into the in-process queue: the caller gets an
/// error when the ledger is unavailable and must convert it to a fail-closed
/// response. The recommended sequence is `ensure_audit_storage().await`,
/// perform the mutation, then await this function with the committed outcome.
pub(crate) async fn audit_event_required(
    event: &str,
    fields: serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<()> {
    let queued = prepare_event(event, fields)
        .map_err(|reason| anyhow::anyhow!("security audit event rejected: {reason}"))?;
    let Some(required) = REQUIRED_AUDIT_REPOSITORY.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    let receipt = required
        .repository
        .append(SecurityAuditEvent {
            event_id: queued.event_id,
            event_type: queued.event_type.clone(),
            event_category: queued.event_category.clone(),
            payload: queued.payload.clone(),
            occurred_at: queued.occurred_at,
        })
        .await
        .map_err(|error| anyhow::anyhow!("security audit append failed: {error}"))?;
    tracing::info!(
        target: "audit",
        event,
        fields = %queued.payload,
        sequence = receipt.sequence,
        persistence_status = "durable",
        "security audit event"
    );
    Ok(())
}

/// Emit a best-effort audit event for low-risk telemetry. Queue saturation is
/// intentionally not retried on the request path; the loss is emitted as a
/// structured `audit.persistence` error. High-impact management actions must
/// use [`ensure_audit_storage`] and [`audit_event_required`] instead.
pub(crate) fn audit_event(event: &str, fields: serde_json::Map<String, serde_json::Value>) {
    debug_assert!(audit_event_name_valid(event));
    debug_assert!(audit_event_category(event).is_some());
    let queued = match prepare_event(event, fields) {
        Ok(queued) => queued,
        Err(reason) => {
            tracing::error!(
                target: "audit.persistence",
                event,
                persistence_status = "rejected",
                reason,
                "security audit event is not allowlisted"
            );
            return;
        }
    };
    tracing::info!(
        target: "audit",
        event,
        fields = %queued.payload,
        "security audit event"
    );
    let Some(sink) = PERSISTENT_AUDIT_SINK.get() else {
        tracing::error!(
            target: "audit.persistence",
            event,
            persistence_status = "not_configured",
            "security audit event has no durable sink"
        );
        return;
    };
    if let Err(error) = sink.try_send(queued) {
        let reason = match error {
            mpsc::error::TrySendError::Full(_) => "queue_full",
            mpsc::error::TrySendError::Closed(_) => "sink_closed",
        };
        tracing::error!(
            target: "audit.persistence",
            event,
            persistence_status = "not_queued",
            reason,
            "security audit event could not enter durable sink"
        );
    }
}

fn prepare_event(
    event: &str,
    mut fields: serde_json::Map<String, serde_json::Value>,
) -> Result<QueuedAuditEvent, &'static str> {
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }
    let Some(category) = audit_event_category(event) else {
        return Err("unknown_event_type");
    };
    fields.insert(
        "schema_version".to_owned(),
        serde_json::Value::String(AUDIT_SCHEMA_VERSION.to_owned()),
    );
    fields.insert(
        "event_category".to_owned(),
        serde_json::Value::String(category.to_owned()),
    );
    let payload = serde_json::Value::Object(fields);
    let payload_size = serde_json::to_vec(&payload)
        .map_err(|_| "payload_serialization_failed")?
        .len();
    if payload_size > nazo_postgres::MAX_SECURITY_AUDIT_PAYLOAD_BYTES {
        return Err("payload_too_large");
    }
    Ok(QueuedAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: event.to_owned(),
        event_category: category.to_owned(),
        payload,
        occurred_at: Utc::now(),
    })
}

pub(crate) fn audit_fields(
    items: &[(&str, serde_json::Value)],
) -> serde_json::Map<String, serde_json::Value> {
    items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn audit_event_category(event: &str) -> Option<&'static str> {
    AUDIT_EVENT_DEFINITIONS
        .iter()
        .find_map(|(name, category)| (*name == event).then_some(*category))
}

fn audit_event_name_valid(event: &str) -> bool {
    let mut chars = event.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/audit.rs"]
mod tests;
