use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;
use uuid::Uuid;

use nazo_identity::ports::RepositoryError;

use crate::DbPool;

/// The maximum JSON payload accepted by the durable audit ledger.
///
/// Audit events deliberately contain identifiers and hashes, not bearer
/// credentials. A bounded payload keeps the in-process queue and the database
/// outbox from becoming an unbounded memory/storage sink when a caller makes a
/// programming mistake.
pub const MAX_SECURITY_AUDIT_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct SecurityAuditEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub event_category: String,
    pub payload: Value,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditReceipt {
    pub event_id: Uuid,
    pub sequence: i64,
    pub event_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SecurityAuditOutboxDelivery {
    pub event_id: Uuid,
    pub sequence: i64,
    pub event_type: String,
    pub event_category: String,
    pub payload: Value,
    pub occurred_at: DateTime<Utc>,
    pub previous_hash: Vec<u8>,
    pub event_hash: Vec<u8>,
    pub attempts: i32,
}

/// The exporter-only health snapshot. It is returned by a SECURITY DEFINER
/// function, so the exporter needs no table SELECT privilege.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditAnchorHealth {
    pub head_sequence: i64,
    pub head_hash: Vec<u8>,
    pub pending_count: i64,
    pub oldest_pending_occurred_at: Option<DateTime<Utc>>,
    pub last_exported_sequence: Option<i64>,
    pub last_exported_hash: Option<Vec<u8>>,
    pub last_exported_occurred_at: Option<DateTime<Utc>>,
    pub last_exported_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditAnchorFreshness {
    pub head_sequence: i64,
    pub head_hash: Vec<u8>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AuditLedgerRepository {
    pool: DbPool,
}

impl AuditLedgerRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Verify that the writer API and append-only chain are available before a
    /// caller starts a high-impact management operation. Strict mode rejects
    /// superusers, table owners, and any direct ledger table privilege.
    pub async fn check_available(&self) -> Result<(), RepositoryError> {
        self.check_available_with_policy(true).await
    }

    /// The policy switch is explicit so isolated development fixtures can opt
    /// out of strict role checks without weakening the function API boundary.
    /// Function EXECUTE grants and chain integrity are required in both modes.
    pub async fn check_available_with_policy(
        &self,
        require_least_privilege: bool,
    ) -> Result<(), RepositoryError> {
        self.check_capabilities(require_least_privilege, true, false)
            .await
    }

    /// Verify the exporter API and append-only chain. The writer role does not
    /// receive claim/ack/health EXECUTEs, so it cannot use this preflight.
    pub async fn check_exporter_available(&self) -> Result<(), RepositoryError> {
        self.check_exporter_available_with_policy(true).await
    }

    pub async fn check_exporter_available_with_policy(
        &self,
        require_least_privilege: bool,
    ) -> Result<(), RepositoryError> {
        self.check_capabilities(require_least_privilege, false, true)
            .await
    }

    async fn check_capabilities(
        &self,
        require_least_privilege: bool,
        require_append: bool,
        require_exporter: bool,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let privileges = sql_query(
            "SELECT policy_satisfied \
             FROM public.nazo_security_audit_privilege_preflight($1, $2, $3)",
        )
        .bind::<diesel::sql_types::Bool, _>(require_least_privilege)
        .bind::<diesel::sql_types::Bool, _>(require_append)
        .bind::<diesel::sql_types::Bool, _>(require_exporter)
        .get_result::<AuditPrivilegePreflightRow>(&mut connection)
        .await
        .map_err(map_error)?;
        if !privileges.policy_satisfied {
            return Err(RepositoryError::Consistency(
                "security audit privilege preflight failed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Return a valid chain head for a writer-side fail-closed check. The
    /// SECURITY DEFINER function returns no row when the persisted head does
    /// not match the immutable ledger.
    pub async fn anchor_freshness(&self) -> Result<SecurityAuditAnchorFreshness, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query(
            "SELECT last_sequence AS head_sequence, last_hash AS head_hash, checked_at \
             FROM public.nazo_security_audit_anchor_freshness()",
        )
        .get_result::<SecurityAuditAnchorFreshnessRow>(&mut connection)
        .await
        .map(Into::into)
        .map_err(map_error)
    }

    /// Return the exporter checkpoint and durable backlog without granting the
    /// exporter direct SELECT/UPDATE privileges on any audit table.
    pub async fn anchor_health(&self) -> Result<SecurityAuditAnchorHealth, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query(
            "SELECT last_sequence AS head_sequence, last_hash AS head_hash, \
                    pending_count, oldest_pending_occurred_at, \
                    last_exported_sequence, last_exported_hash, \
                    last_exported_occurred_at, last_exported_at \
             FROM public.nazo_security_audit_anchor_health() \
             WHERE chain_valid",
        )
        .get_result::<SecurityAuditAnchorHealthRow>(&mut connection)
        .await
        .map(Into::into)
        .map_err(map_error)
    }

    /// Append one event and its exporter outbox entry in one transaction.
    ///
    /// The chain head is locked through a SECURITY DEFINER function. The
    /// append function re-checks the locked head and performs all table writes
    /// as its migration-owner definer, while the caller receives no direct
    /// table INSERT/UPDATE privilege.
    pub async fn append(
        &self,
        event: SecurityAuditEvent,
    ) -> Result<SecurityAuditReceipt, RepositoryError> {
        validate_event(&event)?;
        let payload_bytes = serde_json::to_vec(&event.payload).map_err(|error| {
            RepositoryError::Unexpected(format!("invalid audit payload: {error}"))
        })?;
        if payload_bytes.len() > MAX_SECURITY_AUDIT_PAYLOAD_BYTES {
            return Err(RepositoryError::Unexpected(format!(
                "audit payload exceeds {MAX_SECURITY_AUDIT_PAYLOAD_BYTES} bytes"
            )));
        }

        let mut connection = self.connection().await?;
        connection
            .transaction::<SecurityAuditReceipt, diesel::result::Error, _>(async |connection| {
                let canonical_payload = sql_query("SELECT $1::jsonb::text AS payload_canonical")
                    .bind::<diesel::sql_types::Jsonb, _>(&event.payload)
                    .get_result::<CanonicalAuditPayloadRow>(connection)
                    .await?;
                let state = sql_query(
                    "SELECT last_sequence, last_hash \
                     FROM public.nazo_security_audit_chain_head_for_update()",
                )
                .get_result::<ChainStateRow>(connection)
                .await?;
                if state.last_hash.len() != 32 {
                    return Err(invariant_error(
                        "security audit chain state hash must be exactly 32 bytes",
                    ));
                }
                let sequence = state
                    .last_sequence
                    .checked_add(1)
                    .ok_or_else(|| invariant_error("security audit sequence overflow"))?;
                let event_hash = hash_event(
                    sequence,
                    &state.last_hash,
                    &event,
                    canonical_payload.payload_canonical.as_bytes(),
                );

                let append = sql_query(
                    "SELECT event_id, sequence, event_hash \
                     FROM public.nazo_append_security_audit_event(\
                         $1, $2, $3, $4, $5, $6, $7)",
                )
                .bind::<diesel::sql_types::Uuid, _>(event.event_id)
                .bind::<diesel::sql_types::Text, _>(&event.event_type)
                .bind::<diesel::sql_types::Text, _>(&event.event_category)
                .bind::<diesel::sql_types::Jsonb, _>(&event.payload)
                .bind::<diesel::sql_types::Timestamptz, _>(event.occurred_at)
                .bind::<diesel::sql_types::Binary, _>(state.last_hash)
                .bind::<diesel::sql_types::Binary, _>(event_hash.to_vec())
                .get_result::<SecurityAuditAppendRow>(connection)
                .await?;
                let returned_hash: [u8; 32] = append
                    .event_hash
                    .try_into()
                    .map_err(|_| invariant_error("security audit append returned invalid hash"))?;
                let fresh_receipt = append.sequence == sequence && returned_hash == event_hash;
                let idempotent_receipt =
                    append.sequence > 0 && append.sequence <= state.last_sequence;
                if append.event_id != event.event_id || (!fresh_receipt && !idempotent_receipt) {
                    return Err(invariant_error(
                        "security audit append returned an unexpected receipt",
                    ));
                }

                Ok(SecurityAuditReceipt {
                    event_id: append.event_id,
                    sequence: append.sequence,
                    event_hash: returned_hash,
                })
            })
            .await
            .map_err(map_error)
    }

    /// Claim durable events for an external exporter. The event body is read
    /// from the immutable ledger while delivery state is advanced in the
    /// mutable outbox row by the exporter-only SECURITY DEFINER function.
    pub async fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> Result<Vec<SecurityAuditOutboxDelivery>, RepositoryError> {
        if !(1..=256).contains(&limit) || !(1..=3_600).contains(&lock_timeout_seconds) {
            return Err(RepositoryError::Unexpected(
                "audit outbox claim limit or lock timeout is outside its safe bound".to_owned(),
            ));
        }
        let mut connection = self.connection().await?;
        sql_query(
            "SELECT event_id, attempts, sequence, event_type, event_category, \
                    payload, occurred_at, previous_hash, event_hash \
             FROM public.nazo_claim_security_audit_events($1, $2)",
        )
        .bind::<diesel::sql_types::BigInt, _>(limit)
        .bind::<diesel::sql_types::Integer, _>(lock_timeout_seconds)
        .load::<SecurityAuditOutboxRow>(&mut connection)
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(map_error)
    }

    pub async fn mark_exported(
        &self,
        event_id: Uuid,
        expected_attempts: i32,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let result = sql_query("SELECT public.nazo_ack_security_audit_event($1, $2) AS changed")
            .bind::<diesel::sql_types::Uuid, _>(event_id)
            .bind::<diesel::sql_types::Integer, _>(expected_attempts)
            .get_result::<AuditMutationRow>(&mut connection)
            .await
            .map_err(map_error)?;
        require_current_outbox_claim(result.changed)
    }

    pub async fn reschedule(
        &self,
        event_id: Uuid,
        expected_attempts: i32,
        available_at: DateTime<Utc>,
        last_error: &str,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let result = sql_query(
            "SELECT public.nazo_reschedule_security_audit_event($1, $2, $3, $4) AS changed",
        )
        .bind::<diesel::sql_types::Uuid, _>(event_id)
        .bind::<diesel::sql_types::Integer, _>(expected_attempts)
        .bind::<diesel::sql_types::Timestamptz, _>(available_at)
        .bind::<diesel::sql_types::Text, _>(last_error)
        .get_result::<AuditMutationRow>(&mut connection)
        .await
        .map_err(map_error)?;
        require_current_outbox_claim(result.changed)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

#[derive(QueryableByName)]
struct ChainStateRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    last_sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    last_hash: Vec<u8>,
}

#[derive(QueryableByName)]
struct SecurityAuditAppendRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    event_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    event_hash: Vec<u8>,
}

#[derive(QueryableByName)]
struct CanonicalAuditPayloadRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    payload_canonical: String,
}

#[derive(QueryableByName)]
struct AuditPrivilegePreflightRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    policy_satisfied: bool,
}

#[derive(QueryableByName)]
struct SecurityAuditAnchorFreshnessRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    head_sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    head_hash: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    checked_at: DateTime<Utc>,
}

impl From<SecurityAuditAnchorFreshnessRow> for SecurityAuditAnchorFreshness {
    fn from(row: SecurityAuditAnchorFreshnessRow) -> Self {
        Self {
            head_sequence: row.head_sequence,
            head_hash: row.head_hash,
            checked_at: row.checked_at,
        }
    }
}

#[derive(QueryableByName)]
struct SecurityAuditAnchorHealthRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    head_sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    head_hash: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pending_count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    oldest_pending_occurred_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    last_exported_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
    last_exported_hash: Option<Vec<u8>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_exported_occurred_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_exported_at: Option<DateTime<Utc>>,
}

impl From<SecurityAuditAnchorHealthRow> for SecurityAuditAnchorHealth {
    fn from(row: SecurityAuditAnchorHealthRow) -> Self {
        Self {
            head_sequence: row.head_sequence,
            head_hash: row.head_hash,
            pending_count: row.pending_count,
            oldest_pending_occurred_at: row.oldest_pending_occurred_at,
            last_exported_sequence: row.last_exported_sequence,
            last_exported_hash: row.last_exported_hash,
            last_exported_occurred_at: row.last_exported_occurred_at,
            last_exported_at: row.last_exported_at,
        }
    }
}

#[derive(QueryableByName)]
struct AuditMutationRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    changed: bool,
}

#[derive(QueryableByName)]
struct SecurityAuditOutboxRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    event_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    attempts: i32,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_type: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_category: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    payload: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    occurred_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    previous_hash: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    event_hash: Vec<u8>,
}

impl From<SecurityAuditOutboxRow> for SecurityAuditOutboxDelivery {
    fn from(row: SecurityAuditOutboxRow) -> Self {
        Self {
            event_id: row.event_id,
            sequence: row.sequence,
            event_type: row.event_type,
            event_category: row.event_category,
            payload: row.payload,
            occurred_at: row.occurred_at,
            previous_hash: row.previous_hash,
            event_hash: row.event_hash,
            attempts: row.attempts,
        }
    }
}

fn validate_event(event: &SecurityAuditEvent) -> Result<(), RepositoryError> {
    if event.event_id.is_nil()
        || !valid_identifier(&event.event_type)
        || !valid_identifier(&event.event_category)
        || !event.payload.is_object()
    {
        return Err(RepositoryError::Unexpected(
            "security audit event has invalid identity or payload".to_owned(),
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
}

fn hash_event(
    sequence: i64,
    previous_hash: &[u8],
    event: &SecurityAuditEvent,
    payload_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nazo.audit.v1\0");
    hasher.update(&sequence.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(event.event_id.as_bytes());
    update_len_prefixed(&mut hasher, event.event_type.as_bytes());
    update_len_prefixed(&mut hasher, event.event_category.as_bytes());
    hasher.update(&event.occurred_at.timestamp_micros().to_be_bytes());
    update_len_prefixed(&mut hasher, payload_bytes);
    *hasher.finalize().as_bytes()
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn invariant_error(message: &'static str) -> diesel::result::Error {
    diesel::result::Error::SerializationError(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    )))
}

fn require_current_outbox_claim(changed: bool) -> Result<(), RepositoryError> {
    if changed {
        Ok(())
    } else {
        Err(RepositoryError::Consistency(
            "security audit outbox claim is stale or already terminal".to_owned(),
        ))
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/audit_ledger.rs"]
mod tests;
