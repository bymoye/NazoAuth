//! E04 admission stages 1/2/4: strict presentation parsing and Controller
//! Registry admission.
//!
//! Stage 1 parses the presented compact JWS far enough to classify malformed
//! input *before* any authority is consulted: size bounds, three segments,
//! base64url payload, closed envelope schema (`deny_unknown_fields`
//! everywhere), and the frozen policy validators.  It deliberately does not
//! touch signatures — key material is not known yet.
//!
//! Stage 2 resolves the controller kid/public key **by deployment_id** from
//! the D01/D02 Controller Registry (PostgreSQL).  This replaces the retired
//! mounted-file `controller.pub` trust path: NazoAuth is now the only
//! authority that answers "does this controller key exist, is it revoked, has
//! it expired".  Stage 4 falls out of the same lookup, because admission
//! requires an `active` slot with `expires_at > now`; the extra registry read
//! only separates `CONTROLLER_KEY_EXPIRED` from
//! `CONTROLLER_KEY_UNTRUSTED` for the closed rejection taxonomy.

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use nazo_operator_protocol::{
    ControlOperation, MAX_COMPACT_JWS_BYTES, MAX_CONTROL_OPERATION_BYTES,
    validate_control_operation,
};
use nazo_postgres::{
    AdmittedController, ControllerRegistryRepository, ControllerSlotStatus, StoredControllerSlot,
};

/// Stage 1: bounded, strict parse of the presented operation.
///
/// The returned operation is *not* trusted: signature verification (stage 3)
/// re-derives it through [`nazo_operator_protocol::
/// verify_control_operation_signature`] and callers must use that value for
/// every later decision.  This pass only exists so malformed requests are
/// classified before a database round-trip and so the deployment/kid needed
/// for the registry lookup are available.
pub(super) fn present(compact: &str) -> anyhow::Result<ControlOperation> {
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        bail!("control operation exceeds the maximum compact JWS size");
    }
    let mut segments = compact.split('.');
    let (payload,) = match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some(protected), Some(payload), Some(signature), None)
            if !protected.is_empty() && !payload.is_empty() && !signature.is_empty() =>
        {
            (payload,)
        }
        _ => bail!("control operation must be a three-segment compact JWS"),
    };
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("control operation payload is not canonical base64url")?;
    if payload_bytes.len() > MAX_CONTROL_OPERATION_BYTES {
        bail!("control operation payload exceeds the maximum size");
    }
    // deny_unknown_fields applies to the envelope, both target variants, and
    // every typed operation payload; unknown operations are rejected here as
    // protocol changes rather than passed through.
    let operation: ControlOperation =
        serde_json::from_slice(&payload_bytes).context("control operation payload is invalid")?;
    validate_control_operation(&operation).context("control operation violates protocol policy")?;
    Ok(operation)
}

/// A controller key the registry admits right now (stage 2 + 4 output).
pub(super) struct AdmittedControllerIdentity {
    pub(super) controller_id: String,
    pub(super) kid: String,
    pub(super) verifying_key: VerifyingKey,
}

/// Closed classification of an admission refusal (E01 taxonomy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyAdmissionFailure {
    /// Active slot whose fixed server-side TTL has passed.
    Expired,
    /// Unknown kid for this deployment, or a terminally revoked slot.
    Untrusted,
}

/// Typed admission failures.  Transport failures are infrastructure faults;
/// they never classify an operation outcome.
#[derive(Debug)]
pub(super) enum AdmissionError {
    Rejected(KeyAdmissionFailure),
    Transport(anyhow::Error),
}

/// Pure stage-4 classifier for a kid that the admission lookup refused: the
/// raw stored slot (if any) decides whether it aged out of its fixed window
/// (`Expired`) or was never trusted / is terminally revoked (`Untrusted`).
/// An active slot can only fail admission by expiry, so no clock is needed
/// here — the registry already made that decision.
pub(super) fn classify_unadmitted_key(
    stored: Option<&StoredControllerSlot>,
) -> KeyAdmissionFailure {
    match stored {
        Some(slot) if slot.status == ControllerSlotStatus::Active => KeyAdmissionFailure::Expired,
        // Revoked slots are terminal and stay distinct from unknown kids only
        // in the rejection taxonomy; both refuse identically.
        _ => KeyAdmissionFailure::Untrusted,
    }
}

/// Stage 2+4: resolve and admit the presenting controller key by deployment.
pub(super) async fn admit_controller(
    repository: &ControllerRegistryRepository,
    deployment_id: &str,
    kid: &str,
    now: DateTime<Utc>,
) -> Result<AdmittedControllerIdentity, AdmissionError> {
    let admitted = repository
        .admitted_controller_by_kid(deployment_id, kid, now)
        .await
        .map_err(|error| {
            AdmissionError::Transport(
                anyhow::Error::new(error).context("controller registry admission lookup failed"),
            )
        })?;
    if let Some(admitted) = admitted {
        return build_identity(admitted).map_err(AdmissionError::Transport);
    }
    // Not admissible right now.  One more authoritative read separates "the
    // key aged out of its fixed 30-day window" from "never trusted / revoked"
    // purely for the rejection taxonomy; both refuse identically.
    let slots = repository
        .list_slots(deployment_id)
        .await
        .map_err(|error| {
            AdmissionError::Transport(
                anyhow::Error::new(error).context("controller registry history lookup failed"),
            )
        })?;
    let failure = classify_unadmitted_key(slots.iter().find(|slot| slot.kid == kid));
    Err(AdmissionError::Rejected(failure))
}

fn build_identity(admitted: AdmittedController) -> anyhow::Result<AdmittedControllerIdentity> {
    let bytes: [u8; 32] =
        admitted.public_key.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("controller registry holds an invalid public key length")
        })?;
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("controller registry holds an invalid public key"))?;
    Ok(AdmittedControllerIdentity {
        controller_id: admitted.controller_id,
        kid: admitted.kid,
        verifying_key,
    })
}

/// Refuse tenant-resource mutations before journal acceptance (E05/H07
/// boundary): the payload-less wire contract cannot drive resource work that
/// requires the provider's per-resource payloads and preparation bridge, so
/// admitting it would create guaranteed-to-fail authorizations.
pub(super) fn ensure_serviced_by_one_shot(
    operation: &nazo_operator_protocol::ControlOperationPayload,
) -> anyhow::Result<()> {
    use nazo_operator_protocol::ControlOperationPayload as Payload;
    match operation {
        Payload::TenantResourceApply { .. } | Payload::TenantResourceRevoke { .. } => {
            bail!("tenant-resource mutations are not serviced by the one-shot operator")
        }
        _ => Ok(()),
    }
}
