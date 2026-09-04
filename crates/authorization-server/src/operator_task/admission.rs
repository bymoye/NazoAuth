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
//! the D01/D02 Controller Registry persistence port. NazoAuth is the only
//! authority that answers whether this controller key is currently admitted.
//! Stage 4 falls out of the same lookup, because admission requires an
//! `active` slot with `expires_at > now`.

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use nazo_operator_protocol::{
    ControlOperation, MAX_COMPACT_JWS_BYTES, MAX_CONTROL_OPERATION_BYTES,
    validate_control_operation,
};
use nazo_persistence::{AdmittedController, ControllerRegistryPort};

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
    // deny_unknown_fields applies to the envelope and every typed operation
    // payload; unknown operations are rejected here as protocol changes rather
    // than passed through.
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

/// Typed admission failures.  Transport failures are infrastructure faults;
/// they never classify an operation outcome.
#[derive(Debug)]
pub(super) enum AdmissionError {
    Unauthorized,
    Transport(anyhow::Error),
}

/// Stage 2+4: resolve and admit the presenting controller key by deployment.
pub(super) async fn admit_controller(
    repository: &dyn ControllerRegistryPort,
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
        return decode_admitted_identity(admitted).map_err(AdmissionError::Transport);
    }
    Err(AdmissionError::Unauthorized)
}

fn decode_admitted_identity(
    admitted: AdmittedController,
) -> anyhow::Result<AdmittedControllerIdentity> {
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
