//! The frozen cross-process control-plane contract (E01/E02).
//!
//! One [`ControlOperation`] per top-level NazoAuth application-level
//! operation, signed once with the instance Controller Key; one plain
//! [`ControlResult`] journal entry as the durable outcome record.  There are
//! deliberately no receipt chains, capability suites, or multi-envelope
//! patterns here: replay protection, response-loss recovery, and crash
//! recovery are owned by `operation_id` + request hash + the server-side
//! operation journal (E03), not by additional signed artifacts.
//!
//! # Canonical bytes (E02)
//!
//! The canonical encoding of a value is: serialize to JSON, recursively
//! rewrite every object so its members are sorted by UTF-8 key order, then
//! emit compact UTF-8 JSON (no whitespace, minimal number/escape forms).
//!
//! * `request_hash` = lowercase hexadecimal SHA-256 of exactly those canonical
//!   payload bytes.  It is an equality/idempotency token only; it never carries
//!   identity.
//! * Signatures are Ed25519 over `<base64url(header)>.<base64url(canonical
//!   payload)>` with a fixed protected header (`alg`, derived `kid`, fixed
//!   `typ`).  Callers cannot choose algorithm or media type.
//! * Signature and idempotency therefore share one canonical payload
//!   definition while remaining separate responsibilities.  Verifiers reject
//!   any payload that is not canonically encoded.
//!
//! The controller key id (`kid`) is `base64url(SHA-256(raw public key
//! bytes))`, unpadded (43 characters); see [`controller_key_id`].

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::verification::{validate_file_identifier, validate_identifier};
use crate::wire::{FixedAlgorithm, ProtectedHeader};
use crate::{MAX_COMPACT_JWS_BYTES, ProtocolError};

/// Wire schema tag for [`ControlOperation`].
pub const CONTROL_OPERATION_SCHEMA: u32 = 1;
/// Wire schema tag for [`ControlResult`].
pub const CONTROL_RESULT_SCHEMA: u32 = 1;
/// Fixed JWS media type for signed control operations.  Not caller-chosen.
pub const CONTROL_OPERATION_JWS_TYPE: &str = "nazoauth-control-operation+jwt";
/// C1 admission window: a control operation must be admitted within this many
/// seconds of issuance.  Server-enforced at admission; after acceptance the
/// operation journal owns authorization and later key expiry does not retract
/// it.
pub const MAX_CONTROL_OPERATION_LIFETIME_SECONDS: i64 = 60;
/// Maximum canonical [`ControlOperation`] payload size in bytes.
pub const MAX_CONTROL_OPERATION_BYTES: usize = 64 * 1024;
/// Maximum serialized [`ControlResult`] size in bytes.
pub const MAX_CONTROL_RESULT_BYTES: usize = 64 * 1024;
/// Unpadded base64url length of a 32-byte SHA-256 digest.
const CONTROLLER_KID_LENGTH: usize = 43;

/// The single signed envelope for one top-level application-level operation.
///
/// `operation_id` is a UUIDv7 and doubles as the journal idempotency key:
/// same id + same request hash resumes or returns the recorded outcome; same
/// id + different request hash is a permanent conflict (E03).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlOperation {
    pub schema: u32,
    /// UUIDv7 (RFC 9562), canonical lowercase form; also the journal jti.
    pub operation_id: String,
    /// Issuing controller key id ([`controller_key_id`] derivation).
    pub kid: String,
    /// Audience binding: exactly one target deployment.
    pub deployment_id: String,
    pub iat: i64,
    pub nbf: i64,
    /// Admission deadline; `exp - iat` must not exceed
    /// [`MAX_CONTROL_OPERATION_LIFETIME_SECONDS`].
    pub exp: i64,
    /// Build identity of the artifact the operation was authorized for (J1):
    /// the executing binary must equal these fields at admission.
    pub embedded: ControlBuildIdentity,
    /// Opaque secret-revision fencing token (D2): rejected unless it equals
    /// the deployment's current revision marker via constant-time comparison.
    pub opaque_revision: String,
    /// Closed operation set with typed payloads.  Unknown operations are a
    /// protocol change and must be rejected by older consumers.
    pub operation: ControlOperationPayload,
}

/// Embedded build identity carried by every control operation (J1
/// semantics).  The equality check against the executing binary belongs to
/// the server-side verifier boundary; this type only freezes the wire shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBuildIdentity {
    pub product: String,
    pub version: String,
    pub commit: String,
}

/// Closed operation names seeded from E05's naming, each carrying its typed
/// payload inline.  No arbitrary command/shell passthrough exists.
///
/// Deserialization is deliberately hand-written instead of derived: serde's
/// `deny_unknown_fields` is silently ignored for internally tagged enums with
/// unit variants, so a derived implementation would accept (and drop) unknown
/// members such as `{"name":"migrate-apply","argv":[...]}`.  The manual
/// implementation below rejects every member outside the variant's closed
/// field set, keeping the wire shape exactly as strict as every other type
/// in this contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "name", rename_all = "kebab-case")]
pub enum ControlOperationPayload {
    MigrateApply,
    KeysList,
    KeysValidate,
    KeysGenerateLocal {
        alg: String,
        purposes: Vec<String>,
    },
    KeysRegisterExternal {
        kid: String,
        alg: String,
        key_ref: String,
        public_jwk_sha256: String,
    },
}

impl<'de> Deserialize<'de> for ControlOperationPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut members = match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Object(members) => members,
            _ => return Err(serde::de::Error::custom("operation must be a JSON object")),
        };
        let name = take_string_member(&mut members, "name").map_err(serde::de::Error::custom)?;
        let payload = match name.as_str() {
            "migrate-apply" => ControlOperationPayload::MigrateApply,
            "keys-list" => ControlOperationPayload::KeysList,
            "keys-validate" => ControlOperationPayload::KeysValidate,
            "keys-generate-local" => {
                let alg =
                    take_string_member(&mut members, "alg").map_err(serde::de::Error::custom)?;
                let purposes = take_string_vec_member(&mut members, "purposes")
                    .map_err(serde::de::Error::custom)?;
                ControlOperationPayload::KeysGenerateLocal { alg, purposes }
            }
            "keys-register-external" => {
                let kid =
                    take_string_member(&mut members, "kid").map_err(serde::de::Error::custom)?;
                let alg =
                    take_string_member(&mut members, "alg").map_err(serde::de::Error::custom)?;
                let key_ref = take_string_member(&mut members, "key_ref")
                    .map_err(serde::de::Error::custom)?;
                let public_jwk_sha256 = take_string_member(&mut members, "public_jwk_sha256")
                    .map_err(serde::de::Error::custom)?;
                ControlOperationPayload::KeysRegisterExternal {
                    kid,
                    alg,
                    key_ref,
                    public_jwk_sha256,
                }
            }
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown operation '{other}'"
                )));
            }
        };
        if let Some(member) = members.keys().next() {
            return Err(serde::de::Error::custom(format!(
                "unknown operation field '{member}'"
            )));
        }
        Ok(payload)
    }
}

fn take_string_member(
    members: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
) -> Result<String, String> {
    match members.remove(key) {
        Some(serde_json::Value::String(text)) => Ok(text),
        Some(_) => Err(format!("operation field '{key}' must be a string")),
        None => Err(format!("operation requires field '{key}'")),
    }
}

fn take_string_vec_member(
    members: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
) -> Result<Vec<String>, String> {
    match members.remove(key) {
        Some(serde_json::Value::Array(values)) => {
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    serde_json::Value::String(text) => parsed.push(text),
                    _ => return Err(format!("operation field '{key}' must contain strings")),
                }
            }
            Ok(parsed)
        }
        _ => Err(format!(
            "operation field '{key}' must be an array of strings"
        )),
    }
}

/// Plain durable journal entry for one operation outcome (E01 §2 / 05 §8).
///
/// This is not a signed receipt chain: the journal is the authority, ctl
/// recovers lost responses by re-reading it through a resumed operation, and
/// no second long-term identity is introduced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResult {
    pub schema: u32,
    /// Echo of the accepted operation's id.
    pub operation_id: String,
    /// Echo of [`control_operation_request_hash`] of the accepted operation;
    /// binds the result to exactly one canonical request (D5 concept, no
    /// signing key involved).
    pub request_hash: String,
    pub outcome: ControlOutcome,
    /// Stable failure taxonomy; present if and only if `outcome` is
    /// [`ControlOutcome::Failed`].
    pub error: Option<ControlErrorCode>,
    /// Journal acceptance time (authorization snapshot anchor, E03 §5).
    pub accepted_at: i64,
    /// Terminal completion time; required exactly when the outcome is
    /// terminal, absent while in progress.
    pub completed_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOutcome {
    Succeeded,
    Failed,
    InProgress,
}

/// Closed, stable error taxonomy spelled exactly like the CLI stable error
/// codes (09 §5).  Adding a code is a protocol change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlErrorCode {
    /// Same `operation_id` presented with a different canonical request hash.
    OperationIdConflict,
    /// Unknown, revoked, or otherwise untrusted controller kid.
    ControllerKeyUntrusted,
    /// Controller key no longer valid at first admission (does not affect
    /// already-accepted operations resumed from the journal).
    ControllerKeyExpired,
    /// Embedded build identity does not equal the executing binary (J1) or
    /// the artifact binding does not match the runtime.
    TargetIdentityMismatch,
    /// Opaque config/revision fencing failed (D2 family).
    ConfigRevisionMismatch,
    /// The operation was admitted and executed but the business action
    /// failed inside NazoAuth.
    ExecutionFailed,
}

/// Validate envelope structure without evaluating the admission clock.
pub fn validate_control_operation(operation: &ControlOperation) -> Result<(), ProtocolError> {
    if operation.schema != CONTROL_OPERATION_SCHEMA {
        return Err(ProtocolError::Policy(
            "unsupported control operation schema",
        ));
    }
    validate_uuidv7(&operation.operation_id)?;
    validate_controller_kid(&operation.kid)?;
    validate_file_identifier(&operation.deployment_id)?;
    validate_window_bounds(operation.iat, operation.nbf, operation.exp)?;
    let ControlBuildIdentity {
        product,
        version,
        commit,
    } = &operation.embedded;
    for value in [product, version, commit] {
        validate_identifier(value)?;
    }
    validate_identifier(&operation.opaque_revision)?;
    validate_control_payload(&operation.operation)
}

/// C1 short-window admission check, server-enforced.  `now` must lie in
/// `[nbf, exp]`.
pub fn verify_control_operation_admission(
    operation: &ControlOperation,
    now: i64,
) -> Result<(), ProtocolError> {
    if now < operation.nbf || now > operation.exp {
        return Err(ProtocolError::Policy(
            "control operation is outside its validity window",
        ));
    }
    Ok(())
}

fn validate_window_bounds(iat: i64, nbf: i64, exp: i64) -> Result<(), ProtocolError> {
    if iat <= 0
        || nbf <= 0
        || exp <= 0
        || exp < iat
        || exp - iat > MAX_CONTROL_OPERATION_LIFETIME_SECONDS
    {
        return Err(ProtocolError::Policy(
            "control operation lifetime exceeds the admission window",
        ));
    }
    if nbf < iat {
        return Err(ProtocolError::Policy(
            "control operation validity starts before issuance",
        ));
    }
    Ok(())
}

fn validate_control_payload(payload: &ControlOperationPayload) -> Result<(), ProtocolError> {
    match payload {
        ControlOperationPayload::MigrateApply
        | ControlOperationPayload::KeysList
        | ControlOperationPayload::KeysValidate => {}
        ControlOperationPayload::KeysGenerateLocal { alg, purposes } => {
            validate_identifier(alg)?;
            if purposes.is_empty() || purposes.len() > 8 {
                return Err(ProtocolError::Policy("invalid signing purposes"));
            }
            for purpose in purposes {
                validate_identifier(purpose)?;
            }
        }
        ControlOperationPayload::KeysRegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk_sha256,
        } => {
            validate_file_identifier(kid)?;
            validate_identifier(alg)?;
            validate_lower_hex_digest(public_jwk_sha256)?;
            if key_ref.is_empty()
                || key_ref.len() > 512
                || ["//", "@", "?", "#", "="]
                    .iter()
                    .any(|forbidden| key_ref.contains(forbidden))
                || !key_ref.chars().all(|character| {
                    character.is_ascii_alphanumeric() || ".:_/-+".contains(character)
                })
            {
                return Err(ProtocolError::Policy(
                    "external key reference must be a non-secret provider locator",
                ));
            }
        }
    }
    Ok(())
}

/// Canonical lowercase UUIDv7 enforcement (RFC 9562 version and variant
/// nibbles included).  No UUID dependency is pulled into this crate.
fn validate_uuidv7(value: &str) -> Result<(), ProtocolError> {
    let bytes = value.as_bytes();
    let hex = |byte: &u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte);
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                hex(byte)
            }
        })
    {
        return Err(ProtocolError::Policy(
            "operation_id is not a canonical UUID",
        ));
    }
    if bytes[14] != b'7' {
        return Err(ProtocolError::Policy("operation_id must be a UUIDv7"));
    }
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return Err(ProtocolError::Policy(
            "operation_id must use the RFC 9562 variant",
        ));
    }
    Ok(())
}

fn validate_controller_kid(kid: &str) -> Result<(), ProtocolError> {
    if kid.len() != CONTROLLER_KID_LENGTH
        || !kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolError::Policy(
            "controller kid must be unpadded base64url SHA-256 of the public key",
        ));
    }
    Ok(())
}

fn validate_lower_hex_digest(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(ProtocolError::Policy("invalid digest"));
    }
    Ok(())
}

/// Derive the controller key id per E02: `base64url(SHA-256(raw public key
/// bytes))`, unpadded.
pub fn controller_key_id(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.to_bytes()))
}

/// Canonical bytes of a control operation: sorted-key compact UTF-8 JSON
/// (see the module docs for the exact algorithm), bounded by
/// [`MAX_CONTROL_OPERATION_BYTES`].  Pure serialization; validation is
/// separate so verifiers can canonicalize before or after policy checks.
pub fn canonical_control_operation_bytes(
    operation: &ControlOperation,
) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::to_value(operation).map_err(|_| ProtocolError::Json)?;
    let bytes =
        serde_json::to_vec(&canonicalize_json_value(value)).map_err(|_| ProtocolError::Json)?;
    if bytes.len() > MAX_CONTROL_OPERATION_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes)
}

/// Single canonical-hash API (E02): validates the operation, serializes it
/// canonically, and returns the lowercase hexadecimal SHA-256 of those
/// bytes.  Pretty JSON, map ordering, and escape spelling never reach the
/// digest.
pub fn control_operation_request_hash(
    operation: &ControlOperation,
) -> Result<String, ProtocolError> {
    validate_control_operation(operation)?;
    let bytes = canonical_control_operation_bytes(operation)?;
    Ok(lower_hex_sha256(&bytes))
}

/// Recursively sort object members by UTF-8 key order so two encodings of
/// the same logical value always produce identical canonical bytes.
pub(crate) fn canonicalize_json_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        serde_json::Value::Object(members) => {
            let sorted: BTreeMap<String, serde_json::Value> = members
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json_value(value)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

/// Sign one control operation with the instance Controller Key.
///
/// The signer's derived kid must match `operation.kid`; the compact JWS uses
/// the fixed protected header and the canonical payload bytes.
pub fn sign_control_operation(
    operation: &ControlOperation,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_control_operation(operation)?;
    let kid = controller_key_id(&key.verifying_key());
    if operation.kid != kid {
        return Err(ProtocolError::Policy(
            "controller kid does not match signer",
        ));
    }
    let protected = encode_protected_header(&operation.kid)?;
    let payload = URL_SAFE_NO_PAD.encode(canonical_control_operation_bytes(operation)?);
    let signing_input = format!("{protected}.{payload}");
    let signature = key.sign(signing_input.as_bytes());
    let compact = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(compact)
}

/// Verify signature, canonical encoding, envelope policy, and header/key
/// binding without the admission clock.  Returns the decoded operation.
pub fn verify_control_operation_signature(
    compact: &str,
    expected_kid: &str,
    key: &VerifyingKey,
) -> Result<ControlOperation, ProtocolError> {
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    validate_controller_kid(expected_kid).map_err(|_| ProtocolError::Header)?;
    let mut segments = compact.split('.');
    let (protected, payload, signature) = match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some(protected), Some(payload), Some(signature), None)
            if !protected.is_empty() && !payload.is_empty() && !signature.is_empty() =>
        {
            (protected, payload, signature)
        }
        _ => return Err(ProtocolError::SegmentCount),
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(protected)
        .map_err(|_| ProtocolError::Base64)?;
    let header: ProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| ProtocolError::Header)?;
    if header.alg != FixedAlgorithm::EdDSA
        || header.typ != CONTROL_OPERATION_JWS_TYPE
        || header.kid != expected_kid
    {
        return Err(ProtocolError::Header);
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ProtocolError::Base64)?;
    let operation: ControlOperation =
        serde_json::from_slice(&payload_bytes).map_err(|_| ProtocolError::Json)?;
    if operation.kid != expected_kid {
        return Err(ProtocolError::Policy(
            "envelope kid does not match the controller key id claim",
        ));
    }
    validate_control_operation(&operation)?;
    // E02: there is exactly one encoding semantics.  A differently encoded
    // but logically equal payload would still verify cryptographically, so
    // the canonical form is enforced explicitly and in constant time.
    let canonical = canonical_control_operation_bytes(&operation)?;
    if !constant_time_eq(&payload_bytes, &canonical) {
        return Err(ProtocolError::Policy(
            "control operation payload is not canonically encoded",
        ));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ProtocolError::Base64)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ProtocolError::Signature)?;
    key.verify(format!("{protected}.{payload}").as_bytes(), &signature)
        .map_err(|_| ProtocolError::Signature)?;
    Ok(operation)
}

/// Full verifier entry point: signature plus C1 admission at `now`.
pub fn verify_control_operation(
    compact: &str,
    expected_kid: &str,
    key: &VerifyingKey,
    now: i64,
) -> Result<ControlOperation, ProtocolError> {
    let operation = verify_control_operation_signature(compact, expected_kid, key)?;
    verify_control_operation_admission(&operation, now)?;
    Ok(operation)
}

/// Constant-time byte-slice equality for secret-adjacent values (opaque
/// revision tokens, request-hash echoes).  Length differences return false
/// immediately; lengths themselves are public metadata.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// D2 fencing consumption: true only when the envelope's opaque revision
/// token equals the deployment's current secret-revision marker value,
/// compared in constant time.
pub fn opaque_revision_matches(operation: &ControlOperation, current_revision: &[u8]) -> bool {
    constant_time_eq(operation.opaque_revision.as_bytes(), current_revision)
}

/// Validate and serialize a [`ControlResult`] for the journal or the
/// one-shot stdout channel.  Plain deterministic compact JSON; results are
/// never signed or hashed.
pub fn encode_control_result(result: &ControlResult) -> Result<Vec<u8>, ProtocolError> {
    validate_control_result(result)?;
    let bytes = serde_json::to_vec(result).map_err(|_| ProtocolError::Json)?;
    if bytes.len() > MAX_CONTROL_RESULT_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes)
}

/// Decode and validate a [`ControlResult`] received from a one-shot process
/// or read back from the journal.
pub fn decode_control_result(bytes: &[u8]) -> Result<ControlResult, ProtocolError> {
    if bytes.len() > MAX_CONTROL_RESULT_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let result: ControlResult = serde_json::from_slice(bytes).map_err(|_| ProtocolError::Json)?;
    validate_control_result(&result)?;
    Ok(result)
}

/// Validate journal-entry invariants: error presence matches the outcome and
/// timestamps are ordered.
pub fn validate_control_result(result: &ControlResult) -> Result<(), ProtocolError> {
    if result.schema != CONTROL_RESULT_SCHEMA {
        return Err(ProtocolError::Policy("unsupported control result schema"));
    }
    validate_uuidv7(&result.operation_id)?;
    validate_lower_hex_digest(&result.request_hash)?;
    match result.outcome {
        ControlOutcome::InProgress => {
            if result.error.is_some() {
                return Err(ProtocolError::Policy(
                    "in-progress results carry no error code",
                ));
            }
            if result.completed_at.is_some() {
                return Err(ProtocolError::Policy(
                    "in-progress results have no completion time",
                ));
            }
        }
        ControlOutcome::Succeeded | ControlOutcome::Failed => {
            if result.completed_at.is_none() {
                return Err(ProtocolError::Policy(
                    "terminal results require a completion time",
                ));
            }
            if result
                .completed_at
                .is_some_and(|completed| completed < result.accepted_at)
            {
                return Err(ProtocolError::Policy(
                    "completion precedes journal acceptance",
                ));
            }
            if result.outcome == ControlOutcome::Failed {
                if result.error.is_none() {
                    return Err(ProtocolError::Policy(
                        "failed results require an error code",
                    ));
                }
            } else if result.error.is_some() {
                return Err(ProtocolError::Policy(
                    "succeeded results carry no error code",
                ));
            }
        }
    }
    Ok(())
}

fn encode_protected_header(kid: &str) -> Result<String, ProtocolError> {
    let header = ProtectedHeader {
        alg: FixedAlgorithm::EdDSA,
        kid: kid.to_owned(),
        typ: CONTROL_OPERATION_JWS_TYPE.to_owned(),
    };
    let bytes = serde_json::to_vec(&header).map_err(|_| ProtocolError::Json)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn lower_hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
