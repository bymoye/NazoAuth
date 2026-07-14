use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::query::SCIM_MAX_PAGE_SIZE;

pub const SCIM_CURSOR_TIMEOUT_SECONDS: i64 = 600;
pub const SCIM_CURSOR_KEY_LABEL: &[u8] = b"nazo-scim-cursor-aes256gcm-v1";
pub const SCIM_CURSOR_AAD: &[u8] = b"nazo-scim-cursor-v1";
pub const SCIM_CURSOR_NONCE_LEN: usize = 12;
pub const SCIM_CURSOR_TAG_LEN: usize = 16;

const SCIM_CURSOR_VERSION: u8 = 1;
const SCIM_CURSOR_SORT: &str = "created_at,id";
const SCIM_CURSOR_MAX_ENCODED_LEN: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScimCursorSubject {
    pub tenant_id: Uuid,
    pub actor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScimCursorPosition {
    pub last_created_at: DateTime<Utc>,
    pub last_id: Uuid,
}

pub struct ScimCursorContext<'a> {
    pub subject: &'a ScimCursorSubject,
    pub filter: Option<&'a str>,
    pub count: i64,
    pub last_created_at: DateTime<Utc>,
    pub last_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScimCursorError {
    Invalid,
    Expired,
    InvalidCount,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScimCursorPayload {
    v: u8,
    tenant_id: Uuid,
    actor: String,
    filter: Option<String>,
    count: i64,
    sort: String,
    last_created_at: DateTime<Utc>,
    last_id: Uuid,
    issued_at: i64,
    expires_at: i64,
}

/// Builds the stable plaintext authenticated by the cursor protection adapter.
///
/// Encryption and key derivation stay outside the identity core. The current
/// AES-256-GCM adapter can therefore move without making this crate depend on
/// OpenSSL, while the claims and validation rules remain compiler-owned here.
pub fn build_scim_cursor_plaintext(
    context: &ScimCursorContext<'_>,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&ScimCursorPayload {
        v: SCIM_CURSOR_VERSION,
        tenant_id: context.subject.tenant_id,
        actor: context.subject.actor.clone(),
        filter: context.filter.map(ToOwned::to_owned),
        count: context.count,
        sort: SCIM_CURSOR_SORT.to_owned(),
        last_created_at: context.last_created_at,
        last_id: context.last_id,
        issued_at: now.timestamp(),
        expires_at: now.timestamp() + SCIM_CURSOR_TIMEOUT_SECONDS,
    })
}

#[must_use]
pub fn encode_scim_cursor_envelope(protected: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(protected)
}

pub fn decode_scim_cursor_envelope(encoded: &str) -> Result<Vec<u8>, ScimCursorError> {
    if encoded.is_empty()
        || encoded.len() > SCIM_CURSOR_MAX_ENCODED_LEN
        || encoded.contains('=')
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ScimCursorError::Invalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ScimCursorError::Invalid)?;
    if decoded.len() <= SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN {
        return Err(ScimCursorError::Invalid);
    }
    Ok(decoded)
}

pub fn decode_scim_cursor_plaintext(
    plaintext: &[u8],
    subject: &ScimCursorSubject,
    filter: Option<&str>,
    count: i64,
    now: DateTime<Utc>,
) -> Result<ScimCursorPosition, ScimCursorError> {
    let payload = serde_json::from_slice::<ScimCursorPayload>(plaintext)
        .map_err(|_| ScimCursorError::Invalid)?;
    if payload.v != SCIM_CURSOR_VERSION
        || payload.sort != SCIM_CURSOR_SORT
        || payload.tenant_id != subject.tenant_id
        || payload.actor != subject.actor
        || payload.filter.as_deref() != filter
        || !(0..=SCIM_MAX_PAGE_SIZE).contains(&payload.count)
        || payload.issued_at > now.timestamp() + 60
        || payload.expires_at <= payload.issued_at
        || payload.expires_at - payload.issued_at > SCIM_CURSOR_TIMEOUT_SECONDS
    {
        return Err(ScimCursorError::Invalid);
    }
    if payload.expires_at <= now.timestamp() {
        return Err(ScimCursorError::Expired);
    }
    if payload.count != count {
        return Err(ScimCursorError::InvalidCount);
    }
    Ok(ScimCursorPosition {
        last_created_at: payload.last_created_at,
        last_id: payload.last_id,
    })
}
