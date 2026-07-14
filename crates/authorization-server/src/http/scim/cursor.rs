use super::auth::ScimCredential;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub(super) const SCIM_CURSOR_TIMEOUT_SECONDS: i64 = 600;

const SCIM_CURSOR_VERSION: u8 = 1;
const SCIM_CURSOR_SORT: &str = "created_at,id";
const SCIM_CURSOR_KEY_LABEL: &[u8] = b"nazo-scim-cursor-aes256gcm-v1";
const SCIM_CURSOR_AAD: &[u8] = b"nazo-scim-cursor-v1";
const SCIM_CURSOR_NONCE_LEN: usize = 12;
const SCIM_CURSOR_TAG_LEN: usize = 16;
const SCIM_CURSOR_MAX_ENCODED_LEN: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(super) struct ScimCursorKey([u8; 32]);

impl ScimCursorKey {
    pub(super) fn from_client_secret_pepper(pepper: &str) -> anyhow::Result<Self> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(pepper.as_bytes())?;
        mac.update(SCIM_CURSOR_KEY_LABEL);
        Ok(Self(mac.finalize().into_bytes().into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ScimCursorPosition {
    pub(super) last_created_at: DateTime<Utc>,
    pub(super) last_id: Uuid,
}

pub(super) struct ScimCursorContext<'a> {
    pub(super) credential: &'a ScimCredential,
    pub(super) filter: Option<&'a str>,
    pub(super) count: i64,
    pub(super) last_created_at: DateTime<Utc>,
    pub(super) last_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScimCursorError {
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

pub(super) fn encode_scim_cursor(
    key: &ScimCursorKey,
    context: &ScimCursorContext<'_>,
    now: DateTime<Utc>,
) -> anyhow::Result<String> {
    let payload = ScimCursorPayload {
        v: SCIM_CURSOR_VERSION,
        tenant_id: context.credential.tenant_id,
        actor: credential_actor(context.credential),
        filter: context.filter.map(ToOwned::to_owned),
        count: context.count,
        sort: SCIM_CURSOR_SORT.to_owned(),
        last_created_at: context.last_created_at,
        last_id: context.last_id,
        issued_at: now.timestamp(),
        expires_at: now.timestamp() + SCIM_CURSOR_TIMEOUT_SECONDS,
    };
    encrypt_scim_cursor_payload(key, &payload)
}

fn encrypt_scim_cursor_payload(
    key: &ScimCursorKey,
    payload: &ScimCursorPayload,
) -> anyhow::Result<String> {
    let plaintext = serde_json::to_vec(payload)?;
    let nonce = rand::random::<[u8; SCIM_CURSOR_NONCE_LEN]>();
    let mut tag = [0u8; SCIM_CURSOR_TAG_LEN];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key.0,
        Some(&nonce),
        SCIM_CURSOR_AAD,
        &plaintext,
        &mut tag,
    )?;
    let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len() + tag.len());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    encoded.extend_from_slice(&tag);
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

pub(super) fn decode_scim_cursor(
    key: &ScimCursorKey,
    encoded: &str,
    credential: &ScimCredential,
    filter: Option<&str>,
    count: i64,
    now: DateTime<Utc>,
) -> Result<ScimCursorPosition, ScimCursorError> {
    let payload = decrypt_scim_cursor(key, encoded)?;
    if payload.v != SCIM_CURSOR_VERSION
        || payload.sort != SCIM_CURSOR_SORT
        || payload.tenant_id != credential.tenant_id
        || payload.actor != credential_actor(credential)
        || payload.filter.as_deref() != filter
        || !(0..=200).contains(&payload.count)
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

fn decrypt_scim_cursor(
    key: &ScimCursorKey,
    encoded: &str,
) -> Result<ScimCursorPayload, ScimCursorError> {
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
    let (nonce, remainder) = decoded.split_at(SCIM_CURSOR_NONCE_LEN);
    let (ciphertext, tag) = remainder.split_at(remainder.len() - SCIM_CURSOR_TAG_LEN);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key.0,
        Some(nonce),
        SCIM_CURSOR_AAD,
        ciphertext,
        tag,
    )
    .map_err(|_| ScimCursorError::Invalid)?;
    serde_json::from_slice(&plaintext).map_err(|_| ScimCursorError::Invalid)
}

fn credential_actor(credential: &ScimCredential) -> String {
    credential
        .token_id
        .map(|token_id| format!("database:{token_id}"))
        .unwrap_or_else(|| credential.source.to_owned())
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/scim/tests/cursor.rs"]
mod tests;
