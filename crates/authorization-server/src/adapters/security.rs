//! 密码、哈希、客户端认证和客户端 JWT 验证工具。

use super::audit::{audit_event, audit_fields};
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::TestAppState;
#[cfg(test)]
use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use crate::http::mtls::request_mtls_client_certificate_from_headers;
#[cfg(test)]
use crate::settings::Settings;
use actix_web::HttpRequest;
use actix_web::http::header;
use actix_web::http::header::{HeaderMap, HeaderValue};
use anyhow::{anyhow, bail};
use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use nazo_auth::{
    Claims, ClientAssertionVerificationInput, unverified_client_assertion_client_id,
    verify_private_key_jwt,
};
use serde_json::{Value, json};
use sha2::Digest;
use sha2::Sha256;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use uuid::Uuid;

pub(crate) mod tokens;
#[cfg(test)]
pub(crate) use tokens::decode_access_claims_with;
#[cfg(test)]
pub(crate) use tokens::{AccessTokenJwtInput, IssuedAccessToken, make_jwt};

type HmacSha256 = Hmac<Sha256>;

const ARGON2_MEMORY_COST_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY: usize = 8;
const DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS: u64 = 100;
const CLIENT_SECRET_HASH_VERSION: &str = "client-secret-v1";
pub(crate) const LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER: &str =
    "local-development-client-secret-pepper-00000001";

static PASSWORD_HASH_MAX_CONCURRENCY: AtomicUsize =
    AtomicUsize::new(DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY);
static PASSWORD_HASH_QUEUE_TIMEOUT_MS: AtomicU64 =
    AtomicU64::new(DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS);
static PASSWORD_HASH_CONCURRENCY_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static DUMMY_PASSWORD_HASH: OnceLock<Result<String, String>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordVerificationError {
    Saturated,
    WorkerFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordHashingError {
    Saturated,
    WorkerFailed,
    HashFailed,
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub(crate) fn hash_password(password: &str) -> argon2::password_hash::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(password_hasher()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

#[cfg(test)]
pub(crate) fn verify_password(password: &str, password_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(password_hash) else {
        return false;
    };
    password_hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub(crate) fn initialize_dummy_password_hash() -> anyhow::Result<()> {
    dummy_password_hash().map(drop)
}

pub(crate) fn dummy_password_hash() -> anyhow::Result<String> {
    match DUMMY_PASSWORD_HASH
        .get_or_init(|| hash_password(&random_urlsafe_token()).map_err(|error| error.to_string()))
    {
        Ok(hash) => Ok(hash.clone()),
        Err(error) => Err(anyhow!("failed to initialize dummy password hash: {error}")),
    }
}

pub(crate) fn default_password_hash_max_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .map(|cpus| (cpus / 2).max(1))
        .unwrap_or(DEFAULT_PASSWORD_HASH_MAX_CONCURRENCY)
}

pub(crate) fn default_password_hash_queue_timeout_ms() -> u64 {
    DEFAULT_PASSWORD_HASH_QUEUE_TIMEOUT_MS
}

pub(crate) fn configure_password_hash_limits(
    max_concurrency: usize,
    queue_timeout_ms: u64,
) -> anyhow::Result<()> {
    if max_concurrency == 0 {
        bail!("PASSWORD_HASH_MAX_CONCURRENCY must be positive");
    }
    if queue_timeout_ms == 0 {
        bail!("PASSWORD_HASH_QUEUE_TIMEOUT_MS must be positive");
    }
    if PASSWORD_HASH_CONCURRENCY_LIMIT.get().is_some() {
        bail!("password hash limits must be configured before password verification");
    }
    AtomicUsize::store(
        &PASSWORD_HASH_MAX_CONCURRENCY,
        max_concurrency,
        Ordering::Relaxed,
    );
    AtomicU64::store(
        &PASSWORD_HASH_QUEUE_TIMEOUT_MS,
        queue_timeout_ms,
        Ordering::Relaxed,
    );
    Ok(())
}

pub(crate) async fn verify_password_blocking_limited(
    password: String,
    password_hash: nazo_identity::PasswordHash,
) -> Result<bool, PasswordVerificationError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(_permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordVerificationError::Saturated);
    };

    tokio::task::spawn_blocking(move || password_hash.verify_password(&password))
        .await
        .map_err(|_| PasswordVerificationError::WorkerFailed)
}

pub(crate) async fn hash_password_blocking_limited(
    password: String,
) -> Result<String, PasswordHashingError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(_permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordHashingError::Saturated);
    };

    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| PasswordHashingError::WorkerFailed)?
        .map_err(|_| PasswordHashingError::HashFailed)
}

pub(crate) async fn verify_encoded_hashes_blocking_limited(
    secret: String,
    candidates: Vec<nazo_identity::ports::EncodedSecretHash>,
) -> Result<Option<usize>, PasswordVerificationError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(_permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordVerificationError::Saturated);
    };

    tokio::task::spawn_blocking(move || {
        candidates.into_iter().position(|candidate| {
            let Ok(parsed) = PasswordHash::new(candidate.as_str()) else {
                return false;
            };
            password_hasher()
                .verify_password(secret.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await
    .map_err(|_| PasswordVerificationError::WorkerFailed)
}

#[cfg(test)]
pub(crate) fn hash_client_secret(secret: &str, pepper: &str) -> String {
    let salt = random_urlsafe_token();
    client_secret_digest(secret, pepper, &salt)
}

pub(crate) fn client_secret_digest(secret: &str, pepper: &str, salt: &str) -> String {
    let mac = client_secret_mac(secret, pepper, salt);
    format!("{CLIENT_SECRET_HASH_VERSION}:{salt}:{mac}")
}

pub(crate) fn access_delivery_token(secret: &str, user_id: Uuid, request_id: Uuid) -> String {
    nazo_identity::access_delivery_token(secret, user_id, request_id)
}

fn client_secret_mac(secret: &str, pepper: &str, salt: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key");
    mac.update(salt.as_bytes());
    mac.update(b":");
    mac.update(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn password_hasher() -> Argon2<'static> {
    let params = argon2::Params::new(
        ARGON2_MEMORY_COST_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        None,
    )
    .expect("Argon2 password hash policy must be valid");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn password_hash_concurrency_limit() -> &'static Arc<Semaphore> {
    PASSWORD_HASH_CONCURRENCY_LIMIT.get_or_init(|| {
        Arc::new(Semaphore::new(AtomicUsize::load(
            &PASSWORD_HASH_MAX_CONCURRENCY,
            Ordering::Relaxed,
        )))
    })
}

fn password_hash_queue_timeout() -> Duration {
    Duration::from_millis(AtomicU64::load(
        &PASSWORD_HASH_QUEUE_TIMEOUT_MS,
        Ordering::Relaxed,
    ))
}

pub(crate) fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

pub(crate) fn access_token_tenant_id(claims: &Claims) -> Option<Uuid> {
    claims.tenant_id.parse::<Uuid>().ok()
}

pub(crate) fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

#[cfg(test)]
pub(crate) fn random_numeric_code() -> String {
    const RANGE: u32 = 1_000_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);

    loop {
        let value = u32::from_be_bytes(rand::random::<[u8; 4]>());
        if value < LIMIT {
            return format!("{:06}", value % RANGE);
        }
    }
}

pub(crate) fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) use nazo_auth::{CLIENT_ASSERTION_TYPE_JWT_BEARER, ValidatedClientAssertion};
#[cfg(test)]
pub(crate) const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];
pub(crate) const SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS: &[&str] = &["RSA-OAEP-256"];
pub(crate) const SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS: &[&str] = &["A256GCM"];

pub(crate) use nazo_auth::PresentedClientCredentials as ClientCredentials;

pub(crate) fn has_basic_authorization_scheme(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .map(HeaderValue::as_bytes)
    else {
        return false;
    };
    let start = raw
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    raw[start..end].eq_ignore_ascii_case(b"Basic")
}

#[cfg(test)]
pub(crate) fn extract_client_credentials(
    req: &HttpRequest,
    settings: &Settings,
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
    form_assertion_type: Option<&str>,
    form_assertion: Option<&str>,
) -> ClientCredentials {
    extract_client_credentials_with_trusted_proxies(
        req,
        &settings.endpoint.trusted_proxy_cidrs,
        form_client_id,
        form_secret,
        form_assertion_type,
        form_assertion,
    )
}

pub(crate) fn extract_client_credentials_with_trusted_proxies(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[crate::http::client_ip::IpCidr],
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
    form_assertion_type: Option<&str>,
    form_assertion: Option<&str>,
) -> ClientCredentials {
    let facts = nazo_http_actix::token_client_auth_transport_facts(
        req,
        nazo_http_actix::TokenClientAuthForm {
            client_id: form_client_id,
            client_secret: form_secret,
            client_assertion_type: form_assertion_type,
            client_assertion: form_assertion,
        },
    );
    let assertion_client_id = facts
        .client_assertion()
        .filter(|_| facts.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
        .and_then(unverified_client_assertion_client_id);
    let presentation = facts.presentation();
    let mtls_client_id = if !presentation.http_basic
        && !presentation.client_assertion_type
        && !presentation.client_assertion
        && form_secret.is_none()
    {
        form_client_id
            .filter(|_| {
                crate::http::client_ip::request_from_trusted_proxy_cidrs(req, trusted_proxy_cidrs)
                    && request_mtls_client_certificate_from_headers(req.headers()).is_some()
            })
            .map(str::to_owned)
    } else {
        None
    };
    facts.presented_credentials(assertion_client_id, mtls_client_id)
}

#[derive(Debug)]
pub(crate) enum ClientAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

pub(crate) fn verify_private_key_jwt_claims_for_issuer(
    issuer: &str,
    endpoint_path: &str,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    verify_private_key_jwt_claims_with_issuer(issuer, endpoint_path, client, assertion)
}

#[cfg(test)]
fn verify_private_key_jwt_claims_with_settings(
    settings: &Settings,
    req: &HttpRequest,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    verify_private_key_jwt_claims_with_issuer(
        &settings.endpoint.issuer,
        req.uri().path(),
        client,
        assertion,
    )
}

fn verify_private_key_jwt_claims_with_issuer(
    issuer: &str,
    endpoint_path: &str,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    verify_private_key_jwt(ClientAssertionVerificationInput {
        issuer,
        endpoint_path,
        client,
        assertion,
        now: Utc::now().timestamp(),
    })
    .map_err(|error| {
        log_client_assertion_rejection(endpoint_path, client, error.audit_reason());
        ClientAssertionError::Invalid
    })
}

fn log_client_assertion_rejection(endpoint_path: &str, client: &ClientRow, reason: &'static str) {
    tracing::warn!(
        target: "client_assertion",
        "client_assertion_rejected reason={} path={} client_id_hash={}",
        reason,
        endpoint_path,
        blake3_hex(&client.client_id)
    );
}

#[cfg(test)]
pub(crate) async fn consume_private_key_jwt(
    state: &TestAppState,
    client: &ClientRow,
    assertion: &ValidatedClientAssertion,
) -> Result<(), ClientAssertionError> {
    consume_private_key_jwt_with_store(
        &nazo_valkey::ReplayStore::new(&state.valkey_connection()),
        client,
        assertion,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn consume_private_key_jwt_with_store(
    replay: &nazo_valkey::ReplayStore,
    client: &ClientRow,
    assertion: &ValidatedClientAssertion,
) -> Result<(), ClientAssertionError> {
    let now = Utc::now().timestamp();
    let ttl_seconds = assertion.replay_ttl_seconds(now);
    match replay
        .consume_private_key_jwt(&client.client_id, assertion.jti(), ttl_seconds)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit_event(
                "client_assertion_replay_detected",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("jti_hash", json!(blake3_hex(assertion.jti()))),
                    ("kid", json!(assertion.kid())),
                ]),
            );
            Err(ClientAssertionError::ReplayDetected)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to store private_key_jwt jti");
            Err(ClientAssertionError::StoreUnavailable)
        }
    }
}

pub(crate) async fn consume_private_key_jwt_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: &ValidatedClientAssertion,
) -> Result<(), ClientAssertionError> {
    let now = Utc::now().timestamp();
    let ttl_seconds = assertion.replay_ttl_seconds(now);
    match service
        .consume_private_key_jwt(&client.client_id, assertion.jti(), ttl_seconds)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit_event(
                "client_assertion_replay_detected",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("jti_hash", json!(blake3_hex(assertion.jti()))),
                    ("kid", json!(assertion.kid())),
                ]),
            );
            Err(ClientAssertionError::ReplayDetected)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to store private_key_jwt jti");
            Err(ClientAssertionError::StoreUnavailable)
        }
    }
}

#[cfg(test)]
fn client_assertion_replay_key(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:client_assertion:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

#[cfg(test)]
pub(crate) fn client_jwt_algorithm_from_name(value: &str) -> Option<jsonwebtoken::Algorithm> {
    match value {
        "EdDSA" => Some(jsonwebtoken::Algorithm::EdDSA),
        "RS256" => Some(jsonwebtoken::Algorithm::RS256),
        "ES256" => Some(jsonwebtoken::Algorithm::ES256),
        "PS256" => Some(jsonwebtoken::Algorithm::PS256),
        _ => None,
    }
}

enum SupportedClientJwtAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

pub(crate) fn client_jwt_decoding_key(
    client: &ClientRow,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let keys = client.jwks.as_ref()?.get("keys")?.as_array()?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))?;
    jwt_decoding_key_from_jwk(key, alg)
}

pub(crate) fn jwt_decoding_key_from_jwk(
    key: &Value,
    alg: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let (expected_alg, supported_alg) = supported_client_jwt_algorithm(alg)?;
    if let Some(key_alg) = key.get("alg").and_then(Value::as_str)
        && key_alg != expected_alg
    {
        return None;
    }
    if key.get("d").is_some() {
        return None;
    }
    if let Some(use_) = key.get("use").and_then(Value::as_str)
        && use_ != "sig"
    {
        return None;
    }
    match supported_alg {
        SupportedClientJwtAlgorithm::EdDsa => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(x).ok()
        }
        SupportedClientJwtAlgorithm::Rsa => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n").and_then(Value::as_str)?;
            let e = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
            if modulus.len() < 256 || exponent.is_empty() {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok()
        }
        SupportedClientJwtAlgorithm::Ec => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
            let x_bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
            let y_bytes = URL_SAFE_NO_PAD.decode(y).ok()?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
    }
}

fn supported_client_jwt_algorithm(
    alg: jsonwebtoken::Algorithm,
) -> Option<(&'static str, SupportedClientJwtAlgorithm)> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some(("EdDSA", SupportedClientJwtAlgorithm::EdDsa)),
        jsonwebtoken::Algorithm::RS256 => Some(("RS256", SupportedClientJwtAlgorithm::Rsa)),
        jsonwebtoken::Algorithm::ES256 => Some(("ES256", SupportedClientJwtAlgorithm::Ec)),
        jsonwebtoken::Algorithm::PS256 => Some(("PS256", SupportedClientJwtAlgorithm::Rsa)),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/security.rs"]
mod tests;
