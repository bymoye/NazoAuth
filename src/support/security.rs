//! 密码、哈希、客户端认证和客户端 JWT 验证工具。

use super::prelude::*;
use super::{audit_event, audit_fields, request_mtls_client_certificate, valkey_set_ex_nx};
use anyhow::{anyhow, bail};
use hmac::{Hmac, KeyInit, Mac};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};

mod tokens;
pub(crate) use tokens::*;

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
    password_hash: String,
) -> Result<bool, PasswordVerificationError> {
    let acquire = password_hash_concurrency_limit().clone().acquire_owned();
    let Ok(Ok(_permit)) = timeout(password_hash_queue_timeout(), acquire).await else {
        return Err(PasswordVerificationError::Saturated);
    };

    tokio::task::spawn_blocking(move || verify_password(&password, &password_hash))
        .await
        .map_err(|_| PasswordVerificationError::WorkerFailed)
}

pub(crate) fn hash_client_secret(secret: &str, pepper: &str) -> String {
    let salt = random_urlsafe_token();
    let mac = client_secret_mac(secret, pepper, &salt);
    format!("{CLIENT_SECRET_HASH_VERSION}:{salt}:{mac}")
}

pub(crate) fn verify_client_secret(secret: &str, stored_hash: &str, pepper: &str) -> bool {
    let mut parts = stored_hash.split(':');
    let Some(version) = parts.next() else {
        return false;
    };
    let Some(salt) = parts.next() else {
        return false;
    };
    let Some(stored_mac) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || version != CLIENT_SECRET_HASH_VERSION {
        return false;
    }
    let actual_mac = client_secret_mac(secret, pepper, salt);
    constant_time_eq(actual_mac.as_bytes(), stored_mac.as_bytes())
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

pub(crate) const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CLIENT_ASSERTION_MAX_TTL_SECONDS: i64 = 300;
const CLIENT_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_CLIENT_ASSERTION_JTI_BYTES: usize = 128;
pub(crate) const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];
pub(crate) const SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS: &[&str] = &["RSA-OAEP-256"];
pub(crate) const SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS: &[&str] = &["A256GCM"];

pub(crate) struct ClientCredentials {
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion: Option<String>,
    pub(crate) method: String,
}

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

pub(crate) fn extract_client_credentials(
    req: &HttpRequest,
    settings: &Settings,
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
    form_assertion_type: Option<&str>,
    form_assertion: Option<&str>,
) -> ClientCredentials {
    let headers = req.headers();
    if form_assertion_type.is_some() || form_assertion.is_some() {
        let client_id = form_assertion
            .filter(|_| form_assertion_type == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
            .and_then(unverified_client_assertion_client_id);
        return ClientCredentials {
            client_id,
            client_secret: None,
            client_assertion: form_assertion.map(ToOwned::to_owned),
            method: "private_key_jwt".to_owned(),
        };
    }
    if let Some((id, secret)) = basic_authorization_credentials(headers)
        .and_then(|raw| STANDARD.decode(raw).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|text| {
            let (id, secret) = text.split_once(':')?;
            Some((id.to_string(), secret.to_string()))
        })
    {
        return ClientCredentials {
            client_id: Some(id),
            client_secret: Some(secret),
            client_assertion: None,
            method: "client_secret_basic".to_owned(),
        };
    }
    match form_client_id {
        Some(id) if form_secret.is_some() => ClientCredentials {
            client_id: Some(id.to_string()),
            client_secret: form_secret.map(ToOwned::to_owned),
            client_assertion: None,
            method: "client_secret_post".to_owned(),
        },
        Some(id) if request_mtls_client_certificate(req, settings).is_some() => ClientCredentials {
            client_id: Some(id.to_string()),
            client_secret: None,
            client_assertion: None,
            method: "tls_client_auth".to_owned(),
        },
        Some(id) => ClientCredentials {
            client_id: Some(id.to_string()),
            client_secret: None,
            client_assertion: None,
            method: "none".to_owned(),
        },
        None => ClientCredentials {
            client_id: None,
            client_secret: None,
            client_assertion: None,
            method: "none".to_owned(),
        },
    }
}

fn basic_authorization_credentials(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim_start();
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let credentials = parts.next()?.trim();
    (scheme.eq_ignore_ascii_case("Basic")
        && !credentials.is_empty()
        && credentials.split_whitespace().count() == 1)
        .then_some(credentials)
}

#[derive(serde::Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: String,
}

#[derive(Debug)]
pub(crate) enum ClientAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

pub(crate) struct ValidatedClientAssertion {
    jti: String,
    exp: i64,
    kid: String,
    alg: jsonwebtoken::Algorithm,
}

pub(crate) fn verify_private_key_jwt_claims(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    verify_private_key_jwt_claims_with_settings(&state.settings, req, client, assertion)
}

fn verify_private_key_jwt_claims_with_settings(
    settings: &Settings,
    req: &HttpRequest,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    let header = jsonwebtoken::decode_header(assertion).map_err(|_| {
        log_client_assertion_rejection(req, client, "decode_header");
        ClientAssertionError::Invalid
    })?;
    let kid = header.kid.ok_or_else(|| {
        log_client_assertion_rejection(req, client, "missing_kid");
        ClientAssertionError::Invalid
    })?;
    let decoding_key = client_jwt_decoding_key(client, &kid, header.alg).ok_or_else(|| {
        log_client_assertion_rejection(req, client, "key_not_found");
        ClientAssertionError::Invalid
    })?;

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[client.client_id.as_str()]);
    let token_data =
        jsonwebtoken::decode::<ClientAssertionClaims>(assertion, &decoding_key, &validation)
            .map_err(|error| {
                log_client_assertion_rejection(req, client, client_assertion_decode_reason(&error));
                ClientAssertionError::Invalid
            })?;
    let claims = token_data.claims;
    let now = Utc::now().timestamp();
    if claims.iss != client.client_id || claims.sub != client.client_id {
        log_client_assertion_rejection(req, client, "issuer_subject");
        return Err(ClientAssertionError::Invalid);
    }
    if !audience_matches(
        &claims.aud,
        &client_assertion_audiences(settings, req, client),
        client.allow_client_assertion_audience_array,
    ) {
        log_client_assertion_rejection(req, client, "audience");
        return Err(ClientAssertionError::Invalid);
    }
    if !valid_client_assertion_times(&claims, now) {
        log_client_assertion_rejection(req, client, "time");
        return Err(ClientAssertionError::Invalid);
    }
    if !valid_client_assertion_jti(&claims.jti) {
        log_client_assertion_rejection(req, client, "jti");
        return Err(ClientAssertionError::Invalid);
    }

    Ok(ValidatedClientAssertion {
        jti: claims.jti,
        exp: claims.exp,
        kid,
        alg: header.alg,
    })
}

fn log_client_assertion_rejection(req: &HttpRequest, client: &ClientRow, reason: &'static str) {
    tracing::warn!(
        target: "client_assertion",
        "client_assertion_rejected reason={} path={} client_id_hash={}",
        reason,
        req.uri().path(),
        blake3_hex(&client.client_id)
    );
}

fn client_assertion_decode_reason(error: &jsonwebtoken::errors::Error) -> &'static str {
    use jsonwebtoken::errors::ErrorKind;

    match error.kind() {
        ErrorKind::ExpiredSignature => "decode_expired",
        ErrorKind::ImmatureSignature => "decode_immature",
        ErrorKind::InvalidIssuer => "decode_issuer",
        ErrorKind::InvalidSignature => "decode_signature",
        ErrorKind::InvalidAlgorithm => "decode_algorithm",
        _ => "decode",
    }
}

pub(crate) async fn consume_private_key_jwt(
    state: &AppState,
    client: &ClientRow,
    assertion: &ValidatedClientAssertion,
) -> Result<(), ClientAssertionError> {
    let now = Utc::now().timestamp();
    let ttl_seconds = assertion.replay_ttl_seconds(now);
    let replay_key = client_assertion_replay_key(&client.client_id, &assertion.jti);
    match valkey_set_ex_nx(&state.valkey, replay_key, "1", ttl_seconds).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit_event(
                "client_assertion_replay_detected",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("jti_hash", json!(blake3_hex(&assertion.jti))),
                    ("kid", json!(assertion.kid)),
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

impl ValidatedClientAssertion {
    pub(crate) fn alg(&self) -> jsonwebtoken::Algorithm {
        self.alg
    }

    fn replay_ttl_seconds(&self, now: i64) -> u64 {
        self.exp
            .saturating_sub(now)
            .clamp(1, CLIENT_ASSERTION_MAX_TTL_SECONDS) as u64
    }
}

fn client_assertion_replay_key(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:client_assertion:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

fn unverified_client_assertion_client_id(assertion: &str) -> Option<String> {
    let claims = jsonwebtoken::dangerous::insecure_decode::<ClientAssertionClaims>(assertion)
        .ok()?
        .claims;
    (claims.iss == claims.sub && !claims.sub.trim().is_empty()).then_some(claims.sub)
}

pub(crate) fn supported_client_jwt_algorithm_name(
    alg: jsonwebtoken::Algorithm,
) -> Option<&'static str> {
    supported_client_jwt_algorithm(alg).map(|(name, _)| name)
}

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

fn client_assertion_audiences(
    settings: &Settings,
    req: &HttpRequest,
    client: &ClientRow,
) -> Vec<String> {
    client_assertion_audience_candidates(
        &settings.issuer,
        req.uri().path(),
        client.allow_client_assertion_endpoint_audience,
    )
}

fn client_assertion_audience_candidates(
    issuer: &str,
    path: &str,
    allow_endpoint_audience: bool,
) -> Vec<String> {
    if path == "/bc-authorize" && allow_endpoint_audience {
        return vec![
            issuer.to_owned(),
            format!("{issuer}/bc-authorize"),
            format!("{issuer}/token"),
        ];
    }
    if path != "/par" {
        return vec![issuer.to_owned(), format!("{issuer}{path}")];
    }
    if allow_endpoint_audience {
        return vec![
            issuer.to_owned(),
            format!("{issuer}/par"),
            format!("{issuer}/token"),
        ];
    }
    vec![issuer.to_owned()]
}

fn audience_matches(aud: &Value, expected: &[String], allow_array: bool) -> bool {
    match aud {
        Value::String(value) => expected.iter().any(|candidate| candidate == value),
        Value::Array(values) if allow_array => values
            .iter()
            .any(|value| audience_matches(value, expected, allow_array)),
        _ => false,
    }
}

fn valid_client_assertion_times(claims: &ClientAssertionClaims, now: i64) -> bool {
    if claims.exp <= now || claims.exp > now.saturating_add(CLIENT_ASSERTION_MAX_TTL_SECONDS) {
        return false;
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(CLIENT_ASSERTION_CLOCK_SKEW_SECONDS))
    {
        return false;
    }
    if claims.iat.is_some_and(|iat| {
        iat > now.saturating_add(CLIENT_ASSERTION_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(iat) > CLIENT_ASSERTION_MAX_TTL_SECONDS
    }) {
        return false;
    }
    true
}

fn valid_client_assertion_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= MAX_CLIENT_ASSERTION_JTI_BYTES
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/security.rs"]
mod tests;
