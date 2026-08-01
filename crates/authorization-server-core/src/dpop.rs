use std::{collections::BTreeMap, future::Future, pin::Pin};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use rand::random;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    AuthorizationRepositoryPort, AuthorizationResponseSignerPort, AuthorizationService,
    AuthorizationStateStorePort,
};

pub const DPOP_REPLAY_TTL_SECONDS: u64 = 300;
pub const DPOP_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_DPOP_JTI_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DpopNoncePolicy {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug)]
pub struct DpopProofRequest<'a> {
    pub proof: Option<&'a str>,
    pub method: &'a str,
    /// Exact externally visible endpoint URIs accepted for this request.
    /// Callers must omit query and fragment components.
    pub target_uris: &'a [&'a str],
    pub access_token: Option<&'a str>,
    pub expected_jkt: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpopReplayAudit {
    pub jti_hash: String,
    pub key_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DpopError {
    MissingProof,
    MalformedProof,
    InvalidProof,
    ReplayDetected(DpopReplayAudit),
    BindingMismatch,
    TokenNotBound,
    UseNonce(String),
    NonceStoreUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DpopStateStoreError;

pub type DpopStateFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DpopStateStoreError>> + Send + 'a>>;

/// Atomic short-lived state required by Authorization Server DPoP admission.
pub trait DpopStateStorePort: Send + Sync {
    /// Atomically inserts the replay marker if absent.
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool>;

    fn issue_nonce<'a>(&'a self, nonce: &'a str, ttl_seconds: u64) -> DpopStateFuture<'a, ()>;

    /// Returns whether a server-issued nonce remains inside its validity window.
    ///
    /// RFC 9449 Section 11.1 permits a nonce to be accepted more than once as
    /// long as proof `jti` values are tracked and duplicates are rejected.
    fn validate_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedDpopProof {
    pub jkt: String,
    pub jti: String,
    pub nonce: Option<String>,
    pub audit: DpopReplayAudit,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DpopProofVerifier;

#[derive(Deserialize)]
struct DpopHeader {
    alg: String,
    typ: Option<String>,
    jwk: Value,
}

#[derive(Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

impl DpopProofVerifier {
    pub fn verify(
        self,
        request: DpopProofRequest<'_>,
    ) -> Result<Option<VerifiedDpopProof>, DpopError> {
        self.verify_at(request, chrono::Utc::now().timestamp())
    }

    pub fn verify_at(
        self,
        request: DpopProofRequest<'_>,
        now: i64,
    ) -> Result<Option<VerifiedDpopProof>, DpopError> {
        verify_dpop_proof_at(request, now)
    }
}

impl<R, S, K> DpopStateStorePort for AuthorizationService<R, S, K>
where
    R: AuthorizationRepositoryPort,
    S: AuthorizationStateStorePort,
    K: AuthorizationResponseSignerPort,
{
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.consume_dpop(jkt, jti, ttl_seconds)
                .await
                .map_err(|_| DpopStateStoreError)
        })
    }

    fn issue_nonce<'a>(&'a self, nonce: &'a str, ttl_seconds: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async move {
            self.issue_dpop_nonce(nonce, ttl_seconds)
                .await
                .map_err(|_| DpopStateStoreError)
        })
    }

    fn validate_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.validate_dpop_nonce(nonce)
                .await
                .map_err(|_| DpopStateStoreError)
        })
    }
}

pub async fn validate_authorization_server_dpop<S>(
    store: &S,
    request: DpopProofRequest<'_>,
    nonce_policy: DpopNoncePolicy,
) -> Result<Option<String>, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    validate_authorization_server_dpop_at(
        store,
        request,
        nonce_policy,
        chrono::Utc::now().timestamp(),
    )
    .await
}

pub async fn validate_authorization_server_dpop_at<S>(
    store: &S,
    request: DpopProofRequest<'_>,
    nonce_policy: DpopNoncePolicy,
    now: i64,
) -> Result<Option<String>, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    let Some(verified) = DpopProofVerifier.verify_at(request, now)? else {
        return Ok(None);
    };

    // RFC 9449 Sections 8 and 9 allow a client to retry a nonce challenge by
    // adding the supplied nonce to the proof while retaining the original jti.
    // A proof that has not yet satisfied the nonce policy therefore must not
    // consume its replay marker.
    validate_nonce(store, nonce_policy, verified.nonce.as_deref()).await?;

    let replay_scope = replay_scope(&request, &verified)?;
    match store
        .consume_replay(&replay_scope, &verified.jti, DPOP_REPLAY_TTL_SECONDS)
        .await
    {
        Ok(true) => Ok(Some(verified.jkt)),
        Ok(false) => Err(DpopError::ReplayDetected(verified.audit)),
        Err(DpopStateStoreError) => Err(DpopError::InvalidProof),
    }
}

fn replay_scope(
    request: &DpopProofRequest<'_>,
    verified: &VerifiedDpopProof,
) -> Result<String, DpopError> {
    if request.access_token.is_none() {
        return Ok(verified.jkt.clone());
    }
    let target = request
        .target_uris
        .first()
        .ok_or(DpopError::InvalidProof)
        .and_then(|target| normalize_htu(target))?;
    let material = format!("{}:{target}", request.method.to_ascii_uppercase());
    Ok(format!(
        "resource:{}",
        blake3::hash(material.as_bytes()).to_hex()
    ))
}

pub async fn issue_authorization_server_dpop_nonce<S>(store: &S) -> Result<String, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    let nonce = new_dpop_nonce();
    store
        .issue_nonce(&nonce, DPOP_REPLAY_TTL_SECONDS)
        .await
        .map_err(|DpopStateStoreError| DpopError::NonceStoreUnavailable)?;
    Ok(nonce)
}

async fn validate_nonce<S>(
    store: &S,
    policy: DpopNoncePolicy,
    nonce: Option<&str>,
) -> Result<(), DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    let Some(nonce) = nonce else {
        return if policy == DpopNoncePolicy::Optional {
            Ok(())
        } else {
            Err(DpopError::UseNonce(
                issue_authorization_server_dpop_nonce(store).await?,
            ))
        };
    };
    match store.validate_nonce(nonce).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(DpopError::UseNonce(
            issue_authorization_server_dpop_nonce(store).await?,
        )),
        Err(DpopStateStoreError) => Err(DpopError::NonceStoreUnavailable),
    }
}

fn verify_dpop_proof_at(
    request: DpopProofRequest<'_>,
    now: i64,
) -> Result<Option<VerifiedDpopProof>, DpopError> {
    let Some(raw) = request.proof.filter(|proof| !proof.trim().is_empty()) else {
        return if request.expected_jkt.is_some() {
            Err(DpopError::MissingProof)
        } else {
            Ok(None)
        };
    };

    let (header, claims, signing_input, signature) = decode_proof(raw)?;
    if !header
        .typ
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("dpop+jwt"))
    {
        return Err(DpopError::InvalidProof);
    }
    let algorithm = dpop_algorithm(&header.alg).ok_or(DpopError::InvalidProof)?;
    let decoding_key = public_dpop_decoding_key(&header.jwk, algorithm)?;
    verify_signature(
        algorithm,
        &decoding_key,
        signing_input.as_bytes(),
        &signature,
    )?;

    let jkt = jwk_thumbprint(&header.jwk)?;
    if request
        .expected_jkt
        .is_some_and(|expected| !constant_time_eq(expected.as_bytes(), jkt.as_bytes()))
    {
        return Err(DpopError::BindingMismatch);
    }
    validate_claims(request, &claims, now)?;

    Ok(Some(VerifiedDpopProof {
        audit: DpopReplayAudit {
            jti_hash: blake3::hash(claims.jti.as_bytes()).to_hex().to_string(),
            key_id: header
                .jwk
                .get("kid")
                .and_then(Value::as_str)
                .map(str::to_owned),
        },
        jkt,
        jti: claims.jti,
        nonce: claims.nonce,
    }))
}

pub fn new_dpop_nonce() -> String {
    URL_SAFE_NO_PAD.encode(random::<[u8; 32]>())
}

fn validate_claims(
    request: DpopProofRequest<'_>,
    claims: &DpopClaims,
    now: i64,
) -> Result<(), DpopError> {
    let actual_htu = normalize_htu(&claims.htu)?;
    let mut htu_matches = false;
    for expected in request.target_uris {
        if actual_htu == normalize_htu(expected)? {
            htu_matches = true;
        }
    }
    if !htu_matches || !claims.htm.eq_ignore_ascii_case(request.method) {
        return Err(DpopError::InvalidProof);
    }
    if !iat_within_window(claims.iat, now) || !valid_jti(&claims.jti) {
        return Err(DpopError::InvalidProof);
    }
    if let Some(access_token) = request.access_token {
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(DpopError::InvalidProof);
        }
    }
    Ok(())
}

fn decode_proof(raw: &str) -> Result<(DpopHeader, DpopClaims, String, String), DpopError> {
    let mut parts = raw.split('.');
    let encoded_header = nonempty_segment(parts.next())?;
    let encoded_payload = nonempty_segment(parts.next())?;
    let encoded_signature = nonempty_segment(parts.next())?;
    if parts.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let header = serde_json::from_slice::<DpopHeader>(
        &URL_SAFE_NO_PAD
            .decode(encoded_header)
            .map_err(|_| DpopError::MalformedProof)?,
    )
    .map_err(|_| DpopError::MalformedProof)?;
    let claims = serde_json::from_slice::<DpopClaims>(
        &URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .map_err(|_| DpopError::MalformedProof)?,
    )
    .map_err(|_| DpopError::MalformedProof)?;
    URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| DpopError::MalformedProof)?;
    Ok((
        header,
        claims,
        format!("{encoded_header}.{encoded_payload}"),
        encoded_signature.to_owned(),
    ))
}

fn nonempty_segment(segment: Option<&str>) -> Result<&str, DpopError> {
    segment
        .filter(|segment| !segment.is_empty())
        .ok_or(DpopError::MalformedProof)
}

fn dpop_algorithm(value: &str) -> Option<Algorithm> {
    match value {
        "EdDSA" => Some(Algorithm::EdDSA),
        "ES256" => Some(Algorithm::ES256),
        _ => None,
    }
}

fn public_dpop_decoding_key(key: &Value, algorithm: Algorithm) -> Result<DecodingKey, DpopError> {
    let expected_alg = match algorithm {
        Algorithm::EdDSA => "EdDSA",
        Algorithm::ES256 => "ES256",
        _ => return Err(DpopError::InvalidProof),
    };
    if key
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|value| value != expected_alg)
        || key
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != "sig")
        || has_private_key_material(key)
        || !key_ops_allow_verification(key)
    {
        return Err(DpopError::InvalidProof);
    }

    match algorithm {
        Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return Err(DpopError::InvalidProof);
            }
            let x = key
                .get("x")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            if URL_SAFE_NO_PAD
                .decode(x)
                .ok()
                .is_none_or(|bytes| bytes.len() != 32)
            {
                return Err(DpopError::InvalidProof);
            }
            DecodingKey::from_ed_components(x).map_err(|_| DpopError::InvalidProof)
        }
        Algorithm::ES256 => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return Err(DpopError::InvalidProof);
            }
            let x = key
                .get("x")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            let y = key
                .get("y")
                .and_then(Value::as_str)
                .ok_or(DpopError::MalformedProof)?;
            if [x, y].iter().any(|coordinate| {
                URL_SAFE_NO_PAD
                    .decode(coordinate)
                    .ok()
                    .is_none_or(|bytes| bytes.len() != 32)
            }) {
                return Err(DpopError::InvalidProof);
            }
            DecodingKey::from_ec_components(x, y).map_err(|_| DpopError::InvalidProof)
        }
        _ => Err(DpopError::InvalidProof),
    }
}

fn has_private_key_material(key: &Value) -> bool {
    ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|member| key.get(member).is_some())
}

fn key_ops_allow_verification(key: &Value) -> bool {
    let Some(operations) = key.get("key_ops") else {
        return true;
    };
    let Some(operations) = operations.as_array() else {
        return false;
    };
    operations.len() == 1 && operations[0].as_str() == Some("verify")
}

fn verify_signature(
    algorithm: Algorithm,
    decoding_key: &DecodingKey,
    signing_input: &[u8],
    signature: &str,
) -> Result<(), DpopError> {
    match jsonwebtoken::crypto::verify(signature, signing_input, decoding_key, algorithm) {
        Ok(true) => Ok(()),
        Ok(false) => Err(DpopError::InvalidProof),
        Err(_) => Err(DpopError::MalformedProof),
    }
}

pub fn jwk_thumbprint(key: &Value) -> Result<String, DpopError> {
    let mut members = BTreeMap::new();
    match key.get("kty").and_then(Value::as_str) {
        Some("OKP") => {
            members.insert(
                "crv",
                key.get("crv")
                    .and_then(Value::as_str)
                    .ok_or(DpopError::MalformedProof)?,
            );
            members.insert("kty", "OKP");
            members.insert(
                "x",
                key.get("x")
                    .and_then(Value::as_str)
                    .ok_or(DpopError::MalformedProof)?,
            );
        }
        Some("EC") => {
            members.insert(
                "crv",
                key.get("crv")
                    .and_then(Value::as_str)
                    .ok_or(DpopError::MalformedProof)?,
            );
            members.insert("kty", "EC");
            members.insert(
                "x",
                key.get("x")
                    .and_then(Value::as_str)
                    .ok_or(DpopError::MalformedProof)?,
            );
            members.insert(
                "y",
                key.get("y")
                    .and_then(Value::as_str)
                    .ok_or(DpopError::MalformedProof)?,
            );
        }
        _ => return Err(DpopError::InvalidProof),
    }
    let canonical = serde_json::to_vec(&members).map_err(|_| DpopError::InvalidProof)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))
}

fn iat_within_window(iat: i64, now: i64) -> bool {
    if iat > now.saturating_add(DPOP_CLOCK_SKEW_SECONDS) {
        return false;
    }
    iat > now
        || now
            .checked_sub(iat)
            .is_some_and(|age| age <= DPOP_REPLAY_TTL_SECONDS as i64)
}

fn valid_jti(jti: &str) -> bool {
    let trimmed = jti.trim();
    !trimmed.is_empty() && jti.len() <= MAX_DPOP_JTI_BYTES
}

fn normalize_htu(value: &str) -> Result<String, DpopError> {
    let mut url = url::Url::parse(value).map_err(|_| DpopError::MalformedProof)?;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    bool::from(left.ct_eq(right))
}

#[cfg(test)]
#[path = "../tests/unit/dpop.rs"]
mod tests;
