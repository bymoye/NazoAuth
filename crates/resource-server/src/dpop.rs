use super::VerifiedSenderConstraintProof;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

const DEFAULT_DPOP_MAX_AGE_SECONDS: i64 = super::DEFAULT_DPOP_MAX_AGE_SECONDS;
const DEFAULT_CLOCK_SKEW_SECONDS: i64 = super::DEFAULT_CLOCK_SKEW_SECONDS;
const DEFAULT_REPLAY_CACHE_MAX_ENTRIES: usize = 100_000;
const MAX_DPOP_JTI_BYTES: usize = 128;

#[derive(Clone, Debug)]
pub struct DpopProofVerifier {
    config: DpopProofVerifierConfig,
    max_replay_cache_entries: usize,
    replay_cache: Arc<Mutex<HashMap<String, i64>>>,
}

#[derive(Clone, Debug)]
pub struct DpopProofVerifierConfig {
    pub allowed_algs: Vec<Algorithm>,
    pub clock_skew_seconds: i64,
    pub max_age_seconds: i64,
    pub required_nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopProofVerifierError {
    MalformedProof,
    UnsupportedAlgorithm,
    MissingPublicJwk,
    InvalidPublicJwk,
    InvalidSignature,
    WrongType,
    MethodMismatch,
    UriMismatch,
    AccessTokenHashMismatch,
    MissingJti,
    ReplayDetected,
    Expired,
    NotYetValid,
    NonceMismatch,
    ReplayStoreUnavailable,
    ReplayCacheFull,
}

pub(crate) struct DpopProofVerification {
    pub(crate) proof: VerifiedSenderConstraintProof,
    pub(crate) jti: String,
    pub(crate) expires_at: i64,
    pub(crate) nonce: Option<String>,
}

enum SupportedDpopAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

#[derive(Debug, Deserialize)]
pub(super) struct DpopProofClaims {
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
    pub fn new(config: DpopProofVerifierConfig) -> Self {
        Self::new_with_replay_cache_limit(config, DEFAULT_REPLAY_CACHE_MAX_ENTRIES)
    }

    pub fn new_with_replay_cache_limit(
        config: DpopProofVerifierConfig,
        max_replay_cache_entries: usize,
    ) -> Self {
        Self {
            config,
            max_replay_cache_entries: max_replay_cache_entries.max(1),
            replay_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn verify(
        &self,
        proof_jwt: &str,
        method: &str,
        htu: &str,
        access_token: &str,
    ) -> Result<VerifiedSenderConstraintProof, DpopProofVerifierError> {
        let verification = self.verify_without_replay_at(
            proof_jwt,
            method,
            htu,
            access_token,
            Utc::now().timestamp(),
        )?;
        let jkt = verification
            .proof
            .dpop_jkt
            .as_deref()
            .ok_or(DpopProofVerifierError::InvalidPublicJwk)?;
        self.check_replay(jkt, &verification.jti)?;
        Ok(verification.proof)
    }

    pub(crate) fn verify_without_replay_at(
        &self,
        proof_jwt: &str,
        method: &str,
        htu: &str,
        access_token: &str,
        now: i64,
    ) -> Result<DpopProofVerification, DpopProofVerifierError> {
        self.verify_without_replay_for_targets_at(proof_jwt, method, &[htu], access_token, now)
    }

    pub(crate) fn verify_without_replay_for_targets_at(
        &self,
        proof_jwt: &str,
        method: &str,
        target_uris: &[&str],
        access_token: &str,
        now: i64,
    ) -> Result<DpopProofVerification, DpopProofVerifierError> {
        let header = jsonwebtoken::decode_header(proof_jwt)
            .map_err(|_| DpopProofVerifierError::MalformedProof)?;
        if !header
            .typ
            .as_deref()
            .is_some_and(|typ| typ.eq_ignore_ascii_case("dpop+jwt"))
        {
            return Err(DpopProofVerifierError::WrongType);
        }
        if !self.config.allowed_algs.contains(&header.alg) {
            return Err(DpopProofVerifierError::UnsupportedAlgorithm);
        }
        let public_jwk = dpop_header_jwk(proof_jwt)?;
        let decoding_key = dpop_jwk_decoding_key(&public_jwk, header.alg)
            .ok_or(DpopProofVerifierError::InvalidPublicJwk)?;
        let claims = decode_and_verify_dpop_proof(proof_jwt, &decoding_key, header.alg)?;
        self.validate_claims(&claims, method, target_uris, access_token, now)?;
        let jkt =
            dpop_jwk_thumbprint(&public_jwk).ok_or(DpopProofVerifierError::InvalidPublicJwk)?;
        let expires_at = claims
            .iat
            .saturating_add(self.config.max_age_seconds.max(1))
            .saturating_add(self.config.clock_skew_seconds.max(0));
        Ok(DpopProofVerification {
            proof: VerifiedSenderConstraintProof {
                dpop_jkt: Some(jkt),
                mtls_x5t_s256: None,
            },
            jti: claims.jti,
            expires_at,
            nonce: claims.nonce,
        })
    }

    fn validate_claims(
        &self,
        claims: &DpopProofClaims,
        method: &str,
        target_uris: &[&str],
        access_token: &str,
        now: i64,
    ) -> Result<(), DpopProofVerifierError> {
        if !claims.htm.eq_ignore_ascii_case(method) {
            return Err(DpopProofVerifierError::MethodMismatch);
        }
        let actual_htu =
            normalize_dpop_htu(&claims.htu).ok_or(DpopProofVerifierError::MalformedProof)?;
        let normalized_targets = target_uris
            .iter()
            .map(|target_uri| normalize_dpop_htu(target_uri))
            .collect::<Option<Vec<_>>>()
            .ok_or(DpopProofVerifierError::UriMismatch)?;
        if normalized_targets.is_empty() || !normalized_targets.contains(&actual_htu) {
            return Err(DpopProofVerifierError::UriMismatch);
        }
        if claims.ath.as_deref() != Some(access_token_hash(access_token).as_str()) {
            return Err(DpopProofVerifierError::AccessTokenHashMismatch);
        }
        if claims.jti.trim().is_empty() || claims.jti.len() > MAX_DPOP_JTI_BYTES {
            return Err(DpopProofVerifierError::MissingJti);
        }
        let skew = self.config.clock_skew_seconds.max(0);
        let max_age = self.config.max_age_seconds.max(1);
        if claims.iat < now.saturating_sub(max_age.saturating_add(skew)) {
            return Err(DpopProofVerifierError::Expired);
        }
        if claims.iat > now.saturating_add(skew) {
            return Err(DpopProofVerifierError::NotYetValid);
        }
        if let Some(expected) = self.config.required_nonce.as_deref()
            && claims.nonce.as_deref() != Some(expected)
        {
            return Err(DpopProofVerifierError::NonceMismatch);
        }
        Ok(())
    }

    fn check_replay(&self, jkt: &str, jti: &str) -> Result<(), DpopProofVerifierError> {
        let now = Utc::now().timestamp();
        let ttl = self
            .config
            .max_age_seconds
            .max(1)
            .saturating_add(self.config.clock_skew_seconds.max(0));
        let mut cache = self
            .replay_cache
            .lock()
            .map_err(|_| DpopProofVerifierError::ReplayStoreUnavailable)?;
        cache.retain(|_, expires_at| *expires_at > now);
        let replay_key = format!("{jkt}:{jti}");
        if cache.contains_key(&replay_key) {
            return Err(DpopProofVerifierError::ReplayDetected);
        }
        if cache.len() >= self.max_replay_cache_entries {
            return Err(DpopProofVerifierError::ReplayCacheFull);
        }
        cache.insert(replay_key, now.saturating_add(ttl));
        Ok(())
    }
}

fn dpop_header_jwk(proof_jwt: &str) -> Result<Value, DpopProofVerifierError> {
    let encoded_header = proof_jwt
        .split('.')
        .next()
        .filter(|part| !part.is_empty())
        .ok_or(DpopProofVerifierError::MalformedProof)?;
    let header = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| DpopProofVerifierError::MalformedProof)?;
    let header = serde_json::from_slice::<Value>(&header)
        .map_err(|_| DpopProofVerifierError::MalformedProof)?;
    header
        .get("jwk")
        .cloned()
        .ok_or(DpopProofVerifierError::MissingPublicJwk)
}

fn normalize_dpop_htu(value: &str) -> Option<String> {
    let mut url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

impl Default for DpopProofVerifierConfig {
    fn default() -> Self {
        Self {
            allowed_algs: vec![
                Algorithm::EdDSA,
                Algorithm::RS256,
                Algorithm::ES256,
                Algorithm::PS256,
            ],
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
            max_age_seconds: DEFAULT_DPOP_MAX_AGE_SECONDS,
            required_nonce: None,
        }
    }
}

pub(super) fn decode_and_verify_dpop_proof(
    proof_jwt: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<DpopProofClaims, DpopProofVerifierError> {
    let mut parts = proof_jwt.split('.');
    let Some(header) = parts.next().filter(|part| !part.is_empty()) else {
        return Err(DpopProofVerifierError::MalformedProof);
    };
    let Some(payload) = parts.next().filter(|part| !part.is_empty()) else {
        return Err(DpopProofVerifierError::MalformedProof);
    };
    let Some(signature) = parts.next().filter(|part| !part.is_empty()) else {
        return Err(DpopProofVerifierError::MalformedProof);
    };
    if parts.next().is_some() {
        return Err(DpopProofVerifierError::MalformedProof);
    }
    let signing_input = format!("{header}.{payload}");
    if !jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), decoding_key, alg)
        .map_err(|_| DpopProofVerifierError::InvalidSignature)?
    {
        return Err(DpopProofVerifierError::InvalidSignature);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| DpopProofVerifierError::MalformedProof)?;
    let claims = serde_json::from_slice::<DpopProofClaims>(&payload)
        .map_err(|_| DpopProofVerifierError::MalformedProof)?;
    Ok(claims)
}

pub(super) fn dpop_jwk_decoding_key(key: &Value, alg: Algorithm) -> Option<DecodingKey> {
    const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    let key = key.as_object()?;
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| key.contains_key(*member))
    {
        return None;
    }
    let key = Value::Object(key.clone());
    let (expected_alg, supported_alg) = supported_dpop_algorithm(alg)?;
    if let Some(key_alg) = key.get("alg").and_then(Value::as_str)
        && key_alg != expected_alg
    {
        return None;
    }
    if key
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|use_| use_ != "sig")
    {
        return None;
    }
    match supported_alg {
        SupportedDpopAlgorithm::EdDsa => {
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
            DecodingKey::from_ed_components(x).ok()
        }
        SupportedDpopAlgorithm::Rsa => {
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
            DecodingKey::from_rsa_components(n, e).ok()
        }
        SupportedDpopAlgorithm::Ec => {
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
            DecodingKey::from_ec_components(x, y).ok()
        }
    }
}

fn supported_dpop_algorithm(alg: Algorithm) -> Option<(&'static str, SupportedDpopAlgorithm)> {
    match alg {
        Algorithm::EdDSA => Some(("EdDSA", SupportedDpopAlgorithm::EdDsa)),
        Algorithm::RS256 => Some(("RS256", SupportedDpopAlgorithm::Rsa)),
        Algorithm::ES256 => Some(("ES256", SupportedDpopAlgorithm::Ec)),
        Algorithm::PS256 => Some(("PS256", SupportedDpopAlgorithm::Rsa)),
        _ => None,
    }
}

pub(super) fn dpop_jwk_thumbprint(key: &Value) -> Option<String> {
    let mut members = BTreeMap::new();
    match key.get("kty").and_then(Value::as_str)? {
        "EC" => {
            members.insert("crv", key.get("crv")?.as_str()?);
            members.insert("kty", "EC");
            members.insert("x", key.get("x")?.as_str()?);
            members.insert("y", key.get("y")?.as_str()?);
        }
        "OKP" => {
            members.insert("crv", key.get("crv")?.as_str()?);
            members.insert("kty", "OKP");
            members.insert("x", key.get("x")?.as_str()?);
        }
        "RSA" => {
            members.insert("e", key.get("e")?.as_str()?);
            members.insert("kty", "RSA");
            members.insert("n", key.get("n")?.as_str()?);
        }
        _ => return None,
    }
    let canonical = serde_json::to_string(&members).ok()?;
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

pub(super) fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;

    #[test]
    fn supported_dpop_algorithm_rejects_unsupported_algs() {
        assert!(supported_dpop_algorithm(Algorithm::HS256).is_none());
        assert!(supported_dpop_algorithm(Algorithm::ES384).is_none());
        assert!(supported_dpop_algorithm(Algorithm::RS384).is_none());
    }
}
