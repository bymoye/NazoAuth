use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::{OAuthClient, rsa_public_key_components_are_safe};

pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub const CLIENT_ASSERTION_MAX_TTL_SECONDS: i64 = 300;
pub const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];
const CLIENT_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_CLIENT_ASSERTION_JTI_BYTES: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct ClientAssertionVerificationInput<'a> {
    pub issuer: &'a str,
    pub endpoint_path: &'a str,
    /// Additional configured endpoint origins that may be accepted only for a
    /// client that explicitly permits endpoint audiences. These are not issuer
    /// aliases: the issuer itself remains the sole issuer-audience candidate.
    pub endpoint_audience_aliases: &'a [&'a str],
    pub client: &'a OAuthClient,
    pub assertion: &'a str,
    pub now: i64,
    pub expected_signing_algorithm: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAssertionValidationError {
    DecodeHeader,
    KeyNotFound,
    InvalidSignature,
    InvalidAlgorithm,
    Decode,
    IssuerSubject,
    Audience,
    Time,
    Jti,
}

impl ClientAssertionValidationError {
    #[must_use]
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::DecodeHeader => "decode_header",
            Self::KeyNotFound => "key_not_found",
            Self::InvalidSignature => "decode_signature",
            Self::InvalidAlgorithm => "decode_algorithm",
            Self::Decode => "decode",
            Self::IssuerSubject => "issuer_subject",
            Self::Audience => "audience",
            Self::Time => "time",
            Self::Jti => "jti",
        }
    }
}

#[derive(Clone)]
pub struct ValidatedClientAssertion {
    jti: Box<str>,
    expires_at: i64,
    kid: Option<Box<str>>,
    algorithm: Algorithm,
}

impl std::fmt::Debug for ValidatedClientAssertion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedClientAssertion")
            .field("jti", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl ValidatedClientAssertion {
    #[must_use]
    pub fn jti(&self) -> &str {
        &self.jti
    }

    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[must_use]
    pub fn replay_ttl_seconds(&self, now: i64) -> u64 {
        self.expires_at
            .saturating_sub(now)
            .clamp(1, CLIENT_ASSERTION_MAX_TTL_SECONDS) as u64
    }
}

#[derive(Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: String,
}

#[must_use]
pub fn unverified_client_assertion_client_id(assertion: &str) -> Option<String> {
    let claims = jsonwebtoken::dangerous::insecure_decode::<ClientAssertionClaims>(assertion)
        .ok()?
        .claims;
    (claims.iss == claims.sub && !claims.sub.trim().is_empty()).then_some(claims.sub)
}

pub fn verify_private_key_jwt(
    input: ClientAssertionVerificationInput<'_>,
) -> Result<ValidatedClientAssertion, ClientAssertionValidationError> {
    let header =
        decode_header(input.assertion).map_err(|_| ClientAssertionValidationError::DecodeHeader)?;
    let Some((algorithm_name, _)) = supported_client_jwt_algorithm(header.alg) else {
        return Err(ClientAssertionValidationError::InvalidAlgorithm);
    };
    if input
        .expected_signing_algorithm
        .is_some_and(|expected| expected != algorithm_name)
    {
        return Err(ClientAssertionValidationError::InvalidAlgorithm);
    }
    let (kid, decoding_key) = client_assertion_decoding_key(
        input.client,
        header.kid.as_deref().filter(|kid| !kid.trim().is_empty()),
        header.alg,
    )
    .ok_or(ClientAssertionValidationError::KeyNotFound)?;

    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false;
    // The explicit policy below uses the injected clock and tighter profile bounds.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let claims = decode::<ClientAssertionClaims>(input.assertion, &decoding_key, &validation)
        .map_err(client_assertion_decode_error)?
        .claims;
    if claims.iss != input.client.client_id || claims.sub != input.client.client_id {
        return Err(ClientAssertionValidationError::IssuerSubject);
    }
    if !audience_matches(
        &claims.aud,
        &client_assertion_audience_candidates(
            input.issuer,
            input.endpoint_path,
            input.client.allow_client_assertion_endpoint_audience,
            input.endpoint_audience_aliases,
        ),
        input.client.allow_client_assertion_audience_array,
    ) {
        return Err(ClientAssertionValidationError::Audience);
    }
    if !valid_client_assertion_times(&claims, input.now) {
        return Err(ClientAssertionValidationError::Time);
    }
    if !valid_client_assertion_jti(&claims.jti) {
        return Err(ClientAssertionValidationError::Jti);
    }

    Ok(ValidatedClientAssertion {
        jti: claims.jti.into_boxed_str(),
        expires_at: claims.exp,
        kid: kid.map(String::into_boxed_str),
        algorithm: header.alg,
    })
}

fn client_assertion_audience_candidates(
    issuer: &str,
    endpoint_path: &str,
    allow_endpoint_audience: bool,
    endpoint_audience_aliases: &[&str],
) -> Vec<String> {
    let mut candidates = vec![issuer.to_owned()];
    if !allow_endpoint_audience {
        return candidates;
    }

    for endpoint_origin in std::iter::once(issuer).chain(endpoint_audience_aliases.iter().copied())
    {
        candidates.push(format!("{endpoint_origin}{endpoint_path}"));
        if matches!(endpoint_path, "/par" | "/bc-authorize") {
            candidates.push(format!("{endpoint_origin}/token"));
        }
    }
    candidates
}

fn client_assertion_decode_error(
    error: jsonwebtoken::errors::Error,
) -> ClientAssertionValidationError {
    use jsonwebtoken::errors::ErrorKind;

    match error.kind() {
        ErrorKind::InvalidSignature => ClientAssertionValidationError::InvalidSignature,
        ErrorKind::InvalidAlgorithm => ClientAssertionValidationError::InvalidAlgorithm,
        _ => ClientAssertionValidationError::Decode,
    }
}

fn audience_matches(audience: &Value, expected: &[String], allow_array: bool) -> bool {
    match audience {
        Value::String(value) => expected.iter().any(|candidate| candidate == value),
        Value::Array(values) if allow_array => {
            values.iter().all(Value::is_string)
                && values
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|value| expected.iter().any(|candidate| candidate == value))
        }
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
    !trimmed.is_empty() && trimmed == jti && jti.len() <= MAX_CLIENT_ASSERTION_JTI_BYTES
}

fn client_assertion_decoding_key(
    client: &OAuthClient,
    kid: Option<&str>,
    algorithm: Algorithm,
) -> Option<(Option<String>, DecodingKey)> {
    if let Some(kid) = kid {
        return client_jwt_decoding_key(client, kid, algorithm)
            .map(|decoding_key| (Some(kid.to_owned()), decoding_key));
    }
    let keys = client.jwks.as_ref()?.get("keys")?.as_array()?;
    let mut matching = keys.iter().filter_map(|key| {
        jwt_decoding_key_from_jwk(key, algorithm).map(|decoding_key| (None, decoding_key))
    });
    let selected = matching.next()?;
    matching.next().is_none().then_some(selected)
}

pub(crate) fn client_jwt_decoding_key(
    client: &OAuthClient,
    kid: &str,
    algorithm: Algorithm,
) -> Option<DecodingKey> {
    let keys = client.jwks.as_ref()?.get("keys")?.as_array()?;
    let mut matching = keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid));
    let selected = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    jwt_decoding_key_from_jwk(selected, algorithm)
}

fn jwt_decoding_key_from_jwk(key: &Value, algorithm: Algorithm) -> Option<DecodingKey> {
    let (expected_algorithm, key_type) = supported_client_jwt_algorithm(algorithm)?;
    if key
        .get("alg")
        .is_some_and(|registered| registered.as_str() != Some(expected_algorithm))
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|parameter| key.get(*parameter).is_some())
        || key
            .get("use")
            .is_some_and(|use_| use_.as_str() != Some("sig"))
        || !valid_verification_key_ops(key.get("key_ops"))
    {
        return None;
    }
    match key_type {
        SupportedClientJwtAlgorithm::EdDsa => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            (URL_SAFE_NO_PAD.decode(x).ok()?.len() == 32)
                .then(|| DecodingKey::from_ed_components(x).ok())?
        }
        SupportedClientJwtAlgorithm::Rsa => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let modulus = key.get("n").and_then(Value::as_str)?;
            let exponent = key.get("e").and_then(Value::as_str)?;
            let modulus = URL_SAFE_NO_PAD.decode(modulus).ok()?;
            let exponent_bytes = URL_SAFE_NO_PAD.decode(exponent).ok()?;
            if !rsa_public_key_components_are_safe(&modulus, &exponent_bytes) {
                return None;
            }
            DecodingKey::from_rsa_components(
                key.get("n").and_then(Value::as_str)?,
                key.get("e").and_then(Value::as_str)?,
            )
            .ok()
        }
        SupportedClientJwtAlgorithm::Ec => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32
                || URL_SAFE_NO_PAD.decode(y).ok()?.len() != 32
            {
                return None;
            }
            DecodingKey::from_ec_components(x, y).ok()
        }
    }
}

fn valid_verification_key_ops(key_ops: Option<&Value>) -> bool {
    match key_ops {
        None => true,
        Some(Value::Array(operations)) => {
            operations.len() == 1 && operations[0].as_str() == Some("verify")
        }
        Some(_) => false,
    }
}

enum SupportedClientJwtAlgorithm {
    EdDsa,
    Rsa,
    Ec,
}

fn supported_client_jwt_algorithm(
    algorithm: Algorithm,
) -> Option<(&'static str, SupportedClientJwtAlgorithm)> {
    match algorithm {
        Algorithm::EdDSA => Some(("EdDSA", SupportedClientJwtAlgorithm::EdDsa)),
        Algorithm::RS256 => Some(("RS256", SupportedClientJwtAlgorithm::Rsa)),
        Algorithm::ES256 => Some(("ES256", SupportedClientJwtAlgorithm::Ec)),
        Algorithm::PS256 => Some(("PS256", SupportedClientJwtAlgorithm::Rsa)),
        _ => None,
    }
}

pub(crate) fn supported_client_jwt_algorithm_name(algorithm: Algorithm) -> Option<&'static str> {
    supported_client_jwt_algorithm(algorithm).map(|(name, _)| name)
}

#[cfg(test)]
#[path = "../tests/unit/client_assertion/jwk_policy.rs"]
mod jwk_policy_tests;
