use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JwkSignatureVerificationError {
    #[error("unsupported HTTP message signature algorithm")]
    UnsupportedAlgorithm,
    #[error("JWK set is missing or malformed")]
    MalformedJwkSet,
    #[error("JWK kid was not found")]
    KeyNotFound,
    #[error("JWK kid is ambiguous")]
    AmbiguousKey,
    #[error("JWK is not a usable public verification key")]
    InvalidPublicKey,
    #[error("HTTP message signature verification failed")]
    InvalidSignature,
}

/// Verifies a raw RFC 9421 signature against one uniquely selected public JWK.
///
/// Client identity, tenant binding, registration state, and replay policy stay
/// with the caller. This primitive owns only algorithm mapping, strict public
/// key selection, and cryptographic verification.
pub fn verify_jwk_signature(
    jwks: &Value,
    kid: &str,
    algorithm: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwkSignatureVerificationError> {
    let algorithm = jwt_algorithm(algorithm)?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(JwkSignatureVerificationError::MalformedJwkSet)?;
    let mut matching = keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid));
    let key = matching
        .next()
        .ok_or(JwkSignatureVerificationError::KeyNotFound)?;
    if matching.next().is_some() {
        return Err(JwkSignatureVerificationError::AmbiguousKey);
    }
    let decoding_key = public_decoding_key(key, algorithm)
        .ok_or(JwkSignatureVerificationError::InvalidPublicKey)?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
    match jsonwebtoken::crypto::verify(&encoded_signature, signing_input, &decoding_key, algorithm)
    {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(JwkSignatureVerificationError::InvalidSignature),
    }
}

fn jwt_algorithm(algorithm: &str) -> Result<Algorithm, JwkSignatureVerificationError> {
    match algorithm {
        "ed25519" => Ok(Algorithm::EdDSA),
        "rsa-v1_5-sha256" => Ok(Algorithm::RS256),
        "ecdsa-p256-sha256" => Ok(Algorithm::ES256),
        _ => Err(JwkSignatureVerificationError::UnsupportedAlgorithm),
    }
}

fn public_decoding_key(key: &Value, algorithm: Algorithm) -> Option<DecodingKey> {
    let expected_algorithm = match algorithm {
        Algorithm::EdDSA => "EdDSA",
        Algorithm::RS256 => "RS256",
        Algorithm::ES256 => "ES256",
        _ => return None,
    };
    match key.get("alg") {
        None => {}
        Some(Value::String(value)) if value == expected_algorithm => {}
        Some(_) => return None,
    }
    match key.get("use") {
        None => {}
        Some(Value::String(value)) if value == "sig" => {}
        Some(_) => return None,
    }
    if ["k", "d", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|member| key.get(member).is_some())
    {
        return None;
    }
    if let Some(key_ops) = key.get("key_ops") {
        let operations = key_ops.as_array()?;
        if operations.len() != 1 || operations[0].as_str() != Some("verify") {
            return None;
        }
    }

    match algorithm {
        Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x")?.as_str()?;
            (URL_SAFE_NO_PAD.decode(x).ok()?.len() == 32)
                .then(|| DecodingKey::from_ed_components(x).ok())?
        }
        Algorithm::RS256 => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n")?.as_str()?;
            let e = key.get("e")?.as_str()?;
            let modulus = URL_SAFE_NO_PAD.decode(n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(e).ok()?;
            if !(2_048..=8_192).contains(&unsigned_integer_bit_length(&modulus))
                || !valid_rsa_public_exponent(&exponent)
            {
                return None;
            }
            DecodingKey::from_rsa_components(n, e).ok()
        }
        Algorithm::ES256 => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            let x = key.get("x")?.as_str()?;
            let y = key.get("y")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32
                || URL_SAFE_NO_PAD.decode(y).ok()?.len() != 32
            {
                return None;
            }
            DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}

fn unsigned_integer_bit_length(bytes: &[u8]) -> usize {
    let Some((offset, first)) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0) else {
        return 0;
    };
    (bytes.len() - offset - 1) * 8 + (u8::BITS - first.leading_zeros()) as usize
}

fn valid_rsa_public_exponent(bytes: &[u8]) -> bool {
    let offset = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    match &bytes[offset..] {
        [] => false,
        [value] => *value >= 3 && value % 2 == 1,
        values => values.last().is_some_and(|value| value % 2 == 1),
    }
}

#[cfg(test)]
#[path = "../tests/unit/jwk.rs"]
mod tests;
