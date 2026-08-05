use std::{collections::HashSet, str::FromStr};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey};
use nazo_auth::{
    AdminClientCryptoPort, ClientSecretDigesterPort, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    client_jwe_encryption_key_matches_alg,
};
use serde_json::Value;
use sha2::Sha256;

use crate::KeyManager;

const CLIENT_SECRET_HASH_VERSION: &str = "client-secret-v1";
pub use nazo_auth::SUPPORTED_CLIENT_JWT_SIGNING_ALGS;

/// Concrete client-registration crypto bound to the active signing key snapshot.
#[derive(Clone)]
pub struct ClientRegistrationCrypto {
    keyset: KeyManager,
}

impl ClientRegistrationCrypto {
    #[must_use]
    pub fn new(keyset: KeyManager) -> Self {
        Self { keyset }
    }
}

impl AdminClientCryptoPort for ClientRegistrationCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        self.keyset
            .snapshot()
            .response_signing_alg_values_supported()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn id_token_signing_algorithms(&self) -> Vec<String> {
        self.keyset
            .snapshot()
            .id_token_signing_alg_values_supported()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value) -> Result<(), String> {
        validate_client_jwks(jwks)
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        validate_rfc4514_dn(value)
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        client_jwks_contains_signing_key(jwks)
    }

    fn contains_signing_key_for_algorithm(&self, jwks: &Value, algorithm: &str) -> bool {
        client_jwks_contains_signing_key_for_algorithm(jwks, algorithm)
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        validate_self_signed_mtls_jwks(jwks)
    }
}

impl ClientSecretDigesterPort for ClientRegistrationCrypto {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        client_secret_digest(secret, pepper, salt)
    }
}

#[must_use]
pub fn client_jwks_matching_encryption_key_count(jwks: &Value, alg: &str) -> usize {
    jwks.get("keys")
        .and_then(Value::as_array)
        .map_or(0, |keys| {
            keys.iter()
                .filter(|key| client_jwe_encryption_key_matches_alg(key, alg))
                .count()
        })
}

#[must_use]
pub fn client_jwks_contains_signing_key(jwks: &Value) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
                let Some(algorithm) = key
                    .get("alg")
                    .and_then(Value::as_str)
                    .and_then(client_jwt_algorithm_from_name)
                else {
                    return false;
                };
                public_key_use == "sig" && jwt_decoding_key_from_jwk(key, algorithm).is_some()
            })
        })
}

#[must_use]
pub fn client_jwks_contains_signing_key_for_algorithm(jwks: &Value, expected: &str) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
                let algorithm_name = key.get("alg").and_then(Value::as_str);
                let Some(algorithm) = algorithm_name.and_then(client_jwt_algorithm_from_name)
                else {
                    return false;
                };
                public_key_use == "sig"
                    && algorithm_name == Some(expected)
                    && jwt_decoding_key_from_jwk(key, algorithm).is_some()
            })
        })
}

pub fn validate_client_jwks(jwks: &Value) -> Result<(), String> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "jwks 必须包含 keys 数组".to_owned())?;
    if keys.is_empty() {
        return Err("jwks.keys 不能为空".to_owned());
    }
    let mut seen_kids = HashSet::new();
    let mut unidentified_key_classes = HashSet::new();
    for key in keys {
        let key_object = key
            .as_object()
            .ok_or_else(|| "jwks 公钥必须是 JSON object".to_owned())?;
        ensure_public_client_jwk(key_object)?;
        let kid = match key.get("kid") {
            None => None,
            Some(Value::String(kid)) if !kid.trim().is_empty() && kid.trim() == kid => {
                Some(kid.as_str())
            }
            Some(Value::String(_)) => return Err("jwks kid 不能为空或包含首尾空白".to_owned()),
            Some(_) => return Err("jwks kid 必须是字符串".to_owned()),
        };
        let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
        if let Some(kid) = kid {
            if !seen_kids.insert(kid) {
                return Err(format!("jwks kid 不能重复: {kid}"));
            }
        } else {
            // RFC 7517 section 4.5 defines `kid` as optional. Runtime key
            // selection rejects ambiguity when a JOSE message omits it.
        }
        let alg = key
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| "jwks 公钥必须声明 alg".to_owned())?;
        if kid.is_none()
            && !unidentified_key_classes.insert((public_key_use.to_owned(), alg.to_owned()))
        {
            return Err("省略 kid 时，相同 use 与 alg 的公钥必须唯一".to_owned());
        }
        match public_key_use {
            "sig" => {
                let Some(algorithm) = client_jwt_algorithm_from_name(alg) else {
                    return Err(format!(
                        "jwks alg 必须是 {} 或 {}",
                        SUPPORTED_CLIENT_JWT_SIGNING_ALGS.join(", "),
                        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.join(", ")
                    ));
                };
                if jwt_decoding_key_from_jwk(key, algorithm).is_none() {
                    return Err("jwks 公钥材料与 alg 不匹配".to_owned());
                }
            }
            "enc" => {
                if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg)
                    || !client_jwe_encryption_key_matches_alg(key, alg)
                {
                    return Err("jwks 公钥材料与 alg 不匹配".to_owned());
                }
            }
            _ => return Err("jwks 公钥 use 必须为 sig 或 enc".to_owned()),
        }
    }
    Ok(())
}

pub fn validate_rfc4514_dn(value: &str) -> Result<(), String> {
    parse_rfc4514_dn(value).map(|_| ()).ok_or_else(|| {
        "tls_client_auth_subject_dn 必须是合法的 RFC 4514 distinguished name".to_owned()
    })
}

#[must_use]
pub fn rfc4514_dn_matches(registered: &str, certificate_subject: &str) -> bool {
    let Some(registered) = parse_rfc4514_dn(registered) else {
        return false;
    };
    let Some(certificate_subject) = parse_rfc4514_dn(certificate_subject) else {
        return false;
    };
    registered == certificate_subject
}

fn parse_rfc4514_dn(value: &str) -> Option<String> {
    if value.is_empty() || value.trim() != value || value.len() > 2_048 {
        return None;
    }
    let name = x509_cert::name::Name::from_str(value).ok()?;
    if name.is_empty() {
        return None;
    }
    // Parsing first resolves attribute aliases and escaping. The canonical
    // display form gives equivalent RFC 4514 spellings one representation;
    // Unicode lowercase retains the case-insensitive matching behavior used
    // by the previous X509_NAME comparison.
    Some(name.to_string().to_lowercase())
}

#[must_use]
pub fn validate_self_signed_mtls_jwks(jwks: &Value) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                key.get("x5c")
                    .and_then(Value::as_array)
                    .and_then(|x5c| x5c.first())
                    .and_then(Value::as_str)
                    .is_some_and(valid_current_x5c_certificate)
            })
        })
}

fn ensure_public_client_jwk(jwk: &serde_json::Map<String, Value>) -> Result<(), String> {
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| jwk.contains_key(*member))
    {
        return Err("jwks 不能包含私钥材料或对称密钥材料".to_owned());
    }
    Ok(())
}

fn client_jwt_algorithm_from_name(value: &str) -> Option<Algorithm> {
    match value {
        "EdDSA" => Some(Algorithm::EdDSA),
        "RS256" => Some(Algorithm::RS256),
        "ES256" => Some(Algorithm::ES256),
        "PS256" => Some(Algorithm::PS256),
        _ => None,
    }
}

fn jwt_decoding_key_from_jwk(key: &Value, alg: Algorithm) -> Option<DecodingKey> {
    let expected_alg = match alg {
        Algorithm::EdDSA => "EdDSA",
        Algorithm::RS256 => "RS256",
        Algorithm::ES256 => "ES256",
        Algorithm::PS256 => "PS256",
        _ => return None,
    };
    if key.get("alg").and_then(Value::as_str) != Some(expected_alg)
        || key.get("d").is_some()
        || key
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != "sig")
    {
        return None;
    }
    match alg {
        Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            let x = key.get("x").and_then(Value::as_str)?;
            (URL_SAFE_NO_PAD.decode(x).ok()?.len() == 32)
                .then(|| DecodingKey::from_ed_components(x).ok())
                .flatten()
        }
        Algorithm::RS256 | Algorithm::PS256 => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            let n = key.get("n").and_then(Value::as_str)?;
            let e = key.get("e").and_then(Value::as_str)?;
            if URL_SAFE_NO_PAD.decode(n).ok()?.len() < 256
                || URL_SAFE_NO_PAD.decode(e).ok()?.is_empty()
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
            let x = key.get("x").and_then(Value::as_str)?;
            let y = key.get("y").and_then(Value::as_str)?;
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

fn valid_current_x5c_certificate(value: &str) -> bool {
    let Ok(der) = STANDARD.decode(
        value
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>(),
    ) else {
        return false;
    };
    let Ok((remainder, x509)) = x509_parser::parse_x509_certificate(&der) else {
        return false;
    };
    remainder.is_empty() && x509.validity().is_valid()
}

fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn hash_client_secret(secret: &str, pepper: &str) -> String {
    let salt = random_urlsafe_token();
    client_secret_digest(secret, pepper, &salt)
}

fn client_secret_digest(secret: &str, pepper: &str, salt: &str) -> String {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(pepper.as_bytes())
        .expect("HMAC accepts any key");
    mac.update(salt.as_bytes());
    mac.update(b":");
    mac.update(secret.as_bytes());
    let digest = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{CLIENT_SECRET_HASH_VERSION}:{salt}:{digest}")
}

#[cfg(test)]
#[path = "../tests/unit/client_registration.rs"]
mod tests;
