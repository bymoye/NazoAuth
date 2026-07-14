use std::{cmp::Ordering, collections::HashSet};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey};
use nazo_auth::{AdminClientCryptoPort, ClientSecretDigesterPort};
use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, sign::Signer, x509::X509};
use serde_json::Value;

use crate::KeyManager;

const CLIENT_SECRET_HASH_VERSION: &str = "client-secret-v1";
const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];
const SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS: &[&str] = &["RSA-OAEP-256"];

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

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String> {
        validate_client_jwks_with_missing_kid_policy(jwks, allow_missing_kid)
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        client_jwks_contains_signing_key(jwks)
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
                .filter(|key| {
                    key.get("use").and_then(Value::as_str) == Some("enc")
                        && key.get("alg").and_then(Value::as_str) == Some(alg)
                        && valid_rsa_jwe_encryption_key(key)
                })
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

pub fn validate_client_jwks_with_missing_kid_policy(
    jwks: &Value,
    allow_missing_kid: bool,
) -> Result<(), String> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "jwks 必须包含 keys 数组".to_owned())?;
    if keys.is_empty() {
        return Err("jwks.keys 不能为空".to_owned());
    }
    let mut seen_kids = HashSet::new();
    let mut signing_key_count = 0usize;
    let mut kidless_signing_key_count = 0usize;
    for key in keys {
        let key_object = key
            .as_object()
            .ok_or_else(|| "jwks 公钥必须是 JSON object".to_owned())?;
        ensure_public_client_jwk(key_object)?;
        let kid = key.get("kid").and_then(Value::as_str).unwrap_or_default();
        let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
        if public_key_use == "sig" {
            signing_key_count += 1;
        }
        if kid.trim().is_empty() {
            if public_key_use == "enc" {
                return Err("jwks 加密公钥必须包含 kid".to_owned());
            }
            if !allow_missing_kid {
                return Err("jwks 公钥必须包含 kid".to_owned());
            }
            kidless_signing_key_count += 1;
        } else if !seen_kids.insert(kid) {
            return Err(format!("jwks kid 不能重复: {kid}"));
        }
        let alg = key
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| "jwks 公钥必须声明 alg".to_owned())?;
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
                    || !valid_rsa_jwe_encryption_key(key)
                {
                    return Err("jwks 公钥材料与 alg 不匹配".to_owned());
                }
            }
            _ => return Err("jwks 公钥 use 必须为 sig 或 enc".to_owned()),
        }
    }
    if kidless_signing_key_count > 0 && signing_key_count != 1 {
        return Err("省略 kid 时 jwks 必须且只能包含一个签名公钥".to_owned());
    }
    Ok(())
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

fn valid_rsa_jwe_encryption_key(key: &Value) -> bool {
    if key.get("kty").and_then(Value::as_str) != Some("RSA") {
        return false;
    }
    let Some(n) = key.get("n").and_then(Value::as_str) else {
        return false;
    };
    let Some(e) = key.get("e").and_then(Value::as_str) else {
        return false;
    };
    let Ok(modulus) = URL_SAFE_NO_PAD.decode(n) else {
        return false;
    };
    let Ok(exponent) = URL_SAFE_NO_PAD.decode(e) else {
        return false;
    };
    modulus.len() >= 256 && !exponent.is_empty()
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
    let Ok(x509) = X509::from_der(&der) else {
        return false;
    };
    let Ok(now) = Asn1Time::from_unix(Utc::now().timestamp()) else {
        return false;
    };
    let Ok(not_before) = x509.not_before().compare(&now) else {
        return false;
    };
    let Ok(not_after) = x509.not_after().compare(&now) else {
        return false;
    };
    not_before != Ordering::Greater && not_after != Ordering::Less
}

fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn hash_client_secret(secret: &str, pepper: &str) -> String {
    let salt = random_urlsafe_token();
    client_secret_digest(secret, pepper, &salt)
}

fn client_secret_digest(secret: &str, pepper: &str, salt: &str) -> String {
    let key = PKey::hmac(pepper.as_bytes()).expect("HMAC accepts any key");
    let mut signer = Signer::new(MessageDigest::sha256(), &key).expect("SHA-256 HMAC is available");
    signer.update(salt.as_bytes()).expect("HMAC update");
    signer.update(b":").expect("HMAC update");
    signer.update(secret.as_bytes()).expect("HMAC update");
    let digest = URL_SAFE_NO_PAD.encode(signer.sign_to_vec().expect("HMAC finalize"));
    format!("{CLIENT_SECRET_HASH_VERSION}:{salt}:{digest}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn client_secret_digest_preserves_persisted_v1_format() {
        assert_eq!(
            client_secret_digest("secret", "pepper", "salt"),
            "client-secret-v1:salt:9H5GZ-kyQt1opgZoNCnaRK1w3aTK1xF1-HoStANbmzM"
        );
    }

    #[test]
    fn client_jwks_reject_private_key_material() {
        let error = validate_client_jwks_with_missing_kid_policy(
            &json!({
                "keys": [{
                    "kid": "private",
                    "use": "sig",
                    "alg": "RS256",
                    "kty": "RSA",
                    "n": "AQ",
                    "e": "AQAB",
                    "d": "private"
                }]
            }),
            false,
        )
        .expect_err("private key material must be rejected");
        assert_eq!(error, "jwks 不能包含私钥材料或对称密钥材料");
    }
}
