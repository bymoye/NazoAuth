use std::io::{Read, Write};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand::Rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JweError {
    #[error("the JWE is malformed")]
    Malformed,
    #[error("the JWE uses an unsupported algorithm")]
    Unsupported,
    #[error("the JWE key is invalid")]
    InvalidKey,
    #[error("the JWE authentication tag is invalid")]
    AuthenticationFailed,
    #[error("the JWE compression payload is invalid or too large")]
    InvalidCompression,
}

#[derive(Clone)]
pub struct EphemeralEncryptionKey {
    secret: SecretKey,
}

impl EphemeralEncryptionKey {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    #[must_use]
    pub fn public_jwk(&self) -> Value {
        public_jwk(self.secret.public_key())
    }

    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes().into()
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, JweError> {
        SecretKey::from_slice(bytes)
            .map(|secret| Self { secret })
            .map_err(|_| JweError::InvalidKey)
    }

    pub fn derive(root_key: &[u8; 32], purpose: &[u8]) -> Result<Self, JweError> {
        for counter in 0_u32..=u32::MAX {
            let mut digest = Sha256::new();
            digest.update(b"NazoAuth OpenID4VC ECDH-ES\0");
            digest.update(root_key);
            digest.update(purpose);
            digest.update(counter.to_be_bytes());
            let bytes: [u8; 32] = digest.finalize().into();
            if let Ok(key) = Self::from_secret_bytes(&bytes) {
                return Ok(key);
            }
        }
        Err(JweError::InvalidKey)
    }

    pub fn decrypt(&self, compact: &str) -> Result<Vec<u8>, JweError> {
        decrypt_ecdh_es(compact, &self.secret, None)
    }

    pub fn decrypt_credential_request(
        &self,
        compact: &str,
        expected_kid: &str,
    ) -> Result<Vec<u8>, JweError> {
        decrypt_ecdh_es(compact, &self.secret, Some(expected_kid))
    }
}

pub fn encrypt_ecdh_es(
    plaintext: &[u8],
    recipient_jwk: &Value,
    content_type: Option<&str>,
) -> Result<String, JweError> {
    encrypt_ecdh_es_with_zip(plaintext, recipient_jwk, content_type, None, "A256GCM")
}

pub fn encrypt_ecdh_es_a128(
    plaintext: &[u8],
    recipient_jwk: &Value,
    content_type: Option<&str>,
) -> Result<String, JweError> {
    encrypt_ecdh_es_with_zip(plaintext, recipient_jwk, content_type, None, "A128GCM")
}

pub fn encrypt_ecdh_es_deflate(
    plaintext: &[u8],
    recipient_jwk: &Value,
    content_type: Option<&str>,
) -> Result<String, JweError> {
    encrypt_ecdh_es_with_zip(
        plaintext,
        recipient_jwk,
        content_type,
        Some("DEF"),
        "A256GCM",
    )
}

fn encrypt_ecdh_es_with_zip(
    plaintext: &[u8],
    recipient_jwk: &Value,
    content_type: Option<&str>,
    zip: Option<&str>,
    enc: &str,
) -> Result<String, JweError> {
    let key_bits = match enc {
        "A128GCM" => 128,
        "A256GCM" => 256,
        _ => return Err(JweError::Unsupported),
    };
    let recipient = parse_public_jwk(recipient_jwk)?;
    let ephemeral = SecretKey::generate();
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let key = concat_kdf(
        shared.raw_secret_bytes().as_slice(),
        enc,
        &[],
        &[],
        key_bits,
    );
    let mut header = json!({
        "alg": "ECDH-ES", "enc": enc, "epk": public_jwk(ephemeral.public_key()),
    });
    if let Some(kid) = recipient_jwk.get("kid").and_then(Value::as_str) {
        header["kid"] = Value::String(kid.to_owned());
    }
    if let Some(content_type) = content_type {
        header["cty"] = Value::String(content_type.to_owned());
    }
    if let Some(zip) = zip {
        header["zip"] = Value::String(zip.to_owned());
    }
    let protected =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| JweError::Malformed)?);
    let compressed;
    let plaintext = if zip == Some("DEF") {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(plaintext)
            .map_err(|_| JweError::InvalidCompression)?;
        compressed = encoder.finish().map_err(|_| JweError::InvalidCompression)?;
        compressed.as_slice()
    } else {
        plaintext
    };
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let payload = Payload {
        msg: plaintext,
        aad: protected.as_bytes(),
    };
    let ciphertext_and_tag = match enc {
        "A128GCM" => Aes128Gcm::new_from_slice(&key)
            .map_err(|_| JweError::InvalidKey)?
            .encrypt((&nonce).into(), payload),
        "A256GCM" => Aes256Gcm::new_from_slice(&key)
            .map_err(|_| JweError::InvalidKey)?
            .encrypt((&nonce).into(), payload),
        _ => unreachable!("enc was validated above"),
    }
    .map_err(|_| JweError::AuthenticationFailed)?;
    let tag_at = ciphertext_and_tag
        .len()
        .checked_sub(16)
        .ok_or(JweError::Malformed)?;
    let (ciphertext, tag) = ciphertext_and_tag.split_at(tag_at);
    Ok(format!(
        "{protected}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

fn decrypt_ecdh_es(
    compact: &str,
    recipient: &SecretKey,
    expected_kid: Option<&str>,
) -> Result<Vec<u8>, JweError> {
    let parts = compact.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || !parts[1].is_empty() {
        return Err(JweError::Malformed);
    }
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| JweError::Malformed)?,
    )
    .map_err(|_| JweError::Malformed)?;
    if header.get("alg").and_then(Value::as_str) != Some("ECDH-ES") {
        return Err(JweError::Unsupported);
    }
    let (enc, key_bits) = match header.get("enc").and_then(Value::as_str) {
        Some("A128GCM") => ("A128GCM", 128),
        Some("A256GCM") => ("A256GCM", 256),
        _ => return Err(JweError::Unsupported),
    };
    if let Some(expected_kid) = expected_kid
        && (header.get("kid").and_then(Value::as_str) != Some(expected_kid)
            || !matches!(
                header.get("cty").and_then(Value::as_str),
                Some("json" | "application/json")
            ))
    {
        return Err(JweError::Unsupported);
    }
    let ephemeral = parse_public_jwk(header.get("epk").ok_or(JweError::Malformed)?)?;
    let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
    let apu = decode_party_info(&header, "apu")?;
    let apv = decode_party_info(&header, "apv")?;
    let key = concat_kdf(
        shared.raw_secret_bytes().as_slice(),
        enc,
        &apu,
        &apv,
        key_bits,
    );
    let nonce: [u8; 12] = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| JweError::Malformed)?
        .try_into()
        .map_err(|_| JweError::Malformed)?;
    let mut ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|_| JweError::Malformed)?;
    let tag = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|_| JweError::Malformed)?;
    if tag.len() != 16 {
        return Err(JweError::Malformed);
    }
    ciphertext.extend_from_slice(&tag);
    let payload = Payload {
        msg: &ciphertext,
        aad: parts[0].as_bytes(),
    };
    let plaintext = match enc {
        "A128GCM" => Aes128Gcm::new_from_slice(&key)
            .map_err(|_| JweError::InvalidKey)?
            .decrypt((&nonce).into(), payload),
        "A256GCM" => Aes256Gcm::new_from_slice(&key)
            .map_err(|_| JweError::InvalidKey)?
            .decrypt((&nonce).into(), payload),
        _ => unreachable!("enc was validated above"),
    }
    .map_err(|_| JweError::AuthenticationFailed)?;
    match header.get("zip").and_then(Value::as_str) {
        None => Ok(plaintext),
        Some("DEF") => decompress_deflate(&plaintext),
        Some(_) => Err(JweError::Unsupported),
    }
}

fn decompress_deflate(compressed: &[u8]) -> Result<Vec<u8>, JweError> {
    const MAX_DECOMPRESSED_BYTES: u64 = 1_048_576;
    let mut decoder = DeflateDecoder::new(compressed);
    let mut output = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|_| JweError::InvalidCompression)?;
    if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(JweError::InvalidCompression);
    }
    Ok(output)
}

fn public_jwk(key: PublicKey) -> Value {
    let point = key.to_sec1_point(false);
    json!({
        "kty": "EC", "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed P-256 point has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed P-256 point has y")),
        "use": "enc", "alg": "ECDH-ES",
    })
}

fn parse_public_jwk(jwk: &Value) -> Result<PublicKey, JweError> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.get("alg").and_then(Value::as_str) != Some("ECDH-ES")
    {
        return Err(JweError::InvalidKey);
    }
    let x = decode_coordinate(jwk, "x")?;
    let y = decode_coordinate(jwk, "y")?;
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&point).map_err(|_| JweError::InvalidKey)
}

fn decode_coordinate(jwk: &Value, name: &str) -> Result<[u8; 32], JweError> {
    URL_SAFE_NO_PAD
        .decode(
            jwk.get(name)
                .and_then(Value::as_str)
                .ok_or(JweError::InvalidKey)?,
        )
        .map_err(|_| JweError::InvalidKey)?
        .try_into()
        .map_err(|_| JweError::InvalidKey)
}

fn decode_party_info(header: &Value, name: &str) -> Result<Vec<u8>, JweError> {
    header
        .get(name)
        .map(|value| {
            URL_SAFE_NO_PAD
                .decode(value.as_str().ok_or(JweError::Malformed)?)
                .map_err(|_| JweError::Malformed)
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn concat_kdf(
    shared_secret: &[u8],
    algorithm: &str,
    apu: &[u8],
    apv: &[u8],
    key_bits: u32,
) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(1_u32.to_be_bytes());
    digest.update(shared_secret);
    digest.update((algorithm.len() as u32).to_be_bytes());
    digest.update(algorithm.as_bytes());
    digest.update((apu.len() as u32).to_be_bytes());
    digest.update(apu);
    digest.update((apv.len() as u32).to_be_bytes());
    digest.update(apv);
    digest.update(key_bits.to_be_bytes());
    digest.finalize()[..(key_bits / 8) as usize].to_vec()
}
