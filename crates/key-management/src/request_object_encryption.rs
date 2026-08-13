use std::io::ErrorKind;

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest as _;

use crate::{
    KeyManager,
    crypto::{aes_256_gcm_decrypt, rsa_oaep_sha256_decrypt},
    model::KeySettings,
    serialization::write_private_key_pem_if_absent,
};

pub(crate) const REQUEST_OBJECT_ENCRYPTION_KEY_FILE: &str = "request-object-encryption.pem";

pub(crate) async fn ensure_request_object_encryption_key(
    settings: &KeySettings,
) -> anyhow::Result<()> {
    let path = settings.keys_dir.join(REQUEST_OBJECT_ENCRYPTION_KEY_FILE);
    match tokio::fs::metadata(&path).await {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let pem = String::from_utf8(crate::crypto::generate_rsa_pkcs8_pem(3072)?)
        .context("generated request object key was not PEM text")?;
    write_private_key_pem_if_absent(&path, &pem).await
}

pub(crate) async fn load_request_object_decryption_key(
    settings: &KeySettings,
) -> anyhow::Result<Vec<u8>> {
    let path = settings.keys_dir.join(REQUEST_OBJECT_ENCRYPTION_KEY_FILE);
    let pem = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    crate::crypto::validate_rsa_pkcs8_pem(&pem)
        .context("request object decryption key is not valid PKCS#8 PEM")?;
    Ok(pem)
}

pub(crate) fn request_object_encryption_jwk(private_key_pem: &[u8]) -> anyhow::Result<Value> {
    let (n, e, public_der) = crate::crypto::rsa_public_components_from_pem(private_key_pem)?;
    let kid = format!(
        "request-object-{}",
        URL_SAFE_NO_PAD.encode(&sha2::Sha256::digest(&public_der)[..12])
    );
    Ok(serde_json::json!({
        "kty": "RSA",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(n),
        "e": URL_SAFE_NO_PAD.encode(e)
    }))
}

#[derive(Deserialize)]
struct ProtectedHeader {
    alg: String,
    enc: String,
    kid: String,
    cty: Option<String>,
}

impl KeyManager {
    /// Decrypts an RSA-OAEP-256/A256GCM Request Object and returns the nested JWT.
    ///
    /// The dedicated recipient key is intentionally separate from protocol
    /// signing keys. Reusing a signing key here would collapse two independent
    /// key purposes and make rotation or external signing unsafe.
    pub fn decrypt_request_object(&self, compact: &str) -> anyhow::Result<String> {
        let mut segments = compact.split('.');
        let protected = segments
            .next()
            .ok_or_else(|| anyhow!("missing protected header"))?;
        let encrypted_key = segments
            .next()
            .ok_or_else(|| anyhow!("missing encrypted key"))?;
        let iv = segments.next().ok_or_else(|| anyhow!("missing iv"))?;
        let ciphertext = segments
            .next()
            .ok_or_else(|| anyhow!("missing ciphertext"))?;
        let tag = segments
            .next()
            .ok_or_else(|| anyhow!("missing authentication tag"))?;
        if segments.next().is_some() {
            return Err(anyhow!("request object JWE must contain five segments"));
        }

        let header: ProtectedHeader = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(protected)
                .context("invalid protected header encoding")?,
        )
        .context("invalid protected header")?;
        let generation = self.inner.generation.load();
        let expected = &generation.loaded.request_object_encryption_jwk;
        if header.alg != "RSA-OAEP-256"
            || header.enc != "A256GCM"
            || header.cty.as_deref() != Some("JWT")
            || expected.get("kid").and_then(serde_json::Value::as_str) != Some(header.kid.as_str())
        {
            return Err(anyhow!("unsupported request object JWE header"));
        }

        let encrypted_key = URL_SAFE_NO_PAD
            .decode(encrypted_key)
            .context("invalid encrypted key encoding")?;
        let cek = rsa_oaep_sha256_decrypt(
            &generation.loaded.request_object_decryption_key,
            &encrypted_key,
        )?;
        if cek.len() != 32 {
            return Err(anyhow!(
                "request object content encryption key must be 256 bits"
            ));
        }

        let iv = URL_SAFE_NO_PAD.decode(iv).context("invalid iv encoding")?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(ciphertext)
            .context("invalid ciphertext encoding")?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .context("invalid tag encoding")?;
        if iv.len() != 12 || tag.len() != 16 {
            return Err(anyhow!("invalid A256GCM iv or tag length"));
        }
        let plaintext = aes_256_gcm_decrypt(&cek, &iv, protected.as_bytes(), &ciphertext, &tag)
            .context("request object authentication failed")?;
        String::from_utf8(plaintext).context("request object plaintext is not UTF-8")
    }
}

#[cfg(test)]
#[path = "../tests/unit/request_object_encryption.rs"]
mod tests;
