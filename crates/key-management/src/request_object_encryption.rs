use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
    symm::{Cipher, decrypt_aead},
};
use serde::Deserialize;

use crate::KeyManager;

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

        let private_key =
            PKey::private_key_from_pem(&generation.loaded.request_object_decryption_key)
                .context("invalid request object decryption key")?;
        let mut decrypter = Decrypter::new(&private_key)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
        let encrypted_key = URL_SAFE_NO_PAD
            .decode(encrypted_key)
            .context("invalid encrypted key encoding")?;
        let mut cek = vec![0_u8; decrypter.decrypt_len(&encrypted_key)?];
        let cek_len = decrypter.decrypt(&encrypted_key, &mut cek)?;
        cek.truncate(cek_len);
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
        let plaintext = decrypt_aead(
            Cipher::aes_256_gcm(),
            &cek,
            Some(&iv),
            protected.as_bytes(),
            &ciphertext,
            &tag,
        )
        .context("request object authentication failed")?;
        String::from_utf8(plaintext).context("request object plaintext is not UTF-8")
    }
}

#[cfg(test)]
#[path = "../tests/unit/request_object_encryption.rs"]
mod tests;
