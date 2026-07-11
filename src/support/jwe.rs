//! Client-bound compact JWE construction for encrypted OAuth and OIDC responses.

use super::prelude::*;
use super::{SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS};
use openssl::{
    bn::BigNum,
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    symm::{Cipher, encrypt_aead},
};

pub(crate) struct ClientJweKey<'a> {
    pub(crate) kid: &'a str,
    pub(crate) alg: &'a str,
    pub(crate) enc: &'a str,
    pub(crate) jwk: &'a Value,
}

#[derive(Clone, Copy)]
pub(crate) enum JwePayloadKind {
    Claims,
    NestedJwt,
}

pub(crate) fn client_jwe_key<'a>(
    jwks: Option<&'a Value>,
    alg: Option<&'a str>,
    enc: Option<&'a str>,
    response_name: &str,
) -> anyhow::Result<Option<ClientJweKey<'a>>> {
    let Some(alg) = alg else {
        if enc.is_some() {
            anyhow::bail!("{response_name} JWE enc configured without alg");
        }
        return Ok(None);
    };
    let Some(enc) = enc else {
        anyhow::bail!("{response_name} JWE alg configured without enc");
    };
    if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg) {
        anyhow::bail!("unsupported {response_name} JWE alg");
    }
    if !SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.contains(&enc) {
        anyhow::bail!("unsupported {response_name} JWE enc");
    }
    let keys = jwks
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("{response_name} JWE client has no jwks"))?;
    let mut matching_keys = keys.iter().filter(|key| {
        key.get("use").and_then(Value::as_str) == Some("enc")
            && key.get("alg").and_then(Value::as_str) == Some(alg)
    });
    let Some(jwk) = matching_keys.next() else {
        anyhow::bail!("{response_name} JWE client has no matching encryption key");
    };
    if matching_keys.next().is_some() {
        anyhow::bail!("{response_name} JWE client has ambiguous encryption keys");
    }
    let kid = jwk
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{response_name} JWE key has no kid"))?;
    Ok(Some(ClientJweKey { kid, alg, enc, jwk }))
}

pub(crate) fn encrypt_compact_jwe(
    key: &ClientJweKey<'_>,
    plaintext: &[u8],
    payload_kind: JwePayloadKind,
) -> anyhow::Result<String> {
    if key.alg != "RSA-OAEP-256" || key.enc != "A256GCM" {
        anyhow::bail!("unsupported client JWE policy");
    }
    let mut protected_header = serde_json::Map::from_iter([
        ("alg".to_owned(), json!(key.alg)),
        ("enc".to_owned(), json!(key.enc)),
        ("kid".to_owned(), json!(key.kid)),
    ]);
    match payload_kind {
        JwePayloadKind::Claims => {
            protected_header.insert("typ".to_owned(), json!("JWT"));
        }
        JwePayloadKind::NestedJwt => {
            protected_header.insert("cty".to_owned(), json!("JWT"));
        }
    }
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected_header)?);
    let cek = rand::random::<[u8; 32]>();
    let iv = rand::random::<[u8; 12]>();
    let encrypted_key = rsa_oaep_256_encrypt_jwk(key.jwk, &cek)?;
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        protected.as_bytes(),
        plaintext,
        &mut tag,
    )?;
    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected,
        URL_SAFE_NO_PAD.encode(encrypted_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

fn rsa_oaep_256_encrypt_jwk(jwk: &Value, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let n = jwk
        .get("n")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("RSA JWE key missing n"))?;
    let e = jwk
        .get("e")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("RSA JWE key missing e"))?;
    let n = BigNum::from_slice(&URL_SAFE_NO_PAD.decode(n)?)?;
    let e = BigNum::from_slice(&URL_SAFE_NO_PAD.decode(e)?)?;
    let rsa = Rsa::from_public_components(n, e)?;
    let public_key = PKey::from_rsa(rsa)?;
    let mut encrypter = Encrypter::new(&public_key)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let mut encrypted = vec![0; encrypter.encrypt_len(plaintext)?];
    let len = encrypter.encrypt(plaintext, &mut encrypted)?;
    encrypted.truncate(len);
    Ok(encrypted)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/jwe.rs"]
mod tests;
