//! Client-bound compact JWE construction for encrypted OAuth and OIDC responses.

use crate::adapters::security::{
    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
};
use aws_lc_rs::key_wrap::{AES_128, AES_256, AesKek, KeyWrap};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nazo_auth::{ClientJweKeyManagement, client_jwe_key_management_from_name};
use openssl::{
    bn::BigNum,
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    symm::{Cipher, encrypt_aead},
};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) struct ClientJweKey<'a> {
    pub(crate) kid: Option<&'a str>,
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
        .filter(|kid| !kid.trim().is_empty());
    Ok(Some(ClientJweKey { kid, alg, enc, jwk }))
}

pub(crate) fn encrypt_compact_jwe(
    key: &ClientJweKey<'_>,
    plaintext: &[u8],
    payload_kind: JwePayloadKind,
) -> anyhow::Result<String> {
    let Some(alg) = client_jwe_key_management_from_name(key.alg) else {
        anyhow::bail!("unsupported client JWE policy");
    };
    if key.enc != "A256GCM" {
        anyhow::bail!("unsupported client JWE enc");
    }
    let mut protected_header = serde_json::Map::from_iter([
        ("alg".to_owned(), json!(key.alg)),
        ("enc".to_owned(), json!(key.enc)),
    ]);
    if let Some(kid) = key.kid {
        protected_header.insert("kid".to_owned(), json!(kid));
    }
    match payload_kind {
        JwePayloadKind::Claims => {
            protected_header.insert("typ".to_owned(), json!("JWT"));
        }
        JwePayloadKind::NestedJwt => {
            protected_header.insert("cty".to_owned(), json!("JWT"));
        }
    }
    let (cek, encrypted_key) = match alg {
        ClientJweKeyManagement::RsaOaep256 => {
            let cek = rand::random::<[u8; 32]>();
            let encrypted_key = rsa_oaep_256_encrypt_jwk(key.jwk, &cek)?;
            (cek, encrypted_key)
        }
        ClientJweKeyManagement::EcdhEsDirect => {
            let recipient = parse_p256_public_jwk(key.jwk)?;
            let ephemeral = SecretKey::generate();
            protected_header.insert("epk".to_owned(), public_p256_jwk(ephemeral.public_key()));
            let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected_header)?);
            return encrypt_compact_jwe_with_cek(
                &protected,
                &ecdh_derive_key(&ephemeral, &recipient, key.enc, 256)?,
                &[],
                plaintext,
            );
        }
        ClientJweKeyManagement::EcdhEsA128Kw | ClientJweKeyManagement::EcdhEsA256Kw => {
            let recipient = parse_p256_public_jwk(key.jwk)?;
            let ephemeral = SecretKey::generate();
            protected_header.insert("epk".to_owned(), public_p256_jwk(ephemeral.public_key()));
            let kek_bits = match alg {
                ClientJweKeyManagement::EcdhEsA128Kw => 128,
                ClientJweKeyManagement::EcdhEsA256Kw => 256,
                _ => unreachable!("alg was matched above"),
            };
            let kek = ecdh_derive_key(&ephemeral, &recipient, alg.name(), kek_bits)?;
            let cek = rand::random::<[u8; 32]>();
            let encrypted_key = aes_key_wrap(&kek, &cek)?;
            (cek, encrypted_key)
        }
    };
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected_header)?);
    encrypt_compact_jwe_with_cek(&protected, &cek, &encrypted_key, plaintext)
}

fn encrypt_compact_jwe_with_cek(
    protected: &str,
    cek: &[u8],
    encrypted_key: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<String> {
    let iv = rand::random::<[u8; 12]>();
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        cek,
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

fn parse_p256_public_jwk(jwk: &Value) -> anyhow::Result<PublicKey> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.get("d").is_some()
    {
        anyhow::bail!("ECDH JWE key must be a public P-256 key");
    }
    let x = decode_p256_coordinate(jwk, "x")?;
    let y = decode_p256_coordinate(jwk, "y")?;
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&point).map_err(|error| anyhow::anyhow!(error))
}

fn decode_p256_coordinate(jwk: &Value, name: &str) -> anyhow::Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(
            jwk.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("P-256 JWE key missing {name}"))?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("P-256 JWE key {name} has invalid length"))
}

fn public_p256_jwk(key: PublicKey) -> Value {
    let point = key.to_sec1_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed P-256 point has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed P-256 point has y")),
    })
}

fn ecdh_derive_key(
    ephemeral: &SecretKey,
    recipient: &PublicKey,
    algorithm: &str,
    key_bits: u32,
) -> anyhow::Result<Vec<u8>> {
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    Ok(concat_kdf(
        shared.raw_secret_bytes().as_slice(),
        algorithm,
        &[],
        &[],
        key_bits,
    ))
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

fn aes_key_wrap(kek: &[u8], cek: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = vec![0_u8; cek.len() + 8];
    let wrapped = match kek.len() {
        16 => AesKek::new(&AES_128, kek)
            .map_err(|_| anyhow::anyhow!("invalid A128KW key"))?
            .wrap(cek, &mut output),
        32 => AesKek::new(&AES_256, kek)
            .map_err(|_| anyhow::anyhow!("invalid A256KW key"))?
            .wrap(cek, &mut output),
        _ => anyhow::bail!("unsupported AES-KW key length"),
    }
    .map_err(|_| anyhow::anyhow!("AES-KW wrapping failed"))?;
    Ok(wrapped.to_vec())
}

#[cfg(test)]
#[path = "../../tests/unit/domain/client_jwe.rs"]
mod tests;
