//! Keyset serialization, validation, and key-material encoding.
//!
//! The keyset is persisted as JSON for compatibility with existing deployments.  This module
//! owns the schema boundary and the atomic file primitives used by lifecycle and registration
//! operations; callers never write a partially updated keyset or private key directly.

use std::collections::{BTreeSet, HashSet};
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, anyhow};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use nazo_auth::SigningPurpose;
use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey as EncodeEcPrivateKey};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::model::{KeyRecord, KeyRecordStatus, KeySettings};

pub(crate) async fn list_keys(settings: &KeySettings) -> anyhow::Result<Vec<KeyRecord>> {
    let value = load_keyset_json(settings).await?;
    let active_kid = keyset_active_kid(&value)?;
    let now = Utc::now();
    keyset_keys(&value)?
        .iter()
        .map(|key| {
            let kid = key
                .get("kid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("key entry missing kid"))?;
            let retire_at = key_entry_retire_at(key)?;
            let status = if kid == active_kid {
                KeyRecordStatus::Active
            } else if retire_at.is_some_and(|retire_at| retire_at <= now) {
                KeyRecordStatus::Retired
            } else if retire_at.is_some() {
                KeyRecordStatus::Grace
            } else if key.get("purposes").is_some() {
                KeyRecordStatus::PurposeScoped
            } else {
                KeyRecordStatus::Prepublished
            };
            Ok(KeyRecord {
                kid: kid.to_owned(),
                status,
                algorithm: key
                    .get("alg")
                    .and_then(Value::as_str)
                    .unwrap_or("EdDSA")
                    .to_owned(),
                backend: key_entry_backend(key).to_owned(),
                locator: key
                    .get("file")
                    .or_else(|| key.get("key_ref"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                retire_at: key
                    .get("retire_at")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect()
}

pub(crate) async fn load_keyset_json(settings: &KeySettings) -> anyhow::Result<Value> {
    let path = settings.keys_dir.join("keyset.json");
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    validate_keyset_json(&value)?;
    Ok(value)
}

pub(crate) fn validate_keyset_json(value: &Value) -> anyhow::Result<()> {
    let active = keyset_active_kid(value)?;
    let mut seen = HashSet::new();
    let mut active_exists = false;
    for key in keyset_keys(value)? {
        let kid = key
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("key entry missing kid"))?;
        if !seen.insert(kid) {
            anyhow::bail!("duplicate key kid {kid}");
        }
        let backend = key_entry_backend(key);
        let alg = key.get("alg").and_then(Value::as_str).unwrap_or("EdDSA");
        if signing_algorithm_from_name(alg).is_none() {
            anyhow::bail!("key {kid} has unsupported alg {alg}");
        }
        match backend {
            "local-pem" => {
                if key.get("file").and_then(Value::as_str).is_none() {
                    anyhow::bail!("key {kid} missing file");
                }
            }
            "external-command" => {
                if key.get("key_ref").and_then(Value::as_str).is_none() {
                    anyhow::bail!("key {kid} missing key_ref");
                }
                validate_external_public_jwk_metadata(key, kid, alg)?;
            }
            _ => anyhow::bail!("key {kid} has unsupported backend {backend}"),
        }
        let purposes = key_entry_purposes(key)?;
        if purposes.is_some() && backend != "local-pem" {
            anyhow::bail!("purpose-scoped key {kid} must use local-pem backend");
        }
        let retire_at = key_entry_retire_at(key)?;
        if kid == active {
            active_exists = true;
            if purposes.is_some() {
                anyhow::bail!("active rotation key {kid} cannot be purpose-scoped");
            }
            if retire_at.is_some() {
                anyhow::bail!("active key {kid} cannot have retire_at");
            }
        }
    }
    if !active_exists {
        anyhow::bail!("active key {active} does not exist");
    }
    Ok(())
}

pub(crate) fn key_entry_purposes(
    entry: &Value,
) -> anyhow::Result<Option<BTreeSet<SigningPurpose>>> {
    let Some(raw) = entry.get("purposes") else {
        return Ok(None);
    };
    let values = raw
        .as_array()
        .ok_or_else(|| anyhow!("purposes must be an array"))?;
    if values.is_empty() {
        anyhow::bail!("purposes must not be empty");
    }
    let mut purposes = BTreeSet::new();
    for value in values {
        let name = value
            .as_str()
            .ok_or_else(|| anyhow!("purpose names must be strings"))?;
        let purpose = SigningPurpose::from_name(name)
            .ok_or_else(|| anyhow!("unsupported signing purpose {name}"))?;
        if !purposes.insert(purpose) {
            anyhow::bail!("duplicate signing purpose {name}");
        }
    }
    Ok(Some(purposes))
}

fn validate_external_public_jwk_metadata(key: &Value, kid: &str, alg: &str) -> anyhow::Result<()> {
    let public_jwk = key
        .get("public_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("key {kid} missing public_jwk"))?;
    if public_jwk
        .get("kid")
        .and_then(Value::as_str)
        .is_some_and(|value| value != kid)
    {
        anyhow::bail!("key {kid} public_jwk kid mismatch");
    }
    if public_jwk
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|value| value != alg)
    {
        anyhow::bail!("key {kid} public_jwk alg mismatch");
    }
    if public_jwk
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|value| value != "sig")
    {
        anyhow::bail!("key {kid} public_jwk use must be sig");
    }
    reject_private_jwk_members(public_jwk)?;
    let algorithm = signing_algorithm_from_name(alg)
        .ok_or_else(|| anyhow!("key {kid} has unsupported alg {alg}"))?;
    if crate::external::decoding_key_from_public_jwk(&Value::Object(public_jwk.clone()), algorithm)
        .is_none()
    {
        anyhow::bail!("key {kid} public_jwk is not usable for {alg} verification");
    }
    Ok(())
}

pub(crate) fn keyset_active_kid(value: &Value) -> anyhow::Result<&str> {
    value
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset.json missing active_kid"))
}

pub(crate) fn keyset_keys(value: &Value) -> anyhow::Result<&Vec<Value>> {
    value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keyset.json missing keys array"))
}

pub(crate) fn keyset_keys_mut(value: &mut Value) -> anyhow::Result<&mut Vec<Value>> {
    value
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("keyset.json missing keys array"))
}

pub(crate) async fn write_json_atomic(path: &Path, value: &Value) -> anyhow::Result<()> {
    let body = serde_json::to_string_pretty(value)?;
    write_file_atomic(path, body.as_bytes()).await
}

pub(crate) async fn write_private_key_pem_atomic(path: &Path, pem: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target file must have a parent directory"))?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("private-key"),
        Uuid::now_v7()
    ));
    let result = write_private_key_temp(&tmp_path, pem.as_bytes()).await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(error);
    }
    if let Err(error) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(error).with_context(|| {
            format!(
                "failed to atomically rename private key {} to {}",
                tmp_path.display(),
                path.display()
            )
        });
    }
    sync_parent_directory(parent).await?;
    Ok(())
}

pub(crate) async fn write_private_key_pem_if_absent(path: &Path, pem: &str) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target file must have a parent directory"))?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("private-key"),
        Uuid::now_v7()
    ));
    let prepare_result = async { write_private_key_temp(&tmp_path, pem.as_bytes()).await }.await;
    if let Err(error) = prepare_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(error);
    }
    let link_result = tokio::fs::hard_link(&tmp_path, path).await;
    let cleanup_result = tokio::fs::remove_file(&tmp_path).await;
    match link_result {
        Ok(()) => {
            cleanup_result.with_context(|| {
                format!(
                    "failed to remove private-key temporary file {}",
                    tmp_path.display()
                )
            })?;
            sync_parent_directory(parent).await?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let _ = cleanup_result;
            Ok(())
        }
        Err(error) => {
            let _ = cleanup_result;
            Err(error).with_context(|| {
                format!("failed to atomically create private key {}", path.display())
            })
        }
    }
}

async fn write_private_key_temp(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    #[cfg(not(unix))]
    set_private_key_permissions(path).await?;
    Ok(())
}

#[cfg(unix)]
async fn sync_parent_directory(path: &Path) -> anyhow::Result<()> {
    tokio::fs::File::open(path).await?.sync_all().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn sync_parent_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

async fn write_file_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("target file must have a parent directory"))?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("keyset"),
        Uuid::now_v7()
    ));
    let prepare_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await
    }
    .await;
    if let Err(error) = prepare_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(error)
            .with_context(|| format!("failed to durably prepare {}", tmp_path.display()));
    }
    if let Err(error) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(error).with_context(|| {
            format!(
                "failed to atomically rename {} to {}",
                tmp_path.display(),
                path.display()
            )
        });
    }
    sync_parent_directory(parent).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_private_key_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub(crate) struct GeneratedKeyMaterial {
    pub(crate) private_pkcs8_der: Vec<u8>,
}

pub(crate) fn generate_key_material(
    alg: jsonwebtoken::Algorithm,
) -> anyhow::Result<GeneratedKeyMaterial> {
    let private_pkcs8_der = match alg {
        jsonwebtoken::Algorithm::EdDSA => {
            let seed: [u8; 32] = rand::random();
            ed25519_pkcs8_private_der(&seed)
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            crate::crypto::generate_rsa_pkcs1_der(2048)?
        }
        jsonwebtoken::Algorithm::ES256 => {
            let secret_key = p256::SecretKey::try_generate()?;
            secret_key.to_pkcs8_der()?.as_bytes().to_vec()
        }
        _ => anyhow::bail!("unsupported server signing alg"),
    };
    Ok(GeneratedKeyMaterial { private_pkcs8_der })
}

fn public_key_from_ed_private_der(private_pkcs8_der: &[u8]) -> Option<[u8; 32]> {
    let seed = ed25519_seed_from_pkcs8(private_pkcs8_der)?;
    Some(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

pub(crate) fn public_jwk_from_private_der(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
) -> anyhow::Result<Value> {
    let mut jwk = match alg {
        jsonwebtoken::Algorithm::EdDSA => {
            let public_key = public_key_from_ed_private_der(private_pkcs8_der)
                .ok_or_else(|| anyhow!("invalid Ed25519 private key"))?;
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public_key),
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid
            })
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            public_jwk_from_encoding_key(
                kid,
                alg,
                &jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der),
            )?
        }
        jsonwebtoken::Algorithm::ES256 => public_jwk_from_encoding_key(
            kid,
            alg,
            &jsonwebtoken::EncodingKey::from_ec_der(private_pkcs8_der),
        )?,
        _ => anyhow::bail!("unsupported server signing alg"),
    };
    jwk["kid"] = json!(kid);
    jwk["use"] = json!("sig");
    Ok(jwk)
}

fn public_jwk_from_encoding_key(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    encoding_key: &jsonwebtoken::EncodingKey,
) -> anyhow::Result<Value> {
    let mut jwk = Jwk::from_encoding_key(encoding_key, alg)?;
    jwk.common.key_id = Some(kid.to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    Ok(serde_json::to_value(jwk)?)
}

pub fn signing_algorithm_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::EdDSA => Some("EdDSA"),
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        _ => None,
    }
}

pub fn signing_algorithm_from_name(value: &str) -> Option<jsonwebtoken::Algorithm> {
    match value {
        "EdDSA" => Some(jsonwebtoken::Algorithm::EdDSA),
        "RS256" => Some(jsonwebtoken::Algorithm::RS256),
        "ES256" => Some(jsonwebtoken::Algorithm::ES256),
        "PS256" => Some(jsonwebtoken::Algorithm::PS256),
        _ => None,
    }
}

pub(crate) fn key_entry_algorithm(entry: &Value) -> anyhow::Result<jsonwebtoken::Algorithm> {
    entry
        .get("alg")
        .and_then(Value::as_str)
        .map(signing_algorithm_from_name)
        .unwrap_or(Some(jsonwebtoken::Algorithm::EdDSA))
        .ok_or_else(|| anyhow!("unsupported signing alg"))
}

pub(crate) fn key_entry_backend(entry: &Value) -> &str {
    entry
        .get("backend")
        .and_then(Value::as_str)
        .unwrap_or("local-pem")
}

pub(crate) fn reject_private_jwk_members(
    jwk: &serde_json::Map<String, Value>,
) -> anyhow::Result<()> {
    const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(member) = PRIVATE_JWK_MEMBERS
        .iter()
        .find(|member| jwk.contains_key(**member))
    {
        anyhow::bail!(
            "public_jwk must not contain private or symmetric key material member {member}"
        );
    }
    Ok(())
}

pub(crate) fn external_public_jwk(entry: &Value) -> anyhow::Result<Value> {
    let kid = entry
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("key entry missing kid"))?;
    let alg = entry.get("alg").and_then(Value::as_str).unwrap_or("EdDSA");
    let jwk = entry
        .get("public_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("public_jwk must be an object"))?;
    reject_private_jwk_members(jwk)?;
    let mut jwk = Value::Object(jwk.clone());
    match jwk.get("kid").and_then(Value::as_str) {
        Some(value) if value != kid => anyhow::bail!("public_jwk kid does not match key entry"),
        Some(_) => {}
        None => jwk["kid"] = json!(kid),
    }
    match jwk.get("alg").and_then(Value::as_str) {
        Some(value) if value != alg => anyhow::bail!("public_jwk alg does not match key entry"),
        Some(_) => {}
        None => jwk["alg"] = json!(alg),
    }
    match jwk.get("use").and_then(Value::as_str) {
        Some("sig") => {}
        Some(_) => anyhow::bail!("public_jwk use must be sig"),
        None => jwk["use"] = json!("sig"),
    }
    Ok(jwk)
}

pub(crate) fn key_entry_retire_at(entry: &Value) -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(value) = entry.get("retire_at") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("retire_at must be RFC3339 or null"))?;
    let retire_at = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("retire_at is not RFC3339: {raw}"))?
        .with_timezone(&Utc);
    Ok(Some(retire_at))
}

pub(crate) fn key_entry_created_at(entry: &Value) -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(value) = entry.get("created_at") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("created_at must be RFC3339 or null"))?;
    let created_at = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("created_at is not RFC3339: {raw}"))?
        .with_timezone(&Utc);
    Ok(Some(created_at))
}

pub(crate) fn ed25519_pkcs8_private_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    der.extend_from_slice(seed);
    der
}

pub(crate) fn ed25519_seed_from_pkcs8(der: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    if der.len() != PREFIX.len() + 32 || !der.starts_with(PREFIX) {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[PREFIX.len()..]);
    Some(seed)
}

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

pub(crate) fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    STANDARD.decode(body).ok()
}
