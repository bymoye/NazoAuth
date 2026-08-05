//! JWT JWK/PEM 密钥管理。
// 负责加载、生成和编码 OAuth/OIDC 签名密钥。

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::DateTime;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::{Jwk, PublicKeyUse};
use nazo_auth::SigningPurpose;
use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey as EncodeEcPrivateKey};
use sha2::Digest as _;

use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::model::{
    ActiveSigningKey, ExternalKeyRegistration, ExternalSigningKey, KeyHandle, KeyRecord,
    KeyRecordStatus, KeySettings, KeyState, LoadedKeyset, LocalKeyRegistration, ManagedKey,
    StoredVerificationKey,
};

const OIDC_DEFAULT_ID_TOKEN_SIGNING_ALG: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::RS256;
const FAPI_ID_TOKEN_SIGNING_ALG: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::PS256;
const REQUEST_OBJECT_ENCRYPTION_KEY_FILE: &str = "request-object-encryption.pem";

pub(crate) async fn load_or_create_keyset(settings: &KeySettings) -> anyhow::Result<LoadedKeyset> {
    tokio::fs::create_dir_all(&settings.keys_dir).await?;
    let keyset_path = settings.keys_dir.join("keyset.json");
    if try_load_keyset(settings, &keyset_path).await?.is_some() {
        maintain_keyset_lifecycle(settings, &keyset_path).await?;
        if let Some(keyset) = try_load_keyset(settings, &keyset_path).await? {
            return Ok(keyset);
        }
        anyhow::bail!("keyset.json disappeared during signing key lifecycle maintenance");
    } else {
        create_new_keyset(settings).await
    }
}

pub(crate) async fn maintain_keyset_lifecycle(
    settings: &KeySettings,
    keyset_path: &Path,
) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(keyset_path)
        .await
        .with_context(|| format!("failed to read {}", keyset_path.display()))?;
    let mut payload = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("failed to parse {}", keyset_path.display()))?;
    let now = Utc::now();
    let Some(active_kid) = payload
        .get("active_kid")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return Ok(());
    };
    let Some(active_index) = payload
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter()
                .position(|entry| entry.get("kid").and_then(Value::as_str) == Some(&active_kid))
        })
    else {
        return Ok(());
    };
    let mut changed = false;
    let mut new_active_kid = None;
    let (active_alg, active_backend) = {
        let Some(keys) = payload.get_mut("keys").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        let active_entry = &mut keys[active_index];
        if key_entry_created_at(active_entry)?.is_none() {
            active_entry["created_at"] = json!(timestamp(now));
            changed = true;
        }
        let active_created_at = key_entry_created_at(&keys[active_index])?
            .ok_or_else(|| anyhow!("active key created_at could not be determined"))?;
        let current_active_alg = key_entry_algorithm(&keys[active_index])?;
        let active_backend = key_entry_backend(&keys[active_index]).to_owned();
        let rotation_interval = settings.rotation_interval;
        let prepublish_window = settings.prepublish_window;
        let rotation_due_at = active_created_at + rotation_interval;
        let prepublish_due_at = rotation_due_at - prepublish_window;
        let candidate_index =
            find_prepublished_candidate(settings, keys, &active_kid, current_active_alg, now)?;
        if now >= rotation_due_at {
            if let Some(candidate_index) = candidate_index {
                let candidate_created_at = key_entry_created_at(&keys[candidate_index])?
                    .ok_or_else(|| anyhow!("prepublished key missing created_at"))?;
                if candidate_created_at + prepublish_window <= now {
                    let next_kid = keys[candidate_index]
                        .get("kid")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("prepublished key missing kid"))?
                        .to_owned();
                    activate_prepublished_key(settings, keys, &active_kid, &next_kid, now);
                    new_active_kid = Some(next_kid);
                    changed = true;
                }
            } else if active_backend == "local-pem" {
                let entry =
                    create_prepublished_local_key_entry(settings, current_active_alg, now).await?;
                keys.push(entry);
                changed = true;
            }
        } else if now >= prepublish_due_at
            && candidate_index.is_none()
            && active_backend == "local-pem"
        {
            let entry =
                create_prepublished_local_key_entry(settings, current_active_alg, now).await?;
            keys.push(entry);
            changed = true;
        }
        (current_active_alg, active_backend)
    };
    if active_backend == "local-pem" {
        let Some(keys) = payload.get_mut("keys").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        for algorithm in [OIDC_DEFAULT_ID_TOKEN_SIGNING_ALG, FAPI_ID_TOKEN_SIGNING_ALG] {
            if algorithm != active_alg && !has_live_protocol_key_for_alg(keys, algorithm, now)? {
                let entry = create_protocol_signing_key_entry(settings, algorithm, now).await?;
                keys.push(entry);
                changed = true;
            }
        }
    }
    if let Some(keys) = payload.get_mut("keys").and_then(Value::as_array_mut) {
        for entry in keys {
            let Some(purposes) = entry.get_mut("purposes").and_then(Value::as_array_mut) else {
                continue;
            };
            let protocol_response_key = purposes.iter().any(|value| value == "id_token")
                && purposes.iter().any(|value| value == "jarm");
            if protocol_response_key && !purposes.iter().any(|value| value == "introspection") {
                purposes.push(json!("introspection"));
                changed = true;
            }
        }
    }
    if let Some(next_kid) = new_active_kid {
        payload["active_kid"] = json!(next_kid);
    }

    if changed {
        write_json_atomic(keyset_path, &payload).await?;
    }
    Ok(())
}

fn find_prepublished_candidate(
    settings: &KeySettings,
    keys: &[Value],
    active_kid: &str,
    active_alg: jsonwebtoken::Algorithm,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<usize>> {
    let mut candidate = None;
    for (index, entry) in keys.iter().enumerate() {
        if entry.get("kid").and_then(Value::as_str) == Some(active_kid) {
            continue;
        }
        if entry.get("purposes").is_some() {
            continue;
        }
        if key_entry_retire_at(entry)?.is_some() || key_entry_algorithm(entry)? != active_alg {
            continue;
        }
        let backend = key_entry_backend(entry);
        if backend == "external-command" && settings.external_command.is_empty() {
            continue;
        }
        if backend != "local-pem" && backend != "external-command" {
            continue;
        }
        let created_at = key_entry_created_at(entry)?.unwrap_or(now);
        match candidate {
            Some((_, selected_created_at)) if selected_created_at <= created_at => {}
            _ => candidate = Some((index, created_at)),
        }
    }
    Ok(candidate.map(|(index, _)| index))
}

fn has_live_protocol_key_for_alg(
    keys: &[Value],
    alg: jsonwebtoken::Algorithm,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    for entry in keys {
        let purposes = key_entry_purposes(entry)?;
        if !purposes.as_ref().is_some_and(|purposes| {
            purposes.contains(&SigningPurpose::IdToken) && purposes.contains(&SigningPurpose::Jarm)
        }) || key_entry_backend(entry) != "local-pem"
            || key_entry_algorithm(entry)? != alg
            || !entry
                .get("file")
                .and_then(Value::as_str)
                .is_some_and(|file| {
                    let trimmed = file.trim();
                    !trimmed.is_empty() && trimmed == file
                })
        {
            continue;
        }
        if key_entry_retire_at(entry)?.is_none_or(|retire_at| retire_at > now) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn create_protocol_signing_key_entry(
    settings: &KeySettings,
    alg: jsonwebtoken::Algorithm,
    now: DateTime<Utc>,
) -> anyhow::Result<Value> {
    let mut entry = create_prepublished_local_key_entry(settings, alg, now).await?;
    entry["purposes"] = json!([
        SigningPurpose::IdToken.as_str(),
        SigningPurpose::Jarm.as_str(),
        SigningPurpose::Introspection.as_str()
    ]);
    Ok(entry)
}

async fn create_prepublished_local_key_entry(
    settings: &KeySettings,
    alg: jsonwebtoken::Algorithm,
    now: DateTime<Utc>,
) -> anyhow::Result<Value> {
    let alg_name =
        signing_algorithm_name(alg).ok_or_else(|| anyhow!("unsupported server signing alg"))?;
    let private_pkcs8_der = generate_key_material(alg)?.private_pkcs8_der;
    let kid = format!("{}-{}", alg_name.to_ascii_lowercase(), Uuid::now_v7());
    let file_name = format!("{kid}.pem");
    let pem = der_to_pem(&private_pkcs8_der, "PRIVATE KEY");
    write_private_key_pem_atomic(&settings.keys_dir.join(&file_name), &pem).await?;
    Ok(json!({
        "kid": kid,
        "alg": alg_name,
        "file": file_name,
        "created_at": timestamp(now),
        "retire_at": null
    }))
}

fn activate_prepublished_key(
    settings: &KeySettings,
    keys: &mut [Value],
    previous_active_kid: &str,
    next_kid: &str,
    now: DateTime<Utc>,
) {
    let retire_at = timestamp(now + settings.verification_grace);
    for entry in keys {
        if entry.get("kid").and_then(Value::as_str) == Some(previous_active_kid) {
            entry["retire_at"] = json!(retire_at);
        } else if entry.get("kid").and_then(Value::as_str) == Some(next_kid) {
            entry["retire_at"] = Value::Null;
        }
    }
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub(crate) async fn try_load_keyset(
    settings: &KeySettings,
    keyset_path: &Path,
) -> anyhow::Result<Option<LoadedKeyset>> {
    let raw = match tokio::fs::read_to_string(keyset_path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", keyset_path.display()));
        }
    };
    let payload = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("failed to parse {}", keyset_path.display()))?;
    // A loaded keyset must be immediately usable for every advertised key
    // capability. Existing installations predate the dedicated Request Object
    // recipient key, so loading is also the atomic upgrade boundary.
    ensure_request_object_encryption_key(settings).await?;
    let active_kid = payload
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset.json missing active_kid"))?;
    let keys = payload
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keyset.json missing keys array"))?;
    let mut active_signing_key = None;
    let mut active_alg = None;
    let mut seen_kids = std::collections::HashSet::new();
    let mut verification_keys = Vec::new();

    for entry in keys {
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("keyset entry missing kid"))?;
        if !seen_kids.insert(kid) {
            anyhow::bail!("keyset.json contains duplicate kid {kid}");
        }
        let is_active = kid == active_kid;
        let retire_at = key_entry_retire_at(entry)
            .with_context(|| format!("keyset entry {kid} has invalid retire_at"))?;
        if is_active {
            if retire_at.is_some() {
                return Err(anyhow!(
                    "keyset.json active key {kid} cannot have retire_at"
                ));
            }
        } else if retire_at.is_some_and(|retire_at| retire_at <= Utc::now()) {
            continue;
        }

        let alg = key_entry_algorithm(entry)
            .with_context(|| format!("keyset entry {kid} has unsupported alg"))?;
        let backend = key_entry_backend(entry);
        let explicit_purposes = key_entry_purposes(entry)
            .with_context(|| format!("keyset entry {kid} has invalid purposes"))?;
        let (public_jwk, signing_key, handle) = match backend {
            "local-pem" => {
                let file_name = entry
                    .get("file")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("keyset entry {kid} missing file"))?;
                let raw_key = tokio::fs::read_to_string(settings.keys_dir.join(file_name))
                    .await
                    .with_context(|| {
                        format!("failed to read keyset entry {kid} from {file_name}")
                    })?;
                let der = pem_to_der(&raw_key)
                    .with_context(|| format!("keyset entry {kid} is not valid PEM"))?;
                let public_jwk =
                    public_jwk_from_private_der(kid, alg, &der).with_context(|| {
                        format!("keyset entry {kid} private key does not match alg")
                    })?;
                (
                    public_jwk,
                    Some(ActiveSigningKey::LocalPkcs8Der(der.clone())),
                    KeyHandle::Local(der),
                )
            }
            "external-command" => {
                let public_jwk = external_public_jwk(entry)
                    .with_context(|| format!("keyset entry {kid} missing public_jwk"))?;
                let key_ref = entry
                    .get("key_ref")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("keyset entry {kid} missing key_ref"))?;
                let signing_key = if is_active {
                    if settings.external_command.is_empty() {
                        anyhow::bail!(
                            "SIGNING_EXTERNAL_COMMAND is required for active external-command key {kid}"
                        );
                    }
                    Some(ActiveSigningKey::ExternalCommand(ExternalSigningKey {
                        command: Arc::new(settings.external_command.clone()),
                        key_ref: key_ref.to_owned(),
                        timeout: settings.external_timeout,
                    }))
                } else {
                    None
                };
                (
                    public_jwk,
                    signing_key,
                    KeyHandle::External {
                        key_ref: key_ref.to_owned(),
                    },
                )
            }
            _ => anyhow::bail!("keyset entry {kid} has unsupported backend {backend}"),
        };
        if is_active {
            active_signing_key = signing_key;
            active_alg = Some(alg);
        }
        verification_keys.push(StoredVerificationKey {
            public_jwk,
            managed: ManagedKey {
                kid: kid.to_owned(),
                algorithm: signing_algorithm_name(alg).unwrap().to_owned(),
                purposes: if let Some(purposes) = explicit_purposes.as_ref() {
                    purposes.clone()
                } else if is_active {
                    all_signing_purposes()
                } else {
                    BTreeSet::new()
                },
                state: if explicit_purposes.is_some() || is_active {
                    KeyState::Active
                } else if retire_at.is_some() {
                    KeyState::Grace
                } else {
                    KeyState::Prepublished
                },
                handle,
            },
        });
    }

    let request_object_decryption_key = load_request_object_decryption_key(settings).await?;
    let request_object_encryption_jwk =
        request_object_encryption_jwk(&request_object_decryption_key)?;
    Ok(Some(LoadedKeyset {
        active_kid: active_kid.to_owned(),
        active_alg: active_alg
            .ok_or_else(|| anyhow!("keyset.json active_kid does not reference a live key"))?,
        active_signing_key: active_signing_key
            .ok_or_else(|| anyhow!("keyset.json active_kid does not reference a live key"))?,
        verification_keys,
        request_object_decryption_key,
        request_object_encryption_jwk,
    }))
}

async fn ensure_request_object_encryption_key(settings: &KeySettings) -> anyhow::Result<()> {
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

async fn load_request_object_decryption_key(settings: &KeySettings) -> anyhow::Result<Vec<u8>> {
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
    Ok(json!({
        "kty": "RSA",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(n),
        "e": URL_SAFE_NO_PAD.encode(e)
    }))
}

pub(crate) async fn create_new_keyset(settings: &KeySettings) -> anyhow::Result<LoadedKeyset> {
    let now = Utc::now();
    let rs256 =
        create_prepublished_local_key_entry(settings, OIDC_DEFAULT_ID_TOKEN_SIGNING_ALG, now)
            .await?;
    let active_kid = rs256["kid"]
        .as_str()
        .ok_or_else(|| anyhow!("generated RS256 key missing kid"))?
        .to_owned();
    let ps256 = create_protocol_signing_key_entry(settings, FAPI_ID_TOKEN_SIGNING_ALG, now).await?;
    let payload = json!({
        "active_kid": active_kid,
        "keys": [rs256, ps256]
    });
    let keyset_path = settings.keys_dir.join("keyset.json");
    write_json_atomic(&keyset_path, &payload).await?;
    try_load_keyset(settings, &keyset_path)
        .await?
        .ok_or_else(|| anyhow!("newly created keyset could not be loaded"))
}

fn all_signing_purposes() -> BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::Introspection,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
        SigningPurpose::SecurityEvent,
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
#[path = "../tests/unit/store.rs"]
mod tests;

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

pub(crate) async fn register_external_key(
    settings: &KeySettings,
    registration: ExternalKeyRegistration,
) -> anyhow::Result<()> {
    let algorithm = signing_algorithm_name(registration.algorithm)
        .ok_or_else(|| anyhow!("unsupported signing alg"))?;
    let public_jwk_raw = tokio::fs::read_to_string(&registration.public_jwk_file)
        .await
        .with_context(|| format!("failed to read {}", registration.public_jwk_file.display()))?;
    let public_jwk: Value = serde_json::from_str(&public_jwk_raw)
        .with_context(|| format!("failed to parse {}", registration.public_jwk_file.display()))?;
    let path = settings.keys_dir.join("keyset.json");
    let mut keyset = if path.exists() {
        load_keyset_json(settings).await?
    } else {
        json!({"active_kid":registration.kid,"keys":[]})
    };
    if let Some(existing) = keyset_keys(&keyset)?
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(registration.kid.as_str()))
    {
        if existing.get("alg").and_then(Value::as_str) == Some(algorithm)
            && existing.get("key_ref").and_then(Value::as_str)
                == Some(registration.key_ref.as_str())
            && existing.get("public_jwk") == Some(&public_jwk)
        {
            return Ok(());
        }
        anyhow::bail!("external key kid already exists with different material");
    }
    keyset_keys_mut(&mut keyset)?.push(json!({
        "kid":registration.kid,
        "alg":algorithm,
        "backend":"external-command",
        "key_ref":registration.key_ref,
        "public_jwk":public_jwk,
        "created_at":Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "retire_at":null
    }));
    validate_keyset_json(&keyset)?;
    write_json_atomic(&path, &keyset).await
}

pub(crate) async fn register_local_key(
    settings: &KeySettings,
    registration: LocalKeyRegistration,
) -> anyhow::Result<String> {
    if registration.purposes.is_empty() {
        anyhow::bail!("purpose-scoped local key requires at least one signing purpose");
    }
    if registration.purposes.iter().any(|purpose| {
        !matches!(
            purpose,
            SigningPurpose::Credential | SigningPurpose::PresentationRequest
        )
    }) {
        anyhow::bail!(
            "purpose-scoped local keys are restricted to credential and presentation_request"
        );
    }
    let algorithm = signing_algorithm_name(registration.algorithm)
        .ok_or_else(|| anyhow!("unsupported signing alg"))?;
    let path = settings.keys_dir.join("keyset.json");
    let mut keyset = load_keyset_json(settings).await?;
    for key in keyset_keys(&keyset)? {
        if key.get("alg").and_then(Value::as_str) != Some(algorithm) {
            continue;
        }
        let Some(existing) = key_entry_purposes(key)? else {
            continue;
        };
        if existing == registration.purposes {
            return key
                .get("kid")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("purpose-scoped key is missing kid"));
        }
        if existing
            .iter()
            .any(|purpose| registration.purposes.contains(purpose))
        {
            anyhow::bail!(
                "a purpose-scoped {algorithm} key already covers one or more requested purposes"
            );
        }
    }
    let mut entry =
        create_prepublished_local_key_entry(settings, registration.algorithm, Utc::now()).await?;
    let kid = entry
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("generated local key entry missing kid"))?
        .to_owned();
    let file = entry
        .get("file")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("generated local key entry missing file"))?
        .to_owned();
    entry["purposes"] = json!(
        registration
            .purposes
            .iter()
            .map(|purpose| purpose.as_str())
            .collect::<Vec<_>>()
    );
    keyset_keys_mut(&mut keyset)?.push(entry);
    let result = match validate_keyset_json(&keyset) {
        Ok(()) => write_json_atomic(&path, &keyset).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(settings.keys_dir.join(file)).await;
        return Err(error);
    }
    Ok(kid)
}

async fn load_keyset_json(settings: &KeySettings) -> anyhow::Result<Value> {
    let path = settings.keys_dir.join("keyset.json");
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    validate_keyset_json(&value)?;
    Ok(value)
}

fn validate_keyset_json(value: &Value) -> anyhow::Result<()> {
    let active = keyset_active_kid(value)?;
    let mut seen = std::collections::HashSet::new();
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

fn key_entry_purposes(entry: &Value) -> anyhow::Result<Option<BTreeSet<SigningPurpose>>> {
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
    reject_private_jwk_members(public_jwk)
}

fn keyset_active_kid(value: &Value) -> anyhow::Result<&str> {
    value
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset.json missing active_kid"))
}

fn keyset_keys(value: &Value) -> anyhow::Result<&Vec<Value>> {
    value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("keyset.json missing keys array"))
}

fn keyset_keys_mut(value: &mut Value) -> anyhow::Result<&mut Vec<Value>> {
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
    sync_private_key_directory(parent).await?;
    Ok(())
}

async fn write_private_key_pem_if_absent(path: &Path, pem: &str) -> anyhow::Result<()> {
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
            sync_private_key_directory(parent).await?;
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
        use std::os::unix::fs::OpenOptionsExt;
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
async fn sync_private_key_directory(path: &Path) -> anyhow::Result<()> {
    tokio::fs::File::open(path).await?.sync_all().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn sync_private_key_directory(_path: &Path) -> anyhow::Result<()> {
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
    tokio::fs::write(&tmp_path, bytes).await?;
    tokio::fs::rename(&tmp_path, path).await.with_context(|| {
        format!(
            "failed to atomically rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
async fn set_private_key_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(path, permissions).await?;
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

fn key_entry_algorithm(entry: &Value) -> anyhow::Result<jsonwebtoken::Algorithm> {
    entry
        .get("alg")
        .and_then(Value::as_str)
        .map(signing_algorithm_from_name)
        .unwrap_or(Some(jsonwebtoken::Algorithm::EdDSA))
        .ok_or_else(|| anyhow!("unsupported signing alg"))
}

fn key_entry_backend(entry: &Value) -> &str {
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

fn external_public_jwk(entry: &Value) -> anyhow::Result<Value> {
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

fn key_entry_retire_at(entry: &Value) -> anyhow::Result<Option<DateTime<Utc>>> {
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

fn key_entry_created_at(entry: &Value) -> anyhow::Result<Option<DateTime<Utc>>> {
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

#[cfg(test)]
#[path = "../tests/unit/store/keyset_store.rs"]
mod keyset_store_tests;
