use std::{io::ErrorKind, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use nazo_auth::SigningPurpose;
#[cfg(test)]
use nazo_auth::{SignRequest, Signer};
use serde_json::{Value, json};

#[cfg(test)]
use crate::model::{KeyHealth, KeyHealthStatus};
use crate::{
    KeyManager,
    model::{
        ActiveSigningKey, ExternalSigningKey, KeyHandle, KeySettings, KeyState, LoadedKeyset,
        ManagedKey, StoredVerificationKey,
    },
    request_object_encryption::{
        ensure_request_object_encryption_key, load_request_object_decryption_key,
        request_object_encryption_jwk,
    },
    serialization::{
        external_public_jwk, key_entry_algorithm, key_entry_backend, key_entry_created_at,
        key_entry_purposes, key_entry_retire_at, write_json_atomic,
    },
};

impl KeyManager {
    pub async fn run_lifecycle(self) {
        let normal_interval = refresh_interval(self.inner.settings.prepublish_window);
        let mut retry_interval = normal_interval;
        let mut failure_backoff = MIN_FAILURE_BACKOFF;
        let mut shutdown = self.inner.lifecycle_shutdown.subscribe();
        if *shutdown.borrow() {
            return;
        }
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                () = tokio::time::sleep(retry_interval) => {}
            }
            match self.refresh().await {
                Ok(()) => {
                    retry_interval = normal_interval;
                    failure_backoff = MIN_FAILURE_BACKOFF;
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        retry_in_seconds = failure_backoff.as_secs(),
                        "signing key lifecycle refresh failed; retaining the last good generation"
                    );
                    retry_interval = failure_backoff;
                    failure_backoff = next_failure_backoff(failure_backoff);
                }
            }
        }
    }
}

const MIN_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(60);

fn next_failure_backoff(current: Duration) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(MAX_FAILURE_BACKOFF)
        .min(MAX_FAILURE_BACKOFF)
}

fn refresh_interval(prepublish_window: chrono::Duration) -> Duration {
    let seconds = (prepublish_window.num_seconds() / 2).clamp(1, 3_600);
    Duration::from_secs(seconds as u64)
}

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
        for algorithm in [
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::PS256,
        ] {
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

pub(crate) async fn create_prepublished_local_key_entry(
    settings: &KeySettings,
    alg: jsonwebtoken::Algorithm,
    now: DateTime<Utc>,
) -> anyhow::Result<Value> {
    let alg_name = crate::serialization::signing_algorithm_name(alg)
        .ok_or_else(|| anyhow!("unsupported server signing alg"))?;
    let private_pkcs8_der = crate::serialization::generate_key_material(alg)?.private_pkcs8_der;
    let kid = format!("{}-{}", alg_name.to_ascii_lowercase(), uuid::Uuid::now_v7());
    let file_name = format!("{kid}.pem");
    let pem = crate::serialization::der_to_pem(&private_pkcs8_der, "PRIVATE KEY");
    crate::serialization::write_private_key_pem_atomic(&settings.keys_dir.join(&file_name), &pem)
        .await?;
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

pub(crate) fn timestamp(value: DateTime<Utc>) -> String {
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
                let der = crate::serialization::pem_to_der(&raw_key)
                    .with_context(|| format!("keyset entry {kid} is not valid PEM"))?;
                let public_jwk = crate::serialization::public_jwk_from_private_der(kid, alg, &der)
                    .with_context(|| {
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
                algorithm: crate::serialization::signing_algorithm_name(alg)
                    .unwrap()
                    .to_owned(),
                purposes: if let Some(purposes) = explicit_purposes.as_ref() {
                    purposes.clone()
                } else if is_active {
                    all_signing_purposes()
                } else {
                    std::collections::BTreeSet::new()
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

pub(crate) async fn create_new_keyset(settings: &KeySettings) -> anyhow::Result<LoadedKeyset> {
    let now = Utc::now();
    let rs256 =
        create_prepublished_local_key_entry(settings, jsonwebtoken::Algorithm::RS256, now).await?;
    let active_kid = rs256["kid"]
        .as_str()
        .ok_or_else(|| anyhow!("generated RS256 key missing kid"))?
        .to_owned();
    let ps256 =
        create_protocol_signing_key_entry(settings, jsonwebtoken::Algorithm::PS256, now).await?;
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

pub(crate) fn all_signing_purposes() -> std::collections::BTreeSet<SigningPurpose> {
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
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
