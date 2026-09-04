use std::{collections::BTreeSet, sync::Arc};

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use nazo_auth::SigningPurpose;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    ExternalKeyRegistration, KeyRecord, KeyRecordStatus, LocalKeyRegistration,
    PersistedSigningKeyset, SealedKeyMaterial, SigningKeyRepository, SigningKeyWrappingKeyRing,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
    model::{
        ActiveSigningKey, ExternalSigningKey, KeyHandle, KeySettings, KeyState, LoadedKeyset,
        ManagedKey, StoredVerificationKey,
    },
    serialization::{
        KEYSET_SCHEMA_VERSION, der_to_pem, external_public_jwk, generate_key_material,
        key_entry_algorithm, key_entry_created_at, key_entry_purposes, key_entry_retire_at,
        public_jwk_from_private_der, signing_algorithm_name,
    },
};

const MAX_CAS_ATTEMPTS: usize = 8;

pub(crate) async fn load_or_create(
    settings: &KeySettings,
    tenant_id: Uuid,
    repository: Arc<dyn SigningKeyRepository>,
    wrapping_keys: SigningKeyWrappingKeyRing,
) -> anyhow::Result<(LoadedKeyset, DatabaseKeysetBinding)> {
    match repository.load().await? {
        Some(_) => {}
        None => {
            let candidate = persist_payload(tenant_id, 1, initial_payload()?, &wrapping_keys)?;
            match repository.create_if_absent(candidate).await? {
                SigningKeysetCreateResult::Created(_) | SigningKeysetCreateResult::Existing(_) => {}
            }
        }
    }
    let binding = DatabaseKeysetBinding {
        tenant_id,
        repository,
        wrapping_keys,
    };
    // Startup is a lifecycle boundary.  Do not wait for the periodic refresh
    // before creating a required prepublished key or promoting one that has
    // completed its prepublication window.
    let loaded = refresh(settings, &binding).await?;
    Ok((loaded, binding))
}

/// One-shot migration of an existing file keyset. This is deliberately never
/// called by normal startup: after it returns, the database is authoritative.
pub(crate) async fn import_legacy_file_keyset(
    settings: &KeySettings,
    tenant_id: Uuid,
    repository: Arc<dyn SigningKeyRepository>,
    wrapping_keys: SigningKeyWrappingKeyRing,
) -> anyhow::Result<(LoadedKeyset, DatabaseKeysetBinding)> {
    let binding = DatabaseKeysetBinding {
        tenant_id,
        repository,
        wrapping_keys,
    };
    let imported_payload = legacy_file_payload(settings).await?;
    let record = match binding.repository.load().await? {
        Some(record) => {
            let existing = decrypt_payload(binding.tenant_id, &binding.wrapping_keys, &record)?;
            ensure_import_is_compatible(&imported_payload, &existing)?;
            record
        }
        None => {
            let candidate = persist_payload(
                tenant_id,
                1,
                imported_payload.clone(),
                &binding.wrapping_keys,
            )?;
            match binding.repository.create_if_absent(candidate).await? {
                SigningKeysetCreateResult::Created(record) => record,
                SigningKeysetCreateResult::Existing(record) => {
                    let existing =
                        decrypt_payload(binding.tenant_id, &binding.wrapping_keys, &record)?;
                    ensure_import_is_compatible(&imported_payload, &existing)?;
                    record
                }
            }
        }
    };
    let loaded = load_record(settings, tenant_id, &binding.wrapping_keys, &record)?;
    Ok((loaded, binding))
}

fn ensure_import_is_compatible(imported: &Value, existing: &Value) -> anyhow::Result<()> {
    if imported.get("request_object_private_pem") != existing.get("request_object_private_pem") {
        anyhow::bail!("database signing keyset has different request-object key material");
    }
    let existing_keys = existing
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("database keyset missing keys"))?;
    for imported_key in imported
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("legacy keyset missing keys"))?
    {
        let kid = imported_key
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legacy keyset key missing kid"))?;
        let existing_key = existing_keys
            .iter()
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
            .ok_or_else(|| {
                anyhow!("database signing keyset does not contain imported key {kid}")
            })?;
        if import_identity(imported_key)? != import_identity(existing_key)? {
            anyhow::bail!("database signing keyset key {kid} has different imported material");
        }
    }
    Ok(())
}

fn import_identity(entry: &Value) -> anyhow::Result<Value> {
    let backend = entry
        .get("backend")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset key missing backend"))?;
    let mut identity = serde_json::Map::new();
    for field in ["kid", "alg", "backend", "purposes", "public_jwk"] {
        identity.insert(
            field.to_owned(),
            entry.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    match backend {
        "local-db" => {
            identity.insert(
                "private_pkcs8_der".to_owned(),
                entry
                    .get("private_pkcs8_der")
                    .cloned()
                    .ok_or_else(|| anyhow!("local database key missing private material"))?,
            );
        }
        "external-command" => {
            identity.insert(
                "key_ref".to_owned(),
                entry
                    .get("key_ref")
                    .cloned()
                    .ok_or_else(|| anyhow!("external key missing key reference"))?,
            );
        }
        _ => anyhow::bail!("keyset key has unsupported backend {backend}"),
    }
    Ok(Value::Object(identity))
}

#[derive(Clone)]
pub(crate) struct DatabaseKeysetBinding {
    pub(crate) tenant_id: Uuid,
    pub(crate) repository: Arc<dyn SigningKeyRepository>,
    pub(crate) wrapping_keys: SigningKeyWrappingKeyRing,
}

pub(crate) async fn refresh(
    settings: &KeySettings,
    binding: &DatabaseKeysetBinding,
) -> anyhow::Result<LoadedKeyset> {
    update(binding, settings, true, |payload| {
        maintain_payload(payload, settings)
    })
    .await
}

pub(crate) async fn list(
    settings: &KeySettings,
    binding: &DatabaseKeysetBinding,
) -> anyhow::Result<Vec<KeyRecord>> {
    let record = require_record(binding).await?;
    let payload = decrypt_payload(binding.tenant_id, &binding.wrapping_keys, &record)?;
    let _ = load_payload(settings, &payload)?;
    records(&payload)
}

pub(crate) async fn validate(
    settings: &KeySettings,
    binding: &DatabaseKeysetBinding,
) -> anyhow::Result<()> {
    let record = require_record(binding).await?;
    let _ = load_record(settings, binding.tenant_id, &binding.wrapping_keys, &record)?;
    Ok(())
}

pub(crate) async fn revision(binding: &DatabaseKeysetBinding) -> anyhow::Result<String> {
    Ok(require_record(binding).await?.revision.to_string())
}

pub(crate) async fn register_local(
    settings: &KeySettings,
    binding: &DatabaseKeysetBinding,
    registration: LocalKeyRegistration,
) -> anyhow::Result<(String, LoadedKeyset)> {
    validate_local_registration(&registration)?;
    let mut registered_kid = None;
    let loaded = update(binding, settings, false, |payload| {
        let keys = payload
            .get_mut("keys")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("keyset missing keys"))?;
        let algorithm = signing_algorithm_name(registration.algorithm)
            .ok_or_else(|| anyhow!("unsupported signing alg"))?;
        for key in keys.iter() {
            if key.get("alg").and_then(Value::as_str) != Some(algorithm) {
                continue;
            }
            let Some(existing) = key_entry_purposes(key)? else {
                continue;
            };
            if existing == registration.purposes {
                registered_kid = Some(
                    key.get("kid")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| anyhow!("purpose-scoped key is missing kid"))?,
                );
                return Ok(false);
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
        let entry = local_entry(
            registration.algorithm,
            timestamp(Utc::now()),
            Some(registration.purposes.iter().copied()),
        )?;
        registered_kid = Some(
            entry
                .get("kid")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("generated local key entry missing kid"))?,
        );
        keys.push(entry);
        Ok(true)
    })
    .await?;
    Ok((
        registered_kid.ok_or_else(|| anyhow!("local key registration did not select a key"))?,
        loaded,
    ))
}

pub(crate) async fn register_external(
    settings: &KeySettings,
    binding: &DatabaseKeysetBinding,
    registration: ExternalKeyRegistration,
) -> anyhow::Result<LoadedKeyset> {
    validate_external_registration(&registration)?;
    update(binding, settings, false, |payload| {
        let keys = payload.get_mut("keys").and_then(Value::as_array_mut).ok_or_else(|| anyhow!("keyset missing keys"))?;
        let algorithm = signing_algorithm_name(registration.algorithm).ok_or_else(|| anyhow!("unsupported signing alg"))?;
        if let Some(existing) = keys.iter().find(|key| key.get("kid").and_then(Value::as_str) == Some(registration.kid.as_str())) {
            if existing.get("alg").and_then(Value::as_str) == Some(algorithm)
                && existing.get("key_ref").and_then(Value::as_str) == Some(registration.key_ref.as_str())
                && existing.get("public_jwk") == Some(&registration.public_jwk) { return Ok(false); }
            anyhow::bail!("external key kid already exists with different material");
        }
        keys.push(json!({"kid":registration.kid,"alg":algorithm,"backend":"external-command","key_ref":registration.key_ref,"public_jwk":registration.public_jwk,"created_at":timestamp(Utc::now()),"retire_at":null}));
        Ok(true)
    }).await
}

pub(crate) fn local_private_key_pem(loaded: &LoadedKeyset, kid: &str) -> anyhow::Result<String> {
    let entry = loaded
        .verification_keys
        .iter()
        .find(|entry| entry.managed.kid == kid)
        .ok_or_else(|| anyhow!("signing key {kid} does not exist"))?;
    match &entry.managed.handle {
        KeyHandle::Local(der) => Ok(der_to_pem(der, "PRIVATE KEY")),
        KeyHandle::External { .. } => {
            anyhow::bail!("signing key {kid} has no local private material")
        }
    }
}

async fn require_record(binding: &DatabaseKeysetBinding) -> anyhow::Result<PersistedSigningKeyset> {
    binding
        .repository
        .load()
        .await?
        .ok_or_else(|| anyhow!("database signing keyset disappeared"))
}

async fn update<F>(
    binding: &DatabaseKeysetBinding,
    settings: &KeySettings,
    reseal_if_current_key_changed: bool,
    mut mutation: F,
) -> anyhow::Result<LoadedKeyset>
where
    F: FnMut(&mut Value) -> anyhow::Result<bool>,
{
    let mut record = require_record(binding).await?;
    for _ in 0..MAX_CAS_ATTEMPTS {
        let mut payload = decrypt_payload(binding.tenant_id, &binding.wrapping_keys, &record)?;
        if !mutation(&mut payload)?
            && (!reseal_if_current_key_changed
                || record.wrapping_key_id == binding.wrapping_keys.current_id())
        {
            return load_payload(settings, &payload);
        }
        let revision = record
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow!("signing keyset revision overflow"))?;
        let candidate =
            persist_payload(binding.tenant_id, revision, payload, &binding.wrapping_keys)?;
        match binding
            .repository
            .compare_and_swap(record.revision, candidate)
            .await?
        {
            SigningKeysetCompareAndSwapResult::Applied(record) => {
                return load_record(settings, binding.tenant_id, &binding.wrapping_keys, &record);
            }
            SigningKeysetCompareAndSwapResult::Conflict(winner) => record = winner,
        }
    }
    anyhow::bail!("signing keyset update did not converge after {MAX_CAS_ATTEMPTS} conflicts")
}

fn initial_payload() -> anyhow::Result<Value> {
    let now = timestamp(Utc::now());
    let active = local_entry(
        jsonwebtoken::Algorithm::RS256,
        now.clone(),
        None::<Vec<SigningPurpose>>,
    )?;
    let protocol = local_entry(
        jsonwebtoken::Algorithm::PS256,
        now,
        Some([
            SigningPurpose::IdToken,
            SigningPurpose::Jarm,
            SigningPurpose::Introspection,
        ]),
    )?;
    Ok(
        json!({"schema_version":KEYSET_SCHEMA_VERSION,"active_kid":active["kid"].clone(),"keys":[active,protocol],"request_object_private_pem":URL_SAFE_NO_PAD.encode(crate::crypto::generate_rsa_pkcs8_pem(3072)?)}),
    )
}

async fn legacy_file_payload(settings: &KeySettings) -> anyhow::Result<Value> {
    let mut payload = crate::serialization::load_keyset_json(settings).await?;
    let request_object_private_pem =
        crate::request_object_encryption::load_request_object_decryption_key(settings).await?;
    let entries = payload
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("legacy keyset missing keys"))?;
    for entry in entries {
        if entry.get("backend").and_then(Value::as_str) != Some("local-pem") {
            continue;
        }
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legacy local key missing kid"))?
            .to_owned();
        let algorithm = key_entry_algorithm(entry)?;
        let file = entry
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legacy local key {kid} missing file"))?;
        let pem = tokio::fs::read_to_string(settings.keys_dir.join(file))
            .await
            .with_context(|| format!("failed to read legacy local key {kid}"))?;
        let private = crate::serialization::pem_to_der(&pem)
            .ok_or_else(|| anyhow!("legacy local key {kid} is not valid PEM"))?;
        let public = public_jwk_from_private_der(&kid, algorithm, &private)?;
        let object = entry
            .as_object_mut()
            .ok_or_else(|| anyhow!("legacy local key {kid} must be an object"))?;
        object.insert("backend".to_owned(), json!("local-db"));
        object.remove("file");
        object.insert("public_jwk".to_owned(), public);
        object.insert(
            "private_pkcs8_der".to_owned(),
            json!(URL_SAFE_NO_PAD.encode(private)),
        );
    }
    payload["request_object_private_pem"] =
        json!(URL_SAFE_NO_PAD.encode(request_object_private_pem));
    Ok(payload)
}

fn local_entry(
    algorithm: jsonwebtoken::Algorithm,
    created_at: String,
    purposes: Option<impl IntoIterator<Item = SigningPurpose>>,
) -> anyhow::Result<Value> {
    let name =
        signing_algorithm_name(algorithm).ok_or_else(|| anyhow!("unsupported signing alg"))?;
    let private = generate_key_material(algorithm)?.private_pkcs8_der;
    let kid = format!("{}-{}", name.to_ascii_lowercase(), Uuid::now_v7());
    let public_jwk = public_jwk_from_private_der(&kid, algorithm, &private)?;
    let mut entry = json!({"kid":kid,"alg":name,"backend":"local-db","public_jwk":public_jwk,"private_pkcs8_der":URL_SAFE_NO_PAD.encode(private),"created_at":created_at,"retire_at":null});
    if let Some(purposes) = purposes {
        entry["purposes"] = json!(
            purposes
                .into_iter()
                .map(|purpose| purpose.as_str())
                .collect::<Vec<_>>()
        );
    }
    Ok(entry)
}

fn maintain_payload(payload: &mut Value, settings: &KeySettings) -> anyhow::Result<bool> {
    let active_kid = payload
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset missing active_kid"))?
        .to_owned();
    let (changed, next_active) = {
        let keys = payload
            .get_mut("keys")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("keyset missing keys"))?;
        let active_index = keys
            .iter()
            .position(|entry| entry.get("kid").and_then(Value::as_str) == Some(active_kid.as_str()))
            .ok_or_else(|| anyhow!("keyset active key {active_kid} does not exist"))?;
        let active = &keys[active_index];
        if active.get("purposes").is_some() || active.get("retire_at") != Some(&Value::Null) {
            anyhow::bail!("keyset active key {active_kid} is not a current rotation key");
        }
        let active_algorithm = key_entry_algorithm(active)?;
        if active.get("backend").and_then(Value::as_str) != Some("local-db") {
            return Ok(false);
        }
        let now = Utc::now();
        let rotation_due = key_entry_created_at(active)? + settings.rotation_interval;
        let candidate = prepublished_candidate(keys, &active_kid, active_algorithm)?;
        let mut changed = false;
        let mut next_active = None;
        if now >= rotation_due {
            if let Some(index) = candidate {
                if key_entry_created_at(&keys[index])? + settings.prepublish_window <= now {
                    let next_kid = keys[index]["kid"]
                        .as_str()
                        .ok_or_else(|| anyhow!("prepublished key missing kid"))?
                        .to_owned();
                    activate(
                        keys,
                        &active_kid,
                        &next_kid,
                        now + settings.verification_grace
                            + crate::lifecycle::MAX_DATABASE_SNAPSHOT_STALENESS,
                    );
                    next_active = Some(next_kid);
                    changed = true;
                }
            } else {
                keys.push(local_entry(
                    active_algorithm,
                    timestamp(now),
                    None::<Vec<SigningPurpose>>,
                )?);
                changed = true;
            }
        } else if now >= rotation_due - settings.prepublish_window && candidate.is_none() {
            keys.push(local_entry(
                active_algorithm,
                timestamp(now),
                None::<Vec<SigningPurpose>>,
            )?);
            changed = true;
        }
        for algorithm in [
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::PS256,
        ] {
            if algorithm != active_algorithm && !has_live_protocol_key(keys, algorithm, now)? {
                keys.push(local_entry(
                    algorithm,
                    timestamp(now),
                    Some([
                        SigningPurpose::IdToken,
                        SigningPurpose::Jarm,
                        SigningPurpose::Introspection,
                    ]),
                )?);
                changed = true;
            }
        }
        (changed, next_active)
    };
    if let Some(next_active) = next_active {
        payload["active_kid"] = json!(next_active);
    }
    Ok(changed)
}

fn prepublished_candidate(
    keys: &[Value],
    active_kid: &str,
    algorithm: jsonwebtoken::Algorithm,
) -> anyhow::Result<Option<usize>> {
    let mut selected: Option<(usize, DateTime<Utc>)> = None;
    for (index, entry) in keys.iter().enumerate() {
        if entry.get("kid").and_then(Value::as_str) == Some(active_kid)
            || entry.get("purposes").is_some()
            || key_entry_retire_at(entry)?.is_some()
            || key_entry_algorithm(entry)? != algorithm
            || entry.get("backend").and_then(Value::as_str) != Some("local-db")
        {
            continue;
        }
        let created = key_entry_created_at(entry)?;
        if selected.is_none_or(|(_, selected_created)| created < selected_created) {
            selected = Some((index, created));
        }
    }
    Ok(selected.map(|(index, _)| index))
}

fn activate(keys: &mut [Value], old_kid: &str, new_kid: &str, retire_at: DateTime<Utc>) {
    for entry in keys {
        if entry.get("kid").and_then(Value::as_str) == Some(old_kid) {
            entry["retire_at"] = json!(timestamp(retire_at));
        } else if entry.get("kid").and_then(Value::as_str) == Some(new_kid) {
            entry["retire_at"] = Value::Null;
        }
    }
}

fn has_live_protocol_key(
    keys: &[Value],
    algorithm: jsonwebtoken::Algorithm,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    for entry in keys {
        if entry.get("backend").and_then(Value::as_str) == Some("local-db")
            && key_entry_algorithm(entry)? == algorithm
            && key_entry_purposes(entry)?.is_some_and(|purposes| {
                purposes.contains(&SigningPurpose::IdToken)
                    && purposes.contains(&SigningPurpose::Jarm)
            })
            && key_entry_retire_at(entry)?.is_none_or(|retire| retire > now)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn persist_payload(
    tenant_id: Uuid,
    revision: i64,
    payload: Value,
    keys: &SigningKeyWrappingKeyRing,
) -> anyhow::Result<PersistedSigningKeyset> {
    let public_metadata = public_projection(&payload)?;
    let sealed = keys.seal_generation(
        tenant_id,
        revision,
        &public_metadata,
        &serde_json::to_vec(&payload)?,
    )?;
    Ok(PersistedSigningKeyset {
        revision,
        public_metadata,
        encrypted_private_material: sealed.into_persisted_bytes(),
        wrapping_key_id: keys.current_id().to_owned(),
    })
}

fn public_projection(payload: &Value) -> anyhow::Result<Value> {
    let mut metadata = payload.clone();
    metadata
        .as_object_mut()
        .ok_or_else(|| anyhow!("keyset payload must be object"))?
        .remove("request_object_private_pem");
    for entry in metadata["keys"]
        .as_array_mut()
        .ok_or_else(|| anyhow!("keyset payload missing keys"))?
    {
        entry
            .as_object_mut()
            .ok_or_else(|| anyhow!("keyset entry must be object"))?
            .remove("private_pkcs8_der");
    }
    Ok(metadata)
}

fn decrypt_payload(
    tenant_id: Uuid,
    wrapping_keys: &SigningKeyWrappingKeyRing,
    record: &PersistedSigningKeyset,
) -> anyhow::Result<Value> {
    if record.revision < 1 {
        anyhow::bail!("database signing keyset revision must be positive");
    }
    let sealed = SealedKeyMaterial::from_persisted_bytes(
        record.wrapping_key_id.clone(),
        &record.encrypted_private_material,
    )?;
    let payload: Value = serde_json::from_slice(&wrapping_keys.open_generation(
        tenant_id,
        record.revision,
        &record.public_metadata,
        &sealed,
    )?)?;
    if public_projection(&payload)? != record.public_metadata {
        anyhow::bail!("signing keyset public metadata does not match encrypted generation");
    }
    Ok(payload)
}

fn load_record(
    settings: &KeySettings,
    tenant_id: Uuid,
    keys: &SigningKeyWrappingKeyRing,
    record: &PersistedSigningKeyset,
) -> anyhow::Result<LoadedKeyset> {
    load_payload(settings, &decrypt_payload(tenant_id, keys, record)?)
}

fn load_payload(settings: &KeySettings, payload: &Value) -> anyhow::Result<LoadedKeyset> {
    if payload.get("schema_version").and_then(Value::as_str) != Some(KEYSET_SCHEMA_VERSION) {
        anyhow::bail!("database keyset has unsupported schema version");
    }
    let active_kid = payload
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset missing active_kid"))?
        .to_owned();
    let request_object_decryption_key = URL_SAFE_NO_PAD.decode(
        payload["request_object_private_pem"]
            .as_str()
            .ok_or_else(|| anyhow!("keyset missing request object private key"))?,
    )?;
    crate::crypto::validate_rsa_pkcs8_pem(&request_object_decryption_key)?;
    let request_object_encryption_jwk =
        crate::request_object_encryption::request_object_encryption_jwk(
            &request_object_decryption_key,
        )?;
    let mut active = None;
    let mut active_alg = None;
    let mut verification_keys = Vec::new();
    let mut kids = std::collections::HashSet::new();
    for entry in payload["keys"]
        .as_array()
        .ok_or_else(|| anyhow!("keyset missing keys"))?
    {
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.trim().is_empty())
            .ok_or_else(|| anyhow!("keyset key missing kid"))?
            .to_owned();
        if !kids.insert(kid.clone()) {
            anyhow::bail!("keyset contains duplicate kid {kid}");
        }
        let algorithm = key_entry_algorithm(entry)?;
        let purposes = key_entry_purposes(entry)?.unwrap_or_else(|| {
            if kid == active_kid {
                crate::lifecycle::all_signing_purposes()
            } else {
                BTreeSet::new()
            }
        });
        let retired_at = key_entry_retire_at(entry)?;
        let backend = entry
            .get("backend")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("keyset key {kid} missing backend"))?;
        let (public_jwk, handle, signing) = match backend {
            "local-db" => {
                let private =
                    URL_SAFE_NO_PAD.decode(entry["private_pkcs8_der"].as_str().ok_or_else(
                        || anyhow!("local database key {kid} missing private material"),
                    )?)?;
                let public = public_jwk_from_private_der(&kid, algorithm, &private)?;
                if entry.get("public_jwk") != Some(&public) {
                    anyhow::bail!(
                        "local database key {kid} public metadata does not match private material"
                    );
                }
                (
                    public,
                    KeyHandle::Local(private.clone()),
                    (kid == active_kid).then_some(ActiveSigningKey::LocalPkcs8Der(private)),
                )
            }
            "external-command" => {
                let public = external_public_jwk(entry)?;
                let key_ref = entry
                    .get("key_ref")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("external key {kid} missing key_ref"))?
                    .to_owned();
                let signing = if kid == active_kid {
                    if settings.external_command.is_empty() {
                        anyhow::bail!(
                            "SIGNING_EXTERNAL_COMMAND is required for active external-command key {kid}"
                        );
                    }
                    Some(ActiveSigningKey::ExternalCommand(ExternalSigningKey {
                        command: Arc::new(settings.external_command.clone()),
                        key_ref: key_ref.clone(),
                        timeout: settings.external_timeout,
                    }))
                } else {
                    None
                };
                (public, KeyHandle::External { key_ref }, signing)
            }
            _ => anyhow::bail!("keyset key {kid} has unsupported backend {backend}"),
        };
        if kid == active_kid {
            if entry.get("purposes").is_some() || retired_at.is_some() {
                anyhow::bail!("active key {kid} is not a current rotation key");
            }
            active_alg = Some(algorithm);
            active = signing;
        }
        verification_keys.push(StoredVerificationKey {
            public_jwk,
            retire_at: retired_at,
            managed: ManagedKey {
                kid,
                algorithm: signing_algorithm_name(algorithm).unwrap().to_owned(),
                purposes,
                state: if entry.get("purposes").is_some()
                    || entry.get("kid").and_then(Value::as_str) == Some(active_kid.as_str())
                {
                    KeyState::Active
                } else if retired_at.is_some_and(|time| time <= Utc::now()) {
                    KeyState::Retired
                } else if retired_at.is_some() {
                    KeyState::Grace
                } else {
                    KeyState::Prepublished
                },
                handle,
            },
        });
    }
    Ok(LoadedKeyset {
        active_kid,
        active_alg: active_alg.ok_or_else(|| anyhow!("active key is unavailable"))?,
        active_signing_key: active.ok_or_else(|| anyhow!("active signer unavailable"))?,
        verification_keys,
        request_object_decryption_key,
        request_object_encryption_jwk,
    })
}

fn records(payload: &Value) -> anyhow::Result<Vec<KeyRecord>> {
    let active_kid = payload
        .get("active_kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("keyset missing active_kid"))?;
    let now = Utc::now();
    payload["keys"]
        .as_array()
        .ok_or_else(|| anyhow!("keyset missing keys"))?
        .iter()
        .map(|entry| {
            let kid = entry
                .get("kid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("keyset key missing kid"))?;
            let retire_at = key_entry_retire_at(entry)?;
            let status = if kid == active_kid {
                KeyRecordStatus::Active
            } else if retire_at.is_some_and(|time| time <= now) {
                KeyRecordStatus::Retired
            } else if retire_at.is_some() {
                KeyRecordStatus::Grace
            } else if entry.get("purposes").is_some() {
                KeyRecordStatus::PurposeScoped
            } else {
                KeyRecordStatus::Prepublished
            };
            Ok(KeyRecord {
                kid: kid.to_owned(),
                status,
                algorithm: entry
                    .get("alg")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("keyset key {kid} missing alg"))?
                    .to_owned(),
                backend: entry
                    .get("backend")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("keyset key {kid} missing backend"))?
                    .to_owned(),
                locator: entry
                    .get("key_ref")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                retire_at: entry
                    .get("retire_at")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            })
        })
        .collect()
}

fn validate_local_registration(registration: &LocalKeyRegistration) -> anyhow::Result<()> {
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
    if signing_algorithm_name(registration.algorithm).is_none() {
        anyhow::bail!("unsupported signing alg");
    }
    Ok(())
}

fn validate_external_registration(registration: &ExternalKeyRegistration) -> anyhow::Result<()> {
    if registration.kid.trim().is_empty() || registration.key_ref.trim().is_empty() {
        anyhow::bail!("external key kid and key_ref must not be empty");
    }
    let algorithm = signing_algorithm_name(registration.algorithm)
        .ok_or_else(|| anyhow!("unsupported signing alg"))?;
    let entry = json!({"kid":registration.kid,"alg":algorithm,"backend":"external-command","key_ref":registration.key_ref,"public_jwk":registration.public_jwk,"created_at":timestamp(Utc::now()),"retire_at":null});
    external_public_jwk(&entry).context("external key public JWK is invalid")?;
    Ok(())
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
