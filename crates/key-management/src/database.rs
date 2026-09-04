use std::sync::Arc;

use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_auth::SigningPurpose;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    PersistedSigningKeyset, SealedKeyMaterial, SigningKeyRepository,
    SigningKeyWrappingKeyRing, SigningKeysetCreateResult,
    model::{ActiveSigningKey, ExternalSigningKey, KeyHandle, KeySettings, KeyState, LoadedKeyset, ManagedKey, StoredVerificationKey},
    serialization::{KEYSET_SCHEMA_VERSION, generate_key_material, public_jwk_from_private_der, signing_algorithm_name},
};

pub(crate) async fn load_or_create(
    settings: &KeySettings,
    tenant_id: Uuid,
    repository: Arc<dyn SigningKeyRepository>,
    wrapping_keys: SigningKeyWrappingKeyRing,
) -> anyhow::Result<(LoadedKeyset, DatabaseKeysetBinding)> {
    let record = match repository.load().await? {
        Some(record) => record,
        None => {
            let payload = initial_payload()?;
            let candidate = persist_payload(tenant_id, 1, payload, &wrapping_keys)?;
            match repository.create_if_absent(candidate).await? {
                SigningKeysetCreateResult::Created(record) | SigningKeysetCreateResult::Existing(record) => record,
            }
        }
    };
    let loaded = load_record(settings, tenant_id, &wrapping_keys, &record)?;
    Ok((loaded, DatabaseKeysetBinding { tenant_id, repository, wrapping_keys }))
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
    let record = binding.repository.load().await?.ok_or_else(|| anyhow!("database signing keyset disappeared"))?;
    load_record(settings, binding.tenant_id, &binding.wrapping_keys, &record)
}

fn initial_payload() -> anyhow::Result<Value> {
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let active = local_entry(jsonwebtoken::Algorithm::RS256, now.clone(), None::<Vec<SigningPurpose>>)?;
    let protocol = local_entry(
        jsonwebtoken::Algorithm::PS256,
        now,
        Some([SigningPurpose::IdToken, SigningPurpose::Jarm, SigningPurpose::Introspection]),
    )?;
    Ok(json!({
        "schema_version": KEYSET_SCHEMA_VERSION,
        "active_kid": active["kid"].clone(),
        "keys": [active, protocol],
        "request_object_private_pem": URL_SAFE_NO_PAD.encode(crate::crypto::generate_rsa_pkcs8_pem(3072)?)
    }))
}

fn local_entry(
    algorithm: jsonwebtoken::Algorithm,
    created_at: String,
    purposes: Option<impl IntoIterator<Item = SigningPurpose>>,
) -> anyhow::Result<Value> {
    let name = signing_algorithm_name(algorithm).ok_or_else(|| anyhow!("unsupported signing alg"))?;
    let private = generate_key_material(algorithm)?.private_pkcs8_der;
    let kid = format!("{}-{}", name.to_ascii_lowercase(), Uuid::now_v7());
    let public_jwk = public_jwk_from_private_der(&kid, algorithm, &private)?;
    let mut entry = json!({"kid":kid,"alg":name,"backend":"local-db","public_jwk":public_jwk,"private_pkcs8_der":URL_SAFE_NO_PAD.encode(private),"created_at":created_at,"retire_at":null});
    if let Some(purposes) = purposes {
        entry["purposes"] = json!(purposes.into_iter().map(|purpose| purpose.as_str()).collect::<Vec<_>>());
    }
    Ok(entry)
}

fn persist_payload(tenant_id: Uuid, revision: i64, payload: Value, keys: &SigningKeyWrappingKeyRing) -> anyhow::Result<PersistedSigningKeyset> {
    let public_metadata = public_projection(&payload)?;
    let sealed = keys.seal_generation(tenant_id, revision, &public_metadata, &serde_json::to_vec(&payload)?)?;
    Ok(PersistedSigningKeyset { revision, public_metadata, encrypted_private_material: sealed.into_persisted_bytes(), wrapping_key_id: keys.current_id().to_owned() })
}

fn public_projection(payload: &Value) -> anyhow::Result<Value> {
    let mut metadata = payload.clone();
    metadata.as_object_mut().ok_or_else(|| anyhow!("keyset payload must be object"))?.remove("request_object_private_pem");
    for entry in metadata["keys"].as_array_mut().ok_or_else(|| anyhow!("keyset payload missing keys"))? {
        entry.as_object_mut().ok_or_else(|| anyhow!("keyset entry must be object"))?.remove("private_pkcs8_der");
    }
    Ok(metadata)
}

fn load_record(settings: &KeySettings, tenant_id: Uuid, keys: &SigningKeyWrappingKeyRing, record: &PersistedSigningKeyset) -> anyhow::Result<LoadedKeyset> {
    let sealed = SealedKeyMaterial::from_persisted_bytes(record.wrapping_key_id.clone(), &record.encrypted_private_material)?;
    let payload: Value = serde_json::from_slice(&keys.open_generation(tenant_id, record.revision, &record.public_metadata, &sealed)?)?;
    if public_projection(&payload)? != record.public_metadata { anyhow::bail!("signing keyset public metadata does not match encrypted generation"); }
    let active_kid = payload["active_kid"].as_str().ok_or_else(|| anyhow!("keyset missing active_kid"))?.to_owned();
    let request_object_decryption_key = URL_SAFE_NO_PAD.decode(payload["request_object_private_pem"].as_str().ok_or_else(|| anyhow!("keyset missing request object private key"))?)?;
    crate::crypto::validate_rsa_pkcs8_pem(&request_object_decryption_key)?;
    let request_object_encryption_jwk = crate::request_object_encryption::request_object_encryption_jwk(&request_object_decryption_key)?;
    let mut active = None;
    let mut active_alg = None;
    let mut verification_keys = Vec::new();
    for entry in payload["keys"].as_array().ok_or_else(|| anyhow!("keyset missing keys"))? {
        let kid = entry["kid"].as_str().ok_or_else(|| anyhow!("keyset key missing kid"))?.to_owned();
        let algorithm = crate::serialization::signing_algorithm_from_name(entry["alg"].as_str().unwrap_or_default()).ok_or_else(|| anyhow!("keyset key has unsupported alg"))?;
        let backend = entry["backend"].as_str().unwrap_or_default();
        let purposes = entry.get("purposes").and_then(Value::as_array).map(|values| values.iter().filter_map(Value::as_str).filter_map(SigningPurpose::from_name).collect()).unwrap_or_else(|| if kid == active_kid { crate::lifecycle::all_signing_purposes() } else { Default::default() });
        let (public_jwk, handle, signing) = if backend == "local-db" {
            let private = URL_SAFE_NO_PAD.decode(entry["private_pkcs8_der"].as_str().ok_or_else(|| anyhow!("local database key missing private material"))?)?;
            let public = public_jwk_from_private_der(&kid, algorithm, &private)?;
            (public, KeyHandle::Local(private.clone()), (kid == active_kid).then_some(ActiveSigningKey::LocalPkcs8Der(private)))
        } else if backend == "external-command" {
            let public = entry["public_jwk"].clone();
            let key_ref = entry["key_ref"].as_str().ok_or_else(|| anyhow!("external key missing key_ref"))?.to_owned();
            let signing = if kid == active_kid { Some(ActiveSigningKey::ExternalCommand(ExternalSigningKey { command: Arc::new(settings.external_command.clone()), key_ref: key_ref.clone(), timeout: settings.external_timeout })) } else { None };
            (public, KeyHandle::External { key_ref }, signing)
        } else { anyhow::bail!("keyset key has unsupported backend"); };
        if kid == active_kid { active_alg = Some(algorithm); active = signing; }
        verification_keys.push(StoredVerificationKey { public_jwk, managed: ManagedKey { kid, algorithm: signing_algorithm_name(algorithm).unwrap().to_owned(), purposes, state: if entry.get("purposes").is_some() || entry["kid"] == payload["active_kid"] { KeyState::Active } else { KeyState::Prepublished }, handle } });
    }
    Ok(LoadedKeyset { active_kid, active_alg: active_alg.ok_or_else(|| anyhow!("active key is unavailable"))?, active_signing_key: active.ok_or_else(|| anyhow!("active signer unavailable"))?, verification_keys, request_object_decryption_key, request_object_encryption_jwk })
}
