use std::{future::Future, pin::Pin};

use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_auth::{SignError, Signature};
use serde_json::json;

use crate::{
    lifecycle::create_prepublished_local_key_entry,
    model::{KeySettings, LocalKeyRegistration},
    serialization::{
        key_entry_purposes, keyset_keys, keyset_keys_mut, load_keyset_json, validate_keyset_json,
        write_json_atomic,
    },
};

pub(crate) trait SigningBackend {
    fn sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignError>> + Send + 'a>>;
}

pub(crate) struct LocalBackend<'a> {
    pub(crate) algorithm: jsonwebtoken::Algorithm,
    pub(crate) private_key: &'a [u8],
}

impl SigningBackend for LocalBackend<'_> {
    fn sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignError>> + Send + 'a>> {
        Box::pin(async move {
            let encoded = sign(self.algorithm, self.private_key, signing_input)
                .map_err(|_| SignError::SigningFailed)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SignError::SigningFailed)?;
            Ok(Signature::new(bytes))
        })
    }
}

fn sign(
    algorithm: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
    signing_input: &[u8],
) -> jsonwebtoken::errors::Result<String> {
    let key = match algorithm {
        jsonwebtoken::Algorithm::EdDSA => jsonwebtoken::EncodingKey::from_ed_der(private_pkcs8_der),
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der)
        }
        jsonwebtoken::Algorithm::ES256 => jsonwebtoken::EncodingKey::from_ec_der(private_pkcs8_der),
        _ => return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into()),
    };
    jsonwebtoken::crypto::sign(signing_input, &key, algorithm)
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
            nazo_auth::SigningPurpose::Credential | nazo_auth::SigningPurpose::PresentationRequest
        )
    }) {
        anyhow::bail!(
            "purpose-scoped local keys are restricted to credential and presentation_request"
        );
    }
    let algorithm = crate::serialization::signing_algorithm_name(registration.algorithm)
        .ok_or_else(|| anyhow!("unsupported signing alg"))?;
    let path = settings.keys_dir.join("keyset.json");
    let mut keyset = load_keyset_json(settings).await?;
    for key in keyset_keys(&keyset)? {
        if key.get("alg").and_then(serde_json::Value::as_str) != Some(algorithm) {
            continue;
        }
        let Some(existing) = key_entry_purposes(key)? else {
            continue;
        };
        if existing == registration.purposes {
            return key
                .get("kid")
                .and_then(serde_json::Value::as_str)
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
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("generated local key entry missing kid"))?
        .to_owned();
    let file = entry
        .get("file")
        .and_then(serde_json::Value::as_str)
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
