use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub fn string_value<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("OIDF config is missing string field {key}"))
}

pub fn public_jwks(jwks: &Value) -> anyhow::Result<Value> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("generated OIDF client jwks must contain keys array"))?;
    let public_keys = keys
        .iter()
        .map(|key| {
            let mut object = key
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("generated OIDF jwks key must be an object"))?
                .clone();
            for private_field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
                object.remove(private_field);
            }
            Ok(Value::Object(object))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(json!({ "keys": public_keys }))
}

pub fn plan_config_files(runtime_dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(runtime_dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if name.ends_with("-plan-config.json") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn certificate_pem_thumbprint(value: &str) -> anyhow::Result<String> {
    let start = value
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| anyhow::anyhow!("mTLS certificate is missing BEGIN marker"))?;
    let end = value
        .find("-----END CERTIFICATE-----")
        .ok_or_else(|| anyhow::anyhow!("mTLS certificate is missing END marker"))?;
    let body_start = start + "-----BEGIN CERTIFICATE-----".len();
    let body = value[body_start..end]
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    let der = STANDARD
        .decode(body)
        .map_err(|error| anyhow::anyhow!("mTLS certificate base64 decode failed: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&der)))
}

pub fn mtls_thumbprint(plan: &Value, key: &str) -> anyhow::Result<Option<String>> {
    let mtls_key = if key == "client2" { "mtls2" } else { "mtls" };
    let Some(cert) = plan
        .get(mtls_key)
        .and_then(|value| value.get("cert"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    Ok(Some(certificate_pem_thumbprint(cert)?))
}

pub fn client_scopes(client: &serde_json::Map<String, Value>) -> Value {
    let scopes = client
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("openid profile email offline_access")
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    json!(scopes)
}

pub fn read_plan_config(runtime_dir: &Path, file_name: &str) -> anyhow::Result<Value> {
    let path = runtime_dir.join(file_name);
    let body = fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&body)
        .map_err(|error| anyhow::anyhow!("failed to parse {}: {error}", path.display()))
}

#[cfg(test)]
#[path = "../../tests/in_source/src/oidf_seed/tests/config.rs"]
mod tests;
