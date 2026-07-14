//! External signer boundary for active JWT signing keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time;

use crate::local::SigningBackend;
use crate::{model::ExternalSigningKey, store::signing_algorithm_name};
use nazo_auth::{SignError, Signature};
use std::{future::Future, pin::Pin};

pub(crate) struct ExternalBackend<'a> {
    pub(crate) external: &'a ExternalSigningKey,
    pub(crate) kid: &'a str,
    pub(crate) algorithm: jsonwebtoken::Algorithm,
    pub(crate) public_jwk: &'a Value,
}

impl SigningBackend for ExternalBackend<'_> {
    fn sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignError>> + Send + 'a>> {
        Box::pin(async move {
            let input = std::str::from_utf8(signing_input).map_err(|_| SignError::SigningFailed)?;
            let encoded = sign_external_jwt_input(
                self.external,
                self.kid,
                self.algorithm,
                input,
                self.public_jwk,
            )
            .await
            .map_err(|_| SignError::SigningFailed)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SignError::SigningFailed)?;
            Ok(Signature::new(bytes))
        })
    }
}

pub(super) async fn sign_external_jwt_input(
    external: &ExternalSigningKey,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    signing_input: &str,
    public_jwk: &Value,
) -> jsonwebtoken::errors::Result<String> {
    let alg_name =
        signing_algorithm_name(alg).ok_or(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
    let request = json!({
        "version": 1,
        "kid": kid,
        "alg": alg_name,
        "key_ref": external.key_ref,
        "signing_input": signing_input
    });
    let mut child = Command::new(
        external
            .command
            .as_slice()
            .first()
            .ok_or_else(|| jwt_provider_error("external signer command is empty"))?,
    )
    .args(external.command.iter().skip(1))
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .map_err(|error| jwt_provider_error(format!("failed to spawn external signer: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdin unavailable"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdout unavailable"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stderr unavailable"))?;
    let stdout_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.map(|_| output)
    });
    let stderr_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).await.map(|_| output)
    });
    stdin
        .write_all(serde_json::to_string(&request)?.as_bytes())
        .await
        .map_err(|error| {
            jwt_provider_error(format!("failed to write external signer request: {error}"))
        })?;
    drop(stdin);
    let status = match time::timeout(external.timeout, child.wait()).await {
        Ok(result) => result
            .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?,
        Err(_) => {
            let _ = child.kill().await;
            return Err(jwt_provider_error("external signer timed out"));
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|error| {
            jwt_provider_error(format!("external signer stdout join failed: {error}"))
        })?
        .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?;
    let _stderr = stderr_task
        .await
        .map_err(|error| {
            jwt_provider_error(format!("external signer stderr join failed: {error}"))
        })?
        .map_err(|error| jwt_provider_error(format!("external signer failed: {error}")))?;
    if !status.success() {
        return Err(jwt_provider_error(format!(
            "external signer exited with status {status}"
        )));
    }
    let response: Value = serde_json::from_slice(&stdout)?;
    let signature = response
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| jwt_provider_error("external signer response missing signature"))?;
    let decoded = URL_SAFE_NO_PAD.decode(signature).map_err(|error| {
        jwt_provider_error(format!(
            "external signer returned invalid signature: {error}"
        ))
    })?;
    if decoded.is_empty() {
        return Err(jwt_provider_error(
            "external signer returned empty signature",
        ));
    }
    verify_external_jwt_signature(external, kid, alg, signing_input, signature, public_jwk)?;
    Ok(signature.to_owned())
}

fn verify_external_jwt_signature(
    external: &ExternalSigningKey,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    signing_input: &str,
    signature: &str,
    public_jwk: &Value,
) -> jsonwebtoken::errors::Result<()> {
    let decoding_key = decoding_key_from_public_jwk(public_jwk, alg).ok_or_else(|| {
        jwt_provider_error("active external signer public JWK is not usable for verification")
    })?;
    match jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), &decoding_key, alg) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => {
            tracing::error!(
                kid,
                alg = ?alg,
                key_ref = %external.key_ref,
                "external signer returned a signature that failed local verification"
            );
            Err(jwt_provider_error(
                "external signer returned signature that does not verify with active public JWK",
            ))
        }
    }
}

fn decoding_key_from_public_jwk(
    key: &Value,
    algorithm: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let expected_algorithm = signing_algorithm_name(algorithm)?;
    if key
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|value| value != expected_algorithm)
        || key.get("d").is_some()
        || key
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != "sig")
    {
        return None;
    }
    match algorithm {
        jsonwebtoken::Algorithm::EdDSA => {
            if key.get("kty").and_then(Value::as_str) != Some("OKP")
                || key.get("crv").and_then(Value::as_str) != Some("Ed25519")
            {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(key.get("x")?.as_str()?).ok()
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(
                key.get("n")?.as_str()?,
                key.get("e")?.as_str()?,
            )
            .ok()
        }
        jsonwebtoken::Algorithm::ES256 => {
            if key.get("kty").and_then(Value::as_str) != Some("EC")
                || key.get("crv").and_then(Value::as_str) != Some("P-256")
            {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ec_components(
                key.get("x")?.as_str()?,
                key.get("y")?.as_str()?,
            )
            .ok()
        }
        _ => None,
    }
}

pub(super) fn jwt_provider_error(message: impl Into<String>) -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::ErrorKind::Provider(message.into()).into()
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;

    #[cfg(windows)]
    fn sleep_command() -> Arc<Vec<String>> {
        Arc::new(vec![
            "pwsh".to_owned(),
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            "$null=[Console]::In.ReadToEnd(); Start-Sleep -Seconds 2".to_owned(),
        ])
    }

    #[cfg(windows)]
    fn error_command() -> Arc<Vec<String>> {
        Arc::new(vec![
            "pwsh".to_owned(),
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            "$null=[Console]::In.ReadToEnd(); [Console]::Error.Write('secret'); exit 7".to_owned(),
        ])
    }

    #[cfg(unix)]
    fn error_command() -> Arc<Vec<String>> {
        Arc::new(vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "cat >/dev/null; printf secret >&2; exit 7".to_owned(),
        ])
    }

    #[cfg(unix)]
    fn sleep_command() -> Arc<Vec<String>> {
        Arc::new(vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "cat >/dev/null; sleep 2".to_owned(),
        ])
    }

    #[tokio::test]
    async fn external_signer_timeout_fails_closed() {
        let key = ExternalSigningKey {
            command: sleep_command(),
            key_ref: "kms://test/key".to_owned(),
            timeout: Duration::from_millis(25),
        };
        let error = sign_external_jwt_input(
            &key,
            "external",
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &json!({
                "kty":"OKP", "crv":"Ed25519", "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "kid":"external", "alg":"EdDSA", "use":"sig"
            }),
        )
        .await
        .expect_err("timeout must fail closed");
        assert!(format!("{error}").contains("timed out"));
    }

    #[tokio::test]
    async fn external_signer_process_fault_fails_closed_without_stderr_disclosure() {
        let key = ExternalSigningKey {
            command: error_command(),
            key_ref: "kms://test/key".to_owned(),
            timeout: Duration::from_secs(1),
        };
        let error = sign_external_jwt_input(
            &key,
            "external",
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &json!({
                "kty":"OKP", "crv":"Ed25519", "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "kid":"external", "alg":"EdDSA", "use":"sig"
            }),
        )
        .await
        .expect_err("process fault must fail closed");
        let message = format!("{error}");
        assert!(message.contains("exited with status"));
        assert!(!message.contains("secret"));
    }
}

#[cfg(test)]
#[path = "tests/external_compat.rs"]
mod compatibility_tests;
