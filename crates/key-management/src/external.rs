//! External signer boundary for active JWT signing keys.

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{
    ChildWrapper as ProcessChildWrapper, CommandWrap as ProcessCommandWrap,
    CommandWrapper as ProcessCommandWrapper, KillOnDrop as ProcessKillOnDrop,
};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time;

use crate::local::SigningBackend;
use crate::{
    model::{ExternalKeyRegistration, ExternalSigningKey, KeySettings},
    serialization::{
        keyset_keys, keyset_keys_mut, load_keyset_json, signing_algorithm_name,
        validate_keyset_json, write_json_atomic,
    },
};
use nazo_auth::{SignError, Signature};
use std::{
    future::Future,
    io::{Error, ErrorKind},
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, LazyLock},
};

const MAX_EXTERNAL_SIGNER_STDOUT_BYTES: usize = 64 * 1024;
const MAX_EXTERNAL_SIGNER_STDERR_BYTES: usize = 8 * 1024;
const MAX_CONCURRENT_EXTERNAL_SIGNERS: usize = 32;
const EXTERNAL_SIGNER_REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

static EXTERNAL_SIGNER_SLOTS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_EXTERNAL_SIGNERS));

struct AbortTasksOnDrop(Vec<tokio::task::AbortHandle>);

#[derive(Debug)]
enum ExternalSignerRequestWriteError {
    Io(std::io::Error),
    TimedOut,
}

impl Drop for AbortTasksOnDrop {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn write_external_signer_request(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    request_body: &[u8],
    deadline: time::Instant,
) -> Result<(), ExternalSignerRequestWriteError> {
    match time::timeout_at(deadline, writer.write_all(request_body)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ExternalSignerRequestWriteError::Io(error)),
        Err(_) => Err(ExternalSignerRequestWriteError::TimedOut),
    }
}

/// Process-wrap's platform wrappers provide the process group/job ownership, but Tokio's
/// `kill_on_drop` only knows about the direct child. Keep an explicit armed bit so cancellation of
/// this future still asks the platform wrapper to terminate the whole signer tree.
#[derive(Clone, Debug)]
struct KillProcessTreeOnDrop {
    armed: Arc<AtomicBool>,
}

#[derive(Debug)]
struct KillProcessTreeChild {
    inner: Option<Box<dyn ProcessChildWrapper>>,
    armed: Arc<AtomicBool>,
}

impl ProcessCommandWrapper for KillProcessTreeOnDrop {
    fn wrap_child(
        &mut self,
        child: Box<dyn ProcessChildWrapper>,
        _core: &ProcessCommandWrap,
    ) -> std::io::Result<Box<dyn ProcessChildWrapper>> {
        Ok(Box::new(KillProcessTreeChild {
            inner: Some(child),
            armed: Arc::clone(&self.armed),
        }))
    }
}

impl KillProcessTreeChild {
    fn inner_child(&self) -> &dyn ProcessChildWrapper {
        self.inner
            .as_deref()
            .expect("external signer child wrapper was consumed")
    }

    fn inner_child_mut(&mut self) -> &mut dyn ProcessChildWrapper {
        self.inner
            .as_deref_mut()
            .expect("external signer child wrapper was consumed")
    }
}

impl Drop for KillProcessTreeChild {
    fn drop(&mut self) {
        if self.armed.load(Ordering::Acquire) {
            let _ = self.inner_child_mut().start_kill();
            if let (Some(mut child), Ok(runtime)) =
                (self.inner.take(), tokio::runtime::Handle::try_current())
            {
                let armed = Arc::clone(&self.armed);
                runtime.spawn(async move {
                    if matches!(
                        time::timeout(EXTERNAL_SIGNER_REAP_TIMEOUT, child.wait()).await,
                        Ok(Ok(_))
                    ) {
                        armed.store(false, Ordering::Release);
                    } else {
                        tracing::error!(
                            "external signer process tree could not be reaped after cancellation"
                        );
                    }
                });
            }
        }
    }
}

impl ProcessChildWrapper for KillProcessTreeChild {
    fn inner(&self) -> &dyn ProcessChildWrapper {
        self.inner_child().inner()
    }

    fn inner_mut(&mut self) -> &mut dyn ProcessChildWrapper {
        self.inner_child_mut().inner_mut()
    }

    fn into_inner(mut self: Box<Self>) -> Box<dyn ProcessChildWrapper> {
        self.armed.store(false, Ordering::Release);
        self.inner
            .take()
            .expect("external signer child wrapper was consumed")
            .into_inner()
    }

    fn start_kill(&mut self) -> std::io::Result<()> {
        // Call the wrapped process-group/job wrapper directly. Its `inner_mut` intentionally
        // exposes the raw Tokio child, which would otherwise bypass whole-tree termination.
        self.inner_child_mut().start_kill()
    }

    fn wait(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<std::process::ExitStatus>> + Send + '_>> {
        self.inner_child_mut().wait()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.inner_child_mut().try_wait()
    }
}

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
    let deadline = time::Instant::now() + external.timeout;
    let _slot = time::timeout_at(deadline, EXTERNAL_SIGNER_SLOTS.acquire())
        .await
        .map_err(|_| jwt_provider_error("external signer capacity timeout"))?
        .map_err(|_| jwt_provider_error("external signer capacity unavailable"))?;
    let program = external
        .command
        .as_slice()
        .first()
        .ok_or_else(|| jwt_provider_error("external signer command is empty"))?;
    let armed = Arc::new(AtomicBool::new(true));
    let mut command = ProcessCommandWrap::with_new(program, |command| {
        command
            .args(external.command.iter().skip(1))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
    });
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    command.wrap(JobObject);
    // Keep Tokio's direct-child fallback armed for wrapper setup failures. The custom wrapper
    // below is registered last so its Drop invokes the platform group/job kill first.
    command.wrap(ProcessKillOnDrop);
    command.wrap(KillProcessTreeOnDrop {
        armed: Arc::clone(&armed),
    });
    let mut child = command
        .spawn()
        .map_err(|error| jwt_provider_error(format!("failed to spawn external signer: {error}")))?;
    let mut stdin = child
        .stdin()
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdin unavailable"))?;
    let stdout = child
        .stdout()
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stdout unavailable"))?;
    let stderr = child
        .stderr()
        .take()
        .ok_or_else(|| jwt_provider_error("external signer stderr unavailable"))?;
    let mut stdout_task = tokio::spawn(read_limited(stdout, MAX_EXTERNAL_SIGNER_STDOUT_BYTES));
    let mut stderr_task = tokio::spawn(read_limited(stderr, MAX_EXTERNAL_SIGNER_STDERR_BYTES));
    let _reader_abort_guard =
        AbortTasksOnDrop(vec![stdout_task.abort_handle(), stderr_task.abort_handle()]);
    let request_body = serde_json::to_string(&request)?;
    match write_external_signer_request(&mut stdin, request_body.as_bytes(), deadline).await {
        Ok(()) => {}
        Err(ExternalSignerRequestWriteError::Io(error)) => {
            stdout_task.abort();
            stderr_task.abort();
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error(format!(
                "failed to write external signer request: {error}"
            )));
        }
        Err(ExternalSignerRequestWriteError::TimedOut) => {
            stdout_task.abort();
            stderr_task.abort();
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error("external signer timed out"));
        }
    }
    drop(stdin);
    let stdout = match time::timeout_at(deadline, &mut stdout_task).await {
        Ok(result) => match result {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                stderr_task.abort();
                terminate_process_tree(&mut child, &armed).await;
                return Err(jwt_provider_error(format!(
                    "external signer failed: {error}"
                )));
            }
            Err(error) => {
                stderr_task.abort();
                terminate_process_tree(&mut child, &armed).await;
                return Err(jwt_provider_error(format!(
                    "external signer stdout join failed: {error}"
                )));
            }
        },
        Err(_) => {
            stdout_task.abort();
            stderr_task.abort();
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error("external signer timed out"));
        }
    };
    let _stderr = match time::timeout_at(deadline, &mut stderr_task).await {
        Ok(result) => match result {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                terminate_process_tree(&mut child, &armed).await;
                return Err(jwt_provider_error(format!(
                    "external signer failed: {error}"
                )));
            }
            Err(error) => {
                terminate_process_tree(&mut child, &armed).await;
                return Err(jwt_provider_error(format!(
                    "external signer stderr join failed: {error}"
                )));
            }
        },
        Err(_) => {
            stdout_task.abort();
            stderr_task.abort();
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error("external signer timed out"));
        }
    };
    // Wait only for the raw leader, not the process-group/job wrapper: the latter deliberately
    // waits for every owned descendant, while a valid response may be emitted just before those
    // descendants are terminated below.
    let status = match time::timeout_at(deadline, child.inner_mut().wait()).await {
        Ok(Ok(status)) => status,
        Err(_) => {
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error("external signer timed out"));
        }
        Ok(Err(error)) => {
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error(format!(
                "failed to read external signer status: {error}"
            )));
        }
    };
    if !status.success() {
        terminate_process_tree(&mut child, &armed).await;
        return Err(jwt_provider_error(format!(
            "external signer exited with status {status}"
        )));
    }
    let response: Value = match serde_json::from_slice(&stdout) {
        Ok(response) => response,
        Err(error) => {
            terminate_process_tree(&mut child, &armed).await;
            return Err(error.into());
        }
    };
    let signature = match response.get("signature").and_then(Value::as_str) {
        Some(signature) => signature,
        None => {
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error(
                "external signer response missing signature",
            ));
        }
    };
    let decoded = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(decoded) => decoded,
        Err(error) => {
            terminate_process_tree(&mut child, &armed).await;
            return Err(jwt_provider_error(format!(
                "external signer returned invalid signature: {error}"
            )));
        }
    };
    if decoded.is_empty() {
        terminate_process_tree(&mut child, &armed).await;
        return Err(jwt_provider_error(
            "external signer returned empty signature",
        ));
    }
    if let Err(error) =
        verify_external_jwt_signature(external, kid, alg, signing_input, signature, public_jwk)
    {
        terminate_process_tree(&mut child, &armed).await;
        return Err(error);
    }
    // A signer is not allowed to daemonize: even after a valid response and a normal leader exit,
    // every process in the owned group/job must be terminated and reaped before returning.
    terminate_process_tree(&mut child, &armed).await;
    Ok(signature.to_owned())
}

async fn terminate_process_tree(child: &mut Box<dyn ProcessChildWrapper>, armed: &AtomicBool) {
    let _ = child.start_kill();
    match time::timeout(EXTERNAL_SIGNER_REAP_TIMEOUT, child.wait()).await {
        Ok(Ok(_)) => armed.store(false, Ordering::Release),
        Ok(Err(error)) => tracing::error!(%error, "failed to reap external signer process tree"),
        Err(_) => tracing::error!(
            timeout_seconds = EXTERNAL_SIGNER_REAP_TIMEOUT.as_secs(),
            "timed out reaping external signer process tree"
        ),
    }
}

async fn read_limited<R>(reader: R, limit: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.saturating_add(1));
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut output)
        .await?;
    if output.len() > limit {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "external signer output exceeds configured limit",
        ));
    }
    Ok(output)
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
            let modulus = key.get("n")?.as_str()?;
            let exponent = key.get("e")?.as_str()?;
            if !nazo_auth::rsa_public_key_components_are_safe(
                &URL_SAFE_NO_PAD.decode(modulus).ok()?,
                &URL_SAFE_NO_PAD.decode(exponent).ok()?,
            ) {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(modulus, exponent).ok()
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

/// Registers an externally managed signing key without copying private material into the keyset.
///
/// The public JWK is read before the keyset is changed, and the JSON update is committed through
/// the shared atomic writer.  Retrying the exact registration is idempotent; changing any part of
/// an existing `kid` fails closed so a key reference cannot silently drift.
pub(crate) async fn register_external_key(
    settings: &KeySettings,
    registration: ExternalKeyRegistration,
) -> anyhow::Result<()> {
    let algorithm = signing_algorithm_name(registration.algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg"))?;
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
        "created_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "retire_at":null
    }));
    validate_keyset_json(&keyset)?;
    write_json_atomic(&path, &keyset).await
}

#[cfg(test)]
#[path = "../tests/unit/external.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/external/external_signer.rs"]
mod external_signer_tests;
