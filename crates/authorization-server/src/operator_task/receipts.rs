use super::*;

pub(super) fn sign_task_outcome(
    task: &TaskEnvelope,
    request_sha256: &str,
    outcome: TaskOutcome,
    receipt_key_id: &str,
    receipt_key_path: &Path,
    started_at: i64,
    completed_at: i64,
) -> anyhow::Result<String> {
    let receipt = RuntimeReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("runtime:{}", task.deployment_id),
        aud: task.iss.clone(),
        jti: task.jti.clone(),
        request_sha256: request_sha256.to_owned(),
        deployment_id: task.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        started_at,
        completed_at,
        embedded: embedded_identity(),
        config: task.config.clone(),
        outcome,
    };
    validate_runtime_receipt_deployment_binding(&receipt, &task.deployment_id).map_err(
        |error| anyhow::anyhow!("runtime receipt deployment identity is invalid: {error}"),
    )?;
    let receipt_key = read_signing_key(receipt_key_path)?;
    Ok(sign_runtime_receipt(
        &receipt,
        receipt_key_id,
        &receipt_key,
    )?)
}

pub(super) fn read_published_receipt(
    path: &Path,
    task: &TaskEnvelope,
    request_sha256: &str,
    expected_deployment_id: &str,
    receipt_key_id: &str,
    receipt_key_path: &Path,
) -> anyhow::Result<Option<String>> {
    if !regular_state_file_present(path, "operator task receipt")? {
        return Ok(None);
    }
    let compact = fs::read_to_string(path)?;
    validate_receipt_for_task(
        &compact,
        task,
        request_sha256,
        expected_deployment_id,
        receipt_key_id,
        receipt_key_path,
    )?;
    Ok(Some(compact))
}

pub(super) fn recover_receipt_temporary(
    path: &Path,
    task: &TaskEnvelope,
    request_sha256: &str,
    expected_deployment_id: &str,
    receipt_key_id: &str,
    receipt_key_path: &Path,
) -> anyhow::Result<Option<String>> {
    let temporary = receipt_temporary_path(path);
    if !state_path_present(&temporary)? {
        return Ok(None);
    }
    regular_state_file_present(&temporary, "operator task receipt temporary")?;
    let compact = fs::read_to_string(&temporary)?;
    validate_receipt_for_task(
        &compact,
        task,
        request_sha256,
        expected_deployment_id,
        receipt_key_id,
        receipt_key_path,
    )?;
    fs::rename(&temporary, path)?;
    sync_directory(
        path.parent()
            .context("operator task receipt has no state directory")?,
    )?;
    Ok(Some(compact))
}

pub(super) fn validate_receipt_for_task(
    compact: &str,
    task: &TaskEnvelope,
    request_sha256: &str,
    expected_deployment_id: &str,
    receipt_key_id: &str,
    receipt_key_path: &Path,
) -> anyhow::Result<()> {
    let receipt_key = read_signing_key(receipt_key_path)?;
    let receipt = verify_runtime_receipt(compact, receipt_key_id, &receipt_key.verifying_key())
        .map_err(|error| anyhow::anyhow!("operator task receipt is invalid: {error}"))?;
    validate_runtime_receipt_deployment_binding(&receipt, expected_deployment_id).map_err(
        |error| anyhow::anyhow!("operator task receipt deployment identity is invalid: {error}"),
    )?;
    if receipt.jti != task.jti
        || receipt.request_sha256 != request_sha256
        || receipt.actor != task.actor
        || receipt.operation != operation_name(&task.operation)
        || receipt.embedded != task.embedded
        || receipt.config != task.config
    {
        bail!("operator task receipt is not bound to this request");
    }
    Ok(())
}

pub(super) fn write_receipt_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = receipt_temporary_path(path);
    if state_path_present(&temporary)? {
        bail!("operator task receipt has an incomplete durable publication; refusing recovery");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    pause_at_test_failpoint("after-receipt-sync")?;
    fs::rename(temporary, path)?;
    sync_directory(
        path.parent()
            .context("operator task receipt has no state directory")?,
    )?;
    Ok(())
}

pub(super) fn receipt_temporary_path(path: &Path) -> PathBuf {
    path.with_extension("receipt.jws.tmp")
}

pub(super) fn verify_public_jwk(expected_sha256: &str) -> anyhow::Result<PathBuf> {
    let path = configured_path(
        "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE",
        EXTERNAL_PUBLIC_JWK_PATH,
    );
    verify_public_jwk_at(expected_sha256, path)
}

pub(super) fn verify_public_jwk_at(
    expected_sha256: &str,
    path: PathBuf,
) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(&path).context("external public JWK was not mounted")?;
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected_sha256 {
        bail!("external public JWK digest mismatch");
    }
    Ok(path)
}

pub(super) fn read_verifying_key(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = read_key_bytes(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid controller public key")
}

pub(super) fn read_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = read_key_bytes(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(super) fn read_key_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    let value = fs::read_to_string(path)?;
    URL_SAFE_NO_PAD
        .decode(value.trim())
        .context("operator key is not canonical base64url")
}

pub(super) fn stable_error_code(error: &anyhow::Error) -> String {
    let digest = Sha256::digest(format!("{error:#}").as_bytes());
    format!(
        "operation-failed-{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}
