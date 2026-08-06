use super::*;
use std::{
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::Arc,
    time::Duration,
};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

use crate::store::{generate_key_material, public_jwk_from_private_der};

fn external_signing_key() -> ExternalSigningKey {
    external_signing_key_with_command(Arc::new(vec!["unused-test-signer".to_owned()]), 100)
}

fn external_signing_key_with_command(
    command: Arc<Vec<String>>,
    timeout_ms: u64,
) -> ExternalSigningKey {
    ExternalSigningKey {
        command,
        key_ref: "kms://test/key".to_owned(),
        timeout: Duration::from_millis(timeout_ms),
    }
}

#[cfg(unix)]
fn signer_stdout_command(stdout: &str) -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("cat >/dev/null; printf '%s' {}", shell_single_quote(stdout)),
    ])
}

#[cfg(windows)]
fn signer_stdout_command(stdout: &str) -> Arc<Vec<String>> {
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        format!(
            "$null = [Console]::In.ReadToEnd(); [Console]::Out.Write({})",
            powershell_single_quote(stdout)
        ),
    ])
}

#[cfg(unix)]
fn signer_error_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "cat >/dev/null; printf '%s' 'denied by signer' >&2; exit 7".to_owned(),
    ])
}

#[cfg(windows)]
fn signer_error_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        "$null = [Console]::In.ReadToEnd(); [Console]::Error.Write('denied by signer'); exit 7"
            .to_owned(),
    ])
}

#[cfg(unix)]
fn signer_sleep_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "cat >/dev/null; sleep 2".to_owned(),
    ])
}

#[cfg(windows)]
fn signer_sleep_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        "$null = [Console]::In.ReadToEnd(); Start-Sleep -Seconds 2".to_owned(),
    ])
}

#[cfg(unix)]
fn signer_large_stdout_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "cat >/dev/null; head -c 65537 /dev/zero".to_owned(),
    ])
}

#[cfg(unix)]
fn signer_large_stderr_command(signature: &str) -> Arc<Vec<String>> {
    let response = shell_single_quote(&json!({"signature": signature}).to_string());
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("cat >/dev/null; printf '%s' {response}; head -c 8193 /dev/zero >&2"),
    ])
}

#[cfg(unix)]
fn signer_stderr_timeout_command(signature: &str) -> Arc<Vec<String>> {
    let response = shell_single_quote(&json!({"signature": signature}).to_string());
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "cat >/dev/null; printf '%s' {response}; exec 1>&-; (sleep 30 </dev/null >/dev/null) &"
        ),
    ])
}

#[cfg(unix)]
fn signer_status_timeout_command(signature: &str) -> Arc<Vec<String>> {
    let response = shell_single_quote(&json!({"signature": signature}).to_string());
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("cat >/dev/null; printf '%s' {response}; exec 1>&- 2>&-; sleep 30"),
    ])
}

#[cfg(unix)]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(windows)]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(unix)]
fn descendant_signer_command(pid_path: &Path, response: Option<&str>) -> Arc<Vec<String>> {
    let pid_path = shell_single_quote(
        pid_path
            .to_str()
            .expect("temporary descendant pid path should be valid UTF-8"),
    );
    let action = response.map_or_else(
        || "sleep 30".to_owned(),
        |response| {
            format!(
                "sleep 1; printf '%s' {}; exit 0",
                shell_single_quote(response)
            )
        },
    );
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "(sleep 30 </dev/null >/dev/null 2>&1) & child=$!; printf '%s' \"$child\" > {pid_path}; cat >/dev/null; {action}",
        ),
    ])
}

#[cfg(windows)]
fn descendant_signer_command(pid_path: &Path, response: Option<&str>) -> Arc<Vec<String>> {
    let pid_path = powershell_single_quote(
        pid_path
            .to_str()
            .expect("temporary descendant pid path should be valid UTF-8"),
    );
    let action = response.map_or_else(
        || "Start-Sleep -Seconds 30".to_owned(),
        |response| {
            format!(
                "Start-Sleep -Seconds 1; [Console]::Out.Write({}); exit 0",
                powershell_single_quote(response)
            )
        },
    );
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        format!(
            "$child=Start-Process -FilePath 'pwsh' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden; Set-Content -LiteralPath {pid_path} -Value $child.Id -NoNewline; $null=[Console]::In.ReadToEnd(); {action}",
        ),
    ])
}

#[cfg(unix)]
fn descendant_blocking_stdin_command(pid_path: &Path) -> Arc<Vec<String>> {
    let pid_path = shell_single_quote(
        pid_path
            .to_str()
            .expect("temporary descendant pid path should be valid UTF-8"),
    );
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "(sleep 30 </dev/null >/dev/null 2>&1) & child=$!; printf '%s' \"$child\" > {pid_path}; sleep 30",
        ),
    ])
}

#[cfg(windows)]
fn descendant_blocking_stdin_command(pid_path: &Path) -> Arc<Vec<String>> {
    let pid_path = powershell_single_quote(
        pid_path
            .to_str()
            .expect("temporary descendant pid path should be valid UTF-8"),
    );
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        format!(
            "$child=Start-Process -FilePath 'pwsh' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden; Set-Content -LiteralPath {pid_path} -Value $child.Id -NoNewline; Start-Sleep -Seconds 30",
        ),
    ])
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        return stat
            .split_whitespace()
            .nth(2)
            .is_some_and(|state| state != "Z");
    }
    ProcessCommand::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    let script = format!(
        "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
    );
    ProcessCommand::new("pwsh")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn kill_process_for_test(pid: u32) {
    let _ = ProcessCommand::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

#[cfg(windows)]
fn kill_process_for_test(pid: u32) {
    let _ = ProcessCommand::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status();
}

struct DescendantFixture {
    pid_path: PathBuf,
    pid: Option<u32>,
}

impl DescendantFixture {
    fn new() -> Self {
        Self {
            pid_path: std::env::temp_dir().join(format!(
                "nazo-external-signer-descendant-{}.pid",
                Uuid::now_v7()
            )),
            pid: None,
        }
    }

    async fn wait_until_alive(&mut self) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pid) = std::fs::read_to_string(&self.pid_path)
                .ok()
                .and_then(|value| value.trim().parse().ok())
                && process_is_alive(pid)
            {
                self.pid = Some(pid);
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "signer did not publish a live descendant pid at {}",
                self.pid_path.display()
            );
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn assert_gone(&self, pid: u32) {
        assert_eq!(self.pid, Some(pid));
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_is_alive(pid) {
            assert!(
                Instant::now() < deadline,
                "external signer descendant {pid} survived tree termination"
            );
            sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for DescendantFixture {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.filter(|pid| process_is_alive(*pid)) {
            kill_process_for_test(pid);
        }
        let _ = std::fs::remove_file(&self.pid_path);
    }
}

fn eddsa_fixture(kid: &str) -> (Vec<u8>, Value) {
    let material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        &material.private_pkcs8_der,
    )
    .expect("public JWK should derive");
    (material.private_pkcs8_der, public_jwk)
}

fn sign_input(private_key: &[u8], signing_input: &str) -> String {
    jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        &jsonwebtoken::EncodingKey::from_ed_der(private_key),
        jsonwebtoken::Algorithm::EdDSA,
    )
    .expect("test signature should sign")
}

async fn sign_with_command(command: Arc<Vec<String>>) -> jsonwebtoken::errors::Result<String> {
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    sign_external_jwt_input(
        &external_signing_key_with_command(command, 5_000),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &public_jwk,
    )
    .await
}

#[test]
fn jwt_provider_error_creates_provider_error_kind() {
    let error = jwt_provider_error("test error message");
    let display = format!("{error}");
    assert!(
        display.contains("test error message"),
        "error display should contain message: {display}"
    );
}

#[test]
fn jwt_provider_error_is_jsonwebtoken_error() {
    use std::error::Error;
    let error = jwt_provider_error("some error");
    let source = error.source();
    assert!(
        source.is_none(),
        "jsonwebtoken::Error with Provider kind should not have a source"
    );
}

#[test]
fn jwt_provider_error_with_empty_message() {
    let error = jwt_provider_error("");
    let display = format!("{error}");
    assert!(!display.is_empty());
}

#[test]
fn jwt_provider_error_with_owned_string() {
    let msg = "dynamic".to_owned() + " error";
    let error = jwt_provider_error(msg);
    assert!(format!("{error}").contains("dynamic error"));
}

#[test]
fn external_signature_verification_accepts_signature_bound_to_active_public_jwk() {
    let kid = "external-kid";
    let signing_input = "header.claims";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, signing_input);

    verify_external_jwt_signature(
        &external_signing_key(),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        signing_input,
        &signature,
        &public_jwk,
    )
    .expect("matching external signature should verify locally");
}

#[test]
fn external_signature_verification_rejects_signature_that_does_not_match_input() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "header.claims");
    let error = verify_external_jwt_signature(
        &external_signing_key(),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.tampered_claims",
        &signature,
        &public_jwk,
    )
    .expect_err("external signer output must be checked against the exact signing input");

    assert!(
        format!("{error}").contains("does not verify"),
        "unexpected verification error: {error}"
    );
}

#[test]
fn external_signature_verification_rejects_unusable_active_public_jwk() {
    let error = verify_external_jwt_signature(
        &external_signing_key(),
        "external-kid",
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        "ZmFrZS1zaWduYXR1cmU",
        &json!({"kty": "oct", "k": "not-a-public-signing-key"}),
    )
    .expect_err("external signer verification must fail closed without usable public JWK");

    assert!(
        format!("{error}").contains("not usable"),
        "unexpected verification error: {error}"
    );
}

#[test]
fn external_public_jwk_policy_is_algorithm_and_usage_bound() {
    let (_private_key, ed_jwk) = eddsa_fixture("ed-kid");
    assert!(decoding_key_from_public_jwk(&ed_jwk, jsonwebtoken::Algorithm::EdDSA).is_some());

    let mut wrong_algorithm = ed_jwk.clone();
    wrong_algorithm["alg"] = json!("RS256");
    assert!(
        decoding_key_from_public_jwk(&wrong_algorithm, jsonwebtoken::Algorithm::EdDSA).is_none()
    );

    let mut private_jwk = ed_jwk.clone();
    private_jwk["d"] = json!("private-material");
    assert!(decoding_key_from_public_jwk(&private_jwk, jsonwebtoken::Algorithm::EdDSA).is_none());

    let mut encryption_key = ed_jwk.clone();
    encryption_key["use"] = json!("enc");
    assert!(
        decoding_key_from_public_jwk(&encryption_key, jsonwebtoken::Algorithm::EdDSA).is_none()
    );

    let mut wrong_curve = ed_jwk.clone();
    wrong_curve["crv"] = json!("P-256");
    assert!(decoding_key_from_public_jwk(&wrong_curve, jsonwebtoken::Algorithm::EdDSA).is_none());

    let mut missing_x = ed_jwk.clone();
    missing_x
        .as_object_mut()
        .expect("fixture should be an object")
        .remove("x");
    assert!(decoding_key_from_public_jwk(&missing_x, jsonwebtoken::Algorithm::EdDSA).is_none());

    let ec_material = generate_key_material(jsonwebtoken::Algorithm::ES256)
        .expect("ES256 test key should generate");
    let ec_jwk = public_jwk_from_private_der(
        "ec-kid",
        jsonwebtoken::Algorithm::ES256,
        &ec_material.private_pkcs8_der,
    )
    .expect("ES256 public JWK should derive");
    assert!(decoding_key_from_public_jwk(&ec_jwk, jsonwebtoken::Algorithm::ES256).is_some());

    let mut wrong_ec_kty = ec_jwk.clone();
    wrong_ec_kty["kty"] = json!("OKP");
    assert!(decoding_key_from_public_jwk(&wrong_ec_kty, jsonwebtoken::Algorithm::ES256).is_none());

    let mut missing_ec_coordinate = ec_jwk.clone();
    missing_ec_coordinate
        .as_object_mut()
        .expect("fixture should be an object")
        .remove("y");
    assert!(
        decoding_key_from_public_jwk(&missing_ec_coordinate, jsonwebtoken::Algorithm::ES256)
            .is_none()
    );

    let rsa_material = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("RSA test key should generate");
    let rsa_jwk = public_jwk_from_private_der(
        "rsa-kid",
        jsonwebtoken::Algorithm::RS256,
        &rsa_material.private_pkcs8_der,
    )
    .expect("RSA public JWK should derive");
    assert!(decoding_key_from_public_jwk(&rsa_jwk, jsonwebtoken::Algorithm::RS256).is_some());
    assert!(decoding_key_from_public_jwk(&rsa_jwk, jsonwebtoken::Algorithm::PS256).is_none());

    let mut unsafe_rsa = rsa_jwk.clone();
    unsafe_rsa["n"] = json!("AQ");
    unsafe_rsa["e"] = json!("AQ");
    assert!(decoding_key_from_public_jwk(&unsafe_rsa, jsonwebtoken::Algorithm::RS256).is_none());

    assert!(
        decoding_key_from_public_jwk(
            &json!({"kty": "oct", "k": "not-a-public-key"}),
            jsonwebtoken::Algorithm::HS256,
        )
        .is_none()
    );
}

#[tokio::test]
async fn external_signing_rejects_empty_command_before_any_signing_attempt() {
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(Arc::new(Vec::new()), 100),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &public_jwk,
    )
    .await
    .expect_err("external signer command must be configured explicitly");

    assert!(
        format!("{error}").contains("command is empty"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_signing_rejects_non_server_signing_algorithm_before_spawn() {
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(signer_stdout_command("{}"), 100),
        kid,
        jsonwebtoken::Algorithm::HS256,
        "header.claims",
        &public_jwk,
    )
    .await
    .expect_err("external signer must only be invoked for server asymmetric signing algorithms");

    assert!(matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
    ));
}

#[tokio::test]
async fn external_signing_reports_stable_process_rejection_without_stderr() {
    let error = sign_with_command(signer_error_command())
        .await
        .expect_err("non-zero signer exit must fail the JWT issuance boundary");

    let display = format!("{error}");
    assert!(
        display.contains("exited with status") && !display.contains("denied by signer"),
        "unexpected error: {display}"
    );
}

#[tokio::test]
async fn external_signing_rejects_malformed_json_response() {
    let error = sign_with_command(signer_stdout_command("not-json"))
        .await
        .expect_err("external signer output must be structured JSON");

    assert!(
        format!("{error}").contains("expected"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_signing_requires_signature_member() {
    let error = sign_with_command(signer_stdout_command("{}"))
        .await
        .expect_err("external signer response without a signature must fail closed");

    assert!(
        format!("{error}").contains("missing signature"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_signing_rejects_non_base64url_signature() {
    let error = sign_with_command(signer_stdout_command(r#"{"signature":"***"}"#))
        .await
        .expect_err("external signer response must carry base64url signature bytes");

    assert!(
        format!("{error}").contains("invalid signature"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_signing_rejects_empty_signature_bytes() {
    let error = sign_with_command(signer_stdout_command(r#"{"signature":""}"#))
        .await
        .expect_err("external signer response must not be an empty signature");

    assert!(
        format!("{error}").contains("empty signature"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_signing_times_out_and_fails_closed() {
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(signer_sleep_command(), 50),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &public_jwk,
    )
    .await
    .expect_err("slow external signer must not block token issuance indefinitely");

    assert!(
        format!("{error}").contains("timed out"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_request_writer_classifies_closed_pipe_and_backpressure_timeout() {
    let (mut closed_writer, closed_reader) = tokio::io::duplex(64);
    drop(closed_reader);
    let error = write_external_signer_request(
        &mut closed_writer,
        b"request",
        tokio::time::Instant::now() + std::time::Duration::from_secs(1),
    )
    .await
    .expect_err("a closed signer pipe must reject the request write");
    assert!(matches!(
        error,
        ExternalSignerRequestWriteError::Io(error)
            if error.kind() == std::io::ErrorKind::BrokenPipe
    ));

    let (mut blocked_writer, _blocked_reader) = tokio::io::duplex(1);
    let error = write_external_signer_request(
        &mut blocked_writer,
        b"request",
        tokio::time::Instant::now() + std::time::Duration::from_millis(10),
    )
    .await
    .expect_err("a backpressured signer pipe must honor the request deadline");
    assert!(matches!(error, ExternalSignerRequestWriteError::TimedOut));
}

#[cfg(unix)]
#[tokio::test]
async fn external_signing_rejects_oversized_stdout() {
    let error = sign_with_command(signer_large_stdout_command())
        .await
        .expect_err("external signer stdout must be bounded");

    assert!(
        format!("{error}").contains("exceeds configured limit"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn external_signing_rejects_oversized_stderr() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "header.claims");
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(signer_large_stderr_command(&signature), 5_000),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &public_jwk,
    )
    .await
    .expect_err("external signer stderr must be bounded");

    assert!(
        format!("{error}").contains("exceeds configured limit"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn external_signing_stderr_timeout_fails_closed() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "header.claims");
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(signer_stderr_timeout_command(&signature), 50),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &public_jwk,
    )
    .await
    .expect_err("a signer that leaves stderr open must time out");

    assert!(
        format!("{error}").contains("timed out"),
        "unexpected error: {error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn external_signing_status_timeout_fails_closed() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "header.claims");
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(signer_status_timeout_command(&signature), 50),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &public_jwk,
    )
    .await
    .expect_err("a signer that never exits must time out while waiting for status");

    assert!(
        format!("{error}").contains("timed out"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_signing_reports_spawn_failures_without_panicking() {
    let error = sign_external_jwt_input(
        &external_signing_key_with_command(
            Arc::new(vec!["nazo-auth-test-signer-that-does-not-exist".to_owned()]),
            500,
        ),
        "external-kid",
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        &eddsa_fixture("external-kid").1,
    )
    .await
    .expect_err("missing signer executable must fail at the process boundary");

    assert!(
        format!("{error}").contains("failed to spawn external signer"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn external_output_reader_enforces_the_configured_limit() {
    let exact = read_limited(std::io::Cursor::new(b"abc".to_vec()), 3)
        .await
        .expect("output at the limit should be accepted");
    assert_eq!(exact, b"abc");

    let error = read_limited(std::io::Cursor::new(b"abcd".to_vec()), 3)
        .await
        .expect_err("output above the limit must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("exceeds configured limit"));
}

#[cfg(unix)]
#[tokio::test]
async fn process_tree_child_delegates_nonblocking_wait_and_consumption() {
    use process_wrap::tokio::{CommandWrap, ProcessGroup};
    use std::process::Stdio;
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut command = CommandWrap::with_new("sh", |command| {
        command
            .args(["-c", "sleep 1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    });
    command.wrap(ProcessGroup::leader());
    let armed = Arc::new(AtomicBool::new(true));
    command.wrap(KillProcessTreeOnDrop {
        armed: Arc::clone(&armed),
    });
    let mut child = command.spawn().expect("test process should spawn");

    assert!(
        child
            .try_wait()
            .expect("try_wait should delegate to the wrapped child")
            .is_none()
    );
    child
        .start_kill()
        .expect("start_kill should delegate to the process-group wrapper");
    let status = child
        .wait()
        .await
        .expect("wait should delegate to the wrapped child");
    assert!(!status.success());
    let _raw_child = child.into_inner();
    assert!(!armed.load(Ordering::Acquire));
}

#[tokio::test]
async fn external_signer_success_terminates_owned_descendant() {
    let mut fixture = DescendantFixture::new();
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "header.claims");
    let response = json!({"signature": signature}).to_string();
    let external = external_signing_key_with_command(
        descendant_signer_command(&fixture.pid_path, Some(&response)),
        5_000,
    );
    let task = tokio::spawn(async move {
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &public_jwk,
        )
        .await
    });
    let pid = fixture.wait_until_alive().await;
    let result = task
        .await
        .expect("external signer task should not panic")
        .expect("valid signer response should succeed");
    assert_eq!(result, signature);
    fixture.assert_gone(pid).await;
}

#[tokio::test]
async fn external_signer_malformed_response_terminates_owned_descendant() {
    let mut fixture = DescendantFixture::new();
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let external = external_signing_key_with_command(
        descendant_signer_command(&fixture.pid_path, Some("not-json")),
        5_000,
    );
    let task = tokio::spawn(async move {
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &public_jwk,
        )
        .await
    });
    let pid = fixture.wait_until_alive().await;
    let error = task
        .await
        .expect("external signer task should not panic")
        .expect_err("malformed signer output must fail");
    assert!(format!("{error}").contains("expected"));
    fixture.assert_gone(pid).await;
}

#[tokio::test]
async fn external_signer_invalid_signature_terminates_owned_descendant() {
    let mut fixture = DescendantFixture::new();
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let response = json!({"signature": "ZmFrZQ"}).to_string();
    let external = external_signing_key_with_command(
        descendant_signer_command(&fixture.pid_path, Some(&response)),
        5_000,
    );
    let task = tokio::spawn(async move {
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &public_jwk,
        )
        .await
    });
    let pid = fixture.wait_until_alive().await;
    let error = task
        .await
        .expect("external signer task should not panic")
        .expect_err("invalid signer signature must fail closed");
    assert!(format!("{error}").contains("does not verify"));
    fixture.assert_gone(pid).await;
}

#[tokio::test]
async fn external_signer_timeout_terminates_owned_descendant() {
    let mut fixture = DescendantFixture::new();
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let external = external_signing_key_with_command(
        descendant_signer_command(&fixture.pid_path, None),
        // Windows PowerShell cold start can exceed two seconds under a full
        // workspace test load. Keep the timeout well below the fixture's
        // thirty-second sleep while allowing the descendant to be observed.
        8_000,
    );
    let task = tokio::spawn(async move {
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &public_jwk,
        )
        .await
    });
    let pid = fixture.wait_until_alive().await;
    let error = task
        .await
        .expect("external signer task should not panic")
        .expect_err("slow signer must time out");
    assert!(format!("{error}").contains("timed out"));
    fixture.assert_gone(pid).await;
}

#[tokio::test]
async fn external_signer_stdin_timeout_terminates_owned_descendant() {
    let mut fixture = DescendantFixture::new();
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let external = external_signing_key_with_command(
        descendant_blocking_stdin_command(&fixture.pid_path),
        // Starting nested PowerShell processes can take several seconds on a
        // loaded Windows test runner. Keep the signer timeout comfortably past
        // fixture readiness so this test measures blocked stdin termination,
        // not process-startup scheduling.
        10_000,
    );
    let signing_input = "x".repeat(2 * 1024 * 1024);
    let task = tokio::spawn(async move {
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            &signing_input,
            &public_jwk,
        )
        .await
    });
    let pid = fixture.wait_until_alive().await;
    let error = task
        .await
        .expect("external signer task should not panic")
        .expect_err("signer that does not consume stdin must time out");
    assert!(format!("{error}").contains("timed out"));
    fixture.assert_gone(pid).await;
}

#[tokio::test]
async fn external_signer_future_cancellation_terminates_owned_descendant() {
    let mut fixture = DescendantFixture::new();
    let kid = "external-kid";
    let (_private_key, public_jwk) = eddsa_fixture(kid);
    let external = external_signing_key_with_command(
        descendant_signer_command(&fixture.pid_path, None),
        5_000,
    );
    let task = tokio::spawn(async move {
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "header.claims",
            &public_jwk,
        )
        .await
    });
    let pid = fixture.wait_until_alive().await;
    task.abort();
    assert!(
        task.await
            .expect_err("aborted signer future should report cancellation")
            .is_cancelled()
    );
    fixture.assert_gone(pid).await;
}

#[tokio::test]
async fn external_signer_output_is_verified_against_exact_message() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "expected");
    let external = external_signing_key_with_command(
        signer_stdout_command(&json!({"signature": signature}).to_string()),
        5_000,
    );

    assert!(
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "expected",
            &public_jwk,
        )
        .await
        .is_ok()
    );
    assert!(
        sign_external_jwt_input(
            &external,
            kid,
            jsonwebtoken::Algorithm::EdDSA,
            "tampered",
            &public_jwk,
        )
        .await
        .is_err()
    );
}
