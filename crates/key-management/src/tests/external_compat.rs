use super::*;
use std::{sync::Arc, time::Duration};

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
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(windows)]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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
        &external_signing_key_with_command(command, 500),
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
async fn external_signer_output_is_verified_against_exact_message() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "expected");
    let external = external_signing_key_with_command(
        signer_stdout_command(&json!({"signature": signature}).to_string()),
        500,
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
