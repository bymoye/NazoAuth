use super::*;
use chrono::DateTime;

#[cfg(test)]
pub(super) fn consumed_authorization_code_transition_result(result: &str) -> anyhow::Result<()> {
    if result == "ok" {
        Ok(())
    } else {
        anyhow::bail!("authorization code state is {result}, expected consuming")
    }
}

pub(super) fn failed_authorization_code_transition_result(result: &str) -> anyhow::Result<()> {
    if matches!(result, "ok" | "missing" | "failed" | "consumed") {
        Ok(())
    } else {
        anyhow::bail!("authorization code state is {result}, expected consuming")
    }
}

pub(super) fn consumed_authorization_code_ttl_seconds(
    access_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
    refresh_token_family_id: Option<Uuid>,
) -> u64 {
    let ttl_seconds = if refresh_token_family_id.is_some() {
        refresh_token_ttl_seconds
    } else {
        access_token_ttl_seconds
    };
    ttl_seconds.max(1) as u64
}

pub(super) async fn persist_consumed_authorization_code(
    service: &ServerTokenService,
    issued: nazo_auth::IssuedAuthorizationCodeTokens<'_>,
) -> anyhow::Result<()> {
    service
        .finalize_authorization_code(issued)
        .await
        .map_err(|error| anyhow::anyhow!("failed to finalize authorization code: {error:?}"))
}

pub(crate) async fn mark_failed_authorization_code(
    service: &ServerTokenService,
    code_hash: &str,
    error_code: &str,
    ttl_seconds: u64,
) -> anyhow::Result<()> {
    let result = service
        .mark_authorization_code_failed(code_hash, error_code, ttl_seconds)
        .await
        .map_err(|error| anyhow::anyhow!("failed to mark authorization code: {error:?}"))?;
    failed_authorization_code_transition_result(authorization_transition_name(result))
}

fn authorization_transition_name(
    result: nazo_auth::AuthorizationCodeTransitionResult,
) -> &'static str {
    match result {
        nazo_auth::AuthorizationCodeTransitionResult::Applied => "ok",
        nazo_auth::AuthorizationCodeTransitionResult::Missing => "missing",
        nazo_auth::AuthorizationCodeTransitionResult::Malformed => "malformed",
        nazo_auth::AuthorizationCodeTransitionResult::Pending => "pending",
        nazo_auth::AuthorizationCodeTransitionResult::Consuming => "consuming",
        nazo_auth::AuthorizationCodeTransitionResult::Consumed => "consumed",
        nazo_auth::AuthorizationCodeTransitionResult::Failed => "failed",
    }
}

pub(super) async fn mark_failed_authorization_code_if_needed(
    service: &ServerTokenService,
    code_hash: Option<&str>,
    error_code: &str,
    ttl_seconds: u64,
) {
    if let Some(code_hash) = code_hash
        && let Err(error) =
            mark_failed_authorization_code(service, code_hash, error_code, ttl_seconds).await
    {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

pub(crate) async fn revoke_issued_authorization_code_tokens(
    service: &ServerTokenService,
    client: &ClientRow,
    access_token_jti: &str,
    access_token_expires_at: i64,
    refresh_token_family_id: Option<Uuid>,
) -> anyhow::Result<()> {
    service
        .revoke_issued_tokens(
            client.tenant_id,
            client.id,
            access_token_jti,
            DateTime::<Utc>::from_timestamp(access_token_expires_at, 0),
            refresh_token_family_id,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to revoke authorization-code tokens: {error:?}"))
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/token/tests/authorization_code_state.rs"]
mod tests;
