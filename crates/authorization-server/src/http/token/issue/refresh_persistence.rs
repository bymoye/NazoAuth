use super::*;
use chrono::DateTime;

use crate::domain::client_policy::client_supports_grant;
pub(super) use nazo_auth::RefreshTokenPersistResult as RefreshPersistResult;

pub(super) struct PendingRefreshToken {
    pub(super) raw: String,
    pub(super) family: Uuid,
    pub(super) rotated_from: Option<Uuid>,
    pub(super) lost_response_retry: Option<(Uuid, DateTime<Utc>)>,
    pub(super) issued_at: DateTime<Utc>,
    pub(super) expires_at: DateTime<Utc>,
}

fn refresh_token_persistence_scopes(
    access_token_scopes: &[String],
    original_refresh_token_scopes: Option<&[String]>,
) -> Vec<String> {
    original_refresh_token_scopes
        .unwrap_or(access_token_scopes)
        .to_vec()
}

pub(crate) fn should_issue_refresh_token(
    client: &ClientRow,
    scopes: &[String],
    openid4vci_credential_authorization: bool,
) -> bool {
    client_supports_grant(client, "refresh_token")
        && (scopes.iter().any(|scope| scope == "offline_access")
            || openid4vci_credential_authorization)
}

pub(super) async fn persist_refresh_token(
    service: &ServerTokenService,
    client: &ClientRow,
    issue: &TokenIssue,
    refresh: &PendingRefreshToken,
) -> anyhow::Result<RefreshPersistResult> {
    service
        .persist_refresh_token(nazo_auth::NewRefreshToken {
            raw_token: refresh.raw.clone(),
            tenant_id: client.tenant_id,
            family_id: refresh.family,
            rotated_from_id: refresh.rotated_from,
            lost_response_retry: refresh.lost_response_retry.map(
                |(original_id, retry_started_at)| nazo_auth::LostResponseRetry {
                    original_id,
                    retry_started_at,
                },
            ),
            client_id: client.id,
            user_id: issue.user_id,
            scopes: refresh_token_persistence_scopes(
                &issue.scopes,
                issue.refresh_token_scopes.as_deref(),
            ),
            audiences: issue.audiences.clone(),
            authorization_details: issue.authorization_details.clone(),
            issued_at: refresh.issued_at,
            expires_at: refresh.expires_at,
            subject: issue.subject.clone(),
            dpop_jkt: issue.refresh_token_dpop_jkt.clone(),
            mtls_x5t_s256: issue.refresh_token_mtls_x5t_s256.clone(),
            client_attestation_jkt: issue.refresh_token_client_attestation_jkt.clone(),
        })
        .await
        .map_err(|error| anyhow::anyhow!("failed to persist refresh token: {error:?}"))
}

#[cfg(test)]
#[path = "../../../../tests/unit/http/token/issue/refresh_persistence.rs"]
mod tests;
