use super::MfaRepository;
use nazo_identity::{
    TenantId, UserId,
    ports::{
        BackupCodeCandidate, EncodedSecretHash, MfaRepositoryPort, RepositoryFuture,
        TotpCredential, TotpEnrollment, TotpVerificationOutcome,
    },
};

impl MfaRepositoryPort for MfaRepository {
    fn totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>> {
        Box::pin(async move { self.totp_enrollment(tenant_id, user_id).await })
    }

    fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.begin_totp_enrollment(tenant_id, user_id, secret, label)
                .await
        })
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async move {
            self.verify_and_confirm_totp(
                tenant_id,
                user_id,
                code,
                timestamp,
                hashes
                    .into_iter()
                    .map(|hash| hash.as_str().to_owned())
                    .collect(),
            )
            .await
        })
    }

    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move { self.record_invalid_totp_attempt(tenant_id, user_id).await })
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async move {
            self.verify_and_consume_totp(tenant_id, user_id, code, timestamp)
                .await
        })
    }

    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>> {
        Box::pin(async move { self.totp_credential(tenant_id, user_id).await })
    }
    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.compare_and_set_totp_step(tenant_id, user_id, step)
                .await
        })
    }
    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        Box::pin(async move { self.backup_code_candidates(tenant_id, user_id).await })
    }

    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: uuid::Uuid,
    ) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            self.consume_backup_code_candidate(tenant_id, user_id, candidate_id)
                .await
        })
    }

    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.record_invalid_backup_code_attempt(tenant_id, user_id)
                .await
        })
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.replace_backup_code_hashes(
                tenant_id,
                user_id,
                hashes
                    .into_iter()
                    .map(|hash| hash.as_str().to_owned())
                    .collect(),
            )
            .await
        })
    }
    fn clear_mfa_state<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move { self.clear_mfa_state(tenant_id, user_id).await })
    }

    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.remember_device(tenant_id, user_id, token_hash, user_agent_hash, expires_at)
                .await
        })
    }
}
