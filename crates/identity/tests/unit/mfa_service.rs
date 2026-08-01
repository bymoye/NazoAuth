use std::sync::Mutex;

use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::{
    AccountIdentity, Principal, TenantContext, UserId, UserProfile, UserRole,
    ports::{BackupCodeCandidate, MfaHashFuture, RepositoryFuture, TotpCredential, TotpEnrollment},
};

struct ConfirmRepository(Mutex<TotpVerificationOutcome>);

impl MfaRepositoryPort for ConfirmRepository {
    fn totp_enrollment<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>> {
        unreachable!()
    }

    fn begin_totp_enrollment(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _secret: String,
        _label: String,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _code: &'a str,
        _timestamp: i64,
        _hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        let outcome = *self.0.lock().unwrap();
        Box::pin(async move { Ok(outcome) })
    }

    fn record_invalid_totp_attempt(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _code: &'a str,
        _timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        unreachable!()
    }

    fn totp_credential<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>> {
        unreachable!()
    }

    fn compare_and_set_totp_step<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _step: i64,
    ) -> RepositoryFuture<'a, bool> {
        unreachable!()
    }

    fn backup_code_candidates(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        unreachable!()
    }

    fn consume_backup_code_candidate(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _candidate_id: Uuid,
    ) -> RepositoryFuture<'_, bool> {
        unreachable!()
    }

    fn record_invalid_backup_code_attempt(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, ()> {
        unreachable!()
    }

    fn clear_mfa_state<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, ()> {
        unreachable!()
    }

    fn remember_device(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _token_hash: String,
        _user_agent_hash: Option<String>,
        _expires_at: DateTime<Utc>,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }
}

struct UnusedHasher;

impl MfaSecretHashPort for UnusedHasher {
    fn hash_secrets(&self, _secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        unreachable!()
    }

    fn find_matching_secret(
        &self,
        _secret: String,
        _candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>> {
        unreachable!()
    }
}

#[tokio::test]
async fn failed_or_replayed_confirmation_cannot_return_backup_code_secrets() {
    for expected in [
        TotpConfirmationOutcome::Invalid,
        TotpConfirmationOutcome::Replay,
    ] {
        let outcome = match &expected {
            TotpConfirmationOutcome::Invalid => TotpVerificationOutcome::Invalid,
            TotpConfirmationOutcome::Replay => TotpVerificationOutcome::Replay,
            TotpConfirmationOutcome::Accepted { .. } => unreachable!(),
        };
        let service = MfaService::new(
            Arc::new(ConfirmRepository(Mutex::new(outcome))),
            Arc::new(UnusedHasher),
        );
        let result = service
            .confirm_totp(
                &account(),
                PreparedTotpConfirmation {
                    code: "123456".to_owned(),
                    backup_codes: vec!["must-not-escape".to_owned()],
                    hashes: vec![EncodedSecretHash::new("encoded").unwrap()],
                },
                1_000,
            )
            .await
            .unwrap();
        assert_eq!(result, expected);
    }
}

fn account() -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::now_v7()).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "user".to_owned(),
            email: "user@example.com".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}
