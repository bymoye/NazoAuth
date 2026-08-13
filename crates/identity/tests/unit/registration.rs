use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    PasswordHash, RegistrationService, RegistrationServiceConfig, SendVerificationCodeError,
    SendVerificationCodeOutcome, TenantContext,
    ports::{
        EmailVerificationConsume, EmailVerificationRecord, EmailVerificationStorePort, NewUser,
        PasswordHashInput, RegistrationAccountRepositoryPort, RepositoryError, RepositoryFuture,
        SecretHashPort, VerificationEmailDeliveryPort,
    },
};

use super::random_numeric_code;

fn unsupported<'a, T>() -> RepositoryFuture<'a, T> {
    Box::pin(async {
        Err(RepositoryError::Unexpected(
            "unused test operation".to_owned(),
        ))
    })
}

#[test]
fn verification_codes_are_fixed_width_decimal_values() {
    for _ in 0..64 {
        let code = random_numeric_code();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }
}

#[derive(Default)]
struct VerificationCalls {
    peer_reservations: AtomicUsize,
    email_reservations: AtomicUsize,
    peer_releases: AtomicUsize,
    email_releases: AtomicUsize,
    code_stores: AtomicUsize,
}

#[derive(Clone)]
struct RecordingVerificationStore {
    email_reservation: Result<bool, RepositoryError>,
    calls: Arc<VerificationCalls>,
}

impl EmailVerificationStorePort for RecordingVerificationStore {
    fn reserve_peer_send<'a>(
        &'a self,
        _subject: &'a str,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.peer_reservations.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        })
    }

    fn reserve_email_send<'a>(
        &'a self,
        _email: &'a str,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        let calls = Arc::clone(&self.calls);
        let result = self.email_reservation.clone();
        Box::pin(async move {
            calls.email_reservations.fetch_add(1, Ordering::Relaxed);
            result
        })
    }

    fn store_code<'a>(
        &'a self,
        _email: &'a str,
        _password_hash: PasswordHashInput,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.code_stores.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }

    fn load_code<'a>(
        &'a self,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>> {
        unsupported()
    }

    fn consume_code<'a>(
        &'a self,
        _email: &'a str,
        _expected: &'a EmailVerificationRecord,
    ) -> RepositoryFuture<'a, EmailVerificationConsume> {
        unsupported()
    }

    fn delete_code<'a>(&'a self, _email: &'a str) -> RepositoryFuture<'a, ()> {
        unsupported()
    }

    fn release_email_send<'a>(&'a self, _email: &'a str) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.email_releases.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }

    fn release_peer_send<'a>(&'a self, _subject: &'a str) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.peer_releases.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
struct NoExistingAccount;

impl RegistrationAccountRepositoryPort for NoExistingAccount {
    fn account_by_email<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::PublicAccount>> {
        Box::pin(async { Ok(None) })
    }

    fn create_user(&self, _user: NewUser) -> RepositoryFuture<'_, crate::PublicAccount> {
        unsupported()
    }
}

#[derive(Clone)]
struct RecordingSecretHashes {
    hash_calls: Arc<AtomicUsize>,
    verify_calls: Arc<AtomicUsize>,
}

impl SecretHashPort for RecordingSecretHashes {
    fn hash_secret(&self, _secret: String) -> RepositoryFuture<'_, PasswordHashInput> {
        let calls = Arc::clone(&self.hash_calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(PasswordHashInput::new("test-code-hash").unwrap())
        })
    }

    fn verify_secret(
        &self,
        _secret: String,
        _password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool> {
        let calls = Arc::clone(&self.verify_calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        })
    }
}

#[derive(Clone)]
struct RecordingDelivery {
    calls: Arc<AtomicUsize>,
}

impl VerificationEmailDeliveryPort for RecordingDelivery {
    fn deliver<'a>(
        &'a self,
        _normalized_email: &'a str,
        _code: &'a str,
        _code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

async fn assert_email_reservation_short_circuit(
    email_reservation: Result<bool, RepositoryError>,
    expected: Result<SendVerificationCodeOutcome, SendVerificationCodeError>,
) {
    let verification_calls = Arc::new(VerificationCalls::default());
    let hash_calls = Arc::new(AtomicUsize::new(0));
    let verify_calls = Arc::new(AtomicUsize::new(0));
    let delivery_calls = Arc::new(AtomicUsize::new(0));
    let service = RegistrationService::new(
        NoExistingAccount,
        RecordingVerificationStore {
            email_reservation,
            calls: Arc::clone(&verification_calls),
        },
        RecordingSecretHashes {
            hash_calls: Arc::clone(&hash_calls),
            verify_calls,
        },
        RecordingDelivery {
            calls: Arc::clone(&delivery_calls),
        },
        TenantContext::default(),
        RegistrationServiceConfig {
            delivery_enabled: true,
            send_peer_cooldown_seconds: 60,
            send_cooldown_seconds: 60,
            code_ttl_seconds: 300,
        },
    );

    assert_eq!(
        service
            .send_verification_code("alice@example.test", "peer-1")
            .await,
        expected
    );
    assert_eq!(
        verification_calls.peer_reservations.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        verification_calls
            .email_reservations
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        verification_calls.peer_releases.load(Ordering::Relaxed),
        1,
        "a successful peer reservation must be released when email reservation fails"
    );
    assert_eq!(
        verification_calls.email_releases.load(Ordering::Relaxed),
        0,
        "email reservation was not acquired"
    );
    assert_eq!(hash_calls.load(Ordering::Relaxed), 0);
    assert_eq!(verification_calls.code_stores.load(Ordering::Relaxed), 0);
    assert_eq!(delivery_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn denied_email_reservation_releases_peer_and_skips_code_delivery() {
    assert_email_reservation_short_circuit(Ok(false), Ok(SendVerificationCodeOutcome::Suppressed))
        .await;
}

#[tokio::test]
async fn failed_email_reservation_releases_peer_and_skips_code_delivery() {
    assert_email_reservation_short_circuit(
        Err(RepositoryError::Unavailable),
        Err(SendVerificationCodeError::Reservation(
            RepositoryError::Unavailable,
        )),
    )
    .await;
}
