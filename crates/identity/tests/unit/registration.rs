use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    PasswordHash, RegisterLocalAccountError, RegistrationService, RegistrationServiceConfig,
    SendVerificationCodeError, SendVerificationCodeOutcome, TenantContext,
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
    code_loads: AtomicUsize,
    code_consumes: AtomicUsize,
    code_deletes: AtomicUsize,
    tenant_ids: Mutex<Vec<crate::TenantId>>,
}

#[derive(Clone)]
struct RecordingVerificationStore {
    email_reservation: Result<bool, RepositoryError>,
    calls: Arc<VerificationCalls>,
}

impl EmailVerificationStorePort for RecordingVerificationStore {
    fn reserve_peer_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _subject: &'a str,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.peer_reservations.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            Ok(true)
        })
    }

    fn reserve_email_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _email: &'a str,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        let calls = Arc::clone(&self.calls);
        let result = self.email_reservation.clone();
        Box::pin(async move {
            calls.email_reservations.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            result
        })
    }

    fn store_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _email: &'a str,
        _password_hash: PasswordHashInput,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.code_stores.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            Ok(())
        })
    }

    fn load_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.code_loads.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            Ok(Some(EmailVerificationRecord {
                password_hash: PasswordHash::new("stored-code-hash").unwrap(),
                opaque_version: "stored-code-hash".to_owned(),
            }))
        })
    }

    fn consume_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _email: &'a str,
        _expected: &'a EmailVerificationRecord,
    ) -> RepositoryFuture<'a, EmailVerificationConsume> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.code_consumes.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            Ok(EmailVerificationConsume::Consumed)
        })
    }

    fn delete_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.code_deletes.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            Ok(())
        })
    }

    fn release_email_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.email_releases.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
            Ok(())
        })
    }

    fn release_peer_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        _subject: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.peer_releases.fetch_add(1, Ordering::Relaxed);
            calls.tenant_ids.lock().unwrap().push(tenant_id);
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
    verify_result: bool,
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
        let result = self.verify_result;
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(result)
        })
    }
}

#[derive(Clone)]
struct RecordingDelivery {
    calls: Arc<AtomicUsize>,
    result: Result<(), RepositoryError>,
}

impl VerificationEmailDeliveryPort for RecordingDelivery {
    fn deliver<'a>(
        &'a self,
        _normalized_email: &'a str,
        _code: &'a str,
        _code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        let calls = Arc::clone(&self.calls);
        let result = self.result.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            result
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
            verify_result: false,
        },
        RecordingDelivery {
            calls: Arc::clone(&delivery_calls),
            result: Ok(()),
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
    assert!(
        verification_calls
            .tenant_ids
            .lock()
            .unwrap()
            .iter()
            .all(|tenant_id| *tenant_id == TenantContext::default().tenant_id)
    );
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

#[tokio::test]
async fn successful_send_scopes_code_and_cooldowns_to_service_tenant() {
    let tenant = TenantContext {
        tenant_id: crate::TenantId::new(uuid::Uuid::from_u128(101)).unwrap(),
        realm_id: crate::RealmId::new(uuid::Uuid::from_u128(102)).unwrap(),
        organization_id: crate::OrganizationId::new(uuid::Uuid::from_u128(103)).unwrap(),
    };
    let verification_calls = Arc::new(VerificationCalls::default());
    let hash_calls = Arc::new(AtomicUsize::new(0));
    let delivery_calls = Arc::new(AtomicUsize::new(0));
    let service = RegistrationService::new(
        NoExistingAccount,
        RecordingVerificationStore {
            email_reservation: Ok(true),
            calls: Arc::clone(&verification_calls),
        },
        RecordingSecretHashes {
            hash_calls: Arc::clone(&hash_calls),
            verify_calls: Arc::new(AtomicUsize::new(0)),
            verify_result: false,
        },
        RecordingDelivery {
            calls: Arc::clone(&delivery_calls),
            result: Ok(()),
        },
        tenant,
        RegistrationServiceConfig {
            delivery_enabled: true,
            send_peer_cooldown_seconds: 5,
            send_cooldown_seconds: 60,
            code_ttl_seconds: 900,
        },
    );

    assert!(matches!(
        service
            .send_verification_code("shared@example.test", "peer-1")
            .await
            .unwrap(),
        SendVerificationCodeOutcome::Sent { .. }
    ));
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
    assert_eq!(verification_calls.code_stores.load(Ordering::Relaxed), 1);
    assert_eq!(hash_calls.load(Ordering::Relaxed), 1);
    assert_eq!(delivery_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        *verification_calls.tenant_ids.lock().unwrap(),
        vec![tenant.tenant_id; 3]
    );
}

#[tokio::test]
async fn failed_delivery_deletes_code_and_releases_tenant_scoped_reservations() {
    let tenant = TenantContext {
        tenant_id: crate::TenantId::new(uuid::Uuid::from_u128(301)).unwrap(),
        realm_id: crate::RealmId::new(uuid::Uuid::from_u128(302)).unwrap(),
        organization_id: crate::OrganizationId::new(uuid::Uuid::from_u128(303)).unwrap(),
    };
    let verification_calls = Arc::new(VerificationCalls::default());
    let service = RegistrationService::new(
        NoExistingAccount,
        RecordingVerificationStore {
            email_reservation: Ok(true),
            calls: Arc::clone(&verification_calls),
        },
        RecordingSecretHashes {
            hash_calls: Arc::new(AtomicUsize::new(0)),
            verify_calls: Arc::new(AtomicUsize::new(0)),
            verify_result: false,
        },
        RecordingDelivery {
            calls: Arc::new(AtomicUsize::new(0)),
            result: Err(RepositoryError::Unavailable),
        },
        tenant,
        RegistrationServiceConfig {
            delivery_enabled: true,
            send_peer_cooldown_seconds: 5,
            send_cooldown_seconds: 60,
            code_ttl_seconds: 900,
        },
    );

    assert_eq!(
        service
            .send_verification_code("shared@example.test", "peer-1")
            .await,
        Err(SendVerificationCodeError::Delivery(
            RepositoryError::Unavailable
        ))
    );
    assert_eq!(verification_calls.code_deletes.load(Ordering::Relaxed), 1);
    assert_eq!(verification_calls.peer_releases.load(Ordering::Relaxed), 1);
    assert_eq!(verification_calls.email_releases.load(Ordering::Relaxed), 1);
    assert_eq!(
        *verification_calls.tenant_ids.lock().unwrap(),
        vec![tenant.tenant_id; 6]
    );
}

#[tokio::test]
async fn registration_scopes_code_load_and_consumption_to_service_tenant() {
    let tenant = TenantContext {
        tenant_id: crate::TenantId::new(uuid::Uuid::from_u128(201)).unwrap(),
        realm_id: crate::RealmId::new(uuid::Uuid::from_u128(202)).unwrap(),
        organization_id: crate::OrganizationId::new(uuid::Uuid::from_u128(203)).unwrap(),
    };
    let verification_calls = Arc::new(VerificationCalls::default());
    let service = RegistrationService::new(
        NoExistingAccount,
        RecordingVerificationStore {
            email_reservation: Ok(true),
            calls: Arc::clone(&verification_calls),
        },
        RecordingSecretHashes {
            hash_calls: Arc::new(AtomicUsize::new(0)),
            verify_calls: Arc::new(AtomicUsize::new(0)),
            verify_result: true,
        },
        RecordingDelivery {
            calls: Arc::new(AtomicUsize::new(0)),
            result: Ok(()),
        },
        tenant,
        RegistrationServiceConfig {
            delivery_enabled: false,
            send_peer_cooldown_seconds: 5,
            send_cooldown_seconds: 60,
            code_ttl_seconds: 900,
        },
    );

    let result = service
        .register_local_account(crate::RegisterLocalAccountInput {
            email: "shared@example.test".to_owned(),
            verification_code: "123456".to_owned(),
            password: "correct horse battery staple".to_owned(),
        })
        .await;

    assert!(matches!(result, Err(RegisterLocalAccountError::Create(_))));
    assert_eq!(verification_calls.code_loads.load(Ordering::Relaxed), 1);
    assert_eq!(verification_calls.code_consumes.load(Ordering::Relaxed), 1);
    assert_eq!(
        *verification_calls.tenant_ids.lock().unwrap(),
        vec![tenant.tenant_id; 2]
    );
}
