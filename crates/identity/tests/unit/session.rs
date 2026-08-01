use std::sync::Mutex;

use crate::{
    AccountIdentity, Principal, TenantContext, UserProfile, UserRole,
    ports::{RepositoryFuture, SessionAccountPort, SessionStorePort},
    session::{SessionRotationOutcome, SessionSnapshot, SessionVersion},
};

use super::*;

#[derive(Clone, Debug)]
struct RotationCall {
    old_session_id: SessionId,
    new_session_id: SessionId,
    replacement: SessionRecord,
    ttl_seconds: u64,
}

struct FakeStore {
    snapshot: Mutex<Option<SessionSnapshot>>,
    load_error: Mutex<Option<RepositoryError>>,
    compare_outcomes: Mutex<Vec<SessionUpdateOutcome>>,
    deleted: Mutex<Vec<SessionId>>,
    rotations: Mutex<Vec<RotationCall>>,
    rotation_outcome: SessionRotationOutcome,
}

impl FakeStore {
    fn with_record(record: SessionRecord) -> Self {
        Self {
            snapshot: Mutex::new(Some(SessionSnapshot::new(
                record,
                SessionVersion::from_storage(b"version-1".to_vec().into_boxed_slice()),
            ))),
            load_error: Mutex::new(None),
            compare_outcomes: Mutex::new(Vec::new()),
            deleted: Mutex::new(Vec::new()),
            rotations: Mutex::new(Vec::new()),
            rotation_outcome: SessionRotationOutcome::Applied,
        }
    }
}

impl SessionStorePort for FakeStore {
    fn load<'a>(
        &'a self,
        _session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async move {
            if let Some(error) = self.load_error.lock().unwrap().clone() {
                return Err(error);
            }
            Ok(self.snapshot.lock().unwrap().clone())
        })
    }

    fn delete<'a>(&'a self, session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.deleted.lock().unwrap().push(session_id.clone());
            Ok(true)
        })
    }

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        new_session_id: &'a SessionId,
        replacement: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async move {
            self.rotations.lock().unwrap().push(RotationCall {
                old_session_id: old_session_id.clone(),
                new_session_id: new_session_id.clone(),
                replacement: replacement.clone(),
                ttl_seconds,
            });
            Ok(self.rotation_outcome)
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        _session_id: &'a SessionId,
        expected: &'a SessionSnapshot,
        replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, SessionUpdateOutcome> {
        Box::pin(async move {
            let forced_outcome = {
                let mut outcomes = self.compare_outcomes.lock().unwrap();
                (!outcomes.is_empty()).then(|| outcomes.remove(0))
            };
            if let Some(outcome) = forced_outcome {
                return Ok(outcome);
            }
            let mut snapshot = self.snapshot.lock().unwrap();
            if snapshot.as_ref() != Some(expected) {
                return Ok(SessionUpdateOutcome::Conflict);
            }
            *snapshot = Some(SessionSnapshot::new(
                replacement.clone(),
                SessionVersion::from_storage(b"version-2".to_vec().into_boxed_slice()),
            ));
            Ok(SessionUpdateOutcome::Applied)
        })
    }
}

struct MissingAccounts;

impl SessionAccountPort for MissingAccounts {
    fn public_account_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(async { Ok(None) })
    }
}

fn record(pending_mfa: bool) -> SessionRecord {
    SessionRecord::new(
        UserId::new(uuid::Uuid::from_u128(2)).unwrap(),
        900,
        vec!["password".to_owned()],
        pending_mfa,
        Some("oidc-sid".to_owned()),
    )
}

fn service(store: Arc<FakeStore>) -> SessionService {
    SessionService::new(
        store,
        Arc::new(MissingAccounts),
        TenantId::new(uuid::Uuid::from_u128(1)).unwrap(),
    )
}

#[test]
fn add_amr_deduplicates_methods_and_preserves_claim_order() {
    let mut amr = vec!["pwd".to_owned(), "otp".to_owned()];

    add_amr(&mut amr, "mfa");
    add_amr(&mut amr, "pwd");
    add_amr(&mut amr, "mfa");

    assert_eq!(amr, vec!["pwd", "otp", "mfa"]);
}

#[test]
fn current_session_exposes_exact_logged_in_clients() {
    let now = chrono::Utc::now();
    let session = CurrentSession {
        user: PublicAccount {
            principal: Principal {
                user_id: UserId::new(uuid::Uuid::from_u128(2)).unwrap(),
                tenant: TenantContext::default_system(),
                role: UserRole::User,
                active: true,
            },
            account: AccountIdentity {
                username: "user".to_owned(),
                email: "user@example.com".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            },
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
        },
        auth_time: 900,
        amr: vec!["password".to_owned()],
        oidc_sid: "oidc-sid".to_owned(),
        logged_in_client_ids: vec!["client-a".to_owned(), "client-b".to_owned()],
    };

    assert_eq!(
        session.logged_in_client_ids(),
        &["client-a".to_owned(), "client-b".to_owned()]
    );
}

#[tokio::test]
async fn corrupt_session_is_deleted_and_resolves_as_missing() {
    let store = Arc::new(FakeStore::with_record(record(false)));
    *store.load_error.lock().unwrap() = Some(RepositoryError::Consistency("bad json".into()));
    let session_id = SessionId::new("session-1");

    assert_eq!(
        service(store.clone())
            .current(&session_id, 1_000)
            .await
            .unwrap(),
        SessionResolution::Missing
    );
    assert_eq!(
        store.deleted.lock().unwrap().as_slice(),
        std::slice::from_ref(&session_id)
    );
}

#[tokio::test]
async fn binding_clients_is_session_scoped_and_idempotent() {
    let store = Arc::new(FakeStore::with_record(record(false)));
    let session_id = SessionId::new("session-1");
    let service = service(store.clone());

    assert!(service.bind_client(&session_id, "client-a").await.unwrap());
    assert!(service.bind_client(&session_id, "client-a").await.unwrap());
    assert!(service.bind_client(&session_id, "client-b").await.unwrap());

    assert_eq!(
        store
            .snapshot
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .record()
            .logged_in_client_ids(),
        &["client-a".to_owned(), "client-b".to_owned()]
    );
}

#[tokio::test]
async fn binding_client_fails_closed_for_invalid_or_missing_sessions() {
    let store = Arc::new(FakeStore::with_record(record(false)));
    let session_id = SessionId::new("session-1");
    let service = service(store.clone());

    assert_eq!(
        service.bind_client(&session_id, "  ").await,
        Err(RepositoryError::Consistency(
            "logged-in client identifier is empty".to_owned()
        ))
    );

    *store.snapshot.lock().unwrap() = None;
    assert!(!service.bind_client(&session_id, "client-a").await.unwrap());

    *store.snapshot.lock().unwrap() = Some(SessionSnapshot::new(
        record(false),
        SessionVersion::from_storage(b"version-1".to_vec().into_boxed_slice()),
    ));
    store
        .compare_outcomes
        .lock()
        .unwrap()
        .push(SessionUpdateOutcome::Missing);
    assert!(!service.bind_client(&session_id, "client-a").await.unwrap());
}

#[tokio::test]
async fn binding_client_rejects_repeated_compare_and_set_conflicts() {
    let store = Arc::new(FakeStore::with_record(record(false)));
    store
        .compare_outcomes
        .lock()
        .unwrap()
        .extend(vec![SessionUpdateOutcome::Conflict; 4]);
    let result = service(store)
        .bind_client(&SessionId::new("session-1"), "client-a")
        .await;

    assert_eq!(
        result,
        Err(RepositoryError::Consistency(
            "session changed repeatedly while binding logged-in client".to_owned()
        ))
    );
}

#[tokio::test]
async fn unavailable_session_store_is_not_downgraded_to_anonymous() {
    let store = Arc::new(FakeStore::with_record(record(false)));
    *store.load_error.lock().unwrap() = Some(RepositoryError::Unavailable);
    let session_id = SessionId::new("session-1");

    assert_eq!(
        service(store.clone()).current(&session_id, 1_000).await,
        Err(RepositoryError::Unavailable)
    );
    assert!(store.deleted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_authentication_metadata_is_deleted_fail_closed() {
    let mut invalid = record(false);
    invalid.set_auth_time(0);
    let store = Arc::new(FakeStore::with_record(invalid));
    let session_id = SessionId::new("session-1");

    assert_eq!(
        service(store.clone())
            .current(&session_id, 1_000)
            .await
            .unwrap(),
        SessionResolution::Invalidated
    );
    assert_eq!(
        store.deleted.lock().unwrap().as_slice(),
        std::slice::from_ref(&session_id)
    );
}

#[tokio::test]
async fn step_up_builds_a_fresh_session_and_csrf_pair_for_atomic_rotation() {
    let store = Arc::new(FakeStore::with_record(record(true)));
    let old_session_id = SessionId::new("session-1");
    let rotation = service(store.clone())
        .step_up(&old_session_id, "totp", 3_600, true, 1_000)
        .await
        .unwrap()
        .unwrap();

    assert_ne!(rotation.session_id(), &old_session_id);
    assert_eq!(rotation.csrf_token().len(), 43);
    let calls = store.rotations.lock().unwrap();
    let call = calls.first().unwrap();
    assert_eq!(call.old_session_id, old_session_id);
    assert_eq!(call.new_session_id, *rotation.session_id());
    assert_eq!(call.ttl_seconds, 3_600);
    assert_eq!(call.replacement.auth_time(), 1_000);
    assert!(!call.replacement.pending_mfa());
    assert_eq!(call.replacement.amr(), ["password", "totp", "mfa"]);
}
