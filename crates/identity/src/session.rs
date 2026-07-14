use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{PublicAccount, TenantId, UserId, ports::RepositoryError};

#[must_use]
pub fn valid_authentication_metadata(
    auth_time: i64,
    amr: &[String],
    oidc_sid: Option<&str>,
    now: i64,
) -> bool {
    auth_time > 0
        && auth_time <= now.saturating_add(30)
        && !amr.is_empty()
        && oidc_sid.is_some_and(|sid| !sid.trim().is_empty())
}

pub fn add_amr(amr: &mut Vec<String>, value: &str) {
    if !amr.iter().any(|method| method == value) {
        amr.push(value.to_owned());
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    user_id: UserId,
    auth_time: i64,
    amr: Vec<String>,
    pending_mfa: bool,
    oidc_sid: Option<String>,
}

/// Opaque identifier for a browser login session.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(Box<str>);

impl SessionId {
    #[must_use]
    pub fn new(value: impl Into<Box<str>>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::random();
        Self(URL_SAFE_NO_PAD.encode(bytes).into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Opaque persistence revision used only for compare-and-swap rotation.
///
/// Storage adapters may preserve their exact serialized representation here;
/// domain callers cannot interpret or mutate it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionVersion(Box<[u8]>);

impl SessionVersion {
    #[doc(hidden)]
    #[must_use]
    pub fn from_storage(value: impl Into<Box<[u8]>>) -> Self {
        Self(value.into())
    }

    #[doc(hidden)]
    #[must_use]
    pub fn storage_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    record: SessionRecord,
    version: SessionVersion,
}

impl SessionSnapshot {
    #[must_use]
    pub fn new(record: SessionRecord, version: SessionVersion) -> Self {
        Self { record, version }
    }

    #[must_use]
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }

    #[doc(hidden)]
    #[must_use]
    pub fn version(&self) -> &SessionVersion {
        &self.version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRotationOutcome {
    Applied,
    Conflict,
    Collision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSession {
    user: PublicAccount,
    auth_time: i64,
    amr: Vec<String>,
    oidc_sid: String,
}

impl CurrentSession {
    #[must_use]
    pub fn user(&self) -> &PublicAccount {
        &self.user
    }

    #[must_use]
    pub fn into_user(self) -> PublicAccount {
        self.user
    }

    #[must_use]
    pub const fn auth_time(&self) -> i64 {
        self.auth_time
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    #[must_use]
    pub fn oidc_sid(&self) -> &str {
        &self.oidc_sid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionResolution {
    Present(Box<CurrentSession>),
    Missing,
    Invalidated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRotation {
    session_id: SessionId,
    csrf_token: Box<str>,
}

impl SessionRotation {
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// Identity application service for resolving and atomically rotating sessions.
#[derive(Clone)]
pub struct SessionService {
    sessions: Arc<dyn crate::ports::SessionStorePort>,
    accounts: Arc<dyn crate::ports::SessionAccountPort>,
    tenant_id: TenantId,
}

impl SessionService {
    #[must_use]
    pub fn new(
        sessions: Arc<dyn crate::ports::SessionStorePort>,
        accounts: Arc<dyn crate::ports::SessionAccountPort>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            sessions,
            accounts,
            tenant_id,
        }
    }

    pub async fn delete(&self, session_id: &SessionId) -> Result<bool, RepositoryError> {
        self.sessions.delete(session_id).await
    }

    pub async fn current(
        &self,
        session_id: &SessionId,
        now: i64,
    ) -> Result<SessionResolution, RepositoryError> {
        self.resolve(session_id, now, false).await
    }

    pub async fn pending_mfa(
        &self,
        session_id: &SessionId,
        now: i64,
    ) -> Result<SessionResolution, RepositoryError> {
        self.resolve(session_id, now, true).await
    }

    pub async fn step_up(
        &self,
        session_id: &SessionId,
        method: &str,
        ttl_seconds: u64,
        require_pending_mfa: bool,
        now: i64,
    ) -> Result<Option<SessionRotation>, RepositoryError> {
        let Some(snapshot) = self.load_fail_closed(session_id).await? else {
            return Ok(None);
        };
        let mut replacement = snapshot.record().clone();
        if !valid_authentication_metadata(
            replacement.auth_time(),
            replacement.amr(),
            replacement.oidc_sid(),
            now,
        ) || (require_pending_mfa && !replacement.pending_mfa())
        {
            return Ok(None);
        }
        replacement.set_pending_mfa(false);
        replacement.set_auth_time(now);
        replacement.add_amr(method);
        replacement.add_amr("mfa");

        let new_session_id = SessionId::generate();
        match self
            .sessions
            .rotate(
                session_id,
                &snapshot,
                &new_session_id,
                &replacement,
                ttl_seconds,
            )
            .await?
        {
            SessionRotationOutcome::Applied => Ok(Some(SessionRotation {
                session_id: new_session_id,
                csrf_token: random_urlsafe_token().into(),
            })),
            SessionRotationOutcome::Conflict => Ok(None),
            SessionRotationOutcome::Collision => Err(RepositoryError::Unexpected(
                "generated session identifier already exists".to_owned(),
            )),
        }
    }

    async fn resolve(
        &self,
        session_id: &SessionId,
        now: i64,
        pending_mfa: bool,
    ) -> Result<SessionResolution, RepositoryError> {
        let Some(snapshot) = self.load_fail_closed(session_id).await? else {
            return Ok(SessionResolution::Missing);
        };
        let record = snapshot.record();
        if !valid_authentication_metadata(record.auth_time(), record.amr(), record.oidc_sid(), now)
        {
            let _ = self.sessions.delete(session_id).await;
            return Ok(SessionResolution::Invalidated);
        }
        if record.pending_mfa() != pending_mfa {
            return Ok(SessionResolution::Missing);
        }
        let Some(user) = self
            .accounts
            .public_account_by_id(self.tenant_id, record.user_id())
            .await?
            .filter(|account| account.principal.active)
        else {
            let _ = self.sessions.delete(session_id).await;
            return Ok(SessionResolution::Invalidated);
        };
        Ok(SessionResolution::Present(Box::new(CurrentSession {
            user,
            auth_time: record.auth_time(),
            amr: record.amr().to_vec(),
            oidc_sid: record
                .oidc_sid()
                .expect("validated session has an OIDC sid")
                .to_owned(),
        })))
    }

    async fn load_fail_closed(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionSnapshot>, RepositoryError> {
        match self.sessions.load(session_id).await {
            Ok(snapshot) => Ok(snapshot),
            Err(RepositoryError::Consistency(_)) => {
                let _ = self.sessions.delete(session_id).await;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

fn random_urlsafe_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

impl SessionRecord {
    #[must_use]
    pub fn new(
        user_id: UserId,
        auth_time: i64,
        amr: Vec<String>,
        pending_mfa: bool,
        oidc_sid: Option<String>,
    ) -> Self {
        Self {
            user_id,
            auth_time,
            amr,
            pending_mfa,
            oidc_sid,
        }
    }

    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    #[must_use]
    pub const fn auth_time(&self) -> i64 {
        self.auth_time
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    #[must_use]
    pub const fn pending_mfa(&self) -> bool {
        self.pending_mfa
    }

    #[must_use]
    pub fn oidc_sid(&self) -> Option<&str> {
        self.oidc_sid.as_deref()
    }

    pub fn set_auth_time(&mut self, auth_time: i64) {
        self.auth_time = auth_time;
    }

    pub fn set_pending_mfa(&mut self, pending_mfa: bool) {
        self.pending_mfa = pending_mfa;
    }

    pub fn add_amr(&mut self, value: &str) {
        add_amr(&mut self.amr, value);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::{
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
}
