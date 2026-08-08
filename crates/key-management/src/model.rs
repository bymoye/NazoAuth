use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

use crate::local::SigningBackend;
use arc_swap::ArcSwap;
use base64::{Engine, encoded_len, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignError, SignRequest, Signature, Signer, SigningPurpose};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    Prepublished,
    Active,
    Grace,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyHealthStatus {
    Healthy,
    Unhealthy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyHealth {
    pub status: KeyHealthStatus,
    pub consecutive_failures: u32,
}

impl KeyHealth {
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            status: KeyHealthStatus::Healthy,
            consecutive_failures: 0,
        }
    }

    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self.status, KeyHealthStatus::Healthy)
    }
}

pub(crate) struct LifecycleHealth {
    healthy: AtomicBool,
    consecutive_failures: AtomicU32,
}

impl LifecycleHealth {
    fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            consecutive_failures: AtomicU32::new(0),
        }
    }

    fn snapshot(&self) -> KeyHealth {
        KeyHealth {
            status: if self.healthy.load(Ordering::Acquire) {
                KeyHealthStatus::Healthy
            } else {
                KeyHealthStatus::Unhealthy
            },
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
        }
    }

    fn mark_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Release);
    }

    fn mark_failure(&self) {
        self.consecutive_failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            })
            .ok();
        self.healthy.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
pub(crate) enum KeyHandle {
    Local(Vec<u8>),
    External { key_ref: String },
}

#[derive(Clone)]
pub(crate) struct ExternalSigningKey {
    pub(crate) command: Arc<Vec<String>>,
    pub(crate) key_ref: String,
    pub(crate) timeout: Duration,
}

#[derive(Clone)]
pub(crate) enum ActiveSigningKey {
    LocalPkcs8Der(Vec<u8>),
    ExternalCommand(ExternalSigningKey),
}

#[derive(Clone)]
pub(crate) struct StoredVerificationKey {
    pub(crate) public_jwk: Value,
    pub(crate) managed: ManagedKey,
}

#[derive(Clone)]
pub(crate) struct LoadedKeyset {
    pub(crate) active_kid: String,
    pub(crate) active_alg: jsonwebtoken::Algorithm,
    pub(crate) active_signing_key: ActiveSigningKey,
    pub(crate) verification_keys: Vec<StoredVerificationKey>,
    pub(crate) request_object_decryption_key: Vec<u8>,
    pub(crate) request_object_encryption_jwk: Value,
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub kid: String,
    pub public_jwk: Value,
    pub(crate) signing_purposes: BTreeSet<SigningPurpose>,
}

impl VerificationKey {
    #[must_use]
    pub fn can_sign(&self, purpose: SigningPurpose) -> bool {
        self.signing_purposes.contains(&purpose)
    }
}

#[derive(Clone, Debug)]
pub struct KeySnapshot {
    pub active_kid: String,
    pub active_alg: jsonwebtoken::Algorithm,
    pub verification_keys: Vec<VerificationKey>,
    pub(crate) id_token_signing_algorithms: Vec<jsonwebtoken::Algorithm>,
    pub(crate) response_signing_algorithms: Vec<jsonwebtoken::Algorithm>,
    pub request_object_encryption_jwk: Value,
}

impl KeySnapshot {
    #[must_use]
    pub fn verification_key(&self, kid: &str) -> Option<&VerificationKey> {
        self.verification_keys.iter().find(|key| key.kid == kid)
    }

    #[must_use]
    pub fn signing_verification_key(
        &self,
        purpose: SigningPurpose,
        algorithm: jsonwebtoken::Algorithm,
    ) -> Option<&VerificationKey> {
        let algorithm = crate::store::signing_algorithm_name(algorithm)?;
        let matches = |key: &&VerificationKey| {
            key.can_sign(purpose)
                && key.public_jwk.get("alg").and_then(Value::as_str) == Some(algorithm)
        };
        self.verification_key(&self.active_kid)
            .filter(matches)
            .or_else(|| {
                self.verification_keys
                    .iter()
                    .filter(|key| key.kid != self.active_kid)
                    .find(matches)
            })
    }

    #[must_use]
    pub fn response_signing_alg_values_supported(&self) -> Vec<&'static str> {
        self.response_signing_algorithms
            .iter()
            .filter_map(|algorithm| crate::store::signing_algorithm_name(*algorithm))
            .collect()
    }

    #[must_use]
    pub fn id_token_signing_alg_values_supported(&self) -> Vec<&'static str> {
        self.id_token_signing_algorithms
            .iter()
            .filter_map(|algorithm| crate::store::signing_algorithm_name(*algorithm))
            .collect()
    }

    #[must_use]
    pub fn jwks(&self) -> Value {
        crate::jwks::public_jwks(&self.verification_keys, &self.request_object_encryption_jwk)
    }
}

#[derive(Clone, Debug)]
pub struct KeySettings {
    pub keys_dir: PathBuf,
    pub external_command: Vec<String>,
    pub external_timeout: Duration,
    pub rotation_interval: chrono::Duration,
    pub prepublish_window: chrono::Duration,
    pub verification_grace: chrono::Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    pub kid: String,
    pub status: KeyRecordStatus,
    pub algorithm: String,
    pub backend: String,
    pub locator: String,
    pub retire_at: Option<String>,
}

/// Operator-facing categorization derived from persisted keyset metadata.
///
/// Purpose-scoped signing keys are reported separately from rotation
/// candidates so operators cannot mistake them for the next OIDC active key.
/// Entries without explicit `purposes` are rotation keys and are reported as
/// `Prepublished` until selected through `active_kid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRecordStatus {
    Prepublished,
    PurposeScoped,
    Active,
    Grace,
    Retired,
}

impl KeyRecordStatus {
    /// Stable keyctl text used in the tab-separated list output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepublished => "prepublished",
            Self::PurposeScoped => "purpose-scoped",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExternalKeyRegistration {
    pub kid: String,
    pub algorithm: jsonwebtoken::Algorithm,
    pub key_ref: String,
    pub public_jwk_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct LocalKeyRegistration {
    pub algorithm: jsonwebtoken::Algorithm,
    pub purposes: BTreeSet<SigningPurpose>,
}

pub(crate) struct KeyGeneration {
    pub(crate) loaded: LoadedKeyset,
    pub(crate) snapshot: Arc<KeySnapshot>,
}

pub(crate) struct KeyManagerInner {
    pub(crate) generation: ArcSwap<KeyGeneration>,
    pub(crate) settings: KeySettings,
    pub(crate) health: Arc<LifecycleHealth>,
    pub(crate) lifecycle_shutdown: watch::Sender<bool>,
}

#[derive(Clone)]
pub struct KeyManager {
    pub(crate) inner: Arc<KeyManagerInner>,
}

pub struct HttpSigningLease {
    generation: Arc<KeyGeneration>,
    health: Arc<LifecycleHealth>,
    kid: String,
    algorithm: jsonwebtoken::Algorithm,
    http_algorithm: &'static str,
}

impl HttpSigningLease {
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.http_algorithm
    }

    pub async fn sign(&self, signing_input: &[u8]) -> anyhow::Result<Signature> {
        if !self.health.snapshot().is_healthy() {
            anyhow::bail!("signing key lifecycle is unhealthy");
        }
        let selected = self
            .generation
            .loaded
            .selected_key(SigningPurpose::HttpMessage, self.algorithm)
            .filter(|selected| selected.kid == self.kid)
            .ok_or_else(|| {
                anyhow::anyhow!("HTTP signing lease no longer matches its generation")
            })?;
        sign_selected(&selected, signing_input)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub enum TestSigningBehavior {
    Working,
    Failing,
    ExternalFailure { stderr: String },
}

impl LoadedKeyset {
    pub(crate) fn selected_key(
        &self,
        purpose: SigningPurpose,
        algorithm: jsonwebtoken::Algorithm,
    ) -> Option<SelectedKey<'_>> {
        let algorithm_name = crate::store::signing_algorithm_name(algorithm)?;
        let active = self
            .verification_keys
            .iter()
            .find(|key| key.managed.kid == self.active_kid)?;
        if algorithm == self.active_alg
            && active.managed.algorithm == algorithm_name
            && active.managed.can_sign(purpose)
            && active.public_jwk.get("alg").and_then(Value::as_str) == Some(algorithm_name)
        {
            return Some(SelectedKey {
                kid: &self.active_kid,
                algorithm,
                handle: SelectedHandle::Active(&self.active_signing_key),
                public_jwk: &active.public_jwk,
            });
        }
        self.verification_keys.iter().find_map(|key| {
            if key.managed.kid == self.active_kid
                || !key.managed.can_sign(purpose)
                || key.managed.algorithm != algorithm_name
                || key.public_jwk.get("alg").and_then(Value::as_str) != Some(algorithm_name)
            {
                return None;
            }
            Some(SelectedKey {
                kid: &key.managed.kid,
                algorithm,
                handle: match &key.managed.handle {
                    KeyHandle::Local(private_key) => SelectedHandle::Local(private_key),
                    KeyHandle::External { key_ref } => {
                        let _ = key_ref;
                        return None;
                    }
                },
                public_jwk: &key.public_jwk,
            })
        })
    }
}

pub(crate) struct SelectedKey<'a> {
    pub(crate) kid: &'a str,
    pub(crate) algorithm: jsonwebtoken::Algorithm,
    pub(crate) handle: SelectedHandle<'a>,
    pub(crate) public_jwk: &'a Value,
}

pub(crate) enum SelectedHandle<'a> {
    Active(&'a ActiveSigningKey),
    Local(&'a [u8]),
}

impl KeyManager {
    pub async fn list_keys(settings: &KeySettings) -> anyhow::Result<Vec<KeyRecord>> {
        crate::store::list_keys(settings).await
    }

    pub async fn register_external(
        settings: &KeySettings,
        registration: ExternalKeyRegistration,
    ) -> anyhow::Result<()> {
        crate::store::register_external_key(settings, registration).await
    }

    pub async fn register_local(
        settings: &KeySettings,
        registration: LocalKeyRegistration,
    ) -> anyhow::Result<String> {
        crate::store::register_local_key(settings, registration).await
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test(algorithm: jsonwebtoken::Algorithm) -> Self {
        Self::for_test_behavior(algorithm, TestSigningBehavior::Working)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test_behavior(
        algorithm: jsonwebtoken::Algorithm,
        behavior: TestSigningBehavior,
    ) -> Self {
        let material = crate::store::generate_key_material(algorithm)
            .expect("test signing key should generate");
        let kid = format!(
            "test-{}",
            crate::store::signing_algorithm_name(algorithm).unwrap()
        );
        let public_jwk =
            crate::store::public_jwk_from_private_der(&kid, algorithm, &material.private_pkcs8_der)
                .expect("test public JWK should derive");
        let active_signing_key = match behavior {
            TestSigningBehavior::Working => {
                ActiveSigningKey::LocalPkcs8Der(material.private_pkcs8_der.clone())
            }
            TestSigningBehavior::Failing => ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            TestSigningBehavior::ExternalFailure { stderr } => {
                ActiveSigningKey::ExternalCommand(ExternalSigningKey {
                    command: Arc::new(external_failure_command(&stderr)),
                    key_ref: "kms://test/failure".to_owned(),
                    timeout: Duration::from_secs(2),
                })
            }
        };
        let loaded = LoadedKeyset {
            active_kid: kid.clone(),
            active_alg: algorithm,
            active_signing_key,
            verification_keys: vec![StoredVerificationKey {
                public_jwk,
                managed: ManagedKey {
                    kid,
                    algorithm: crate::store::signing_algorithm_name(algorithm)
                        .unwrap()
                        .to_owned(),
                    purposes: all_signing_purposes(),
                    state: KeyState::Active,
                    handle: KeyHandle::Local(material.private_pkcs8_der),
                },
            }],
            request_object_decryption_key: test_request_object_decryption_key()
                .expect("test request object decryption key"),
            request_object_encryption_jwk: Value::Null,
        };
        let mut loaded = loaded;
        loaded.request_object_encryption_jwk =
            crate::store::request_object_encryption_jwk(&loaded.request_object_decryption_key)
                .expect("test request object encryption JWK");
        let generation = KeyGeneration::new(loaded);
        Self {
            inner: Arc::new(KeyManagerInner {
                generation: ArcSwap::from_pointee(generation),
                settings: KeySettings {
                    keys_dir: PathBuf::new(),
                    external_command: Vec::new(),
                    external_timeout: Duration::from_secs(2),
                    rotation_interval: chrono::Duration::days(90),
                    prepublish_window: chrono::Duration::days(1),
                    verification_grace: chrono::Duration::minutes(10),
                },
                health: Arc::new(LifecycleHealth::new()),
                lifecycle_shutdown: watch::channel(false).0,
            }),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn for_test_with_auxiliary(algorithm: jsonwebtoken::Algorithm) -> Self {
        let manager = Self::for_test(jsonwebtoken::Algorithm::EdDSA);
        let mut loaded = manager.inner.generation.load().loaded.clone();
        let material = crate::store::generate_key_material(algorithm).unwrap();
        let kid = format!(
            "test-aux-{}",
            crate::store::signing_algorithm_name(algorithm).unwrap()
        );
        let public_jwk =
            crate::store::public_jwk_from_private_der(&kid, algorithm, &material.private_pkcs8_der)
                .unwrap();
        loaded.verification_keys.push(StoredVerificationKey {
            public_jwk,
            managed: ManagedKey {
                kid,
                algorithm: crate::store::signing_algorithm_name(algorithm)
                    .unwrap()
                    .to_owned(),
                purposes: [
                    SigningPurpose::IdToken,
                    SigningPurpose::Jarm,
                    SigningPurpose::Introspection,
                    SigningPurpose::Credential,
                    SigningPurpose::PresentationRequest,
                ]
                .into_iter()
                .collect(),
                state: KeyState::Active,
                handle: KeyHandle::Local(material.private_pkcs8_der),
            },
        });
        manager
            .inner
            .generation
            .store(Arc::new(KeyGeneration::new(loaded)));
        manager
    }

    pub async fn validate(settings: &KeySettings) -> anyhow::Result<()> {
        let path = settings.keys_dir.join("keyset.json");
        if crate::store::try_load_keyset(settings, &path)
            .await?
            .is_none()
        {
            anyhow::bail!("keyset.json does not exist");
        }
        Ok(())
    }

    pub async fn load_or_create(settings: KeySettings) -> anyhow::Result<Self> {
        let loaded = crate::store::load_or_create_keyset(&settings).await?;
        Ok(Self::from_loaded(settings, loaded))
    }

    pub(crate) fn from_loaded(settings: KeySettings, loaded: LoadedKeyset) -> Self {
        Self {
            inner: Arc::new(KeyManagerInner {
                generation: ArcSwap::from_pointee(KeyGeneration::new(loaded)),
                settings,
                health: Arc::new(LifecycleHealth::new()),
                lifecycle_shutdown: watch::channel(false).0,
            }),
        }
    }

    #[must_use]
    pub fn health(&self) -> KeyHealth {
        self.inner.health.snapshot()
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.health().is_healthy()
    }

    /// Stop the lifecycle loop owned by the caller's background task.
    ///
    /// The manager remains usable for inspection, but no further automatic
    /// refreshes are attempted after the loop observes this signal.
    pub fn stop_lifecycle(&self) {
        self.inner.lifecycle_shutdown.send_replace(true);
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<KeySnapshot> {
        Arc::clone(&self.inner.generation.load().snapshot)
    }

    pub async fn encode_jwt<T: Serialize>(
        &self,
        purpose: SigningPurpose,
        header: &jsonwebtoken::Header,
        claims: &T,
    ) -> jsonwebtoken::errors::Result<String> {
        if !self.is_healthy() {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat.into());
        }
        let generation = self.inner.generation.load_full();
        let selected = generation
            .loaded
            .selected_key(purpose, header.alg)
            .ok_or(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
        if header.kid.as_deref().is_some_and(|kid| kid != selected.kid) {
            return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
        }
        let mut header = header.clone();
        header.kid = Some(selected.kid.to_owned());
        let header_json = serde_json::to_vec(&header)?;
        let claims_json = serde_json::to_vec(claims)?;
        let mut signing_input = String::with_capacity(
            encoded_len(header_json.len(), false)
                .expect("JWT header is too large to encode")
                .saturating_add(1)
                .saturating_add(
                    encoded_len(claims_json.len(), false)
                        .expect("JWT claims are too large to encode"),
                ),
        );
        URL_SAFE_NO_PAD.encode_string(&header_json, &mut signing_input);
        signing_input.push('.');
        URL_SAFE_NO_PAD.encode_string(&claims_json, &mut signing_input);
        drop(header_json);
        drop(claims_json);
        let signature = sign_selected(&selected, signing_input.as_bytes())
            .await
            .map_err(sign_error_to_jwt)?;
        signing_input.reserve(
            encoded_len(signature.as_bytes().len(), false)
                .expect("JWT signature is too large to encode")
                .saturating_add(1),
        );
        signing_input.push('.');
        URL_SAFE_NO_PAD.encode_string(signature.as_bytes(), &mut signing_input);
        Ok(signing_input)
    }

    pub fn prepare_http_signing(&self) -> anyhow::Result<HttpSigningLease> {
        if !self.is_healthy() {
            anyhow::bail!("signing key lifecycle is unhealthy");
        }
        let generation = self.inner.generation.load_full();
        let selected = generation
            .loaded
            .selected_key(SigningPurpose::HttpMessage, generation.loaded.active_alg)
            .ok_or_else(|| anyhow::anyhow!("HTTP message signing key unavailable"))?;
        let http_algorithm = match selected.algorithm {
            jsonwebtoken::Algorithm::EdDSA => "ed25519",
            jsonwebtoken::Algorithm::RS256 => "rsa-v1_5-sha256",
            jsonwebtoken::Algorithm::ES256 => "ecdsa-p256-sha256",
            _ => anyhow::bail!("unsupported HTTP message signing algorithm"),
        };
        Ok(HttpSigningLease {
            algorithm: selected.algorithm,
            kid: selected.kid.to_owned(),
            http_algorithm,
            generation,
            health: Arc::clone(&self.inner.health),
        })
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        match crate::store::load_or_create_keyset(&self.inner.settings).await {
            Ok(loaded) => {
                self.inner
                    .generation
                    .store(Arc::new(KeyGeneration::new(loaded)));
                self.inner.health.mark_success();
                Ok(())
            }
            Err(error) => {
                self.inner.health.mark_failure();
                Err(error)
            }
        }
    }
}

#[cfg(all(any(test, feature = "test-support"), windows))]
fn external_failure_command(stderr: &str) -> Vec<String> {
    vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        format!(
            "$null=[Console]::In.ReadToEnd(); [Console]::Error.Write('{}'); exit 7",
            stderr.replace('\'', "''")
        ),
    ]
}

#[cfg(all(any(test, feature = "test-support"), unix))]
fn external_failure_command(stderr: &str) -> Vec<String> {
    vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!(
            "cat >/dev/null; printf '%s' '{}' >&2; exit 7",
            stderr.replace('\'', "'\"'\"'")
        ),
    ]
}

impl Signer for KeyManager {
    async fn sign<'a>(&'a self, request: SignRequest<'a>) -> Result<Signature, SignError> {
        if !self.is_healthy() {
            return Err(SignError::KeyUnavailable);
        }
        let algorithm = crate::store::signing_algorithm_from_name(request.algorithm)
            .ok_or(SignError::UnsupportedAlgorithm)?;
        let generation = self.inner.generation.load_full();
        let selected = generation
            .loaded
            .selected_key(request.purpose, algorithm)
            .ok_or(SignError::KeyUnavailable)?;
        sign_selected(&selected, request.signing_input).await
    }
}

async fn sign_selected(selected: &SelectedKey<'_>, input: &[u8]) -> Result<Signature, SignError> {
    match &selected.handle {
        SelectedHandle::Active(ActiveSigningKey::LocalPkcs8Der(private_key)) => {
            crate::local::LocalBackend {
                algorithm: selected.algorithm,
                private_key,
            }
            .sign(input)
            .await
        }
        SelectedHandle::Active(ActiveSigningKey::ExternalCommand(external)) => {
            crate::external::ExternalBackend {
                external,
                kid: selected.kid,
                algorithm: selected.algorithm,
                public_jwk: selected.public_jwk,
            }
            .sign(input)
            .await
        }
        SelectedHandle::Local(private_key) => {
            crate::local::LocalBackend {
                algorithm: selected.algorithm,
                private_key,
            }
            .sign(input)
            .await
        }
    }
}

fn sign_error_to_jwt(error: SignError) -> jsonwebtoken::errors::Error {
    crate::external::jwt_provider_error(error.to_string())
}

impl KeyGeneration {
    fn new(loaded: LoadedKeyset) -> Self {
        let snapshot = Arc::new(snapshot_from_loaded(&loaded));
        Self { loaded, snapshot }
    }
}

pub(crate) fn snapshot_from_loaded(loaded: &LoadedKeyset) -> KeySnapshot {
    const ORDERED: [jsonwebtoken::Algorithm; 4] = [
        jsonwebtoken::Algorithm::EdDSA,
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::ES256,
        jsonwebtoken::Algorithm::PS256,
    ];
    let id_token_signing_algorithms = ORDERED
        .into_iter()
        .filter(|algorithm| {
            loaded
                .selected_key(SigningPurpose::IdToken, *algorithm)
                .is_some()
        })
        .collect();
    let response_signing_algorithms = ORDERED
        .into_iter()
        .filter(|algorithm| {
            loaded
                .selected_key(SigningPurpose::IdToken, *algorithm)
                .is_some()
                || loaded
                    .selected_key(SigningPurpose::Jarm, *algorithm)
                    .is_some()
                || loaded
                    .selected_key(SigningPurpose::Introspection, *algorithm)
                    .is_some()
        })
        .collect();
    KeySnapshot {
        active_kid: loaded.active_kid.clone(),
        active_alg: loaded.active_alg,
        verification_keys: loaded
            .verification_keys
            .iter()
            .map(|key| VerificationKey {
                kid: key.managed.kid.clone(),
                public_jwk: key.public_jwk.clone(),
                signing_purposes: if key.managed.state == KeyState::Active {
                    key.managed.purposes.clone()
                } else {
                    BTreeSet::new()
                },
            })
            .collect(),
        id_token_signing_algorithms,
        response_signing_algorithms,
        request_object_encryption_jwk: loaded.request_object_encryption_jwk.clone(),
    }
}

#[cfg(any(test, feature = "test-support"))]
fn test_request_object_decryption_key() -> anyhow::Result<Vec<u8>> {
    crate::crypto::generate_rsa_pkcs8_pem(2048)
}

#[cfg(any(test, feature = "test-support"))]
fn all_signing_purposes() -> BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::Introspection,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
        SigningPurpose::SecurityEvent,
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect()
}

#[derive(Clone)]
pub struct ManagedKey {
    pub kid: String,
    pub algorithm: String,
    pub purposes: BTreeSet<SigningPurpose>,
    pub state: KeyState,
    pub(crate) handle: KeyHandle,
}

impl ManagedKey {
    #[must_use]
    pub fn can_sign(&self, purpose: SigningPurpose) -> bool {
        self.state == KeyState::Active && self.purposes.contains(&purpose)
    }

    #[must_use]
    pub fn can_verify(&self) -> bool {
        matches!(
            self.state,
            KeyState::Prepublished | KeyState::Active | KeyState::Grace
        )
    }
}

#[cfg(test)]
#[path = "../tests/unit/model.rs"]
mod tests;
