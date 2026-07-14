use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use crate::local::SigningBackend;
use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignError, SignRequest, Signature, Signer, SigningPurpose};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    Prepublished,
    Active,
    Grace,
    Retired,
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
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub kid: String,
    pub public_jwk: Value,
}

#[derive(Clone, Debug)]
pub struct KeySnapshot {
    pub active_kid: String,
    pub active_alg: jsonwebtoken::Algorithm,
    pub verification_keys: Vec<VerificationKey>,
    pub(crate) id_token_signing_algorithms: Vec<jsonwebtoken::Algorithm>,
    pub(crate) response_signing_algorithms: Vec<jsonwebtoken::Algorithm>,
}

impl KeySnapshot {
    #[must_use]
    pub fn verification_key(&self, kid: &str) -> Option<&VerificationKey> {
        self.verification_keys.iter().find(|key| key.kid == kid)
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
        crate::jwks::public_jwks(&self.verification_keys)
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
/// This status preserves keyctl's storage/lifecycle presentation and does not
/// describe runtime signing capability. A persisted non-active auxiliary key
/// can therefore be `Prepublished` here while its runtime [`ManagedKey`] is
/// [`KeyState::Active`] for a restricted purpose set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRecordStatus {
    Prepublished,
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

pub(crate) struct KeyGeneration {
    pub(crate) loaded: LoadedKeyset,
    pub(crate) snapshot: Arc<KeySnapshot>,
}

pub(crate) struct KeyManagerInner {
    pub(crate) generation: ArcSwap<KeyGeneration>,
    pub(crate) settings: KeySettings,
}

#[derive(Clone)]
pub struct KeyManager {
    pub(crate) inner: Arc<KeyManagerInner>,
}

pub struct HttpSigningLease {
    generation: Arc<KeyGeneration>,
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
        };
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
                purposes: [SigningPurpose::IdToken, SigningPurpose::Jarm]
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
            }),
        }
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
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = sign_selected(&selected, signing_input.as_bytes())
            .await
            .map_err(sign_error_to_jwt)?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_bytes())
        ))
    }

    pub fn prepare_http_signing(&self) -> anyhow::Result<HttpSigningLease> {
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
        })
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let loaded = crate::store::load_or_create_keyset(&self.inner.settings).await?;
        self.inner
            .generation
            .store(Arc::new(KeyGeneration::new(loaded)));
        Ok(())
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
            })
            .collect(),
        id_token_signing_algorithms,
        response_signing_algorithms,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn all_signing_purposes() -> BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
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
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use nazo_auth::{SignRequest, Signer, SigningPurpose};

    use super::{KeyGeneration, KeyHandle, KeyManager, KeyState, ManagedKey};

    fn managed_key(state: KeyState, purposes: &[SigningPurpose]) -> ManagedKey {
        ManagedKey {
            kid: "purpose-key".to_owned(),
            algorithm: "EdDSA".to_owned(),
            purposes: purposes.iter().copied().collect::<BTreeSet<_>>(),
            state,
            handle: KeyHandle::Local(Vec::new()),
        }
    }

    fn manager_with_policy(state: KeyState, purposes: &[SigningPurpose]) -> KeyManager {
        let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        let mut loaded = manager.inner.generation.load().loaded.clone();
        loaded.verification_keys[0].managed.state = state;
        loaded.verification_keys[0].managed.purposes = purposes.iter().copied().collect();
        manager
            .inner
            .generation
            .store(Arc::new(KeyGeneration::new(loaded)));
        manager
    }

    #[test]
    fn id_token_key_rejects_http_message_signing() {
        let key = managed_key(KeyState::Active, &[SigningPurpose::IdToken]);
        assert!(key.can_sign(SigningPurpose::IdToken));
        assert!(!key.can_sign(SigningPurpose::HttpMessage));
    }

    #[test]
    fn metadata_snapshot_does_not_advertise_jarm_only_keys_for_id_tokens() {
        let manager = manager_with_policy(KeyState::Active, &[SigningPurpose::Jarm]);
        let snapshot = manager.snapshot();

        assert_eq!(
            snapshot.response_signing_alg_values_supported(),
            vec!["EdDSA"]
        );
        assert!(snapshot.id_token_signing_alg_values_supported().is_empty());
    }

    #[test]
    fn grace_key_verifies_but_does_not_sign() {
        let key = managed_key(KeyState::Grace, &[SigningPurpose::AccessToken]);
        assert!(key.can_verify());
        assert!(!key.can_sign(SigningPurpose::AccessToken));
    }

    #[test]
    fn retired_key_neither_verifies_nor_signs() {
        let key = managed_key(KeyState::Retired, &[SigningPurpose::AccessToken]);
        assert!(!key.can_verify());
        assert!(!key.can_sign(SigningPurpose::AccessToken));
    }

    #[tokio::test]
    async fn http_signing_lease_keeps_label_and_key_on_one_generation_during_rotation() {
        let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        let original_snapshot = manager.snapshot();
        let lease = manager
            .prepare_http_signing()
            .expect("active HTTP signing key should produce a lease");
        assert_eq!(lease.kid(), original_snapshot.active_kid);
        assert_eq!(lease.algorithm(), "ed25519");

        let replacement = KeyManager::for_test(jsonwebtoken::Algorithm::RS256);
        manager
            .inner
            .generation
            .store(replacement.inner.generation.load_full());

        let signature = lease
            .sign(b"generation-bound signature base")
            .await
            .expect("lease must retain its captured signing generation");
        let public = &original_snapshot
            .verification_key(lease.kid())
            .expect("lease kid must identify a captured public key")
            .public_jwk;
        let decoding_key =
            jsonwebtoken::DecodingKey::from_ed_components(public["x"].as_str().unwrap()).unwrap();
        assert!(
            jsonwebtoken::crypto::verify(
                &URL_SAFE_NO_PAD.encode(signature.as_bytes()),
                b"generation-bound signature base",
                &decoding_key,
                jsonwebtoken::Algorithm::EdDSA,
            )
            .unwrap()
        );
        assert_eq!(
            manager.snapshot().active_alg,
            jsonwebtoken::Algorithm::RS256
        );
    }

    #[tokio::test]
    async fn http_signing_lease_fails_closed_when_identity_does_not_match_generation() {
        let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        let mut lease = manager.prepare_http_signing().unwrap();
        lease.kid = "mismatched-kid".to_owned();

        let error = lease
            .sign(b"identity mismatch")
            .await
            .expect_err("a mismatched lease identity must fail closed");
        assert!(format!("{error:#}").contains("no longer matches"));
    }

    #[tokio::test]
    async fn signer_rejects_active_key_with_wrong_purpose() {
        let manager = manager_with_policy(KeyState::Active, &[SigningPurpose::IdToken]);
        let error = manager
            .sign(SignRequest {
                purpose: SigningPurpose::HttpMessage,
                algorithm: "EdDSA",
                signing_input: b"wrong purpose",
            })
            .await
            .expect_err("purpose policy must be enforced by the real Signer path");
        assert_eq!(error, nazo_auth::SignError::KeyUnavailable);
    }

    #[tokio::test]
    async fn jwt_encoding_rejects_grace_and_retired_keys() {
        for state in [KeyState::Grace, KeyState::Retired] {
            let manager = manager_with_policy(state, &[SigningPurpose::IdToken]);
            let error = manager
                .encode_jwt(
                    SigningPurpose::IdToken,
                    &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
                    &serde_json::json!({"sub":"policy-test"}),
                )
                .await
                .expect_err("non-active keys must not encode JWTs");
            assert!(matches!(
                error.kind(),
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
            ));
        }
    }

    #[test]
    fn http_signing_rejects_wrong_purpose_grace_and_retired_keys() {
        for (state, purposes) in [
            (KeyState::Active, vec![SigningPurpose::IdToken]),
            (KeyState::Grace, vec![SigningPurpose::HttpMessage]),
            (KeyState::Retired, vec![SigningPurpose::HttpMessage]),
        ] {
            let manager = manager_with_policy(state, &purposes);
            assert!(
                manager.prepare_http_signing().is_err(),
                "HTTP signing must reject policy state {state:?}"
            );
        }
    }
}
