use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Instant,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignRequest, Signer, SigningPurpose};

use super::{
    KeyGeneration, KeyHandle, KeyManager, KeyRecordStatus, KeySettings, KeyState, ManagedKey,
};
use crate::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};

#[derive(Default)]
struct MemoryRepository(Mutex<Option<PersistedSigningKeyset>>);

impl SigningKeyRepository for MemoryRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let mut record = self.0.lock().unwrap();
            Ok(match record.clone() {
                Some(existing) => SigningKeysetCreateResult::Existing(existing),
                None => {
                    *record = Some(candidate.clone());
                    SigningKeysetCreateResult::Created(candidate)
                }
            })
        })
    }

    fn compare_and_swap(
        &self,
        expected: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let mut record = self.0.lock().unwrap();
            let current = record.clone().expect("keyset exists before CAS");
            Ok(if current.revision == expected {
                *record = Some(candidate.clone());
                SigningKeysetCompareAndSwapResult::Applied(candidate)
            } else {
                SigningKeysetCompareAndSwapResult::Conflict(current)
            })
        })
    }
}

fn database_settings(
    name: &str,
    rotation_interval: chrono::Duration,
    prepublish_window: chrono::Duration,
) -> KeySettings {
    KeySettings {
        keys_dir: std::env::temp_dir().join(format!("nazo-key-{name}-{}", uuid::Uuid::now_v7())),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval,
        prepublish_window,
        verification_grace: chrono::Duration::minutes(10),
    }
}

async fn database_manager(settings: KeySettings) -> KeyManager {
    KeyManager::load_or_create_database(
        settings,
        uuid::Uuid::now_v7(),
        Arc::new(MemoryRepository::default()),
        SigningKeyWrappingKeyRing::new("current", [17_u8; 32], None).unwrap(),
    )
    .await
    .unwrap()
}

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

#[tokio::test]
async fn jwt_encoding_preserves_compact_wire_bytes() {
    let manager = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let mut expected_header = header.clone();
    expected_header.kid = Some(manager.snapshot().active_kid.clone());
    let claims = serde_json::json!({
        "sub": "wire-format-test",
        "scope": "openid profile",
    });

    let token = manager
        .encode_jwt(SigningPurpose::IdToken, &header, &claims)
        .await
        .expect("active test key should encode JWT");
    let expected_signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&expected_header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
    );
    let signature = manager
        .sign(SignRequest {
            purpose: SigningPurpose::IdToken,
            algorithm: "EdDSA",
            signing_input: expected_signing_input.as_bytes(),
        })
        .await
        .expect("active test key should sign the expected input");
    let expected = format!(
        "{expected_signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_bytes())
    );

    assert_eq!(token, expected);
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

#[tokio::test]
async fn expired_database_generation_fails_closed_while_lifecycle_flag_is_still_healthy() {
    let manager = database_manager(database_settings(
        "expired-generation",
        chrono::Duration::days(90),
        chrono::Duration::days(1),
    ))
    .await;
    let mut expired = KeyGeneration::database(manager.inner.generation.load().loaded.clone());
    expired.expires_at = Some(Instant::now() - std::time::Duration::from_secs(1));
    manager.inner.generation.store(Arc::new(expired));

    assert_eq!(
        manager.inner.health.snapshot().status,
        super::KeyHealthStatus::Healthy
    );
    assert_eq!(manager.health().status, super::KeyHealthStatus::Unhealthy);
    assert!(manager.prepare_http_signing().is_err());
    assert!(
        manager
            .encode_jwt(
                SigningPurpose::IdToken,
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &serde_json::json!({"sub":"expired"}),
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn expired_http_lease_cannot_use_old_generation_after_newer_generation_is_current() {
    let manager = database_manager(database_settings(
        "expired-lease",
        chrono::Duration::days(90),
        chrono::Duration::days(1),
    ))
    .await;
    let mut lease = manager.prepare_http_signing().unwrap();
    manager
        .inner
        .generation
        .store(Arc::new(KeyGeneration::database(
            manager.inner.generation.load().loaded.clone(),
        )));
    Arc::get_mut(&mut lease.generation)
        .expect("lease owns its captured generation")
        .expires_at = Some(Instant::now() - std::time::Duration::from_secs(1));

    assert!(lease.sign(b"old generation must expire").await.is_err());
}

#[tokio::test]
async fn database_rotation_retains_old_public_key_for_grace_and_snapshot_bounds() {
    let settings = database_settings(
        "retirement-bound",
        chrono::Duration::seconds(-1),
        chrono::Duration::zero(),
    );
    let manager = database_manager(settings).await;
    let old_kid = manager.snapshot().active_kid.clone();
    let before = chrono::Utc::now();
    manager.refresh().await.unwrap(); // publishes a prepublished key
    manager.refresh().await.unwrap(); // activates it
    let old = manager
        .database_list_keys()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.kid == old_kid)
        .expect("prior active key remains published");
    assert_eq!(old.status, KeyRecordStatus::Grace);
    let retire_at = chrono::DateTime::parse_from_rfc3339(old.retire_at.as_deref().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert!(
        retire_at
            >= before
                + chrono::Duration::minutes(10)
                + crate::lifecycle::MAX_DATABASE_SNAPSHOT_STALENESS
                - chrono::Duration::seconds(1)
    );
}
