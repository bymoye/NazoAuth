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
