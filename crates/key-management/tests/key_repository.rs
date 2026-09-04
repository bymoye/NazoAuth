use std::sync::{Arc, Mutex};

use nazo_key_management::{
    KeyManager, KeySettings, PersistedSigningKeyset, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
use uuid::Uuid;

#[test]
fn encrypted_key_material_is_bound_to_its_tenant_and_purpose() {
    let ring = SigningKeyWrappingKeyRing::new("current", [7_u8; 32], None)
        .expect("test wrapping ring should be valid");
    let tenant = Uuid::now_v7();
    let sealed = ring
        .seal(tenant, "credential", b"private-key-material")
        .expect("material should seal");

    assert_eq!(
        ring.open(tenant, "credential", &sealed)
            .expect("matching scope should open"),
        b"private-key-material"
    );
    assert!(ring.open(Uuid::now_v7(), "credential", &sealed).is_err());
    assert!(ring.open(tenant, "presentation_request", &sealed).is_err());
}

#[test]
fn encrypted_generation_rejects_swapped_public_metadata() {
    let ring = SigningKeyWrappingKeyRing::new("current", [9_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let metadata = serde_json::json!({"active_kid":"one","keys":[{"kid":"one"}]});
    let sealed = ring
        .seal_generation(tenant, 4, &metadata, b"private-generation")
        .unwrap();
    assert!(
        ring.open_generation(
            tenant,
            4,
            &serde_json::json!({"active_kid":"two","keys":[{"kid":"two"}]}),
            &sealed,
        )
        .is_err()
    );
}

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
            let current = record.clone().unwrap();
            Ok(if current.revision == expected {
                *record = Some(candidate.clone());
                SigningKeysetCompareAndSwapResult::Applied(candidate)
            } else {
                SigningKeysetCompareAndSwapResult::Conflict(current)
            })
        })
    }
}

#[tokio::test]
async fn two_managers_share_database_keyset_without_writing_key_files() {
    let root = std::env::temp_dir().join(format!("nazoauth-db-keys-{}", Uuid::now_v7()));
    let settings = KeySettings {
        keys_dir: root.clone(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemoryRepository::default());
    let ring = SigningKeyWrappingKeyRing::new("current", [3_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let (first, second) = tokio::join!(
        KeyManager::load_or_create_database(
            settings.clone(),
            tenant,
            repository.clone(),
            ring.clone()
        ),
        KeyManager::load_or_create_database(settings, tenant, repository.clone(), ring),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.snapshot().active_kid, second.snapshot().active_kid);
    assert!(
        !root.exists(),
        "database key path must not create local files"
    );
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 1);
}

#[tokio::test]
async fn database_registration_converges_and_survives_restart_without_files() {
    let root = std::env::temp_dir().join(format!("nazoauth-db-register-{}", Uuid::now_v7()));
    let settings = KeySettings {
        keys_dir: root.clone(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemoryRepository::default());
    let ring = SigningKeyWrappingKeyRing::new("current", [4_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let first = KeyManager::load_or_create_database(
        settings.clone(),
        tenant,
        repository.clone(),
        ring.clone(),
    )
    .await
    .unwrap();
    let purposes: std::collections::BTreeSet<_> = [
        nazo_auth::SigningPurpose::Credential,
        nazo_auth::SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect();
    let (first_kid, second_kid) = tokio::join!(
        first.database_register_local(nazo_key_management::LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: purposes.clone()
        }),
        KeyManager::load_or_create_database(
            settings.clone(),
            tenant,
            repository.clone(),
            ring.clone()
        ),
    );
    let first_kid = first_kid.unwrap();
    let second = second_kid.unwrap();
    let records = second.database_list_keys().await.unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.kid == first_kid && record.backend == "local-db")
    );
    assert!(
        !root.exists(),
        "database key registration must not write key files"
    );
    let restarted = KeyManager::load_or_create_database(settings, tenant, repository.clone(), ring)
        .await
        .unwrap();
    assert_eq!(
        restarted
            .database_register_local(nazo_key_management::LocalKeyRegistration {
                algorithm: jsonwebtoken::Algorithm::ES256,
                purposes
            })
            .await
            .unwrap(),
        first_kid
    );
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 2);
}

#[tokio::test]
async fn explicit_file_import_preserves_existing_kid_without_second_authority() {
    let root = std::env::temp_dir().join(format!("nazoauth-key-import-{}", Uuid::now_v7()));
    let settings = KeySettings {
        keys_dir: root.clone(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let legacy = KeyManager::load_or_create(settings.clone()).await.unwrap();
    let expected_kid = legacy.snapshot().active_kid.clone();
    let repository = Arc::new(MemoryRepository::default());
    let imported = KeyManager::import_legacy_file_keyset(
        settings,
        Uuid::now_v7(),
        repository.clone(),
        SigningKeyWrappingKeyRing::new("current", [5_u8; 32], None).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(imported.snapshot().active_kid, expected_kid);
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 1);
}

#[tokio::test]
async fn refresh_reseals_an_old_generation_before_previous_wrapping_key_is_removed() {
    let root = std::env::temp_dir().join(format!("nazoauth-key-reseal-{}", Uuid::now_v7()));
    let settings = KeySettings {
        keys_dir: root,
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemoryRepository::default());
    let tenant = Uuid::now_v7();
    let old = SigningKeyWrappingKeyRing::new("old", [6_u8; 32], None).unwrap();
    KeyManager::load_or_create_database(settings.clone(), tenant, repository.clone(), old)
        .await
        .unwrap();
    let rollover =
        SigningKeyWrappingKeyRing::new("new", [7_u8; 32], Some(("old".to_owned(), [6_u8; 32])))
            .unwrap();
    let manager =
        KeyManager::load_or_create_database(settings.clone(), tenant, repository.clone(), rollover)
            .await
            .unwrap();
    manager.refresh().await.unwrap();
    assert_eq!(
        repository.load().await.unwrap().unwrap().wrapping_key_id,
        "new"
    );
    KeyManager::load_or_create_database(
        settings,
        tenant,
        repository,
        SigningKeyWrappingKeyRing::new("new", [7_u8; 32], None).unwrap(),
    )
    .await
    .unwrap();
}
