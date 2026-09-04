use std::sync::{Arc, Mutex};

use nazo_key_management::{
    KeyManager, KeySettings, PersistedSigningKeyset, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
use uuid::Uuid;

#[test]
fn encrypted_key_material_is_bound_to_its_tenant_and_purpose() {
    let ring = SigningKeyWrappingKeyRing::new(
        "current",
        [7_u8; 32],
        None,
    )
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
    assert!(ring
        .open_generation(
            tenant,
            4,
            &serde_json::json!({"active_kid":"two","keys":[{"kid":"two"}]}),
            &sealed,
        )
        .is_err());
}

#[derive(Default)]
struct MemoryRepository(Mutex<Option<PersistedSigningKeyset>>);

impl SigningKeyRepository for MemoryRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }
    fn create_if_absent(&self, candidate: PersistedSigningKeyset) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let mut record = self.0.lock().unwrap();
            Ok(match record.clone() { Some(existing) => SigningKeysetCreateResult::Existing(existing), None => { *record = Some(candidate.clone()); SigningKeysetCreateResult::Created(candidate) } })
        })
    }
    fn compare_and_swap(&self, expected: i64, candidate: PersistedSigningKeyset) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let mut record = self.0.lock().unwrap();
            let current = record.clone().unwrap();
            Ok(if current.revision == expected { *record = Some(candidate.clone()); SigningKeysetCompareAndSwapResult::Applied(candidate) } else { SigningKeysetCompareAndSwapResult::Conflict(current) })
        })
    }
}

#[tokio::test]
async fn two_managers_share_database_keyset_without_writing_key_files() {
    let root = std::env::temp_dir().join(format!("nazoauth-db-keys-{}", Uuid::now_v7()));
    let settings = KeySettings { keys_dir: root.clone(), external_command: Vec::new(), external_timeout: std::time::Duration::from_secs(1), rotation_interval: chrono::Duration::days(90), prepublish_window: chrono::Duration::days(1), verification_grace: chrono::Duration::minutes(10) };
    let repository = Arc::new(MemoryRepository::default());
    let ring = SigningKeyWrappingKeyRing::new("current", [3_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let first = KeyManager::load_or_create_database(settings.clone(), tenant, repository.clone(), ring.clone()).await.unwrap();
    let second = KeyManager::load_or_create_database(settings, tenant, repository, ring).await.unwrap();
    assert_eq!(first.snapshot().active_kid, second.snapshot().active_kid);
    assert!(!root.exists(), "database key path must not create local files");
}
