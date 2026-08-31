use super::*;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId,
};
use nazo_persistence::TenantDirectoryStore;
use uuid::Uuid;

use crate::bootstrap::{TenantDirectoryCachePort, TransientStateError, TransientStateFuture};

fn binding(id: u128, host: &str, issuer: &str) -> TenantDirectoryBinding {
    TenantDirectoryBinding {
        tenant: TenantContext {
            tenant_id: TenantId::new(Uuid::from_u128(id)).expect("tenant id is non-nil"),
            realm_id: RealmId::new(Uuid::from_u128(id + 0x100)).expect("realm id is non-nil"),
            organization_id: OrganizationId::new(Uuid::from_u128(id + 0x200))
                .expect("organization id is non-nil"),
        },
        runtime_revision: 1,
        issuer: issuer.to_owned(),
        external_host: host.to_owned(),
    }
}

fn snapshot(revision: u64, tenants: Vec<TenantDirectoryBinding>) -> TenantDirectorySnapshot {
    TenantDirectorySnapshot { revision, tenants }
}

#[derive(Clone)]
enum CacheReply {
    Snapshot(TenantDirectorySnapshot),
    Miss,
    Error(TransientStateError),
}

struct RecordingCache {
    replies: Mutex<VecDeque<CacheReply>>,
    loads: AtomicUsize,
    stores: Mutex<Vec<TenantDirectorySnapshot>>,
}

impl RecordingCache {
    fn new(replies: impl IntoIterator<Item = CacheReply>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
            loads: AtomicUsize::new(0),
            stores: Mutex::new(Vec::new()),
        }
    }

    fn load_count(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }

    fn stored(&self) -> Vec<TenantDirectorySnapshot> {
        self.stores.lock().expect("cache stores lock").clone()
    }
}

impl TenantDirectoryCachePort for RecordingCache {
    fn load(&self) -> TransientStateFuture<'_, Option<TenantDirectorySnapshot>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        let reply = self
            .replies
            .lock()
            .expect("cache replies lock")
            .pop_front()
            .unwrap_or(CacheReply::Miss);
        Box::pin(async move {
            match reply {
                CacheReply::Snapshot(snapshot) => Ok(Some(snapshot)),
                CacheReply::Miss => Ok(None),
                CacheReply::Error(error) => Err(error),
            }
        })
    }

    fn publish_authoritative<'a>(
        &'a self,
        snapshot: &'a TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool> {
        self.stores
            .lock()
            .expect("cache stores lock")
            .push(snapshot.clone());
        Box::pin(async { Ok(true) })
    }
}

struct RecordingDirectory {
    revision: Mutex<u64>,
    snapshots:
        Mutex<VecDeque<Result<TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>>>,
    revision_reads: AtomicUsize,
    snapshot_reads: AtomicUsize,
}

impl RecordingDirectory {
    fn new(revision: u64, snapshots: impl IntoIterator<Item = TenantDirectorySnapshot>) -> Self {
        Self {
            revision: Mutex::new(revision),
            snapshots: Mutex::new(snapshots.into_iter().map(Ok).collect()),
            revision_reads: AtomicUsize::new(0),
            snapshot_reads: AtomicUsize::new(0),
        }
    }

    fn revision_read_count(&self) -> usize {
        self.revision_reads.load(Ordering::SeqCst)
    }

    fn snapshot_read_count(&self) -> usize {
        self.snapshot_reads.load(Ordering::SeqCst)
    }

    fn set_revision(&self, revision: u64) {
        *self.revision.lock().expect("directory revision lock") = revision;
    }

    fn push_snapshot(&self, snapshot: TenantDirectorySnapshot) {
        self.snapshots
            .lock()
            .expect("directory snapshots lock")
            .push_back(Ok(snapshot));
    }
}

impl TenantDirectoryStore for RecordingDirectory {
    fn current_revision(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>>
    {
        self.revision_reads.fetch_add(1, Ordering::SeqCst);
        let revision = *self.revision.lock().expect("directory revision lock");
        Box::pin(async move { Ok(revision) })
    }

    fn load_active(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>,
    > {
        self.snapshot_reads.fetch_add(1, Ordering::SeqCst);
        let result = self
            .snapshots
            .lock()
            .expect("directory snapshots lock")
            .pop_front()
            .unwrap_or_else(|| {
                Err(nazo_identity::ports::RepositoryError::Unexpected(
                    "unscripted directory read".to_owned(),
                ))
            });
        Box::pin(async move { result })
    }
}

struct RecordingBuilder {
    builds: AtomicUsize,
    builds_with_previous: AtomicUsize,
    failing_host: Mutex<Option<String>>,
}

impl RecordingBuilder {
    fn new() -> Self {
        Self {
            builds: AtomicUsize::new(0),
            builds_with_previous: AtomicUsize::new(0),
            failing_host: Mutex::new(None),
        }
    }

    fn build_count(&self) -> usize {
        self.builds.load(Ordering::SeqCst)
    }

    fn build_with_previous_count(&self) -> usize {
        self.builds_with_previous.load(Ordering::SeqCst)
    }

    fn fail_for(&self, host: &str) {
        *self.failing_host.lock().expect("builder failure lock") = Some(host.to_owned());
    }
}

impl TenantRuntimeBuildPort for RecordingBuilder {
    fn build(
        &self,
        binding: &TenantDirectoryBinding,
        previous_same_tenant: Option<Arc<TenantRuntime>>,
    ) -> TenantRuntimeBuildFuture<'_> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        if previous_same_tenant.is_some() {
            self.builds_with_previous.fetch_add(1, Ordering::SeqCst);
        }
        let binding = binding.clone();
        let should_fail = self
            .failing_host
            .lock()
            .expect("builder failure lock")
            .as_deref()
            == Some(binding.external_host.as_str());
        Box::pin(async move {
            if should_fail {
                anyhow::bail!("scripted build failure for {}", binding.external_host);
            }
            Ok(match previous_same_tenant {
                Some(previous) => TenantRuntime::for_test_reusing(binding, &previous),
                None => TenantRuntime::for_test(binding),
            })
        })
    }
}

struct Fixture {
    registry: TenantRuntimeRegistry,
    cache: Arc<RecordingCache>,
    directory: Arc<RecordingDirectory>,
    builder: Arc<RecordingBuilder>,
    refresher: TenantRuntimeRefresher,
}

impl Fixture {
    async fn new(
        initial: TenantDirectorySnapshot,
        cache_replies: impl IntoIterator<Item = CacheReply>,
        directory_revision: u64,
        directory_snapshots: impl IntoIterator<Item = TenantDirectorySnapshot>,
    ) -> Self {
        let registry = TenantRuntimeRegistry::empty();
        let cache = Arc::new(RecordingCache::new(cache_replies));
        let directory = Arc::new(RecordingDirectory::new(
            directory_revision,
            directory_snapshots,
        ));
        let builder = Arc::new(RecordingBuilder::new());
        let refresher = TenantRuntimeRefresher::new(
            registry.clone(),
            directory.clone(),
            cache.clone(),
            TenantRuntimeBuilder::new(builder.clone()),
        );
        let expected_revision = initial.revision;
        assert_eq!(
            refresher
                .install_initial(initial)
                .await
                .expect("initial tenant snapshot installs"),
            TenantDirectoryRefreshOutcome::Applied {
                revision: expected_revision
            }
        );
        Self {
            registry,
            cache,
            directory,
            builder,
            refresher,
        }
    }
}

#[tokio::test]
async fn request_snapshot_hits_never_touch_cache_or_database() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let fixture = Fixture::new(snapshot(1, vec![tenant_a]), [], 1, []).await;
    let cache_stores_before = fixture.cache.stored().len();

    let first = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("tenant A is locally routable");
    let second = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("tenant A remains locally routable");
    assert!(Arc::ptr_eq(&first, &second));
    assert!(fixture.registry.resolve("unknown.example").is_none());

    assert_eq!(fixture.cache.load_count(), 0);
    assert_eq!(fixture.cache.stored().len(), cache_stores_before);
    assert_eq!(fixture.directory.revision_read_count(), 0);
    assert_eq!(fixture.directory.snapshot_read_count(), 0);
}

#[tokio::test]
async fn old_and_equal_cached_revisions_are_rejected_without_database_or_builds() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let changed_a = binding(1, "tenant-a.example", "https://tenant-a.example/v2");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a.clone()]),
        [
            CacheReply::Snapshot(snapshot(0, vec![tenant_b.clone()])),
            CacheReply::Snapshot(snapshot(1, vec![changed_a, tenant_b])),
        ],
        1,
        [],
    )
    .await;
    let original = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("tenant A was installed");

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("old cache snapshot is handled"),
        TenantDirectoryRefreshOutcome::Unchanged
    );
    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("equal cache snapshot is handled"),
        TenantDirectoryRefreshOutcome::Unchanged
    );

    assert_eq!(fixture.registry.revision(), 1);
    assert!(Arc::ptr_eq(
        &original,
        &fixture
            .registry
            .resolve("tenant-a.example")
            .expect("last-good tenant A remains")
    ));
    assert!(fixture.registry.resolve("tenant-b.example").is_none());
    assert_eq!(fixture.builder.build_count(), 1);
    assert_eq!(fixture.cache.load_count(), 2);
    assert_eq!(fixture.directory.revision_read_count(), 0);
    assert_eq!(fixture.directory.snapshot_read_count(), 0);
}

#[tokio::test]
async fn newer_cached_snapshot_is_published_without_database_read() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let changed_a = binding(1, "tenant-a.example", "https://tenant-a.example/v2");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a]),
        [CacheReply::Snapshot(snapshot(
            2,
            vec![changed_a.clone(), tenant_b],
        ))],
        2,
        [],
    )
    .await;

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("new cache snapshot applies"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );

    assert_eq!(fixture.registry.revision(), 2);
    assert_eq!(
        fixture
            .registry
            .resolve("tenant-a.example")
            .expect("updated tenant A is routable")
            .binding,
        changed_a
    );
    assert!(fixture.registry.resolve("tenant-b.example").is_some());
    assert_eq!(fixture.cache.load_count(), 1);
    assert_eq!(fixture.directory.revision_read_count(), 0);
    assert_eq!(fixture.directory.snapshot_read_count(), 0);
}

#[tokio::test]
async fn tenant_runtime_revision_rebuilds_only_the_changed_tenant() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let mut reloaded_a = tenant_a.clone();
    reloaded_a.runtime_revision = 2;
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a, tenant_b]),
        [CacheReply::Snapshot(snapshot(
            2,
            vec![
                reloaded_a.clone(),
                binding(2, "tenant-b.example", "https://tenant-b.example"),
            ],
        ))],
        2,
        [],
    )
    .await;
    let previous_a = fixture.registry.resolve("tenant-a.example").unwrap();
    let previous_b = fixture.registry.resolve("tenant-b.example").unwrap();

    assert_eq!(
        fixture.refresher.refresh_cache_once().await.unwrap(),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );

    let current_a = fixture.registry.resolve("tenant-a.example").unwrap();
    let current_b = fixture.registry.resolve("tenant-b.example").unwrap();
    assert!(!Arc::ptr_eq(&previous_a, &current_a));
    assert!(Arc::ptr_eq(&previous_b, &current_b));
    assert_eq!(current_a.binding, reloaded_a);
    assert_eq!(fixture.builder.build_count(), 3);
    assert_eq!(fixture.builder.build_with_previous_count(), 1);
}

#[tokio::test]
async fn database_payload_replaces_same_revision_previously_applied_from_cache() {
    let initial_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let cached_a = binding(1, "tenant-a.example", "https://tenant-a.example/cache");
    let authoritative_a = binding(1, "tenant-a.example", "https://tenant-a.example/database");
    let authoritative = snapshot(2, vec![authoritative_a.clone()]);
    let fixture = Fixture::new(
        snapshot(1, vec![initial_a]),
        [CacheReply::Snapshot(snapshot(2, vec![cached_a.clone()]))],
        2,
        [authoritative.clone()],
    )
    .await;

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("cache revision two applies first"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    let cache_runtime = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("cached tenant A is routable");
    assert_eq!(cache_runtime.binding, cached_a);

    assert_eq!(
        fixture
            .refresher
            .reconcile_database_once()
            .await
            .expect("database payload reconciles the same revision"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    let authoritative_runtime = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("authoritative tenant A is routable");
    assert_eq!(authoritative_runtime.binding, authoritative_a);
    assert!(!Arc::ptr_eq(&cache_runtime, &authoritative_runtime));
    assert!(authoritative_runtime.shares_lifecycle_with(&cache_runtime));
    assert_eq!(fixture.builder.build_with_previous_count(), 2);
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
    assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
}

#[tokio::test]
async fn cache_ahead_of_database_rolls_back_and_rejects_repeated_revision() {
    let authoritative_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let cached_a = binding(1, "tenant-a.example", "https://tenant-a.example/cache");
    let cached_revision = snapshot(3, vec![cached_a.clone()]);
    let authoritative = snapshot(1, vec![authoritative_a.clone()]);
    let fixture = Fixture::new(
        authoritative.clone(),
        [
            CacheReply::Snapshot(cached_revision.clone()),
            CacheReply::Snapshot(cached_revision),
        ],
        1,
        [authoritative.clone()],
    )
    .await;

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("cache-ahead revision applies speculatively"),
        TenantDirectoryRefreshOutcome::Applied { revision: 3 }
    );
    assert_eq!(
        fixture
            .registry
            .resolve("tenant-a.example")
            .expect("cached tenant A is routable")
            .binding,
        cached_a
    );

    assert_eq!(
        fixture
            .refresher
            .reconcile_database_once()
            .await
            .expect("database rolls back cache-ahead revision"),
        TenantDirectoryRefreshOutcome::Applied { revision: 1 }
    );
    assert_eq!(fixture.registry.revision(), 1);
    assert_eq!(
        fixture
            .registry
            .resolve("tenant-a.example")
            .expect("authoritative tenant A is restored")
            .binding,
        authoritative_a
    );
    assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
    let builds_after_rollback = fixture.builder.build_count();

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("rejected cache revision is ignored"),
        TenantDirectoryRefreshOutcome::Unchanged
    );
    assert_eq!(fixture.registry.revision(), 1);
    assert_eq!(fixture.builder.build_count(), builds_after_rollback);
    assert_eq!(fixture.cache.load_count(), 2);
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
}

async fn assert_cache_failure_falls_back_to_database(cache_reply: CacheReply) {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let authoritative = snapshot(2, vec![tenant_a.clone(), tenant_b]);
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a]),
        [cache_reply],
        2,
        [authoritative.clone()],
    )
    .await;

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("database fallback applies"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    assert_eq!(fixture.registry.revision(), 2);
    assert!(fixture.registry.resolve("tenant-b.example").is_some());
    assert_eq!(fixture.cache.load_count(), 1);
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
    assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
}

#[tokio::test]
async fn cache_miss_falls_back_to_database_and_repairs_cache() {
    assert_cache_failure_falls_back_to_database(CacheReply::Miss).await;
}

#[tokio::test]
async fn corrupt_cache_falls_back_to_database_and_repairs_cache() {
    assert_cache_failure_falls_back_to_database(CacheReply::Error(
        TransientStateError::CorruptData,
    ))
    .await;
}

#[tokio::test]
async fn invalid_cache_snapshot_repairs_from_database_and_quarantines_revision() {
    let authoritative_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let invalid_a = binding(1, "Tenant-A.example", "https://tenant-a.example");
    let invalid_revision = snapshot(2, vec![invalid_a]);
    let authoritative = snapshot(1, vec![authoritative_a.clone()]);
    let fixture = Fixture::new(
        authoritative.clone(),
        [
            CacheReply::Snapshot(invalid_revision.clone()),
            CacheReply::Snapshot(invalid_revision),
        ],
        1,
        [authoritative.clone()],
    )
    .await;

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("invalid cache snapshot falls back to database"),
        TenantDirectoryRefreshOutcome::Applied { revision: 1 }
    );
    assert_eq!(fixture.registry.revision(), 1);
    assert_eq!(
        fixture
            .registry
            .resolve("tenant-a.example")
            .expect("authoritative tenant A remains routable")
            .binding,
        authoritative_a
    );
    assert_eq!(fixture.cache.stored().last(), Some(&authoritative));
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
    let builds_after_repair = fixture.builder.build_count();

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("quarantined cache revision is ignored"),
        TenantDirectoryRefreshOutcome::Unchanged
    );
    assert_eq!(fixture.registry.revision(), 1);
    assert_eq!(fixture.builder.build_count(), builds_after_repair);
    assert_eq!(fixture.cache.load_count(), 2);
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
}

#[tokio::test]
async fn database_reconciliation_reads_snapshot_only_for_newer_revision() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let fixture = Fixture::new(snapshot(1, vec![tenant_a.clone()]), [], 1, []).await;

    assert_eq!(
        fixture
            .refresher
            .reconcile_database_once()
            .await
            .expect("equal database revision is handled"),
        TenantDirectoryRefreshOutcome::Unchanged
    );
    assert_eq!(fixture.directory.revision_read_count(), 1);
    assert_eq!(fixture.directory.snapshot_read_count(), 0);

    fixture.directory.set_revision(2);
    fixture
        .directory
        .push_snapshot(snapshot(2, vec![tenant_a, tenant_b]));
    assert_eq!(
        fixture
            .refresher
            .reconcile_database_once()
            .await
            .expect("new database revision applies"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    assert_eq!(fixture.directory.revision_read_count(), 2);
    assert_eq!(fixture.directory.snapshot_read_count(), 1);
    assert_eq!(fixture.registry.revision(), 2);
    assert!(fixture.registry.resolve("tenant-b.example").is_some());
    assert_eq!(
        fixture
            .cache
            .stored()
            .last()
            .expect("new authoritative snapshot is cached")
            .revision,
        2
    );
}

#[tokio::test]
async fn candidate_build_failure_retains_last_good_snapshot() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a.clone()]),
        [CacheReply::Snapshot(snapshot(2, vec![tenant_a, tenant_b]))],
        2,
        [],
    )
    .await;
    let original = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("tenant A was installed");
    fixture.builder.fail_for("tenant-b.example");

    let error = fixture
        .refresher
        .refresh_cache_once()
        .await
        .expect_err("scripted candidate build must fail");
    assert!(error.to_string().contains("scripted build failure"));

    assert_eq!(fixture.registry.revision(), 1);
    assert!(Arc::ptr_eq(
        &original,
        &fixture
            .registry
            .resolve("tenant-a.example")
            .expect("last-good tenant A remains")
    ));
    assert!(fixture.registry.resolve("tenant-b.example").is_none());
    assert_eq!(fixture.builder.build_count(), 2);
    assert_eq!(fixture.directory.revision_read_count(), 0);
    assert_eq!(fixture.directory.snapshot_read_count(), 0);
}

#[tokio::test]
async fn in_flight_request_arc_keeps_old_runtime_after_atomic_update() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let changed_a = binding(1, "tenant-a.example", "https://tenant-a.example/v2");
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a.clone()]),
        [CacheReply::Snapshot(snapshot(2, vec![changed_a.clone()]))],
        2,
        [],
    )
    .await;
    let in_flight = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("tenant A was installed");

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("updated tenant A applies"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    let next_request = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("updated tenant A is routable");

    assert!(!Arc::ptr_eq(&in_flight, &next_request));
    assert_eq!(fixture.builder.build_with_previous_count(), 1);
    assert!(next_request.shares_lifecycle_with(&in_flight));
    assert_eq!(in_flight.binding, tenant_a);
    assert_eq!(next_request.binding, changed_a);
}

#[tokio::test]
async fn disable_removes_tenant_only_from_new_requests() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let fixture = Fixture::new(
        snapshot(1, vec![tenant_a.clone(), tenant_b.clone()]),
        [CacheReply::Snapshot(snapshot(2, vec![tenant_b]))],
        2,
        [],
    )
    .await;
    let in_flight_a = fixture
        .registry
        .resolve("tenant-a.example")
        .expect("tenant A was installed");
    let original_b = fixture
        .registry
        .resolve("tenant-b.example")
        .expect("tenant B was installed");

    assert_eq!(
        fixture
            .refresher
            .refresh_cache_once()
            .await
            .expect("disabled tenant is removed"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );

    assert!(fixture.registry.resolve("tenant-a.example").is_none());
    assert_eq!(in_flight_a.binding, tenant_a);
    assert!(Arc::ptr_eq(
        &original_b,
        &fixture
            .registry
            .resolve("tenant-b.example")
            .expect("unchanged tenant B keeps its runtime")
    ));
}

#[tokio::test]
async fn two_instances_converge_on_new_cache_revision_and_reject_stale_replay() {
    let tenant_a = binding(1, "tenant-a.example", "https://tenant-a.example");
    let tenant_b = binding(2, "tenant-b.example", "https://tenant-b.example");
    let revision_two = snapshot(2, vec![tenant_a.clone(), tenant_b]);
    let shared_cache = Arc::new(RecordingCache::new([
        CacheReply::Snapshot(revision_two.clone()),
        CacheReply::Snapshot(revision_two),
        CacheReply::Snapshot(snapshot(1, vec![tenant_a.clone()])),
        CacheReply::Snapshot(snapshot(1, vec![tenant_a.clone()])),
    ]));
    let shared_directory = Arc::new(RecordingDirectory::new(2, []));

    let registry_one = TenantRuntimeRegistry::empty();
    let builder_one = Arc::new(RecordingBuilder::new());
    let refresher_one = TenantRuntimeRefresher::new(
        registry_one.clone(),
        shared_directory.clone(),
        shared_cache.clone(),
        TenantRuntimeBuilder::new(builder_one),
    );
    refresher_one
        .install_initial(snapshot(1, vec![tenant_a.clone()]))
        .await
        .expect("instance one installs revision one");

    let registry_two = TenantRuntimeRegistry::empty();
    let builder_two = Arc::new(RecordingBuilder::new());
    let refresher_two = TenantRuntimeRefresher::new(
        registry_two.clone(),
        shared_directory.clone(),
        shared_cache.clone(),
        TenantRuntimeBuilder::new(builder_two),
    );
    refresher_two
        .install_initial(snapshot(1, vec![tenant_a]))
        .await
        .expect("instance two installs revision one");

    assert_eq!(
        refresher_one
            .refresh_cache_once()
            .await
            .expect("instance one reads revision two"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    assert_eq!(
        refresher_two
            .refresh_cache_once()
            .await
            .expect("instance two reads revision two"),
        TenantDirectoryRefreshOutcome::Applied { revision: 2 }
    );
    assert_eq!(registry_one.revision(), 2);
    assert_eq!(registry_two.revision(), 2);
    assert!(registry_one.resolve("tenant-b.example").is_some());
    assert!(registry_two.resolve("tenant-b.example").is_some());

    assert_eq!(
        refresher_one
            .refresh_cache_once()
            .await
            .expect("instance one rejects stale replay"),
        TenantDirectoryRefreshOutcome::Unchanged
    );
    assert_eq!(
        refresher_two
            .refresh_cache_once()
            .await
            .expect("instance two rejects stale replay"),
        TenantDirectoryRefreshOutcome::Unchanged
    );
    assert_eq!(shared_directory.revision_read_count(), 0);
    assert_eq!(shared_directory.snapshot_read_count(), 0);
}
