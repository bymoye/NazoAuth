//! Database-backed invariant pins for the controller registry (D01/D02) and
//! identity approvals (D05).  Every test runs in an isolated schema; without
//! `NAZO_TEST_DATABASE_URL` (or `DATABASE_URL`) they skip so the suite stays
//! hermetic.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};
use nazo_postgres::{
    CONTROLLER_KEY_TTL_SECONDS, CommitWithApprovalError, ControllerIdentityAction,
    ControllerRegistryError, ControllerRegistryRepository, ControllerSlotStatus,
    IDENTITY_APPROVAL_TTL_SECONDS, NewControllerSlot, RotateControllerKey, create_pool,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

mod support;

use support::{run_isolated_application_migrations, schema_database_url};

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI controller registry tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn kid_of(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

fn slot_input(deployment: &str, label: &str, key_seed: u8) -> NewControllerSlot {
    let public_key = [key_seed; 32];
    NewControllerSlot {
        deployment_id: deployment.to_owned(),
        label: label.to_owned(),
        kid: kid_of(&public_key),
        public_key,
    }
}

fn rotation_input(deployment: &str, controller_id: &str, key_seed: u8) -> RotateControllerKey {
    let public_key = [key_seed; 32];
    RotateControllerKey {
        deployment_id: deployment.to_owned(),
        controller_id: controller_id.to_owned(),
        label: "rotated".to_owned(),
        kid: kid_of(&public_key),
        public_key,
    }
}

async fn isolated_repository(case: &str) -> Option<(String, ControllerRegistryRepository)> {
    let database_url = database_url()?;
    let schema = format!("controller_registry_{}_{}", case, Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .expect("isolated schema should create");
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    Some((
        isolated_url.clone(),
        ControllerRegistryRepository::new(
            create_pool(isolated_url, 8).expect("pool should create"),
        ),
    ))
}

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_is_exactly_thirty_days_and_admission_fails_at_the_boundary() {
    let Some((_url, repository)) = isolated_repository("ttl").await else {
        return;
    };
    let deployment = "deployment-ttl";
    let now = at(0);
    let slot = repository
        .create_slot(slot_input(deployment, "primary", 1), now)
        .await
        .expect("first slot should enroll");

    // Fixed TTL is exact server-side math; no natural months, no drift.
    assert_eq!(
        (slot.expires_at - slot.issued_at).num_seconds(),
        CONTROLLER_KEY_TTL_SECONDS
    );
    assert_eq!(slot.status, ControllerSlotStatus::Active);

    // One second before expiry the key admits.
    let admitted_before = repository
        .admitted_controller_by_kid(
            deployment,
            &slot.kid,
            slot.expires_at - Duration::seconds(1),
        )
        .await
        .expect("admission lookup should succeed");
    assert!(admitted_before.is_some());

    // At exactly expires_at admission fails; nothing about storage changed.
    let admitted_at_boundary = repository
        .admitted_controller_by_kid(deployment, &slot.kid, slot.expires_at)
        .await
        .expect("admission lookup should succeed");
    assert!(admitted_at_boundary.is_none());

    let list_after_expiry = repository
        .admitted_controllers(deployment, slot.expires_at)
        .await
        .expect("admission listing should succeed");
    assert!(list_after_expiry.is_empty());

    // The row itself remains active-but-expired until a human rotates or
    // revokes it; expiry never deletes authority records.
    let stored = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].status, ControllerSlotStatus::Active);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fourth_add_is_refused_in_transaction_with_non_secret_summaries() {
    let Some((_url, repository)) = isolated_repository("limit").await else {
        return;
    };
    let deployment = "deployment-limit";
    let now = at(0);
    for seed in 1..=3u8 {
        repository
            .create_slot(slot_input(deployment, &format!("slot-{seed}"), seed), now)
            .await
            .unwrap_or_else(|error| panic!("slot {seed} should enroll: {error}"));
    }

    let fourth = repository
        .create_slot(slot_input(deployment, "fourth", 4), now)
        .await
        .expect_err("fourth active slot must fail");
    let ControllerRegistryError::SlotLimit(summaries) = &fourth else {
        panic!("expected CONTROLLER_SLOT_LIMIT, got {fourth}");
    };
    assert_eq!(summaries.len(), 3);
    for summary in summaries {
        // Summaries carry identifiers and times only, never key bytes.
        let rendered = format!("{summary:?}");
        assert!(!rendered.contains("public_key"));
        assert_eq!(summary.status, ControllerSlotStatus::Active);
    }

    // No partial record from the refused add.
    let slots = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(slots.len(), 3);

    // A revoked slot frees its index: three active remain the hard bound.
    repository
        .revoke_slot(deployment, &slots[0].controller_id, at(10))
        .await
        .expect("revoke should succeed");
    repository
        .create_slot(slot_input(deployment, "replacement", 5), at(11))
        .await
        .expect("replacement slot should enroll after revocation freed capacity");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_add_races_never_exceed_three_active_slots() {
    let Some((url, _repository)) = isolated_repository("race").await else {
        return;
    };
    let deployment = "deployment-race";
    let pool = create_pool(url, 16).expect("race pool should create");
    let repository = ControllerRegistryRepository::new(pool);

    let mut tasks = tokio::task::JoinSet::new();
    for seed in 0..8u8 {
        let repository = repository.clone();
        let deployment = deployment.to_owned();
        tasks.spawn(async move {
            let input = NewControllerSlot {
                deployment_id: deployment,
                label: format!("racer-{seed}"),
                kid: kid_of(&[seed.wrapping_add(1); 32]),
                public_key: [seed.wrapping_add(1); 32],
            };
            (seed, repository.create_slot(input, at(0)).await)
        });
    }
    let mut created = 0usize;
    let mut limits = 0usize;
    while let Some(joined) = tasks.join_next().await {
        let (_, outcome) = joined.expect("racer task should not panic");
        match outcome {
            Ok(_) => created += 1,
            Err(ControllerRegistryError::SlotLimit(_)) => limits += 1,
            Err(error) => panic!("unexpected registry error: {error}"),
        }
    }
    assert_eq!(created, 3, "exactly three racers may win slots");
    assert_eq!(limits, 5, "every loser must observe CONTROLLER_SLOT_LIMIT");
    let slots = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(
        slots
            .iter()
            .filter(|s| s.status == ControllerSlotStatus::Active)
            .count(),
        3
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_is_terminal_and_rotation_cannot_resurrect() {
    let Some((_url, repository)) = isolated_repository("revoke").await else {
        return;
    };
    let deployment = "deployment-revoke";
    let now = at(0);
    let slot = repository
        .create_slot(slot_input(deployment, "primary", 1), now)
        .await
        .expect("slot should enroll");

    let revoked = repository
        .revoke_slot(deployment, &slot.controller_id, at(5))
        .await
        .expect("revoke should succeed");
    assert_eq!(revoked.status, ControllerSlotStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(at(5)));

    // Revoked keys stop admitting immediately.
    let admitted = repository
        .admitted_controller_by_kid(deployment, &slot.kid, at(6))
        .await
        .expect("admission lookup should succeed");
    assert!(admitted.is_none());

    // Rotation of a revoked slot is impossible.
    let rotate_revoked = repository
        .rotate_slot(rotation_input(deployment, &slot.controller_id, 2), at(7))
        .await
        .expect_err("rotating a revoked slot must fail");
    assert!(matches!(
        rotate_revoked,
        ControllerRegistryError::AlreadyRevoked
    ));

    // A second revoke refuses instead of silently succeeding.
    let second_revoke = repository
        .revoke_slot(deployment, &slot.controller_id, at(8))
        .await
        .expect_err("double revoke must be an explicit error");
    assert!(matches!(
        second_revoke,
        ControllerRegistryError::AlreadyRevoked
    ));

    // The terminal state survives every refusal unchanged.
    let stored = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(stored[0].status, ControllerSlotStatus::Revoked);
    assert_eq!(stored[0].revoked_at, Some(at(5)));
    assert_eq!(stored[0].kid, slot.kid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_keeps_count_and_identity_while_replacing_material() {
    let Some((_url, repository)) = isolated_repository("rotate").await else {
        return;
    };
    let deployment = "deployment-rotate";
    let now = at(0);
    let first = repository
        .create_slot(slot_input(deployment, "primary", 1), now)
        .await
        .expect("slot should enroll");
    repository
        .create_slot(slot_input(deployment, "second", 2), now)
        .await
        .expect("second slot should enroll");

    let rotated = repository
        .rotate_slot(rotation_input(deployment, &first.controller_id, 9), at(100))
        .await
        .expect("rotation should succeed");
    assert_eq!(rotated.controller_id, first.controller_id);
    assert_eq!(rotated.kid, kid_of(&[9u8; 32]));
    assert_eq!(rotated.issued_at, at(100));
    assert_eq!(
        (rotated.expires_at - rotated.issued_at).num_seconds(),
        CONTROLLER_KEY_TTL_SECONDS
    );
    assert_eq!(rotated.slot_index, first.slot_index);

    let slots = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(slots.len(), 2, "rotation must not change the slot count");
    // Old material no longer admits; new material does.
    assert!(
        repository
            .admitted_controller_by_kid(deployment, &first.kid, at(101))
            .await
            .expect("lookup should succeed")
            .is_none()
    );
    assert!(
        repository
            .admitted_controller_by_kid(deployment, &rotated.kid, at(101))
            .await
            .expect("lookup should succeed")
            .is_some()
    );

    // Duplicate kid across controllers is refused.
    let duplicate = repository
        .rotate_slot(
            rotation_input(deployment, &slots[1].controller_id, 9),
            at(102),
        )
        .await
        .expect_err("duplicate kid must be refused");
    assert!(matches!(duplicate, ControllerRegistryError::DuplicateKid));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crud_negatives_are_typed_and_leave_no_partial_state() {
    let Some((_url, repository)) = isolated_repository("negatives").await else {
        return;
    };
    let deployment = "deployment-neg";

    // Unknown controller on every exact-id path.
    let ghost = Uuid::now_v7().to_string();
    for outcome in [
        repository
            .revoke_slot(deployment, &ghost, at(0))
            .await
            .err(),
        repository
            .rotate_slot(rotation_input(deployment, &ghost, 3), at(0))
            .await
            .err(),
    ] {
        assert!(matches!(
            outcome,
            Some(ControllerRegistryError::UnknownController)
        ));
    }

    // Malformed shapes are rejected before any SQL runs.
    let bad_deployment = slot_input("bad deployment id!", "primary", 1);
    let error = repository
        .create_slot(bad_deployment, at(0))
        .await
        .expect_err("malformed deployment_id must fail");
    assert!(matches!(error, ControllerRegistryError::InvalidIdentity(_)));

    let good = slot_input(deployment, "primary", 1);
    let mismatched_kid = NewControllerSlot {
        kid: kid_of(&[42u8; 32]),
        ..good
    };
    let error = repository
        .create_slot(mismatched_kid, at(0))
        .await
        .expect_err("kid/key binding mismatch must fail");
    assert!(matches!(error, ControllerRegistryError::InvalidIdentity(_)));

    let empty = repository
        .list_slots(deployment)
        .await
        .expect("empty listing should succeed");
    assert!(empty.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approvals_are_single_use_bound_to_action_hash_and_expire() {
    let Some((_url, repository)) = isolated_repository("approval").await else {
        return;
    };
    let deployment = "deployment-approve";
    let admin = Uuid::now_v7();
    let action_sha256 = "a".repeat(64);

    let issued = repository
        .issue_identity_approval(
            deployment,
            ControllerIdentityAction::Bind,
            &action_sha256,
            admin,
            at(0),
        )
        .await
        .expect("issuance should succeed");
    assert_eq!(
        issued.token.len(),
        43,
        "base64url of 32 bytes is 43 characters"
    );
    assert_eq!(issued.action, ControllerIdentityAction::Bind);
    let expected_expiry = at(0) + Duration::seconds(IDENTITY_APPROVAL_TTL_SECONDS);
    assert_eq!(issued.expires_at, expected_expiry);

    // Wrong action digest cannot consume.
    let wrong_digest = repository
        .commit_slot_creation(
            &issued.token,
            ControllerIdentityAction::Bind,
            &"b".repeat(64),
            slot_input(deployment, "bind-target", 1),
            at(1),
        )
        .await
        .expect_err("digest mismatch must refuse commit");
    assert!(matches!(
        wrong_digest,
        CommitWithApprovalError::Approval(nazo_postgres::IdentityApprovalError::ActionMismatch)
    ));

    // Wrong action kind cannot consume.
    let wrong_action = repository
        .commit_slot_creation(
            &issued.token,
            ControllerIdentityAction::Add,
            &action_sha256,
            slot_input(deployment, "add-target", 1),
            at(2),
        )
        .await
        .expect_err("action mismatch must refuse commit");
    assert!(matches!(
        wrong_action,
        CommitWithApprovalError::Approval(nazo_postgres::IdentityApprovalError::ActionMismatch)
    ));

    // First correct commit consumes and enrolls atomically.
    let committed = repository
        .commit_slot_creation(
            &issued.token,
            ControllerIdentityAction::Bind,
            &action_sha256,
            slot_input(deployment, "bind-target", 1),
            at(3),
        )
        .await
        .expect("atomic commit should succeed");
    assert_eq!(committed.label, "bind-target");

    // Replay fails and enrolls nothing further.
    let replay = repository
        .commit_slot_creation(
            &issued.token,
            ControllerIdentityAction::Bind,
            &action_sha256,
            slot_input(deployment, "bind-target", 1),
            at(4),
        )
        .await
        .expect_err("replay must fail");
    assert!(matches!(
        replay,
        CommitWithApprovalError::Approval(nazo_postgres::IdentityApprovalError::Replayed)
    ));
    let slots = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(slots.len(), 1);

    // Unknown tokens fail closed.
    let unknown = repository
        .commit_slot_creation(
            &URL_SAFE_NO_PAD.encode([0u8; 32]),
            ControllerIdentityAction::Add,
            &action_sha256,
            slot_input(deployment, "unknown", 6),
            at(5),
        )
        .await
        .expect_err("unknown token must fail");
    assert!(matches!(
        unknown,
        CommitWithApprovalError::Approval(nazo_postgres::IdentityApprovalError::UnknownToken)
    ));

    // Expiry: an unconsumed approval past its fixed window cannot commit.
    let stale = repository
        .issue_identity_approval(
            deployment,
            ControllerIdentityAction::Add,
            &"c".repeat(64),
            admin,
            at(0),
        )
        .await
        .expect("issuance should succeed");
    let expired_commit = repository
        .commit_slot_creation(
            &stale.token,
            ControllerIdentityAction::Add,
            &"c".repeat(64),
            slot_input(deployment, "late", 7),
            expected_expiry,
        )
        .await
        .expect_err("expired approval must refuse commit");
    assert!(matches!(
        expired_commit,
        CommitWithApprovalError::Approval(nazo_postgres::IdentityApprovalError::Expired)
    ));

    // Concurrent double-consumption race: the token is offered twice with two
    // different payloads; exactly one racer may commit, the loser must observe
    // a typed replay rejection, and exactly one slot exists afterwards.
    let racing = repository
        .issue_identity_approval(
            deployment,
            ControllerIdentityAction::Add,
            &"d".repeat(64),
            admin,
            at(20),
        )
        .await
        .expect("issuance should succeed");
    let pool_repository = repository.clone();
    let deployment_clone = deployment.to_owned();
    let token_a = racing.token.clone();
    let token_b = racing.token;
    let digest_a = "d".repeat(64);
    let digest_b = "d".repeat(64);
    let first = tokio::spawn(async move {
        pool_repository
            .commit_slot_creation(
                &token_a,
                ControllerIdentityAction::Add,
                &digest_a,
                slot_input(&deployment_clone, "race-a", 21),
                at(21),
            )
            .await
    });
    let second_outcome = repository
        .commit_slot_creation(
            &token_b,
            ControllerIdentityAction::Add,
            &digest_b,
            slot_input(deployment, "race-b", 22),
            at(21),
        )
        .await;
    let first_outcome = first.await.expect("racing task should not panic");
    let wins = [&first_outcome, &second_outcome]
        .into_iter()
        .filter(|outcome| outcome.is_ok())
        .count();
    let replays = [&first_outcome, &second_outcome]
        .into_iter()
        .filter_map(|outcome| outcome.as_ref().err())
        .filter(|error| {
            matches!(
                error,
                CommitWithApprovalError::Approval(nazo_postgres::IdentityApprovalError::Replayed)
            )
        })
        .count();
    assert_eq!(wins, 1, "exactly one racer may win the single-use approval");
    assert_eq!(replays, 1, "the loser must see a typed replay rejection");
    let slots = repository
        .list_slots(deployment)
        .await
        .expect("listing should succeed");
    assert_eq!(
        slots
            .iter()
            .filter(|slot| slot.label.starts_with("race-"))
            .count(),
        1,
        "the winning commit enrolls exactly one slot"
    );
}
