//! Database-backed invariant pins for the Recovery Root plane (04A D10/D11/D12).
//! Every test runs in an isolated schema; without `NAZO_TEST_DATABASE_URL`
//! (or `DATABASE_URL`) they skip so the suite stays hermetic.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};
use ed25519_dalek::{Signer as _, SigningKey};
use nazo_operator_protocol::{
    RECOVERY_KDF_ID, RecoveryProposal, RecoveryRootRotation, derive_recovery_seed,
    format_recovery_secret, parse_recovery_secret, recovery_kid, validate_controller_id,
};
use nazo_postgres::{
    CONTROLLER_KEY_TTL_SECONDS, ControllerRegistryError, ControllerRegistryRepository,
    ControllerSlotStatus, IdentityApprovalError, IssuedIdentityApproval,
    MAX_RECOVERY_CHALLENGE_ATTEMPTS, NewControllerSlot, NewRecoveryChallenge, NewRecoveryRoot,
    RECOVERY_CHALLENGE_TTL_SECONDS, RecoveredSlotCommit, RecoveryRootError, RecoveryRootRepository,
    RecoveryRotationError, RecoverySubmission, create_pool,
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
        panic!("CI recovery tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

async fn isolated(case: &str) -> Option<(String, RecoveryRootRepository)> {
    let database_url = database_url()?;
    let schema = format!("controller_recovery_{}_{}", case, Uuid::now_v7().simple());
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
        RecoveryRootRepository::new(create_pool(isolated_url, 8).expect("pool should create")),
    ))
}

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn kid_of(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

/// Stand-in for the control side: one generation's offline recovery material.
/// The secret is produced through the mandated display form and parsed back,
/// so the fixture exercises the exact transcription contract (04A §2).
struct RecoveryMaterial {
    display_secret: String,
    seed: [u8; 32],
    public_key: [u8; 32],
}

fn recovery_material(deployment: &str, generation: u8) -> RecoveryMaterial {
    let display_secret = format_recovery_secret(&[generation; 32]);
    let secret = parse_recovery_secret(&display_secret).expect("display form must parse");
    let seed = derive_recovery_seed(&secret, deployment);
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    RecoveryMaterial {
        display_secret,
        seed,
        public_key,
    }
}

impl RecoveryMaterial {
    fn rotation(&self, deployment: &str) -> RecoveryRootRotation {
        RecoveryRootRotation {
            deployment_id: deployment.to_owned(),
            kid: kid_of(&self.public_key),
            public_key: self.public_key,
        }
    }

    fn root_input(&self, deployment: &str) -> NewRecoveryRoot {
        NewRecoveryRoot {
            deployment_id: deployment.to_owned(),
            kid: kid_of(&self.public_key),
            public_key: self.public_key,
        }
    }

    fn sign(&self, proposal: &RecoveryProposal, challenge_id: Uuid, nonce: &[u8; 32]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed)
            .sign(&proposal.challenge_message(&challenge_id.to_string(), nonce))
            .to_bytes()
    }
}

fn controller_key_for_slot(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// The proposed replacement state of one recovery: a fresh controller key and
/// the next generation's Recovery Public Key.
fn challenge_input(
    deployment: &str,
    controller_seed: u8,
    next: &RecoveryMaterial,
) -> NewRecoveryChallenge {
    NewRecoveryChallenge {
        deployment_id: deployment.to_owned(),
        controller_label: "recovered-primary".to_owned(),
        controller_kid: kid_of(&controller_key_for_slot(controller_seed)),
        controller_public_key: controller_key_for_slot(controller_seed),
        recovery_kid: recovery_kid(&next.public_key),
        recovery_public_key: next.public_key,
    }
}

fn proposal_from(challenge: &NewRecoveryChallenge) -> RecoveryProposal {
    RecoveryProposal {
        deployment_id: challenge.deployment_id.clone(),
        controller_label: challenge.controller_label.clone(),
        controller_kid: challenge.controller_kid.clone(),
        controller_public_key: challenge.controller_public_key,
        recovery_kid: challenge.recovery_kid.clone(),
        recovery_public_key: challenge.recovery_public_key,
    }
}

fn submission(
    deployment: &str,
    challenge_id: Uuid,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> RecoverySubmission {
    RecoverySubmission {
        deployment_id: deployment.to_owned(),
        challenge_id,
        nonce: *nonce,
        signature: *signature,
    }
}

/// Enroll a root through the D12 approval path — the only way roots exist.
async fn enroll_root(
    repository: &RecoveryRootRepository,
    deployment: &str,
    material: &RecoveryMaterial,
    now: DateTime<Utc>,
) -> IssuedIdentityApproval {
    let rotation = material.rotation(deployment);
    let issued = repository
        .issue_rotation_approval(deployment, &rotation.action_sha256(), Uuid::now_v7(), now)
        .await
        .expect("approval issuance should succeed");
    repository
        .commit_rotation(
            &issued.token,
            deployment,
            &rotation.action_sha256(),
            material.root_input(deployment),
            now,
        )
        .await
        .expect("root enrollment should succeed in fixtures");
    issued
}

async fn registry_repository(url: &str) -> ControllerRegistryRepository {
    ControllerRegistryRepository::new(create_pool(url.to_owned(), 8).expect("pool should create"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_needs_unconsumed_fresh_approval_and_bumps_exactly_one_generation() {
    let Some((_url, repository)) = isolated("rotate").await else {
        return;
    };
    let deployment = "deployment-recovery-rotate";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);

    assert!(
        repository
            .current_root(deployment)
            .await
            .expect("read should succeed")
            .is_none()
    );

    // Enrollment through the approved path lands at generation 1 with the
    // pinned KDF id stored alongside the key (D10).
    enroll_root(&repository, deployment, &first, at(0)).await;
    let root = repository
        .current_root(deployment)
        .await
        .expect("read should succeed")
        .expect("root should exist after enrollment");
    assert_eq!(root.generation, 1);
    assert_eq!(root.kdf, RECOVERY_KDF_ID);
    assert_eq!(root.recovery_kid, kid_of(&first.public_key));
    // Neither the stored row nor its summary view carries any secret marker.
    let summary_rendered = format!("{:?}", root.summary());
    let rendered = format!("{root:?} {summary_rendered}");
    assert!(!rendered.contains("NAZO-RECOVERY-"));
    assert!(!rendered.contains(&first.display_secret));

    // An unknown token cannot commit.
    let unknown = repository
        .commit_rotation(
            "unused",
            deployment,
            &"a".repeat(64),
            second.root_input(deployment),
            at(1),
        )
        .await
        .expect_err("unknown token must fail");
    assert!(matches!(
        unknown,
        RecoveryRotationError::Approval(IdentityApprovalError::UnknownToken)
    ));

    // Approved rotation bumps exactly one generation and replaces material.
    let rotation = second.rotation(deployment);
    let issued = repository
        .issue_rotation_approval(deployment, &rotation.action_sha256(), Uuid::now_v7(), at(2))
        .await
        .expect("issuance should succeed");
    let rotated = repository
        .commit_rotation(
            &issued.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(3),
        )
        .await
        .expect("approved rotation should commit");
    assert_eq!(rotated.generation, 2);
    assert_eq!(rotated.recovery_kid, kid_of(&second.public_key));

    // Replay of the consumed token fails and changes nothing.
    let replay = repository
        .commit_rotation(
            &issued.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(4),
        )
        .await
        .expect_err("replay must fail");
    assert!(matches!(
        replay,
        RecoveryRotationError::Approval(IdentityApprovalError::Replayed)
    ));
    assert_eq!(
        repository
            .current_root(deployment)
            .await
            .expect("read should succeed")
            .expect("root remains")
            .generation,
        2
    );

    // An unconsumed but expired approval cannot commit either.
    let stale_rotation = first.rotation(deployment);
    let stale = repository
        .issue_rotation_approval(
            deployment,
            &stale_rotation.action_sha256(),
            Uuid::now_v7(),
            at(5),
        )
        .await
        .expect("issuance should succeed");
    let expired = repository
        .commit_rotation(
            &stale.token,
            deployment,
            &stale_rotation.action_sha256(),
            first.root_input(deployment),
            at(5) + Duration::seconds(RECOVERY_CHALLENGE_TTL_SECONDS + 60),
        )
        .await
        .expect_err("expired approval must fail");
    assert!(matches!(
        expired,
        RecoveryRotationError::Approval(IdentityApprovalError::Expired)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenges_are_refused_while_any_controller_is_admitted_and_single_pending() {
    let Some((_url, repository)) = isolated("gate").await else {
        return;
    };
    let deployment = "deployment-recovery-gate";
    enroll_root(
        &repository,
        deployment,
        &recovery_material(deployment, 1),
        at(0),
    )
    .await;
    let registry = repository.registry();
    let key = controller_key_for_slot(9);
    registry
        .create_slot(
            NewControllerSlot {
                deployment_id: deployment.to_owned(),
                label: "primary".to_owned(),
                kid: kid_of(&key),
                public_key: key,
            },
            at(0),
        )
        .await
        .expect("slot should enroll");

    // With one admitting key left the ordinary fresh-2FA identity paths are
    // available, so the break-glass challenge is refused outright.
    let refused = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 10, &recovery_material(deployment, 2)),
            at(1),
        )
        .await
        .expect_err("challenge must be refused while controllers admit");
    match refused {
        RecoveryRootError::ControllersStillAdmitted(admitted) => {
            assert_eq!(admitted.len(), 1);
            assert!(!format!("{admitted:?}").contains("public_key"));
        }
        other => panic!("unexpected error: {other}"),
    }

    // Revoke the last slot: no admitting key remains, issuance succeeds.
    for slot in registry
        .list_slots(deployment)
        .await
        .expect("listing works")
    {
        registry
            .revoke_slot(deployment, &slot.controller_id, at(2))
            .await
            .expect("revocation should succeed");
    }
    let issued = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 10, &recovery_material(deployment, 2)),
            at(3),
        )
        .await
        .expect("challenge should issue without admitting keys");
    assert_eq!(
        (issued.expires_at - at(3)).num_seconds(),
        RECOVERY_CHALLENGE_TTL_SECONDS
    );

    // At most ONE outstanding challenge per deployment.
    let pending = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 11, &recovery_material(deployment, 3)),
            at(4),
        )
        .await
        .expect_err("second pending challenge must be refused");
    assert!(matches!(pending, RecoveryRootError::ChallengePending));

    // Burn the outstanding challenge through its attempt cap; afterwards a
    // new challenge may be issued again because the dead one stops blocking.
    for attempt in 0..MAX_RECOVERY_CHALLENGE_ATTEMPTS {
        let outcome = repository
            .submit_recovery_challenge(
                submission(
                    deployment,
                    issued.challenge_id,
                    &issued.nonce,
                    &[0xffu8; 64],
                ),
                at(5 + i64::from(attempt)),
            )
            .await
            .expect_err("wrong signature must fail");
        assert!(matches!(outcome, RecoveryRootError::InvalidSignature));
    }
    let dead = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                issued.challenge_id,
                &issued.nonce,
                &[0xffu8; 64],
            ),
            at(20),
        )
        .await
        .expect_err("exhausted challenge must refuse");
    assert!(matches!(dead, RecoveryRootError::ChallengeExhausted));

    repository
        .issue_recovery_challenge(
            challenge_input(deployment, 12, &recovery_material(deployment, 4)),
            at(21),
        )
        .await
        .expect("a new challenge may issue once the old one is dead");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_recovery_revokes_everything_installs_one_slot_and_rotates_the_root() {
    let Some((url, repository)) = isolated("commit").await else {
        return;
    };
    let registry = registry_repository(&url).await;
    let deployment = "deployment-recovery-commit";
    let old_material = recovery_material(deployment, 1);
    let next_material = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &old_material, at(0)).await;

    // Two lost keys exist, then get revoked out of the admitting set.
    for seed in [1u8, 2] {
        let key = controller_key_for_slot(seed);
        let slot = registry
            .create_slot(
                NewControllerSlot {
                    deployment_id: deployment.to_owned(),
                    label: format!("lost-{seed}"),
                    kid: kid_of(&key),
                    public_key: key,
                },
                at(0),
            )
            .await
            .expect("fixture slot should enroll");
        registry
            .revoke_slot(deployment, &slot.controller_id, at(5))
            .await
            .expect("fixture revocation should succeed");
    }

    // The break-glass flow: challenge bound to the EXACT proposed material.
    let challenge = challenge_input(deployment, 9, &next_material);
    let proposal = proposal_from(&challenge);
    proposal
        .validate()
        .expect("fixture proposal is well formed");
    let issued = repository
        .issue_recovery_challenge(challenge, at(10))
        .await
        .expect("challenge should issue");
    let signature = old_material.sign(&proposal, issued.challenge_id, &issued.nonce);

    // Wrong nonce fails without consuming anything but the attempt counter.
    let mut wrong_nonce = issued.nonce;
    wrong_nonce[0] ^= 1;
    let nonce_failure = repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &wrong_nonce, &signature),
            at(11),
        )
        .await
        .expect_err("wrong nonce must fail");
    assert!(matches!(nonce_failure, RecoveryRootError::NonceMismatch));

    // The correct answer atomically commits the whole recovery.
    let commit: RecoveredSlotCommit = repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(12),
        )
        .await
        .expect("signed answer must commit");
    assert_eq!(commit.recovery_generation, 2);
    validate_controller_id(&commit.slot.controller_id)
        .expect("the recovered slot gets a freshly assigned UUIDv7 controller_id");
    assert_eq!(commit.slot.status, ControllerSlotStatus::Active);
    assert_eq!(commit.slot.label, "recovered-primary");
    assert_eq!(commit.slot.kid, kid_of(&controller_key_for_slot(9)));
    assert_eq!(commit.slot.issued_at, at(12));
    assert_eq!(
        (commit.slot.expires_at - commit.slot.issued_at).num_seconds(),
        CONTROLLER_KEY_TTL_SECONDS,
        "the recovered slot obeys the fixed 30-day expiry"
    );
    assert_eq!(
        commit.slot.slot_index, 0,
        "lowest free index after mass revocation"
    );

    // Exactly one admitting key exists; everything else stays revoked history.
    let admitted = repository
        .registry()
        .admitted_controllers(deployment, at(13))
        .await
        .expect("admission listing works");
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0].kid, commit.slot.kid);
    let slots = registry
        .list_slots(deployment)
        .await
        .expect("listing works");
    assert_eq!(slots.len(), 3);
    assert_eq!(
        slots
            .iter()
            .filter(|slot| slot.status == ControllerSlotStatus::Revoked)
            .count(),
        2
    );

    // The root was replaced in the same transaction.
    let root = repository
        .current_root(deployment)
        .await
        .expect("read works")
        .expect("root remains");
    assert_eq!(root.generation, 2);
    assert_eq!(root.recovery_kid, kid_of(&next_material.public_key));

    // The OLD secret is dead: on a fresh challenge it cannot verify anymore.
    registry
        .revoke_slot(deployment, &commit.slot.controller_id, at(20))
        .await
        .expect("fixture revocation frees the gate");
    let later = recovery_material(deployment, 3);
    let issued_second = repository
        .issue_recovery_challenge(challenge_input(deployment, 21, &later), at(21))
        .await
        .expect("new challenge should issue");
    let stale_signature = old_material.sign(
        &proposal_from(&challenge_input(deployment, 21, &later)),
        issued_second.challenge_id,
        &issued_second.nonce,
    );
    let stale_outcome = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                issued_second.challenge_id,
                &issued_second.nonce,
                &stale_signature,
            ),
            at(22),
        )
        .await
        .expect_err("old-generation secret must fail");
    assert!(matches!(stale_outcome, RecoveryRootError::InvalidSignature));

    // A recovery-derived public key never admits ordinary operations: the
    // admission lookup only answers for controller slots.
    for kid in [kid_of(&old_material.public_key), root.recovery_kid.clone()] {
        assert!(
            registry
                .admitted_controller_by_kid(deployment, &kid, at(23))
                .await
                .expect("lookup works")
                .is_none(),
            "recovery material must never appear in the admitting set"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_expiry_and_wrong_signers_fail_closed_without_partial_state() {
    let Some((_url, repository)) = isolated("failclosed").await else {
        return;
    };
    let deployment = "deployment-recovery-fail";
    let material = recovery_material(deployment, 1);
    let next = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &material, at(0)).await;

    // Expired challenge: dead by the fixed server-side window even though it
    // was never consumed.
    let expired_challenge = challenge_input(deployment, 30, &next);
    let expired_proposal = proposal_from(&expired_challenge);
    let expired_issued = repository
        .issue_recovery_challenge(expired_challenge, at(0))
        .await
        .expect("challenge issues");
    let expired_signature = material.sign(
        &expired_proposal,
        expired_issued.challenge_id,
        &expired_issued.nonce,
    );
    let outcome = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                expired_issued.challenge_id,
                &expired_issued.nonce,
                &expired_signature,
            ),
            expired_issued.expires_at,
        )
        .await
        .expect_err("expired challenge must refuse");
    assert!(matches!(outcome, RecoveryRootError::ChallengeExpired));

    // Unknown challenge ids fail closed.
    let ghost = Uuid::now_v7();
    let unknown = repository
        .submit_recovery_challenge(submission(deployment, ghost, &[0u8; 32], &[0u8; 64]), at(1))
        .await
        .expect_err("unknown challenge must fail");
    assert!(matches!(unknown, RecoveryRootError::ChallengeUnknown));

    // Live challenge: wrong signer cannot pass, the right one commits once,
    // and an identical replay afterwards is rejected as consumed.  The first
    // (lapsed) challenge stays pending until its TTL passes, so reissuing
    // starts after expiry — a live pending challenge blocks issuance.
    let live_challenge = challenge_input(deployment, 31, &next);
    let live_proposal = proposal_from(&live_challenge);
    let live_issued = repository
        .issue_recovery_challenge(live_challenge, at(601))
        .await
        .expect("challenge issues after the lapsed one expired");
    let impostor = SigningKey::from_bytes(&[0x77u8; 32]);
    let forged = impostor
        .sign(
            &live_proposal
                .challenge_message(&live_issued.challenge_id.to_string(), &live_issued.nonce),
        )
        .to_bytes();
    let forged_outcome = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &forged,
            ),
            at(602),
        )
        .await
        .expect_err("a non-recovery signer must fail");
    assert!(matches!(
        forged_outcome,
        RecoveryRootError::InvalidSignature
    ));

    let genuine = material.sign(&live_proposal, live_issued.challenge_id, &live_issued.nonce);
    let commit = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &genuine,
            ),
            at(603),
        )
        .await
        .expect("the right answer commits");
    assert_eq!(commit.slot.kid, kid_of(&controller_key_for_slot(31)));

    let replayed = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &genuine,
            ),
            at(604),
        )
        .await
        .expect_err("replay must fail");
    assert!(matches!(replayed, RecoveryRootError::ChallengeReplayed));

    // Cross-deployment submissions cannot read another deployment's challenge.
    let cross = repository
        .submit_recovery_challenge(
            submission(
                "deployment-other",
                live_issued.challenge_id,
                &live_issued.nonce,
                &genuine,
            ),
            at(14),
        )
        .await
        .expect_err("cross-deployment submission must fail");
    assert!(matches!(cross, RecoveryRootError::ChallengeUnknown));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_slots_count_toward_the_three_slot_bound() {
    let Some((_url, repository)) = isolated("bound").await else {
        return;
    };
    let deployment = "deployment-recovery-bound";
    let material = recovery_material(deployment, 1);
    let next = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &material, at(0)).await;

    let challenge = challenge_input(deployment, 40, &next);
    let proposal = proposal_from(&challenge);
    let issued = repository
        .issue_recovery_challenge(challenge, at(0))
        .await
        .expect("no admitting keys, no active slots: gate open");
    let signature = material.sign(&proposal, issued.challenge_id, &issued.nonce);
    repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(1),
        )
        .await
        .expect("recovery commits");

    let registry = repository.registry();
    // Two more ordinary slots fill the set to three...
    for seed in [41u8, 42] {
        let key = controller_key_for_slot(seed);
        registry
            .create_slot(
                NewControllerSlot {
                    deployment_id: deployment.to_owned(),
                    label: format!("extra-{seed}"),
                    kid: kid_of(&key),
                    public_key: key,
                },
                at(2),
            )
            .await
            .unwrap_or_else(|error| panic!("slot {seed} should enroll: {error}"));
    }
    // ...and the fourth add is refused exactly like any normal over-add.
    let fourth_key = controller_key_for_slot(43);
    let refused = registry
        .create_slot(
            NewControllerSlot {
                deployment_id: deployment.to_owned(),
                label: "fourth".to_owned(),
                kid: kid_of(&fourth_key),
                public_key: fourth_key,
            },
            at(3),
        )
        .await
        .expect_err("fourth active slot must be refused");
    assert!(matches!(refused, ControllerRegistryError::SlotLimit(_)));
}

/// P0-5 negative test: a recovery submission must WAIT for the shared
/// per-deployment identity lock. Before the lock unification a concurrent
/// bind could commit its active slot between the challenge's re-check and
/// the batch revoke, because recovery held a different advisory key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_submission_waits_for_the_deployment_identity_lock() {
    use nazo_postgres::DEPLOYMENT_IDENTITY_LOCK_SEED;
    use std::time::Duration as StdDuration;

    let Some((url, repository)) = isolated("lock_interleave").await else {
        return;
    };
    let deployment = "deployment-recovery-lock";
    let material = recovery_material(deployment, 1);
    let next = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &material, at(0)).await;

    // No admitting controllers exist, so break-glass issuance succeeds.
    let challenge = challenge_input(deployment, 40, &next);
    let proposal = proposal_from(&challenge);
    let issued = repository
        .issue_recovery_challenge(challenge, at(1))
        .await
        .expect("challenge issues without admitted controllers");
    let signature = material.sign(&proposal, issued.challenge_id, &issued.nonce);

    // An explicit transaction occupies the SHARED deployment identity lock —
    // exactly what any concurrent bind/rotate commit holds while it runs.
    let mut holder = AsyncPgConnection::establish(&url)
        .await
        .expect("holder connection");
    holder
        .batch_execute("BEGIN")
        .await
        .expect("holder transaction");
    holder
        .batch_execute(&format!(
            "SELECT pg_advisory_xact_lock(hashtextextended('{deployment}', \
             {DEPLOYMENT_IDENTITY_LOCK_SEED}));"
        ))
        .await
        .expect("holder takes the identity lock");

    // While the lock is held the submission cannot complete.
    let pending = repository.submit_recovery_challenge(
        submission(deployment, issued.challenge_id, &issued.nonce, &signature),
        at(2),
    );
    tokio::pin!(pending);
    let raced = tokio::time::timeout(StdDuration::from_millis(400), pending.as_mut()).await;
    assert!(
        raced.is_err(),
        "submission must block on the shared deployment identity lock"
    );

    // Releasing the holder lets the same submission finish its commit.
    holder
        .batch_execute("COMMIT")
        .await
        .expect("holder releases the lock");
    let commit = pending
        .await
        .expect("submission completes once the lock releases");
    assert_eq!(commit.slot.kid, kid_of(&controller_key_for_slot(40)));
}
