# M6 CIBA / FAPI-CIBA Completion Implementation Plan

> Historical implementation record. Repository locations must be discovered and
> validated at execution time; this document does not authorize a specific tool
> or local checkout path.

**Goal:** Complete M6 by making every CIBA lifecycle transition atomic and fail-closed, shipping the authenticated confirmation page, preserving official FAPI-CIBA compatibility, and recording a fresh successful official OIDF run for the exact deployed implementation commit.

**Architecture:** Keep Valkey as the sole live `auth_req_id` source of truth. Add generic Lua-backed snapshot and conditional-write primitives in the support layer, place the CIBA stored model and pure transition functions in a focused `ciba/state.rs` module, and let `ciba.rs` remain responsible for HTTP mapping, client-assertion consumption, token issuance, and audit commit points. Integrate the existing frontend CIBA page onto current `NazoAuthWeb/main`, then deploy and test the exact backend commit before changing roadmap completion state.

**Tech Stack:** Rust 2024, Actix Web, fred/Valkey Lua, serde/serde_json, tracing, PostgreSQL/Diesel, React 19, TypeScript 6, Vite 8, GitHub Actions, OpenID Foundation Conformance Suite.

## Global Constraints

- Backend repository: the verified NazoAuth checkout; backend branch: `codex/m6-ciba-completion` from fetched `origin/main`.
- Frontend repository: the verified sibling NazoAuthWeb checkout; frontend branch: `codex/m6-ciba-completion` from fetched `origin/main`.
- No new Rust crate, frontend package, state library, or test framework.
- `expires_at` and `retention_expires_at` are immutable absolute Unix-second timestamps calculated exactly once at request creation.
- Every successful premature poll adds exactly 5 seconds; a CAS conflict adds nothing until the reloaded transition commits.
- Conditional mutations return exactly `Applied`, `Conflict`, or `DeadlineElapsed`; only `Conflict` consumes the four-attempt retry budget.
- Client-assertion validation and replay-JTI consumption happen once, before the CAS retry loop.
- Token issuance is unreachable without `Applied` from an approved compare-delete; consumed state is never restored after downstream failure.
- Approve/deny audit events are emitted only from a committed CAS outcome. Audit delivery remains best-effort and never rolls back or repeats the state transition.
- Every Valkey transport, Lua, malformed-state, or expiry-metadata error maps to non-cacheable HTTP 503 `server_error` and stops protocol processing.
- The official `fapi-ciba-id1-plain-private-key-jwt-poll` compatibility profile and internal `fapi2-ciba` hardening profile remain distinct; no authorization-code-only PAR, PKCE, or `response_type=code` requirement is added to CIBA.
- Do not create a pull request. Push both implementation branches; push backend to both `origin` and `cnb` after verifying the remote branch SHAs agree.
- Do not mark M6 complete until the exact backend implementation commit has passed Docker gates, has been deployed to `auth.nazo.run`, and a fresh `oidf-conformance-full.yml` run has completed successfully.

---

### Task 1: Generic Valkey Snapshot and Conditional-Transition Primitives

**Files:**
- Modify: `src/support/valkey.rs`
- Create: `tests/in_source/src/support/tests/valkey.rs`

**Interfaces:**
- Consumes: existing `ValkeyClient`, `ValkeyError`, and `valkey_eval_string` support boundary.
- Produces: `ValkeySnapshot { raw: String, expire_at: i64 }`, `ValkeyAtomicResult::{Applied, Conflict, DeadlineElapsed}`, `ValkeyAtomicError`, `valkey_atomic_snapshot`, `valkey_set_nx_at_deadline`, `valkey_compare_set_at_deadline`, and `valkey_compare_delete_at_deadline`.

- [ ] **Step 1: Write failing parser and live-Valkey tests**

Create `tests/in_source/src/support/tests/valkey.rs` with a `VALKEY_URL` fixture and these exact assertions:

```rust
#[test]
fn valkey_atomic_result_parser_accepts_only_declared_states() {
    assert_eq!(parse_valkey_atomic_result("applied").unwrap(), ValkeyAtomicResult::Applied);
    assert_eq!(parse_valkey_atomic_result("conflict").unwrap(), ValkeyAtomicResult::Conflict);
    assert_eq!(parse_valkey_atomic_result("deadline_elapsed").unwrap(), ValkeyAtomicResult::DeadlineElapsed);
    assert!(parse_valkey_atomic_result("ok").is_err());
}

#[actix_web::test]
async fn valkey_atomic_primitives_compare_exact_raw_value_and_preserve_deadline() {
    let Some(valkey) = live_valkey().await else { return };
    let key = format!("test:valkey:atomic:{}", Uuid::now_v7());
    let now = valkey_server_time(&valkey).await;
    let deadline = now + 30;

    assert_eq!(valkey_set_nx_at_deadline(&valkey, &key, "v1", deadline).await.unwrap(), ValkeyAtomicResult::Applied);
    assert_eq!(valkey_set_nx_at_deadline(&valkey, &key, "other", deadline).await.unwrap(), ValkeyAtomicResult::Conflict);
    let first = valkey_atomic_snapshot(&valkey, &key).await.unwrap().unwrap();
    assert_eq!(first.raw, "v1");
    assert_eq!(first.expire_at, deadline);

    assert_eq!(valkey_compare_set_at_deadline(&valkey, &key, "wrong", "v2", deadline).await.unwrap(), ValkeyAtomicResult::Conflict);
    assert_eq!(valkey_compare_set_at_deadline(&valkey, &key, "v1", "v2", deadline).await.unwrap(), ValkeyAtomicResult::Applied);
    assert_eq!(valkey_atomic_snapshot(&valkey, &key).await.unwrap().unwrap().expire_at, deadline);
    assert_eq!(valkey_compare_delete_at_deadline(&valkey, &key, "wrong", deadline).await.unwrap(), ValkeyAtomicResult::Conflict);
    assert_eq!(valkey_compare_delete_at_deadline(&valkey, &key, "v2", deadline).await.unwrap(), ValkeyAtomicResult::Applied);
    assert!(valkey_atomic_snapshot(&valkey, &key).await.unwrap().is_none());
}

#[actix_web::test]
async fn valkey_atomic_primitives_report_deadline_elapsed_instead_of_applied() {
    let Some(valkey) = live_valkey().await else { return };
    let key = format!("test:valkey:deadline:{}", Uuid::now_v7());
    let now = valkey_server_time(&valkey).await;
    assert_eq!(valkey_set_nx_at_deadline(&valkey, &key, "new", now).await.unwrap(), ValkeyAtomicResult::DeadlineElapsed);

    valkey_set_ex(&valkey, &key, "existing", 30).await.unwrap();
    assert_eq!(valkey_compare_set_at_deadline(&valkey, &key, "existing", "replacement", now).await.unwrap(), ValkeyAtomicResult::DeadlineElapsed);
    assert!(valkey_atomic_snapshot(&valkey, &key).await.unwrap().is_none());
}
```

The fixture must build fred with one-second connection/command timeouts, call `init()`, and derive server time from `TIME`, not the Windows host clock.

- [ ] **Step 2: Run the focused test and verify the red state**

Run from the backend repository after starting the disposable Valkey container:

```powershell
rtk docker run --rm --network nazo-oauth-codecov-net -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace -v nazo-oauth-cargo-registry:/usr/local/cargo/registry -v nazo-oauth-cargo-git:/usr/local/cargo/git -v nazo-oauth-codecov-target:/docker-target -w /workspace -e VALKEY_URL=redis://nazo-oauth-codecov-valkey:6379/0 -e CARGO_TARGET_DIR=/docker-target/check -e CARGO_BUILD_JOBS=1 nazo-oauth-codecov-runner:local bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib valkey_atomic -- --nocapture'
```

Expected: compilation fails because the new types and functions do not exist.

- [ ] **Step 3: Implement the exact Lua linearization boundary**

Add the following behavior to `src/support/valkey.rs` and attach the test module with `#[path = "../../tests/in_source/src/support/tests/valkey.rs"]`:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValkeySnapshot {
    pub(crate) raw: String,
    pub(crate) expire_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValkeyAtomicResult { Applied, Conflict, DeadlineElapsed }

#[derive(Debug)]
pub(crate) enum ValkeyAtomicError {
    Command(ValkeyError),
    InvalidReply(String),
}

const SNAPSHOT_SCRIPT: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then return cjson.encode({found = false}) end
return cjson.encode({found = true, value = value, expire_at = redis.call('EXPIRETIME', KEYS[1])})
"#;

const SET_NX_AT_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then return 'deadline_elapsed' end
if redis.call('SETNX', KEYS[1], ARGV[1]) == 0 then return 'conflict' end
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then return 'deadline_elapsed' end
return 'applied'
"#;

const COMPARE_SET_AT_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[3])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then redis.call('DEL', KEYS[1]) end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('EXPIREAT', KEYS[1], deadline)
if redis.call('EXISTS', KEYS[1]) == 0 then return 'deadline_elapsed' end
return 'applied'
"#;

const COMPARE_DELETE_AT_DEADLINE_SCRIPT: &str = r#"
local deadline = tonumber(ARGV[2])
local now = tonumber(redis.call('TIME')[1])
if now >= deadline then
  local expired = redis.call('GET', KEYS[1])
  if expired and expired == ARGV[1] then redis.call('DEL', KEYS[1]) end
  return 'deadline_elapsed'
end
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
redis.call('DEL', KEYS[1])
return 'applied'
"#;
```

`valkey_atomic_snapshot` parses the script JSON into `Option<ValkeySnapshot>`. The three mutation wrappers pass decimal deadline strings, call `parse_valkey_atomic_result`, and never translate an unknown script reply into success. Implement `Display`, `Error`, and `From<ValkeyError>` for `ValkeyAtomicError` without logging key values.

- [ ] **Step 4: Run the focused test and verify green**

Run the command from Step 2. Expected: all `valkey_atomic_*` tests pass.

- [ ] **Step 5: Commit**

```powershell
rtk git add src/support/valkey.rs tests/in_source/src/support/tests/valkey.rs
rtk git commit -m "feat: add atomic Valkey transition primitives"
```

### Task 2: Immutable CIBA State Model and Pure Transitions

**Files:**
- Create: `src/http/token/ciba/state.rs`
- Create: `tests/in_source/src/http/token/tests/ciba_state.rs`
- Modify: `src/http/token/ciba.rs`

**Interfaces:**
- Consumes: Task 1 `ValkeySnapshot` and atomic mutation functions.
- Produces: `CibaRequestState`, `CibaStatus`, `StoredCibaRequest`, `CibaPollTransition`, `CibaDecision`, `CibaDecisionEvaluation`, `load_ciba_request_state`, `create_ciba_request_state`, `replace_ciba_request_state`, `delete_ciba_request_state`, `evaluate_ciba_poll`, `evaluate_ciba_decision`, `ciba_retention_deadline`, and `ciba_request_key`.

- [ ] **Step 1: Write pure-transition and stored-deadline tests**

Create `tests/in_source/src/http/token/tests/ciba_state.rs`. Use a `pending_state(now)` fixture containing `expires_at = now + 60` and `retention_expires_at = now + 180`. Assert these exact cases:

```rust
#[test]
fn ciba_poll_transition_preserves_absolute_deadlines() {
    let state = pending_state(1_000);
    let CibaPollTransition::AuthorizationPending(next) = evaluate_ciba_poll(&state, 1_001) else { panic!() };
    assert_eq!(next.expires_at, state.expires_at);
    assert_eq!(next.retention_expires_at, state.retention_expires_at);
    assert_eq!(next.last_poll_at, Some(1_001));
}

#[test]
fn every_committed_premature_poll_adds_exactly_five_seconds() {
    let mut state = pending_state(1_000);
    state.last_poll_at = Some(1_000);
    for expected in [10, 15, 20] {
        let CibaPollTransition::SlowDown(next) = evaluate_ciba_poll(&state, 1_001) else { panic!() };
        assert_eq!(next.interval_seconds, expected);
        assert_eq!(next.expires_at, 1_060);
        assert_eq!(next.retention_expires_at, 1_180);
        state = next;
    }
}

#[test]
fn ciba_poll_selects_terminal_states_before_protocol_success() {
    let mut state = pending_state(1_000);
    assert!(matches!(evaluate_ciba_poll(&state, state.expires_at), CibaPollTransition::Expired));
    state.status = CibaStatus::Approved;
    assert!(matches!(evaluate_ciba_poll(&state, 1_001), CibaPollTransition::Approved));
    state.status = CibaStatus::Denied;
    assert!(matches!(evaluate_ciba_poll(&state, 1_001), CibaPollTransition::Denied));
}

#[test]
fn ciba_decision_rejects_mismatch_terminal_and_expired_states() {
    let state = pending_state(1_000);
    assert!(matches!(evaluate_ciba_decision(&state, Some(Uuid::now_v7()), CibaDecision::Approve, 1_001), CibaDecisionEvaluation::UserMismatch));
    let mut terminal = state.clone();
    terminal.status = CibaStatus::Approved;
    assert!(matches!(evaluate_ciba_decision(&terminal, Some(terminal.user_id), CibaDecision::Deny, 1_001), CibaDecisionEvaluation::AlreadyHandled));
    assert!(matches!(evaluate_ciba_decision(&state, Some(state.user_id), CibaDecision::Approve, state.expires_at), CibaDecisionEvaluation::Expired));
}
```

Add live-Valkey tests that stage legacy JSON without `retention_expires_at`, set its absolute `EXPIREAT`, load it, and assert the parsed field equals the key's actual `EXPIRETIME`; stage a new-format state whose field differs by one second and assert `CibaStateError::Malformed`; replace pending state and assert both stored timestamps and `EXPIRETIME` remain unchanged.

- [ ] **Step 2: Run the focused tests and verify red**

```powershell
rtk docker run --rm --network nazo-oauth-codecov-net -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace -v nazo-oauth-cargo-registry:/usr/local/cargo/registry -v nazo-oauth-cargo-git:/usr/local/cargo/git -v nazo-oauth-codecov-target:/docker-target -w /workspace -e VALKEY_URL=redis://nazo-oauth-codecov-valkey:6379/0 -e CARGO_TARGET_DIR=/docker-target/check -e CARGO_BUILD_JOBS=1 nazo-oauth-codecov-runner:local bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib ciba_state -- --nocapture'
```

Expected: compilation fails because `ciba/state.rs` and its types do not exist.

- [ ] **Step 3: Implement the focused state module**

Move the state types out of `ciba.rs`, add `mod state; use state::*;`, and implement these exact shapes:

```rust
pub(super) const CIBA_TRANSITION_MAX_ATTEMPTS: usize = 4;
const CIBA_EXPIRED_STATE_RETENTION_SECONDS: i64 = 120;
const CIBA_SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct CibaRequestState {
    pub(super) client_id: String,
    pub(super) user_id: Uuid,
    pub(super) scopes: Vec<String>,
    pub(super) audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) binding_message: Option<String>,
    #[serde(default)]
    pub(super) issued_at: i64,
    pub(super) status: CibaStatus,
    pub(super) interval_seconds: u64,
    pub(super) expires_at: i64,
    pub(super) retention_expires_at: i64,
    pub(super) last_poll_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CibaStatus { Pending, Approved, Denied }

#[derive(Clone, Debug)]
pub(super) struct StoredCibaRequest { pub(super) raw: String, pub(super) state: CibaRequestState }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CibaPollTransition {
    AuthorizationPending(CibaRequestState),
    SlowDown(CibaRequestState),
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CibaDecision { Approve, Deny }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CibaDecisionEvaluation {
    Commit(CibaRequestState),
    UserMismatch,
    AlreadyHandled,
    Expired,
}
```

`evaluate_ciba_poll` checks protocol expiry first, clones only for pending updates, uses saturating `+5`, and never writes either deadline. `evaluate_ciba_decision` validates user, pending status, and expiry in that order, then changes only `status`.

`load_ciba_request_state` must atomically read raw JSON and `EXPIRETIME`. It rejects non-finite expiry (`expire_at <= 0`), malformed JSON, a new-format deadline unequal to `EXPIRETIME`, and `retention_expires_at < expires_at`. For legacy JSON, insert the snapshot `expire_at` into the JSON object before deserializing while retaining the original raw string for the next CAS. Creation and replacement always serialize the required field. No function reads the current retention configuration.

- [ ] **Step 4: Run the focused tests and verify green**

Run the Step 2 command. Expected: all pure state and stored-deadline tests pass.

- [ ] **Step 5: Commit**

```powershell
rtk git add src/http/token/ciba.rs src/http/token/ciba/state.rs tests/in_source/src/http/token/tests/ciba_state.rs
rtk git commit -m "refactor: model immutable CIBA state transitions"
```

### Task 3: Collision-Safe Request Creation and Start Audit

**Files:**
- Modify: `src/http/token/ciba.rs`
- Modify: `src/support/audit.rs`
- Modify: `tests/in_source/src/http/token/tests/ciba.rs`
- Modify: `tests/in_source/src/support/tests/audit.rs`

**Interfaces:**
- Consumes: Task 2 state creation and immutable deadline fields.
- Produces: `create_unique_ciba_request`, registered `ciba_authorization_started`, `ciba_authorization_approved`, and `ciba_authorization_denied` event names, plus redacted start-audit fields.

- [ ] **Step 1: Write failing creation and redaction tests**

Add tests asserting that a preoccupied first generated ID is never overwritten, a later ID is used, four collisions return 503, `retention_expires_at == expires_at + 120`, and no audit outcome exists for failed creation. Add a field test:

```rust
#[test]
fn ciba_start_audit_fields_are_redacted() {
    let state = pending_state(1_000);
    let fields = ciba_start_audit_fields(&state, "secret-auth-req-id", Some("ip-hash".to_owned()));
    let serialized = serde_json::to_string(&fields).unwrap();
    assert!(serialized.contains(&blake3_hex("secret-auth-req-id")));
    assert!(!serialized.contains("secret-auth-req-id"));
    assert!(!serialized.contains("binding_message"));
    assert!(!serialized.contains("client_assertion"));
}
```

Update the audit registry test to require the three new names and category `authorization`.

- [ ] **Step 2: Run focused tests and verify red**

Run: `cargo test --locked ciba_start_audit --lib` in the Docker runner. Expected: missing helper/event registration failures.

- [ ] **Step 3: Implement creation as SET NX with four collision attempts**

In `backchannel_authentication`, calculate `now` once, then:

```rust
let expires_at = now.saturating_add(expires_in.min(i64::MAX as u64) as i64);
let state_payload = CibaRequestState {
    client_id: client.client_id,
    user_id: user.id,
    scopes,
    audiences: vec![state.settings.default_audience.clone()],
    acr,
    binding_message: form.binding_message,
    issued_at: now,
    status: CibaStatus::Pending,
    interval_seconds: state.settings.ciba_poll_interval_seconds,
    expires_at,
    retention_expires_at: ciba_retention_deadline(expires_at),
    last_poll_at: None,
};
```

`create_unique_ciba_request` accepts an ID-generator closure in tests, tries at most `CIBA_TRANSITION_MAX_ATTEMPTS`, retries only `Conflict`, returns the ID only for `Applied`, and maps `DeadlineElapsed`, Valkey failure, or four collisions to 503. Emit `ciba_authorization_started` only after the helper returns the committed ID. Fields are `client_id`, `user_id`, `auth_req_id_hash`, `scopes`, `audiences`, and optional `source_ip_hash = blake3_hex(client_ip(req, settings))`.

- [ ] **Step 4: Run focused tests and verify green**

Run: `cargo test --locked ciba_start_audit --lib` and `cargo test --locked audit_event_registry --lib` in Docker. Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
rtk git add src/http/token/ciba.rs src/support/audit.rs tests/in_source/src/http/token/tests/ciba.rs tests/in_source/src/support/tests/audit.rs
rtk git commit -m "feat: create and audit CIBA requests atomically"
```

### Task 4: Atomic Manual and Automated Decisions with Post-Commit Audit

**Files:**
- Modify: `src/http/token/ciba.rs`
- Modify: `tests/in_source/src/http/token/tests/ciba_state.rs`
- Modify: `tests/in_source/src/http/token/tests/ciba.rs`

**Interfaces:**
- Consumes: `evaluate_ciba_decision`, exact snapshot CAS/delete, and registered audit events.
- Produces: `CommittedCibaDecision`, `CibaDecisionFailure`, `commit_ciba_decision`, and `complete_ciba_decision`.

- [ ] **Step 1: Write failing decision linearization tests**

Use live Valkey to assert: approve applies once; a concurrent deny cannot overwrite it; a repeated decision is `AlreadyHandled`; user mismatch leaves pending state unchanged; expired state is compare-deleted; `DeadlineElapsed` follows the expired path; unavailable Valkey maps to 503. Add an audit-count tracing layer and assert `complete_ciba_decision` emits exactly one audit event for `Ok(CommittedCibaDecision)` and zero for conflict exhaustion, repeated decision, user mismatch, expiry, malformed state, and storage failure.

Add a failing writer test that installs a `tracing_subscriber::fmt()` subscriber whose `Write::write` returns `io::Error`, then asserts the committed decision response remains HTTP 200 and the Valkey state remains terminal.

- [ ] **Step 2: Run focused tests and verify red**

Run: `cargo test --locked ciba_decision --lib` in the Docker runner with `VALKEY_URL`. Expected: non-atomic decision behavior and missing committed outcome types.

- [ ] **Step 3: Implement the four-attempt decision loop**

Use these exact outcome types:

```rust
#[derive(Clone, Debug)]
struct CommittedCibaDecision { state: CibaRequestState, decision: CibaDecision }

#[derive(Debug)]
enum CibaDecisionFailure {
    Missing,
    UserMismatch,
    AlreadyHandled,
    Expired,
    Storage(CibaStateError),
    Contended,
}
```

For each attempt, load a fresh snapshot, evaluate it, compare-set a valid terminal state, or compare-delete an expired state. `Conflict` loops; `DeadlineElapsed` returns `Expired`; `Applied` returns a committed outcome; any storage error returns immediately; after four conflicts return `Contended`. No branch writes audit data inside this loop.

Change `ciba_automated_decision` to accept `HttpRequest` so both decision sources can hash the source IP. `complete_ciba_decision` maps the domain result to HTTP, and only its `Ok` arm calls `audit_event` with `decision_source = "user"` or `"automation"`. It then returns the existing `{"success":true}` response. The automation token and raw `auth_req_id` are never fields.

- [ ] **Step 4: Run focused tests and verify green**

Run the Step 2 test. Expected: decision, audit commit-point, and failing-writer tests pass.

- [ ] **Step 5: Commit**

```powershell
rtk git add src/http/token/ciba.rs tests/in_source/src/http/token/tests/ciba.rs tests/in_source/src/http/token/tests/ciba_state.rs
rtk git commit -m "feat: commit CIBA decisions with compare-and-set"
```

### Task 5: Atomic Polling, One-Time Assertion Consumption, and At-Most-Once Issuance

**Files:**
- Modify: `src/http/token/ciba.rs`
- Modify: `tests/in_source/src/http/token/tests/ciba_state.rs`
- Modify: `tests/in_source/src/http/token/tests/ciba.rs`

**Interfaces:**
- Consumes: Task 2 poll evaluation and Task 1 conditional operations.
- Produces: `AuthorizedCibaPoll`, `CibaPollCommit`, `CibaPollFailure`, `authorize_ciba_poll`, and `commit_ciba_poll`.

- [ ] **Step 1: Write failing concurrency and invariant tests**

Cover these exact cases with live Valkey:

1. Start three authorized poll operations from the same pending snapshot whose `last_poll_at` is current. Run them with `tokio::join!`; all three outcomes must be `SlowDown`, and the final interval must be original +15.
2. Start two authorized consumers from the same approved snapshot; exactly one outcome must be `Approved`, the other must be `Missing`, and the key must be absent.
3. Force a CAS conflict after an `authorize_ciba_poll` closure increments an `AtomicUsize`; the retry must succeed while the counter remains exactly one.
4. Force downstream issuance failure after `Approved`; reload must remain `None`.
5. A compare-delete `Conflict`, `DeadlineElapsed`, malformed state, and unavailable Valkey must never produce `CibaPollCommit::Approved`.
6. Every storage failure maps to HTTP 503 `server_error`, never `authorization_pending`, `slow_down`, `access_denied`, or token issuance.

- [ ] **Step 2: Run focused tests and verify red**

Run: `cargo test --locked ciba_poll --lib` in the Docker runner with `VALKEY_URL`. Expected: races expose ignored store/delete results and missing retry guard types.

- [ ] **Step 3: Implement assertion authorization outside the retry loop**

Use these exact types:

```rust
struct AuthorizedCibaPoll { initial: StoredCibaRequest }

#[derive(Clone, Debug, PartialEq, Eq)]
enum CibaPollCommit {
    AuthorizationPending,
    SlowDown,
    Approved(CibaRequestState),
    Denied,
    Expired,
}

#[derive(Debug)]
enum CibaPollFailure {
    Missing,
    ClientMismatch,
    Storage(CibaStateError),
    Contended,
}
```

`authorize_ciba_poll` takes a `FnOnce() -> Future<Output = Result<(), HttpResponse>>`, awaits it exactly once, and wraps the already loaded initial snapshot. Production passes a closure calling `consume_token_client_assertion`; the retry function has no assertion parameter or replay-cache dependency.

`commit_ciba_poll` checks the expected client on every loaded snapshot. Pending outcomes compare-set; approved/denied/expired outcomes compare-delete. Only `Applied` returns the corresponding protocol outcome. `Conflict` reloads and reevaluates, missing-after-conflict returns `Missing`, `DeadlineElapsed` returns `Expired`, storage error stops immediately, and four conflicts return `Contended`.

Reorder `token_ciba` to: profile/binding validation; initial snapshot load; client-ID check; one-time assertion consumption; `commit_ciba_poll`; response mapping. The approved arm must call `find_user_by_id`, subject construction, and `issue_token_response` only after the compare-delete has returned `Applied`. Delete the old post-issuance `valkey_del` and every ignored state-write/delete result.

- [ ] **Step 4: Run focused tests and verify green**

Run the Step 2 command. Expected: all concurrency and security-invariant tests pass, including exact +15 and exactly one approved consumer.

- [ ] **Step 5: Commit**

```powershell
rtk git add src/http/token/ciba.rs tests/in_source/src/http/token/tests/ciba.rs tests/in_source/src/http/token/tests/ciba_state.rs
rtk git commit -m "fix: make CIBA polling and consumption atomic"
```

### Task 6: FAPI-CIBA Profile and Discovery Truth Regression Gates

**Files:**
- Modify: `tests/in_source/src/http/tests/well_known.rs`
- Modify: `tests/in_source/src/http/token/tests/ciba.rs`
- Modify only if a test exposes a mismatch: `src/http/well_known.rs`, `src/settings/profile.rs`, or `src/http/token/dispatch.rs`

**Interfaces:**
- Consumes: current `authorization_server_metadata`, CIBA profile validation, and generic grant dispatch.
- Produces: explicit regression proof for M6-02 and M6-03.

- [ ] **Step 1: Add explicit metadata and profile tests**

Add `discovery_omits_entire_ciba_surface_when_disabled`: assert the CIBA grant is absent and all five backchannel metadata fields are missing. Extend the internal-profile test to assert serialized metadata contains neither `Fapi2Ciba` nor `fapi2-ciba`. Add a CIBA request-validation test with authorization-server PAR/PKCE settings enabled and prove a valid signed CIBA request is accepted without authorization-code fields. Add a dispatch test proving a client without the registered CIBA grant receives `unauthorized_client` before CIBA execution.

- [ ] **Step 2: Run tests and verify their current result**

```powershell
rtk docker run --rm --network nazo-oauth-codecov-net -v F:/projects/nazo_oauth/oauth_backend_rust:/workspace -v nazo-oauth-cargo-registry:/usr/local/cargo/registry -v nazo-oauth-cargo-git:/usr/local/cargo/git -v nazo-oauth-codecov-target:/docker-target -w /workspace -e CARGO_TARGET_DIR=/docker-target/check -e CARGO_BUILD_JOBS=1 nazo-oauth-codecov-runner:local bash -lc '. /usr/local/cargo/env && cargo test --locked --workspace --all-features --lib well_known -- --nocapture && cargo test --locked --workspace --all-features --lib ciba_profile -- --nocapture'
```

Expected: tests pass without broadening runtime metadata. If a focused assertion fails, change only the matching existing gate and rerun until green.

- [ ] **Step 3: Commit**

```powershell
rtk git add tests/in_source/src/http/tests/well_known.rs tests/in_source/src/http/token/tests/ciba.rs src/http/well_known.rs src/settings/profile.rs src/http/token/dispatch.rs
rtk git commit -m "test: lock CIBA profile and metadata boundaries"
```

### Task 7: Official Frontend CIBA Confirmation Page

**Files:**
- Modify: `src/App.tsx`
- Create from reviewed commit: `src/pages/Ciba.tsx`
- Create from reviewed commit: `src/pages/Ciba.css`
- Modify: `src/types/auth.ts`
- Modify: `src/i18n/messages.ts`

**Interfaces:**
- Consumes: backend `GET/POST /auth/ciba/{auth_req_id}`, existing `RequireAuth`, CSRF value, `apiFetch`, and i18n provider.
- Produces: authenticated isolated route `/ciba/:authReqId` with ambiguity-safe approve/deny handling.

- [ ] **Step 1: Create the frontend branch and import the reviewed base page**

```powershell
rtk git fetch origin
rtk git switch -c codex/m6-ciba-completion origin/main
rtk git cherry-pick 0ebf6c7
```

Expected: route, page, CSS, and CIBA response types are present with no conflicts.

- [ ] **Step 2: Convert all visible CIBA copy to the current i18n provider**

Add English and `zh-CN` keys for title, subtitle, loading, invalid/handled request, unavailable request, client/application/issued/expires/binding/permissions/resources labels, empty scopes/resources, approve/deny states, success states, generic load failure, ambiguous decision, confirmed-terminal-after-timeout, retry-after-status-refresh, and secured-by footer. In `Ciba.tsx`, call `const { t } = useI18n()`, pass the localized unknown label to `formatDateTime`, and render no raw `authReqId` or response `auth_req_id` text.

- [ ] **Step 3: Implement ambiguity-safe decision handling**

Replace the catch branch with this control flow:

```typescript
    } catch (error) {
      if (error instanceof ApiError) {
        if (error.status === 401) {
          navigate(buildAuthRedirectWithNext(buildCurrentPath(window.location)), { replace: true });
          return;
        }
        setErrorMsg(error.message || t('ciba.error.decision'));
        return;
      }

      try {
        const latest = await apiFetch<CibaVerificationView>(
          `/auth/ciba/${encodeURIComponent(view.auth_req_id)}`
        );
        setView(latest);
        setErrorMsg(
          latest.request
            ? t('ciba.warning.statusReloaded')
            : t('ciba.warning.mayBeProcessed')
        );
      } catch (reloadError) {
        if (reloadError instanceof ApiError && reloadError.status === 401) {
          navigate(buildAuthRedirectWithNext(buildCurrentPath(window.location)), { replace: true });
          return;
        }
        setErrorMsg(t('ciba.warning.statusUnknown'));
      }
    } finally {
      setSubmitting(null);
    }
```

There is no second POST. If reload shows a live request, both actions become available only after `finally`; if reload shows no request, actions disappear and the warning says the request may already have been processed.

- [ ] **Step 4: Run the frontend gate**

```powershell
rtk npm test
```

Expected: ESLint and `tsc -b && vite build` both succeed.

- [ ] **Step 5: Commit**

```powershell
rtk git add src/App.tsx src/pages/Ciba.tsx src/pages/Ciba.css src/types/auth.ts src/i18n/messages.ts
rtk git commit -m "feat: ship CIBA authorization confirmation page"
```

### Task 8: Full Local Gates, Remote Branches, and Exact-Commit Deployment

**Files:**
- Modify only for test-discovered defects: files already listed in Tasks 1-7.

**Interfaces:**
- Consumes: complete backend and frontend implementation.
- Produces: exact tested backend SHA, frontend SHA, pushed branch refs, deployed image identity, and live probes.

- [ ] **Step 1: Run backend formatting, check, clippy, targeted, and full tests in Linux/Docker**

Run in order with PostgreSQL and Valkey disposable containers available:

```text
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --locked --workspace --all-features --lib ciba -- --nocapture
cargo test --locked --workspace --all-features --lib well_known -- --nocapture
cargo test --locked --workspace --all-features --lib
```

Use `nazo-oauth-codecov-runner:local`, `/docker-target/check`, `DATABASE_URL=postgresql://postgres:postgres@nazo-oauth-codecov-postgres:5432/oauth`, `VALKEY_URL=redis://nazo-oauth-codecov-valkey:6379/0`, and `RUST_TEST_THREADS=1`. Expected: every command exits 0. Fix actual failures and rerun the failed focused gate plus the full sequence.

- [ ] **Step 2: Run the real HTTP security path**

Start the repository compose dependencies, run migrations, and execute `scripts/full_real_request_e2e.py`. Expected: exit 0 with health, discovery, authorization, token, and protected-resource checks successful. If host port 8000 is occupied, use the documented no-published-port verification container and probe over the compose network.

- [ ] **Step 3: Re-run the frontend gate on the committed tree**

Run `rtk npm ci` and `rtk npm test` in `NazoAuthWeb`. Expected: both exit 0 and `git status --short` is empty.

- [ ] **Step 4: Push both repositories and verify remote SHAs**

Backend:

```powershell
$backendSha = rtk git rev-parse HEAD
rtk git push -u origin codex/m6-ciba-completion
rtk git push -u cnb codex/m6-ciba-completion
rtk git ls-remote origin refs/heads/codex/m6-ciba-completion
rtk git ls-remote cnb refs/heads/codex/m6-ciba-completion
```

Frontend:

```powershell
$frontendSha = rtk git rev-parse HEAD
rtk git push -u origin codex/m6-ciba-completion
rtk git ls-remote origin refs/heads/codex/m6-ciba-completion
```

Expected: each printed remote SHA equals its local variable.

- [ ] **Step 5: Deploy the exact backend implementation commit**

From the backend repository, deploy through the configured `hostinger` SSH target with the exact tested image tag:

```powershell
$imageTag = "m6-$($backendSha.Substring(0,7))"
rtk pwsh -NoLogo -NoProfile -File scripts/deploy_live.ps1 -RemoteHost hostinger -ImageRepository localhost/nazo-oauth-server -ImageTag $imageTag
rtk ssh hostinger "podman inspect nazo-oauth-server --format '{{.ImageName}} {{.NetworkSettings.Networks.nazo_oauth_net.IPAddress}}'"
rtk curl.exe -fsS https://auth.nazo.run/health
rtk curl.exe -fsS https://auth.nazo.run/.well-known/openid-configuration
rtk curl.exe -fsS https://auth.nazo.run/jwks.json
```

Expected: the running image is `localhost/nazo-oauth-server:$imageTag`, the fixed IP is `10.101.0.20`, health succeeds, discovery issuer is `https://auth.nazo.run`, and Discovery contains the enabled standard CIBA surface. Inspect the running container mounts and preserve the existing `.env.yaml`, key, avatar, and UI paths before starting OIDF.

- [ ] **Step 6: Commit any verification-only corrections and redeploy**

If Tasks 8.1-8.5 required code corrections, commit them with a scoped message, rerun all gates, repush both backend remotes, redeploy the new exact SHA, and replace `$backendSha`. Do not proceed with an older deployed image.

### Task 9: Fresh Official OIDF Run, Evidence Record, and M6 Completion State

**Files:**
- Create after success: `docs/conformance/2026-07-11-m6-official-fapi-ciba-oidf-results.md`
- Modify after success: `docs/conformance/README.md`
- Modify after success: `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`

**Interfaces:**
- Consumes: exact pushed/deployed backend implementation SHA and official workflow.
- Produces: fresh run ID/job/check evidence and truthful M6 completion state.

- [ ] **Step 1: Dispatch the official full workflow and capture the new run**

```powershell
rtk gh workflow run oidf-conformance-full.yml --ref codex/m6-ciba-completion -f runner_mode=parallel-isolated
Start-Sleep -Seconds 5
$run = rtk gh run list --workflow oidf-conformance-full.yml --branch codex/m6-ciba-completion --event workflow_dispatch --limit 1 --json databaseId,headSha,status,conclusion,url,createdAt | ConvertFrom-Json | Select-Object -First 1
if ($run.headSha -ne $backendSha) { throw "OIDF workflow head SHA does not match deployed implementation SHA" }
$runId = $run.databaseId
```

Expected: `$runId` is a new run and `headSha` equals the deployed implementation SHA.

- [ ] **Step 2: Wait for final completion and inspect every job**

```powershell
rtk gh run watch $runId --exit-status
rtk gh run view $runId --json status,conclusion,jobs,updatedAt,url,headSha
```

Expected: overall `conclusion=success`; `oidf-conformance-full` succeeds; both isolated browser jobs succeed; the full job contains the `fapi-ciba-id1-test-plan-private_key_jwt-poll-plain_fapi-static_client` result. On failure, download artifacts/logs, diagnose the exact module, fix the implementation or environment source, repeat Tasks 8 and 9 with a new run, and retain only the final successful run as completion evidence while mentioning failed diagnostic runs in the record.

- [ ] **Step 3: Record artifact and FAPI-CIBA module evidence**

Use `gh api repos/nazozero/NazoAuth/actions/runs/$runId/artifacts` and the exported artifact summary to record: run URL/ID, workflow head SHA, deployed image, start/completion timestamps, all job names/conclusions, official suite ref, FAPI-CIBA plan ID, module count, passed/failed/warning counts, artifact IDs/sizes/digests, and exact profile variant. Do not commit raw result archives, secrets, runner tokens, rendered private configuration, or raw `auth_req_id` values.

- [ ] **Step 4: Update conformance index and roadmap only after success**

Add the new record as the latest M6 official result in `docs/conformance/README.md`. Change only M6-01, M6-02, and M6-03 checkboxes to `[x]`. Replace the CIBA status row with: `M6 已完成；CIBA poll mode 生命周期、用户确认、审计、metadata truth、官方 FAPI-CIBA 兼容 profile 与内部 fapi2-ciba 强化边界均已有本地门禁和最新官方 OIDF 证据。` Update the current-priority row so it no longer names completed M5 or M6 as the next gap.

- [ ] **Step 5: Verify documentation attribution and commit**

```powershell
rtk rg -n "M6-01|M6-02|M6-03|CIBA|$runId|$backendSha" docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md docs/conformance/README.md docs/conformance/2026-07-11-m6-official-fapi-ciba-oidf-results.md
rtk git diff --check
rtk git add docs/conformance/2026-07-11-m6-official-fapi-ciba-oidf-results.md docs/conformance/README.md docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md
rtk git commit -m "docs: record M6 official FAPI-CIBA verification"
rtk git push origin codex/m6-ciba-completion
rtk git push cnb codex/m6-ciba-completion
```

Expected: the result record names the implementation SHA exercised by OIDF even though the documentation commit advances the branch head; both remotes contain the final documentation commit.

- [ ] **Step 6: Final repository audit**

Verify both worktrees are clean, backend origin/CNB branch tips match, frontend origin branch tip matches, and retain these final handoff facts: backend implementation SHA, backend documentation SHA, frontend SHA, deployed image, OIDF run ID/URL, exact job names, FAPI-CIBA plan ID, module/failure/warning totals, and final conclusions.
