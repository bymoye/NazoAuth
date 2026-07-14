# M6 CIBA / FAPI-CIBA Completion Design

**Date:** 2026-07-10  
**Status:** Approved for implementation  
**Backend repository:** verified NazoAuth checkout  
**Frontend repository:** verified sibling NazoAuthWeb checkout

## 1. Context

The M6 roadmap requires three outcomes:

- M6-01 completes the CIBA poll-mode product boundary, including user confirmation, audit events, protocol errors, sender-constrained tokens, polling interval enforcement, and the complete `auth_req_id` lifecycle.
- M6-02 keeps the official FAPI-CIBA compatibility profile separate from the internal `fapi2-ciba` hardening profile.
- M6-03 keeps Discovery metadata and runtime feature/grant gates aligned without applying authorization-code-only controls to CIBA.

The current implementation already provides most CIBA Core and profile behavior, but its state transitions are not atomic. Approved state is loaded and later deleted with the deletion result ignored, so concurrent token requests can both observe an approved request and reach token issuance. Pending poll state writes and terminal deletes also ignore storage failures. These are lifecycle correctness defects, not documentation gaps.

The official frontend repository has an unmerged CIBA page in commit `0ebf6c7`, while its `main` branch already contains the shared authentication, routing, i18n, and device-verification foundations needed to integrate that page.

## 2. Goals

1. Make every CIBA state transition conditional on the exact Valkey state that was evaluated.
2. Guarantee that an approved `auth_req_id` can be consumed by at most one token request.
3. Store the original protocol expiry and retention deadline in each request state and preserve both across every update; polling must never extend either deadline.
4. Consume each client assertion exactly once even when a CIBA state transition retries after a comparison conflict.
5. Propagate Valkey failures as protocol-level server failures instead of continuing with stale state.
6. Record structured, redacted audit events for CIBA request creation and user/automation decisions.
7. Ship the authenticated user-confirmation page in the official frontend repository.
8. Preserve the existing official FAPI-CIBA compatibility behavior and the stricter internal `fapi2-ciba` behavior as separate profiles.
9. Prove the result with deterministic unit/integration tests, Linux/Docker gates, frontend lint/build, and a fresh official FAPI-CIBA OIDF workflow run.

## 3. Non-goals

- CIBA ping or push delivery modes.
- CIBA `user_code` support.
- A PostgreSQL persistence model for short-lived CIBA requests.
- An official “FAPI2-CIBA” standards or certification claim.
- Applying PAR, PKCE, authorization-code response types, or other authorization-code-only controls to CIBA.
- A general frontend redesign or a new frontend test framework.
- Creating a pull request unless separately requested.

## 4. Repository and Branch Boundaries

Both repositories start from their fetched, clean `main` branches.

- Backend work uses `codex/m6-ciba-completion` in `NazoAuth`.
- Frontend work uses `codex/m6-ciba-completion` in `NazoAuthWeb`.
- The approved design specification is committed in the backend branch before implementation.
- The existing frontend commit `0ebf6c7` is reviewed and cherry-picked or reapplied onto the new frontend branch; its old branch is not treated as the delivery branch.
- Both branches may be pushed because the official backend workflow requires a remote ref. No pull request is created without a separate request.

## 5. State Model and Atomic Storage Primitives

Valkey remains the only source of truth for a live `auth_req_id`. No database table or secondary state cache is added.

### 5.1 Stored snapshot

Loading a CIBA request returns both:

- the exact raw JSON string read from Valkey; and
- the parsed `CibaRequestState`.

The raw value is the optimistic-concurrency version. A transition is valid only if Valkey still contains that exact value.

`CibaRequestState` stores two immutable absolute Unix-second timestamps:

- `expires_at`: the protocol expiry;
- `retention_expires_at`: the Valkey retention deadline.

Both values are calculated once when the request is created. Every transition preserves them unchanged. No read, poll, decision, retry, or configuration reload derives a new retention deadline from `expires_at` and the current retention setting.

The Valkey key expiry is set to the absolute retention deadline. As wall-clock time advances, the remaining TTL only decreases. Pending polls, `slow_down`, approval, and denial cannot refresh or extend it.

For a rolling upgrade, a pre-M6 state that lacks `retention_expires_at` is migrated only from that key’s existing absolute Valkey `EXPIRETIME`, read atomically with the raw value. It is never reconstructed from the running binary’s current retention setting. A legacy key without a finite expiry, or a new-format state whose stored deadline disagrees with the key’s absolute expiry, is malformed and returns HTTP 503 `server_error`. The next successful compare-and-set persists the migrated field.

### 5.2 Atomic primitives

The existing Valkey support module gains snapshot and conditional-transition operations implemented with Valkey-side Lua and the existing client dependency:

- atomic snapshot read: return the raw value and its Valkey `EXPIRETIME` from one script;
- compare-and-set-at-absolute-deadline: replace a key only when its current value exactly equals the expected raw value, then retain the state’s stored `retention_expires_at`;
- compare-and-delete: delete a key only when its current value exactly equals the expected raw value.

Both conditional operations return one of:

- `Applied`: the expected value matched and the transition committed before the deadline;
- `Conflict`: another operation changed or consumed the state before this operation;
- `DeadlineElapsed`: Valkey server time reached `retention_expires_at` at the transition’s linearization point.

Transport or script failures remain Valkey errors. No new crate is introduced.

The scripts use Valkey `TIME` as the deadline clock and `EXPIREAT` as the absolute expiry operation. They do not use `SETEX` with the original duration. Immediately before applying the mutation, the script compares the server’s Unix time with the stored deadline. If `now >= retention_expires_at`, it does not report `Applied`; it removes the expected expired value when still present and returns `DeadlineElapsed`.

Callers treat `DeadlineElapsed` as an expiry result, not as a successful pending, slow-down, approval, denial, or consumption result. It does not enter the comparison retry budget and cannot produce a success audit or token issuance.

### 5.3 Conflict handling

CIBA transition callers use at most four read/evaluate/compare attempts. Only `Conflict` reloads the current snapshot and recomputes the protocol result. The caller never continues using the stale snapshot. `DeadlineElapsed` immediately follows the operation-specific expiry path.

Four consecutive conflicts or any Valkey command failure returns the existing non-cacheable `server_error` response with HTTP 503. This bound prevents an unbounded loop under hostile concurrent polling while failing closed.

## 6. Pure Rust State Transitions

Protocol decisions remain in Rust rather than Lua. Small pure transition functions make the behavior deterministic and independently testable.

### 6.1 Poll transition

Given a snapshot and the current timestamp, the poll transition produces one of:

- `AuthorizationPending(next_state)` when this is the first permitted pending poll;
- `SlowDown(next_state)` when the client polls before the active interval has elapsed;
- `ConsumeApproved`;
- `ConsumeDenied`;
- `ConsumeExpired`.

For `AuthorizationPending`, `last_poll_at` becomes the current time. For `SlowDown`, the interval increases by five seconds using saturating arithmetic and `last_poll_at` becomes the current time.

Pending and slow-down transitions use compare-and-set. Approved, denied, and expired transitions use compare-and-delete.

Every premature poll that successfully commits its own compare-and-set increases the stored interval by exactly five seconds. A comparison conflict does not itself increase the interval; the request reloads the latest state and reevaluates. Therefore, if three concurrent premature polls all complete their state transitions before a terminal decision, all three return `slow_down` and the final interval is the original interval plus fifteen seconds. If a reload observes approval, denial, expiry, or prior consumption, that terminal result supersedes `slow_down` and no further interval increase occurs.

### 6.2 Decision transition

The decision transition validates, in order:

1. the request still exists;
2. an authenticated user decision belongs to the request user;
3. the request is still pending;
4. the request has not expired;
5. the requested decision is approve or deny.

A valid decision produces a terminal replacement state and is persisted by compare-and-set. A conflict reloads the state. A terminal state cannot be overwritten by a later manual or automated decision.

Expired decision state is consumed with compare-and-delete before returning the existing expired/invalid request response.

### 6.3 Complete state transition table

All audit entries in this table are emitted only after the named atomic operation succeeds.

| Current stored state | Operation and condition | Atomic operation | State after success | HTTP/protocol result | Successful audit |
| --- | --- | --- | --- | --- | --- |
| No key | Create a valid backchannel request | `SET NX` with stored `retention_expires_at` | `Pending` | `auth_req_id`, `expires_in`, and `interval` | `ciba_authorization_started` |
| No key | Read a decision/verification request | None | No key | HTTP 404 `invalid_request` | None |
| No key | Poll token endpoint | None | No key | `invalid_grant` | None |
| `Pending`, unexpired | Verification read by the bound user | None | Unchanged | HTTP 200 request view | None |
| `Pending`, unexpired | Verification read or decision by another user | None | Unchanged | `access_denied` | None |
| `Approved`, `Denied`, or retained expired state | Verification read by the bound user | None | Unchanged | HTTP 200 with no actionable request | None |
| Any state | Manual decision without a valid session or CSRF token | None | Unchanged | Existing login-required or CSRF error | None |
| Any state | Automated decision without the valid constant-time decision token | None | Unchanged | HTTP 404 | None |
| `Pending`, unexpired | Decision value other than approve or deny | None | Unchanged | `invalid_request` | None |
| `Pending`, unexpired | Approve | Compare-and-set at the original absolute retention deadline | `Approved` | HTTP 200 success | `ciba_authorization_approved` after CAS success |
| `Pending`, unexpired | Deny | Compare-and-set at the original absolute retention deadline | `Denied` | HTTP 200 success | `ciba_authorization_denied` after CAS success |
| `Pending`, expired | Approve or deny | Compare-and-delete | No key | HTTP 404 `invalid_request` | None |
| `Approved` or `Denied` | Approve or deny again | None | Unchanged | `invalid_request` | None |
| `Pending`, unexpired | First poll or poll after the active interval | Compare-and-set at the original absolute retention deadline | `Pending`, `last_poll_at=now` | `authorization_pending` | None |
| `Pending`, unexpired | Poll before the active interval | Compare-and-set at the original absolute retention deadline | `Pending`, interval +5 seconds, `last_poll_at=now` | `slow_down` | None |
| `Approved`, unexpired, matching client | Poll token endpoint | Compare-and-delete | No key | Issue tokens only after delete succeeds | Existing `token_issued` only after issuance succeeds |
| `Denied`, unexpired, matching client | Poll token endpoint | Compare-and-delete | No key | `access_denied` | None |
| Any retained state, expired, matching client | Poll token endpoint | Compare-and-delete | No key | `expired_token` | None |
| Any stored state | Poll by a different client | None | Unchanged | `invalid_grant` | None |
| Any state | Compare conflict | No transition committed; reload and reevaluate | Current winner’s state | Winner-dependent result, or HTTP 503 `server_error` after four conflicts | None for the failed attempt |
| Any state | Conditional script returns `DeadlineElapsed` | No successful transition; remove expected expired value when present | No key | Decision path: expired `invalid_request`; token path: `expired_token` | None |
| Any state | Valkey read, compare, write, or delete error | No successful atomic operation | Unknown; processing stops | HTTP 503 `server_error` | None |
| Malformed stored JSON | Read for verification, decision, or poll | None | Unchanged | HTTP 503 `server_error` | None |

## 7. HTTP and Protocol Data Flow

### 7.1 Backchannel authentication request

The existing order remains:

1. require `ENABLE_CIBA=true`;
2. parse the backchannel form and reject mixed client-authentication methods;
3. authenticate an active client;
4. require the registered CIBA grant;
5. apply the selected CIBA profile and request-object policy;
6. validate scope, user hint, requested expiry, ACR, and binding message;
7. calculate and store immutable `expires_at` and `retention_expires_at` values;
8. persist the pending state with `SET NX` and the stored absolute retention deadline;
9. emit the start audit event;
10. return `auth_req_id`, `expires_in`, and `interval`.

The audit event is emitted only after persistence succeeds.

An `auth_req_id` collision does not overwrite an existing key. The handler generates a new random identifier and retries `SET NX` up to four times. Four collisions return HTTP 503 `server_error`; no start audit is emitted for failed attempts.

### 7.2 User and automated decisions

The authenticated user flow retains session and CSRF enforcement. The automated OIDF hook retains constant-time decision-token validation. Both flows use the same atomic decision transition.

The automated handler accepts the request context so its source IP can be hashed for audit parity. The automation decision token is never logged or included in an audit field.

Approve or deny audit data is constructed from the committed snapshot and emitted only after compare-and-set returns `true`. A compare conflict, repeated decision, user mismatch, expired request, malformed state, or Valkey failure cannot produce an approve/deny success audit event.

### 7.3 Token polling

The existing token endpoint continues to authenticate the client and require that client’s registered CIBA grant before entering CIBA processing.

For each poll:

1. validate the selected CIBA profile and required DPoP or mTLS proof;
2. load the stored snapshot;
3. require the stored client ID to match the authenticated client;
4. complete cryptographic client-assertion validation and consume its replay identifier exactly once;
5. enter the state-transition retry loop using the already validated assertion result;
6. evaluate the pure poll transition;
7. atomically apply or consume the exact snapshot;
8. return the corresponding protocol result.

Both assertion validation and replay-identifier consumption are outside the compare-and-transition retry loop. A comparison conflict retries only the Valkey snapshot evaluation. It must not revalidate or reconsume the assertion.

Only a request that successfully compare-deletes an approved snapshot can construct and issue tokens. Concurrent consumers that lose the comparison reload and then receive `invalid_grant` after the state is absent.

The approved state is consumed before database-backed token issuance, matching the project’s one-time authorization-code and device-code security boundary. If downstream issuance fails, the one-time grant is not restored; replay prevention takes precedence over retrying a partially executed grant.

The token-issuance branch is reachable only through a successful approved compare-delete result. A failed comparison, missing key, malformed state, or Valkey error cannot call token issuance. No code path recreates or restores a consumed `auth_req_id`.

If compare-and-set or compare-and-delete returns `DeadlineElapsed`, token polling returns `expired_token`; decision handling returns its existing expired `invalid_request` response. The caller cannot return `authorization_pending`, `slow_down`, decision success, or a token response for that attempt.

## 8. Error Semantics

The implementation keeps protocol errors precise and non-cacheable:

| Condition | Response |
| --- | --- |
| CIBA disabled at `/bc-authorize` | HTTP 404 |
| CIBA disabled at `/token` | `unsupported_grant_type` |
| Client lacks CIBA grant | `unauthorized_client` |
| Missing `auth_req_id` | `invalid_request` |
| Unknown/consumed `auth_req_id` | `invalid_grant` |
| Stored client mismatch | `invalid_grant` |
| Pending first/allowed poll | `authorization_pending` |
| Poll before interval | `slow_down` and interval +5 seconds |
| Retained but expired state | `expired_token` |
| Denied request | `access_denied` |
| Repeated/terminal decision | `invalid_request` |
| Manual decision user mismatch | `access_denied` |
| Valkey read, compare, write, or delete failure | HTTP 503 `server_error` |
| Persistent state contention after four attempts | HTTP 503 `server_error` |

No state update or terminal delete error is discarded.

## 9. Audit Model

The structured audit registry gains three authorization-category events:

- `ciba_authorization_started`;
- `ciba_authorization_approved`;
- `ciba_authorization_denied`.

The event fields are intentionally bounded:

- `client_id`;
- `user_id`;
- `auth_req_id_hash` using the project’s existing BLAKE3 helper;
- scope and audience for the start event;
- `decision_source` with value `user` or `automation` for terminal decisions;
- `source_ip_hash` when a request context is available.

Raw `auth_req_id`, binding message, decision token, client assertion, DPoP proof, access token, refresh token, and client secret are excluded. Polling events are not logged individually because they would create attacker-controlled audit volume. Successful token creation remains covered by the existing `token_issued` event.

Decision handling returns a committed-decision outcome only after compare-and-set succeeds. Audit emission accepts that committed outcome rather than the uncommitted request payload. Conflict retries and every error/terminal outcome have no committed-decision value and therefore cannot emit `ciba_authorization_approved` or `ciba_authorization_denied`.

### 9.1 Audit delivery failure policy

The existing project audit API returns `()` and publishes through `tracing`; it has no failure result that can be propagated to an HTTP handler. CIBA follows that existing best-effort delivery policy:

1. the Valkey state transition commits first;
2. the handler publishes the audit event;
3. the handler returns the already committed protocol result.

An absent or failing tracing subscriber does not turn a committed decision into HTTP 503. It never rolls back, restores, or repeats the state transition, and it never retries the client assertion or decision. Audit delivery health belongs to the operational logging pipeline rather than the OAuth state machine.

If the project later replaces `audit_event` with a fallible sink, CIBA records a redacted internal delivery error through the available independent operational channel and still returns the committed result. The state transition remains authoritative and is never replayed to obtain another audit attempt.

## 10. FAPI-CIBA and Internal Profile Isolation

`fapi-ciba-id1-plain-private-key-jwt-poll` remains the compatibility profile used by the official OIDF plan. Existing per-client request-object policy, private-key JWT endpoint-audience compatibility, and mTLS holder-of-key compatibility remain unchanged unless a failing conformance test proves otherwise.

`fapi2-ciba` remains an internal hardening profile. It continues to require confidential clients, private-key JWT or mTLS authentication, issuer-only private-key JWT audience, signed backchannel request objects, strong signing algorithms, and DPoP or mTLS sender-constrained tokens.

Discovery advertises only standard CIBA capabilities. It never serializes `fapi2-ciba`, `Fapi2Ciba`, or an invented FAPI2-CIBA profile claim. README, profile documentation, and OIDF plan names keep the same distinction.

PAR, PKCE, and `response_type=code` requirements remain scoped to authorization-code processing and are not added to the CIBA request or token paths.

## 11. Metadata and Client Grant Truth

When `ENABLE_CIBA=false`, Discovery omits:

- the CIBA grant type;
- `backchannel_authentication_endpoint`;
- backchannel token delivery modes;
- backchannel request signing algorithms;
- the backchannel user-code capability field.

When `ENABLE_CIBA=true`, Discovery advertises the implemented poll mode and supported signing algorithms without internal profile names.

Discovery is server-wide and therefore cannot depend on a particular unauthenticated client. Runtime execution provides the client-specific half of the truth boundary: both `/bc-authorize` and `/token` require the authenticated client to have registered `urn:openid:params:grant-type:ciba`.

## 12. Frontend Integration

The frontend branch starts from `NazoAuthWeb/main`. Commit `0ebf6c7` supplies the initial route, page, styles, and response types, but the integrated result is adapted to current main rather than accepted blindly.

The page:

- is routed at `/ciba/:authReqId` under the existing authenticated-route guard;
- is treated as an isolated authorization page without the normal navigation shell;
- preserves the full CIBA URL through login and returns to it after authentication;
- loads `/auth/ciba/{auth_req_id}` with URL encoding;
- displays client name and ID, scopes, audiences, binding message, issue time, and expiry time;
- submits approve or deny with the existing CSRF value;
- disables both actions during submission and removes the request after a terminal success;
- does not automatically repeat a decision after a network timeout;
- after an ambiguous decision timeout, reloads the request status and tells the user that the request may already have been processed before offering another action;
- does not render the raw `auth_req_id` as page content;
- uses the current i18n provider for user-visible copy;
- follows the existing design tokens and responsive behavior.

No new frontend framework, state library, or test dependency is introduced.

## 13. Test Strategy

Implementation follows red-green-refactor. Production behavior is not added before a test demonstrates the missing behavior.

### 13.1 Backend unit tests

Tests cover:

- first pending poll;
- permitted later pending poll;
- sequential early polls, with exactly five seconds added for every successfully committed `slow_down`;
- concurrent early polls, with every completed premature poll returning `slow_down` and the final interval increasing by exactly five seconds per successful poll;
- approved, denied, and expired transition selection;
- serialization of immutable `expires_at` and `retention_expires_at` fields;
- preservation of a stored retention deadline when the running configuration differs;
- one-time legacy migration from the key’s actual `EXPIRETIME`, never from current configuration;
- manual decision user mismatch;
- repeated decision rejection;
- client assertion validation and replay consumption occurring exactly once across comparison retries;
- audit field construction and exclusion of raw secrets;
- approve/deny audit creation only for a committed decision outcome;
- no success decision audit for a conflict, repeated decision, user mismatch, expiry, malformed state, or Valkey error;
- committed decision behavior remaining successful with no audit subscriber and with a test subscriber whose writer returns an I/O error, with no state restoration or repeated transition;
- FAPI-CIBA compatibility behavior;
- internal `fapi2-ciba` requirements;
- sender constraint propagation to both access and refresh tokens;
- client/grant mismatch error semantics;
- CIBA metadata absence when disabled;
- standard-only metadata when the internal profile is selected;
- absence of authorization-code-only CIBA requirements.

### 13.2 Live Valkey tests

Docker-backed tests cover:

- `SET NX` collision rejection, identifier regeneration, and no overwrite of an existing request;
- compare-and-set success and expected-value mismatch;
- compare-and-delete success and second-consumer failure;
- an unchanged absolute `expires_at` and unchanged Valkey `EXPIRETIME` across pending, `slow_down`, approve, and deny transitions;
- decreasing remaining TTL across transitions, proving that a state update cannot refresh the original duration;
- compare-and-set and compare-and-delete returning `DeadlineElapsed` when Valkey `TIME` reaches the stored deadline;
- `DeadlineElapsed` never producing `authorization_pending`, `slow_down`, decision success, or token issuance;
- concurrent pending polls producing one applied transition and conflict-driven recomputation;
- three concurrent premature polls producing three `slow_down` responses and an exact fifteen-second interval increase;
- concurrent approved consumers producing exactly one successful terminal consumption;
- no token-issuance outcome when compare-and-delete does not succeed;
- an approved key remaining absent when downstream work is deliberately failed after successful consumption;
- Valkey unavailability mapping to `server_error` rather than a protocol success or stale-state response.

### 13.3 Core security invariant tests

The tests assert these invariants directly rather than inferring them from general endpoint success:

1. without a successful approved compare-and-delete, token issuance is unreachable;
2. after successful consumption, the `auth_req_id` remains absent even when downstream issuance fails;
3. without a successful decision compare-and-set, no approve/deny success audit record is constructed or emitted;
4. every Valkey error returns HTTP 503 `server_error` and stops state-transition, decision, or issuance processing;
5. every transition preserves the original protocol expiry and absolute retention deadline;
6. comparison retries consume the client assertion no more than once;
7. `DeadlineElapsed` is never treated as an applied transition;
8. audit delivery failure never restores or repeats an already committed state transition.

### 13.4 Frontend gate

The frontend runs its existing `npm test`, which executes ESLint and the TypeScript/Vite production build. A new unit-test framework is not introduced solely for this page.

### 13.5 Backend Linux/Docker gates

The backend runs from `oauth_backend_rust` in Linux/Docker with PostgreSQL and Valkey available:

```text
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --locked ciba --lib
cargo test --locked well_known --lib
cargo test --locked --workspace --all-features --lib
```

The current Windows host’s OpenSSL/libpq toolchain result is diagnostic only and is not represented as the Linux gate result.

## 14. Official OIDF Verification

After local gates pass:

1. commit and push the backend implementation branch;
2. dispatch `.github/workflows/oidf-conformance-full.yml` against `codex/m6-ciba-completion`;
3. identify and record the GitHub Actions run ID;
4. wait for the FAPI-CIBA plan job and the overall workflow to finish;
5. record the exact tested commit, job name, plan variant, module counts, failure/warning counts, and final conclusion;
6. do not describe an internal `fapi2-ciba` result as official certification.

The required plan is the official FAPI-CIBA ID1 private-key JWT, poll, plain-FAPI, static-client variant already present in the repository matrix. If the workflow has no single-plan dispatch input, the full matrix runs and the FAPI-CIBA job is reported separately.

A failing official run is investigated and corrected from its actual job/module evidence. It is not replaced by a documentation exception or an old successful result.

## 15. Documentation and Completion State

After the fresh OIDF run succeeds, the backend branch adds an isolated conformance result record containing the run evidence and updates the conformance index.

Only then are M6-01, M6-02, and M6-03 checked as complete in `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`. The roadmap status summary is updated consistently, while the protocol/profile documents continue to describe FAPI-CIBA as a compatibility profile and `fapi2-ciba` as internal hardening.

The result record may be a documentation-only commit after the tested implementation commit. It must name the exact implementation commit exercised by OIDF so that the evidence remains attributable even though the branch head advances for documentation.

## 16. Completion Criteria

M6 is complete only when all of the following are true:

1. approved CIBA state is atomically consumable at most once;
2. the original protocol expiry and absolute retention deadline never move forward during an update;
3. `retention_expires_at` is stored in the state and never reconstructed from current configuration;
4. `DeadlineElapsed` is distinct from `Applied` and follows the expiry path;
5. pending poll interval state and every terminal transition are atomic;
6. each successfully committed premature poll adds exactly five seconds to the active interval;
7. assertion validation and replay consumption execute once per token request, outside state-transition retries;
8. token issuance is unreachable without successful approved compare-and-delete;
9. consumed `auth_req_id` state is never restored, including after downstream failure;
10. approve/deny success audits are unreachable without successful decision compare-and-set;
11. audit delivery failure never rolls back or repeats a committed transition;
12. every Valkey failure returns HTTP 503 and stops further protocol processing;
13. start, approve, and deny audit events are registered, emitted after successful transitions, and redacted;
14. the official frontend contains the authenticated CIBA confirmation flow and passes `npm test`;
15. compatibility and internal profiles remain behaviorally and textually isolated;
16. Discovery and runtime client-grant gates match the implemented surface;
17. targeted and full backend Docker gates pass;
18. the fresh official FAPI-CIBA OIDF run passes and its run/job evidence is recorded;
19. all three M6 roadmap tasks and the status summary are updated only after the evidence above exists.
