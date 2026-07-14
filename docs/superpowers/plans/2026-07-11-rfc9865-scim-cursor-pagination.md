# RFC 9865 SCIM Cursor Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure forward-only RFC 9865 cursor pagination to `GET /scim/v2/Users` while preserving index pagination as the default.

**Architecture:** A stateless AES-256-GCM cursor codec encrypts a versioned actor-, tenant-, filter-, count-, order-, position-, and time-bound payload with a domain-separated key derived from `CLIENT_SECRET_PEPPER`. The SCIM list handler selects index or cursor mode, re-authorizes every request, and uses deterministic `(created_at, id)` keyset queries for cursor pages.

**Tech Stack:** Rust 2024, Actix Web, Diesel/PostgreSQL, OpenSSL AES-GCM, HMAC-SHA-256, serde, chrono, UUID, in-source Actix tests.

## Global Constraints

- Follow red-green-refactor: no production behavior before a failing test proves it is missing.
- Preserve index pagination as the default method.
- Do not implement `previousCursor`, SCIM `/.search`, sorting parameters, RFC 9967, or server-side cursor storage.
- Cursor lifetime is exactly 600 seconds; future `issued_at` tolerance is exactly 60 seconds.
- Cursor responses never expose `startIndex`; index responses retain it.
- Authentication and scope checks occur before cursor decoding on every page.
- No new crate or migration.

---

### Task 1: Stateless Cursor Codec

**Files:**
- Create: `src/http/scim/cursor.rs`
- Create: `tests/in_source/src/http/scim/tests/cursor.rs`
- Modify: `src/http/scim.rs`

**Interfaces:**
- Consumes: `Settings::client_secret_pepper`, `ScimCredential`, exact optional filter, effective count, `DateTime<Utc>`, and the last `(created_at, id)` marker.
- Produces:
  - `SCIM_CURSOR_TIMEOUT_SECONDS: i64 = 600`
  - `ScimCursorContext`
  - `ScimCursorPosition`
  - `ScimCursorError::{Invalid, Expired, InvalidCount}`
  - `encode_scim_cursor(settings, context, now) -> anyhow::Result<String>`
  - `decode_scim_cursor(settings, encoded, credential, filter, count, now) -> Result<ScimCursorPosition, ScimCursorError>`

- [ ] **Step 1: Register the empty cursor module and write failing round-trip tests**

Add `mod cursor;` beside the other SCIM modules. Create tests that use a fixed 32-byte pepper, database credential UUID, tenant UUID, filter, count, and marker. Assert round-trip position equality, URL-safe unpadded output, randomized outputs for identical inputs, and absence of plaintext tenant/token/filter/marker strings.

```rust
#[test]
fn scim_cursor_round_trip_is_opaque_url_safe_and_randomized() {
    let settings = cursor_settings();
    let credential = database_credential();
    let context = cursor_context(&credential);
    let now = Utc::now();

    let first = encode_scim_cursor(&settings, &context, now).expect("cursor should encode");
    let second = encode_scim_cursor(&settings, &context, now).expect("cursor should encode");

    assert_ne!(first, second);
    assert!(first.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    assert!(!first.contains('='));
    assert!(!first.contains("alice@example.test"));
    assert_eq!(
        decode_scim_cursor(
            &settings,
            &first,
            &credential,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Ok(context.position()),
    );
}
```

- [ ] **Step 2: Run the cursor test and verify RED**

Run:

```powershell
cargo test --locked scim_cursor_round_trip_is_opaque_url_safe_and_randomized --lib
```

Expected: compile failure because the cursor types and functions do not exist.

- [ ] **Step 3: Implement the minimum AES-GCM round trip**

Implement a private serde payload with fields `v`, `tenant_id`, `actor`,
`filter`, `count`, `sort`, `last_created_at`, `last_id`, `issued_at`, and
`expires_at`. Derive a 32-byte key with HMAC-SHA-256 over
`nazo-scim-cursor-aes256gcm-v1`; encrypt JSON with `Cipher::aes_256_gcm()`, a
random 12-byte nonce, AAD `nazo-scim-cursor-v1`, and a 16-byte tag. Concatenate
nonce, ciphertext, and tag, then encode with `URL_SAFE_NO_PAD`.

Decode in the reverse order, reject padded/non-URL-safe/oversized/truncated
input, authenticate before JSON parsing, then validate version, sort, actor,
tenant, filter, count, issue/expiry bounds, and expiry.

- [ ] **Step 4: Run the round-trip test and verify GREEN**

Run the command from Step 2. Expected: one passing test.

- [ ] **Step 5: Add failing negative codec tests**

Add separate tests for tampering, wrong credential, wrong tenant, wrong filter,
changed count, expiry, excessive future issue time, invalid lifetime, wrong
version/sort, malformed base64, padding, truncation, and oversize input. Assert
`InvalidCount` only for an otherwise valid cursor whose effective count differs,
`Expired` only for an authenticated expired cursor, and `Invalid` otherwise.

- [ ] **Step 6: Verify RED, implement validation, and verify GREEN**

Run:

```powershell
cargo test --locked scim_cursor --lib
```

Expected before validation: at least one assertion failure. Expected after the
minimal validation implementation: all cursor codec tests pass.

- [ ] **Step 7: Refactor and commit**

Keep cryptographic constants private except the timeout, avoid logging payload
values, run `cargo fmt --check` and the targeted cursor tests, then commit:

```powershell
git add src/http/scim.rs src/http/scim/cursor.rs tests/in_source/src/http/scim/tests/cursor.rs
git commit -m "feat: add opaque SCIM cursor codec"
```

### Task 2: Pagination Method and Response Semantics

**Files:**
- Modify: `src/http/scim.rs`
- Modify: `tests/in_source/src/http/tests/scim.rs`

**Interfaces:**
- Consumes: `ScimListQuery { start_index, count, filter, cursor }` and Task 1 codec.
- Produces:
  - `ScimPagination::{Index { start_index, count }, CursorFirst { count }, CursorNext { count, position }}`
  - exact RFC 9865 pagination selection/errors
  - `scim_cursor_list_users_response(...)`

- [ ] **Step 1: Write failing method-selection tests**

Cover absent pagination parameters, `startIndex` only, empty cursor, non-empty
cursor, both methods, negative first cursor count, count 201, and changed later
count. Assert index remains the default; both methods return `invalidValue`;
over-limit/change returns `invalidCount`.

- [ ] **Step 2: Run and verify RED**

Run:

```powershell
cargo test --locked scim_pagination --lib
```

Expected: compile or assertion failure because cursor method selection is absent.

- [ ] **Step 3: Implement minimal method selection**

Add `cursor: Option<String>` to `ScimListQuery`. Keep the exact raw optional
filter. Resolve first-page cursor count with negative values mapped to zero,
default 100, maximum 200, and over-limit `invalidCount`. Reject simultaneous
`startIndex` and `cursor`. Decode non-empty cursors only after authentication.

- [ ] **Step 4: Add failing cursor response tests**

Assert cursor responses contain `totalResults`, `itemsPerPage`, `Resources`, and
optional `nextCursor`; omit `startIndex` and `previousCursor`; omit `nextCursor`
on final and zero-count pages.

```rust
assert!(body.get("startIndex").is_none());
assert!(body.get("previousCursor").is_none());
assert_eq!(body["nextCursor"], "opaque-next");
```

- [ ] **Step 5: Implement responses and error mapping, then verify GREEN**

Map `ScimCursorError::Invalid`, `Expired`, and `InvalidCount` to HTTP 400 SCIM
errors with `scimType` `invalidCursor`, `expiredCursor`, and `invalidCount`.
Keep authentication/backend errors unchanged.

Run:

```powershell
cargo test --locked scim_pagination --lib
cargo test --locked scim_list_users_response --lib
```

Expected: all matching tests pass.

- [ ] **Step 6: Commit**

```powershell
git add src/http/scim.rs tests/in_source/src/http/tests/scim.rs
git commit -m "feat: add SCIM cursor request semantics"
```

### Task 3: Deterministic Keyset Database Traversal

**Files:**
- Modify: `src/http/scim.rs`
- Modify: `tests/in_source/src/http/tests/scim.rs`

**Interfaces:**
- Consumes: authenticated `ScimCredential`, selected pagination method, normalized email filter, and Task 1 codec.
- Produces: deterministic index queries and forward cursor keyset traversal over `(created_at, id)`.

- [ ] **Step 1: Write failing live database traversal tests**

Use an isolated `users` table and explicitly seed rows with controlled
`created_at` values and UUIDs. Cover equal timestamps, two or more pages,
filtered traversal, exact boundary, final-page omission, credential substitution,
 concurrent insertion after a marker, and deletion before the next request.

The core assertion is:

```rust
assert_eq!(collected_ids, expected_ids);
assert_eq!(collected_ids.iter().collect::<HashSet<_>>().len(), collected_ids.len());
```

- [ ] **Step 2: Run and verify RED**

Run with PostgreSQL available:

```powershell
cargo test --locked scim_cursor_database --lib
```

Expected: failures because the handler still uses offset pagination and does not
emit or consume `nextCursor`.

- [ ] **Step 3: Implement boxed deterministic queries**

For both methods use `(users::created_at.asc(), users::id.asc())`. For cursor
pages add:

```rust
users::created_at
    .gt(position.last_created_at)
    .or(users::created_at
        .eq(position.last_created_at)
        .and(users::id.gt(position.last_id)))
```

Fetch `count + 1`, remove the extra row, and encode the last returned row only
when another page exists. Continue using a separate accurate count query. Keep
the existing exact email filter and tenant predicate on both count and row
queries.

- [ ] **Step 4: Re-run live traversal tests and verify GREEN**

Run the command from Step 2. Expected: all cursor database tests pass. If
`DATABASE_URL` is absent, tests retain the existing explicit skip convention;
the Docker/full CI gate remains required before completion.

- [ ] **Step 5: Run SCIM regression tests**

Run:

```powershell
cargo test --locked scim --lib
```

Expected: all SCIM authentication, projection, filter, create/get/replace/patch/
delete, audit, deprovisioning, index, and cursor tests pass.

- [ ] **Step 6: Commit**

```powershell
git add src/http/scim.rs tests/in_source/src/http/tests/scim.rs
git commit -m "feat: implement RFC 9865 SCIM traversal"
```

### Task 4: Capability Truth and Documentation

**Files:**
- Modify: `src/http/scim.rs`
- Modify: `tests/in_source/src/http/tests/scim.rs`
- Modify: `docs/features/scim.md`
- Modify: `docs/conformance/2026-07-11-m8-watchlist-governance.md`
- Modify: `docs/protocol/rfc-compliance-matrix.md`
- Modify: `docs/protocol/profile-matrix.md`
- Modify: `docs/protocol/oauth-spec-implementation-backlog.md`
- Modify: `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: verified RFC 9865 runtime behavior.
- Produces: truthful capability output and repository documentation without an OIDF certification claim.

- [ ] **Step 1: Write a failing metadata test**

Change the service-provider test to require:

```rust
assert_eq!(body["pagination"]["cursor"], true);
assert_eq!(body["pagination"]["index"], true);
assert_eq!(body["pagination"]["defaultPaginationMethod"], "index");
assert_eq!(body["pagination"]["cursorTimeout"], 600);
```

Also assert RFC 9967 remains disabled.

- [ ] **Step 2: Run RED, update capability output, and run GREEN**

Run:

```powershell
cargo test --locked scim_service_provider --lib
```

Expected before implementation: `cursor` is false and timeout absent. Expected
after implementation: the targeted test passes.

- [ ] **Step 3: Update documentation**

Document index as default, forward-only cursor traversal, 600-second timeout,
actor/filter/count binding, deterministic order, no `previousCursor`, live
result-set semantics, and exact errors. Change the M8 evidence decision to
implemented/local evidence and retain the negative OIDF coverage finding.

- [ ] **Step 4: Verify no overclaim**

Run:

```powershell
rg -n "cursor.*false|RFC 9865.*(deferred|not implemented|selected for separate)" README.md README.zh-CN.md docs
rg -n "RFC 9865|cursorTimeout|nextCursor|previousCursor" README.md README.zh-CN.md docs
```

Expected: no stale disabled/deferred RFC 9865 claim outside historical design/
plan records; all current status documents describe forward-only support and no
OIDF certification.

- [ ] **Step 5: Commit**

```powershell
git add CHANGELOG.md README.md README.zh-CN.md src/http/scim.rs tests/in_source/src/http/tests/scim.rs docs
git commit -m "docs: record RFC 9865 SCIM support"
```

### Task 5: Full Verification

**Files:**
- Verify all files changed by Tasks 1 through 4.

**Interfaces:**
- Consumes: complete RFC 9865 implementation.
- Produces: fresh evidence that the branch satisfies code, test, documentation, and scope gates.

- [ ] **Step 1: Run targeted and full tests**

```powershell
cargo test --locked scim_cursor --lib
cargo test --locked scim --lib
cargo test --locked --lib
```

Expected: zero failures.

- [ ] **Step 2: Run Rust quality gates**

```powershell
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: every command exits zero with no clippy warning.

- [ ] **Step 3: Verify scope and diff hygiene**

```powershell
git diff origin/main...HEAD --check
git status --short
```

Inspect the complete diff. Confirm there is no migration, dependency, RFC 9967
runtime change, `previousCursor`, cursor authorization bypass, or unsupported
OIDF claim.

- [ ] **Step 4: Verify requirement coverage**

Re-read the approved design completion criteria and map each item to a passing
test or exact documentation/code evidence. Any gap returns to RED before
completion.
