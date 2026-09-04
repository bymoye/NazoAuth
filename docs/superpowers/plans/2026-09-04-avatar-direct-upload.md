# Avatar Direct Upload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an S3-compatible, browser-direct avatar upload path whose accepted bytes are published under an immutable object identifier only after the database avatar-reference CAS succeeds.

**Architecture:** `nazo-identity` owns the avatar state transitions and backend-neutral ports. The server owns HTTP, capability injection, and no S3 configuration or SDK types. A new concrete object-store adapter crate owns local-filesystem and S3-compatible implementations, S3 configuration, `rust-s3` signing and S3 I/O. `nazo-valkey` owns the tenant-scoped short-lived upload authorization record; PostgreSQL remains the sole authority for `users.avatar_url`.

**Tech Stack:** Rust 1.97.1, Actix Web, Valkey/fred, PostgreSQL CAS, `rust-s3` 0.37.2 for maintained SigV4 presigned POST and S3-compatible object I/O, MinIO for isolated integration proof.

## Global Constraints

- The `nazo-identity` and `nazo-oauth-server` crates must not import S3, bucket, signing, SQL, Diesel, or an S3 SDK type.
- Direct authorization returns only generic `url`, `method`, `fields`, `headers`, upload id, fixed object identifier, and expiry; HTTP callers do not receive credentials.
- A direct policy fixes the staging object identifier, private bucket/prefix, expiry, and `content-length-range` from zero through `AVATAR_MAX_BYTES`.
- MIME declarations are untrusted. Finalization reads the staged bytes with the same maximum bound, detects PNG/JPEG/WebP signatures, and writes those exact bytes to a new immutable final object before database CAS.
- The client receives no signing capability for a final object. Replaying a valid staging POST can only change staging data; it cannot overwrite the accepted final object.
- Keep server-multipart upload in local mode. Do not fall back from direct-capable object storage to local files.
- The authorization record remains readable through its TTL after a successful finalize, so retry can recognize its fixed final URL. Its expiry is enforced by Valkey TTL and S3 bucket lifecycle removes abandoned staging objects.
- Database uncertainty never triggers deletion of a candidate final object. Cleanup only considers expired staging prefixes and unreferenced immutable finals after an operator-safe retention policy.

## Touched shared integration surfaces

- `Cargo.toml`, `Cargo.lock`, `crates/nazoauth/Cargo.toml`, and `crates/nazoauth/src/main.rs`: register the concrete object-store launcher exactly once.
- `crates/authorization-server/src/cli.rs`, `config.rs`, `bootstrap/*`: generic launcher/config-extension composition and object-store bindings only.
- `crates/authorization-server/src/bootstrap/transient_state.rs`, `crates/authorization-server-valkey/src/lib.rs`, `crates/state-store-valkey/*`: add the narrow avatar-upload authorization port and Valkey implementation.

### Task 1: Replace mutable avatar-file promotion with immutable avatar state transitions

**Files:**
- Modify: `crates/identity/src/avatar.rs`
- Modify: `crates/identity/src/ports/avatar.rs`
- Modify: `crates/identity/src/ports.rs`
- Test: `crates/identity/tests/unit/avatar.rs`

**Interfaces:**
- Produces `AvatarObjectStorePort`, `AvatarUploadAuthorizationStorePort`, `AvatarUploadTarget`, and an object-safe `AvatarService`.
- `AvatarObjectStorePort` supports only prepare direct upload, bounded staged read, immutable final write, immutable final read, and best-effort post-CAS delete.

- [ ] **Step 1: Write failing identity behavior tests**

```rust
#[tokio::test]
async fn finalization_publishes_the_validated_staged_bytes_under_a_new_immutable_id() { /* fake ports assert byte equality and CAS */ }

#[tokio::test]
async fn repeated_finalization_returns_the_already_published_avatar() { /* same authorization and refreshed account */ }

#[tokio::test]
async fn finalization_rejects_non_image_bytes_before_database_cas() { /* staged text */ }
```

- [ ] **Step 2: Run the focused identity test target and verify each new test fails because the direct API does not exist.**

Run: `cargo test -p nazo-identity --test avatar`

Expected: FAIL from missing direct-upload service/port symbols.

- [ ] **Step 3: Implement the minimal immutable flow.**

```rust
// finalization: load authorization -> bind tenant/user/expiry -> bounded staged read
// -> detect actual image -> put immutable final id -> avatar URL CAS -> overview.
// If the refreshed account already references this authorization's final URL,
// return it without a second CAS.
```

- [ ] **Step 4: Run identity tests and verify all pass.**

Run: `cargo test -p nazo-identity --test avatar`

Expected: PASS.

### Task 2: Add tenant-scoped Valkey upload authorization state

**Files:**
- Modify: `crates/authorization-server/src/bootstrap/transient_state.rs`
- Modify: `crates/state-store-valkey/src/{lib.rs,keys.rs}`
- Create: `crates/state-store-valkey/src/avatar_upload.rs`
- Modify: `crates/authorization-server-valkey/src/lib.rs`
- Test: `crates/state-store-valkey/tests/avatar_upload_contract.rs`

**Interfaces:**
- Consumes `AvatarUploadAuthorizationStorePort` from Task 1.
- Produces `ServerTransientStateProvider::avatar_uploads()` backed by an expiring, tenant-scoped Valkey key.

- [ ] **Step 1: Write failing Valkey contract tests for save/load, expiry, tenant isolation, and corrupt-record failure.**
- [ ] **Step 2: Run the explicit Valkey test service test and verify failure is from the absent adapter.**

Run: `cargo test -p nazo-valkey --test avatar_upload_contract -- --ignored`

Expected: FAIL until the adapter exists; it must not return early when `VALKEY_URL` is absent.

- [ ] **Step 3: Store a serialized authorization under a namespaced random upload id with `SET EX`; load without consuming so retry remains possible until TTL.**
- [ ] **Step 4: Re-run the contract test against an isolated Valkey and verify PASS.**

### Task 3: Add the concrete object-store launcher and adapters

**Files:**
- Create: `crates/authorization-server-object-store/{Cargo.toml,src/lib.rs,src/local.rs,src/s3.rs}`
- Modify: workspace `Cargo.toml` and `Cargo.lock`
- Modify: `crates/authorization-server/src/{cli.rs,config.rs,bootstrap/*}`
- Modify: `crates/nazoauth/{Cargo.toml,src/main.rs}`
- Test: `crates/authorization-server-object-store/tests/{local.rs,s3_minio.rs}`

**Interfaces:**
- Consumes generic object-store launcher/binding types from the server and identity ports from Task 1.
- Produces `AvatarObjectStoreLauncher`; it selects an adapter statically from concrete configuration and binds one tenant-specific provider to each request runtime.

- [ ] **Step 1: Write failing adapter tests for local immutable put/read and direct S3 POST policy fields.**
- [ ] **Step 2: Verify failure before implementation.**

Run: `cargo test -p nazo-oauth-server-object-store --test local`

Expected: FAIL because the package and adapter are absent.

- [ ] **Step 3: Add `rust-s3 = 0.37.2` in this concrete crate only.** The S3 implementation builds a SigV4 presigned POST with exact key and `content-length-range`; uses configured endpoint, region, bucket, access key, secret key, and path style internally; it maps S3 failures to the generic storage error. The local implementation accepts server bytes and reports direct upload unavailable.
- [ ] **Step 4: Run local unit tests and a non-skipped isolated MinIO test.**

Run: `cargo test -p nazo-oauth-server-object-store --test local`

Run: `cargo test -p nazo-oauth-server-object-store --test s3_minio -- --ignored`

Expected: both PASS; the MinIO test must submit an actual multipart POST larger-than-limit rejection and valid upload acceptance.

### Task 4: Expose the direct HTTP contract while preserving local upload

**Files:**
- Modify: `crates/authorization-server/src/{http/profile/avatar.rs,bootstrap/routes.rs,bootstrap/profile_services.rs,bootstrap/startup/services/identity.rs}`
- Test: `crates/authorization-server/tests/unit/http/profile/avatar.rs`
- Create: `docs/operations/avatar-direct-upload.md`

**Interfaces:**
- `POST /auth/me/avatar/uploads` returns `{upload_id, expires_at, upload:{url,method,fields,headers}}` after CSRF/session validation.
- `POST /auth/me/avatar/uploads/{upload_id}/complete` validates CSRF/session, finalizes through Task 1, and returns the existing auth-me projection.

- [ ] **Step 1: Write failing HTTP behavior tests for CSRF, ownership, expiry, fixed target, invalid staged image, repeated completion, stale expected avatar, and cross-instance completion.**
- [ ] **Step 2: Run the focused test target and verify failure is due to absent routes/handlers.**

Run: `cargo test -p nazo-oauth-server --lib http::profile::avatar::tests`

Expected: FAIL until direct routes exist.

- [ ] **Step 3: Implement handlers with the existing session and OAuth error conventions; retain `POST /auth/me/avatar` as the local multipart route.**
- [ ] **Step 4: Document the caller sequence and the required S3 bucket policy/CORS/lifecycle rules.** No web client lives in this repository: `release/frontend.json` identifies a separate release artifact, so this document is its executable caller contract.
- [ ] **Step 5: Re-run focused HTTP tests and verify PASS.**

### Task 5: End-to-end isolated cross-instance proof and commit

**Files:**
- Create or modify: test-only isolated MinIO/Valkey harness under the owning crates
- Modify: `docs/operations/avatar-direct-upload.md`

- [ ] **Step 1: Start isolated MinIO and Valkey; use separate adapter/provider instances A and B with the same tenant namespace and bucket.**
- [ ] **Step 2: Authorize and POST from A, finalize from B, then read from B. Assert the database reference is the final immutable id and the response bytes equal the uploaded bytes.**
- [ ] **Step 3: Replay the signed staging POST after finalization; assert the final read remains the originally accepted bytes.**
- [ ] **Step 4: Exercise concurrent stale completion, invalid image, expired authorization, and database-error retry. Assert no referenced object is deleted.**
- [ ] **Step 5: Run formatting and scoped gates, inspect `git diff --check`, then commit the coherent slice.**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p nazo-identity --test avatar`

Run: `cargo test -p nazo-valkey --test avatar_upload_contract -- --ignored`

Run: `cargo test -p nazo-oauth-server-object-store --test s3_minio -- --ignored`

Run: `git diff --check`

Expected: all commands exit 0; do not treat skipped integration tests as evidence.

## Rollback and stop rules

The old local objects remain readable only until the compatible migration plan is explicitly supplied; this avatar slice does not silently delete them. Before a configuration rollback, stop direct-upload writers and preserve bucket lifecycle state. Stop if the concrete S3 provider cannot enforce the POST content-length condition, if a test service is unavailable rather than merely unconfigured, or if object writes cannot be made immutable by server-only final keys.
