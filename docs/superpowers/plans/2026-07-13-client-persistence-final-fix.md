# OAuth Client Persistence Final Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `nazo-postgres::OAuthClientRepository` the sole production owner of OAuth-client persistence and secret comparison, leaving server `ClientRow` as only an alias of the auth-owned runtime type.

**Architecture:** Private Diesel records and every `oauth_clients` read/write stay in `nazo-postgres`. Focused repository methods return domain clients, focused projections, pages, or booleans; no digest or full persistence record crosses the adapter boundary. Server handlers preserve their existing HTTP taxonomy, especially `401 invalid_client` for credential mismatch and `503 server_error` for repository failure.

**Tech Stack:** Rust, Diesel async, PostgreSQL, Actix Web, Valkey, HMAC-SHA256.

## Global Constraints

- No server `ClientRecord`, full persistence conversion, direct Diesel `oauth_clients` query, facade, manager, controller, trait object, or `block_on`.
- Preserve routes and DCR/admin/PAR/token/introspection/revocation/logout/application behavior.
- Preserve the existing `client-secret-v1:<salt>:<HMAC-SHA256>` peppered verifier format and compatibility.
- Repository secret checks expose only `bool`; storage failure remains `503`, mismatch remains `401`.
- Do not touch refresh behavior, frontend, push, deployment, or PR state.

---

### Task 1: Architecture and secret-behavior contracts

**Files:**
- Modify: `crates/persistence-postgres/tests/identity_repositories.rs`
- Modify: `crates/authorization-server/tests/in_source/src/http/token/tests/client_auth.rs`

**Interfaces:**
- Consumes: recursive source scan rooted at `crates/authorization-server/src`.
- Produces: contracts rejecting persistence-shaped client structs/conversions and semantic Diesel/raw-SQL OAuth-client access; default correct/wrong secret and store-failure tests.

- [ ] **Step 1: Write failing contracts** that recursively inspect Rust production files, excluding `schema.rs`, and reject `oauth_clients::`, Diesel operations whose source contains the OAuth-client table, raw SQL CRUD for that table, a client struct containing the sentinel fields `client_id`, `client_secret_hash`, `redirect_uris`, and `grant_types`, and record-to-domain field-copy conversions.
- [ ] **Step 2: Run RED:** `rtk cargo test -p nazo-postgres --test identity_repositories oauth_client --all-features --locked -- --nocapture`; expect failures naming server rows/DCR/admin/introspection/revocation/profile/seed residuals.
- [ ] **Step 3: Add default non-live auth tests** for correct candidate, wrong candidate, and unavailable repository; run the focused tests and record the expected pre-implementation failures.

### Task 2: Focused PostgreSQL repository operations

**Files:**
- Modify: `crates/persistence-postgres/src/repositories/clients.rs`
- Modify: `crates/persistence-postgres/src/repositories/mod.rs`
- Modify: `crates/persistence-postgres/src/lib.rs`
- Test: `crates/persistence-postgres/tests/identity_repositories.rs`

**Interfaces:**
- Consumes: `nazo_auth::{OAuthClient, ValidatedClientRegistration}` and tenant/client identifiers.
- Produces: focused create, page, update, DCR authenticate/rotate/replace/deactivate, application/logout projection, seed upsert, and secret-match methods. Secret methods return `Result<bool, RepositoryError>` and never expose verifier material.

- [ ] **Step 1: Add repository unit/integration tests** for insert/list/update/DCR operations, correct/wrong/missing secret equality, malformed metadata, and focused application/logout reads.
- [ ] **Step 2: Run RED** with `rtk cargo test -p nazo-postgres --all-features --locked -- --nocapture`; expect missing repository methods.
- [ ] **Step 3: Implement minimal private Diesel rows/commands** and focused methods. Keep `OAuthClientRecord` private; calculate/compare the unchanged verifier inside the security boundary and return only booleans.
- [ ] **Step 4: Run GREEN** for all PostgreSQL unit and live integration tests.

### Task 3: Server caller migration and row deletion

**Files:**
- Modify: `crates/authorization-server/src/domain/rows.rs`
- Modify: `crates/authorization-server/src/http/mod.rs`
- Modify: `crates/authorization-server/src/http/admin/clients/{create,list,update,detail}.rs`
- Modify: `crates/authorization-server/src/http/dynamic_client_registration.rs`
- Modify: `crates/authorization-server/src/http/token/{client_auth,dispatch,introspect,revoke}.rs`
- Modify: `crates/authorization-server/src/http/profile/{applications,oidc_logout}.rs`
- Modify: `crates/authorization-server/src/bin/nazo_oauth_seed_oidf.rs`
- Modify: affected in-source tests and fixtures under `crates/authorization-server/tests/in_source/src`

**Interfaces:**
- Consumes: Task 2 repository methods.
- Produces: direct focused repository calls at each handler/binary; `pub(crate) type ClientRow = nazo_auth::OAuthClient` only.

- [ ] **Step 1: Migrate DCR and admin create/list/update/detail** and run their focused tests after each caller group.
- [ ] **Step 2: Migrate client auth, PAR/token dispatch, introspection and revocation**, preserving `StoreUnavailable` to 503 and mismatch to 401; run focused tests after each group.
- [ ] **Step 3: Migrate profile application/logout and seed paths**, then delete `ClientRecord`, its conversion, and the production schema re-export/import token.
- [ ] **Step 4: Run architecture GREEN** and recursively confirm no server production Diesel/raw-SQL OAuth-client persistence access remains.

### Task 4: Real-service regression and completion evidence

**Files:**
- Modify: `.superpowers/sdd/domain-task-4-report.md`

**Interfaces:**
- Consumes: migrated server and repository.
- Produces: auditable RED/GREEN, live PostgreSQL/Valkey, workspace, docs, and commit evidence.

- [ ] **Step 1: Run focused DCR/admin/client-auth/PAR/token/introspect/revoke suites** including default correct/wrong secret and explicit 503 tests.
- [ ] **Step 2: Run real PostgreSQL/Valkey focused tests** and `nazo-postgres` integration tests.
- [ ] **Step 3: Run gates:** `rtk cargo fmt --all -- --check`, `rtk cargo check --workspace --all-targets --all-features --locked`, `rtk cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `rtk cargo test --workspace --all-features --locked`, and `rtk cargo doc --workspace --no-deps --all-features --locked`.
- [ ] **Step 4: Update the report** with exact results and the rejected 401 recommendation, commit logical code/test changes, then commit report evidence separately.
