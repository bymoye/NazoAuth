# Transport, Runtime Administration, and Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the one-binary cutover with thin Actix handlers, focused composition, revision-safe runtime administration, and the tested NazoAuthWeb management experience.

**Architecture:** Actix parses/presents and directly calls auth, identity, resource-server, or runtime-module services. The server is the only composition root. Runtime PATCH records desired intent and returns 202; per-instance reconcilers publish immutable snapshots and persist audited outcomes. The sibling React frontend consumes this API through the existing same-origin session/CSRF client.

**Tech Stack:** Rust 1.97.0, Actix Web, arc-swap, Tokio, PostgreSQL, Valkey Lua, React 19, TypeScript 6, Vite 8, Vitest, jsdom, React Testing Library.

## Global Constraints

- Complete the workspace foundation and domain/infrastructure plans first with green CI.
- Normal request path is handler -> focused service -> repository/store/signer -> presenter; no forwarding service layer.
- Static Actix routes preserve exact method/status/header/body/content-type/CORS/security-header behavior for disabled modules.
- Runtime desired mode is exactly `inherit | enabled | disabled`; PATCH returns 202 and never completion.
- Every async transition is revision-bound and revalidated before snapshot publication, drain completion, and final state persistence.
- Management write requires admin level >=2, CSRF, recent MFA, bounded reason, and expected revision.
- Frontend stores no session, MFA, module state, audit data, or secrets in local/session storage or IndexedDB.
- Use `rtk` for every local shell command and TDD for each behavior.

---

### Task 1: Extract the Actix transport crate and shortest handlers

**Files:**
- Create: `crates/http-actix/Cargo.toml`
- Create: `crates/http-actix/src/lib.rs`
- Move/adapt: `crates/authorization-server/src/http/` -> `crates/http-actix/src/endpoints/`
- Move/adapt: `crates/authorization-server/src/bootstrap/{routes,cors}.rs` -> `crates/http-actix/src/`
- Create: `crates/http-actix/src/{extract,present,middleware,request_context}.rs`
- Create: `crates/http-actix/src/resource_server.rs`
- Move/adapt HTTP tests into `crates/http-actix/tests/`
- Modify: `Cargo.toml`
- Modify: `crates/authorization-server/Cargo.toml`

**Interfaces:**
- Consumes: concrete auth/identity focused services, resource-server verifier, runtime snapshot handle.
- Produces: `HttpServices`, `configure_routes`, extractors, presenters, and Actix resource-server integration; no Diesel/Fred.

- [ ] **Step 1: Add a failing forbidden-import check**

The check fails if `crates/http-actix` contains `diesel`, `diesel_async`, `fred`, `DbPool`, database rows, or raw Valkey clients. Run before creation; expected failure because package is absent.

- [ ] **Step 2: Define focused transport inputs**

Use a concrete aggregate at route construction only:

```rust
pub struct HttpServices {
    pub authorization: std::sync::Arc<AuthorizationService>,
    pub tokens: std::sync::Arc<TokenService>,
    pub identity: std::sync::Arc<IdentityServices>,
    pub metadata: std::sync::Arc<MetadataService>,
    pub admin: std::sync::Arc<AdminService>,
    pub runtime_modules: std::sync::Arc<RuntimeModuleRegistry>,
    pub resource_server: std::sync::Arc<ResourceServerVerifier>,
}

pub fn configure_routes(cfg: &mut actix_web::web::ServiceConfig, services: &HttpServices);
```

Register each focused `web::Data<Arc<_>>` separately. Do not register `HttpServices` or the server composition aggregate as handler data.

- [ ] **Step 3: Move parsing/presentation and keep policy out**

Handlers may read Actix request/form/query/header/cookie data, load one module snapshot, call one focused service, and map typed output. Move OAuth error/redirect/browser/JSON presenters here. Move CORS, CSRF transport checks, proxy-derived context, cookies, and security headers here. Delete policy/query/key-management code from handlers as each endpoint moves.

- [ ] **Step 4: Restore the Actix resource-server adapter only here**

Implement extraction by converting Actix headers/method/URI into the framework-neutral `nazo-resource-server` input and map its typed error to the existing `WWW-Authenticate` response. Do not restore Tower/Tonic code.

- [ ] **Step 5: Verify and commit**

Run HTTP unit/integration tests, forbidden-import checks, workspace check, Clippy, and static route contracts. Commit `refactor: isolate actix transport`.

### Task 2: Replace giant settings/state with focused composition

**Files:**
- Move/adapt: `crates/authorization-server/src/config.rs` -> `crates/authorization-server/src/config/`
- Replace: `crates/authorization-server/src/settings.rs` and `crates/authorization-server/src/settings/`
- Create: `crates/authorization-server/src/config/{source,http,auth,identity,postgres,valkey,keys,observability}.rs`
- Replace: `crates/authorization-server/src/domain/state.rs`
- Modify: `crates/authorization-server/src/bootstrap/mod.rs`
- Modify: `crates/authorization-server/src/lib.rs`
- Modify: `crates/authorization-server/src/main.rs`
- Test: `crates/authorization-server/tests/configuration.rs`
- Test: `crates/authorization-server/tests/composition.rs`

**Interfaces:**
- Consumes: unchanged configuration namespace and concrete adapters/services.
- Produces: focused immutable settings and composition-root-only `AppModules`.

- [ ] **Step 1: Write failing configuration parity tests**

For every canonical config key, compare the pre-refactor fixture with focused parsing: default, environment override, YAML precedence, invalid type/value, and unknown-key rejection. Assert the canonical key set is byte-for-byte unchanged except explicitly added runtime-module operational settings if any.

- [ ] **Step 2: Define focused settings**

Create concrete immutable structs named `HttpSettings`, `AuthSettings`, `IdentitySettings`, `PostgresSettings`, `ValkeySettings`, `KeySettings`, and `ObservabilitySettings`. Each parser reads from `ConfigSource`; no service receives `ConfigSource` or a complete aggregate.

- [ ] **Step 3: Build only one composition aggregate**

```rust
pub struct AppModules {
    pub auth: nazo_auth::AuthServices,
    pub identity: nazo_identity::IdentityServices,
    pub runtime_modules: nazo_runtime_modules::RuntimeModuleRegistry,
}
```

Keep this type private to `nazo_oauth_server::bootstrap`. Construct adapters, then identity, auth, runtime catalog, HTTP services, and background tasks. Do not pass `AppModules`, pool, Fred client, or full settings into handlers.

- [ ] **Step 4: Delete the old giant state/settings**

After all consumers use focused values, delete `AppState`, the old `Settings`, and their glob/prelude exports. A repository-wide search for `AppState`, `settings.` field fan-out, and `support::prelude` must return no production matches.

- [ ] **Step 5: Verify and commit**

Run config/composition tests and full workspace gate. Commit `refactor: focus server composition and settings`.

### Task 3: Implement the revision-bound runtime registry and reconciliation

**Files:**
- Create: `crates/runtime-capabilities/src/{registry,catalog,reconcile,lease}.rs`
- Extend: `crates/runtime-capabilities/src/{model,snapshot,transition,repository}.rs`
- Create: `crates/runtime-capabilities/tests/{revision_races,disable_policies,audit}.rs`
- Create: `crates/authorization-server/src/runtime_modules.rs`
- Modify: `crates/authorization-server/src/bootstrap/mod.rs`
- Modify: `crates/authorization-server-core/src/metadata.rs`
- Modify module admission in auth/identity services

**Interfaces:**
- Consumes: `ModuleStateRepository`, fixed module specs, focused settings, concrete lifecycle callbacks where required.
- Produces: `RuntimeModuleRegistry::set_desired_mode`, `snapshot`, `events`, `reconcile_once`, per-module request leases, and background reconciliation.

- [ ] **Step 1: Write deterministic stale-transition tests**

Use barriers, not sleeps: pause revision 7 after initialization; publish desired revision 8; release revision 7; assert revision 7 emits `StaleTransitionDiscarded` and cannot publish a snapshot, complete drain, or persist final state. Repeat at all three checkpoints.

- [ ] **Step 2: Define the fixed catalog and all disable policies**

Construct one `ModuleSpec` per `ModuleId` with dependencies and the exact policy table from the design. Durations come from focused auth/identity settings. Validate acyclicity and reject disabling profile dependencies.

- [ ] **Step 3: Implement request leases and drains**

`FinishExecutingRequests` removes admission then waits for the snapshot generation's lease counter to reach zero. `DrainStoredTransactions` also queries the module-specific outstanding-state counter until zero or validated maximum duration. Deadline with valid remaining state produces `TransitionFailed`, not forced disable. `NotRuntimeDisableable` rejects the desired mutation before persistence.

- [ ] **Step 4: Implement exhaustive audit sequencing**

Desired API writes only `DesiredStateChanged`. Enable emits Started then Completed/Failed. Disable with drain emits Started, DrainStarted, DrainCompleted, then Completed; stale paths emit StaleTransitionDiscarded and no completion. Events carry module, revision, instance, actor/reason where applicable, and stable redacted outcome codes.

- [ ] **Step 5: Build metadata from the same snapshot**

`MetadataService` loads exactly one snapshot and produces typed metadata. Removing admission and metadata occurs in the same compare-and-publish. Tests race metadata and module calls and assert no snapshot advertises a capability whose new-work admission is absent.

- [ ] **Step 6: Verify and commit**

Run runtime unit/race tests repeatedly, auth metadata tests, and Clippy. Commit `feat: add revision-safe runtime module reconciliation`.

### Task 4: Harden MFA step-up and administrator hierarchy

**Files:**
- Modify: `crates/identity/src/{mfa,session,service,ports}.rs`
- Modify: `crates/persistence-postgres/src/repositories/{mfa,users,audit}.rs`
- Modify: `crates/state-store-valkey/src/stores/{session,rate_limit}.rs`
- Create: `crates/http-actix/src/endpoints/profile/mfa_step_up.rs`
- Modify: `crates/http-actix/src/routes.rs`
- Test: `crates/http-actix/tests/mfa_step_up.rs`
- Test: `crates/persistence-postgres/tests/admin_hierarchy.rs`
- Test: `crates/state-store-valkey/tests/session_rotation.rs`

**Interfaces:**
- Consumes: current session, trusted client context, identity MFA service, session/rate-limit stores.
- Produces: `POST /auth/me/mfa/step-up` with no-store and a `RecentMfaAdmin` authorization guard.

- [ ] **Step 1: Write failing security tests**

Cover per-user and per-IP rate limits, Valkey outage fail-closed, invalid code, same-step TOTP replay, concurrent backup-code reuse, audit redaction, session rotation conflict, old session rejection, CSRF mismatch, exact two-cookie rotation, five-minute freshness boundary, and no-store.

- [ ] **Step 2: Reuse atomic PostgreSQL MFA primitives**

Retain `last_used_step < candidate` conditional update and `used_at IS NULL` conditional backup update. Move them behind `MfaRepository`; do not implement an in-memory replay check. Emit redacted security events for success and every failure category.

- [ ] **Step 3: Bind CSRF to the elevated session**

Generate session ID and CSRF together, include the bound CSRF in the new session payload, and use one Lua compare-and-rotate to store the new payload/delete the old key. Set both cookies and return the same CSRF token only after Lua success. The elevated admin guard requires header/cookie/stored CSRF equality.

- [ ] **Step 4: Enforce admin hierarchy**

Level >=2 is required for runtime reads/writes. An admin cannot grant a level >= their own, alter an admin >= their level, or lower/disable themselves. Add negative tests for self-elevation, peer modification, and cross-tenant targets.

- [ ] **Step 5: Verify and commit**

Run focused security/concurrency tests, then workspace tests. Commit `fix: harden privileged admin step up`.

### Task 5: Add the runtime module Admin API with exact HTTP contracts

**Files:**
- Create: `crates/http-actix/src/endpoints/admin/runtime_modules.rs`
- Modify: `crates/http-actix/src/endpoints/admin/mod.rs`
- Modify: `crates/http-actix/src/routes.rs`
- Create: `crates/http-actix/tests/runtime_modules_api.rs`
- Create: `crates/http-actix/tests/disabled_module_routes.rs`
- Modify: `tests/contracts/routes.json`

**Interfaces:**
- Consumes: `RecentMfaAdmin`, `RuntimeModuleRegistry`, pagination/request context.
- Produces: GET list/events and PATCH desired-mode API; statically registered optional routes with locked disabled behavior.

- [ ] **Step 1: Write failing API tests**

Assert exact unauthenticated/level-1/stale-MFA/CSRF failures; tri-state parse; reason bounds; expected revision conflict; cascade dependency conflict; no-op audit; 202 body/Location/status URL; no-store; event pagination/redaction; and PATCH never returns completed state.

- [ ] **Step 2: Implement explicit wire types in the Actix crate**

```rust
#[derive(serde::Deserialize)]
struct PatchModuleRequest {
    desired_state: DesiredMode,
    expected_revision: u64,
    reason: String,
    #[serde(default)] cascade: bool,
}

#[derive(serde::Serialize)]
struct AcceptedModuleChange {
    module_id: ModuleId,
    desired_state: DesiredMode,
    revision: u64,
    actual_state: ModuleState,
    status_url: String,
}
```

The handler authenticates/presents only; registry owns transition/dependency policy.

- [ ] **Step 3: Statically register optional routes**

Register DCR and every optional endpoint regardless of initial desired mode. At entry, load one snapshot and reproduce the current disabled feature behavior.

- [ ] **Step 4: Lock the disabled HTTP matrix**

For each formerly conditional/flagged route test GET, POST, OPTIONS, and unsupported methods. Assert exact status, headers, body bytes/JSON, content type, CORS, security headers, Allow/WWW-Authenticate where applicable, and no-store. Initial config must produce the same behavior as baseline.

- [ ] **Step 5: Verify and commit**

Run the two HTTP test binaries, full HTTP tests, route contract verifier, and workspace gate. Commit `feat: add audited runtime module admin api`.

### Task 6: Discover and isolate the sibling frontend repository

**Files:**
- Modify: no source file yet; create a Git worktree and branch in the verified sibling repository.

**Interfaces:**
- Consumes: sibling `NazoAuthWeb` with exact GitHub remote and clean checkout.
- Produces: isolated `codex/runtime-module-admin` based on fetched `origin/main`.

- [ ] **Step 1: Resolve and verify without hard-coded absolute paths**

Resolve the backend's absolute common Git directory, take the parent of the checkout directory, and append only the sibling repository name. In PowerShell:

```text
$gitCommonDir = (rtk git rev-parse --path-format=absolute --git-common-dir).Trim()
$backendCheckout = Split-Path $gitCommonDir -Parent
$repositoryParent = Split-Path $backendCheckout -Parent
$frontendRepository = Join-Path $repositoryParent "NazoAuthWeb"
rtk git -C $frontendRepository status --short --branch
rtk git -C $frontendRepository remote get-url origin
rtk git -C $frontendRepository fetch origin --prune
rtk git -C $frontendRepository rev-parse origin/main
rtk git -C $frontendRepository branch --list codex/runtime-module-admin
rtk git -C $frontendRepository worktree list --porcelain
```

Expected: clean checkout; origin is exactly `https://github.com/nazozero/NazoAuthWeb`; fetched `origin/main` exists; target branch/worktree absent. Stop on any mismatch.

- [ ] **Step 2: Create the isolated frontend worktree using the worktree skill**

Use `superpowers:using-git-worktrees`, do not alter the existing checkout branch, and base the new branch on the fetched `origin/main`.

- [ ] **Step 3: Verify the frontend baseline**

Run `rtk npm ci`, `rtk npm run lint`, `rtk npm run build`, and current `rtk npm test`. Record that current `npm test` contains no component tests; do not claim otherwise.

### Task 7: Add real frontend tests and split the Admin page

**Files (NazoAuthWeb):**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `vitest.config.ts`
- Create: `src/test/setup.ts`
- Move/refactor: `src/pages/Admin.tsx` -> `src/pages/admin/AdminPage.tsx`
- Create: `src/pages/admin/{UsersPanel,ClientsPanel,AccessRequestsPanel,GrantsPanel,RuntimeModulesPanel}.tsx`
- Create: `src/pages/admin/runtimeModuleTypes.ts`
- Modify: `src/App.tsx`
- Modify relevant styles
- Create: `src/pages/admin/RuntimeModulesPanel.test.tsx`
- Create: `src/pages/admin/AdminPage.test.tsx`

**Interfaces:**
- Consumes: existing `apiFetch`, `AuthUser.admin_level`, runtime Admin API.
- Produces: focused admin panels and tested runtime control UI; no frontend service layer.

- [ ] **Step 1: Install the missing test capability**

Run:

```text
rtk npm install --save-dev vitest jsdom @testing-library/react @testing-library/jest-dom @testing-library/user-event
```

Set scripts exactly:

```json
{
  "test:unit": "vitest run",
  "test": "npm run lint && npm run test:unit && npm run build"
}
```

Configure jsdom and `src/test/setup.ts` importing `@testing-library/jest-dom/vitest`.

- [ ] **Step 2: Write failing privilege and accepted-state tests**

Mock only `apiFetch`, not the component's internal state. Assert level-1 users cannot see the tab; level-2 users can. Select `inherit`, enter reason, confirm, receive 202, and assert UI says accepted/pending—not enabled/disabled/completed—and polls GET for matching revision.

- [ ] **Step 3: Split the existing Admin page by real tab responsibility**

Move existing users, clients, access requests, and grants UI into focused panels without changing API paths or behavior. Keep `apiFetch` calls in panels/hooks colocated with real state; do not add `AdminService`, manager, command bus, or duplicate response models.

- [ ] **Step 4: Implement RuntimeModulesPanel**

Render desired mode separately from resolved/actual state, dependencies/dependents, revision, drain deadline, allowed actions, redacted failure, and audit events. Require reason, impact preview, confirmation, and expected revision. Cascade defaults false and requires a second confirmation.

- [ ] **Step 5: Implement MFA/conflict flows without replay**

On step-up-required, collect MFA code, call `/auth/me/mfa/step-up`, clear the code, and require the user to confirm the module mutation again. Never replay PATCH automatically. On 409 reload authoritative state and display conflict. Never write operational/auth data to browser storage.

- [ ] **Step 6: Implement bounded transition polling**

Poll only while actual state is Starting/Draining or applied revision lags accepted revision. Use bounded exponential intervals, cancel on unmount/hidden page, and stop on stable/failed state. Unit tests use fake timers and assert cancellation.

- [ ] **Step 7: Run frontend gates and commit**

```text
rtk npm ci
rtk npm run lint
rtk npm run test:unit
rtk npm run build
rtk npm test
```

Expected: all commands exit 0. Commit `feat: manage runtime modules from admin ui`.

### Task 8: Push and cross-link the coordinated Draft PRs

**Files:**
- Modify: backend and frontend Draft PR descriptions only.

**Interfaces:**
- Consumes: green backend and frontend phase gates.
- Produces: two pushed, cross-linked Draft PRs with accurate partial evidence.

- [ ] **Step 1: Run backend phase gate**

Run fmt/check/Clippy/test, HTTP E2E, migration tests, security/concurrency/fault tests, static contracts, audit, and deny.

- [ ] **Step 2: Run frontend phase gate from a clean install**

Delete no user files. Run `npm ci`, lint, unit, build, and `npm test`; inspect `git status` for only intended source/lock changes before commit/push.

- [ ] **Step 3: Use `github:yeet` separately in each repository**

Push both branches, create/update both Draft PRs, cross-link their URLs and exact head SHAs, and state that production/OIDF acceptance remains pending.
