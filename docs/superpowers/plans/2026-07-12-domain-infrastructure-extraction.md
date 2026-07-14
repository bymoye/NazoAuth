# Domain and Infrastructure Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract identity, authorization-server policy, key management, PostgreSQL, and Valkey into their final dependency boundaries while preserving behavior.

**Architecture:** Domain crates own models, policy, and only justified infrastructure ports. Concrete Diesel/Fred adapters implement those ports; database rows and Valkey serialization never cross their crate boundaries. The server monolith remains the temporary composition consumer until the Actix cutover plan.

**Tech Stack:** Rust 1.97.0, serde, chrono, uuid, jsonwebtoken, argon2, passkey-auth, Diesel 2.x/diesel-async, Fred 10.x, Tokio.

## Global Constraints

- Complete `2026-07-12-workspace-foundation.md` first with a green workspace and open Draft PR.
- Dependency direction is `auth -> identity, http-signatures, runtime-modules`; identity never depends on auth.
- Auth and identity never depend on Actix, Diesel, Fred, database rows, or complete server configuration.
- Key management depends on auth only for purpose-scoped signing contracts; auth never depends on key management.
- PostgreSQL rows never leave `nazo-postgres`; Valkey owns mechanism, not business policy.
- Do not add application/bridge/facade/orchestrator crates or one-implementation traits without an infrastructure/test boundary.
- Preserve all compatibility contracts and use TDD for every moved behavior or defect fix.
- Use `rtk` for every local shell command.

---

### Task 1: Extract the identity domain and minimal services

**Files:**
- Create: `crates/identity/Cargo.toml`
- Create: `crates/identity/src/lib.rs`
- Create: `crates/identity/src/model.rs`
- Create: `crates/identity/src/ports.rs`
- Create: `crates/identity/src/service.rs`
- Create: `crates/identity/src/{tenancy,mfa,session,passkey,email,federation,scim}.rs`
- Move/adapt tests from: `crates/authorization-server/tests/in_source/src/support/tests/{tenancy,mfa,sessions,passkeys,email}.rs`
- Move/adapt tests from: `crates/authorization-server/tests/in_source/src/http/scim/tests/{normalization,schema}.rs`
- Modify: `Cargo.toml`
- Modify: `crates/authorization-server/Cargo.toml`

**Interfaces:**
- Consumes: existing pure identity behavior and test fixtures.
- Produces: `Principal`, `AuthenticationContext`, `SubjectClaims`, identity services, and infrastructure ports with no auth/Actix/Diesel/Fred edge.

- [ ] **Step 1: Write failing domain-model tests**

Tests construct these types without database rows:

```rust
let principal = Principal {
    user_id: UserId::new(uuid::Uuid::nil()),
    tenant: TenantContext::default_system(),
    role: UserRole::Admin { level: 2 },
    active: true,
};
let context = AuthenticationContext::new(1_700_000_000, [AuthMethod::Password, AuthMethod::Mfa]);
assert!(context.has_mfa());
assert_eq!(principal.admin_level(), Some(2));
```

Run `rtk proxy cargo test -p nazo-identity`; expected failure because the package does not exist.

- [ ] **Step 2: Implement minimal public identity types**

Expose only:

```rust
pub struct UserId(uuid::Uuid);
pub struct TenantId(uuid::Uuid);
pub struct RealmId(uuid::Uuid);
pub struct OrganizationId(uuid::Uuid);
pub struct TenantContext { pub tenant_id: TenantId, pub realm_id: RealmId, pub organization_id: OrganizationId }
pub enum UserRole { User, Admin { level: u32 } }
pub struct Principal { pub user_id: UserId, pub tenant: TenantContext, pub role: UserRole, pub active: bool }
pub enum AuthMethod { Password, Passkey, Totp, BackupCode, RememberedMfa, Federated(String) }
pub struct AuthenticationContext { pub auth_time: i64, pub methods: Vec<AuthMethod>, pub oidc_sid: String }
pub struct SubjectClaims {
    pub subject: UserId,
    pub preferred_username: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub address: Option<PostalAddress>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub updated_at: i64,
}
pub struct PostalAddress {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}
```

Keep constructors validating non-empty IDs/`oidc_sid`, ordered de-duplicated AMR conversion, and tenant consistency. Do not export persistence IDs that protocol code does not need.

- [ ] **Step 3: Define only justified identity ports**

Create separate ports with method sets derived from current call sites and locked by adapter contract tests:

- `UserRepository`: tenant-scoped lookup by id/login/email, registration, profile update, activation/role update, and subject-claim projection; inputs and outputs are `UserId`, `TenantContext`, `Principal`, `SubjectClaims`, `NewUser`, or `ProfileUpdate`.
- `MfaRepository`: credential load/replace/delete, compare-and-set of the last accepted TOTP step, atomic backup-code consumption, and atomic replacement of backup-code hashes.
- `SessionStore`: create, load, compare-and-rotate session id plus CSRF token, update authentication context, and delete.
- `PasskeyRepository`: credential list/lookup/insert/counter update/delete with tenant and user ownership.
- `FederationRepository`: provider lookup plus external-identity-link insert/list/delete with uniqueness preserved.
- `ScimRepository`: tenant-scoped list/get/create/replace/patch/deactivate operations returning identity domain values.
- `EmailDelivery`: one `send_verification(VerificationMessage) -> Result<(), DeliveryError>` operation.

Use an object-safe async boundary only where the server stores multiple adapters or a test fake; otherwise use concrete repository structs. Every port has a concrete PostgreSQL/Valkey/email adapter and a test fake. Do not create an `IdentityService` trait or a forwarding repository service.

- [ ] **Step 4: Move pure policy with red/green tests**

Move TOTP calculation/normalization, backup-code normalization, tenant checks, email normalization/templates, SCIM normalization/schema values, authentication-context logic, and passkey ceremony validation. Leave Diesel/Fred/Actix calls in the server until adapter tasks.

Run:

```text
rtk proxy cargo test -p nazo-identity
rtk proxy cargo tree -p nazo-identity --depth 1
```

Expected: identity tests pass; forbidden direct dependencies are absent.

- [ ] **Step 5: Implement concrete `IdentityServices` without a trait**

Use a concrete aggregate of focused services:

```rust
pub struct IdentityServices {
    pub users: UserService,
    pub sessions: SessionService,
    pub mfa: MfaService,
    pub passkeys: PasskeyService,
    pub federation: FederationService,
    pub scim: ScimService,
}
```

Each service accepts only the ports it uses. A method that merely forwards one call is omitted; handlers may call the focused service directly.

- [ ] **Step 6: Verify and commit**

Run identity tests, server library tests, workspace check, Clippy, and the dependency-boundary checker. Commit:

```text
rtk git add Cargo.toml Cargo.lock crates/identity crates/authorization-server
rtk git commit -m "refactor: extract identity domain"
```

### Task 2: Extract authorization-server domain policy

**Files:**
- Create: `crates/authorization-server-core/Cargo.toml`
- Create: `crates/authorization-server-core/src/lib.rs`
- Create: `crates/authorization-server-core/src/{error,client,claims,authorization_details,profile,grant,authorization,token,metadata,sender_constraint,ports}.rs`
- Move/adapt: `crates/authorization-server/src/domain/{oauth,authorization_details}.rs`
- Move/adapt pure parts of: `crates/authorization-server/src/support/{oauth,oidc_claims,uri_policy,dpop,mtls,jwe}.rs`
- Move/adapt pure token-claim parts of: `crates/authorization-server/src/support/security/tokens.rs`
- Move/adapt corresponding tests into `crates/authorization-server-core/tests/`
- Modify: `Cargo.toml`
- Modify: `crates/authorization-server/Cargo.toml`

**Interfaces:**
- Consumes: minimal `nazo-identity` types, `nazo-runtime-modules::ActiveModuleSnapshot`, and `nazo-http-signatures` primitives.
- Produces: typed protocol requests/outcomes/errors, static grant/profile/sender policy, metadata builder, and auth persistence/signer ports.

- [ ] **Step 1: Write failing compile-boundary and protocol tests**

Add tests for exact OAuth error serialization data, authorization-details canonicalization, profile policy, claim fixtures, URI matching, and capability-driven metadata. Add a metadata fixture where desired CIBA is disabled but actual CIBA remains draining: metadata must omit CIBA while token polling for an existing transaction remains admissible.

Run `rtk proxy cargo test -p nazo-auth`; expected failure because the package does not exist.

- [ ] **Step 2: Define protocol errors and static policy**

Use:

```rust
pub enum ProtocolErrorCode {
    InvalidRequest, InvalidClient, InvalidGrant, UnauthorizedClient,
    UnsupportedGrantType, InvalidScope, AccessDenied, ServerError,
    TemporarilyUnavailable,
}
pub struct ProtocolError { pub code: ProtocolErrorCode, pub description: &'static str }
pub enum GrantType { AuthorizationCode, RefreshToken, ClientCredentials, DeviceCode, TokenExchange, JwtBearer, Ciba }
pub enum SecurityProfile { Baseline, Fapi2Security, Fapi2MessageSigning }
pub enum SenderConstraintPolicy { BearerAllowed, DpopRequired, MtlsRequired, DpopOrMtls }
```

Keep Actix status/header/redirect mapping out of this crate. Use exhaustive matches, not grant/profile trait objects.

- [ ] **Step 3: Define auth ports by infrastructure boundary**

Create `ClientRepository`, `GrantRepository`, `TokenRepository`, `AuthorizationStateStore`, `ReplayStore`, `RateLimitStore`, and `Signer` traits. `Signer` uses purpose-scoped input:

```rust
pub enum SigningPurpose { AccessToken, IdToken, Jarm, LogoutToken, HttpMessage }
pub struct SignRequest<'a> { pub purpose: SigningPurpose, pub algorithm: &'a str, pub signing_input: &'a [u8] }
pub trait Signer: Send + Sync { async fn sign(&self, request: SignRequest<'_>) -> Result<Signature, SignError>; }
```

Do not expose key handles or a generic “sign anything” API.

- [ ] **Step 4: Move pure behavior one module at a time**

For each of authorization details, URI policy, claims, client policy, DPoP/mTLS evidence models, grant dispatch, and metadata: move its existing tests first, observe the expected import/package failure, move the production code, then rerun the focused test. Delete the old module immediately after its final caller changes; do not leave re-export facades.

- [ ] **Step 5: Implement direct auth-to-identity service calls**

Auth methods that need principal/claims/MFA context accept `&IdentityServices` or the exact focused identity service. Do not introduce an application bridge. Tests use identity port fakes through the concrete identity service.

- [ ] **Step 6: Verify and commit**

Run:

```text
rtk proxy cargo test -p nazo-auth
rtk proxy cargo tree -p nazo-auth --depth 1
rtk proxy cargo check --workspace --all-targets --all-features --locked
rtk proxy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: no Actix/Diesel/Fred/row dependency. Commit `refactor: extract authorization server domain`.

### Task 3: Extract purpose-scoped key management

**Files:**
- Create: `crates/key-management/Cargo.toml`
- Create: `crates/key-management/src/lib.rs`
- Create: `crates/key-management/src/{model,store,lifecycle,local,external,jwks}.rs`
- Move/adapt: `crates/authorization-server/src/domain/keyset.rs`
- Move/adapt: `crates/authorization-server/src/support/keyset.rs`
- Move/adapt: `crates/authorization-server/src/support/keyset/external.rs`
- Move/adapt key tests into `crates/key-management/tests/`
- Modify: `crates/authorization-server/src/bootstrap/mod.rs`
- Modify: `crates/authorization-server/Cargo.toml`

**Interfaces:**
- Consumes: `nazo_auth::Signer`, `SigningPurpose`, and focused key settings.
- Produces: `KeyManager`, immutable verification/JWKS snapshots, local/external signer implementations, and lifecycle task.

- [ ] **Step 1: Add failing signing-purpose tests**

Assert that a key policy allowed for `IdToken` cannot be used for `HttpMessage`, retired keys cannot sign, grace keys verify but do not sign, an external signer timeout is fail-closed, and JWKS contains only publishable public material.

- [ ] **Step 2: Implement explicit lifecycle model**

```rust
pub enum KeyState { Prepublished, Active, Grace, Retired }
pub struct ManagedKey {
    pub kid: String,
    pub algorithm: String,
    pub purposes: BTreeSet<SigningPurpose>,
    pub state: KeyState,
    handle: KeyHandle,
}
pub struct KeyManager {
    snapshot: arc_swap::ArcSwap<KeySnapshot>,
    store: std::sync::Arc<dyn KeyStore>,
    backend: std::sync::Arc<dyn SigningBackend>,
}
```

The manager implements `Signer`; there is no public private-key accessor.

- [ ] **Step 3: Move lifecycle and I/O**

Move atomic file writes, loading, generation, prepublication, activation, grace/retirement, external-command protocol, verification, and JWKS. Preserve existing filenames and JSON/PEM formats. Move the background refresh task from bootstrap behind `KeyManager::run_lifecycle`.

- [ ] **Step 4: Verify and commit**

Run key-management tests, external signer fault tests, server tests, and dependency tree inspection. Commit `refactor: isolate key management boundary`.

### Task 4: Extract PostgreSQL rows and identity repositories

**Files:**
- Create: `crates/persistence-postgres/Cargo.toml`
- Create: `crates/persistence-postgres/src/lib.rs`
- Move: `crates/authorization-server/src/db.rs` -> `crates/persistence-postgres/src/pool.rs`
- Move: `crates/authorization-server/src/schema.rs` -> `crates/persistence-postgres/src/schema.rs`
- Move/adapt identity rows from `crates/authorization-server/src/domain/rows.rs` -> `crates/persistence-postgres/src/rows/identity.rs`
- Create: `crates/persistence-postgres/src/repositories/{users,mfa,passkeys,federation,scim}.rs`
- Create: `crates/persistence-postgres/src/convert/identity.rs`
- Modify all identity callers under `crates/authorization-server/src/`
- Test: `crates/persistence-postgres/tests/identity_repositories.rs`

**Interfaces:**
- Consumes: identity repository traits/domain types.
- Produces: Diesel implementations and explicit private row conversions.

- [ ] **Step 1: Write transaction and row-leak tests**

Add PostgreSQL integration tests for tenant-scoped user lookup, TOTP last-step CAS under concurrency, backup-code one-time consumption, passkey uniqueness, SCIM mutation transactions, and federation-link uniqueness. Add a compile-fail/API check that row types are not public.

- [ ] **Step 2: Move pool/schema/rows privately**

`rows` and `schema` modules remain `pub(crate)`. Only repository structs and pool/migration constructors are public. Replace every handler use of a row with a domain type returned by a repository.

- [ ] **Step 3: Implement explicit conversions**

Use `TryFrom<UserRow> for Principal` and separate conversion to `SubjectClaims`; never serialize a row directly. Reject invalid role/admin/tenant data as consistency errors instead of coercing it.

- [ ] **Step 4: Move identity transactions**

MFA verify/consume, backup-code replacement, SCIM writes, access-request approval identity effects, and federation-link changes use one connection transaction for required multi-write atomicity.

- [ ] **Step 5: Verify and commit**

Run the PostgreSQL service integration tests against the configured test database, workspace tests, and `cargo doc -p nazo-postgres --no-deps` to confirm rows are absent from public docs. Commit `refactor: isolate postgres identity repositories`.

### Task 5: Extract PostgreSQL auth/runtime repositories and migrations

**Files:**
- Create: `crates/persistence-postgres/src/rows/{auth,runtime}.rs`
- Create: `crates/persistence-postgres/src/repositories/{clients,grants,tokens,authorization,runtime_modules,audit}.rs`
- Create: `crates/persistence-postgres/src/convert/auth.rs`
- Create: `migrations/20260712000100_runtime_module_state/up.sql`
- Create: `migrations/20260712000100_runtime_module_state/down.sql` (the directory timestamp follows baseline `20260711000100_oidc_response_crypto_metadata`)
- Modify: `crates/authorization-server/src/bin/nazo_oauth_migrate.rs`
- Modify auth callers under `crates/authorization-server/src/`
- Test: `crates/persistence-postgres/tests/{auth_repositories,runtime_modules,migrations}.rs`

**Interfaces:**
- Consumes: auth repository ports and runtime-module repository port.
- Produces: concrete PostgreSQL adapters, migration runner, revision CAS, instance-state CAS, and exhaustive audit persistence.

- [ ] **Step 1: Write failing repository/transaction tests**

Cover client lookup, grant upsert/revoke, refresh-family rotation/reuse, authorization-code state transactions, introspection/revocation, module tri-state resolution records, stale revision 409 source error, stale instance transition rejection, and all seven event kinds.

- [ ] **Step 2: Add the additive migration**

Create tables with database check constraints for `inherit/enabled/disabled`, the five actual states, and the seven event types. Use `(instance_id, module_id)` uniqueness, monotonically increasing desired revision, foreign-key actor where available, bounded reason/error fields, and time indexes. Down migration drops only the new tables/indexes.

- [ ] **Step 3: Implement CAS in one transaction**

Desired mutation locks the row, verifies `expected_revision`, writes the next revision/mode, and appends `DesiredStateChanged` atomically. A no-op keeps revision stable and appends a `noop` event. Instance-state/event completion uses `WHERE transition_revision = $expected` and must return stale rather than overwrite.

- [ ] **Step 4: Move auth queries out of handlers**

Move queries by repository responsibility and return auth/identity domain types. Delete every Diesel import from handler and domain files as its query moves. Do not add a generic repository wrapper.

- [ ] **Step 5: Verify migration compatibility and commit**

Run `rtk python scripts/verify_static_contracts.py --append-migration 20260712000100_runtime_module_state`, then run fresh migration, upgrade from the baseline schema, down/up for only the new migration, repository integration tests, and `rtk python scripts/verify_static_contracts.py --check`. Confirm the checksum diff only appends the new `up.sql` and `down.sql` records. Commit `refactor: isolate postgres auth and runtime repositories`.

### Task 6: Extract Valkey mechanisms behind focused stores

**Files:**
- Create: `crates/state-store-valkey/Cargo.toml`
- Create: `crates/state-store-valkey/src/lib.rs`
- Move/adapt: `crates/authorization-server/src/support/valkey.rs`
- Move/adapt: `crates/authorization-server/src/support/redis_keys.rs`
- Create: `crates/state-store-valkey/src/{connection,command,error,keys}.rs`
- Create: `crates/state-store-valkey/src/stores/{session,authorization,replay,rate_limit,ciba,device,delivery}.rs`
- Move Lua scripts from callers into their owning store modules
- Move/adapt Valkey tests into `crates/state-store-valkey/tests/`
- Modify: callers under `crates/authorization-server/src/`

**Interfaces:**
- Consumes: auth/identity store ports and exact existing key/payload/TTL contracts.
- Produces: Fred adapters with typed infrastructure errors and no HTTP/business policy.

- [ ] **Step 1: Write failing key/payload/Lua contract tests**

For every store, assert exact key bytes, JSON serialization, TTL boundary, NX/GETDEL/CAS result parsing, and failure behavior. Preserve existing Lua text semantics and add concurrent tests for session rotation, authorization-code transitions, replay, CIBA/Device state, and rate counters.

- [ ] **Step 2: Move connection and primitive commands**

Expose no raw Fred client outside this crate. Primitive helpers remain private; public store structs implement domain ports. Map timeout/unavailable/protocol/unexpected-result separately.

- [ ] **Step 3: Keep policy outside**

Move only storage actions. Auth/identity callers still decide rate thresholds, nonce consumption timing, session rotation eligibility, module activation, and OAuth errors.

- [ ] **Step 4: Run fault and concurrency tests**

Run Valkey tests with the service available, then the repository failure-injection script with Valkey stopped. Expected: sensitive paths fail closed with the established public contract.

- [ ] **Step 5: Verify no Fred leakage and commit**

Use `rtk rg -n 'fred::|ValkeyClient' crates --glob '*.rs'`; expected matches only under `crates/state-store-valkey`. Run workspace check/tests/Clippy and commit `refactor: isolate valkey stores`.

### Task 7: Complete the domain/infrastructure phase gate

**Files:**
- Modify: Draft PR description with verified phase results.

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces: green domain/adapter boundaries pushed for CI.

- [ ] **Step 1: Run boundary searches**

```text
rtk rg -n 'actix|diesel|fred' crates/authorization-server-core crates/identity crates/runtime-capabilities crates/resource-server -g '*.rs' -g 'Cargo.toml'
rtk rg -n 'pub .*Row|pub mod rows|pub use .*\*' crates -g '*.rs'
```

Expected: no forbidden dependency; no public row or glob re-export.

- [ ] **Step 2: Run the complete Rust phase gate**

Run fmt, workspace check, Clippy with denied warnings, workspace tests, PostgreSQL integration tests, Valkey concurrency/failure tests, `cargo audit`, `cargo deny`, and static contracts.

- [ ] **Step 3: Commit any documentation generated by actual boundaries, push, and inspect CI**

Do not claim the Actix cutover or deployment is complete. Update the Draft PR only with commands and results actually observed.
