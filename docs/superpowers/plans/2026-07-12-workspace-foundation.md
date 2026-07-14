# Workspace Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish compatibility contracts and the first compiler-enforced Workspace boundaries without changing deployed behavior.

**Architecture:** Convert the root package into a virtual resolver-3 workspace while keeping the existing server monolith compiling inside `crates/authorization-server`. Add the real cross-domain runtime state-machine crate, extract the independent resource-server core, and retain/rename the reusable HTTP Signatures primitive.

**Tech Stack:** Rust 1.97.0, Cargo resolver 3, Actix Web, serde, arc-swap, jsonwebtoken, proptest, GitHub Actions.

## Global Constraints

- Use exact Rust stable `1.97.0` in `rust-toolchain.toml`, CI, and `Containerfile`; never use a floating `stable` production toolchain.
- Preserve every existing HTTP/configuration/PostgreSQL/Valkey/claims/error/metadata behavior unless a task explicitly introduces a documented and tested addition.
- Never edit an existing migration file.
- No empty crate, cross-crate glob re-export, workspace-wide prelude, dynamic-library plugin, RPC, message bus, command bus, or forwarding-only facade.
- `nazo-runtime-modules` must not depend on auth, identity, Actix, Diesel, or Fred.
- `nazo-resource-server` must not depend on auth, identity, or a Web framework.
- Observe TDD red/green/refactor for every production behavior change and run the task-specific test before committing.
- Use `rtk` for every local shell command under the repository rules.

---

### Task 1: Lock the pre-refactor compatibility surface

**Files:**
- Create: `tests/contracts/routes.json`
- Create: `tests/contracts/migrations.sha256`
- Create: `scripts/verify_static_contracts.py`
- Modify: `tests/in_source/src/config/tests/config.rs`
- Modify: `tests/in_source/src/support/tests/redis_keys.rs`
- Modify: `tests/in_source/src/support/tests/security/token_claims.rs`
- Modify: `tests/in_source/src/http/tests/well_known.rs`
- Modify: `.github/workflows/code-quality.yml`
- Modify: `.github/workflows/conformance-security.yml`

**Interfaces:**
- Consumes: current route table, canonical config list, migration files, key builders, token-claim constructors, and metadata constructors at baseline `413e18f`.
- Produces: reviewed fixtures that later crate moves must continue to satisfy; `python scripts/verify_static_contracts.py --check`.

- [ ] **Step 1: Add exact behavioral assertions before moving code**

Extend the existing Rust test files with tables whose values come from the current passing baseline. Use the existing fixture constructors and assert complete values, not subsets. The route fixture is complete and reviewed as one entry per path. `methods` is sorted and `condition` is one of `always`, `dynamic_client_registration`, or `perf_metrics`:

```json
{
  "schema": 1,
  "routes": [
    {"path":"/health","methods":["GET"],"condition":"always"},
    {"path":"/authorize","methods":["GET","POST"],"condition":"always"},
    {"path":"/authorize/consent","methods":["GET"],"condition":"always"},
    {"path":"/authorize/decision","methods":["POST"],"condition":"always"},
    {"path":"/par","methods":["POST"],"condition":"always"},
    {"path":"/bc-authorize","methods":["POST"],"condition":"always"},
    {"path":"/ciba/{auth_req_id}","methods":["GET"],"condition":"always"},
    {"path":"/device_authorization","methods":["POST"],"condition":"always"},
    {"path":"/device","methods":["GET"],"condition":"always"},
    {"path":"/device/verification","methods":["GET"],"condition":"always"},
    {"path":"/device/decision","methods":["POST"],"condition":"always"},
    {"path":"/token","methods":["POST"],"condition":"always"},
    {"path":"/logout","methods":["GET","POST"],"condition":"always"},
    {"path":"/check_session","methods":["GET"],"condition":"always"},
    {"path":"/check_session/status","methods":["GET"],"condition":"always"},
    {"path":"/revoke","methods":["POST"],"condition":"always"},
    {"path":"/introspect","methods":["POST"],"condition":"always"},
    {"path":"/fapi/resource","methods":["GET","POST"],"condition":"always"},
    {"path":"/.well-known/openid-configuration","methods":["GET"],"condition":"always"},
    {"path":"/.well-known/oauth-authorization-server","methods":["GET"],"condition":"always"},
    {"path":"/.well-known/oauth-protected-resource","methods":["GET"],"condition":"always"},
    {"path":"/.well-known/oauth-protected-resource/{tail:.*}","methods":["GET"],"condition":"always"},
    {"path":"/jwks.json","methods":["GET"],"condition":"always"},
    {"path":"/userinfo","methods":["GET","POST"],"condition":"always"},
    {"path":"/scim/v2/ServiceProviderConfig","methods":["GET"],"condition":"always"},
    {"path":"/scim/v2/Schemas","methods":["GET"],"condition":"always"},
    {"path":"/scim/v2/ResourceTypes","methods":["GET"],"condition":"always"},
    {"path":"/scim/v2/Users","methods":["GET","POST"],"condition":"always"},
    {"path":"/scim/v2/Users/{user_id}","methods":["DELETE","GET","PATCH","PUT"],"condition":"always"},
    {"path":"/auth/captcha-config","methods":["GET"],"condition":"always"},
    {"path":"/auth/send-code","methods":["POST"],"condition":"always"},
    {"path":"/auth/register","methods":["POST"],"condition":"always"},
    {"path":"/auth/login","methods":["POST"],"condition":"always"},
    {"path":"/auth/federation/providers","methods":["GET"],"condition":"always"},
    {"path":"/auth/federation/saml/acs","methods":["POST"],"condition":"always"},
    {"path":"/auth/federation/{provider_id}/start","methods":["GET"],"condition":"always"},
    {"path":"/auth/federation/{provider_id}/callback","methods":["GET"],"condition":"always"},
    {"path":"/auth/passkey/begin","methods":["POST"],"condition":"always"},
    {"path":"/auth/passkey/finish","methods":["POST"],"condition":"always"},
    {"path":"/auth/mfa/verify","methods":["POST"],"condition":"always"},
    {"path":"/auth/csrf","methods":["GET"],"condition":"always"},
    {"path":"/auth/me","methods":["GET","PATCH"],"condition":"always"},
    {"path":"/auth/me/passkeys","methods":["GET"],"condition":"always"},
    {"path":"/auth/me/passkeys/registration/begin","methods":["POST"],"condition":"always"},
    {"path":"/auth/me/passkeys/registration/finish","methods":["POST"],"condition":"always"},
    {"path":"/auth/me/passkeys/{passkey_id}","methods":["DELETE"],"condition":"always"},
    {"path":"/auth/me/mfa/totp/begin","methods":["POST"],"condition":"always"},
    {"path":"/auth/me/mfa/totp/confirm","methods":["POST"],"condition":"always"},
    {"path":"/auth/me/mfa/backup-codes/regenerate","methods":["POST"],"condition":"always"},
    {"path":"/auth/me/mfa/disable","methods":["POST"],"condition":"always"},
    {"path":"/auth/me/avatar","methods":["DELETE","GET","POST"],"condition":"always"},
    {"path":"/auth/me/applications","methods":["GET"],"condition":"always"},
    {"path":"/auth/me/federation/links","methods":["GET"],"condition":"always"},
    {"path":"/auth/me/federation/links/{link_id}","methods":["DELETE"],"condition":"always"},
    {"path":"/auth/me/access-requests","methods":["GET","POST"],"condition":"always"},
    {"path":"/auth/me/access-delivery","methods":["GET"],"condition":"always"},
    {"path":"/auth/ciba-automated-decision","methods":["GET","POST"],"condition":"always"},
    {"path":"/auth/ciba/automated","methods":["GET","POST"],"condition":"always"},
    {"path":"/auth/ciba/{auth_req_id}","methods":["GET","POST"],"condition":"always"},
    {"path":"/auth/logout","methods":["POST"],"condition":"always"},
    {"path":"/admin/users","methods":["GET"],"condition":"always"},
    {"path":"/admin/users/{user_id}","methods":["PATCH"],"condition":"always"},
    {"path":"/admin/clients","methods":["GET","POST"],"condition":"always"},
    {"path":"/admin/clients/{client_id}","methods":["GET","PATCH"],"condition":"always"},
    {"path":"/admin/federation/providers","methods":["GET"],"condition":"always"},
    {"path":"/admin/grants","methods":["GET"],"condition":"always"},
    {"path":"/admin/grants/revoke","methods":["POST"],"condition":"always"},
    {"path":"/admin/access-requests","methods":["GET"],"condition":"always"},
    {"path":"/admin/access-requests/{request_id}/approve","methods":["POST"],"condition":"always"},
    {"path":"/admin/access-requests/{request_id}/reject","methods":["POST"],"condition":"always"},
    {"path":"/register","methods":["POST"],"condition":"dynamic_client_registration"},
    {"path":"/register/{client_id}","methods":["DELETE","GET","PUT"],"condition":"dynamic_client_registration"},
    {"path":"/__perf/metrics","methods":["GET"],"condition":"perf_metrics"}
  ]
}
```

Compare this reviewed fixture to the route table in the same commit. Later additions use additive entries; moved routes retain their exact path, method set, and condition.

- [ ] **Step 2: Add the static contract verifier**

Create `scripts/verify_static_contracts.py` with these concrete entry points:

```python
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
CHECKSUMS = ROOT / "tests" / "contracts" / "migrations.sha256"
ROUTES = ROOT / "tests" / "contracts" / "routes.json"


def migration_line(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"{digest}  {path.relative_to(ROOT).as_posix()}"


def migration_lines() -> list[str]:
    return [migration_line(path) for path in sorted(MIGRATIONS.glob("*/*.sql"))]


def write_migration_checksums() -> None:
    if CHECKSUMS.exists():
        raise SystemExit("checksum manifest already exists; use --append-migration")
    CHECKSUMS.write_text("\n".join(migration_lines()) + "\n", encoding="utf-8")


def check_migration_checksums() -> None:
    expected = [line for line in CHECKSUMS.read_text(encoding="utf-8").splitlines() if line]
    actual = migration_lines()
    if actual != expected:
        raise SystemExit("migration history or manifest changed unexpectedly")


def append_migration(directory_name: str) -> None:
    directory = MIGRATIONS / directory_name
    paths = sorted(directory.glob("*.sql"))
    if [path.name for path in paths] != ["down.sql", "up.sql"]:
        raise SystemExit("new migration must contain exactly down.sql and up.sql")
    expected = [line for line in CHECKSUMS.read_text(encoding="utf-8").splitlines() if line]
    recorded_paths = [line.split("  ", 1)[1] for line in expected]
    recorded_directories = [Path(path).parent.name for path in recorded_paths]
    if directory_name in recorded_directories or directory_name <= max(recorded_directories):
        raise SystemExit("migration append must use a new monotonically later directory")
    CHECKSUMS.write_text(
        "\n".join([*expected, *(migration_line(path) for path in paths)]) + "\n",
        encoding="utf-8",
    )


def check_route_fixture() -> None:
    payload = json.loads(ROUTES.read_text(encoding="utf-8"))
    if payload.get("schema") != 1 or not payload.get("routes"):
        raise SystemExit("route contract fixture is missing or invalid")
    paths = [item["path"] for item in payload["routes"]]
    if len(paths) != len(set(paths)):
        raise SystemExit("route contract contains duplicate paths")
    for item in payload["routes"]:
        methods = item.get("methods")
        if not methods or methods != sorted(set(methods)):
            raise SystemExit("route methods must be non-empty, unique, and sorted")
        if item.get("condition") not in {"always", "dynamic_client_registration", "perf_metrics"}:
            raise SystemExit("route condition is invalid")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-migrations", action="store_true")
    parser.add_argument("--append-migration")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write_migrations:
        write_migration_checksums()
    if args.append_migration:
        append_migration(args.append_migration)
    if args.check:
        check_migration_checksums()
        check_route_fixture()


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Generate and review immutable migration checksums**

Run:

```text
rtk python scripts/verify_static_contracts.py --write-migrations
rtk python scripts/verify_static_contracts.py --check
```

Expected: both commands exit 0; the checksum file lists every existing `up.sql` and `down.sql` exactly once.

- [ ] **Step 4: Run focused contract tests**

Run:

```text
rtk proxy cargo +1.97.0 test --locked --lib
```

Expected: the complete library test suite passes, including the new assertions for canonical keys, exact Valkey keys, exact claims, and exact metadata.

- [ ] **Step 5: Wire the verifier into CI and commit**

Add this step before compilation in both workflows:

```yaml
- name: Verify compatibility contracts
  run: python scripts/verify_static_contracts.py --check
```

Run `rtk git diff --check`, then commit:

```text
rtk git add tests/contracts scripts/verify_static_contracts.py tests/in_source .github/workflows
rtk git commit -m "test: lock compatibility contracts"
```

### Task 2: Pin the toolchain and convert to a virtual workspace

**Files:**
- Create: `rust-toolchain.toml`
- Create: `crates/authorization-server/Cargo.toml`
- Move: `src/` -> `crates/authorization-server/src/`
- Move: `tests/in_source/` -> `crates/authorization-server/tests/in_source/`
- Modify: `Cargo.toml`
- Modify: `.github/workflows/code-quality.yml`
- Modify: `.github/workflows/codecov.yml`
- Modify: `.github/workflows/codeql.yml`
- Modify: `.github/workflows/conformance-security.yml`
- Modify: `.github/workflows/dependency-review.yml`
- Modify: `.github/workflows/oidf-conformance.yml`
- Modify: `.github/workflows/oidf-conformance-full.yml`
- Modify: `.github/workflows/oidf-public-seed-configs.yml`
- Modify: `.github/workflows/release-security.yml`
- Modify: `.github/workflows/spec-freshness.yml`
- Modify: `Containerfile`
- Modify: `codecov.yml`
- Modify: `scripts/generate_codecov_lcov.sh`

**Interfaces:**
- Consumes: the complete existing `nazo-oauth-server` package unchanged.
- Produces: virtual root workspace, default member `crates/authorization-server`, and the same binary names and operator commands.

- [ ] **Step 1: Add the exact toolchain file**

Create:

```toml
[toolchain]
channel = "1.97.0"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

Replace every `dtolnay/rust-toolchain@1.96.0` input and builder image `rust:1.96-slim` with `1.97.0` equivalents.

- [ ] **Step 2: Move the package without changing module contents**

Run:

```text
rtk git mv src crates/authorization-server/src
rtk git mv tests/in_source crates/authorization-server/tests/in_source
```

Copy the current `[package]`, binaries, dependencies, and dev-dependencies into `crates/authorization-server/Cargo.toml`. Change only relative paths required by the move. Keep package name `nazo-oauth-server` and all binary names.

- [ ] **Step 3: Replace the root manifest**

The root `Cargo.toml` must have this shape:

```toml
[workspace]
members = [
    "crates/authorization-server",
    "crates/fapi-http-signatures",
]
default-members = ["crates/authorization-server"]
resolver = "3"

[workspace.package]
edition = "2024"
license = "AGPL-3.0-or-later"
repository = "https://github.com/nazozero/NazoAuth"

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }

[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

Set `[lints] workspace = true` in every member manifest.

- [ ] **Step 4: Fix paths mechanically and prove behavior is unchanged**

Update Docker COPY/build paths, Codecov paths, coverage script paths, and any test path attributes. Do not edit production logic.

Run:

```text
rtk proxy cargo fmt --check
rtk proxy cargo check --workspace --all-targets --all-features --locked
rtk proxy cargo test --workspace --all-features --locked
rtk python scripts/verify_static_contracts.py --check
```

Expected: all 1,977 baseline tests and static contracts pass.

- [ ] **Step 5: Commit the pure workspace move**

```text
rtk git add Cargo.toml Cargo.lock rust-toolchain.toml crates/authorization-server Containerfile .github codecov.yml scripts
rtk git commit -m "refactor: establish virtual cargo workspace"
```

### Task 3: Implement the independent runtime-module state machine

**Files:**
- Create: `crates/runtime-capabilities/Cargo.toml`
- Create: `crates/runtime-capabilities/src/lib.rs`
- Create: `crates/runtime-capabilities/src/model.rs`
- Create: `crates/runtime-capabilities/src/policy.rs`
- Create: `crates/runtime-capabilities/src/snapshot.rs`
- Create: `crates/runtime-capabilities/src/transition.rs`
- Create: `crates/runtime-capabilities/src/repository.rs`
- Create: `crates/runtime-capabilities/tests/state_machine.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: no domain or infrastructure crate.
- Produces: `ModuleId`, `DesiredMode`, `ModuleState`, `DisablePolicy`, `ModuleSpec`, `ModuleRevision`, `ModuleEventType`, `ActiveModuleSnapshot`, `SnapshotStore`, `TransitionGuard`, and `ModuleStateRepository`.

- [ ] **Step 1: Write failing state-model tests**

Cover these exact rules:

```rust
assert!(!DesiredMode::Inherit.resolve(false));
assert!(DesiredMode::Inherit.resolve(true));
assert!(DesiredMode::Enabled.resolve(false));
assert!(!DesiredMode::Disabled.resolve(true));
assert_eq!(ModuleState::Disabled.can_transition_to(ModuleState::Starting), true);
assert_eq!(ModuleState::Enabled.can_transition_to(ModuleState::Starting), false);
assert_eq!(ModuleEventType::ALL.len(), 7);
```

Also assert every `ModuleId::ALL` entry has exactly one `ModuleSpec`, all dependencies name known modules, and the dependency graph is acyclic.

Run `rtk proxy cargo test -p nazo-runtime-modules --test state_machine`; expected failure: package not yet present.

- [ ] **Step 2: Implement the exact public model**

Use these public definitions:

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredMode { Inherit, Enabled, Disabled }

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState { Disabled, Starting, Enabled, Draining, Failed }

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    DeviceAuthorization, TokenExchange, JwtBearerGrant, Ciba,
    DynamicClientRegistration, RequestObjects, Jarm, AuthorizationDetails,
    HttpMessageSignatures, Scim, NativeSso, FrontchannelLogout,
    SessionManagement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisablePolicy {
    Immediate,
    FinishExecutingRequests,
    DrainStoredTransactions { max_duration: std::time::Duration },
    NotRuntimeDisableable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleEventType {
    DesiredStateChanged, TransitionStarted, TransitionCompleted,
    TransitionFailed, DrainStarted, DrainCompleted, StaleTransitionDiscarded,
}
```

Implement `DesiredMode::resolve`, legal state transitions, `ModuleId::ALL`, `ModuleEventType::ALL`, and acyclic dependency validation without domain-specific policy.

- [ ] **Step 3: Write failing revision and snapshot tests**

Test that a guard for revision 7 becomes stale after revision 8 is published, stale compare-and-publish fails, and a request lease retains the old snapshot while new loads see the new snapshot.

Run `rtk proxy cargo test -p nazo-runtime-modules`; expected failure on missing transition/snapshot behavior.

- [ ] **Step 4: Implement revision-bound snapshots**

Provide these signatures:

```rust
pub struct ModuleRevision(u64);
impl ModuleRevision { pub const fn new(value: u64) -> Self; pub const fn get(self) -> u64; }

pub struct ActiveModuleSnapshot {
    pub revision: ModuleRevision,
    pub accepting: std::collections::BTreeSet<ModuleId>,
    pub draining: std::collections::BTreeSet<ModuleId>,
}

pub struct SnapshotStore {
    current: arc_swap::ArcSwap<ActiveModuleSnapshot>,
}
impl SnapshotStore {
    pub fn new(initial: ActiveModuleSnapshot) -> Self;
    pub fn load(&self) -> arc_swap::Guard<std::sync::Arc<ActiveModuleSnapshot>>;
    pub fn compare_and_publish(
        &self,
        expected: ModuleRevision,
        next: ActiveModuleSnapshot,
    ) -> Result<(), StaleTransition>;
}

pub struct TransitionGuard {
    latest: std::sync::Arc<std::sync::atomic::AtomicU64>,
    bound: ModuleRevision,
}
impl TransitionGuard {
    pub fn bind(
        latest: std::sync::Arc<std::sync::atomic::AtomicU64>,
        bound: ModuleRevision,
    ) -> Self;
    pub fn ensure_current(&self) -> Result<(), StaleTransition>;
    pub fn revision(&self) -> ModuleRevision;
}
```

No async runtime dependency is permitted in this crate's state model.

- [ ] **Step 5: Define the infrastructure inversion port**

Define `ModuleStateRepository` with stable async trait methods for desired read/CAS, instance transition CAS, event append, and revision validation. Use domain-neutral records defined in this crate. Provide an in-memory test implementation under `tests/`; do not ship a general in-memory production adapter.

- [ ] **Step 6: Verify dependency purity and commit**

Run:

```text
rtk proxy cargo test -p nazo-runtime-modules
rtk proxy cargo tree -p nazo-runtime-modules --depth 1
rtk proxy cargo clippy -p nazo-runtime-modules --all-targets -- -D warnings
```

Expected: tests pass; direct dependencies contain only `arc-swap`, `serde`, `thiserror`, and test dependencies—no auth, identity, Actix, Diesel, Fred, Tokio, or database crate.

Commit:

```text
rtk git add Cargo.toml Cargo.lock crates/runtime-capabilities
rtk git commit -m "feat: add revision-bound runtime module state machine"
```

### Task 4: Extract the framework-independent resource-server core

**Files:**
- Create: `crates/resource-server/Cargo.toml`
- Move: `crates/authorization-server/src/resource_server.rs` -> `crates/resource-server/src/lib.rs`
- Move: `crates/authorization-server/src/resource_server/{dpop,jwk,presentation}.rs` -> `crates/resource-server/src/`
- Move: relevant tests from `crates/authorization-server/tests/in_source/src/resource_server/tests/` -> `crates/resource-server/tests/`
- Delete: `crates/authorization-server/src/resource_server/adapters.rs`
- Delete: Tower/Tonic adapter tests
- Modify: `crates/authorization-server/src/lib.rs`
- Modify: `crates/authorization-server/Cargo.toml`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: existing framework-neutral verifier API.
- Produces: `nazo-resource-server` with no Actix/auth/identity/Tower/Tonic edge.

- [ ] **Step 1: Add a failing dependency-boundary test**

Create a test/script assertion that `cargo metadata` for `nazo-resource-server` contains none of `actix-web`, `tower`, `tonic`, `nazo-auth`, or `nazo-identity`. Run it before extraction; expected failure because the package does not exist.

- [ ] **Step 2: Move only the core and delete historical adapters**

Keep the public verifier/request functions and local wire types. Remove `pub use adapters::*`, `TowerResourceServerLayer`, `authorize_tonic_request`, `authorize_actix_request`, and their tests. Do not add feature flags.

- [ ] **Step 3: Update consumers and run focused tests**

Run:

```text
rtk proxy cargo test -p nazo-resource-server
rtk proxy cargo check --workspace --all-targets --all-features --locked
rtk proxy cargo tree -p nazo-resource-server --depth 1
```

Expected: all resource-server behavior tests pass; forbidden dependencies are absent.

- [ ] **Step 4: Commit**

```text
rtk git add Cargo.toml Cargo.lock crates/resource-server crates/authorization-server
rtk git commit -m "refactor: isolate resource server core"
```

### Task 5: Rename the reusable HTTP Signatures primitive

**Files:**
- Move: `crates/fapi-http-signatures/` -> `crates/http-signatures/`
- Modify: `crates/http-signatures/Cargo.toml`
- Modify: `crates/authorization-server/Cargo.toml`
- Modify: imports under `crates/authorization-server/src/`
- Modify: docs referring to the package name

**Interfaces:**
- Consumes: current public HTTP signature primitive and tests.
- Produces: package `nazo-http-signatures`, crate `nazo_http_signatures`, with no FAPI policy.

- [ ] **Step 1: Rename package and imports mechanically**

Use `rtk git mv crates/fapi-http-signatures crates/http-signatures`. Change package/crate identifiers only; do not alter algorithms, fields, canonicalization, or errors.

- [ ] **Step 2: Add a crate-purpose test/doc assertion**

Ensure public docs describe HTTP Message Signatures and Content-Digest generically and contain no authorization-server policy. Retain all 89 existing integration tests.

- [ ] **Step 3: Verify and commit**

Run:

```text
rtk proxy cargo test -p nazo-http-signatures --locked
rtk proxy cargo tree -p nazo-http-signatures --depth 1
rtk proxy cargo check --workspace --all-targets --all-features --locked
```

Expected: 89 tests pass and only framework-neutral direct dependencies remain.

Commit:

```text
rtk git add Cargo.toml Cargo.lock crates/http-signatures crates/authorization-server docs
rtk git commit -m "refactor: generalize http signatures crate"
```

### Task 6: Push the first compiling boundary and open the backend Draft PR

**Files:**
- Modify: Draft PR description only; no source file.

**Interfaces:**
- Consumes: Tasks 1–5 with clean local gates.
- Produces: pushed branch and Draft PR for continuous CI feedback.

- [ ] **Step 1: Run the phase gate**

```text
rtk proxy cargo fmt --check
rtk proxy cargo check --workspace --all-targets --all-features --locked
rtk proxy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
rtk proxy cargo test --workspace --all-features --locked
rtk python scripts/verify_static_contracts.py --check
rtk git status --short --branch
```

Expected: every command exits 0 and the worktree is clean.

- [ ] **Step 2: Use the GitHub publish workflow**

Invoke `github:yeet`, push `codex/modular-workspace-architecture`, and create a Draft PR targeting `main`. The description states that this is the first boundary phase and does not claim deployment or conformance completion.

- [ ] **Step 3: Record the PR URL in the next phase plan execution notes**

Do not modify the architecture spec or fabricate results. Continue only after the first CI run is visible.
