# Key Management Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all key-management reviewer findings while preserving wire and persisted-file behavior.

**Architecture:** Publish private and public key state as one immutable generation, bind HTTP signature identity and signing through an opaque lease, centralize schema operations on concrete `KeyManager`, and hide server test private material behind behavioral fixtures.

**Tech Stack:** Rust, Tokio, ArcSwap, jsonwebtoken, Actix Web, existing NazoAuth test harness.

## Global Constraints

- No public private-key or generic signing-handle API.
- Preserve exact JSON/PEM filenames, schema, external command protocol, rotation behavior, and wire responses.
- Do not add a key administration facade.
- No server legacy keyset/private API, including under `cfg(test)`.
- Use test-first RED/GREEN cycles and no subagents.

---

### Task 1: Atomic generation and HTTP lease

**Files:** Modify `crates/key-management/src/model.rs`, `crates/key-management/src/lib.rs`, `crates/authorization-server/src/http/fapi_resource.rs`; test `crates/key-management/src/model.rs` and server FAPI tests.

**Interfaces:** Produce `KeyManager::prepare_http_signing() -> Result<HttpSigningLease, _>`; lease exposes only `kid()`, `algorithm()`, and `sign(&[u8])`.

- [ ] Add a deterministic test that captures a lease, rotates the manager generation, signs with the lease, and verifies the signature with the lease-labelled public key.
- [ ] Run the test and confirm it fails because there is no bound lease/single generation.
- [ ] Replace the two ArcSwaps with `ArcSwap<KeyGeneration>` and implement the minimal lease.
- [ ] Update FAPI response preparation to derive labels from the lease and sign through it.
- [ ] Run focused race and FAPI tests until green.

### Task 2: Purpose and state enforcement

**Files:** Modify/test `crates/key-management/src/model.rs` and compatibility tests.

**Interfaces:** All selection goes through `ManagedKey::can_sign(SigningPurpose)`.

- [ ] Add failing real-path tests for `Signer::sign`, `encode_jwt`, and HTTP lease preparation using wrong-purpose, grace, and retired keys.
- [ ] Remove the active fast-path bypass and select active/auxiliary handles only after purpose, state, and algorithm checks.
- [ ] Run the focused policy tests and existing signing compatibility tests.

### Task 3: Concrete keyctl storage operations

**Files:** Modify `crates/key-management/src/store.rs`, `model.rs`, `lib.rs`; simplify `crates/authorization-server/src/keyctl.rs`, support exports, and keyctl tests.

**Interfaces:** `KeyManager` directly produces public `KeyRecord` values and implements focused list/register-external/validate operations.

- [ ] Add failing key-management tests for list status and exact external registration schema.
- [ ] Move schema parsing, filename resolution, public-JWK validation, lifecycle status, and atomic write behind concrete `KeyManager` methods.
- [ ] Remove public low-level store helper exports and simplify server keyctl to parsing, invocation, and presentation.
- [ ] Run keyctl and key-storage compatibility tests.

### Task 4: Opaque server test signing fixtures

**Files:** Modify `crates/authorization-server/src/lib.rs`, `support/mod.rs`, affected `crates/authorization-server/tests/in_source/**`; remove `Keyset` alias in `domain/mod.rs`.

**Interfaces:** `ClientSigningFixture` exposes public JWK and behavioral construction/signing methods, never raw DER/PEM/private JWK.

- [ ] Use compile errors/source scans to enumerate every raw helper consumer.
- [ ] Introduce the minimal opaque fixture methods required by those tests and migrate each consumer without weakening assertions.
- [ ] Remove raw helper reexports and the `Keyset` alias; use `KeySnapshot` exactly.
- [ ] Run focused client assertion, JAR, DPoP/FAPI, and token tests.

### Task 5: Lifecycle classification

**Files:** Modify/test `crates/key-management/src/store.rs` and model snapshot tests.

**Interfaces:** Same-alg inactive live candidates load as `Prepublished`; only different-alg IdToken/Jarm auxiliary keys load as `Active`.

- [ ] Add failing loader assertions for same-alg prepublished, different-alg auxiliary active, grace, and retired behavior.
- [ ] Implement classification without changing persisted fields.
- [ ] Run loader/lifecycle compatibility tests.

### Task 6: Verification, report, and commits

**Files:** Append `.superpowers/sdd/domain-task-3-report.md`.

- [ ] Run formatting, focused suites, key-management, server lib/bins, workspace, and all-target/all-feature Clippy with warnings denied.
- [ ] Run dependency/source-boundary scans and exact baseline/current test reconciliation by Cargo target.
- [ ] Append RED/GREEN evidence, move/API map, compatibility evidence, counts, and concerns to the report.
- [ ] Review staged diffs, run `git diff --check`, and create logical focused commits.
