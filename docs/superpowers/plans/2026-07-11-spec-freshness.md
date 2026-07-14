# Standards Freshness Correction Implementation Plan

> Execute each task with test-first changes and independent review.

**Goal:** Correct all discovered specification/suite version drift, make future
drift automatically detectable, and revalidate production against the latest
official OIDF conformance-suite release.

**Design:** `docs/superpowers/specs/2026-07-11-spec-freshness-design.md`

### Task 1: Add deterministic freshness inventory and checker

- Add failing fixture-driven tests for schema, IETF revision mismatch, OpenID
  marker mismatch, OIDF release mismatch, network failure, and success.
- Add `requirements/spec-freshness.json` covering every active cited primary
  specification and immutable RFC.
- Implement `scripts/check_spec_freshness.py` with offline and online modes.
- Verify tests, offline validation, and online validation.

### Task 2: Add continuous freshness enforcement

- Add a workflow with PR/path-scoped offline validation, weekly online checks,
  and manual dispatch.
- Pin the OIDF workflows' default ref to official `release-v5.2.0` commit
  `dee9a25160e789f0f80517674693ef7989ab9fa1`.
- Add source-policy regression checks for all workflow defaults.

### Task 3: Correct active standards and architecture documentation

- Update active Browser records from draft `-26` to `-27` and record the exact
  delta.
- Correct NazoAuthWeb from “BFF” to same-origin authorization-server frontend;
  explain why the new BFF cookie-prefix SHOULD is not a NazoAuth runtime
  requirement.
- Update Grant Management to the `oauth-v2-grant-management-03` working draft
  and distinguish it from the approved `ID1` Implementer's Draft snapshot.
- Ensure active Client Attestation and Transaction Token records consistently
  use `-10` and `-09`.
- Distinguish historical OIDF evidence from the new `v5.2.0` baseline.

### Task 4: Inspect conformance-suite v5.2.0 coverage

- Clone the exact release and verify its tag commit.
- Re-scan plans/modules for all M8 candidates, including the new RFC 9967/SSF
  recognition noted by the release.
- Record current applicable and absent coverage without overstating
  certification.

### Task 5: Verify, publish, deploy, and run matrices

- Run freshness tests, online checks, relevant Rust tests, formatting, Clippy,
  and repository gates.
- Commit and push a PR; wait for all checks.
- Deploy the exact head to Hostinger.
- Run the remote-local 19 + 1 + 1 OIDF matrix with suite v5.2.0.
- Request the official OIDF matrix for the exact deployed head.
- After official OIDF and all PR checks pass, merge to `main` and verify the
  merged/deployed commit.
