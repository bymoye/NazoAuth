# Verification, Deployment, and Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the modular-workspace change with current stable dependencies, reproducible supply-chain controls, complete local evidence, a rollback-safe `hostinger` deployment, both required 21-plan OIDF matrices, and green checks bound to the final commits.

**Architecture:** Keep build, migration, deployment, protocol verification, and conformance as explicit gates. Deploy one backend image plus one versioned frontend artifact, preserve the previous image/UI target until acceptance, and bind every result to backend SHA, frontend SHA, deployed image, OIDF suite SHA, plan IDs, and GitHub workflow SHA.

**Tech Stack:** Rust 1.97.0, Cargo Workspace, Docker/Podman, PostgreSQL 18, Valkey 8, Python locked requirements, GitHub Actions/CLI, OpenID Foundation Conformance Suite v5.2.0 or the repository-pinned successor.

## Global Constraints

- Complete the other three plans first; this plan does not mask a red earlier phase.
- Upgrade only to current compatible stable releases verified from official Rust/crate/project documentation and changelogs; keep the exact Rust toolchain pinned.
- Never edit historical migrations, weaken a test, reduce an assertion, rewrite an OIDF result, skip a plan, or expand an expected REVIEW/SKIPPED allowlist to obtain green status.
- Local host-matrix acceptance and official-matrix acceptance both use the repository's complete 21-plan scope: 19 concurrency-safe plans plus isolated Front-Channel Logout and Session Management.
- A failed deployment is rolled back before any conformance run. A failed matrix is diagnosed, fixed, committed, redeployed, and rerun in full.
- Every shell command uses `rtk`; PowerShell commands use `pwsh -NoLogo -NoProfile -NonInteractive`.

---

### Task 1: Update dependencies and supply-chain automation

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `rust-toolchain.toml`
- Modify: `Containerfile`
- Modify: `.github/e2e-runner.Containerfile`
- Modify: `.github/dependabot.yml`
- Modify: `.github/renovate.json5`
- Modify: `.github/workflows/{code-quality,dependency-review,release-security,codeql,conformance-security,spec-freshness}.yml`
- Modify: `deny.toml`
- Modify: `requirements/codecov.in`
- Modify: `requirements/codecov.txt`
- Modify: `requirements/oidf-conformance.in`
- Modify: `requirements/oidf-conformance.txt`
- Create: `requirements/live-verification.in`
- Create: `requirements/live-verification.txt`
- Modify: `README.md`
- Modify: `docs/operations/{deployment,configuration}.md`

**Interfaces:**
- Consumes: the final workspace dependency graph and official release/changelog/security documentation.
- Produces: a locked build, scheduled dependency/toolchain update PRs, audit/deny/dependency-review/CodeQL/SBOM/container-scan coverage for every workspace crate and both container definitions.

- [ ] **Step 1: Record the pre-update dependency and advisory state**

Run `rtk proxy cargo tree --workspace --all-features --locked`, `rtk proxy cargo audit`, `rtk proxy cargo deny check advisories bans licenses sources`, `rtk proxy cargo update --dry-run`, and `rtk python -m pip check`. Save command output in the implementation log, not in generated source files. Classify each available update by direct/transitive dependency, SemVer impact, MSRV, API migration, security advisory, and feature change.

- [ ] **Step 2: Verify candidate versions from primary sources**

For Rust, crates, GitHub Actions, PostgreSQL/Valkey images, Python packages, Node packages, and OIDF suite revisions, read the official release notes or changelog before changing pins. Preserve Rust `1.97.0` unless a newer stable has been released and all workspace, CI, and container gates pass with one exact replacement version. Do not use floating `stable`, `latest`, mutable major-only container tags, or unpinned OIDF source.

- [ ] **Step 3: Upgrade in reviewable groups**

Update Rust runtime/protocol dependencies first, infrastructure dependencies second, developer/test dependencies third, and CI/container actions last. After each group run workspace check, Clippy, tests, audit, and deny. Remove unused dependencies proven by `cargo tree` plus source search. Preserve the existing feature matrix unless a removed adapter makes a feature obsolete.

- [ ] **Step 4: Make automated updates workspace-aware**

Configure Dependabot and Renovate to cover Cargo, GitHub Actions, Docker, pip requirements, and the sibling frontend's npm manifest in its own repository. Group low-risk patch/minor updates; keep security updates separate; require the same quality/security/E2E gates. Add a scheduled Rust-stable update that changes `rust-toolchain.toml`, CI, and `Containerfile` together in a PR and never mutates production directly.

- [ ] **Step 5: Verify supply-chain outputs and commit**

Run the commands from Step 1 again, build the server and E2E images, generate the configured SBOM, and scan the exact built image. Resolve actionable findings before committing `build: update dependencies and supply chain gates`.

### Task 2: Run the complete local acceptance gate

**Files:**
- Modify as failures require: production code, tests, scripts, CI, container, and documentation files already in scope
- Create: `docs/verification/2026-07-12-modular-workspace-local.md`

**Interfaces:**
- Consumes: final backend and frontend candidate commits.
- Produces: reproducible local results for formatting, compilation, linting, all tests, HTTP E2E, migrations, security, concurrency/load, fault injection, container builds, and local consistency.

- [ ] **Step 1: Verify both worktrees and record candidate SHAs**

Require clean backend and frontend worktrees, the intended feature branches, and remotes `https://github.com/nazozero/NazoAuth` and `https://github.com/nazozero/NazoAuthWeb`. Record `git rev-parse HEAD`, `git status --short --branch`, and `git remote get-url origin` for both repositories.

- [ ] **Step 2: Run the mandatory Rust gate exactly**

Run, in order:

```text
rtk proxy cargo fmt --check
rtk proxy cargo check --workspace --all-targets --all-features --locked
rtk proxy cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
rtk proxy cargo test --workspace --all-features --locked
```

Any fix invalidates the affected command and all later commands; rerun from the first affected gate.

- [ ] **Step 3: Run repository-native non-Rust gates**

Run `rtk python -m compileall -q scripts tests/unit`, `rtk python -m unittest discover -s tests/unit -t .`, `rtk python scripts/verify_static_contracts.py --check`, `rtk proxy cargo audit`, and `rtk proxy cargo deny check advisories bans licenses sources`. Run the migration test job against a fresh PostgreSQL database and against a database migrated to the pre-change head before applying only new migrations.

- [ ] **Step 4: Run real HTTP, security, concurrency, and failure tests**

Reproduce the `conformance-security` workflow locally with the same server and E2E-runner images: start PostgreSQL and Valkey, run `nazo-oauth-migrate`, run both normal and HTTP-signatures-enabled servers, execute `scripts/full_real_request_e2e.py`, execute `scripts/full_real_request_load.py`, stop Valkey, and execute `scripts/valkey_failure_injection.py`. Preserve the workflow's exact environment, key generation, network, and cleanup semantics. Add focused runtime revision-race, drain, disabled-route, MFA replay/rate-limit, backup-code atomicity, and session/CSRF rotation tests to this gate.

- [ ] **Step 5: Validate the frontend from its real manifest**

From the sibling frontend worktree, inspect the committed lockfile and `package.json`, then run the scripts that exist after the frontend plan: `rtk npm ci`, `rtk npm run lint`, `rtk npm run test:unit -- --run`, `rtk npm test`, and `rtk npm run build`. Do not substitute an assumed script name or omit Vitest results.

- [ ] **Step 6: Record evidence and commit**

Write the exact backend/frontend SHAs, command lines, timestamps, tool versions, test counts, image digests, migration modes, and results to `docs/verification/2026-07-12-modular-workspace-local.md`. Commit only after every result is green with `docs: record modular workspace local verification`.

### Task 3: Make live deployment atomic and rollback-safe

**Files:**
- Modify: `scripts/deploy_live.ps1`
- Modify: `scripts/verify_live_full_interfaces.py`
- Modify: `.github/e2e-runner.Containerfile`
- Modify: `docs/operations/deployment.md`
- Create: `tests/unit/test_deploy_live_script.py`
- Create: `tests/unit/test_verify_live_full_interfaces.py`

**Interfaces:**
- Consumes: clean backend/frontend SHAs, frontend `dist`, SSH host alias `hostinger`, current remote container/image/UI state.
- Produces: staged deployment with preflight record, additive migrations, candidate health verification, atomic UI switch, automatic rollback, and deployed-SHA evidence.

- [ ] **Step 1: Add failing deployment contract tests**

Assert that `deploy_live.ps1` records the current container image/id and current UI symlink target before mutation; creates a new `/opt/nazo-oauth/ui-releases/$FrontendCommit` directory; never deletes the active UI directory; preserves the old image and UI release; runs migrations once; verifies candidate health, discovery issuer, container address, and expected backend/frontend SHA; switches the UI symlink atomically; and restores both previous targets on any later failure.

- [ ] **Step 2: Implement staged UI and rollback records**

Add mandatory `BackendCommit` and `FrontendCommit` parameters. Upload UI assets into the SHA-named release, validate its manifest, and switch `/opt/nazo-oauth/ui` using a same-filesystem temporary symlink plus rename. Store a timestamped deployment record under `/opt/nazo-oauth/deployments/` containing previous/candidate image, container id, UI target, database migration head, and both SHAs. Retain the previous release until all acceptance gates finish.

- [ ] **Step 3: Harden candidate deployment**

Validate SSH connectivity, free space, Podman network, config, key directory, PostgreSQL, Valkey, and TLS before migration. Load the SHA-tagged image, run `nazo-oauth-migrate`, replace only the server container, verify fixed address `10.101.0.20`, health, discovery issuer, logs, PostgreSQL, Valkey, and the served commit metadata. On failure, restore the previous image/container and UI target and verify health before exiting nonzero.

- [ ] **Step 4: Make live verification reproducible**

Move all Python imports needed by `verify_live_full_interfaces.py` into a hash-locked requirements file used by `.github/e2e-runner.Containerfile` and the remote verifier environment. Add an argument parser with explicit `--base-url`, `--secrets-path`, and `--expected-backend-sha`; `--help` must not perform network, database, Valkey, certificate, or filesystem mutation. Keep the default target `https://auth.nazo.run` and `/opt/nazo-oauth/secrets.json`.

- [ ] **Step 5: Verify and commit**

Run the deployment-script unit tests, verifier unit tests, `pwsh` parser validation, container build, and a non-production dry-run fixture over a temporary remote-layout directory. Commit `ops: make live deployment atomic and rollback safe`.

- [ ] **Step 6: Re-run and bind the complete local acceptance gate**

Because Task 3 changes production deployment/verifier/container code after Task 2, repeat every command and environment in Task 2 against the new backend and frontend heads. Update `docs/verification/2026-07-12-modular-workspace-local.md` with the final SHAs/results and commit `docs: finalize modular workspace local verification`. This commit becomes the deployment candidate; no successful post-deployment evidence step may create a newer repository commit.

### Task 4: Deploy the final candidate to `hostinger`

**Files:**
- Write remotely: `/opt/nazo-oauth/deployments/$BackendCommit.json`
- Modify only on failure: implementation, tests, deployment scripts, and operational docs

**Interfaces:**
- Consumes: final pushed backend/frontend commits and green local evidence.
- Produces: `auth.nazo.run` running the exact PR heads, a verified rollback target, and a healthy protocol surface.

- [ ] **Step 1: Capture pre-deployment state without mutation**

Over SSH record hostname, UTC time, current server container id/image/status/address, image digest, `/opt/nazo-oauth/ui` target, process logs, migration head, PostgreSQL readiness, Valkey PING, TLS certificate subject/issuer/expiry, health body, discovery issuer, and JWKS response. The known starting image observed during planning is `localhost/nazo-oauth-server:http-sig-enabled-8041eaa`; treat the deployment-time observation as authoritative.

- [ ] **Step 2: Deploy exact PR heads**

From the backend worktree compute `$backendSha = (rtk git rev-parse HEAD).Trim()`, `$frontendSha = (rtk git -C $frontendWorktree rev-parse HEAD).Trim()`, and `$imageTag = "modular-$($backendSha.Substring(0,7))-web-$($frontendSha.Substring(0,7))"`. Invoke `rtk pwsh -NoLogo -NoProfile -NonInteractive -File scripts/deploy_live.ps1 -RemoteHost hostinger -BackendCommit $backendSha -FrontendCommit $frontendSha -ImageTag $imageTag -LocalUiDist (Join-Path $frontendWorktree "dist")`. Do not use `-SkipBuild` or `-SkipMigrate` for the production cutover.

- [ ] **Step 3: Verify infrastructure and protocol endpoints**

Confirm Podman process/status/address, absence of error/panic loops in logs, migration head, PostgreSQL query, Valkey PING and representative TTL/key compatibility, TLS chain/hostname/expiry, health, discovery, OAuth AS metadata, protected-resource metadata, JWKS, authorization error/redirect behavior, token, PAR, CIBA, UserInfo, introspection, DCR condition, SCIM condition, session, and runtime-module Admin API authorization. Inside the prepared remote Python environment run `python scripts/verify_live_full_interfaces.py --base-url https://auth.nazo.run --secrets-path /opt/nazo-oauth/secrets.json --expected-backend-sha "$backendSha"`.

- [ ] **Step 4: Handle failure before conformance**

If any check fails, stop: collect logs and state, restore the recorded previous image/UI targets, verify restored health, fix the root cause locally with a regression test, commit/push, rerun affected local gates, and redeploy the new heads. Do not start either OIDF matrix while any live check is red.

- [ ] **Step 5: Record deployment evidence without changing the candidate commit**

Write pre/post container/image/UI/migration/TLS/health/protocol evidence and both commit SHAs to the SHA-bound remote deployment record and retain a local copy outside the Git worktree for the PR description. Keep the rollback image and UI release until final acceptance. Do not create a success-only documentation commit after deployment.

### Task 5: Run the host-local OIDF full matrix

**Files:**
- Write remotely: `/root/oauth2_server/evidence/$BackendCommit/host-local-oidf/`
- Modify only on failure: code, tests, plan config generation, or version-controlled expected-state file

**Interfaces:**
- Consumes: healthy deployed PR heads, the running host-local official suite, generated 21-plan config, and the repository-pinned suite revision.
- Produces: host-local plan IDs and exported evidence with no unexpected FAILED, condition failure, warning, REVIEW, or SKIPPED result.

- [ ] **Step 1: Verify the local suite and materialize the final commit's matrix**

On `hostinger`, verify the running suite containers, suite `/version`, suite Git SHA, browser callback reachability, and exact deployed backend SHA. In a SHA-named backend checkout run the locked setup dependencies, `scripts/setup_local_oidf_podman.py`, and its unit tests. Confirm `runtime/oidf/oidf-plan-set.json` contains exactly 21 unique plan expressions and that the separate concurrent/frontchannel/session files contain 19/1/1 plans.

- [ ] **Step 2: Execute all 19 concurrency-safe plans**

Run `scripts/run_oidf_conformance.py` against the host-local conformance URL with `--config-json-file runtime/oidf/oidf-plan-configs.json`, `--plan-set-json-file runtime/oidf/oidf-plan-set-concurrent.json`, `--no-api-token`, the local TLS option required by the existing suite, `--target-issuer https://auth.nazo.run`, a fresh SHA-named export directory, and no rerun filter. Do not use a smoke or targeted plan set.

- [ ] **Step 3: Execute the two browser-sensitive plans in isolation**

Run the same runner separately with `oidf-plan-set-frontchannel.json` and `oidf-plan-set-session.json`, distinct browser/user state, and separate export directories. Never combine these plans with each other or with the concurrent set.

- [ ] **Step 4: Enforce the expected-state policy**

Aggregate all 21 plan exports. Require 0 FAILED modules, 0 condition failures, 0 warnings, and no unexpected REVIEW or SKIPPED modules. The only accepted REVIEW/SKIPPED states are exact entries already committed in the version-controlled allowlist, bound to module, plan/profile, configuration filename, and reason; their count must not exceed baseline. A changed module id or additional state is a failure, not an allowlist update opportunity.

- [ ] **Step 5: Fix and rerun full matrix when necessary**

For any failure, collect plan/module ids and logs, reproduce with a focused local test, fix, run local gates, commit/push, redeploy, rerun live verification, and rerun all 21 plans. Record only the final full run as acceptance evidence.

- [ ] **Step 6: Persist host-local evidence without moving the PR head**

Record backend/frontend/deployed image SHA, suite SHA/version, start/end time, all 21 plan IDs, module and condition totals, exact expected REVIEW/SKIPPED entries, export paths/digests, and zero-unexpected-state result under the SHA-bound remote evidence directory. Copy the summary outside the Git worktree for the PR description. Do not commit after success; the official workflow must run from the same commit that is deployed and tested locally.

### Task 6: Run the official OIDF full matrix

**Files:**
- Retain: GitHub Actions run metadata and downloaded official artifacts keyed by workflow run id and backend SHA
- Modify only on failure: implementation, tests, workflow, configs, or docs

**Interfaces:**
- Consumes: deployed commit from Task 5 and official issuer `https://auth.nazo.run`.
- Produces: successful official workflow jobs, 21 official plan IDs, artifacts/digests, and evidence tied to the same deployed code.

- [ ] **Step 1: Confirm SHA and seed consistency**

Before dispatch, prove that the backend PR head equals the deployed backend SHA, the frontend PR head equals the deployed frontend SHA, and the public OIDF client seed/JWK material matches the plan configs generated by that head. Abort on mismatch.

- [ ] **Step 2: Dispatch the complete official matrix**

Run `rtk gh workflow run oidf-conformance-full.yml --ref codex/modular-workspace-architecture -f runner_mode=parallel-isolated`. Capture the returned Actions run id. The workflow target must resolve to `https://auth.nazo.run`; it must execute the 19-plan concurrent job and the isolated `frontchannel` and `session-management` jobs.

- [ ] **Step 3: Monitor and inspect every job**

Set `$runId` to the run id returned by dispatch, then use `rtk gh run watch $runId --exit-status` and `rtk gh run view $runId --json headSha,status,conclusion,jobs,url`. Download every OIDF result artifact and public-plan-config artifact into a fresh local evidence directory, verify artifact digests, and aggregate module/condition outcomes with the repository's result parser.

- [ ] **Step 4: Apply the same strict acceptance policy**

Require all three jobs success, 0 FAILED modules, 0 condition failures, 0 warnings, and no unexpected REVIEW/SKIPPED result. Verify the workflow head SHA is the commit documented and deployed; if documentation commits follow the implementation commit, record both without misidentifying the runtime code.

- [ ] **Step 5: Fix and repeat the official full matrix when necessary**

An official failure triggers local reproduction, a regression test, code fix, all affected local gates, commit/push, deployment, live verification, host-local full 21-plan matrix, and then another official complete workflow. Do not use `--rerun`, a targeted workflow, an allowlist expansion, or a weaker runner mode as final evidence.

- [ ] **Step 6: Persist official evidence without moving the PR head**

Record run/job URLs, workflow/runtime/frontend SHAs, suite ref/version, all 21 plan IDs, module/condition totals, exact expected states, artifact ids/sizes/digests/expiry, and result parser output in the retained Actions artifacts and a local evidence copy outside the Git worktree. Do not commit after success; update the Draft PR description in Task 7.

### Task 7: Converge PR checks and mark Ready for Review

**Files:**
- Modify: backend Draft PR description
- Modify: frontend Draft PR description
- Modify as checks require: source, tests, CI, dependency, container, config, and docs files

**Interfaces:**
- Consumes: final backend/frontend heads, deployment evidence, both OIDF records, and GitHub check runs.
- Produces: all checks green, accurate PR descriptions, backend PR Ready for Review, frontend coordinated PR reviewable, neither merged.

- [ ] **Step 1: Monitor checks on the final heads**

Run `rtk gh pr checks --watch --fail-fast=false` in both repositories. For every failed/cancelled/timed-out check, inspect its logs, reproduce locally where possible, fix the root cause, commit/push, and rerun all invalidated gates. Never treat a superseded green SHA as final evidence.

- [ ] **Step 2: Perform final diff and boundary review**

Inspect both complete diffs and dependency trees. Confirm crate responsibilities/dependency direction, no forbidden imports/cycles/glob preludes/giant state/settings/support modules/historical adapters, shortest handler paths, typed metadata snapshot consistency, revision-safe transitions, exact route/config/data contracts, and no uncommitted files or secrets.

- [ ] **Step 3: Run the final lightweight identity checks**

Re-read live health/discovery/JWKS and deployed SHA, verify the host-local and official evidence both point to the final implementation SHA, and verify all current PR checks belong to the final PR heads. If a final code commit was introduced, the full deployment and both full matrices must be repeated.

- [ ] **Step 4: Update PR descriptions from actual evidence**

Limit the backend PR summary to final directories/crate responsibilities, dependency direction, architecture and implementation improvements, deleted code, dependency/CI/container/config updates, compatibility treatment, local tests, remote deployment, host-local OIDF matrix, official OIDF matrix, and PR checks. Link the frontend PR and describe its admin UI/test changes there. Report only observed counts, SHAs, URLs, ids, and digests.

- [ ] **Step 5: Mark ready without merging**

After all eight acceptance conditions are simultaneously true, run `rtk gh pr ready` for the backend Draft PR. Leave both PRs unmerged. Remove the retained rollback version only in a later separately authorized operation; final acceptance does not delete it.
