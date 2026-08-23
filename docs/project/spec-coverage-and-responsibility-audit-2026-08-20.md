# Specification Coverage and Responsibility Audit (2026-08-20)

## Scope and evidence boundary

This audit records the specification and security invariants changed between
base `742558f41e0518c141212cb1accee0cd841fb4a9` and implementation/test head
`4c7b42798706001fec765fffd18f3dc45e0df98a`. It is intentionally narrower than
the repository-wide RFC compliance matrix: the purpose is to make each changed
production boundary traceable to a concrete test and to distinguish verified
evidence from remaining work.

Evidence levels used below are:

- **VERIFIED**: the named behavior ran against the exact implementation/test
  head on the private Linux validation host.
- **LOCALLY VERIFIED**: focused Windows evidence exists, but Linux remains the
  acceptance environment where platform behavior matters.
- **UNVERIFIED**: the relevant external service or conformance run did not
  produce current-head evidence.
- **OPEN**: a known behavior or ownership gap remains and is not represented as
  passing.

The line coverage percentage is supporting evidence, not the definition of
effective coverage. Acceptance for this change is greater than 91% patch line
coverage plus explicit tests for the changed protocol, persistence, trust, and
failure-closed boundaries.

## Requirement-to-test traceability

| Specification or invariant | Production owner | Concrete test | Current evidence | Status | Residual gap |
| --- | --- | --- | --- | --- | --- |
| An idempotent token issuance retry must describe the same result-affecting grant identity. The digest binds refresh policy, the authorization-code hash, the [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) actor chain, and the Native SSO stable session identifier, while excluding newly generated response randomness. | [`crates/authorization-server/src/http/token/issue.rs`](../../crates/authorization-server/src/http/token/issue.rs), `issuance_digest` | [`issuance_digest_binds_every_result_affecting_grant_identity`](../../crates/authorization-server/tests/unit/http/token/issue.rs) | Exact-head Hostinger workspace coverage run; Windows focused suite | **VERIFIED** | A future grant type must add every result-affecting input to this digest and its table-driven test before becoming reachable. |
| An externally supplied JWK must have a closed algorithm/key shape and usable public material. For ES256, 32-byte coordinates alone are insufficient: the SEC1 point must be on P-256. This supports [RFC 8725 Sections 3.1, 3.3, and 3.4](https://www.rfc-editor.org/rfc/rfc8725.html). | [`crates/key-management/src/external.rs`](../../crates/key-management/src/external.rs), `decoding_key_from_public_jwk`; persisted shape remains owned by [`serialization.rs`](../../crates/key-management/src/serialization.rs) | [`external_key_registration_rejects_unusable_algorithm_material`](../../crates/key-management/tests/unit/store.rs), including `(x=0,y=0)` | Hostinger: key-management 106/106 across unit and integration groups; exact-head workspace coverage run | **VERIFIED** | Hardware/KMS signer behavior is outside this repository test and still needs provider-side integration evidence. |
| [OpenID Connect Back-Channel Logout Sections 2.4 and 2.5](https://openid.net/specs/openid-connect-backchannel-1_0.html) delivery state must be tenant/client/public-ID bound, atomically enqueued, and first-write-wins under retry. | [`crates/persistence-postgres/src/repositories/audit.rs`](../../crates/persistence-postgres/src/repositories/audit.rs) and migration [`20260820000100_backchannel_logout_tenant_binding`](../../migrations/20260820000100_backchannel_logout_tenant_binding/up.sql) | [`logout_fanout_is_tenant_scoped_idempotent_and_atomic`](../../crates/persistence-postgres/tests/oidc_logout.rs) | Exact-head Hostinger PostgreSQL integration coverage run | **VERIFIED** | Public deployment delivery retry, receiver downtime, and multi-instance recovery remain operational black-box boundaries. |
| Direct TLS must reject malformed DER, a CA certificate used as the leaf, expired or wrong-host leaves, and an adjacent certificate that does not issue and sign its child. Invalid material must not be published as a new generation. This is the repository's fail-closed application of [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) and [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html). | [`crates/authorization-server/src/bootstrap/transport.rs`](../../crates/authorization-server/src/bootstrap/transport.rs), `load_generation` and `validate_tls_server_chain` | [`direct_tls_listener_rejects_malformed_or_unsafe_material_and_reload_intervals`](../../crates/authorization-server/tests/unit/bootstrap.rs), [`direct_tls_listener_rejects_an_unrelated_issuer_chain`](../../crates/authorization-server/tests/unit/bootstrap.rs), and generation-retention tests | Hostinger direct-TLS focused suite 11/11; exact-head workspace coverage run; Windows direct-TLS suite 11/11 | **VERIFIED** | Public routing parity between direct TLS and the trusted-proxy deployment remains part of issue #127, not this unit/integration proof. |
| Operator state-path inspection must propagate real I/O failures instead of converting inspection errors into absence. The test must retain meaning for both an unprivileged runner and a root runner with DAC override. | [`crates/authorization-server/src/operator_task/mod.rs`](../../crates/authorization-server/src/operator_task/mod.rs) state-path helpers | Unix permission branch plus [`operator_state_path_inspection_propagates_invalid_path_errors`](../../crates/authorization-server/tests/unit/operator_task.rs) using a NUL-containing path | Exact-head Hostinger root run and Windows compilation/static gates | **VERIFIED** | Production containers run as UID 10001; a deployed container permission-denial black box was not run in this audit. |
| Coverage collection must discover Cargo JSON test artifacts, isolate PostgreSQL/Valkey and HTTP ports, retain the invoking user's artifact ownership, merge process tests, and clean up only owned fixtures. | [`scripts/generate_codecov_lcov.sh`](../../scripts/generate_codecov_lcov.sh) | [`tests/unit/test_generate_codecov_lcov.py`](../../tests/unit/test_generate_codecov_lcov.py) and the [Codecov Docker runbook](../coverage/codecov-docker-runbook.md) | Exact-head Hostinger script exited 0, merged 100 LCOV reports, and left no owned listener/process/container | **VERIFIED** | Codecov service-side project and component statuses are **UNVERIFIED** until an enabled upload evaluates this head. |

## File responsibility audit

Line count is a review trigger, not a reason to split a file. The following
changed or directly affected files were inspected for distinct ownership,
consumer boundaries, and duplicated facts.

| File (lines at implementation/test head) | Cohesive responsibility and consumers | Decision |
| --- | --- | --- |
| `crates/authorization-server/tests/unit/http/token/issue.rs` (2,090) | Mirrors the token issuance state machine: signing, persistence, retry ownership, refresh, OIDC, Native SSO, and compensation. It is large because the owner has many result boundaries, not because it contains an unrelated subsystem. | **Keep.** Split only if a production grant lifecycle becomes a separate owner; do not create shared fixtures that hide state-machine facts. |
| `crates/persistence-postgres/src/repositories/audit.rs` (613) | Owns audit-event persistence and the atomic outbox effects produced by those events. Logout fanout belongs here because it must commit with the audited event. | **Keep.** A later split is justified only if the transaction owner changes, not by line count. |
| `crates/key-management/src/serialization.rs` (603) | Owns the durable keyset schema, compatibility checks, and atomic file publication. | **Keep.** Public-key cryptographic usability remains delegated to `external.rs`; duplicating that rule here would create two trust authorities. |
| `crates/key-management/src/external.rs` (580) | Owns external signer process protocol, public JWK validation, and verification that returned signatures match the registered key. | **Keep.** The new P-256 point validation is part of this existing trust boundary. |
| `scripts/generate_codecov_lcov.sh` (530) | Owns one coverage lifecycle: fixture creation, artifact discovery, process-test execution, LCOV merge, cleanup, and artifact ownership. | **Keep.** Helpers already separate phases locally; a file split would fragment cleanup ownership without a second consumer. |
| `crates/authorization-server/src/http/token/issue.rs` (521) | Orchestrates a single token issuance transaction and keeps grant-specific work in existing local submodules. | **Keep.** The digest is adjacent to the state it fences; moving it to a generic utility would obscure the invariant. |
| `crates/authorization-server/src/bootstrap/transport.rs` (504) | Owns transport mode, direct-TLS identity loading/reload, certificate/key/CA admission, and last-known-good publication. | **Keep.** Certificate-chain validation is required before the same generation publication and has no independent lifecycle. |
| `crates/authorization-server/tests/unit/bootstrap.rs` (1,208) | Exercises composition-root and direct-TLS bootstrap invariants, including real listener handshakes and reload behavior. | **Keep for this change.** A future split by transport mode is reasonable only if bootstrap production ownership is split at the same boundary. |

No new provider, repository, controller, or shared utility was introduced. No
changed large file contains a second fact authority that needs an immediate
structural move.

## Reproducible evidence

The private Hostinger clone was pinned to
`4c7b42798706001fec765fffd18f3dc45e0df98a`. Existing services were not stopped,
reconfigured, or reused; the coverage script used isolated ports 28000 and
28001 plus its own PostgreSQL and Valkey fixtures.

```text
cargo test --locked -p nazo-key-management
cargo test --locked -p nazo-oauth-server direct_tls_
cargo clippy --locked --workspace --all-targets --all-features --jobs 1 -- -D warnings
CODECOV_PRIMARY_SERVER_PORT=28000 CODECOV_SIGNED_SERVER_PORT=28001 \
  bash scripts/generate_codecov_lcov.sh
python3 scripts/check_patch_coverage.py \
  --lcov lcov.info \
  --base 742558f41e0518c141212cb1accee0cd841fb4a9 \
  --head 4c7b42798706001fec765fffd18f3dc45e0df98a \
  --threshold 91
```

Results:

- Hostinger key-management groups: 106 passed, 0 failed.
- Hostinger direct-TLS focused suite: 11 passed, 0 failed.
- Hostinger workspace Clippy with all targets/features: exit 0.
- Hostinger coverage script: exit 0; authorization-server main group 1,385
  passed, 0 failed, 5 ignored, followed by all 5 ignored live tests passing when
  run explicitly.
- Merged repository LCOV: 130,052 / 144,962 executable lines.
- Changed-line coverage: 117 / 121 = 96.69421%, above the greater-than-91%
  acceptance threshold.
- `lcov.info`: 8,344,627 bytes,
  SHA-256 `6cc426126238be8fea6f97b37a86a10aea7d2fb391a76ffd05cb441838e448e4`.
- `coverage-hostinger-4c7b427.log`: 269,951 bytes,
  SHA-256 `e8999d730aa174a6c470925bc04d7753b252f5b92476c596fc32b955633db41d`.
- Post-run checks found no listeners on 15432, 16383, 28000, or 28001; no
  Cargo/rustc/rustdoc process; and no owned `nazo-oauth-codecov` container.

Windows was retained only as a cross-platform preflight: the key-management
platform suite reported 101 passed, direct TLS reported 11 passed, and workspace
Clippy passed. Linux Hostinger evidence is authoritative for Unix permissions,
real HTTP/TLS, containers, and the coverage runner.

## Open and unverified boundaries

- GitHub PR #153 is not an all-green release proof. Its supply-chain gate reports
  RUSTSEC-2026-0258 through both `h2` 0.3.27 and 0.4.15. The 0.4 dependency can
  move to a patched release, but Actix currently retains the unpatched 0.3 line.
  This audit neither ignores the advisory nor disables direct TLS/HTTP2.
- External OIDF Suite evidence is owned by NazoAuthCtl and was not rerun. The
  2026-08-15 local log is not a passing current-head result: its terminal summary
  is 805 passed, 65 review, 11 skipped, and 171 failed/incomplete. The historical
  146/146 CIBA result belongs to an older v0.1.29 run and must not be attributed
  to this head.
- Codecov service-side project threshold and `security-core` component threshold
  remain **UNVERIFIED** because the PR upload path is disabled. The hashed LCOV
  artifact above is the reproducible local evidence.
- Issues #127 through #130 remain open. This change does not prove public
  direct-TLS/trusted-proxy parity, tenant certificate/key controller ownership,
  or removal of production OIDF Suite special cases.
- Additional high-value tests remain possible around complete OpenID4VP error
  branches, FAPI authorization-code concurrency, access/ID-token decode
  boundaries, and key-rotation grace/expiry. They are backlog, not hidden behind
  the current coverage percentage.

This audit makes the changed invariants and evidence durable; it does not claim
complete protocol conformance, a production deployment, or an external suite
pass.
