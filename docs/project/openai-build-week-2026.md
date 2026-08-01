# OpenAI Build Week 2026 Engineering Record

## Submission boundary

NazoAuth is a pre-existing project. OpenAI Build Week opened its submission
period on `2026-07-13T16:00:00Z` (`2026-07-14 01:00` JST). The submission
claims only work after that instant.

| Boundary | Commit |
| --- | --- |
| Last commit before the submission period | [`ef7df3e4606953002bb768a66a1897a06b42a332`](https://github.com/nazozero/NazoAuth/commit/ef7df3e4606953002bb768a66a1897a06b42a332) |
| Audited implementation snapshot | [`7b35aac4fc2cfae3d62cccedbe66795674870c2a`](https://github.com/nazozero/NazoAuth/commit/7b35aac4fc2cfae3d62cccedbe66795674870c2a) |
| Review range | [`ef7df3e..7b35aac`](https://github.com/nazozero/NazoAuth/compare/ef7df3e4606953002bb768a66a1897a06b42a332...7b35aac4fc2cfae3d62cccedbe66795674870c2a) |

Git reports 280 commits and 738 changed paths in that range, with 74,633
insertions and 48,332 deletions. Those counters include file moves, workspace
extraction, dependency metadata, and deleted legacy code; they are an auditable
change-volume measurement, not a claim of 74,633 lines of unique new
functionality.

Before the period, the project already provided a Rust OAuth/OIDC authorization
server, PostgreSQL/Valkey persistence, a browser UI, and an established
conformance baseline. Judges should evaluate only the following extension.

## What changed during the submission period

### Modular, production-oriented architecture

- [PR #56](https://github.com/nazozero/NazoAuth/pull/56) replaced the root
  monolith with a modular Rust workspace organized by protocol, domain, HTTP,
  persistence, state-store, runtime-capability, key-management, and server
  composition boundaries.
- Runtime capabilities gained revision-safe transitions, immutable snapshots,
  dependency validation, disable policies, stale-transition rejection, and
  auditable management behavior.
- The deployment path now verifies exact backend and frontend commits, hashes
  the UI artifact, preserves rollback state, runs migrations, and checks the
  public UI and discovery surface before committing a release.

### New protocol and product capabilities

- [PR #58](https://github.com/nazozero/NazoAuth/pull/58) added default-closed
  RFC 9967 SCIM security-event delivery with transactional persistence,
  receiver-bound SETs, polling, acknowledgements, retention, and tenant
  isolation.
- [PR #59](https://github.com/nazozero/NazoAuth/pull/59) completed the supported
  FAPI-CIBA combinations: poll/ping delivery with `private_key_jwt` or mTLS
  client authentication, sender-bound tokens, and bounded callback behavior.
- [PR #60](https://github.com/nazozero/NazoAuth/pull/60) implemented the
  OpenID4VC Final issuer and verifier roles, including authorization-code and
  pre-authorized-code issuance, DPoP, credential metadata, SD-JWT VC and mdoc
  paths, presentation requests, holder binding, encrypted responses, and
  negative security boundaries.
- [NazoAuthWeb PR #5](https://github.com/nazozero/NazoAuthWeb/pull/5) made
  authorization screens render verified client metadata and moved one-time
  credential delivery out of URL tokens into an authenticated, owner-bound
  profile flow.

### Black-box conformance and evidence

- [PR #57](https://github.com/nazozero/NazoAuth/pull/57) established isolated
  parallel OIDF execution rather than letting browser/session plans corrupt one
  another.
- [PR #61](https://github.com/nazozero/NazoAuth/pull/61),
  [PR #62](https://github.com/nazozero/NazoAuth/pull/62),
  [PR #63](https://github.com/nazozero/NazoAuth/pull/63), and
  [PR #64](https://github.com/nazozero/NazoAuth/pull/64) added the OpenID4VC
  dispatcher, public black-box evidence, and an operator-supplied issuer
  boundary.
- [PR #74](https://github.com/nazozero/NazoAuth/pull/74) removed privileged
  database seeding from the public test path. Conformance clients and trust
  material now go through the ordinary application, approval, one-time
  delivery, and cleanup control plane.
- [PR #80](https://github.com/nazozero/NazoAuth/pull/80),
  [PR #81](https://github.com/nazozero/NazoAuth/pull/81),
  [PR #82](https://github.com/nazozero/NazoAuth/pull/82),
  [PR #83](https://github.com/nazozero/NazoAuth/pull/83),
  [PR #84](https://github.com/nazozero/NazoAuth/pull/84), and
  [PR #85](https://github.com/nazozero/NazoAuth/pull/85) separated shared
  browser/user jobs, restored parallel execution where state is isolated,
  preferred runtime credentials, and retained only credential-free evidence.

### Security and release hardening

- [PR #76](https://github.com/nazozero/NazoAuth/pull/76) separated conformance
  tooling from production release artifacts and added repository release
  governance.
- [PR #79](https://github.com/nazozero/NazoAuth/pull/79) resolved a repository-
  wide Codex security review, including trust-boundary, cryptographic-key,
  deployment, browser, and artifact-retention findings. Decisions that were
  specification behavior rather than defects were documented instead of being
  changed merely to satisfy a scanner.
- Release gates cover formatting, workspace checks/tests, Clippy warnings,
  CodeQL security queries, dependency policy, container scanning, SBOMs,
  signing, and provenance attestations.

## How Codex and GPT-5.6 were used

The core Build Week work was carried out in Codex tasks running GPT-5.6. The
primary `/feedback` task identifier is supplied privately in the Devpost form
so judges can verify the dated interaction.

Codex accelerated:

- whole-repository architecture and dependency audits;
- small, reviewable Rust/TypeScript implementation steps;
- unit, property, integration, HTTP E2E, migration, browser-security, race, and
  failure-injection tests;
- comparison of behavior against OAuth, OIDC, FAPI, OpenID4VC, SCIM, and OIDF
  suite contracts;
- failure diagnosis across local checks, GitHub Actions, deployment, and the
  public official conformance service;
- security-review triage, remediation, evidence retention, and documentation.

The maintainer made the consequential decisions: crate/domain boundaries,
which protocol roles are supported or intentionally excluded, production
onboarding policy, public black-box testing, acceptable concurrency isolation,
licensing, and whether a change was ready to deploy or merge. The explicit
instruction was to implement standards correctly and let conformance follow,
never add suite-specific shortcuts or production backdoors.

## Run it locally

Prerequisites:

- a current Rust toolchain with the repository's locked dependencies;
- PostgreSQL;
- Valkey;
- Node.js/npm only when rebuilding the sibling browser application.

Start the backend with the documented minimal configuration:

```sh
cargo run --bin nazoauth -- server
# Review the generated .env.yaml, then:
cargo run --bin nazoauth -- migrate
cargo run --bin nazoauth -- server
curl -fsS http://127.0.0.1:8000/health
```

The detailed configuration and production container paths are in
[configuration.md](../operations/configuration.md) and
[deployment.md](../operations/deployment.md). The browser application lives in
[nazozero/NazoAuthWeb](https://github.com/nazozero/NazoAuthWeb) and runs its
complete gate with `npm ci && npm test`.

## Judge test path without rebuilding

The public demonstration instance is free to inspect and does not require a
shared judge credential:

1. Open <https://auth.nazo.run/ui/auth> and switch the interface to English.
2. Use the self-service registration entry if an authenticated account surface
   is required. Do not place credentials in issue reports or submission media.
3. Open <https://auth.nazo.run/ui/docs> for the integration surface.
4. Verify the live service with these read-only endpoints:
   - <https://auth.nazo.run/health>
   - <https://auth.nazo.run/.well-known/openid-configuration>
   - <https://auth.nazo.run/.well-known/oauth-authorization-server>
   - <https://auth.nazo.run/.well-known/openid-credential-issuer>
   - <https://auth.nazo.run/jwks.json>

The intended production platform is a Linux OCI/Podman deployment with
PostgreSQL and Valkey. Local development is supported wherever the Rust,
database, and state-store prerequisites are available. The browser UI targets
current desktop and mobile browsers.

## Evidence index

- [Certification and conformance evidence](../conformance/certification.md)
- [OpenID4VC Final matrix](../conformance/openid4vc-final-matrix.md)
- [Public black-box runbook](../conformance/oidf-public-black-box-runbook.md)
- [Dated public black-box result](../conformance/2026-07-19-public-black-box-full-oidf-results.md)
- [Release and conformance boundary](../operations/release-boundary.md)
- [Security review record](../security/codex-security-findings-2026-07-19.md)
