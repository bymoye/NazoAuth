<p align="center">
  <img src="docs/assets/nazo-auth-cover.png" alt="Nazo Auth cover">
</p>

# Nazo Auth Server

[![code-quality](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml)
[![oidf-conformance-full](https://github.com/nazozero/NazoAuth/actions/workflows/oidf-conformance-full.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/oidf-conformance-full.yml)
[![codecov](https://codecov.io/gh/nazozero/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/nazozero/NazoAuth)

[中文文档](README.zh-CN.md) · [Documentation](#documentation) · [Quick start](#quick-start) · [Security](SECURITY.md)

Nazo Auth Server is a self-hosted OAuth 2.x / OAuth 2.1-aligned and OpenID
Connect authorization server written in Rust. It is built for same-origin
deployments where the issuer, browser UI, passkeys, CORS, cookies, and protocol
endpoints share one public origin.

The project includes the authorization server, a compact identity/admin surface,
local signing key management, WebAuthn/passkeys, MFA, SCIM, and Rust
resource-server verification libraries. Modular external-provider login is
tracked in the future roadmap rather than advertised as a current default
capability. It uses PostgreSQL for durable state and Valkey for short-lived
protocol state.

## OpenAI Build Week 2026

NazoAuth predates OpenAI Build Week. The hackathon submission covers only the
work completed after the submission period opened at
`2026-07-13T16:00:00Z`. The last pre-period commit is
[`ef7df3e`](https://github.com/nazozero/NazoAuth/commit/ef7df3e4606953002bb768a66a1897a06b42a332),
and the complete review range is
[`ef7df3e..main`](https://github.com/nazozero/NazoAuth/compare/ef7df3e4606953002bb768a66a1897a06b42a332...main).

During the submission period, Codex with GPT-5.6 helped turn the existing
server into a modular Rust workspace, implement OpenID4VC Final issuer and
verifier roles, add FAPI-CIBA mTLS/ping and RFC 9967 SCIM security-event
delivery, harden the browser client and onboarding flow, and make the official
OIDF suites exercise the public production service as a black box. Codex
accelerated repository audits, implementation, tests, specification
cross-checks, CI diagnosis, and deployment verification. The maintainer chose
the product and security boundaries, required standards-first behavior instead
of suite-specific shortcuts, reviewed the changes, and controlled deployment
and merge decisions.

See the [Build Week engineering record](docs/project/openai-build-week-2026.md)
for the before/after boundary, dated pull requests, measured change volume,
Codex collaboration details, setup instructions, and a no-rebuild public test
path. The live demo is available at <https://auth.nazo.run/ui/auth>.

## Status

| Item | Value |
| --- | --- |
| Package | `nazo-oauth-server` |
| Workspace version | `0.1.9` release candidate |
| License | AGPL-3.0-or-later |
| Language | Rust 2024 |
| Runtime services | PostgreSQL, Valkey |
| Conformance test issuer | operator-provided public HTTPS origin |
| Default deployment model | same-origin |

## Quality Signals

Project quality is tracked through direct, auditable checks rather than a
composite score:

| Signal | Evidence |
| --- | --- |
| Rust quality gate | `cargo fmt --check`, `cargo check --workspace --all-targets --all-features --locked`, `cargo clippy -D warnings`, migrations, and the complete workspace test suite in `code-quality`. |
| Static security analysis | CodeQL Rust analysis with the `security-extended` query suite. |
| Dependency policy | GitHub dependency review, `cargo audit`, and `cargo deny` over advisories, bans, licenses, and sources. |
| Runtime security behavior | Real HTTP E2E, load/race gate, and Valkey outage injection in `conformance-security`. |
| Protocol conformance | The release gate runs the fixed 27-plan OIDC/FAPI/CIBA/logout matrix and the fixed 17-plan OpenID4VCI/VP matrix against the same public deployment. Historical and exact-release evidence remains versioned under `docs/conformance`. |
| Coverage trend | Codecov LCOV upload from the dedicated coverage workflow. |
| Release provenance | CycloneDX SBOM, Trivy image scan, Sigstore signing, and GitHub artifact attestations. |

## Standards

📚 [Standards and profile support](docs/integration/openid-connect.md)

## Certification

🏅 [Certification and conformance evidence](docs/conformance/certification.md)

## Features

- Authorization code + PKCE, refresh tokens, client credentials, bounded JWT
  bearer grant, bounded Token Exchange, revocation, introspection,
  signed/encrypted introspection, discovery, protected resource metadata, JWKS,
  JSON/signed/encrypted UserInfo, signed/encrypted JARM, PAR, JAR, DPoP, and
  mTLS.
- Runtime profiles: `oauth2-baseline`, `fapi2-security`,
  `fapi2-message-signing-authz-request`, `fapi2-message-signing-jarm`, and
  `fapi2-message-signing-introspection`.
- Local users, profiles, OAuth clients, grants, access requests, TOTP MFA,
  backup codes, remembered MFA, WebAuthn/passkeys, and SCIM provisioning.
- Local signing key lifecycle with prepublish, active, grace, and retired
  states. External-command signing is available for KMS/HSM integrations.
- Framework-independent Rust resource-server verifier plus the project's Actix
  HTTP integration. Historical Axum/Tower and tonic adapters are not shipped.
- Release security workflows for CodeQL, dependency review, cargo audit,
  cargo deny, SBOM generation, Trivy image scanning, keyless signing, and
  provenance attestations.

## Quick start

Install the independently signed `nazoauthctl` from
[`nazozero/NazoAuthCtl`](https://github.com/nazozero/NazoAuthCtl). Controller
source, CI, installation, and Releases now live only in that repository; the
NazoAuth `v0.1.20` tag retains the pre-removal source as a review and rollback
point. See the [repository split boundary](docs/operations/controller-repository-split.md),
then run:

```sh
sudo nazoauthctl install --runtime auto
sudo nazoauthctl bootstrap-admin
sudo nazoauthctl status
sudo nazoauthctl doctor
```

`auto` selects Podman first and Docker second. The controller generates private
PostgreSQL and Valkey credentials, starts both services, runs a signed one-shot
migration task, and starts NazoAuth. There are no published default passwords.
Open `http://127.0.0.1:8000/health` or
`http://127.0.0.1:8000/.well-known/openid-configuration`. Data, signing keys,
generated application secrets, and avatars are persistent.

On a database without an administrator, `nazoauthctl bootstrap-admin` reads the
runtime-owned one-time claim without printing it. Interactive use prompts on a
TTY; automation supplies the closed credential document through stdin or a
dedicated file descriptor. The token, credentials, and any token-bearing URL
never enter argv, ordinary environment variables, logs, or audit records.

For a public issuer, pass `--public-url https://auth.example.com`; see the
[deployment guide](docs/operations/deployment.md) for TLS ingress requirements.
`compose.yml` remains a source-tree development sandbox and uses a development
operator identity; it is not the production lifecycle boundary.

For a direct binary run, `server` creates a local `.env.yaml` when absent,
generates persistent application secrets, creates signing keys when needed,
and continues starting. Schema changes are deliberately owned by the host-side
controller and are never attempted by the managed server runtime:

```sh
nazoauth server
```

Explicit YAML and environment values still take precedence. Managed deployments
run schema changes only through `sudo nazoauthctl migrate --yes`, which issues a
short-lived signed task to the exact verified release target.

## Configuration

Configuration is intentionally small for new deployments:

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
RUST_LOG: "info"
```

`CLIENT_SECRET_PEPPER`, the DCR initial-access token, and a pairwise-subject
secret when required are generated under `DATA_DIR/secrets` if absent.
Back up that directory with the database. A missing or malformed persisted
secret fails startup instead of being silently replaced.

New deployments use composable server capabilities and explicit per-client
policy. `AUTHORIZATION_SERVER_PROFILE` is retained only as a compatibility
preset for clients that predate stored client policy.

`PUBLIC_BASE_URL` drives the same-origin defaults:

| Value | Default rule |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL` |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` |
| `CORS_ALLOWED_ORIGINS` | origin of `PUBLIC_BASE_URL` |
| `COOKIE_SECURE` | `true` for HTTPS issuers |
| `PASSKEY_ORIGIN` and `PASSKEY_RP_ID` | derived from issuer |
| `PROTECTED_RESOURCE_IDENTIFIER` | `ISSUER + "/fapi/resource"` |

`DATA_DIR` drives persistent local file paths:

| Value | Default rule |
| --- | --- |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"` |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"` |

Advanced settings cover specialized deployments.
They are documented in [docs/operations/configuration.md](docs/operations/configuration.md).

## Default boundaries

Stable, non-conflicting server handlers are active together on new databases.
This includes signed Request Objects, JARM, Device Grant, CIBA poll/ping, the
bounded Token Exchange and JWT Bearer Grant profiles, SCIM, Front-Channel
Logout, and Session Management. Server support does not grant a client access:
grant allowlists, registered metadata, sender constraints, and the versioned
per-client `security_policy` still fail closed.

The following capabilities remain conditional or excluded:

- Dynamic Client Registration / RFC 7591 and Client Configuration Management
  / RFC 7592 require a configured
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`.
- OpenID4VCI, OpenID4VP, SCIM Security Events, Native SSO, RAR, and experimental
  HTTP Signatures require their complete role-specific prerequisites.
- External-token, refresh-token, or ID-token Token Exchange profiles.
- Modular third-party login providers such as QQ, WeChat, Google, Microsoft, or
  enterprise SAML; these are roadmap items until provider-specific adapters,
  configuration gates, account linking, and E2E/negative tests exist.
- Request-level dynamic tenant or issuer routing.
- RFC 9701 encrypted introspection responses outside the signed-introspection
  profile, or without per-client JWE response metadata.
- UserInfo or JARM encryption without supported per-client JWE metadata and a
  unique matching public encryption key.

See [docs/project/roadmap.md](docs/project/roadmap.md) for the current scope record.

## Documentation

| Topic | Link |
| --- | --- |
| Documentation index | [docs/README.md](docs/README.md) |
| Workspace architecture | [docs/project/architecture.md](docs/project/architecture.md) |
| OpenAI Build Week 2026 engineering record | [docs/project/openai-build-week-2026.md](docs/project/openai-build-week-2026.md) |
| Configuration | [docs/operations/configuration.md](docs/operations/configuration.md) |
| Deployment | [docs/operations/deployment.md](docs/operations/deployment.md) |
| Chinese deployment guide | [docs/operations/deployment.zh-CN.md](docs/operations/deployment.zh-CN.md) |
| One-click updates | [docs/operations/one-click-update.md](docs/operations/one-click-update.md) |
| 一键升级 | [docs/operations/one-click-update.zh-CN.md](docs/operations/one-click-update.zh-CN.md) |
| Conformance records | [docs/conformance](docs/conformance) |
| Performance benchmarks | [docs/performance/performance-capacity-curve.md](docs/performance/performance-capacity-curve.md) |
| OAuth/OIDC/FAPI best-practice matrix | [docs/protocol/rfc-compliance-matrix.md](docs/protocol/rfc-compliance-matrix.md) |
| OAuth/OIDC/FAPI future roadmap | [docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md](docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md) |
| Profile matrix | [docs/protocol/profile-matrix.md](docs/protocol/profile-matrix.md) |
| Composable capability policy | [docs/protocol/composable-capability-policy.md](docs/protocol/composable-capability-policy.md) |
| Ecosystem client onboarding | [docs/features/ecosystem-onboarding.md](docs/features/ecosystem-onboarding.md) |
| Threat model | [docs/security/threat-model.md](docs/security/threat-model.md) |
| Release security | [docs/operations/release-security.md](docs/operations/release-security.md) |
| PostgreSQL and Valkey operations | [docs/operations/ha-operations.md](docs/operations/ha-operations.md) |
| Resource server verifier | [docs/features/resource-server-verifier.md](docs/features/resource-server-verifier.md) |
| SCIM | [docs/features/scim.md](docs/features/scim.md) |
| Federation | [docs/features/federation.md](docs/features/federation.md) |
| Passkeys | [docs/features/passkeys.md](docs/features/passkeys.md) |
| MFA | [docs/features/mfa.md](docs/features/mfa.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Development

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

HTTP and concurrency checks:

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

Coverage runs are documented in
[docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md).

## License

The public source code is licensed under
[AGPL-3.0-or-later](LICENSE). This applies equally to individuals and
organizations. A separate commercial license may be available for qualifying
closed-source use, but is granted only by a signed agreement with the applicable
copyright holders. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).
