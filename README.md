<p align="center">
  <img src="docs/assets/nazo-auth-cover.png" alt="Nazo Auth cover">
</p>

# Nazo Auth Server

[![code-quality](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml)
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
delivery, and harden the browser client and onboarding flow. Codex
accelerated repository audits, implementation, tests, specification
cross-checks, CI diagnosis, and deployment verification. The maintainer chose
the product and security boundaries, required standards-first behavior instead
of external-client shortcuts, reviewed the changes, and controlled deployment
and merge decisions.

See the [Build Week engineering record](docs/project/openai-build-week-2026.md)
for the before/after boundary, dated pull requests, measured change volume,
Codex collaboration details, setup instructions, and a no-rebuild public test
path. The live demo is available at <https://auth.nazo.run/ui/auth>.

## Status

| Item | Value |
| --- | --- |
| Application package | `nazo-oauth-server` (database-neutral library) |
| Default distribution package | `nazoauth` (PostgreSQL + Valkey) |
| Storage adapters | `nazo-oauth-server-postgres`, `nazo-oauth-server-valkey` |
| Workspace version | `0.2.3` |
| License | AGPL-3.0-or-later |
| Language | Rust 2024 |
| Runtime services | PostgreSQL, plus Valkey |
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
| External protocol validation | Third-party clients exercise only public protocol and tenant-resource interfaces. |
| Coverage trend | Codecov LCOV upload from the dedicated coverage workflow. |
| Release provenance | CycloneDX SBOM, Trivy image scan, Sigstore signing, and GitHub artifact attestations. |

## Standards

📚 [Standards and profile support](docs/integration/openid-connect.md)

## Certification

🏅 External validators interact with NazoAuth exactly like any other client.

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
source, CI, installation, and Releases live only in that repository. Register
the target and provide two existing, distinct PostgreSQL roles plus the existing
Valkey credential:

```sh
nazoauthctl host add production-host --ssh production --privilege sudo
nazoauthctl install --host production-host --name production \
  --public-url https://auth.example.com --runtime podman \
  --database-host db.internal --database-port 5432 --database-name oauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password
nazoauthctl admin create --instance production
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl status --instance production
nazoauthctl doctor --instance production
```

The runtime is exactly `podman`, `docker`, or `host`; there is no automatic
runtime selection. NazoAuthCtl never creates credentials for external
PostgreSQL or Valkey. The lifecycle PostgreSQL role runs migrations, backup,
and recovery; the less-privileged runtime role is the only database identity
given to the server. Open `http://127.0.0.1:8000/health` or
`http://127.0.0.1:8000/.well-known/openid-configuration` on the target's
private boundary. Data, signing keys, generated application secrets, and
avatars are persistent. See [managed installation, update, and recovery](docs/operations/one-click-update.md)
for current-format import and backup policy.

On a database without an administrator, `nazoauthctl admin create` invokes
the target runtime's local `nazoauth admin-provision` one-shot command. The
closed credential document is supplied through the controller's protected
credential path; it is never sent through an HTTP bootstrap route, argv,
ordinary environment variables, logs, or audit records.

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

Explicit YAML and environment values still take precedence. In managed
deployments, schema changes run only inside the signed install, update, or
recover lifecycle operation for the exact verified release target. The server
runtime never holds the lifecycle database credential.

## Configuration

Configuration is intentionally small for new deployments:

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "disabled"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
RUST_LOG: "info"
```

For standalone HTTPS without a reverse proxy, select `TRANSPORT_MODE:
"direct-tls"` and configure the server certificate, private key, mTLS client CA,
and dedicated mTLS listener described in
[`docs/operations/configuration.md`](docs/operations/configuration.md).

`CLIENT_SECRET_PEPPER`, the DCR initial-access token, and a pairwise-subject
secret when required are generated under `DATA_DIR/secrets` if absent.
Back up that directory with the database. A missing or malformed persisted
secret fails startup instead of being silently replaced.

Deployments use composable server capabilities and explicit, versioned
per-client policy. Every OAuth client must have a current `security_policy`;
the server does not infer one from a process-level preset.

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
