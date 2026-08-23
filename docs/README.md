# Documentation

This directory groups durable project documentation by responsibility. Root
files and a few adjacent runbooks remain outside `docs/` when their location is
part of the repository interface, but they are indexed here so the full document
set can be scanned from one place.

## Start Here

| Need | Document |
| --- | --- |
| Project overview | [../README.md](../README.md) |
| Chinese project overview | [../README.zh-CN.md](../README.zh-CN.md) |
| Security policy | [../SECURITY.md](../SECURITY.md) |
| Change history | [../CHANGELOG.md](../CHANGELOG.md) |
| Current scope and roadmap | [project/roadmap.md](project/roadmap.md) |
| Workspace and runtime-module architecture | [project/architecture.md](project/architecture.md) |
| OpenAI Build Week 2026 engineering record | [project/openai-build-week-2026.md](project/openai-build-week-2026.md) |
| Deployment | [operations/deployment.md](operations/deployment.md) |
| Chinese deployment | [operations/deployment.zh-CN.md](operations/deployment.zh-CN.md) |
| Fresh production activation | [operations/fresh-production-activation.md](operations/fresh-production-activation.md) |
| Chinese fresh production activation | [operations/fresh-production-activation.zh-CN.md](operations/fresh-production-activation.zh-CN.md) |
| Configuration | [operations/configuration.md](operations/configuration.md) |
| Release platform support | [operations/platform-support.md](operations/platform-support.md) |
| Operator-task security and UX plan | [security/operator-task-protocol-plan.zh-CN.md](security/operator-task-protocol-plan.zh-CN.md) |
| Operator-task implementation task book | [project/operator-task-protocol-implementation-task.zh-CN.md](project/operator-task-protocol-implementation-task.zh-CN.md) |
| OpenID Connect integration | [integration/openid-connect.md](integration/openid-connect.md) |
| Chinese OpenID Connect integration | [integration/openid-connect.zh-CN.md](integration/openid-connect.zh-CN.md) |
| Protocol and profile status | [protocol/profile-matrix.md](protocol/profile-matrix.md) |
| Composable capability policy | [protocol/composable-capability-policy.md](protocol/composable-capability-policy.md) |
| Product-owned SCIM regression contract | [conformance/README.md](conformance/README.md) |
| Performance benchmark overview | [performance/performance-capacity-curve.md](performance/performance-capacity-curve.md) |

## Categories

| Area | Directory | Purpose |
| --- | --- | --- |
| Integration | [integration](integration) | Relying-party and ecosystem integration guides. |
| Operations | [operations](operations) | Configuration, deployment, release-security, PostgreSQL, and Valkey operations. |
| Protocol | [protocol](protocol) | OAuth/OIDC/FAPI profile matrices, RFC coverage, protocol self-audits, and implementation backlog. |
| Features | [features](features) | Feature design and integration notes for ecosystem onboarding, tenancy, SCIM, federation, MFA, passkeys, and resource-server verification. |
| Security | [security](security) | Threat model, security policy links, and runtime security event taxonomy. |
| Conformance | [conformance](conformance) | Product-owned black-box regression contracts. External Suite artifacts and orchestration live in NazoAuthCtl. |
| Coverage | [coverage](coverage) | Coverage runbooks and evidence. |
| Performance | [performance](performance) | NazoAuth-only capacity, stress, and benchmark reports. |
| Project | [project](project) | Product scope, roadmap, and project-level decision records. |
| Examples | [../examples](../examples) | Resource-server and client fixture documentation. |
| Benchmark tooling | [../perf](../perf) | Reproducible load-test runner instructions and generated report sources. |

## Inventory

### Root Documents

| Document | Role |
| --- | --- |
| [../README.md](../README.md) | Primary English project overview, standards, quick start, and documentation entry point. |
| [../README.zh-CN.md](../README.zh-CN.md) | Primary Chinese project overview and quick start. |
| [../SECURITY.md](../SECURITY.md) | Vulnerability reporting and supported security policy. |
| [../CHANGELOG.md](../CHANGELOG.md) | Release and notable-change history. |

### Operations

| Document | Role |
| --- | --- |
| [operations/configuration.md](operations/configuration.md) | Runtime configuration model and environment settings. |
| [operations/deployment.md](operations/deployment.md) | English deployment guide. |
| [operations/deployment.zh-CN.md](operations/deployment.zh-CN.md) | Chinese deployment guide. |
| [operations/one-click-update.md](operations/one-click-update.md) | Signed one-click Podman, Docker, and host installation and updates. |
| [operations/one-click-update.zh-CN.md](operations/one-click-update.zh-CN.md) | Chinese signed one-click installation and update guide. |
| [operations/ha-operations.md](operations/ha-operations.md) | PostgreSQL and Valkey operational guidance. |
| [operations/release-security.md](operations/release-security.md) | Release security checks, provenance, and supply-chain controls. |
| [operations/platform-support.md](operations/platform-support.md) | Native binary targets, OCI architectures, dependency boundaries, and binary-only Release assets. |
| [operations/release-boundary.md](operations/release-boundary.md) | Production artifact and conformance-tool separation boundary. |
| [operations/release-boundary.zh-CN.md](operations/release-boundary.zh-CN.md) | Chinese production artifact and conformance-tool separation boundary. |
| [operations/github-actions-secrets.md](operations/github-actions-secrets.md) | GitHub Actions Secret inventory and rotation rules. |
| [operations/github-actions-secrets.zh-CN.md](operations/github-actions-secrets.zh-CN.md) | Chinese GitHub Actions Secret inventory and rotation rules. |

### Integration

| Document | Role |
| --- | --- |
| [integration/openid-connect.md](integration/openid-connect.md) | OpenID Connect relying-party integration guide and security boundaries. |
| [integration/openid-connect.zh-CN.md](integration/openid-connect.zh-CN.md) | Chinese OpenID Connect relying-party integration guide and security boundaries. |

### Protocol

| Document | Role |
| --- | --- |
| [protocol/composable-capability-policy.md](protocol/composable-capability-policy.md) | Server defaults, per-client authority, compatible policy composition, and upgrade semantics. |
| [protocol/profile-matrix.md](protocol/profile-matrix.md) | Runtime profile capability matrix. |
| [protocol/rfc-compliance-matrix.md](protocol/rfc-compliance-matrix.md) | OAuth, OAuth 2.1, OIDC, and FAPI best-practice matrix. |
| [protocol/oauth2-1-self-audit.md](protocol/oauth2-1-self-audit.md) | OAuth 2.1 and best-practice self-audit. |
| [protocol/spec-freshness.md](protocol/spec-freshness.md) | Machine-checked current specification inventory. |
| [protocol/oauth-spec-implementation-backlog.md](protocol/oauth-spec-implementation-backlog.md) | Protocol implementation backlog. |
| [protocol/oauth-best-practice-implementation-plan.zh-CN.md](protocol/oauth-best-practice-implementation-plan.zh-CN.md) | Chinese future roadmap for OAuth/OIDC/FAPI best practices. |
| [protocol/refresh-token-rotation.md](protocol/refresh-token-rotation.md) | Refresh-token rotation behavior and boundaries. |

### Features

| Document | Role |
| --- | --- |
| [features/account-profile.md](features/account-profile.md) | Authenticated account profile, pending-MFA projection, caching, and update-consistency contract. |
| [features/ecosystem-onboarding.md](features/ecosystem-onboarding.md) | External client onboarding, DCR/DCRM, Token Exchange, and third-party JWT bearer trust boundaries. |
| [features/federation.md](features/federation.md) | External identity federation design notes. |
| [features/mfa.md](features/mfa.md) | MFA and step-up authentication design notes. |
| [features/passkeys.md](features/passkeys.md) | WebAuthn passkey behavior. |
| [features/resource-server-verifier.md](features/resource-server-verifier.md) | Rust resource-server verifier integration. |
| [features/scim.md](features/scim.md) | SCIM 2.0 provisioning behavior. |
| [features/tenancy.md](features/tenancy.md) | Tenant, realm, and organization boundary model. |

### Security

| Document | Role |
| --- | --- |
| [security/threat-model.md](security/threat-model.md) | Threat model and security boundaries. |
| [security/security-events.md](security/security-events.md) | Security event taxonomy. |
| [security/operator-task-protocol-plan.zh-CN.md](security/operator-task-protocol-plan.zh-CN.md) | Chinese security, capability-boundary, UX, rollout, and final-acceptance plan for privileged ctl/app interactions. |
| [../SECURITY.md](../SECURITY.md) | Security policy and reporting channel. |

### Conformance

| Document | Role |
| --- | --- |
| [conformance/README.md](conformance/README.md) | Product-owned SCIM regression contract. |

### Coverage

| Document | Role |
| --- | --- |
| [coverage/codecov-docker-runbook.md](coverage/codecov-docker-runbook.md) | Codecov Docker runbook. |

### Performance

| Document | Role |
| --- | --- |
| [../perf/README.md](../perf/README.md) | Benchmark runner usage, load model, profiles, and metrics. |
| [performance/README.md](performance/README.md) | Local performance documentation index, report groups, common semantics, and maintenance rules. |
| [performance/performance-capacity-curve.md](performance/performance-capacity-curve.md) | Unified capacity benchmark overview. |
| [performance/performance-benchmarks.md](performance/performance-benchmarks.md) | Latest generated benchmark report. |
| [performance/summaries](performance/summaries) | Main and extended capacity matrix summaries. |
| [performance/reports](performance/reports) | Scenario-level capacity reports grouped by main, extended, and special runs. |
| [performance/archive/dev](performance/archive/dev) | Historical development benchmark reports. |

### Project

| Document | Role |
| --- | --- |
| [project/roadmap.md](project/roadmap.md) | Current scope, roadmap, and deferred capability record. |
| [project/architecture.md](project/architecture.md) | Workspace boundaries, dependency direction, composition, and runtime-module lifecycle contract. |
| [project/spec-coverage-and-responsibility-audit-2026-08-20.md](project/spec-coverage-and-responsibility-audit-2026-08-20.md) | Exact-head specification-to-test traceability, Linux coverage evidence, residual gaps, and file-responsibility decisions for the 2026-08-20 audit. |
| [project/operator-task-protocol-implementation-task.zh-CN.md](project/operator-task-protocol-implementation-task.zh-CN.md) | Chinese ordered implementation task book for the signed operator-task protocol and ctl UX. |
| [project/openai-build-week-2026.md](project/openai-build-week-2026.md) | English Build Week before/after boundary, Codex collaboration, evidence, and judge test path. |

### Examples

| Document | Role |
| --- | --- |
| [../examples/resource-server-fixtures.md](../examples/resource-server-fixtures.md) | Resource-server and client fixture notes. |

### Support Text Files

These files are text artifacts but are not general reader documentation.

| File | Role |
| --- | --- |
| [../requirements/codecov.txt](../requirements/codecov.txt) | Generated Python dependency lock input for Codecov tooling. |
| [../proptest-regressions/support/responses.txt](../proptest-regressions/support/responses.txt) | Proptest regression seed corpus. |
| [../proptest-regressions/support/uri_policy.txt](../proptest-regressions/support/uri_policy.txt) | Proptest URI policy regression seed corpus. |

## Maintenance Rules

- Keep durable design, operations, protocol, security, conformance, coverage,
  performance, and project records under the matching `docs/` subdirectory.
- Keep user-facing repository entry points at the repository root when tools or
  hosting expect them there: `README.md`, `README.zh-CN.md`, `SECURITY.md`, and
  `CHANGELOG.md`.
- Keep benchmark runner instructions in `perf/README.md`; performance entry
  points and summaries belong under `docs/performance/`, while scenario
  reports belong under `docs/performance/reports/`.
- Keep product-owned black-box regression contracts under `docs/conformance/`.
  External Suite evidence is owned by NazoAuthCtl.
- Keep generated lock files and regression seed corpora out of the reader-facing
  documentation flow; index them only as support artifacts.
