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
| Deployment | [operations/deployment.md](operations/deployment.md) |
| Chinese deployment | [operations/deployment.zh-CN.md](operations/deployment.zh-CN.md) |
| Configuration | [operations/configuration.md](operations/configuration.md) |
| Protocol and profile status | [protocol/profile-matrix.md](protocol/profile-matrix.md) |
| OIDF conformance evidence | [conformance/README.md](conformance/README.md) |
| Performance benchmark overview | [performance/performance-capacity-curve.md](performance/performance-capacity-curve.md) |

## Categories

| Area | Directory | Purpose |
| --- | --- | --- |
| Operations | [operations](operations) | Configuration, deployment, release-security, PostgreSQL, and Valkey operations. |
| Protocol | [protocol](protocol) | OAuth/OIDC/FAPI profile matrices, RFC coverage, protocol self-audits, and implementation backlog. |
| Features | [features](features) | Feature design and integration notes for ecosystem onboarding, tenancy, SCIM, federation, MFA, passkeys, and resource-server verification. |
| Security | [security](security) | Threat model, security policy links, and runtime security event taxonomy. |
| Conformance | [conformance](conformance) | OIDF and protocol conformance matrices, run records, and negative fixture notes. |
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
| [operations/ha-operations.md](operations/ha-operations.md) | PostgreSQL and Valkey operational guidance. |
| [operations/release-security.md](operations/release-security.md) | Release security checks, provenance, and supply-chain controls. |

### Protocol

| Document | Role |
| --- | --- |
| [protocol/profile-matrix.md](protocol/profile-matrix.md) | Runtime profile capability matrix. |
| [protocol/rfc-compliance-matrix.md](protocol/rfc-compliance-matrix.md) | OAuth, OAuth 2.1, OIDC, and FAPI best-practice matrix. |
| [protocol/oauth2-1-self-audit.md](protocol/oauth2-1-self-audit.md) | OAuth 2.1 and best-practice self-audit. |
| [protocol/oauth-spec-implementation-backlog.md](protocol/oauth-spec-implementation-backlog.md) | Protocol implementation backlog. |
| [protocol/oauth-best-practice-implementation-plan.zh-CN.md](protocol/oauth-best-practice-implementation-plan.zh-CN.md) | Chinese future roadmap for OAuth/OIDC/FAPI best practices. |
| [protocol/refresh-token-rotation.md](protocol/refresh-token-rotation.md) | Refresh-token rotation behavior and boundaries. |

### Features

| Document | Role |
| --- | --- |
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
| [../SECURITY.md](../SECURITY.md) | Security policy and reporting channel. |

### Conformance

| Document | Role |
| --- | --- |
| [conformance/README.md](conformance/README.md) | English conformance record index and update rules. |
| [conformance/README.zh-CN.md](conformance/README.zh-CN.md) | Chinese conformance record index. |
| [conformance/oidf-full-matrix.md](conformance/oidf-full-matrix.md) | OIDF full-matrix scope. |
| [conformance/oidf-full-matrix.zh-CN.md](conformance/oidf-full-matrix.zh-CN.md) | Chinese OIDF full-matrix scope. |
| [conformance/negative-fixtures.md](conformance/negative-fixtures.md) | Negative conformance fixture notes. |
| [conformance/2026-06-09-oidf-full-matrix.md](conformance/2026-06-09-oidf-full-matrix.md) | Certification baseline full-matrix evidence. |
| [conformance/2026-06-26-security-findings-full-matrix.md](conformance/2026-06-26-security-findings-full-matrix.md) | Security-finding full-matrix evidence. |
| [conformance/2026-06-27-pr15-official-oidf-full-matrix.md](conformance/2026-06-27-pr15-official-oidf-full-matrix.md) | PR 15 official OIDF full-matrix evidence. |
| [conformance/2026-07-01-ni-002-oidf-coverage.md](conformance/2026-07-01-ni-002-oidf-coverage.md) | NI-002 RFC 8628 coverage check. |
| [conformance/2026-07-01-ni-004-oidf-coverage.md](conformance/2026-07-01-ni-004-oidf-coverage.md) | NI-004 RFC 7591 coverage check. |
| [conformance/2026-07-01-tp-ps-full-matrix.md](conformance/2026-07-01-tp-ps-full-matrix.md) | TP/PS private full-matrix regression. |
| [conformance/2026-07-02-ni-004-official-oidf-full-matrix.md](conformance/2026-07-02-ni-004-official-oidf-full-matrix.md) | NI-004 official OIDF full-matrix evidence. |
| [conformance/2026-07-02-ni-005-oidf-coverage.md](conformance/2026-07-02-ni-005-oidf-coverage.md) | NI-005 RFC 7592 coverage check. |
| [conformance/2026-07-02-ni-006-011-private-oidf-results.md](conformance/2026-07-02-ni-006-011-private-oidf-results.md) | NI-006 through NI-011 private targeted results. |
| [conformance/2026-07-03-ni-006-011-official-parallel-isolated-oidf-results.md](conformance/2026-07-03-ni-006-011-official-parallel-isolated-oidf-results.md) | NI-006 through NI-011 official parallel-isolated results. |
| [conformance/2026-07-03-ni-007-public-ciba-oidf-results.md](conformance/2026-07-03-ni-007-public-ciba-oidf-results.md) | NI-007 public FAPI-CIBA results. |
| [conformance/2026-07-08-m2-official-parallel-isolated-oidf-results.md](conformance/2026-07-08-m2-official-parallel-isolated-oidf-results.md) | M2 official parallel-isolated OIDF results. |

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

### Examples

| Document | Role |
| --- | --- |
| [../examples/resource-server-fixtures.md](../examples/resource-server-fixtures.md) | Resource-server and client fixture notes. |

### Support Text Files

These files are text artifacts but are not general reader documentation.

| File | Role |
| --- | --- |
| [../requirements/codecov.txt](../requirements/codecov.txt) | Generated Python dependency lock input for Codecov tooling. |
| [../requirements/oidf-conformance.txt](../requirements/oidf-conformance.txt) | Generated Python dependency lock input for OIDF conformance tooling. |
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
- Keep conformance run records under `docs/conformance/` and update
  [conformance/README.md](conformance/README.md) when adding new official or
  private suite evidence.
- Keep generated lock files and regression seed corpora out of the reader-facing
  documentation flow; index them only as support artifacts.
