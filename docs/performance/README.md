# Performance Documentation

This directory keeps benchmark documentation and durable performance evidence
for NazoAuth. The root of this directory is reserved for stable entry points;
scenario-level reports are grouped below `reports/`.

## Entry Points

| Document | Role |
| --- | --- |
| [performance-capacity-curve.md](performance-capacity-curve.md) | Unified capacity benchmark overview across the main and extended matrices. |
| [performance-benchmarks.md](performance-benchmarks.md) | Latest generated benchmark report from `perf/runner.py`. |
| [summaries/performance-capacity-main-summary.md](summaries/performance-capacity-main-summary.md) | Main capacity matrix summary. |
| [summaries/performance-capacity-extended-summary.md](summaries/performance-capacity-extended-summary.md) | Extended capacity matrix summary. |

## Report Groups

| Group | Directory | Contents |
| --- | --- | --- |
| Main matrix | [reports/main](reports/main) | Token-only, OIDC, refresh-only, and FAPI2 logged-in capacity reports. |
| Extended matrix | [reports/extended](reports/extended) | mTLS, PAR/JAR, introspection, revocation, discovery/JWKS, CIBA, and same-user contention reports. |
| Special runs | [reports/special](reports/special) | App CPU and single-instance capacity experiments. |
| Development archive | [archive/dev](archive/dev) | Historical development capacity reports. |

## Evidence Model

- Markdown summaries and scenario reports live under `docs/performance/`.
- Structured benchmark results and environment captures live under
  [`../../perf/results`](../../perf/results).
- Benchmark runner instructions live in [`../../perf/README.md`](../../perf/README.md).
- Scenario reports intentionally keep only a compact evidence table, capacity
  curve table, and step breakdown. Repeated runner topology belongs in the
  linked `perf/results/cnb-environment-*.md` capture instead of being copied
  into every report.

## Common Semantics

- `oidc_cold_login_refresh` includes a fresh Argon2 password login in every
  flow.
- `oidc_logged_in_authorization_code` keeps a session per VU after warm-up and
  measures authorization-code work without per-flow password verification.
- `oidc_refresh_only` uses pre-seeded refresh tokens and measures refresh
  rotation only; password login is intentionally excluded from this scenario.
- `fapi2_logged_in_high_security` keeps a session per VU after warm-up and
  measures PAR, signed request object, `private_key_jwt`, and DPoP
  authorization-code and refresh work without per-flow password verification.
- Per-core normalization uses observed Docker CPU percent for the NazoAuth
  service: `100%` equals one effective CPU core.

## Maintenance Rules

- Keep stable reader entry points in this directory root.
- Put new main matrix scenario reports under `reports/main/`.
- Put new extended matrix scenario reports under `reports/extended/`.
- Put one-off CPU, single-instance, or experiment reports under
  `reports/special/`.
- Keep generated JSON results and environment captures in `perf/results/`.
- Update [performance-capacity-curve.md](performance-capacity-curve.md) and
  the relevant summary file when adding a durable scenario report.
