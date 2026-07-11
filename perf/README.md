# NazoAuth Performance Benchmarks

This directory contains reproducible Docker Compose based load benchmarks for
NazoAuth. It is separate from correctness, conformance, and browser UI tests.

## Run

Run the full matrix:

```sh
make perf
```

Equivalent direct command:

```sh
docker compose -f docker-compose.perf.yml up --build --abort-on-container-exit --exit-code-from perf
```

Run one profile:

```sh
PERF_PROFILE=oidc-mixed make perf
```

Run one scenario:

```sh
PERF_SCENARIO=token_client_credentials PERF_DURATION=30s PERF_VUS=16 make perf
```

Run a short capacity-curve smoke test:

```sh
make perf-capacity-smoke
```

Run the long fixed-arrival-rate capacity curve:

```sh
make perf-capacity
```

Run a short App CPU smoke test:

```sh
./perf/cnb_app_cpu_capacity_smoke.sh
```

This test uses the NazoAuth service CPU override only (`PERF_APP_CPUS`, default
`1`; optionally `PERF_APP_TASKSET` for process-level CPU affinity). PostgreSQL,
Valkey, migration, key setup, and the k6 perf runner remain unrestricted unless
`APP_CPU_CAPACITY_INFRA_CPUSET` is set explicitly. In nested Docker
environments where Docker CPU quota is not enforced reliably, process-level
`taskset` is the effective limiter.

Run a single-instance full-flow max test:

```sh
./perf/cnb_single_instance_full_flow_max.sh
```

This runs one NazoAuth instance through the full OIDC cold-login flow with
short, high-arrival-rate points. The script splits the runner's allowed CPU set
into an application half and an infrastructure half: NazoAuth is pinned to the
application half, while PostgreSQL, Valkey, migration, key setup, and k6 use the
infrastructure half. The default scenario is `oidc_cold_login_refresh`, which
includes PAR, password login, authorization decision, authorization-code token
exchange, and refresh-token rotation.

Run the extended fixed-arrival-rate matrix on a dedicated CNB runner:

```sh
./perf/cnb_extended_capacity_matrix.sh
```

The long capacity curve runs 30 minutes per point across 1, 2, and 4 NazoAuth
replicas. It is intended for dedicated benchmark machines, not routine local
verification.

Results are written to `perf/results/*.summary.json` and
`perf/results/*.k6.json`. Markdown entry-point reports are written to
`docs/performance/performance-benchmarks.md` and
`docs/performance/performance-capacity-curve.md`; scenario-specific capacity
reports are grouped under `docs/performance/reports/`.

## Load Model

The default model is intentionally closer to production traffic than a shared
happy-path session:

- Multi-user profiles seed a real user pool through `PERF_USER_COUNT`. Each k6
  VU is bound to one user account for the duration of the scenario, with its own
  login session, authorization request, code, refresh token, and DPoP proofs.
- If `PERF_USER_COUNT` is lower than the configured concurrency, the runner
  raises it so the default multi-user case does not collapse into accidental
  account sharing.
- Same-user contention is a separate profile. It deliberately sends concurrent
  flows through one account to expose session, CSRF, refresh rotation, and
  account-level locking behavior under stress.
- `PERF_FLOW_VUS` defaults to `PERF_VUS`. It is only an explicit override for
  long authorization-code style flows, not a hidden reduction in concurrency.

The compose stack also starts a local runtime keyset service before NazoAuth so
FAPI paths can issue the required RS256 and PS256 server-side tokens.

## Profiles

| Profile | Scenarios | Purpose |
| --- | --- | --- |
| `single-endpoint` | `token_client_credentials`, `mtls_client_credentials`, `par_signed_request_object` | Isolates endpoint throughput and authentication overhead. |
| `oidc-mixed` | `refresh_token_rotation`, `introspect_opaque_refresh_token`, `authorize_par_session` | Exercises normal OIDC login, PAR, authorization-code exchange, refresh rotation, and opaque refresh-token introspection across many users. |
| `oidc-same-user-contention` | `same_user_refresh_token_rotation`, `same_user_introspect_opaque_refresh_token`, `same_user_authorize_par_session` | Exercises concurrent operations from one account to reveal account/session contention risks. |
| `fapi2-high-security` | `fapi2_par_jar_private_key_jwt_dpop` | Exercises PAR + signed JAR + `private_key_jwt` + DPoP-bound authorization-code and refresh paths. |
| `capacity` | `token_only_client_credentials`, `oidc_cold_login_refresh`, `oidc_logged_in_authorization_code`, `oidc_refresh_only`, `fapi2_full_security` | Fixed-arrival-rate scenarios used by `perf/capacity.py` to build 1/2/4 replica capacity curves. |
| `extended-capacity` | `mtls_client_credentials`, `par_signed_request_object`, `introspect_opaque_refresh_token`, `authorize_par_session`, `revoke_refresh_token`, `metadata_jwks`, `ciba_private_key_jwt_dpop_poll`, `same_user_refresh_token_rotation`, `same_user_introspect_opaque_refresh_token`, `same_user_authorize_par_session` | Covers protocol and security surfaces that should not be mixed into the primary capacity curve. |

## Capacity Curve Model

`perf/capacity.py` runs one fixed-arrival-rate point at a time, tears down the
compose stack, and repeats for each selected replica count, scenario, and rate.
The default long matrix covers:

- `token_only_client_credentials`: token-only machine-to-machine traffic.
- `oidc_cold_login_refresh`: PAR, password login, authorization decision,
  authorization-code token exchange, and refresh rotation.
- `oidc_logged_in_authorization_code`: one session warm-up per VU, then
  logged-in PAR, authorization decision, and authorization-code exchange.
- `oidc_refresh_only`: one bootstrap flow per VU, then refresh-token rotation.
- `fapi2_full_security`: PAR + signed JAR + `private_key_jwt` + DPoP-bound
  authorization-code and refresh paths.

`perf/cnb_extended_capacity_matrix.sh` runs a separate 30 minute per point
matrix for mTLS, opaque-token introspection, PAR/JAR endpoint cost,
authorization-session cost, token revocation, discovery/JWKS reads, CIBA poll
mode, and same-user contention. The CIBA scenario uses `private_key_jwt`
PS256 client authentication, a signed CIBA request object, automated approval,
and a DPoP-bound CIBA token request. Dynamic Client Registration still requires
dedicated provisioning setup and is kept out of this matrix.

The report normalizes observed throughput by NazoAuth service CPU usage:
`100%` Docker CPU is treated as one effective CPU core. This avoids claiming
capacity only from raw RPS when the service is consuming many cores.

For strict App CPU tests, `perf/cnb_capacity.sh` also supports:

| Variable | Meaning |
| --- | --- |
| `PERF_APP_CPUS` | Docker CPU quota for the NazoAuth service, for example `1`, `2`, or `4`. |
| `PERF_APP_TASKSET` | Process-level CPU affinity for NazoAuth. This is the effective limiter in CNB nested Docker environments where CPU quota is not enforced reliably. |
| `PERF_APP_CPUSET` | Optional CPU set for NazoAuth. |
| `PERF_INFRA_CPUSET` | Optional CPU set for PostgreSQL, Valkey, keyset, migrate, and perf runner. |
| `PERF_CPUSET` | Legacy setting that pins all services to the same CPU set. |
| `SINGLE_INSTANCE_MAX_DURATION` | Duration per point for `cnb_single_instance_full_flow_max.sh`, default `2m`. |
| `SINGLE_INSTANCE_MAX_RATES` | Comma-separated fixed arrival rates for the full-flow max test, default `16,32,64,96,128,192,256,384,512`. |
| `SINGLE_INSTANCE_MAX_MAX_VUS` | k6 maximum VUs for the full-flow max test, default `4096`. |
| `SINGLE_INSTANCE_MAX_SCENARIO` | Scenario for the full-flow max test, default `oidc_cold_login_refresh`. |

## Metrics

Each scenario writes:

- k6 HTTP request count, RPS, error rate, p50/p95/p99 latency
- Docker CPU and memory samples for NazoAuth, PostgreSQL, and Valkey
- PostgreSQL `pg_stat_statements` calls, mean statement latency, and
  statements per HTTP request
- NazoAuth DB pool acquire count and wait time from the perf-only
  `/__perf/metrics` endpoint
- Valkey command, hit, miss, expiry, and key-count deltas

The perf-only metrics endpoint is registered only when
`PERF_METRICS_ENABLED=true` is present in the server process environment.

## Notes

The compose file uses disposable perf volumes. It enables
`pg_stat_statements` for database latency and per-request query accounting.
The server profile remains `oauth2-baseline` so ordinary OIDC and FAPI-style
client-level hardening can be measured in one reproducible environment. The
FAPI scenario uses client-level PAR request-object enforcement,
`private_key_jwt`, signed JAR, and DPoP-bound tokens. The mTLS endpoint scenario
uses trusted forwarded certificate thumbprint headers on the isolated perf
network.
