## Test Environment and Topology

| Field | Value |
| --- | --- |
| Source commit | 1df921b3a7f254ea50e8624e90699df901edbde7 |
| Runner tag | cnb:arch:amd64 |
| Requested runner CPUs | 64 |
| Observed logical CPUs | 384 |
| Process allowed CPUs | 48-63,336-383 |
| Observed CPU model | AMD EPYC 9K65 192-Core Processor |
| Cgroup CPU max | unknown |
| Memory total | unknown |
| Cgroup memory max | unknown |
| Workspace disk available | unknown |
| Kernel | Linux 4c01331e6f85 5.4.241-1-tlinux4-0023.7 #1 SMP Fri May 8 22:13:53 CST 2026 x86_64 GNU/Linux |
| Docker server | 27.5.1 |
| Docker compose | 2.33.0 |
| Compose project | nazoauth-local-token-only-short |
| Compose files | docker-compose.perf.yml + perf/results/docker-compose.cpuset-token-only-short.yml |
| CPU set | 48-59 |
| CPU set size | 12 |
| Services pinned to CPU set | postgres, valkey, keyset, migrate, nazoauth, perf |
| Per-container CPU model | Docker cpuset isolation; no CPU quota. Each service container may run on the listed CPU set. NazoAuth is additionally scaled by the stage instance count. |
| Capacity scenarios | token_only_client_credentials |
| Duration per point | 5m |
| App instance stages | 1,2,4 NazoAuth replica(s) |
| Explicit rates | 1000,2500,5000 |
| Load executor | k6 constant-arrival-rate, time unit 1s |
| Token-only target rates | 1000, 2500, 5000, 7500, 10000 flow/s |
| OIDC cold/login and logged-in target rates | 16, 32, 64, 128, 256 flow/s |
| OIDC refresh-only target rates | 250, 500, 1000, 1500, 2000 flow/s |
| FAPI2 full-security target rates | 16, 32, 64, 128, 256 flow/s |
| Network topology | Single Docker bridge network; perf runner reaches NazoAuth at http://nazoauth:8000; NazoAuth reaches PostgreSQL and Valkey inside the same network. |
| PostgreSQL container | docker.io/library/postgres:18-alpine; pg_stat_statements enabled; track_io_timing enabled; ephemeral Docker volume. |
| Valkey container | docker.io/valkey/valkey:8-alpine; RDB save disabled; AOF disabled; warning log level; ephemeral state for benchmark isolation. |
| NazoAuth container | Built from local Containerfile target runtime; PERF_METRICS_ENABLED=true; runtime key volume shared with keyset/migrate. |
| Key material setup | keyset service generates runtime RS256 and PS256 keys before migration and benchmark traffic. |
| Migration setup | migrate service runs nazo-oauth-migrate before the NazoAuth service is considered ready for benchmark traffic. |
| Perf runner | Built from perf/runner/Containerfile; mounts Docker socket for container stats; writes Markdown reports to docs/ and runtime JSON/logs to ignored perf/results/. |
| Metrics sources | k6 HTTP metrics; Docker stats CPU/memory samples; PostgreSQL pg_stat_statements; NazoAuth DB pool metrics; Valkey INFO counters. |
