# PostgreSQL and Valkey Operations

## Scope

PostgreSQL is the durable state tier. Valkey is the transient protocol state
tier. Production operation requires explicit availability, backup, restore,
timeout, and partial-outage rules for both.

## State Classification

| Store | State | Loss impact | Recovery expectation |
| --- | --- | --- | --- |
| PostgreSQL | users, clients, grants, refresh tokens, access-token revocation state, client metadata, audit-relevant durable rows | durable account, client, token, and grant state can be lost or rolled back | restore from tested backups or promote a consistent replica |
| Valkey | sessions, authorization codes, PAR handles, DPoP proof replay keys, client assertion replay keys, rate-limit counters, consent transaction state | in-flight browser/API transactions fail; replay/rate controls must not silently weaken | fail closed for security-sensitive paths; restart transactions after recovery |
| Key directory | active and previous token-signing private keys | issued tokens can become unverifiable or signing continuity can break | restore from key backup before serving traffic |
| Avatar directory | user-uploaded avatar files | profile media can be lost or desynchronized from PostgreSQL metadata | restore file backup consistent with PostgreSQL metadata |

## PostgreSQL High Availability

Production deployments use a managed PostgreSQL service or an equivalent HA cluster with:

- synchronous or bounded-lag replication for the primary region
- automated primary failover with a tested DNS, virtual IP, or proxy cutover path
- connection pooling sized below the database `max_connections`
- TLS on application-to-database connections when traffic leaves a single trusted host boundary
- least-privilege application credentials that cannot create superusers, change replication, or read unrelated databases
- maintenance windows for major upgrades and extension changes

`DATABASE_URL` points at the HA endpoint when production traffic depends on it. Failover must preserve read-after-write expectations for OAuth state; stale replicas must not serve token, consent, revocation, or client-management writes.

## PostgreSQL Backup and Restore

Backup controls:

- continuous WAL archiving or provider point-in-time recovery
- at least daily logical or physical backups
- backup encryption at rest
- backup access limited separately from application database credentials
- retention long enough to cover compromise detection and operational rollback windows
- restore rehearsal for a recent backup before first production launch and after backup tooling changes

Restore rehearsal proves:

- migrations can run on the restored database
- a known user, OAuth client, grant, refresh token, and revocation row are present
- discovery, JWKS, login, authorization, token, introspection, and revocation endpoints start successfully against the restored database
- refresh-token family state and revoked-token state remain consistent after restore

Point-in-time restore can roll back security events. After any PostgreSQL restore, rotate administrative credentials, review OAuth clients changed near the restore window, and consider revoking refresh-token families issued after the selected recovery point.

## PostgreSQL Failure Behavior

When PostgreSQL is unavailable or the pool is exhausted:

- `/health` can remain a process-health check; external readiness checks include a database probe outside this service.
- Discovery and JWKS can still serve if the process has loaded the keyset and configuration.
- Login, consent, authorization code issuance, token issuance, refresh, introspection, revocation, admin APIs, profile APIs, and userinfo that requires durable lookup fail with server errors.
- The service must not mint tokens, mark grants, or accept revocation/introspection decisions from stale or partial durable state.

Operational response:

- page on sustained connection failures, pool timeout growth, replication lag, storage saturation, or failed backup jobs
- stop rollout or migration automation until the durable store is healthy
- prefer failover or restore over ad hoc manual row edits during an incident

## Valkey High Availability

Production Valkey uses a managed HA Redis-compatible service, Valkey Sentinel
topology, or Valkey Cluster topology appropriate to the deployment. Required
controls:

- authenticated connections and network isolation from untrusted clients
- TLS when traffic crosses a host or private-network boundary that is not otherwise encrypted
- bounded memory policy with alerting before eviction affects OAuth state
- selected persistence policy: AOF or managed persistence for faster recovery, or documented acceptance of losing transient security state
- failover tests that include in-flight sessions, PAR handles, authorization codes, and replay caches

Valkey is not the durable source of truth. Losing it invalidates or interrupts transient flows rather than weakening replay prevention.

## Valkey Timeouts

`VALKEY_COMMAND_TIMEOUT_MS` controls Valkey command, connection, and internal command timeouts. The value must be greater than zero. Production values stay short enough to avoid request pileups and long enough to tolerate normal network jitter; start with `1000` ms and adjust based on measured latency.

Timeout guidance:

- alert when p95 command latency exceeds 25 percent of `VALKEY_COMMAND_TIMEOUT_MS`
- alert when timeout errors occur on security-sensitive paths
- do not increase the timeout to mask saturation or packet loss
- prefer capacity, topology, or network fixes over broad retry loops in protocol handlers

## Valkey Partial-Outage Behavior

When Valkey is unavailable or times out:

| Area | Expected behavior |
| --- | --- |
| Sessions | authenticated profile/admin flows fail or require re-login; session lookup must not be bypassed |
| Authorization codes | code creation, lookup, and replay protection fail closed |
| PAR | pushed request storage and lookup fail closed; authorization requests must not fall back to unsigned or unpushed parameters in FAPI/PAR-required profiles |
| DPoP replay cache | proof replay checks fail closed; a token must not be issued or accepted without replay state when the profile requires it |
| `private_key_jwt` replay cache | assertion `jti` storage failures reject the assertion |
| Rate limiting | rate-limit storage errors fail closed for protected auth/token-management paths instead of disabling limits |
| Consent transactions | consent state lookup or consumption failures reject the transaction |

The CI real HTTP matrix includes Valkey outage injection to verify externally visible fail-closed behavior.

## Recovery Runbook

PostgreSQL incident:

1. Freeze deploys and migrations.
2. Identify whether the issue is connectivity, pool exhaustion, primary failure, replication lag, storage, or data corruption.
3. Fail over through the managed HA path when the primary is unhealthy.
4. Restore from backup only after selecting a recovery point and documenting expected token/client/grant rollback.
5. Run migrations and smoke checks against the recovered database.
6. Review client, grant, refresh-token, and admin changes near the incident window.

Valkey incident:

1. Confirm whether the issue is node failure, failover, network partition, memory eviction, or timeout saturation.
2. Restore HA service or promote a replica through the managed path.
3. Expect users to restart browser authorization flows and reauthenticate if sessions were lost.
4. Treat replay cache loss as security-sensitive; do not relax DPoP, PAR, authorization-code, or client-assertion checks to recover traffic.
5. Run the Valkey outage injection script and core authorization/token smoke tests after recovery.

## Evidence to Preserve

For each production environment, preserve:

- PostgreSQL HA topology and failover owner
- PostgreSQL backup schedule, retention, last successful backup, and last restore rehearsal date
- Valkey HA topology, persistence policy, memory limit, and eviction policy
- configured `VALKEY_COMMAND_TIMEOUT_MS`
- incident runbooks and paging rules
- results from the latest restore rehearsal and Valkey outage test
