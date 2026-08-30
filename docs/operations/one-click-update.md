# Managed installation, update, and recovery

NazoAuthCtl v0.2 manages NazoAuth through one current protocol lineage. A
controller uses its user-scoped Registry for host and instance inventory; the
target host's `DeploymentState` remains authoritative for runtime, artifact,
configuration, resources, journal, and backup facts. Removed controller state,
task envelopes, secret-provider adapters, and old command shapes are not read
or converted.

## Fresh installation

Register the target host first. SSH hosts use an existing OpenSSH Host alias;
the verified remote helper must be the exact same NazoAuthCtl build.

Installation requires a public issuer plus explicit facts for the external
PostgreSQL and Valkey services. Their credentials are read from bounded private
files and never accepted on argv. For example:

```sh
nazoauthctl install \
  --host production-host \
  --name production \
  --public-url https://auth.example.com \
  --to v0.2.3 \
  --runtime podman \
  --database-host db.internal \
  --database-port 5432 \
  --database-name nazoauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal \
  --valkey-port 6379 \
  --valkey-password-file ./valkey-password
```

The command verifies the official Release and immutable runtime artifact,
creates a deployment-scoped non-nil UUIDv7 state epoch, writes the target
configuration and secrets with target-native paths, starts the runtime, checks
local health, commits `DeploymentState`, and only then registers the instance.
If an SSH response is lost, the prepared-install journal replays the exact same
deployment and operation IDs; it never creates a second deployment.

The runtime and lifecycle PostgreSQL roles must be distinct. The server receives
only the runtime URL; migration, backup, and recovery use the lifecycle role.
PostgreSQL and Valkey are external/shared resources. NazoAuthCtl records their
ownership boundary but does not create, replace, or delete them.

To build a clean current deployment from stopped current-format data already on
the target, add both options:

```sh
  --import-data-root /srv/nazoauth-import/data \
  --import-mfa-key-file /srv/nazoauth-import/mfa-totp-key
```

The two absolute target-side paths are an inseparable pair. Import copies only
the current allowlisted data, signing keys, and application secrets plus the
MFA key. It does not read an old DeploymentState, controller state, bootstrap
state, UI cache, or command format.

## Controller binding and initial administrator

Bind a Controller Key before normal mutations:

```sh
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
```

The bind transaction enrolls the first Recovery Root. Its Recovery Secret must
be stored offline before the commit is attempted. If the commit is interrupted,
the owner-only pending record preserves that exact proposal and secret until
terminal reconciliation; a retry never mints a different secret behind the
operator's back.

Create the first administrator interactively:

```sh
nazoauthctl bootstrap-admin --instance production
```

Automation supplies a strict JSON object containing exactly `email` and
`password` through stdin:

```sh
printf '%s' '{"email":"admin@example.com","password":"..."}' | \
  nazoauthctl bootstrap-admin --instance production --credentials-stdin
```

The bootstrap token is single-use and deployment-bound. Neither credentials
nor the token enter argv, ordinary environment variables, Registry, or logs.

## Update and rollback

```sh
nazoauthctl update --instance production --to v0.2.6
nazoauthctl rollback --instance production
```

Update resolves and verifies one immutable artifact, signs one canonical
`ControlOperation`, and executes migration before activation through the
target's journaled lifecycle operation. The durable `ControlResult` is bound to
the exact operation ID, request hash, typed payload, artifact target, and
configuration revision. A lost response replays the same operation; it does not
mint a parallel task.

Rollback only changes the runtime artifact when the signed release policy and
live schema facts permit it. Once an irreversible migration has applied,
`rollback` returns `ROLLBACK_RECOVERY_REQUIRED`, leaves the writer stopped, and
requires `recover` from a verified snapshot. Database rollback is never
inferred from artifact rollback.

## Backup and restore evidence

```sh
nazoauthctl backup snapshot --instance production
nazoauthctl backup restore-test --instance production
nazoauthctl policy backup-before-update require --instance production \
  --max-age-seconds 86400
nazoauthctl backup copy --instance production --to-host recovery-host
nazoauthctl backup show --instance production
```

A snapshot binds the PostgreSQL custom-format dump, deployment data, secrets,
configuration, runtime artifact digest, release version, schema, MFA/JWKS facts, and a
database sentinel in one immutable manifest. A restore test uses an isolated
database and runtime. `require` blocks update unless the exact restore-tested
manifest remains present and is no older than the configured maximum. Off-host
copy uses the registered execution target on each side, so a source or
destination may be local or SSH. The hosts must be distinct and byte-verified
receipts are recorded on both sides; same-host files do not count as off-host
evidence.

## Disaster recovery

```sh
nazoauthctl recover --instance production
```

If the restored Controller Registry rejects the current key with
`CONTROLLER_KEY_UNAUTHORIZED`, provide the offline secret through an owner-only
file:

```sh
nazoauthctl recover --instance production --recovery-secret-file ./recovery-secret
```

The secret is read only after that stable identity rejection. Network errors,
5xx responses, unknown outcomes, and other rejection codes never downgrade into
break-glass recovery.

Recovery quiesces the original runtime, restores the verified snapshot, starts
one loopback-only candidate, and performs the two Recovery Secret ceremony
requests through a process-owned target-local transport. The transport accepts only
`/controller-recovery/challenges` and `/controller-recovery/recover`, sends no
Cookie or CSRF header, and never exposes the candidate through public ingress.

The recovered controller signs `RecoveryInvalidate` with the new UUIDv7 Valkey
state epoch. NazoAuth revokes refresh tokens and returns an absolute
`not_before` deadline covering the maximum access/ID token TTL plus skew. Both
the controller and target host enforce the deadline while the original runtime
remains stopped. Only then does the target replace and start the original
runtime from the restored artifact/config/data and remove the exact candidate.
Any failure remains fail-closed and resumes from the persisted phase.

After an irreversible migration, `rollback` is rejected. Resume only through
the persisted `recover` transaction and its verified snapshot; do not restart a
writer manually or flush shared Valkey.

## Trust boundary

Release bytes, attestations, Sigstore identity, manifest metadata, and the OCI
digest are verified before activation. The application independently validates
the signed ControlOperation against the executing binary or image digest, while
NazoAuthCtl observes the same content identity from the runtime.

Public bootstrap is fail-closed on the attested Release reader and accepts only
a public non-draft Release. The operator host therefore needs GitHub CLI plus
`python3`, `sha256sum`, and `install`; a missing reader or verification tool is
an error, not permission to consume an unattested artifact.

Use `nazoauthctl --help` and subcommand help as the only command-surface
authority. This document describes the current v0.2 model only.
