# Out-of-box secure bootstrap task

Status: completed

## Objective

Make a fresh NazoAuth installation usable without requiring operators to copy
example configuration or invent local secrets. Explicit operator configuration
continues to take precedence.

The effective configuration order is:

1. explicit environment variable;
2. explicit `.env.yaml` value;
3. previously persisted generated value;
4. deterministically derived value;
5. safe built-in default.

## Invariants

- Generated secrets are created once, persisted, and reused across restarts.
- A missing or malformed previously generated secret fails closed; it is never
  silently replaced when doing so could invalidate stored data.
- External facts and trust decisions are not guessed. Public DNS, external
  service credentials, proxy trust, CA trust, and KMS ownership remain explicit.
- A fresh local or official Compose deployment has no published default
  database, Valkey, administrator, or OAuth secret.
- The initial administrator claim is time bounded, single use, stores only a
  verifier in PostgreSQL, and is closed permanently after an administrator
  exists.
- Concurrent first starts and concurrent administrator claims have one
  authoritative winner.
- Existing explicit deployments remain supported.

## Work items

### 1. First-start state machine

- [x] Do not stop after creating `.env.yaml`.
- [x] Run pending migrations before accepting traffic.
- [x] Create or load generated secrets before settings validation.
- [x] Keep automatic signing-key creation in the normal server startup path.
- [x] Create a one-time initial-administrator claim and report its setup URL.
- [x] Add an HTTP endpoint that atomically consumes the claim and creates the
      first administrator without SMTP.
- [x] Reject the endpoint after claim expiry, consumption, or the existence of
      any administrator.

### 2. Persistent generated secrets

- [x] Extend the existing `ConfigSource`; do not introduce a parallel runtime
      configuration system.
- [x] Generate `CLIENT_SECRET_PEPPER` when absent.
- [x] Generate `PAIRWISE_SUBJECT_SECRET` when pairwise subjects are selected.
- [x] Generate a DCR initial-access token when absent, while retaining token
      authentication and explicit override.
- [x] Store generated values under `DATA_DIR/secrets` using create-new and
      atomic persistence semantics.
- [x] Give explicit environment and YAML values precedence.
- [x] Cover stability, precedence, malformed files, and concurrent creation.

### 3. Official Compose credentials

- [x] Remove fixed PostgreSQL and unauthenticated Valkey defaults.
- [x] Generate service credentials once into a private named volume.
- [x] Feed credentials to PostgreSQL, Valkey, migration, and server processes
      through files rather than command-line arguments or committed YAML.
- [x] Add application support for the corresponding `*_FILE` inputs.
- [x] Preserve one-command `docker compose up -d --build`.

## Verification

- [x] Focused configuration and CLI unit tests.
- [x] Initial-administrator repository and HTTP tests, including concurrency
      and replay.
- [x] Compose configuration validation and container smoke test where the
      container runtime is available.
- [x] Migration/schema contract refresh.
- [x] `cargo fmt --check`.
- [x] Relevant crate tests.
- [x] Workspace test gate.
- [x] `git diff --check`.

## Completion evidence

- `cargo test --locked -p nazo-oauth-server --lib`: 1019 passed.
- `cargo test --locked -p nazo-postgres --lib --tests`: 86 passed.
- Live PostgreSQL initial-admin concurrency test: 1 passed, with one claim
  winner and permanent closure.
- `cargo test --locked --workspace --all-features --lib --tests`: 1959 passed.
- Workspace Clippy with all targets/features and `-D warnings`: passed.
- Static contracts, formatting, diff whitespace, and Compose config: passed.
- Isolated Compose smoke deployment: generated credentials, authenticated
  Valkey, migrations, health, Discovery, initial-admin HTTP 201, token removal,
  restart stability, and no bootstrap reopening all verified. The isolated
  containers and volumes were removed after the test.
- Direct binary smoke deployment from an empty working directory: `.env.yaml`,
  generated secrets, bootstrap token, automatic migrations, and live health
  were verified before the isolated process and dependency containers were
  removed.

## Out of scope

- Automatic inference of arbitrary reverse-proxy trust.
- Automatic creation of public DNS records.
- Automatic SMTP, federation-provider, or external KMS accounts.
- Embedded replacement implementations for PostgreSQL or Valkey.
- FAPI 1.0 implementation.
