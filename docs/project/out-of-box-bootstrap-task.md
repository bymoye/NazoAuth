# Out-of-box administrator provisioning task

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
- Administrator creation is available only through the target-local one-shot
  `nazoauth admin-provision`, invoked by `nazoauthctl admin create`; the
  authorization server exposes no public setup route or bearer setup secret.
- The operation and deployment IDs bind one PostgreSQL transaction that creates
  the administrator, durable receipt, and security audit event. Repeating an
  operation returns its receipt; a conflicting operation or existing email is
  rejected without creating a second user.
- Concurrent administrator creation attempts have one authoritative winner.
- Existing explicit deployments remain supported.

## Work items

### 1. First-start state machine

- [x] Do not stop after creating `.env.yaml`.
- [x] Run pending migrations before accepting traffic.
- [x] Create or load generated secrets before settings validation.
- [x] Keep automatic signing-key creation in the normal server startup path.
- [x] Add the local one-shot `nazoauth admin-provision` command with a strict
      credential document and deployment/operation binding.
- [x] Add `nazoauthctl admin create`, which invokes the target-local command
      through the controller's protected credential path.
- [x] Atomically create the administrator, idempotency receipt, and durable
      security audit event in PostgreSQL.
- [x] Return the same receipt for an operation retry and reject conflicting
      operation or existing-email attempts without creating a second user.

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
- [x] Administrator-provisioning repository and CLI tests, including
      concurrency and replay.

- [x] Compose configuration validation and container smoke test where the
      container runtime is available.
- [x] Migration/schema contract refresh.
- [x] `cargo fmt --check`.
- [x] Relevant crate tests.
- [x] Workspace test gate.
- [x] `git diff --check`.

The local command validates the strict credential document and deployment binding
before entering the PostgreSQL transaction. The transaction is the single
authority for administrator creation, operation replay, and conflict rejection;
there is no public HTTP setup boundary or bearer setup secret to keep in sync.

The controller derives the request identity from the fresh install operation.
If the server commits but the response is lost, rerunning the same `admin create`
command replays the one durable application receipt. Deterministic input and
conflict rejections are closed outcomes; database or transport uncertainty is
retried without creating another administrator.

## Completion evidence

- `cargo test --locked -p nazo-oauth-server --lib`: 1019 passed.
- `cargo test --locked -p nazo-postgres --lib --tests`: 86 passed.
- Live PostgreSQL administrator-provisioning concurrency test: 1 passed, with
  one transaction winner and durable replay.
- `cargo test --locked --workspace --all-features --lib --tests`: 1959 passed.
- Workspace Clippy with all targets/features and `-D warnings`: passed.
- Static contracts, formatting, diff whitespace, and Compose config: passed.
- Isolated Compose smoke deployment: generated credentials, authenticated
  Valkey, migrations, health, Discovery, administrator provisioning receipt,
  restart stability, and the absence of a public setup route were verified.
  The isolated containers and volumes were removed after the test.
- Direct binary smoke deployment from an empty working directory: `.env.yaml`,
  generated secrets, automatic migrations, live health, and the local
  administrator-provisioning boundary were verified before the isolated
  process and dependency containers were removed.

## Out of scope

- Automatic inference of arbitrary reverse-proxy trust.
- Automatic creation of public DNS records.
- Automatic SMTP, federation-provider, or external KMS accounts.
- Embedded replacement implementations for PostgreSQL or Valkey.
- FAPI 1.0 implementation.
