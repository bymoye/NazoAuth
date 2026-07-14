# Workspace Architecture

## Design Rule

NazoAuth is a Cargo Workspace deployed as one modular-monolith server. Crates
exist to enforce a domain, infrastructure, transport, or security boundary;
they are not divided one crate per RFC. Calls between crates remain ordinary
in-process Rust calls. The design does not use a dynamic-library plugin ABI,
RPC, an event bus, a command bus, or layers whose only job is forwarding.

The root manifest is a virtual workspace with resolver 3. The default deployed
binary remains `nazo-oauth-server`; operational binaries remain in the
`authorization-server` package unless their dependencies create a demonstrated
build or security boundary.

Every direct child of `crates/` is named for its bounded responsibility.
Technology names appear only where the crate is a concrete adapter. Cargo
package names retain the `nazo-` namespace and do not determine directory names.

## Crate Responsibilities

| Directory | Cargo package | Responsibility |
| --- | --- | --- |
| `authorization-server-core` | `nazo-auth` | Framework-independent OAuth, OIDC, FAPI and CIBA authorization-server policy, protocol types, grants, claims, metadata capability projection, sender constraints, and security profiles. It must not depend on Actix, Diesel, Fred, database rows, or configuration loading. |
| `identity` | `nazo-identity` | Framework-independent users, tenants, organizations, login, sessions, MFA, passkeys, verification, federation, external identities, subject claims, and authentication context. It must not depend on `nazo-auth`, Actix, Diesel, Fred, or database rows. |
| `resource-server` | `nazo-resource-server` | Standalone JWT access-token and sender-constraint verification. It is independent of the authorization server, identity, and every Web framework. |
| `http-signatures` | `nazo-http-signatures` | Reusable HTTP Message Signatures, structured-field, content-digest, signing, and verification primitives. Authorization-server FAPI policy remains in `nazo-auth`. |
| `key-management` | `nazo-key-management` | Key generation, purpose-specific lifecycle, rotation, JWKS material, signing implementations, external-command signing, and future KMS/HSM integration. |
| `persistence-postgres` | `nazo-postgres` | Durable persistence adapter: Diesel schema and rows, pool, queries, repository implementations, explicit row/domain conversion, migrations, and PostgreSQL transaction boundaries. Rows never leave this crate. |
| `state-store-valkey` | `nazo-valkey` | Atomic state-store adapter: Fred connection handling, stable keys and payloads, TTL, Lua operations, replay/session/short-lived protocol state, and rate-limit storage. It owns storage mechanics, not protocol or identity policy. |
| `http-actix` | `nazo-http-actix` | Actix extraction, request context, CORS, middleware, security headers, protocol response presentation, and Actix-specific integration. It does not query Diesel or Fred and does not construct token claims. |
| `runtime-capabilities` | `nazo-runtime-modules` | Runtime-controllable protocol capability identifiers, desired and actual lifecycle state, revision rules, immutable active snapshots, dependency checks, disable policy, request leases, and audit event types. It is not a generic plugin or miscellaneous-module crate. |
| `authorization-server` | `nazo-oauth-server` | Deployable authorization-server application and composition root: validates configuration, creates focused services and adapters, starts background tasks, registers static routes, and starts Actix. Ordinary handlers must receive only the focused handles they use. |

The historical Axum/Tower and tonic adapters are removed. Only Actix transport
integration is maintained. The generic resource-server core may use the
framework-neutral `http` types without becoming a Web-framework adapter.

## Dependency Direction

Dependencies point from policy consumers to stable domain APIs and from
infrastructure adapters to the ports they implement. The composition root is
the only package expected to see all concrete implementations.

```text
authorization-server-core -> identity, runtime-capabilities
key-management            -> authorization-server-core
persistence-postgres       -> authorization-server-core, identity,
                              resource-server, runtime-capabilities
state-store-valkey         -> authorization-server-core, identity, resource-server
http-actix                 -> authorization-server-core, http-signatures, identity,
                              resource-server, runtime-capabilities
authorization-server       -> all concrete crates required for composition

identity, resource-server, runtime-capabilities and http-signatures
                            -> no other NazoAuth crate
```

This list records permitted compile-time direction, not a requirement to add a
dependency where none is needed. The enforced prohibitions are more important:

- `identity` does not depend on `authorization-server-core`.
- `resource-server` does not depend on `authorization-server-core`, `identity`, or Actix.
- `authorization-server-core` does not depend on Actix, PostgreSQL, Diesel,
  Valkey, Fred, or rows.
- `http-actix` does not depend on Diesel or Fred.
- no crate cycle, workspace-wide prelude, or cross-crate glob re-export is
  allowed.

The normal request path is deliberately short:

```text
Actix handler -> authorization-server-core or identity service
              -> repository/store/signer -> typed result -> Actix presenter
```

There is no controller/facade/manager/orchestrator layer between these calls.
Traits are reserved for a real dependency inversion: infrastructure, external
providers, clocks/test substitutes, or multiple genuine implementations.

## Runtime Modules

Optional protocol and product capabilities are compiled into the single
binary. Runtime enablement is capability selection, not dynamic code loading.
Routes remain statically registered so route shape and CORS/security middleware
cannot drift during a transition.

Each `ModuleId` declares:

- dependencies;
- a default inherited state;
- `desired_state`: `inherit`, `enabled`, or `disabled`;
- actual state: `Disabled`, `Starting`, `Enabled`, `Draining`, or `Failed`;
- a `DisablePolicy`: immediate, finish executing requests, drain stored
  transactions with a bound, or not runtime-disableable.

An administrator PATCH changes only desired state and returns `202 Accepted`.
The UI must show the request as pending until actual state and revision confirm
completion. Desired state is durable; actual state is reconciled by each
server instance.

Every asynchronous transition carries the desired-state revision. The worker
revalidates that revision before publishing an active snapshot, before
completing drain, and before persisting final state. A stale worker discards its
result rather than overwriting a newer administrator decision.

The audit stream distinguishes the management request from execution:

- `DesiredStateChanged`
- `TransitionStarted`
- `TransitionCompleted`
- `TransitionFailed`
- `DrainStarted`
- `DrainCompleted`
- `StaleTransitionDiscarded`

Enablement publishes capability and discovery metadata atomically only after
configuration, dependencies, storage, tasks, and health are ready. Disablement
first withdraws capability from metadata, rejects new work, and then follows
the module's declared drain policy. Existing transactions may continue only
where that policy explicitly allows it. Discovery is generated from one typed,
immutable active-capability snapshot; modules never mutate shared JSON.

## Configuration and State Injection

Configuration keys and environment precedence are validated at startup. The
composition root derives small immutable configuration values for each
consumer. A handler must not receive the complete settings object, PostgreSQL
pool, Valkey connection, key manager, or a global application state merely
because another handler needs it.

Top-level composition aggregates may exist while the process is assembled, but
they are not request dependencies. Focused injection is a compiler-enforced
boundary: metadata handlers receive metadata configuration, keys, and the
capability snapshot; session handlers receive session policy and session
storage; repositories are injected only into flows that query them.

## Frontend Repository Discovery

The administration UI lives in a separate sibling repository named
`NazoAuthWeb`. Automation must discover it relative to the resolved backend
repository root, unless an explicit worktree path is supplied. Documentation
and scripts must never embed a workstation-specific absolute path.

Before any coordinated build or deployment, resolve and verify both worktrees:

1. Resolve each repository with `git rev-parse --show-toplevel` and reject a
   path that is not a Git worktree.
2. Verify the normalized `origin` URL is the expected NazoAuth or NazoAuthWeb
   repository; do not accept a same-named unrelated directory.
3. Verify the expected branch, or an explicitly supplied immutable commit for
   detached release worktrees.
4. Verify `HEAD` equals the requested full commit SHA.
5. Verify `git status --porcelain` is empty, including untracked files.
6. Select the frontend package manager from its committed lockfile and execute
   the scripts that actually exist in `package.json`. Do not assume an
   `npm test` script. Missing required lint, unit, browser-security, delivery,
   or build coverage is a repository defect to fix, not a check to silently
   skip.

The live deployment script applies these checks before producing an artifact;
see [deployment.md](../operations/deployment.md).

## Compatibility and Verification

Internal Rust APIs may change before the first stable release, but protocol and
data contracts remain invariants: routes, configuration keys, migration
history, PostgreSQL data, Valkey keys/payloads/TTL, token claims, OAuth/OIDC
errors, discovery, and OIDC/FAPI/CIBA behavior. Contract tests must be in place
before moving an implementation across a boundary.

The final local gate is:

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Integration, migration, HTTP E2E, security, concurrency, fault-injection,
container, deployment, and conformance gates remain additional requirements;
passing the four Cargo commands does not replace them.
