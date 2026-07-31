# Out-of-box deployment completion

This task continues the first-start bootstrap work. The objective is a secure
default path with no user-supplied secret values, while preserving explicit
overrides and refusing to guess external trust facts.

## Invariants

- Generated values are shared and persisted before multiple replicas use them.
- Health endpoints report observed dependency state, not process optimism.
- Client certificate facts are accepted only from an authenticated transport
  boundary.
- RP metadata choices are registration inputs; responses contain the selected
  single-valued metadata.
- Discovery advertises only capabilities whose dependencies are ready.

## Ordered work

1. [x] Add real liveness, startup, and readiness probes for PostgreSQL and
   Valkey; retain `/health` as the readiness-compatible endpoint.
2. [x] Make the mTLS certificate source explicit and fail closed for direct,
   managed-gateway, and external-proxy deployments.
3. [x] Implement all 19 RP Metadata Choices fields with real per-client state
   and runtime consumers, and add client creation templates.
4. [x] Add reviewed proxy presets and a Kubernetes/Helm deployment contract for
   shared generated secrets or externally managed secret/KMS inputs.
5. [x] Run focused tests, full repository gates, and live deployment smokes.

## Evidence boundary

Passing source tests proves the implementation paths. Direct TLS, a particular
proxy product, Kubernetes scheduling, and public deployment remain separate
claims and require their corresponding live environments.

## Verification

- Authorization server: 1,021 tests passed.
- Authorization core: 230 tests passed.
- PostgreSQL adapter: 88 tests passed.
- Valkey adapter: 48 tests passed.
- Workspace: 1,962 tests passed across 87 suites.
- Workspace Clippy with all targets/features and `-D warnings`: passed.
- Explicit non-deployment Python unit modules: 199 tests passed. The
  long-running deployment-contract module remains on its separate CI budget.
- Helm 3.18 lint and default template rendering: passed; the unsafe
  multi-replica/no-shared-secret case was rejected.
- Live probes: `/ready` reported both dependencies up, then returned 503 with
  `valkey=down` after Valkey stopped while `/live` remained 200.
- Live direct TLS: handshake without a client certificate failed; a client
  certificate issued by the configured CA completed the handshake and reached
  `/live` with HTTP 200.

The Helm chart was rendered and linted but was not scheduled on a Kubernetes
cluster. The nginx preset was source-reviewed but not exercised against a live
nginx process. Public DNS/ACME issuance remains an external deployment fact.
