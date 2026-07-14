# Deployment Guide

## Scope

Production deployments run Nazo Auth Server behind a TLS-terminating reverse
proxy. PostgreSQL stores durable state. Valkey stores transient protocol state.

## Deployment Model

Required components:

- `nazo-oauth-server` HTTP process
- `nazo-oauth-migrate` migration command
- PostgreSQL database
- Valkey instance
- persistent JWT key directory
- persistent avatar directory
- HTTPS reverse proxy

The service listens on HTTP, typically `0.0.0.0:8000`. The reverse proxy exposes
the public HTTPS issuer.

## Preflight Checklist

Before first deployment:

1. Create PostgreSQL database and user.
2. Create Valkey instance and decide persistence / HA policy.
3. Allocate a persistent data directory.
4. Create `.env.yaml` outside the repository.
5. Set `PUBLIC_BASE_URL` to the exact public HTTPS origin, without a trailing slash.
6. Configure `TRUSTED_PROXY_CIDRS` only for reverse proxies that you control.
7. Keep `CLIENT_IP_HEADER_MODE=none` until forwarded headers are correctly sanitized by the proxy.
8. Run migrations before serving traffic.

## Configuration Baseline

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://oauth.example.com"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres.example.internal:5432/oauth"
VALKEY_URL: "redis://valkey.example.internal:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<random 32+ byte secret>"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
TRUSTED_PROXY_CIDRS: "10.0.0.0/24"
CLIENT_IP_HEADER_MODE: "forwarded"
RUST_LOG: "info"
```

Do not store production secrets in Git. `CLIENT_SECRET_PEPPER` is required for
non-loopback issuers and must remain stable across restarts because it protects
stored confidential-client secrets.

`ISSUER`, `FRONTEND_BASE_URL`, `CORS_ALLOWED_ORIGINS`, `COOKIE_SECURE`,
`PASSKEY_ORIGIN`, `PASSKEY_RP_ID`, `JWK_KEYS_DIR`, and `AVATAR_STORAGE_DIR`
are derived from `PUBLIC_BASE_URL` and `DATA_DIR` unless explicitly overridden.
Advanced settings are documented in [configuration.md](configuration.md).

Use `AUTHORIZATION_SERVER_PROFILE=fapi2-security` only for client populations
that support confidential-client-only operation, PAR-only authorization
requests, PKCE S256, `private_key_jwt` or mTLS client authentication, and DPoP
or mTLS sender-constrained tokens. Select
`fapi2-message-signing-authz-request` when signed request objects are mandatory
at PAR, `fapi2-message-signing-jarm` when every authorization response must be
signed, or `fapi2-message-signing-introspection` when RFC 9701 signed and
nested encrypted introspection responses are required. Discovery metadata
reflects the active profile and omits mTLS capabilities unless
`TRUSTED_PROXY_CIDRS` is non-empty.

OpenTelemetry is opt-in. Set `OTEL_ENABLED: true` and
`OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP/HTTP collector base URL such as
`http://otel-collector:4318` to export traces, metrics, and logs. The service
appends `/v1/traces`, `/v1/metrics`, and `/v1/logs` internally.
`OTEL_EXPORTER_OTLP_PROTOCOL` is `http/protobuf`; keep `RUST_LOG` configured
for local stdout logs even when OTLP export is enabled.

## Container Build

Build the image:

```sh
docker build -f Containerfile -t nazo-oauth-server:$(git rev-parse --short=7 HEAD) .
```

Run migrations:

```sh
docker run --rm \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-migrate
```

Run the server:

```sh
docker run -d --name nazo-oauth-server \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-server
```

`compose.yml` is for local integration. It is not a complete production
topology.

## Release Security

Before promoting an image, require a successful `conformance-security` workflow
for the exact commit. That workflow runs Rust advisory checks, dependency
policy checks, SBOM generation, image build, and Trivy scanning in addition to
Rust and real HTTP gates.

For versioned releases, create a `v*` tag and require the `release-security`
workflow to complete successfully. It builds release binaries, generates the
Rust SBOM, signs the binaries, SBOM, and image archive through keyless Sigstore
signing, uploads artifacts, and emits GitHub provenance attestations. Preserve
the release evidence listed in [docs/operations/release-security.md](release-security.md).

## Live Deployment Script

The repository includes [scripts/deploy_live.ps1](../../scripts/deploy_live.ps1), which builds from clean backend and frontend worktrees at the requested commits. The worktrees must use branch `codex/modular-workspace-architecture` and the exact HTTPS origins `https://github.com/nazozero/NazoAuth[.git]` and `https://github.com/nazozero/NazoAuthWeb[.git]`. It reads the frontend's committed `packageManager`, requires the matching `package-lock.json` and exact npm version, runs `npm ci` and the aggregate verification script that actually exists in `package.json`, and accepts only the `dist` produced by that gate. It then hashes `dist`, builds the backend image from the verified backend worktree, and checks the immutable image ID again after the archive is loaded remotely. It records the current rollback targets, stages a SHA-named UI release in Angie's traversable static root, normalizes static-file permissions, verifies readability as the Angie worker, runs migrations once, replaces the Podman container, and verifies health and discovery. The application, PostgreSQL, and Valkey containers are assigned `unless-stopped` restart policies, and `podman-restart.service` is enabled before the active application container is replaced so both process exits and host reboots recover automatically. The public UI symlink changes only after the candidate is healthy. Before committing the transaction, the script also requires the public `/ui/auth` document and at least one referenced `/ui/assets/...` resource to return non-empty HTTP 200 responses. A detached verification watchdog starts as soon as the remote transaction state is durably recorded, so it covers artifact staging, image loading, migration, container replacement, and public verification.

Default live assumptions:

| Setting | Default |
| --- | --- |
| Remote host | Required `-RemoteHost` argument |
| Backend commit | Required full SHA in `-BackendCommit` |
| Frontend commit | Required full SHA in `-FrontendCommit` |
| Backend worktree | `.`; must be clean and at the backend commit |
| Frontend worktree | Discovered as sibling `NazoAuthWeb`, or set with `-LocalFrontendWorktree`; must be clean and at the frontend commit |
| Container name | `nazo-oauth-server` |
| Network | `nazo_oauth_net` |
| Network subnet | `10.101.0.0/24` |
| Network gateway | `10.101.0.1` |
| Container IP | `10.101.0.20` |
| Host port publish | Disabled by default; Angie proxies to the container IP |
| Remote config | `/opt/nazo-oauth/.env.yaml` |
| Keys path | `/opt/nazo-oauth/runtime/keys` |
| Avatars path | `/opt/nazo-oauth/runtime/avatars` |
| Health URL | `https://auth.nazo.run/health` |
| Discovery URL | `https://auth.nazo.run/.well-known/openid-configuration` |
| Expected issuer | `https://auth.nazo.run` |
| UI path | `/usr/local/angie/html/auth/ui` |
| UI releases | `/usr/local/angie/html/auth-releases/<frontend-sha>` |
| Angie worker | `www` |
| Public UI probe | `https://auth.nazo.run/ui/auth` plus one referenced `/ui/assets/...` resource |
| Verification lease | 120 seconds by default (`-VerificationLeaseSeconds`) |
| Deployment records | `/opt/nazo-oauth/deployments/<backend-sha>-<frontend-sha>-<deployment-id>.json` |

Example:

```powershell
pwsh scripts/deploy_live.ps1 `
  -RemoteHost <ssh-host> `
  -BackendCommit (git rev-parse HEAD) `
  -FrontendCommit (git -C $frontendWorktree rev-parse HEAD) `
  -LocalBackendWorktree . `
  -LocalFrontendWorktree $frontendWorktree `
  -LocalUiDist (Join-Path $frontendWorktree dist)
```

Omit `-LocalFrontendWorktree` to discover the sibling `NazoAuthWeb` repository.
Whether discovered or explicit, the script verifies its origin, branch, HEAD,
and clean status, including untracked files. Discovery starts from the resolved
backend Git root; it never relies on a workstation-specific absolute path or
accepts a same-named non-repository directory. The frontend package manager is
selected from its committed lockfile, and validation uses the scripts that are
actually declared in `package.json`. Do not assume an `npm test` script exists;
if a required lint, unit, browser-security, delivery, or build gate is absent,
add a real gate to the frontend repository before deployment. Production deployment
does not accept `-SkipBuild` or `-SkipFrontendBuild`; those switches exist only
for rendering the remote script in tests.

Do not delete the previous image or UI release until local OIDF, official OIDF,
and PR acceptance are complete. Each run writes a preflight record before the
first destructive container action. A successful run atomically updates
`deployments/current.json` through a temporary symlink plus `mv -T`; a failed
run retains a `rolled-back` record without overwriting an earlier successful
deployment record. Rollback is successful only after the old immutable image,
UI target, deployment pointer, and application health are all verified. Any
restore or verification failure exits nonzero, writes `rollback-failed`, and
retains the state file, script, lease markers, active-transaction owner, and
record for manual recovery. The state file is a schema-validated JSON document
written through a mode-`0600` same-directory temporary file and atomic rename;
missing, partial, corrupt, or foreign state fails closed. Only one remote
deployment transaction may be active.

The script uses the configured SSH target to deploy the `auth.nazo.run`
environment. Recheck the live listener, reverse-proxy config, container
network, TLS settings, and expected issuer before using it for a different
host.

### Fixed Internal IP and Angie

The `auth.nazo.run` live path uses Podman's `nazo_oauth_net` bridge network with
subnet `10.101.0.0/24`, gateway `10.101.0.1`, and application container IP
`10.101.0.20`. The deployment script requires that exact subnet/gateway layout
(additional or different subnets fail closed), verifies
the started container IP, and probes `http://10.101.0.20:8000/health` and
discovery from the host.

Angie should proxy directly to the fixed container IP rather than a published
`127.0.0.1:8000` port:

```nginx
proxy_pass http://10.101.0.20:8000;
```

When Angie runs on the same host, the application usually sees the bridge
gateway `10.101.0.1` as the trusted proxy peer. Configure
`TRUSTED_PROXY_CIDRS` with only that address or the actual controlled proxy
address, for example `10.101.0.1/32`; do not trust an uncontrolled container
subnet wholesale.

## Reverse Proxy Boundary

Proxy requirements:

- Terminate TLS with the public issuer hostname.
- Disable TLS 1.0 and TLS 1.1; allow only TLS 1.2 or TLS 1.3 on the public issuer listener.
- Forward only sanitized proxy headers to the service.
- Strip inbound client-supplied `Forwarded`, `X-Forwarded-*`, mTLS, and certificate headers before adding trusted values.
- Configure `TRUSTED_PROXY_CIDRS` to include only the reverse proxy addresses that are allowed to forward client IP and mTLS certificate metadata.
- Protect the proxy-to-application hop with TLS, mTLS, or an equivalent private network boundary; forwarded certificate metadata is only meaningful on a trusted internal channel.
- Use one certificate forwarding representation where possible. If multiple forwarded certificate thumbprint/certificate headers are present, the application rejects the request unless they resolve to the same SHA-256 certificate thumbprint. If multiple forwarded subject-DN headers are present, they must be byte-identical after trimming.
- For `tls_client_auth`, register at least one of `tls_client_auth_subject_dn`, `tls_client_auth_san_dns`, `tls_client_auth_san_uri`, `tls_client_auth_san_ip`, `tls_client_auth_san_email`, or `tls_client_auth_cert_sha256`. The application matches these values against trusted forwarded certificate metadata; forwarded PEM certificates are parsed directly for subject DN and DNS/URI/IP/email SAN values.
- For `self_signed_tls_client_auth`, register active client certificates in `jwks.keys[].x5c[0]`. Multiple active `x5c` certificates form the rotation window; removing an old certificate retires it. Expired or not-yet-valid registered certificates are ignored.
- Preserve the exact path for OAuth endpoints.
- Disable response caching for protocol endpoints unless the endpoint is explicitly cacheable.
- Ensure `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/oauth-protected-resource/fapi/resource`, `/jwks.json`, `/authorize`, `/par`, `/token`, `/userinfo`, `/introspect`, and `/revoke` are reachable as intended.

For mTLS sender constraint and mTLS client authentication, the service relies
on a trusted reverse proxy to verify the client certificate and forward
certificate evidence. The application accepts forwarded certificate metadata
only when the connection peer is in `TRUSTED_PROXY_CIDRS`; traffic from any
other peer is treated as not having verified client certificate evidence.

## Key Rotation

Initial startup creates a local RS256 signing key if no keyset exists. Local
PEM keysets rotate automatically through the in-process lifecycle task. The
service refreshes its runtime keyset snapshot periodically, prepublishes the
next local key when the active key enters the prepublication window, activates
it after the window has elapsed, and keeps the previous active key published in
JWKS until
`max(ACCESS_TOKEN_TTL_SECONDS, ID_TOKEN_TTL_SECONDS)` has elapsed.

Default lifecycle settings:

- `SIGNING_KEY_ROTATION_INTERVAL_SECONDS=7776000` (90 days)
- `SIGNING_KEY_PREPUBLISH_SECONDS=86400` (1 day)

The prepublication window must be positive and shorter than the rotation
interval. The runtime refresh interval is derived from the prepublication
window and capped at one hour. Validate the keyset after deployment or backup
restoration:

```sh
nazo-oauth-keyctl validate
```

Validation rejects malformed `retire_at` values and any active key that carries
`retire_at`. Back up the key directory regularly. Losing active private keys
invalidates token signing continuity.

### External KMS/HSM Signing

Local PEM keys are the default. For non-exportable signing keys, register an
external key whose public JWK is stored in `keyset.json` while signing is
delegated to a trusted command or sidecar:

```sh
nazo-oauth-keyctl register-external \
  --kid rs256-kms-2026-06 \
  --alg RS256 \
  --key-ref kms://prod/oauth/rs256-kms-2026-06 \
  --public-jwk /secure/exported-public-jwk.json
nazo-oauth-keyctl validate
```

Configure `SIGNING_EXTERNAL_COMMAND` as a comma-separated argv list, for example
`/usr/local/bin/oauth-kms-signer,--profile,prod`, and set
`SIGNING_EXTERNAL_TIMEOUT_MS` to the maximum allowed signing latency. External
keys are activated only by the automatic lifecycle after their prepublication
window has elapsed and only when the signer command is configured. The service
sends one JSON request on stdin:

```json
{"version":1,"kid":"rs256-kms-2026-06","alg":"RS256","key_ref":"kms://prod/oauth/rs256-kms-2026-06","signing_input":"<base64url(header)>.<base64url(payload)>"}
```

The signer must return JSON on stdout with a base64url raw JWS signature:

```json
{"signature":"<base64url-signature>"}
```

The application rejects active external keys unless `SIGNING_EXTERNAL_COMMAND`
is configured, kills timed-out signer processes, rejects empty or malformed
signatures, verifies the returned signature against the active public JWK before
returning the JWT, and never falls back to unsigned or query-mode responses
after signing failure. A verification failure is an external signer fault: the
signer used the wrong key, algorithm, or signing input.

## Database and Valkey

PostgreSQL stores durable users, clients, grants, tokens, and revocation state.
Production requirements:

- automated backups
- restore rehearsals
- migration rollback planning
- monitoring for replication lag or storage saturation

Migration `20260712000050_social_federation_provider_type` expands the external
identity provider constraint without changing existing OIDC or SAML links. Its
down migration intentionally fails while `oauth2_social` links exist; operators
must migrate or explicitly remove those links before rollback so rollback cannot
silently discard federated identities. The `20260712000100` timestamp remains
reserved for the runtime desired-state migration.

`nazo_oauth_migrate` runs `nazo_oauth_cleanup_expired_security_state()` after
pending migrations. The cleanup removes expired access-token revocation markers,
expired refresh-token rows from leaf tokens upward, and SCIM audit events older
than 180 days. It also removes expired back-channel logout delivery rows so the
logout outbox cannot grow indefinitely after delivery TTLs have passed.
Operators should still monitor table growth; this cleanup is a startup/deploy
maintenance hook, not a substitute for database capacity alerts.

Valkey stores short-lived sessions, authorization codes, PAR handles,
DPoP/client assertion replay state, and rate-limit counters. Production
requirements:

- bounded memory policy
- latency monitoring
- persistence or HA appropriate to your risk model
- clear failure handling expectations

If Valkey is unavailable, sensitive protocol paths fail closed with OAuth errors instead of silently weakening replay or rate-limit controls.

The full HA, backup, restore, timeout, and partial-outage requirements are maintained in [docs/operations/ha-operations.md](ha-operations.md).

## Verification

After deployment:

```sh
curl -fsS https://oauth.example.com/health
curl -fsS https://oauth.example.com/.well-known/openid-configuration
curl -fsS https://oauth.example.com/.well-known/oauth-authorization-server
curl -fsS https://oauth.example.com/.well-known/oauth-protected-resource
curl -fsS https://oauth.example.com/.well-known/oauth-protected-resource/fapi/resource
curl -fsS https://oauth.example.com/jwks.json
```

Check that discovery `issuer` exactly equals `PUBLIC_BASE_URL`, unless `ISSUER`
was explicitly overridden.

If the experimental FAPI HTTP Signatures resource profile is enabled, also
send signed GET and POST probes and verify the response signature against the
current server JWKS. Confirm tampered method, target URI, Authorization, DPoP,
body, time, replay, client, and key cases fail closed. Do not enable the flag
until client JWK rotation, clock monitoring, Valkey replay storage, signing-key
custody, and evidence retention have named owners. The profile is default-off,
is not advertised in metadata, and has no dedicated OIDF conformance plan.

The `nazo.run` deployment helper [scripts/verify_live_full_interfaces.py](../../scripts/verify_live_full_interfaces.py) exercises a broader HTTPS path against `https://auth.nazo.run`. It reads host-local secrets and runs only in the intended deployment environment. The expected SHA is mandatory and is checked against both the successful deployment record and the running container image label:

```sh
python scripts/verify_live_full_interfaces.py \
  --base-url https://auth.nazo.run \
  --secrets-path /opt/nazo-oauth/secrets.json \
  --expected-backend-sha "$BACKEND_COMMIT"
```

Its Python environment is installed from `.github/e2e-requirements.txt` with
hash verification; update the input and regenerate the lock instead of adding
unversioned `pip install` commands.

## OIDF Readiness

Before launching a full OpenID Foundation conformance run:

1. Select the exact commit to test, require a clean worktree, and make sure unrelated deployment patches are not mixed in. Retain the current immutable image, UI release, deployment record, database backup, and other material required for a verified rollback before changing production.
2. Run `oidf-public-seed-configs` for that exact head and download its `oidf-public-plan-configs` artifact. The artifact contains the public plan JSON files, `oidf-mtls-ca-bundle.pem`, and a deterministic manifest binding the source commit, file tree, and CA DER fingerprints; private mTLS keys are never included. Preserve the workflow run ID, workflow head SHA, artifact digest, downloaded artifact digest, manifest digest, and CA-bundle digest as linked evidence. Reject an artifact whose head does not equal the deployment commit.
3. Confirm Angie proxies to fixed container IP `10.101.0.20:8000`, and `.env.yaml` trusts only the actual controlled proxy address.
4. Deploy the same commit to the public entrypoint with `scripts/deploy_live.ps1 -OidfPublicSeedArtifactArchive <downloaded-artifact.zip> -OidfPublicSeedWorkflowRunId <run-id> -OidfPublicSeedArtifactId <artifact-id> -OidfPublicSeedArtifactDigest sha256:<digest>`. For a real deployment all artifact identity arguments are mandatory: the script verifies the GitHub run result, branch, head, artifact identity and archive digest, extracts a private snapshot, and requires its manifest head to equal the backend commit. The deployment transaction then validates the public JSON and CA bundle together, binds the staged and installed bundle to the same SHA-256 digest, backs up the existing Angie CA file and hash, atomically replaces it in the same directory, validates and reloads Angie, and restores the prior bytes and metadata if deployment or verification rolls back. `-OidfPublicSeedArtifactDirectory` exists only for render-only test fixtures. This remains inside the existing deployment lock and verification lease; do not create a separate manual CA installation channel.
5. Put the same exact artifact in the live OIDF runtime directory and use the same commit's `oidf-seed` image / `nazo_oauth_seed_oidf` binary to seed the database used by the public `auth.nazo.run` entrypoint. Do not seed only the `compose.oidf.local.yml` 9443 stack and then run official public tests.
6. Verify the running deployment head and artifact/CA digests, then verify health, discovery, JWKS, mTLS aliases, certificate forwarding, and Angie configuration over the public issuer. Discovery `issuer` must be `https://auth.nazo.run`. Trust the validated CA chain from the exact-head artifact; do not replace it with a leaf-certificate fingerprint allowlist.
7. Run the targeted `.github/workflows/oidf-conformance.yml` plan first. The targeted workflow disables the early-stop monitor by default so failed runs still upload diagnostic artifacts.
8. Run `.github/workflows/oidf-conformance-full.yml` only after the targeted plan passes. Keep `OIDF_NO_PARALLEL=true` for the default full matrix unless deliberately testing runner concurrency. For concurrency validation, dispatch the same workflow with `runner_mode=parallel-isolated`; this runs the concurrency-safe plan set without `--no-parallel` while running logout and session-management in separate isolated matrix jobs with their own runner/browser environment.
9. Preserve the final result index under `docs/conformance` before artifacts expire, together with the deployed head, workflow run and plan IDs, artifact digest, CA-bundle digest, and final PR-check head.

## Operations Checklist

- HTTPS issuer only in production.
- Same-origin `PUBLIC_BASE_URL`.
- Secure cookies enabled. HTTPS `PUBLIC_BASE_URL` enables this by default.
- Minimal CORS exposure.
- Strict trusted proxy CIDRs.
- No proxy header spoofing path.
- PostgreSQL backup and restore tested.
- Valkey availability and memory monitored.
- PostgreSQL and Valkey HA and partial-outage behavior documented.
- Signing key backups and rotation schedule.
- Audit logs collected and retained.
- Admin accounts hardened.
- Dependency and image scanning in release flow.
- Release SBOM, image signature, and provenance attestation retained.
- OIDF conformance records updated before artifacts expire.
