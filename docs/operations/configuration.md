# Configuration

## Model

Nazo Auth Server is configured in two layers:

- startup configuration: values needed before the process can run
- runtime/application configuration: feature and integration settings that can
  move to the administrator UI over time

`nazoauth server` requires `.env.yaml` in its working directory. If the file is
absent, the command copies the minimal example to `.env.yaml`, prints an
instruction to review it, and exits successfully without opening network or
database connections. Edit the file before running the command again.

The default deployment is same-origin. The public URL is configured once and
the server derives the related URLs from it:

```text
PUBLIC_BASE_URL=https://auth.example.com
ISSUER=https://auth.example.com
FRONTEND_BASE_URL=https://auth.example.com/ui/
PASSKEY_ORIGIN=https://auth.example.com
PASSKEY_RP_ID=auth.example.com
PROTECTED_RESOURCE_IDENTIFIER=https://auth.example.com/fapi/resource
CLIENT_SECRET_PEPPER=<random 32+ byte secret>
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY=<base64url-encoded 32-byte key>
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID=response-2026-08
```

## Minimal deployment

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "disabled"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<random 32+ byte secret>"
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY: "<base64url-encoded 32-byte key>"
TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID: "response-2026-08"
RUST_LOG: "info"
```

`DATA_DIR` defaults the persistent file locations:

```text
JWK_KEYS_DIR = DATA_DIR + "/keys"
AVATAR_STORAGE_DIR = DATA_DIR + "/avatars"
```

### Email verification namespace cutover

Email verification codes and their per-email and per-peer cooldowns include the
registration service tenant. The previous key format was deployment-global and
included the normalized email directly. Old and new binaries cannot safely
serve local registration against the same Valkey during this transition:
legacy reads can cross tenant boundaries, while ignoring a live legacy code or
cooldown can admit a duplicate send or make an issued code unreachable.

Define the drain interval as the largest value deployed on the old instances:

```text
T_email = max(
  EMAIL_CODE_TTL_SECONDS,
  EMAIL_CODE_SEND_COOLDOWN_SECONDS,
  EMAIL_CODE_PEER_COOLDOWN_SECONDS
)
```

The default `T_email` is 900 seconds, but these settings accept larger positive
values. Use the actual deployed maximum rather than assuming the default.

Perform a coordinated cutover:

1. Stop admitting both email-code issuance and local-account registration on
   every old instance, drain requests already in progress, and verify that no
   old instance can read or write email verification state.
2. Starting only after that drain completes, wait at least the old deployment's
   `T_email`.
3. Replace every instance with the new binary before restoring registration.

There is no database rewrite or Valkey cleanup job; legacy state expires by its
existing TTL. Rollback is symmetric: stop and drain registration on all new
instances, wait at least the new deployment's `T_email`, then restore every old
instance before resuming traffic. Do not mix old and new binaries or use a
legacy dual-read.

## Startup settings

| Setting | Default | Notes |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | Public listener; HTTPS in `direct-tls`, HTTP otherwise |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | Public same-origin base URL |
| `TRANSPORT_MODE` | implicit only for loopback HTTP | `loopback-http`, `direct-tls`, or `trusted-proxy`; required for non-loopback issuers |
| `TENANT_ID` | `00000000-0000-0000-0000-000000000001` | Process-wide active tenant; the row must exist and have `active` status |
| `REALM_ID` | `00000000-0000-0000-0000-000000000002` | Default identity placement; it must be active and belong to `TENANT_ID`, but it is not a request-routing or authorization partition |
| `ORGANIZATION_ID` | `00000000-0000-0000-0000-000000000003` | Default identity placement; it must be active and belong to `TENANT_ID`, but it is not a request-routing or authorization partition |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL connection string |
| `DATABASE_MAX_CONNECTIONS` | `32` | Maximum PostgreSQL pool size per NazoAuth process |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey connection string; its logical database is permanently claimed by `TENANT_ID`, same-tenant replicas may share it, and a non-default tenant requires an empty database on first claim |
| `DATA_DIR` | `runtime` | Base directory for persistent local files |
| `UI_CACHE_DIR` | `${DATA_DIR}/ui-releases` | Writable cache for the verified frontend release selected from the embedded descriptor |
| `UI_STATIC_DIR` | unset | Optional signed frontend directory containing `index.html`; serves files and SPA routes under `/ui/` |
| `CLIENT_SECRET_PEPPER` | generated under `DATA_DIR/secrets` | Explicit values override the persisted generated value; keep it stable and back it up with the database |
| `PASSWORD_HASH_MAX_CONCURRENCY` | `8` | Maximum concurrent Argon2 password verifications per process; tune from CPU and memory capacity, not by lowering Argon2 cost |
| `PASSWORD_HASH_QUEUE_TIMEOUT_MS` | `100` | Maximum bounded wait for a password-verification slot before returning `temporarily_unavailable` |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window for the broad source-IP admission buckets |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | `100000` | Broad source-IP admission ceiling for authentication endpoints; this is not the failed-login throttle |
| `TOKEN_RATE_LIMIT_MAX_REQUESTS` | `100000` | Broad source-IP admission ceiling for token issuance, sized to tolerate shared client egress |
| `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS` | `100000` | Broad source-IP admission ceiling shared by token-management, PAR, and dynamic-registration paths |
| `EMAIL_CODE_TTL_SECONDS` | `900` | Lifetime of a local-registration email verification code |
| `EMAIL_CODE_SEND_COOLDOWN_SECONDS` | `60` | Per-tenant, per-normalized-email send cooldown |
| `EMAIL_CODE_PEER_COOLDOWN_SECONDS` | `5` | Per-tenant, per-peer send cooldown; the broader authentication rate limiter remains a separate deployment-wide admission control |
| `LOGIN_FAILURE_WINDOW_SECONDS` | `900` | Window for failed-login throttling |
| `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS` | `5` | Maximum failed login attempts per source IP and normalized email in the failed-login window |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | Compatibility preset for clients without a stored `security_policy`; new clients use explicit composable policy. Accepted legacy values remain `oauth2-baseline`, `fapi2-security`, `fapi2-message-signing-authz-request`, `fapi2-message-signing-jarm`, and `fapi2-message-signing-introspection`. |
| `CIBA_SECURITY_PROFILE` | `fapi-ciba-id1` | CIBA-specific policy: FAPI-CIBA ID1 with orthogonal poll/ping delivery and private-key/mTLS client authentication, or internal `fapi2-ciba` hardening. Only these canonical values are accepted; conformance-plan names are not runtime profiles. |
| `CIBA_AUTOMATED_DECISION_MODE` | `disabled` | Selects only the automated-decision HTTP transport: `disabled` keeps the POST/query compatibility endpoint, `header` accepts POST plus `Authorization: Bearer`, and `query` retains the GET/query compatibility endpoint. Every mode authorizes requests through an active tenant-scoped `CibaDecisionBinding`; no global decision token is configured on the server. |
| `MFA_TOTP_ENCRYPTION_KEY` / `MFA_TOTP_ENCRYPTION_KEY_ID` | generated under `DATA_DIR/secrets` | Current 32-byte base64url key and derived version id for TOTP seed envelope encryption. Prefer `MFA_TOTP_ENCRYPTION_KEY_FILE` when importing a controlled existing key. |
| `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY` / `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID` | unset | Optional previous key pair accepted only while rotating TOTP envelopes; startup re-wraps legacy/previous rows before serving traffic, so retain it until that startup succeeds. |
| `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY` / `_ID` | generated under `DATA_DIR/secrets` | Independent current 32-byte base64url key and derived id for durable OAuth token-response envelopes. Do not derive it from `CLIENT_SECRET_PEPPER`; file injection remains available for controlled rotation. Missing or malformed pairs fail startup. |
| `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY` / `_ID` | unset | Optional previous key retained only during a rotation overlap; use `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_FILE` for file injection. Existing live envelopes decrypt with current or previous; new envelopes always use current. Startup authenticates every live envelope, and expired rows are lazily removed before a grant key is reused. Remove the previous pair only after all rows encrypted with that id have expired and all old instances have stopped writing it. |
| `OPENID4VC_REVOCATION_POLICY` | `disabled` | `disabled`, `optional`, or `required`. The VP verifier requires `required`; enabling a policy also requires a bounded local snapshot file. Request handling never performs network or file I/O. |
| `OPENID4VC_REVOCATION_SNAPSHOT_FILE` | unset | Operator-controlled JSON snapshot containing SHA-256 certificate identities and `good`/`revoked` status with hard `this_update`/`next_update` bounds. Invalid reloads retain the previous snapshot only until its own expiry. |
| `OPENID4VC_REVOCATION_RELOAD_INTERVAL_SECONDS` | `30` | Positive local snapshot reload interval. |
| `SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE` | `true` | Reject startup and high-impact administration when the server role is a superuser, can assume a ledger owner/privileged role, has direct ledger table capabilities, or lacks the writer function grants. |
| `ENABLE_FAPI_HTTP_SIGNATURES` | `false` | Experimental resource-only profile for the 2026-06-26 FAPI 2.0 HTTP Signatures working draft; when enabled, `/fapi/resource` requires a registered client JWK and RFC 9421 signature and signs every response |
| `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS` | `60` | Request signature age and replay-marker lifetime; accepted range is 1–300 seconds, with at most five seconds of future clock skew |
| `ENABLE_SCIM_SECURITY_EVENTS` | `false` | Enables default-closed RFC 9967 SET outbox creation, discovery, and RFC 8936 polling; depends on the SCIM runtime module |
| `SCIM_EVENT_RETENTION_SECONDS` | `604800` | Per-receiver delivery window and outbox retention; accepted range is 3600–2592000 seconds |
| `RUST_LOG` | `info` | Tracing filter |

### FAPI HTTP-signature replay namespace cutover

FAPI HTTP-signature replay keys include the validated access-token tenant. The
previous key format did not, so old and new binaries cannot safely serve this
capability against the same Valkey during the transition: reading the old key
would preserve cross-tenant false replays, while ignoring it before expiry could
accept a signature already consumed by an old instance.

Use a coordinated cutover for this one-time key migration:

1. Stop admitting new signed `/fapi/resource` requests on every old instance,
   drain requests already in progress, and verify that no old instance can write
   another replay marker.
2. Starting only after that drain completes, wait at least 305 seconds. This is
   the maximum configured signature age of 300 seconds plus the five-second
   future-skew replay allowance.
3. Replace every instance with the new binary before restoring traffic.

There is no data rewrite or cleanup job; old keys expire through their existing
TTL. Rollback is symmetric: stop this traffic, drain every request that can
write a tenant-scoped marker, wait at least 305 seconds from completion of that
drain, then restore the old binary on every instance.
Do not mix old and new binaries or roll back early, because either action can
split the authoritative replay boundary.

The response key id is not the envelope format. The current format is `v1` and
is stored separately from `response_key_id`; a format change requires an
explicit migration. Keep the current and previous key material available for
the full durable-response recovery window. A `nazoauth migrate` rollback is
refused while issuance rows remain, so take an explicit database backup and
drain/expire the saga before any destructive schema rollback.

PostgreSQL connections use Rustls with the AWS-LC provider. `DATABASE_URL`
accepts `sslmode=disable`, `prefer` (the PostgreSQL client default), or
`require`. TLS connections validate the server hostname and certificate against
the operating system trust store; bundled WebPKI roots are used only when the
platform store is empty. This path does not load `libpq` or the system OpenSSL
ABI. Use `sslmode=require` for remote or untrusted networks and
`sslmode=disable` only for a separately protected local/private transport.

## Derived settings

| Derived value | Rule |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL`, unless explicitly overridden |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"`, unless explicitly overridden |
| `CORS_ALLOWED_ORIGINS` | origin of `PUBLIC_BASE_URL`, unless explicitly overridden |
| `COOKIE_SECURE` | `true` when issuer uses HTTPS |
| `PASSKEY_ORIGIN` | issuer, unless explicitly overridden |
| `PASSKEY_RP_ID` | host of `PASSKEY_ORIGIN`, unless explicitly overridden |
| `PROTECTED_RESOURCE_IDENTIFIER` | `ISSUER + "/fapi/resource"`, unless explicitly overridden |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"`, unless explicitly overridden |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"`, unless explicitly overridden |

Explicit overrides are retained for advanced deployments and backward
compatibility. New deployments should prefer same-origin defaults.

`JWK_KEYS_DIR` is persistent state, not a disposable cache. On first start,
NazoAuth atomically creates both its signing keyset and a dedicated
`request-object-encryption.pem` recipient key. Existing key directories are
upgraded automatically when first loaded. Back up or mount this directory
together with the database; replacing the recipient key makes already-issued
encrypted Request Objects undecryptable.

## Composable capability defaults

New databases activate stable, non-conflicting server modules together.
Client authority remains default-deny: a client still needs the appropriate
grant allowlist, metadata, sender constraint, and versioned `security_policy`.
Device Grant and CIBA therefore have active server support but new clients
cannot use either until `allow_cross_device_flows=true` and the corresponding
grant/metadata are assigned. Session Management similarly requires
`session_management=true`.

Dynamic Client Registration is active only when
`DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` is non-empty. The token is
generated and persisted by the server/managed installer when it is not
provided. Experimental, draft, remote-trust, and role-specific modules remain
conditional on their complete prerequisites.

During the first upgrade to composable defaults, existing inherited module
states are materialized as explicit rows using the current composable defaults.
After migration, runtime module administration is authoritative. The removed
stable-module flags are not accepted as configuration and must be deleted from
older `.env.yaml` files before restarting.

See
[Composable Capability Policy](../protocol/composable-capability-policy.md)
for the server/client boundary, default matrix, policy JSON, and upgrade rules.

## Experimental FAPI HTTP signatures

`ENABLE_FAPI_HTTP_SIGNATURES=true` changes only `/fapi/resource`. It is
default-off, has no discovery metadata, and is not an OIDF-certified profile.
Each token's `client_id` must resolve to an active client with an exact public
JWK matching the request `keyid` and algorithm. Supported algorithms are
Ed25519, RSA PKCS#1 v1.5 SHA-256 with RSA keys of at least 2048 bits, and
ECDSA P-256 SHA-256. Private JWK material, ambiguous keys, unsupported curves,
or algorithm/key mismatches fail closed.

Operators own client-key provisioning and revocation, clock synchronization,
Valkey availability for atomic replay consumption, server signing-key custody,
and signed-message evidence retention. A replay-store or response-signing
failure returns a signed error when possible and never falls back to an
unsigned success. See the [dated draft audit](../protocol/fapi-http-signatures-draft-audit.md).

## Public OP/AS security boundary

Production deployments must expose the issuer through HTTPS. Select exactly one
transport owner with `TRANSPORT_MODE`: NazoAuth terminates TLS in `direct-tls`,
or a reverse proxy terminates TLS in `trusted-proxy`. Public listeners should use
TLS 1.3 where available, allow only modern TLS 1.2 suites when TLS 1.2 is
required, reject TLS 1.0/1.1, and set `Strict-Transport-Security` for
browser-facing issuer hosts. `ISSUER`, `PUBLIC_BASE_URL`, and
`FRONTEND_BASE_URL` must use the externally visible HTTPS origin in production.

Reverse proxies must strip inbound client-supplied `Forwarded`,
`X-Forwarded-*`, mTLS, and certificate-related headers before adding trusted
values. Configure `TRUSTED_PROXY_CIDRS` only for proxy addresses that are
allowed to supply client IP or verified certificate metadata. Keep
`CLIENT_IP_HEADER_MODE=none` unless every hop between the public listener and
the application is under the same administrative trust boundary.

Trusted mTLS header mode is a deployment boundary, not a browser feature. The
proxy or sidecar must verify the client certificate, forward only normalized
certificate evidence over the trusted internal hop, and reject or overwrite any
same-named header received from the public internet. Raw certificate material,
client assertions, DPoP proofs, access tokens, refresh tokens, authorization
codes, provider tokens, and secret references must not be logged or returned in
error responses.

For concrete HAProxy 3.2 and nginx presets, dynamic conformance CA installation,
atomic reload, and rollback requirements, see
[`deploy/proxy/README.md`](../../deploy/proxy/README.md). A conformance client CA
is generated for one run and must not be hard-coded or retained as a permanent
production trust root.

CORS is endpoint-scoped. `CORS_ALLOWED_ORIGINS` is an exact allowlist, not proof
that a browser client is confidential. Authorization and browser-redirect
endpoints are navigation-only and are not CORS APIs. `/token` and `/revoke`
allow non-credentialed browser CORS only for POST with the protocol headers
needed for content type, client/token authorization, DPoP nonce, challenge, and
retry handling. `/userinfo` permits non-credentialed GET/POST bearer or DPoP
access. These public OAuth routes do not accept the session-only
`X-CSRF-Token` header. Auth and admin session APIs may use credentialed CORS
only for exact configured origins and only with CSRF-bearing write requests.
Session cookies are
`HttpOnly`, `SameSite=Lax`, and `Secure` by default; disabling `COOKIE_SECURE`
is only appropriate for local loopback development.

## Advanced settings

The following settings are still supported but should not be part of a quick
deployment path. They are candidates for the administrator UI:

- conditional capability gates: `ENABLE_AUTHORIZATION_DETAILS`,
  `ENABLE_NATIVE_SSO`, `ENABLE_FAPI_HTTP_SIGNATURES`,
  `ENABLE_SCIM_SECURITY_EVENTS`, `ENABLE_OPENID4VCI_ISSUER`,
  `ENABLE_OPENID4VP_VERIFIER`
- protocol tuning: `DPOP_NONCE_POLICY`, `FAPI_RESOURCE_DPOP_NONCE_POLICY`, `REQUEST_OBJECT_JTI_POLICY`,
  `CIBA_SECURITY_PROFILE`, `REQUIRE_PUSHED_AUTHORIZATION_REQUESTS`,
  `PAR_TTL_SECONDS`,
  `PROTECTED_RESOURCE_IDENTIFIER`, `DEVICE_AUTHORIZATION_TTL_SECONDS`,
  `DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS`,
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`,
  `REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS`,
  `BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS`
- token and session lifetimes: `SESSION_TTL_SECONDS`, `AUTH_CODE_TTL_SECONDS`,
  `ACCESS_TOKEN_TTL_SECONDS`, `ID_TOKEN_TTL_SECONDS`,
  `REFRESH_TOKEN_TTL_SECONDS`

`REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS` is a comma-separated list of exact
HTTPS origins allowed to resolve to private/loopback addresses for remote
dynamic-client JWKS and Request Objects. Leave it empty in production unless a
specific private client-document service is required. Public destinations are
always DNS-resolved and blocked when any result is loopback, link-local,
private, unspecified, or multicast; redirects are disabled.

`BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS` is a comma-separated list of exact HTTP(S)
origins that are explicitly permitted to resolve to private or loopback
addresses for Back-Channel Logout delivery. Leave it empty in production unless
a specific private RP is required. Each delivery is DNS-resolved before use,
pinned to the resolved addresses, rejected if any address is private without an
exact allowlist match, and sent with redirects disabled. HTTP remains limited to
loopback endpoints.
- rate limits: `RATE_LIMIT_WINDOW_SECONDS`, `AUTH_RATE_LIMIT_MAX_REQUESTS`,
  `TOKEN_RATE_LIMIT_MAX_REQUESTS`,
  `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS`,
  `LOGIN_FAILURE_WINDOW_SECONDS`,
  `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS`
- password verification capacity: `PASSWORD_HASH_MAX_CONCURRENCY`,
  `PASSWORD_HASH_QUEUE_TIMEOUT_MS`
- email delivery: `EMAIL_DELIVERY`, `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`,
  `EMAIL_SMTP_TLS`, `EMAIL_SMTP_USERNAME`, `EMAIL_SMTP_PASSWORD`,
  `EMAIL_FROM`
- passkeys: `PASSKEY_RP_NAME`, `PASSKEY_REQUIRE_USER_VERIFICATION`,
  `PASSKEY_REQUIRE_USER_HANDLE`, `PASSKEY_STRICT_BASE64`
- federation: `FEDERATION_PROVIDER_CONFIGS`, `FEDERATION_SAML_GATEWAY_*`
- SCIM: `ENABLE_SCIM_SECURITY_EVENTS`,
  `SCIM_EVENT_RETENTION_SECONDS`
- external signing: `SIGNING_EXTERNAL_COMMAND`,
  `SIGNING_EXTERNAL_TIMEOUT_MS`,
  `SIGNING_KEY_ROTATION_INTERVAL_SECONDS`,
  `SIGNING_KEY_PREPUBLISH_SECONDS`
- observability: `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
  `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`
- proxy and client IP handling: `TRUSTED_PROXY_CIDRS`,
  `CLIENT_IP_HEADER_MODE`, `MTLS_CERTIFICATE_SOURCE`

`MTLS_CERTIFICATE_SOURCE` accepts `disabled`, `direct-tls`, `rfc9440`, or
`legacy-verified-headers`. `rfc9440` consumes the singleton RFC 9440
`Client-Cert` DER byte sequence. `legacy-verified-headers` requires
`X-SSL-Client-Verify: SUCCESS` and the existing forwarded certificate fields.
`trusted-proxy` requires both `TRUSTED_PROXY_CIDRS` and an explicit certificate
source; use `disabled` when that proxy does not authenticate client certificates.
`loopback-http` rejects proxy and certificate-source settings. No public mode is
inferred from the presence of proxy CIDRs or certificate headers.

`direct-tls` serves normal HTTPS on `BIND` and client-certificate-required HTTPS
on `TLS_BIND`, using the same server identity. It requires
`TLS_CERTIFICATE_FILE`, `TLS_PRIVATE_KEY_FILE`, and `TLS_CLIENT_CA_FILE`.
The leaf certificate must be currently valid, match the private key, and cover
the issuer and mTLS endpoint hosts. On Unix,
the private key must be a regular file with no group or other permission bits.
Route the RFC 8705 mTLS endpoint aliases to `TLS_BIND`; direct mode rejects all
proxy trust settings and derives client certificate identity only from the TLS
  session. The process revalidates the server certificate chain and private key
  as one immutable TLS identity
generation every `TLS_RELOAD_INTERVAL_SECONDS` (default `5`, allowed `1..=3600`).
A candidate is published only after a non-empty parseable certificate chain,
  leaf/private-key match, current leaf validity, endpoint names, file bounds, and key
permissions pass. Invalid or partially installed material leaves the previous
generation active. New handshakes use the published generation; existing
connections keep the generation they accepted. Server-side TLS resumption is
  disabled so a new connection cannot bypass a server identity change. The
  client-CA bundle is validated and fixed at startup; changing client trust
  currently requires a controlled restart so one handshake cannot combine
  server identity and client trust from different generations.
The deployment owner remains responsible for crash-safe staged file activation,
public health verification, and restoring the previous files after a failed
rollout. Multi-identity SNI selection remains part of the tenant transport
snapshot work; an unknown DNS SNI is rejected instead of falling back to the
single configured identity.

Tenant resource management is an optional machine control-plane surface,
independent from browser `/admin`, SCIM bearer authentication, and any OIDF
Suite integration. Set `TENANT_RESOURCE_CONTROLLER_PUBLIC_KEY_FILE` to a
privileged regular file containing the controller Ed25519 public key as
unpadded base64url. When it is absent, the machine resource routes are not
registered. When it is present but unreadable or invalid, startup fails
closed. The instance identity signs short-lived capability and operation
receipt JWS values; the pinned controller key verifies short-lived tasks.
Resource mutations, audit-chain append, revision CAS, and receipt persistence
commit in one PostgreSQL transaction. Rotate the controller trust anchor with
a controlled restart; this initial boundary deliberately has no remote key
rotation endpoint.

An active machine-resource binding is the sole authority for its managed user,
OAuth client, mTLS anchor, or OpenID4VC dataset. Ordinary admin/SCIM writes may
not change an actively bound user or client; the database rejects such drift.
Resource identities are immutable version fences: changing payload content
requires an explicit digest-fenced Revoke followed by Apply (normally with a
new resource identity), and clearing the desired set uses explicit Revoke.
Successful user/client revocation disables the resource, removes grants and
refresh credentials, and blacklists every still-live OAuth and OpenID4VC access
token owned by the resource in the same transaction.

`EMAIL_SMTP_TLS` accepts only `starttls`, `implicit`, or `none`. The `none`
mode is rejected unless the issuer is loopback HTTP and no SMTP credentials
are configured; production deployments must use encrypted mail submission.
`EMAIL_CODE_DEV_RESPONSE_ENABLED=true` is accepted only by a debug build with
a loopback HTTP issuer, so a deployable server cannot return verification
codes in API responses.

Security-sensitive values such as `DATABASE_URL`, `VALKEY_URL`, SMTP
credentials, federation client secrets, and SAML shared secrets must not be
committed to Git.

`FEDERATION_PROVIDER_CONFIGS` is a JSON array for modular third-party login
providers. Each enabled entry must include `provider_id`, `enabled`,
`display_name`, `adapter_type`, client credentials, redirect URI, scope,
endpoint or issuer configuration, and claim mapping. Providers default to
disabled unless `enabled` is true. Incomplete enabled provider configuration
fails startup; disabled providers do not appear in `/auth/federation/providers`.

Security-state lifetimes and cooldowns must be positive. Startup rejects zero
or negative values for session, authorization-code, access-token, ID-token,
refresh-token, PAR, client-delivery, and email-code lifetimes because those
settings back Valkey `EX` keys, database expiry timestamps, or abuse-control
windows.
