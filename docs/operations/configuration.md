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

## Startup settings

| Setting | Default | Notes |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | HTTP listener |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | Public same-origin base URL |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL connection string |
| `DATABASE_MAX_CONNECTIONS` | `32` | Maximum PostgreSQL pool size per NazoAuth process |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey connection string |
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
| `LOGIN_FAILURE_WINDOW_SECONDS` | `900` | Window for failed-login throttling |
| `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS` | `5` | Maximum failed login attempts per source IP and normalized email in the failed-login window |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | Compatibility preset for clients without a stored `security_policy`; new clients use explicit composable policy. Accepted legacy values remain `oauth2-baseline`, `fapi2-security`, `fapi2-message-signing-authz-request`, `fapi2-message-signing-jarm`, and `fapi2-message-signing-introspection`. |
| `CIBA_SECURITY_PROFILE` | `fapi-ciba-id1` | CIBA-specific policy: FAPI-CIBA ID1 with orthogonal poll/ping delivery and private-key/mTLS client authentication, or internal `fapi2-ciba` hardening. Only these canonical values are accepted; conformance-plan names are not runtime profiles. |
| `CIBA_AUTOMATED_DECISION_MODE` | `disabled` | Automated decisions are closed by default. `nazoauthctl conformance lease create` can temporarily admit the OIDF GET/query endpoint for clients owned by that exact `oidc-fapi-ciba` lease and its independently generated token digest; lease expiry or revocation closes it immediately. Explicit `header` (POST + `Authorization: Bearer`) and `query` (legacy GET/query) modes retain their static transport behavior and are intended only for isolated conformance deployments. |
| `CIBA_AUTOMATED_DECISION_TOKEN` | generated only for explicit static mode | 32+ byte static secret required only by explicit `header`/`query` modes. The default lease-gated OIDF path does not read it. Prefer `CIBA_AUTOMATED_DECISION_TOKEN_FILE` when an isolated deployment explicitly selects a static mode. |
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

Production deployments must expose the issuer through HTTPS. Nazo Auth Server
normally listens on HTTP behind a TLS-terminating reverse proxy; the proxy is
responsible for public TLS policy and browser HSTS. Public listeners should use
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
Both proxy modes require `TRUSTED_PROXY_CIDRS`; without a trusted proxy the
default is `disabled`. When trusted proxy CIDRs are present and the source is
omitted, the compatibility mode remains the default for existing deployments.

`direct-tls` creates a separate client-certificate-required TLS listener. It
requires `TLS_BIND`, `TLS_CERTIFICATE_FILE`, `TLS_PRIVATE_KEY_FILE`, and
`TLS_CLIENT_CA_FILE`. The ordinary `BIND` listener remains available for the
browser/public route behind a normal TLS terminator; route the RFC 8705 mTLS
endpoint aliases to `TLS_BIND`.

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
