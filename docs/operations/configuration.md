# Configuration

## Model

Nazo Auth Server is configured in two layers:

- startup configuration: values needed before the process can run
- runtime/application configuration: feature and integration settings that can
  move to the administrator UI over time

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
```

## Minimal deployment

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<random 32+ byte secret>"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
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
| `CLIENT_SECRET_PEPPER` | development-only default for loopback issuers | Required for non-loopback issuers; use a random 32+ byte secret and keep it stable across restarts |
| `PASSWORD_HASH_MAX_CONCURRENCY` | `8` | Maximum concurrent Argon2 password verifications per process; tune from CPU and memory capacity, not by lowering Argon2 cost |
| `PASSWORD_HASH_QUEUE_TIMEOUT_MS` | `100` | Maximum bounded wait for a password-verification slot before returning `temporarily_unavailable` |
| `LOGIN_FAILURE_WINDOW_SECONDS` | `900` | Window for failed-login throttling |
| `LOGIN_FAILURE_EMAIL_MAX_ATTEMPTS` | `50` | Maximum failed login attempts per normalized email in the failed-login window |
| `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS` | `5` | Maximum failed login attempts per source IP and normalized email in the failed-login window |
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | `oauth2-baseline`, `fapi2-security`, `fapi2-message-signing-authz-request`, `fapi2-message-signing-jarm`, or `fapi2-message-signing-introspection` |
| `CIBA_SECURITY_PROFILE` | `fapi-ciba-id1-plain-private-key-jwt-poll` | CIBA-specific policy: `fapi-ciba-id1-plain-private-key-jwt-poll` for OIDF FAPI-CIBA compatibility, or internal `fapi2-ciba` hardening |
| `ENABLE_FAPI_HTTP_SIGNATURES` | `false` | Experimental resource-only profile for the 2026-06-26 FAPI 2.0 HTTP Signatures working draft; when enabled, `/fapi/resource` requires a registered client JWK and RFC 9421 signature and signs every response |
| `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS` | `60` | Request signature age and replay-marker lifetime; accepted range is 1–300 seconds, with at most five seconds of future clock skew |
| `RUST_LOG` | `info` | Tracing filter |

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

- OAuth/OIDC feature gates: `ENABLE_REQUEST_OBJECT`,
  `ENABLE_REQUEST_URI_PARAMETER`, `ENABLE_PAR_REQUEST_OBJECT`,
  `ENABLE_AUTHORIZATION_DETAILS`, `ENABLE_LEGACY_AUDIENCE_PARAM`,
  `ENABLE_DEVICE_AUTHORIZATION_GRANT`, `ENABLE_DYNAMIC_CLIENT_REGISTRATION`
- protocol tuning: `DPOP_NONCE_POLICY`, `REQUEST_OBJECT_JTI_POLICY`,
  `CIBA_SECURITY_PROFILE`, `REQUIRE_PUSHED_AUTHORIZATION_REQUESTS`,
  `PAR_TTL_SECONDS`,
  `PROTECTED_RESOURCE_IDENTIFIER`, `DEVICE_AUTHORIZATION_TTL_SECONDS`,
  `DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS`,
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`
- token and session lifetimes: `SESSION_TTL_SECONDS`, `AUTH_CODE_TTL_SECONDS`,
  `ACCESS_TOKEN_TTL_SECONDS`, `ID_TOKEN_TTL_SECONDS`,
  `REFRESH_TOKEN_TTL_SECONDS`
- rate limits: `RATE_LIMIT_WINDOW_SECONDS`, `AUTH_RATE_LIMIT_MAX_REQUESTS`,
  `TOKEN_RATE_LIMIT_MAX_REQUESTS`,
  `TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS`,
  `LOGIN_FAILURE_WINDOW_SECONDS`, `LOGIN_FAILURE_EMAIL_MAX_ATTEMPTS`,
  `LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS`
- password verification capacity: `PASSWORD_HASH_MAX_CONCURRENCY`,
  `PASSWORD_HASH_QUEUE_TIMEOUT_MS`
- email delivery: `EMAIL_DELIVERY`, `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`,
  `EMAIL_SMTP_TLS`, `EMAIL_SMTP_USERNAME`, `EMAIL_SMTP_PASSWORD`,
  `EMAIL_FROM`
- passkeys: `PASSKEY_RP_NAME`, `PASSKEY_REQUIRE_USER_VERIFICATION`,
  `PASSKEY_REQUIRE_USER_HANDLE`, `PASSKEY_STRICT_BASE64`
- federation: `FEDERATION_PROVIDER_CONFIGS`, `FEDERATION_SAML_GATEWAY_*`
- SCIM: `SCIM_BEARER_TOKEN`
- external signing: `SIGNING_EXTERNAL_COMMAND`,
  `SIGNING_EXTERNAL_TIMEOUT_MS`,
  `SIGNING_KEY_ROTATION_INTERVAL_SECONDS`,
  `SIGNING_KEY_PREPUBLISH_SECONDS`
- observability: `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
  `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`
- proxy and client IP handling: `TRUSTED_PROXY_CIDRS`,
  `CLIENT_IP_HEADER_MODE`

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
