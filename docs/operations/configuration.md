# Configuration

## Model

Nazo Auth Server is configured in two layers:

- startup configuration: values needed before the process can run
- runtime/application configuration: feature and integration settings that can
  move to the administrator UI over time

`nazoauth server` uses `.env.yaml` in its working directory. If the file is
absent, the command copies the minimal example to `.env.yaml`, reports the new
path, materializes required service-owned secrets, and continues startup.
Explicit YAML and environment values still take precedence.

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

## Startup settings

| Setting | Default | Notes |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8000` | Public listener; HTTPS in `direct-tls`, HTTP otherwise |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:8000` | Public same-origin base URL |
| `TRANSPORT_MODE` | implicit only for loopback HTTP | `loopback-http`, `direct-tls`, or `trusted-proxy`; required for non-loopback issuers |
| `TENANT_ID` | `00000000-0000-0000-0000-000000000001` | Process-wide active tenant; the row must exist and have `active` status |
| `REALM_ID` | `00000000-0000-0000-0000-000000000002` | Default identity placement; it must be active and belong to `TENANT_ID`, but it is not a request-routing or authorization partition |
| `ORGANIZATION_ID` | `00000000-0000-0000-0000-000000000003` | Default identity placement; it must be active and belong to `TENANT_ID`, but it is not a request-routing or authorization partition |
| `DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:5432/oauth` | PostgreSQL connection string for the current `nazoauth` launcher |
| `DATABASE_MAX_CONNECTIONS` | `32` | Maximum PostgreSQL pool size per NazoAuth process |
| `VALKEY_URL` | `redis://127.0.0.1:6379/0` | Valkey connection string; startup rejects an unmarked nonempty database rather than adopting historical keys |
| `VALKEY_STATE_EPOCH` | none (required UUIDv7) | Deployment state boundary. Every transient business key is physically namespaced as `nazo:state:v1:<deployment>:<epoch>:`. Set a fresh UUIDv7 before a restored candidate starts; never reuse a prior epoch. |
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
| `AUTHORIZATION_SERVER_PROFILE` | `oauth2-baseline` | Global protocol profile. Every OAuth client must carry an explicit current `security_policy`; rows without it are rejected rather than inferred from this setting. |
| `CIBA_SECURITY_PROFILE` | `fapi-ciba-id1` | CIBA-specific policy: FAPI-CIBA ID1 with orthogonal poll/ping delivery and private-key/mTLS client authentication, or internal `fapi2-ciba` hardening. Only these canonical values are accepted. |
| `MFA_TOTP_ENCRYPTION_KEY` / `MFA_TOTP_ENCRYPTION_KEY_ID` | generated under `DATA_DIR/secrets` | Current 32-byte base64url key and derived version id for TOTP seed envelope encryption. Prefer `MFA_TOTP_ENCRYPTION_KEY_FILE` when importing a controlled existing key. |
| `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY` / `MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID` | unset | Optional prior key for decrypting existing encrypted envelopes during a controlled key transition. Startup never scans, encrypts, or re-wraps credential rows. |
| `TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY` / `_ID` | generated under `DATA_DIR/secrets` | Independent current 32-byte base64url key and derived id for durable OAuth token-response envelopes. Do not derive it from `CLIENT_SECRET_PEPPER`; file injection remains available for controlled rotation. Missing or malformed pairs fail startup. |
| `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY` / `_ID` | unset | Optional previous key retained only during a rotation overlap; use `TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_FILE` for file injection. Existing live envelopes decrypt with current or previous; new envelopes always use current. Startup authenticates every live envelope, and expired rows are lazily removed before a grant key is reused. Remove the previous pair only after all rows encrypted with that id have expired and no writer still uses that key id. |
| `OPENID4VC_REVOCATION_POLICY` | `disabled` | `disabled`, `optional`, or `required`. The VP verifier requires `required`; enabling a policy also requires a bounded local snapshot file. VP verification never performs network or file I/O. |
| `OPENID4VC_REVOCATION_SNAPSHOT_FILE` | unset | Operator-controlled JSON snapshot containing SHA-256 certificate identities and `good`/`revoked` status with hard `this_update`/`next_update` bounds. Invalid reloads retain the previous snapshot only until its own expiry. |
| `OPENID4VC_REVOCATION_RELOAD_INTERVAL_SECONDS` | `30` | Positive local snapshot reload interval. |
| `OPENID4VC_MDOC_ISSUING_COUNTRY` | unset | Required only when local keyctl generates a certificate for an enabled `mso_mdoc` configuration. Two uppercase ASCII letters, and the generated DS/IACA Subject `C` uses this value. It is not required for externally issued certificate chains. |
| `SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE` | `true` | Reject startup and high-impact administration when the server role is a superuser, can assume a ledger owner/privileged role, has direct ledger table capabilities, or lacks the writer function grants. |
| `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS` | `60` | Request signature age and replay-marker lifetime; accepted range is 1–300 seconds, with at most five seconds of future clock skew |
| `SCIM_EVENT_RETENTION_SECONDS` | `604800` | Per-receiver delivery window and outbox retention; accepted range is 3600–2592000 seconds |
| `RUST_LOG` | `info` | Tracing filter |

The response key id is not the envelope format. The current format is `v1` and
is stored separately from `response_key_id`; a format change requires an
explicit migration. Keep the current and previous key material available for
the full durable-response recovery window. Managed schema changes run only in
the signed install, update, or recover lifecycle. An irreversible migration
requires verified snapshot recovery rather than artifact rollback.

PostgreSQL connections use Rustls with the AWS-LC provider. `DATABASE_URL`
accepts `sslmode=disable`, `prefer` (the PostgreSQL client default), or
`require`. TLS connections validate the server hostname and certificate against
the operating system trust store; bundled WebPKI roots are used only when the
platform store is empty. This path does not load `libpq` or the system OpenSSL
ABI. Use `sslmode=require` for remote or untrusted networks and
`sslmode=disable` only for a separately protected local/private transport.

## Local mdoc certificates and CRLs

Set `OPENID4VC_MDOC_ISSUING_COUNTRY` in the server `.env.yaml` before an
ordinary tenant receives locally generated mdoc material. The OIDF Suite's
current mDL dataset uses `UT`, so the conformance deployment's server
configuration must set `OPENID4VC_MDOC_ISSUING_COUNTRY: "UT"` before its
temporary tenant is materialized. Tenant-local settings inherit this root
configuration through the existing directory-binding path; the OIDF resource
Apply does not carry a second country value.

Existing locally generated mdoc bundles predate this profile and must be
regenerated through the normal tenant-local key generation path after the
setting is present. Generation writes a non-public IACA key under the tenant's
OpenID4VC material directory, named by the IACA certificate fingerprint, then
atomically activates the public DS/IACA bundle. The public bundle never contains
that private key.

The DS publishes `/.well-known/mdoc/<iaca-sha256>.crl`. It is signed for each request from
that IACA's retained key and contains only that IACA's DS when the existing
revocation snapshot marks it `revoked`. A snapshot must contain an explicit
`good` or `revoked` entry for that DS and remain within its `this_update` /
`next_update` interval; missing, stale, or mismatched private-key material makes
the CRL unavailable rather than returning an empty success response. Preserve
the snapshot's revocation entries when updating it, and advance `this_update`
on every change; this timestamp also identifies the CRL revision. Each private IACA PEM record
also retains its DS and CA certificates, so rotation preserves the old CRL URL
and its signer. Keep these records for the lifetime of the issued credentials.

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
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"`, only as an explicit one-shot legacy key import source |
| `SIGNING_KEY_ENCRYPTION_KEY_ID` | required deployment-provided nonempty wrapping-key identifier |
| `SIGNING_KEY_ENCRYPTION_KEY` | required deployment-provided unpadded base64url 32-byte signing-key wrapping key |
| `SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_ID` / `SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY` | optional matched previous wrapping-key pair while rewrapping persisted signing material |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"`, unless explicitly overridden |

Explicit overrides are retained for advanced deployments. New deployments
should prefer same-origin defaults.

Signing keys, their dedicated request-object decryption key, and their public
projection are one encrypted generation in PostgreSQL. `JWK_KEYS_DIR` is not a
runtime authority and is never created or read during ordinary startup. An
operator may explicitly import a complete old directory once; that preserves
every existing `kid` and leaves the source directory untouched for rollback.

Every server instance for a deployment must receive the same
`SIGNING_KEY_ENCRYPTION_KEY_ID` and `SIGNING_KEY_ENCRYPTION_KEY`. The key is
32 bytes encoded as unpadded base64url. Do not generate it per instance or replace
it before the database generation is rewrapped. During a wrapping-key change,
deploy the current and previous pair to every instance, let an operator publish
a new generation, verify all instances can load it, then remove the previous
pair. Back up the encrypted PostgreSQL row and the wrapping root together;
the database ciphertext cannot recover private keys without its wrapping root.

For a file-backed deployment upgrade, stop old writers and run the one-shot
offline import before starting the database-backed server:

```
nazoauth keys-import --tenant <tenant-uuid> --from <legacy-jwk-keys-directory>
```

The target tenant must already be active in the directory and the process must
have the deployment wrapping-key configuration. The command does not delete,
rewrite, or keep reading the source directory. Keep it and a PostgreSQL backup
until rollback is no longer required. Repeating the import is accepted only
when the database contains the same imported key identities and private
material; an unrelated keyset already created by server startup is an error.

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

Before crossing migration `20260828000600`, an existing deployment must
materialize one explicit `enabled` or `disabled` row for every runtime module.
Missing rows or `inherit` stop migration; the server does not reconstruct old
configuration. After migration, runtime module administration is the only
authority. The removed stable-module flags must be deleted from older
`.env.yaml` files before restarting.

The same migration is an offline persisted-security cut, not a data converter.
Before applying it, stop every old writer and retain a verified database
snapshot. Materialize and review a complete v1 `security_policy` for every
OAuth client; terminate refresh families that lack the current issuer,
client-audience, authentication-time, AMR, or claim contract; and remove
pre-binding OpenID4VP transactions. Every TOTP row must already contain a v1
encrypted envelope and a non-empty key id, with no plaintext seed remaining.
Before removing any current or previous TOTP key, an operator-controlled
pre-cut procedure must authenticate-decrypt every retained row using the same
tenant/user AAD as the server and record that every distinct stored key id is
available. Migration 006 can validate envelope shape but cannot prove AEAD
authenticity or key availability. If any probe fails, do not run the migration;
repair the stopped candidate before proceeding. After the cut, artifact rollback
is rejected; `nazoauthctl recover` is the only managed path from a verified
snapshot. The current server has no startup plaintext encryption, policy
inference, runtime-state materializer, or alternate read path.

See
[Composable Capability Policy](../protocol/composable-capability-policy.md)
for the server/client boundary, default matrix, policy JSON, and upgrade rules.

## Experimental FAPI HTTP signatures

The explicit persisted `http_message_signatures` runtime-module state changes
only `/fapi/resource`. It is default-off, has no discovery metadata, and is
not a claimed certification profile.
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

The supported proxy preset strips inbound `Forwarded`, `X-Forwarded-*`,
`Client-Cert`, `Client-Cert-Chain`, and every `X-SSL-*` certificate header. It
adds only the singleton RFC 9440 `Client-Cert` value derived from the verified
TLS peer on the dedicated mTLS listener. Configure `TRUSTED_PROXY_CIDRS` only
for the exact proxy addresses and keep `CLIENT_IP_HEADER_MODE=none` for this
boundary.

Trusted mTLS header mode is a deployment boundary, not a browser feature. The
proxy or sidecar must verify the client certificate, forward only normalized
certificate evidence over the trusted internal hop, and reject or overwrite any
same-named header received from the public internet. Raw certificate material,
client assertions, DPoP proofs, access tokens, refresh tokens, authorization
codes, provider tokens, and secret references must not be logged or returned in
error responses.

For the concrete HAProxy 3.2 preset, trust-bundle installation, atomic reload,
and rollback requirements, see
[`deploy/proxy/README.md`](../../deploy/proxy/README.md).

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

- conditional OpenID4VC service settings: `ENABLE_OPENID4VCI_ISSUER`,
  `ENABLE_OPENID4VP_VERIFIER`. All runtime capabilities use their explicit
  persisted desired state.
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
- SCIM: `SCIM_EVENT_RETENTION_SECONDS`
- external signing: `SIGNING_EXTERNAL_COMMAND`,
  `SIGNING_EXTERNAL_TIMEOUT_MS`,
  `SIGNING_KEY_ROTATION_INTERVAL_SECONDS`,
  `SIGNING_KEY_PREPUBLISH_SECONDS`
- observability: `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`,
  `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`
- proxy and client IP handling: `TRUSTED_PROXY_CIDRS`,
  `CLIENT_IP_HEADER_MODE`, `MTLS_CERTIFICATE_SOURCE`

`MTLS_CERTIFICATE_SOURCE` accepts `disabled`, `direct-tls`, or `rfc9440`.
`rfc9440` consumes the singleton RFC 9440 `Client-Cert` DER byte sequence.
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
