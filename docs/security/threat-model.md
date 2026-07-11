# Threat Model

## Scope

The threat model covers the current authorization-server boundary. Update it
in the same change that adds a profile, changes deployment topology, changes
token format, or expands discovery metadata.

## Assets

- Authorization codes
- Access tokens
- Refresh tokens
- ID Tokens
- DPoP proofs and nonces
- Client assertions
- Request objects and PAR handles
- User sessions and CSRF tokens
- Signing keys and JWKS metadata
- PostgreSQL durable state
- Valkey transient security state
- Discovery metadata
- Audit logs

## Trust Boundaries

| Boundary | Trusted side | Untrusted side | Required control |
| --- | --- | --- | --- |
| Browser to AS | AS endpoints | Browser, user-agent plugins, network attackers before TLS | HTTPS issuer, CSRF protection, redirect URI validation, PKCE |
| Client to AS | AS endpoints | OAuth clients, compromised clients, malicious clients | Client registration policy, client authentication, PAR/JAR validation |
| Reverse proxy to app | Configured trusted proxy CIDRs | Direct client traffic and untrusted proxies | `TRUSTED_PROXY_CIDRS`, header stripping, trusted internal channel |
| App to PostgreSQL | Application process | Database network and operators outside least privilege | credentials, network isolation, backups, migration controls |
| App to Valkey | Application process | Cache network and cache data loss | fail-closed replay/rate/session behavior |
| AS to resource server | Resource server verifier | Token replay and wrong-audience use | issuer/audience/cnf validation, revocation or introspection fallback |

## Threats and Controls

| Threat | Risk | Controls | Operational note |
| --- | --- | --- | --- |
| Authorization code theft | Stolen code exchanged by attacker | PKCE S256, redirect URI matching, client binding, short TTL, atomic code consumption | Profile matrix tests for every high-security client class |
| Authorization code replay | Reuse races mint extra tokens | Valkey state machine, consumed-code token revocation | More concurrency and lost-response regression tests |
| Redirect mix-up | Token delivered to wrong client or endpoint | Exact redirect URI matching, issuer metadata, authorization response issuer support | Negative conformance fixtures for mix-up variants |
| JAR replay | Reused signed request object repeats authorization transaction | Signed object validation, optional `jti` replay state when present | Product hardening profile for mandatory request object `jti` |
| DPoP replay | Captured proof reused inside validity window | Proof `jti`, `htu`, `htm`, `ath`, nonce, JWK thumbprint, Valkey replay state | More explicit nonce profile tests and downgrade tests |
| mTLS header spoofing | Direct attacker forges forwarded certificate headers | mTLS evidence accepted only from trusted proxy CIDRs; duplicate/conflicting forwarded cert headers rejected | Require trusted proxy config in deployments, add proxy-to-app TLS guidance and live checks |
| Refresh token reuse | Stolen refresh token extends session | Opaque token hash storage, token family tracking, reuse detection | State-machine doc for lost-response retry; FAPI2 default no routine rotation |
| CSRF | Browser performs unwanted state-changing request | CSRF cookie/header check, SameSite cookies | Extend CSRF tests across all admin/profile mutation endpoints |
| XSS session theft | Script steals session credential | Session id only in HTTPOnly cookie; login JSON omits `session_id` | Frontend CSP and template audit |
| Key compromise | Signing key leak enables token forgery | Keyset validation, prepublished/active/grace/retired JWKS states, keyctl lifecycle, optional external KMS/HSM signer backend | Emergency rotation runbook and rehearsal evidence |
| Valkey outage | Replay/rate/session state unavailable | Sensitive paths fail with server errors instead of weakening controls | HA guidance, chaos tests, timeout SLOs |
| PostgreSQL outage | Durable state unavailable | Protocol endpoints return server errors | HA guidance, backup/restore tests, migration rollback plan |
| Metadata overclaim | Clients rely on unsupported security behavior | Discovery generated from runtime state for signing algs | Profile-aware metadata tests and conformance records |

## Review Triggers

Update this threat model when:

- a new profile is added or advertised
- discovery metadata changes
- token format, `cnf`, or signing algorithms change
- reverse proxy or mTLS deployment topology changes
- refresh token rotation semantics change
- DCR, RAR, Device Grant, Token Exchange, federation, or SCIM is added
- production incident, conformance failure, or security report reveals a new class
