# OAuth, OAuth 2.1, OIDC, and FAPI Best-Practice Matrix — 10/10 Revision

Last reviewed: 2026-06-30.

## Scope

This document is a best-practice control matrix for Nazo Auth Server. It is
broader and stricter than a feature checklist: the goal is to define the safest
server-side OAuth/OIDC/FAPI profile this project should implement and advertise,
while keeping interoperability exceptions explicit, narrow, and testable.

The matrix follows these source families:

- RFC 9700, OAuth 2.0 Security Best Current Practice:
  <https://www.rfc-editor.org/info/rfc9700/>
- OAuth 2.1 draft `draft-ietf-oauth-v2-1-15`:
  <https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/>
- FAPI 2.0 Security Profile Final:
  <https://openid.net/specs/fapi-security-profile-2_0-final.html>
- FAPI 2.0 Message Signing Final:
  <https://openid.net/specs/fapi-message-signing-2_0-final.html>
- OpenID Connect specifications:
  <https://openid.net/specs/>
- RFC Editor records for published OAuth-related RFCs:
  <https://www.rfc-editor.org/>
- RFC 8725, JSON Web Token Best Current Practices:
  <https://www.rfc-editor.org/info/rfc8725/>
- RFC 9325 / BCP 195, Recommendations for Secure Use of TLS and DTLS:
  <https://www.rfc-editor.org/info/rfc9325/>
- OAuth 2.0 for Browser-Based Applications draft:
  <https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/>

The decision rule is deliberately conservative: standards conformance never
justifies weakening a protocol security boundary. If a conformance suite and a
core sender-constraint, issuer, audience, redirect, replay, key, or client-auth
guarantee appear to conflict, the implementation must preserve the security
guarantee and root-cause the test/profile mismatch.

## 10/10 Acceptance Bar

This matrix is considered complete only if it satisfies all of the following
conditions:

1. Every public capability claim is tied to a runtime-enforced profile and
   generated metadata, not to documentation intent.
2. Each OAuth/OIDC/FAPI capability is classified as Required, Recommended,
   Compatibility-only, Forbidden, Deferred, or External before it is advertised.
3. FAPI 2.0 Security Profile, FAPI 2.0 Message Signing, OAuth 2.1-aligned
   defaults, and project-specific hardening are not conflated.
4. Every sender-constrained-token, issuer, audience, redirect, replay, key,
   JWT, PAR/JAR/JARM, DPoP, mTLS, refresh-token, consent, and metadata rule has
   negative tests, not only happy-path tests.
5. Compatibility exceptions are per-client and per-profile, are never global
   defaults, and cannot apply to FAPI or sender-constrained clients.
6. Deferred standards are invisible in discovery metadata until their full
   security model, state model, policy model, and conformance/negative tests
   exist.
7. Implementation evidence and conformance evidence are treated as separate:
   green conformance tests do not replace local adversarial tests.

## Target Profiles

| Profile | Purpose | Default posture | Advertising rule |
| --- | --- | --- | --- |
| Baseline secure OAuth/OIDC | General self-hosted authorization server profile for normal web, native, and API clients. | OAuth 2.1-style authorization code + PKCE, no implicit/password grants, exact redirect binding, truthful metadata, refresh-token rotation, optional sender-constrained tokens. | Advertise only implemented grant types, auth methods, response modes, PAR/JAR/RAR, mTLS, DPoP, and logout capabilities. |
| High-value API profile | Default security target for sensitive resource access. | PAR, S256 PKCE, confidential clients where possible, DPoP or mTLS sender-constrained access tokens, resource/audience binding, short authorization-code lifetime, strict JWT/JWKS policy, and no browser token leakage. | Use FAPI2-style metadata and enforcement only when the runtime profile actually enforces it. |
| FAPI 2.0 Security Profile | OIDF FAPI 2.0 Security Profile Final. | Confidential clients only, authenticated PAR, S256 PKCE, `code` response type, `redirect_uri` in PAR, sender-constrained access tokens via DPoP or mTLS, authorization-code lifetime <= 60 seconds, PAR `request_uri` `expires_in` < 600 seconds, issuer identification, strict JWT/JWKS policy, and DPoP nonce support. Requiring DPoP nonce is project hardening, not a base FAPI claim. | Advertise FAPI behavior only under the FAPI runtime profile and after conformance tests plus local negative tests remain green. |
| FAPI 2.0 Message Signing | FAPI message-signing options for signed authorization requests, signed authorization responses, and signed or nested encrypted introspection responses. | Signed request object at PAR, JARM where selected, and RFC 9701 signed/nested encrypted introspection where the introspection profile is selected; no fallback to unsigned response after signing failure. | Advertise each message-signing option independently. Introspection JWT response metadata appears only under the signed-introspection runtime profile. |
| Compatibility profile | Narrow support for legacy clients that cannot satisfy all modern controls. | Explicit per-client exceptions only; never for sender-constrained or FAPI clients. | Compatibility capabilities must not leak into high-security metadata. |

## Control Status

| Status | Meaning |
| --- | --- |
| Required | Must exist and remain enforced for the target profile. |
| Recommended | Should be enabled for high-value deployments; safe to keep optional in baseline only when metadata and policy are truthful. |
| Compatibility-only | Allowed only through explicit per-client/profile exception and must not weaken secure defaults. |
| Forbidden | Must not be implemented or advertised for this project profile because it is obsolete, unsafe, or contradicts the security model. |
| Deferred | Potentially valid standard, but not implemented until product scope, threat model, metadata, and tests exist. |
| External | Primarily deployment, client, or resource-server responsibility; document and test integration boundaries where possible. |

## Best-Practice Control Matrix

| Control area | Best-practice requirement | Source basis | Current project posture | Evidence | Gap or action |
| --- | --- | --- | --- | --- | --- |
| Grant types | Support authorization code, refresh token, client credentials, the bounded RFC 7523 JWT bearer grant, bounded RFC 8693 Token Exchange, and RFC 8628 Device Authorization Grant only when `ENABLE_DEVICE_AUTHORIZATION_GRANT=true` and the client registration includes `urn:ietf:params:oauth:grant-type:device_code`. Do not support implicit or resource owner password grants. CIBA remains absent; Dynamic Client Registration is a separate default-closed client provisioning surface. | OAuth 2.1 draft, RFC 7523, RFC 8628, RFC 8693, RFC 9700, FAPI2 | Required for current profile; device grant is optional and default-closed. | `src/http/token/dispatch.rs`, `src/http/token/device.rs`, `src/http/token/token_exchange.rs`, `src/http/authorization/request.rs`, token dispatch/device/token-exchange tests | Keep discovery metadata limited to implemented grants, runtime feature gates, and per-client grant allowlists. |
| Authorization response type | `code` only for user authorization. Do not support front-channel access-token or ID-token issuance for the secure default profile. | OAuth 2.1 draft, RFC 9700, FAPI2 | Required. | Authorization request validation and OIDF plans | Do not add token/id_token hybrid or implicit modes without a separate security review and metadata isolation. |
| PKCE | Require S256 for every authorization-code flow. Plain PKCE and omitted PKCE are not acceptable secure defaults. FAPI clients must use S256 and generate the challenge per authorization request. | RFC 7636, OAuth 2.1 draft, RFC 9700, FAPI2 | Required by default; legacy no-PKCE exception exists only for explicitly registered confidential clients and is forbidden for public, sender-constrained, high-value, and FAPI clients. | PKCE tests under `tests/in_source/src/http/token/tests/authorization_code/pkce.rs` | Keep compatibility exception narrow, per-client, and unadvertised as a modern capability. |
| Redirect URI binding | Require exact registered redirect URI matching except RFC 8252 loopback port variance for native apps. Reject unsafe schemes, ambiguous redirect forms, open redirectors, fragments, and unencrypted redirect URIs except native loopback. | RFC 6749, RFC 8252, RFC 9700, FAPI2 | Required. | Redirect/PKCE support tests and admin client metadata tests | Native OS app-claiming is external; server enforces registration policy only. |
| State and CSRF | Preserve state and use single-use server-side authorization/session state for browser transitions. | RFC 6749, RFC 9700, OIDC Core | Required. | Authorization request and session tests | Continue fail-closed behavior on Valkey state failures. |
| OIDC nonce | If an OIDC authorization request contains `nonce`, include the same nonce in the ID Token and preserve case-sensitive equality. For FAPI/OIDC interoperability, support nonce values up to 64 characters and reject or cap longer values consistently. | OIDC Core, FAPI2, RFC 9700 | Required for OIDC profile. | OIDC request and token tests | Keep nonce length and parsing limits enforced before persistence. |
| OIDC reauthentication and auth context | Support `max_age` and `prompt=login` by forcing active reauthentication when required. When `max_age` is used or `auth_time` is requested as an Essential Claim, include `auth_time`. Do not emit `acr`/`amr` values that are not backed by actual authentication evidence. | OIDC Core, RFC 9700, FAPI2 | Required for OIDC profile where advertised. | OIDC request and token tests | Add negative tests for stale sessions, unsupported essential claims, fake `acr`, and `prompt=none` failure cases. |
| PAR | Support PAR in baseline; require authenticated PAR for FAPI/high-value profile. PAR payload must be single-use, short-lived, bound to client/profile, free of client secrets, and must include `redirect_uri` in FAPI. FAPI authorization endpoint must reject non-PAR authorization requests. | RFC 9126, FAPI2 | Required for FAPI, recommended for high-value baseline clients. | `src/http/authorization/par.rs`, PAR tests, OIDF FAPI plans | Keep request URI consumption exact and one-time; enforce PAR `request_uri` `expires_in` < 600 seconds in FAPI. |
| FAPI authorization endpoint invariants | In FAPI authorization-code flow, accept only `response_type=code`, require S256 PKCE, return authorization response `iss`, reject reused authorization codes, issue authorization codes with lifetime <= 60 seconds, require authorization responses over encrypted channels except native loopback, and avoid HTTP 307 redirects for credential-bearing requests; prefer 303 when redirecting after credential submission. | FAPI2, RFC 9207, RFC 8252, RFC 9700 | Required for FAPI profile. | Authorization, PKCE, redirect, issuer, and OIDF conformance tests | Add explicit tests for code lifetime, non-PAR rejection, missing PAR `redirect_uri`, 307 rejection, 303 preference path, and authorization endpoint receiving only `client_id` + `request_uri` from FAPI clients. |
| JAR | Accept signed request objects where enabled; require signed JAR for the FAPI Message Signing authorization-request option. Validate issuer/client, audience, expiry, not-before, signature, alg allowlist, key status, and parameter conflict rules. | RFC 9101, FAPI2 Message Signing, RFC 8725 | Required for FAPI message-signing authorization-request option; optional in baseline. | `src/http/authorization/jar.rs`, JAR/PAR tests, OIDF plans | External `request_uri` by-reference fetching is deferred because it needs SSRF, cache, lifetime, trust, and content-type controls. |
| Request object replay | Reject signed request-object replay when `jti` is supplied; allow stricter deployments to require `jti`. | RFC 9101, FAPI2 hardening | Recommended; configurable strict policy exists. | `src/http/authorization/jar.rs`, JAR validation and replay cache tests | For high-value production, prefer requiring signed request-object `jti`. |
| JARM / protected authorization response | Support signed authorization responses when the FAPI Message Signing response option or client/profile policy selects it. When per-client JWE metadata is registered, sign first and encrypt as compact JWE using `RSA-OAEP-256` and `A256GCM`. Never fall back to an unsigned/plain query response after policy lookup, signing, or encryption failure. | JARM, FAPI2 Message Signing, RFC 8725 | Required only when advertised by active profile/request; not required by the base FAPI 2.0 Security Profile. | Authorization response JWT/JWE tests and OIDF signed-JARM plans | Metadata must distinguish unsigned code response, signed response, and encrypted response support. OIDF has no encrypted-JARM OP module at the recorded suite snapshot. |
| Resource indicators | Validate `resource` as absolute URI without fragment, preserve multiple resources, bind authorization/PAR/token/refresh flows, and narrow rather than expand resource sets. | RFC 8707, RFC 9700, FAPI2 | Required. | Resource/audience tests across authorization, PAR, token forms, authorization code, refresh, and resource endpoint | Keep duplicate and fragment rejection at input boundaries. |
| Audience binding | Every access token must carry the intended resource audience. Resource servers must reject wrong audience. | RFC 8707, RFC 9068, RFC 9700, FAPI2 | Required. | JWT token claims and resource-server verifier tests | Do not issue broad default audience tokens for clients that requested specific resources. |
| RAR | Accept `authorization_details` only behind explicit feature flag and type allowlist. Bind details through consent, code, token, and resource-server verification. | RFC 9396, FAPI2 ecosystem practice | Recommended for typed high-value permissions; profile-scoped. | Authorization-details domain tests, token-claim tests, resource-server tests | Do not advertise generic arbitrary RAR support. New detail types require parser, consent, policy, and verifier tests. |
| Scope handling | Treat scopes as delegated privilege, not UI text. Reject unknown or unauthorized scopes and prevent silent privilege expansion. | RFC 6749, RFC 9700, OIDC Core | Required. | Authorization/token tests, prompt=none tests, and grant persistence | Continue binding granted scopes, resource indicators, authorization details, and refresh-token state. |
| Consent reuse | Silent consent reuse must not expand scope, resource, audience, or authorization details. | RFC 9700, OIDC Core, FAPI2 | Required. | Consent and prompt=none tests; grant resource binding migration `20260701000100_user_grant_resource_indicators` | High-risk RAR should require exact stored-detail matching. |
| Client authentication | Public clients use `none` with PKCE. Confidential clients authenticate. FAPI clients are confidential and use `private_key_jwt` or mTLS only. Client secret methods are baseline compatibility and must not satisfy FAPI/high-value policy. | RFC 6749, RFC 7523, RFC 8705, RFC 9700, FAPI2 | Required. | `src/http/token/client_auth.rs`, token dispatch tests, OIDF FAPI plans | Keep per-client auth method allowlists, reject method confusion, and do not advertise methods unsupported by active profile. |
| `private_key_jwt` | Validate signature, `iss`/`sub`/client binding, `aud` exactly equal to AS issuer identifier as a string for FAPI, expiry, `iat`/`nbf` clock skew, `jti`, key status, alg allowlist, and replay. | RFC 7523, RFC 9700, FAPI2, RFC 8725 | Required for JWT client auth. | Client assertion tests | Endpoint audience and array audience are explicit per-client compatibility exceptions; clock-skew tests accept small future values and reject values beyond 60 seconds. |
| mTLS client auth | Support `tls_client_auth` and `self_signed_tls_client_auth` with fail-closed certificate metadata validation. | RFC 8705, FAPI2 | Required where mTLS is advertised. | mTLS support tests and OIDF plans | TLS termination and certificate forwarding are deployment boundaries; trusted proxy CIDRs must gate certificate headers. |
| Sender-constrained tokens | Prefer DPoP or mTLS for high-value access tokens; require one for FAPI profile. Reject bearer use of sender-constrained tokens. Access tokens must carry `cnf` data appropriate to the selected proof mechanism. | RFC 8705, RFC 9449, RFC 9700, FAPI2 | Required for FAPI; recommended for high-value clients. | DPoP/mTLS/resource tests and OIDF plans | Do not relax sender binding merely to satisfy a conformance shortcut. For FAPI, treat refresh-token behavior according to profile and sender-constraint semantics rather than generic bearer rotation assumptions. |
| DPoP proof validation | Validate proof type, alg, signature, embedded JWK thumbprint, `htu`, `htm`, `iat`, `jti`, optional `ath`, nonce if issued/required, authorization-code-to-DPoP-key binding where applicable, and replay. FAPI clients must support server-provided nonce; requiring nonce for all FAPI DPoP requests is project hardening and must be documented as such. | RFC 9449, RFC 9700, FAPI2 | Required where DPoP is accepted; nonce support required for FAPI DPoP clients; nonce enforcement is profile/project policy. | `src/support/dpop.rs`, DPoP support tests, resource-server DPoP tests | Clustered AS/RS deployments need shared nonce/replay state or deterministic routing. |
| mTLS sender constraint | Bind token `cnf.x5t#S256` to verified client certificate thumbprint. | RFC 8705, RFC 9700, FAPI2 | Required where mTLS-bound tokens are issued. | FAPI resource tests and mTLS tests | Resource servers must only trust certificate material from the local TLS layer or trusted proxy boundary. |
| Access-token format | Current profile uses RFC 9068-style JWT access tokens with issuer, subject/client, audience, expiry, scope, optional `authorization_details`, and optional `cnf`. Opaque access tokens plus authenticated introspection are also valid high-security strategies; do not imply JWT access tokens are universally required by OAuth/FAPI. | RFC 9068, RFC 7662, RFC 9700, RFC 9701 | Required for current JWT profile; opaque/introspection remains a valid alternative profile if implemented. | Token claim tests and resource-server verifier tests | Keep sensitive internal state out of JWT claims. If opaque tokens are introduced, add RFC 7662/RFC 9701 profile, RS authz, caching, revocation, and signed-introspection tests. |
| Access-token transport | Reject ambiguous or unsafe token transport at protected resources. FAPI resource servers must not accept access tokens in query parameters and should accept only Authorization-header bearer/DPoP forms appropriate to the token type. | RFC 6750, RFC 9700, RFC 9449, FAPI2 | Required. | FAPI resource tests | Prefer Authorization header; form/query token transport must remain tightly controlled and never enabled for FAPI. |
| Refresh-token handling | Baseline bearer refresh-token grants rotate and detect reuse. For FAPI confidential clients with sender-constrained tokens, avoid blindly applying generic rotation semantics where the active profile expects stable sender-constrained refresh tokens; any lost-response retry must be a bounded state-machine rule, not a replay bypass. | RFC 9700, FAPI2 | Required/profile-scoped. | `src/http/token/refresh.rs`, `src/http/token/issue/refresh_persistence.rs`, refresh rotation/reuse/DPoP/mTLS tests, and refresh-token rotation docs | Clearly separate bearer-baseline rotation from FAPI sender-constrained refresh-token behavior in policy, metadata, and tests. |
| Refresh-token audience narrowing | Refresh requests may narrow, not expand, the original audience/resource set. | RFC 8707, RFC 9700 | Required. | Refresh audience tests and migration `20260630000100_refresh_token_audience_binding` | Keep audience stored as refresh-token state, not reconstructed from client input. |
| Revocation | Support authenticated token revocation and avoid leaking token validity. | RFC 7009, RFC 9700 | Required. | Revocation endpoint tests | Keep response shape privacy-preserving. |
| Introspection | Support authenticated JSON introspection for resource servers/admin clients. Do not leak token validity to unauthenticated callers. RFC 9701 signed and nested encrypted introspection is profile-gated and content-negotiated. | RFC 7662, RFC 9700, RFC 9701 | Required for current profile; JWT response is optional/profile-scoped. | Introspection tests | JWT introspection must bind issuer, authenticated RS audience, key selection, content negotiation, JWE metadata, and must avoid top-level access-token claim confusion. |
| Protected resource metadata | Publish protected resource metadata and link AS metadata to protected resource identifier. | RFC 9728 | Required for current resource profile. | Well-known tests and FAPI resource tests | Actual external APIs must publish matching identifiers or use the verifier consistently. |
| Discovery metadata truth | Metadata must be generated from runtime profile, settings, client policy, endpoint availability, and key state; never advertise disabled endpoints, grant types, response types, response modes, auth methods, signing/encryption algs, PAR/JAR/RAR/JARM, DPoP, mTLS, logout, introspection signing, or profiles that are not enforced. | RFC 8414, OIDC Discovery, RFC 9700, FAPI2 | Required. | `src/http/well_known.rs`, well-known tests, OIDF config plan | This is a permanent invariant for every feature addition. Metadata tests must include negative cases for disabled features and missing usable keys. |
| Issuer identification | Include authorization response issuer support to prevent mix-up. | RFC 9207, RFC 9700 | Required. | Authorization response tests and OIDF evidence | Preserve correct JARM interaction. |
| JWKS and signing keys | Publish only valid active/previous public keys; rotate with prepublish, active, grace, and retired states. Serve JWKS only over TLS, avoid remote JOSE key headers such as `x5u`/`jku`, avoid duplicate `kid`; if duplicate `kid` exists for interoperability, select keys using `kty`/`use`/`alg`/`crv` in addition to `kid`. | OIDC Discovery, RFC 9068, FAPI2, RFC 8725 | Required. | Keyset tests and keyctl tests | External-command signer integrations must preserve key lifecycle semantics. Add duplicate-`kid` and wrong-alg/key-use negative tests. |
| Signing algorithms and JWT BCP | Advertise only algorithms backed by usable keys and accepted validators. JWT processing must follow RFC 8725: explicit alg allowlists, no algorithm confusion, no `none`, correct key/alg binding, and full cryptographic validation. FAPI JWTs use `PS256`, `ES256`, or `EdDSA` with Ed25519; RSA keys must be at least 2048 bits; non-user-handled credentials must have at least 128 bits of entropy. | OIDC, JAR, JARM, DPoP, FAPI2, RFC 8725 | Required. | Well-known, client assertion, DPoP, keyset tests | Do not list algorithms for compatibility unless code can actually verify or sign them. Add alg-confusion, wrong-key-type, `none`, weak-key, and low-entropy tests. |
| ID Token issuance and validation | ID Tokens must contain and validate `iss`, `sub`, `aud`, `exp`, `iat`, signature, alg, key, and nonce where requested. If `azp` is present, it must bind to the intended client according to the active extension/profile. Do not issue ID Tokens in front-channel flows for the secure default profile. | OIDC Core, RFC 8725, RFC 9700 | Required for OIDC profile. | OIDC request and token tests | Add negative tests for wrong issuer, wrong audience, expired token, missing nonce, wrong nonce, wrong `azp`, unsupported alg, wrong `kid`, and token substitution. |
| OIDC claims parameter | If `claims` parameter is supported, gate it by profile/client policy, support only allowlisted claims, honor Essential Claims only when actually satisfiable, and preserve consent/privacy boundaries. If unsupported, reject or ignore according to OIDC-compatible policy and do not advertise broad claims support. | OIDC Core, RFC 9700 | Recommended/profile-scoped. | OIDC claim tests | Add tests for unsupported essential claims, unauthorized claim escalation, and `acr` conflict with `acr_values`. |
| Offline access | Issue refresh tokens for OIDC `offline_access` only under explicit client policy and consent/risk rules. Do not treat `openid` alone as permission to issue long-lived refresh tokens. | OIDC Core, RFC 9700 | Recommended/profile-scoped. | Refresh and OIDC consent tests | Add tests for offline access consent, denial, scope narrowing, revocation, and sender constraint where applicable. |
| Pairwise subject | Support pairwise subjects only with configured secret and valid sector handling. | OIDC Core | Recommended for privacy-sensitive OIDC clients. | Sector identifier and admin client tests | Sector identifier fetching must remain fail-closed and SSRF-aware. |
| UserInfo | Require a valid access token with `openid` scope and correct audience policy. Preserve sender-constrained-token validation and return only claims granted by scope/claims/consent policy. Default to JSON; use per-client asymmetric JWS and/or compact JWE only when validated metadata selects it. | OIDC Core, OIDC Registration, RFC 9700, RFC 8725 | Required for OIDC profile; response protection is optional per client. | UserInfo JSON/JWS/JWE, claim-minimization, wrong-key, and fail-closed tests; OIDF signed-UserInfo plan | Discovery and registration metadata must match the implemented allowlists. No signing/encryption failure may downgrade to JSON. |
| RP-Initiated Logout | Validate `id_token_hint`, `client_id`, and exact post-logout redirect URI. | OIDC RP-Initiated Logout | Required where advertised. | `src/http/profile/oidc_logout.rs` and OIDC logout tests | Browser UX is product scope; redirect validation is protocol scope. |
| Back-Channel Logout | Generate signed logout tokens, persist delivery in a PostgreSQL outbox before clearing the OP session, and retry failed deliveries within the logout token TTL. | OIDC Back-Channel Logout | Required where advertised/profile-scoped. | `src/http/profile/oidc_logout.rs`, migration `20260703000100_backchannel_logout_outbox`, OIDC logout tests, and discovery tests | Retry is bounded by token expiry; expired or repeatedly failing deliveries move to a terminal failure state instead of being silently dropped. |
| Browser-based clients / SPA / BFF | Prefer BFF or same-site session architecture for first-party browser applications where possible. If pure browser-based clients are supported, require authorization code + PKCE, no implicit, no access token in authorization response, no long-lived bearer tokens in browser storage, strict redirect/origin policy, refresh-token rotation or sender-constrained refresh tokens, and minimal CORS. | OAuth browser-based apps draft, OAuth 2.1 draft, RFC 9700 | Recommended/profile-scoped. | Browser client and CORS tests | Add tests that block implicit, token-in-fragment, overly broad CORS, refresh-token reuse, and silent privilege expansion from browser clients. |
| CORS | Scope CORS to browser-facing endpoints only and expose only required headers such as DPoP nonce. Do not support CORS for the authorization endpoint; clients must redirect the user agent instead of XHR/fetching the authorization endpoint. | RFC 9700, FAPI2, browser security practice | Required. | CORS tests, including authorization endpoint preflight denial | Do not enable broad credentialed CORS for backchannel endpoints. |
| Cookies and sessions | Same-origin secure cookies, CSRF protection for browser APIs, and server-side session invalidation. | RFC 9700, browser security practice | Required for local identity/admin surface. | Session, CSRF, profile tests | Session cookies are product identity surface, separate from OAuth tokens. |
| Rate limiting | Rate-limit credential, PAR, token, DPoP nonce/replay, and user-code-like endpoints. | RFC 9700, FAPI2 threat model | Required for exposed sensitive endpoints. | Rate-limit support tests | Device Grant, if added, needs explicit polling interval and slow-down handling. |
| Error semantics | Return protocol-correct errors without leaking secret material or token existence. | RFC 6749, RFC 6750, RFC 7009, RFC 7662, RFC 9449 | Required. | Error mapping tests | Keep DPoP/mTLS errors precise enough for clients but not secret-bearing. |
| Logging | Never log client secrets, tokens, assertions, authorization codes, DPoP proofs, private keys, or raw certificates. | RFC 9700, operational security | Required. | PAR secret redaction tests and security tests | Add regression tests when new credential-bearing inputs are added. |
| TLS and HSTS | Require HTTPS in production; prefer TLS 1.3; allow TLS 1.2 only with modern BCP 195/RFC 9325 cipher suites; forbid SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Browser-facing endpoints should use HSTS to resist TLS stripping. | RFC 9700, RFC 9325, FAPI2 deployment security | External. | Deployment docs | RFC 8996/RFC 9325 are deployment requirements, not purely authorization-server implementation claims. Document trusted reverse-proxy boundaries. |
| Database and state integrity | Persist protocol facts atomically and consume one-time credentials exactly once. Authorization codes, PAR `request_uri`, request-object replay `jti`, client assertion `jti`, DPoP `jti`, nonce state, refresh-token family state, and consent state must have fail-closed storage semantics. | RFC 9700, FAPI2 attacker model | Required. | Authorization-code consumption tests, refresh tests, migrations | Keep Valkey/state-store outages fail-closed for single-use state. Add race-condition and concurrent-replay tests. |
| Multi-tenant/issuer boundary | Do not dynamically route issuer/tenant per request unless issuer metadata, keys, sessions, clients, and grants are partitioned end-to-end. | RFC 8414, OIDC Discovery, RFC 9700 | Deferred/forbidden by default. | Tenancy docs and tests | Current README must continue to describe same-origin/default issuer model. |

## Specification-to-Action Matrix

| Specification | Best-practice decision | Current status | Safe action |
| --- | --- | --- | --- |
| RFC 6749 | Treat as historical base, not the target security profile. Implement only secure subsets. | Profile-scoped | Keep authorization code, refresh, and client credentials. Do not add implicit/password. |
| RFC 6750 | Bearer support is baseline compatibility; high-value resources should use sender constraints. | Implemented/profile-scoped | Maintain bearer support but prefer DPoP/mTLS for sensitive clients. |
| RFC 7009 | Required operational hygiene. | Implemented | Keep revocation privacy-preserving and authenticated. |
| RFC 7523 | `private_key_jwt` is required for FAPI; JWT bearer authorization grant is implemented only for authenticated confidential clients asserting their own `client_id`. | Implemented/bounded | Keep third-party assertion trust deferred behind the design in `docs/features/ecosystem-onboarding.md`; arbitrary subject mapping is not a default capability. |
| RFC 7636 | Required everywhere for authorization code. | Implemented | Keep S256 mandatory; plain/no-PKCE only as narrow legacy exception. |
| RFC 7662 | Required for interoperable resource servers. | Implemented | Keep JSON introspection as the baseline response. |
| RFC 8252 | Required for native-app redirect safety. | Profile-scoped | Preserve claimed HTTPS, private-use scheme, and loopback port variance; keep client/platform claims external. |
| RFC 8414 | Required metadata truth source. | Implemented | Fail metadata tests whenever runtime profile changes. |
| RFC 8628 | Device Authorization Grant for constrained-input clients. It adds phishing, polling, and brute-force risks, so it remains default-closed. | Implemented/profile-scoped | Advertise only when `ENABLE_DEVICE_AUTHORIZATION_GRANT=true`; require client grant allowlist, user-code UX, login+CSRF approval, polling interval, `slow_down`, expiration, denial, rate limiting, Valkey state TTL, and no CORS on the device authorization endpoint. |
| RFC 8693 | Powerful but high-risk delegation/impersonation surface. | Implemented/bounded local profile | Current implementation accepts only locally issued access tokens as subject/actor tokens, issues only local access tokens, requires explicit target, downscopes scopes, validates revocation, preserves delegated actor context with `act`, and keeps external token trust, refresh-token exchange, ID-token exchange, and broader token-type matrix profiles out of the default flow. |
| RFC 8705 | Required sender-constraint option for FAPI/high-value APIs. | Profile-scoped | Keep mTLS behind verified deployment boundary and truthful metadata. |
| RFC 8707 | Required for audience/resource correctness. | Implemented | Maintain authorization/PAR/token/refresh narrowing behavior. |
| RFC 9068 | Current JWT access-token profile for resource-server verification, not a universal requirement. | Implemented/profile-scoped | Keep claims minimal and verifier strict; keep opaque-token/introspection alternative architecturally possible. |
| RFC 9101 | Required for FAPI message-signing authorization request profile. | Profile-scoped | Keep direct signed request objects; defer external `request_uri` until SSRF/cache/lifecycle controls exist. |
| RFC 9126 | Required for FAPI and recommended for high-value clients. | Implemented | Keep one-time request URI and secret redaction. |
| RFC 9207 | Required mix-up mitigation. | Implemented | Keep `iss` support and tests. |
| RFC 9396 | Recommended for typed high-value permissions, unsafe as unbounded JSON pass-through. | Profile-scoped | Keep allowlisted types and feature-gated metadata. |
| RFC 9449 | Required sender-constraint option for browser/native-friendly high-value clients. | Implemented | Keep nonce/replay validation strict. |
| RFC 9700 | Governing security baseline. | Profile-scoped | Treat as permanent audit checklist for every protocol change. |
| RFC 9701 | Required only if JWT introspection is advertised or if the FAPI Message Signing signed-introspection option is claimed. | Implemented/profile-scoped | Advertise signed/encrypted introspection only under `fapi2-message-signing-introspection`; bind `iss`, `aud`, active signing key, authenticated RS identity, `Accept: application/token-introspection+jwt`, and per-client JWE metadata. |
| RFC 9728 | Recommended for resource-server discovery and FAPI resource metadata. | Implemented | Keep protected resource identifiers aligned with JWT audiences. |
| OAuth 2.1 draft | Directional target, not final RFC; treat as work in progress until published as RFC. | Partial/aligned | Track latest draft and turn into final RFC audit when published. Do not cite draft conformance as final RFC conformance. |
| OIDC Core | Required for certified OP profile. | Implemented/profile-scoped | Keep authorization-code OP profile; do not imply implicit/hybrid support. Maintain ID Token, nonce, `auth_time`/`max_age`, `acr`/`amr`, claims, JSON/signed/encrypted UserInfo, and offline access controls as separate testable rows. |
| OIDC Discovery | Required. | Implemented | Keep discovery generated from runtime facts. |
| OIDC Dynamic Client Registration | Useful but high-risk provisioning surface. | Implemented/default-closed | Advertise only when `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`; protect public deployments with `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`; support RFC 7592 management only for DCR-created clients with hashed registration access tokens and dynamic-client audit events; software statements and remote `jwks_uri` fetching remain deferred. |
| OIDC RP-Initiated Logout | Required where advertised. | Implemented | Keep exact post-logout redirect validation. |
| OIDC Back-Channel Logout | Useful for server-side logout propagation. | Implemented/profile-scoped | Keep signed logout token, durable outbox, bounded retry, terminal failure state, and metadata truth aligned. |
| OIDC Front-Channel Logout | Browser-mediated and weaker than back-channel. | Implemented/profile-scoped/default-closed | Advertise only when `ENABLE_FRONTCHANNEL_LOGOUT=true`; keep RP metadata validation, iframe notification escaping, `iss`/`sid` behavior, and back-channel logout as the stronger path. |
| OIDC Session Management | Browser polling-based legacy-style session feature. | Implemented/profile-scoped/default-closed | Advertise only when `ENABLE_SESSION_MANAGEMENT=true`; keep `session_state` deterministic, iframe no-store, and polling status isolated from primary logout enforcement. |
| JARM | Required for FAPI message-signing authorization response option. | Implemented/profile-scoped | Keep signed response fail-closed; apply per-client nested JWE only after successful signing and never downgrade on encryption failure. |
| OIDC CIBA / FAPI-CIBA | Separate decoupled authentication product surface. | Partial/profile-scoped/default-closed | Advertise only when `ENABLE_CIBA=true`; keep poll mode, user binding, CSRF-protected decision, interval enforcement, signed backchannel authentication requests, `auth_req_id` lifecycle, FAPI-CIBA compatibility, and optional internal `CIBA_SECURITY_PROFILE=fapi2-ciba` hardening aligned with CIBA-applicable FAPI2 controls. Do not advertise an official “FAPI2-CIBA” profile. |
| OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1 | Trust-chain ecosystem feature, not external login. | Deferred/not implemented | No endpoint or configuration gate is exposed. If this becomes product scope later, implement against the 1.1 specifications with trust anchors, trust chains, metadata policy, trust marks, federation fetch/list/resolve, key rollover, and conformance evidence before advertising support. |
| OIDC Native SSO | Mobile app SSO using ID Token plus `device_secret`. | Implemented/profile-scoped/default-closed | Advertise only when `ENABLE_NATIVE_SSO=true`; bind `device_secret` to ID Token `ds_hash`/`sid`, validate refresh-family activity, and require destination clients to be explicitly scoped for `device_sso`. |
| FAPI 2.0 Security Profile Final | Highest current practical server profile for high-value API access. | Implemented/profile-scoped | Keep conformance evidence and local negative tests aligned with runtime profile. Enforce authenticated PAR, `code`, S256 PKCE, `redirect_uri` in PAR, code lifetime <= 60 seconds, PAR `expires_in` < 600 seconds, FAPI client authentication, sender constraints, issuer metadata, JWT/JWKS rules, and authorization endpoint parameter restrictions. |
| FAPI 2.0 Message Signing Final | Implement signed authorization requests, signed authorization responses, and signed or nested encrypted introspection as independent options layered on FAPI 2.0 Security Profile. | Implemented/profile-scoped | Keep each option independently gated: signed PAR request objects, JARM, and introspection JWT responses must only be advertised by the matching runtime profile. |
| FAPI 2.0 HTTP Signatures draft | Draft-level advanced message integrity. | Deferred | Track maturity; do not implement until target ecosystem needs it. |
| RFC 9865 / RFC 9967 SCIM extensions | Adjacent identity provisioning capabilities, not OAuth/OIDC/FAPI core. | Not advertised | Keep disabled capabilities explicit in SCIM docs and service provider config. |
| RFC 8725 | Governing JWT implementation BCP across ID Tokens, access-token JWTs, client assertions, request objects, JARM, DPoP proofs, and signed introspection. | Implemented/profile-scoped | Enforce explicit alg allowlists, key/alg binding, no `none`, full crypto validation, and cross-JWT confusion defenses. |
| RFC 9325 / BCP 195 | Governing TLS deployment baseline. | External/profile-scoped | Prefer TLS 1.3; allow TLS 1.2 only with modern ciphers; forbid SSL/TLS legacy versions; use HSTS for browser-facing endpoints. |
| OAuth 2.0 for Browser-Based Applications draft | Best-practice guidance for SPA/browser OAuth clients. | Profile-scoped | Prefer BFF/session architecture for first-party browser apps; if pure SPA is supported, enforce code+PKCE, no implicit, no token in authorization response, strict CORS, and safe refresh-token handling. |

## Forbidden or Compatibility-Only Capabilities

These capabilities must not become default behavior:

| Capability | Decision | Reason |
| --- | --- | --- |
| Implicit grant | Forbidden | Superseded by authorization code + PKCE; increases token exposure. |
| Resource owner password credentials grant | Forbidden | Contradicts modern delegation and phishing-resistant architecture. |
| Plain PKCE | Compatibility-only if ever needed | S256 is the secure default and FAPI requirement. |
| Authorization code without PKCE | Compatibility-only for explicitly registered confidential legacy clients | Not acceptable for public, sender-constrained, or FAPI clients. |
| Unsigned request object in FAPI message-signing profile | Forbidden | Breaks signed authorization request profile. |
| Bearer access token for FAPI clients requiring sender constraints | Forbidden | Violates FAPI sender-constraint boundary. |
| Token request resource expansion beyond authorization grant | Forbidden | Breaks resource/audience authorization binding. |
| Metadata overclaiming | Forbidden | Creates false client assumptions and security downgrade risk. |
| Dynamic issuer routing by request host/header | Forbidden by default | Requires end-to-end tenant/issuer/key/client/session partitioning. |
| Trusting mTLS certificate headers from arbitrary clients | Forbidden | Certificate forwarding is valid only across a trusted proxy boundary. |
| Logging tokens/assertions/codes/proofs/secrets | Forbidden | Credential material must not enter logs or fixtures. |
| Authorization endpoint CORS | Forbidden | Browser clients must use redirects; XHR/fetch to the authorization endpoint creates confused-deputy and leakage risks. |
| Query-parameter access tokens for FAPI resources | Forbidden | FAPI resource servers must not accept access tokens in query parameters. |
| Advertising unsupported JARM, JWE, signed UserInfo, or signed introspection algorithms | Forbidden | Cryptographic metadata overclaiming creates false client assumptions and downgrade/confusion risk; optional per-client response protection may be advertised only for implemented algorithms and enforced metadata. |
| Remote JOSE key headers such as `jku`/`x5u` for trusted key discovery | Forbidden by default | Remote key indirection creates SSRF, key-substitution, cache-poisoning, and trust-boundary risks unless a separate allowlisted trust model exists. |

## Deferred Work, Ordered by Security Value

| Priority | Work item | Why it matters | Minimum safe implementation |
| --- | --- | --- | --- |
| P1 | Dedicated OAuth 2.1 final audit | OAuth 2.1 is still a draft; final RFC may change requirements. | Requirement-by-requirement matrix after publication, discovery checks, grant/auth/PKCE/refresh tests. |
| P1 | FAPI precision regression pack | FAPI profile is not only PAR+PKCE+sender constraints; it has precise timing, redirect, JWT/JWKS, and authorization-endpoint restrictions. | Keep code lifetime, PAR lifetime, PAR `redirect_uri`, outer parameter restriction, 303 redirect, JWT skew, duplicate `kid`, client auth, sender constraint, and non-PAR rejection tests green. |
| P2 | Third-party JWT bearer assertion trust implementation | Needed only if external assertion issuers or non-client subjects become product scope. | Implement the deferred design in `docs/features/ecosystem-onboarding.md`: issuer allowlist, subject mapping, audience, expiry, `jti` replay, revocation, metadata gating, negative tests, and audit events. |
| P2 | Device Authorization Grant hardening follow-up | Useful for constrained devices but abuse-prone; baseline support is implemented behind a feature gate. | Expand product UX copy, audit events, brute-force telemetry, and full browser approval E2E around the existing `/device` flow. |
| P2 | Token Exchange hardening follow-up | Baseline local access-token exchange is implemented. | Add external issuer trust profiles, refresh-token or ID-token exchange only if needed, richer audit events, and black-box service-chain E2E coverage. |
| P2 | DCR trust-policy follow-up | Baseline RFC 7591 and RFC 7592 DCR management are implemented, but richer trust policy still expands client lifecycle authority. | Optional software statement trust, optional remote JWKS fetch policy, black-box lifecycle conformance fixtures, and no automatic high-privilege defaults. |
| P3 | Front-Channel Logout / Session Management | Interop feature, weaker than server-side logout paths. | Metadata, iframe/session behavior, browser tests, no weakening of RP-Initiated or Back-Channel Logout. |
| P3 | OIDC CIBA and FAPI CIBA | Separate decoupled authentication flow. | CIBA Core first, then FAPI constraints, user consent UX, polling/backchannel auth state. |
| P3 | OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1 | Ecosystem trust-chain feature. | Entity statements, trust anchors, trust chain resolution, metadata policy, trust marks, fetch/list/resolve endpoints, and conformance evidence. |

## Review Gate for New Standards

Every new OAuth/OIDC/FAPI feature must pass this gate before README metadata or
discovery metadata claims are updated:

1. Define the exact profile, not just the RFC name.
2. Identify whether the feature changes grant issuance, client authentication,
   redirect handling, token format, token audience, replay state, key use,
   consent, metadata, or resource-server behavior.
3. Add negative tests before positive-path expansion where the feature touches
   redirect URI, PKCE, PAR/JAR/JARM, DPoP, mTLS, audience, issuer, nonce,
   refresh tokens, or client assertions.
4. Ensure discovery metadata is generated from runtime state and does not
   advertise disabled or untested behavior. Discovery now has an explicit
   overclaim guard for profile-gated signed introspection, DCR, Device Grant,
   Token Exchange, Front-Channel Logout, Session Management, and
   UserInfo/JWE signing or encryption claims.
5. Verify that compatibility modes cannot affect FAPI/high-value profiles.
6. Update this matrix, `docs/protocol/profile-matrix.md`, README, discovery metadata tests,
   and conformance records in the same change when a public capability claim
   changes.
7. For every newly supported RFC, OIDC/FAPI profile, or standards-track
   protocol capability, search the OpenID Foundation Conformance Suite official
   production/staging plans, public source, and release notes for matching
   official tests. If matching coverage exists, update the repository OIDF
   matrix execution, workflow/config inputs, and conformance records in the same
   change. If no official coverage exists, record the negative search result and
   date. This OIDF evidence is additive and never replaces local positive,
   negative, metadata-truth, and security-boundary tests.
8. For JWT-bearing features, add RFC 8725 negative tests for alg confusion, wrong
   key type, wrong `kid`, `none`, cross-JWT substitution, expired/future claims,
   and wrong audience/issuer.
9. For FAPI features, add tests for exact FAPI profile requirements rather than
   only general OAuth behavior: authenticated PAR, S256, `redirect_uri` in PAR,
   code lifetime, `request_uri` lifetime, sender constraints, client auth method,
   authorization endpoint parameters, and browser redirect status handling.
10. For browser-facing changes, verify CORS, cookies, CSRF, HSTS/TLS, redirect
   handling, and token storage assumptions before advertising support.

## Current Bottom Line

The safe target is not "implement every OAuth-adjacent specification." The safe
target is:

- maintain OAuth 2.1-style secure defaults;
- use RFC 9700 as the baseline security rulebook;
- use FAPI 2.0 Security Profile as the high-value API target;
- implement FAPI 2.0 Message Signing only for the individual options the code
  actually enforces and tests;
- treat JWT/JWKS/TLS/browser-client requirements as first-class protocol
  controls, not deployment footnotes;
- keep deferred standards out of metadata until their full security model,
  state model, policy model, and negative tests exist.
