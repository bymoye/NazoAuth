# Ecosystem Onboarding

## Scope

The default scope keeps ecosystem onboarding features outside the
authorization-server core. The features expand the protocol attack surface and
stay out of discovery metadata until implementation, tests, and deployment
policy explicitly enable them.

## Dynamic Client Registration

### Boundary

RFC 7591 Dynamic Client Registration is implemented as a default-closed
protocol surface.

- DCR changes client creation from an administrator-controlled action into a protocol surface exposed to external callers.
- Redirect URI validation, inline JWKS, software statements, initial access tokens, and client metadata updates all become security-critical input paths.
- The admin client API remains the default explicit onboarding path.
- `/register` is mounted and `registration_endpoint` is advertised only when
  `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`.
- Public deployments should set
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`; otherwise registration is
  intentionally open for controlled test deployments only.
- `software_statement` and remote `jwks_uri` fetching are not supported by
  the baseline RFC 7591 endpoint.
- RFC 7592 Client Configuration Management is available only for clients
  created through DCR and only while `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`.
- Successful DCR registration and RFC 7592 read/update/delete operations emit
  structured `client_lifecycle` audit events without recording client secrets
  or registration access tokens.

### Implemented Enforcement

- Redirect URI validation covers unsafe schemes, fragments, wildcard-style
  inputs, loopback/native exceptions, and exact-match web redirects.
- Client metadata cannot silently enable FAPI, CIBA, admin-management powers,
  arbitrary audiences, JARM, PAR-by-policy, or high-privilege scopes.
- Inline `jwks` is validated by the same client metadata boundary used by the
  admin client API, including private-key rejection and signing-key `kid`
  requirements where the authentication method needs stable key selection.
- `software_statement` is rejected with `invalid_software_statement`.
- `jwks_uri` is rejected until a separate remote-key trust and SSRF model
  exists.
- Registration access token storage and rotation use server-side BLAKE3 hashes;
  plaintext registration access tokens are returned only in DCR management
  responses.
- Metadata truth tests proving discovery only advertises DCR when the registration endpoint is enabled and protected.

### Deferred Scope

- Initial access token issuance, per-token scope, expiry, replay prevention,
  and revocation for broad public onboarding.
- Optional `jwks_uri` fetching, cache lifetime, stale-key behavior, SSRF
  prevention, host allowlists, size limits, MIME validation, timeout policy,
  and key rotation.
- Software statement trust anchors, issuer/audience validation, expiry windows,
  replay prevention, metadata merge rules, and signed onboarding policy.
- Browser or black-box conformance fixtures that exercise the full
  registration management lifecycle against a deployed issuer.

### Required Tests

- DCR is absent from discovery by default and `/register` is not routed when disabled.
- Invalid redirect URIs are rejected.
- Weak or unsupported client authentication metadata is rejected.
- `jwks_uri` is rejected until remote fetch policy exists; if adopted later, it cannot fetch loopback, link-local, private, metadata-service, or non-HTTPS URLs unless an explicit deployment allowlist permits them.
- Duplicate `kid`, private JWK material, and stale JWKS cache behavior are covered.
- Initial access token replay and expired-token paths fail closed.
- Registered clients cannot escalate from public to confidential or from baseline to FAPI profile capabilities without policy approval.
- Dynamic client registration, read, update, and delete audit event names remain
  allowlisted and use non-secret fields only.

## Client Configuration Management

### Boundary

RFC 7592 Client Configuration Management is implemented as part of the
default-closed DCR surface.

- DCRM inherits every DCR risk and adds update/delete authority over existing clients.
- Client update is full-replacement PUT semantics, not partial PATCH. The
  client must present the current `client_id`; clients with a stored
  `client_secret` must also present the matching current secret.
- Server-managed fields are immutable from the client request:
  `registration_access_token`, `registration_client_uri`,
  `client_secret_expires_at`, and `client_id_issued_at`.
- Successful read and update responses rotate the registration access token.
  Secret-authenticated dynamic clients also receive a rotated `client_secret`
  because the server stores only keyed secret digests, never recoverable
  plaintext secrets.
- DELETE deactivates the client, clears the registration access token hash,
  revokes active refresh-token rows for the client, and removes stored user
  grants. Existing self-contained access tokens remain bounded by their normal
  expiry and resource-side revocation checks.
- Successful read, update, and delete operations emit dynamic-client audit
  events with the client id, client type, grant types, token endpoint auth
  method, and source IP hash.

### Activation Criteria

- Optional `jwks_uri` fetching, if ever supported, with SSRF and cache controls.
- Software statement trust anchors and metadata merge policy.
- Browser or black-box conformance fixtures that exercise the full
  registration management lifecycle against a deployed issuer.

## Client Onboarding Profiles

This table is the operator-facing registration contract for external clients.
The runtime must keep discovery metadata aligned with these boundaries.

| Profile | Registration fields | Client authentication | Metadata and enablement | Error semantics |
| --- | --- | --- | --- | --- |
| Baseline OIDC/OAuth client | `redirect_uris`, `response_types=["code"]`, `grant_types` limited to `authorization_code`, `refresh_token`, and `client_credentials` according to client type; `scope` limited to registered user/API scopes; optional inline `jwks` for key-based clients. | Public clients use `none` with S256 PKCE. Confidential baseline clients may use `client_secret_basic`, `client_secret_post`, `private_key_jwt`, mTLS methods, or sender-constrained token policy when registered. | `/register` and `registration_endpoint` appear only when `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`. Baseline discovery must not imply FAPI, CIBA, Device Grant, external token trust, or management APIs beyond RFC 7592 for DCR-created clients. | Metadata validation failures use RFC 7591 style `invalid_client_metadata` or `invalid_software_statement`; missing or wrong initial/registration access tokens use `invalid_token`; disabled endpoints return `404`. |
| FAPI 2.0 Security client | Register through the admin API or a policy-controlled DCR flow that sets confidential client type, PAR requirement, S256 PKCE, exact redirect URI, sender-constrained access tokens, and FAPI-compatible client authentication. | `private_key_jwt` or mTLS. Client secret methods do not satisfy FAPI. DPoP or mTLS sender constraint is required for FAPI access tokens. | FAPI metadata is profile-scoped by `AUTHORIZATION_SERVER_PROFILE`; DCR-created clients do not automatically become FAPI clients. | Non-FAPI client auth, missing PAR, missing PKCE, wrong redirect URI, unsupported sender constraint, or wrong assertion audience fail at the relevant protocol boundary instead of being downgraded. |
| FAPI 2.0 Message Signing client | Same as FAPI Security plus signed request-object, JARM, or signed/nested encrypted introspection metadata only for the selected message-signing profile. | `private_key_jwt` or mTLS, with registered signing keys and algorithm allowlists. | Message-signing discovery fields are advertised only by their matching runtime profile and usable key state. DCR cannot opt into JARM or signed introspection without policy approval. | Unsupported request-object/JARM/introspection metadata is rejected or ignored according to the endpoint contract; a client cannot force metadata advertisement by registration alone. |
| CIBA client | Register backchannel authentication endpoint metadata and polling capability only when CIBA is enabled for the deployment and client policy. | Confidential client authentication; FAPI-CIBA policy requires `private_key_jwt` or mTLS and sender-constrained tokens according to the selected CIBA profile. | CIBA endpoints and grant metadata are absent unless `ENABLE_CIBA=true`. The compatibility FAPI-CIBA profile remains separate from the internal `fapi2-ciba` hardening profile. | Disabled CIBA endpoints are not advertised; invalid signed backchannel requests, wrong audience, unsupported algorithms, polling violations, and expired `auth_req_id` values fail closed. |
| Device Authorization Grant client | Register `urn:ietf:params:oauth:grant-type:device_code` explicitly; do not infer device capability from public client type. | Public or confidential according to client registration; token polling still enforces the client boundary and interval policy. | `device_authorization_endpoint` and `device_code` grant metadata appear only when `ENABLE_DEVICE_AUTHORIZATION_GRANT=true`. | Pending requests return `authorization_pending`, excessive polling returns `slow_down`, denied or expired requests fail without revealing extra user-code state. |
| DCR / DCRM client lifecycle | DCR accepts bounded RFC 7591 metadata; DCRM uses `registration_client_uri`, `registration_access_token`, full replacement `PUT`, and `DELETE` deactivation for DCR-created clients only. | Registration uses optional initial access token. DCRM uses bearer registration access token and, for secret clients, matching current `client_secret` in update payloads. | DCR/DCRM routes exist only under the dynamic-registration feature gate. RFC 7592 management credentials rotate on successful read and update. | Server-managed fields are immutable in `PUT`; stale or missing registration tokens return `invalid_token`; update/deletion failures do not leak whether an inactive or unknown client id exists. |

## Device Authorization Grant

### Boundary

The Device Authorization Grant is implemented but outside the default scope. It
fits CLI, TV, appliance, and constrained-input clients only when
`ENABLE_DEVICE_AUTHORIZATION_GRANT=true` and the client registration explicitly
allows `urn:ietf:params:oauth:grant-type:device_code`.

### Activation Criteria

- User code entropy, display format, expiry, brute-force limits, and replay behavior.
- Device code entropy, storage, expiry, and one-time completion.
- Polling interval enforcement, `slow_down`, expired token behavior, and client rate limits.
- Binding between the browser approval session, displayed client identity, requested scopes, `authorization_details`, resources, and the device code.
- Phishing-resistant UI language and audit events for approved, denied, expired, and rate-limited flows.
- Profile matrix changes for public versus confidential device clients.
- Discovery metadata must remain absent unless `ENABLE_DEVICE_AUTHORIZATION_GRANT=true`.

### Required Tests

- Pending token request returns `authorization_pending`.
- Too-frequent polling returns `slow_down`.
- Expired device code and expired user code fail closed.
- Wrong user code cannot reveal whether a real code exists beyond generic errors.
- Approved code issues tokens only once and preserves scope, audience, DPoP/mTLS sender constraints where applicable, and consent binding.

## Token Exchange

### Boundary

RFC 8693 Token Exchange is implemented for a bounded local profile: a
confidential client registered for
`urn:ietf:params:oauth:grant-type:token-exchange` can exchange a locally issued
access token for a new locally issued access token. The request must include a
valid `subject_token`, `subject_token_type`, and an explicit `resource` or
`audience`. `actor_token` is optional and, when present, must also be a locally
issued access token for the authenticated client.

The implementation does not trust external issuers, does not exchange refresh
tokens or ID tokens, and does not issue refresh tokens from token exchange.

### Activation Criteria

- External subject-token or actor-token issuer trust.
- Refresh-token and ID-token exchange profiles.
- `authorization_details` propagation beyond empty access-token exchanges.
- Sender-constrained actor-token proof composition.
- Product audit events that distinguish the requesting client, subject token client, subject, actor, audience, and policy decision.

### Required Tests

- Exchange cannot mint a token for a target not allowed to the requesting client.
- Requested scopes must be equal to or narrower than both the subject token and client registration.
- Expired, revoked, wrong-issuer, wrong-tenant, unauthorized-subject, and sender-constraint mismatch tokens are rejected.
- Actor tokens are validated and serialized through the `act` claim when delegation is requested.

## Third-Party JWT Bearer Assertion Trust

The implemented RFC 7523 JWT bearer grant is intentionally client-bound: the
assertion `iss` and `sub` must equal the authenticated client id, `aud` must
equal the issuer, the key must come from that client's registered JWKS, and
`jti` replay state is stored per client. It is not a third-party subject-trust
surface.

Third-party JWT bearer assertion trust is deferred until a concrete product
need requires external assertion issuers or non-client subjects. When it is
implemented, it must be a separate, explicit profile rather than a relaxation
of the existing client-bound grant.

### Required Trust Model

| Boundary | Required design |
| --- | --- |
| Issuer allowlist | Store trusted issuer identifiers with tenant/profile scope, accepted algorithms, JWKS source, key cache TTL, and operational owner. Unknown issuers fail before key lookup. |
| Subject mapping | Map external `iss` + `sub` to an internal subject or service principal through an explicit mapping rule. Do not synthesize local users from arbitrary JWT subjects. |
| Audience | Require `aud` to name this issuer or a dedicated token endpoint audience. Endpoint aliases, array audiences, or resource-server audiences require separate compatibility switches and negative tests. |
| Time and replay | Enforce bounded `exp`, optional `nbf`/`iat` clock skew, non-empty bounded `jti`, and replay keys scoped by tenant, issuer, and `jti`. Replay store failure is fail-closed. |
| Revocation | Support issuer-level disablement, subject-mapping disablement, and emergency `jti` or assertion-family revocation where the upstream issuer cannot be trusted to revoke quickly enough. |
| Audit | Emit audit events that distinguish requesting client, assertion issuer, external subject, mapped local subject, audience, grant result, and policy decision without logging the raw assertion. |
| Metadata | Do not advertise third-party assertion trust in discovery until issuer allowlists, mapping, replay, revocation, audit, and negative tests are present. |
| Negative tests | Cover unknown issuer, wrong audience, wrong subject mapping, expired/future claims, replayed `jti`, disabled mapping, disallowed alg/key, missing `kid`, private-key leakage in JWKS, and cross-tenant issuer reuse. |

### Non-Goals

- External JWT bearer assertions do not bypass client authentication.
- External assertions do not grant FAPI, CIBA, admin, or high-value scopes by
  themselves.
- External assertions do not enable Token Exchange for external subject tokens;
  that requires a separate RFC 8693 external-token profile.

## Example Client Matrix

Examples and fixtures are protocol contracts. Each example includes at least one
negative path.

| Client type | Primary profile | Required fixture coverage |
| --- | --- | --- |
| Backend web | OIDC authorization code + PKCE | exact redirect URI, nonce, state, refresh policy, logout redirect |
| SPA | public authorization code + PKCE | no client secret, S256 only, CORS and redirect boundary |
| Native app | public authorization code + PKCE | loopback redirect port exception, custom scheme rejection rules |
| Machine-to-machine | client credentials | confidential client auth, no `openid`, audience binding |
| DPoP client | authorization code or client credentials | proof `jti`, `ath`, nonce challenge, sender-constrained token |
| `private_key_jwt` client | confidential profiles | assertion `aud`, `exp`, `iat`, `jti`, replay, key rotation |

Fixtures belong under `docs/conformance` or `examples` and must stay aligned with discovery metadata and the profile matrix.
