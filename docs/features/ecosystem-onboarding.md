# Ecosystem Onboarding

## Scope

Ecosystem onboarding separates active server support from client authority.
Stable protocol handlers may coexist, while provisioning surfaces, client
grant allowlists, metadata, and versioned client policy remain explicit trust
boundaries.

## Dynamic Client Registration

### Boundary

RFC 7591 Dynamic Client Registration is implemented as a
prerequisite-gated protocol surface.

- DCR changes client creation from an administrator-controlled action into a protocol surface exposed to external callers.
- Redirect URI validation, inline JWKS, software statements, initial access tokens, and client metadata updates all become security-critical input paths.
- The admin client API remains the default explicit onboarding path.
- `/register` is mounted and `registration_endpoint` is advertised only when
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` is non-empty. RFC 7591
  deliberately leaves issuance of this token to the deployment.
- `software_statement` is not supported because no statement issuer or trust
  policy is configured. Remote `jwks_uri` is supported only through the shared
  HTTPS remote-document resolver with DNS rebinding, address-class,
  redirect, media-type, size, timeout, and cache controls.
- RFC 7592 Client Configuration Management is available only for clients
  created through DCR while the DCR runtime module is active.
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
- `jwks_uri` and inline `jwks` are mutually exclusive. A remote key set is
  resolved before registration is committed, and retrieval failures do not
  create a partial client.
- Registration access token storage and rotation use server-side BLAKE3 hashes;
  plaintext registration access tokens are returned only in DCR management
  responses.
- Metadata truth tests proving discovery only advertises DCR when the registration endpoint is enabled and protected.

### Unsupported or separately scoped behavior

- A public protocol for issuing initial access tokens is not implemented.
  RFC 7591 explicitly leaves issuance and validation policy out of scope; the
  production applicant/approver workflow is a separate authenticated product
  control plane, not a private extension of `/register`.
- Software statement trust anchors, issuer/audience validation, expiry windows,
  replay prevention, metadata merge rules, and signed onboarding policy.
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
  automatic and explicit registration are separate trust protocols and are not
  partially emulated by the product approval endpoints.

### Required Tests

- DCR is absent from discovery by default and `/register` is not routed when disabled.
- Invalid redirect URIs are rejected.
- Weak or unsupported client authentication metadata is rejected.
- `jwks_uri` cannot fetch loopback, link-local, private, metadata-service, or
  non-HTTPS targets unless a deployment explicitly allowlists the exact private
  HTTPS origin. Redirects and DNS rebinding cannot escape the resolved policy.
- Duplicate `kid`, private JWK material, and stale JWKS cache behavior are covered.
- Missing or incorrect deployment initial access tokens fail closed. This
  endpoint does not claim token issuance, expiry, or replay semantics that RFC
  7591 leaves to the deployment.
- Registered clients cannot escalate from public to confidential or from baseline to FAPI profile capabilities without policy approval.
- Dynamic client registration, read, update, and delete audit event names remain
  allowlisted and use non-secret fields only.

## Client Configuration Management

### Boundary

RFC 7592 Client Configuration Management is implemented as part of the
initial-access-token-gated DCR surface.

- DCRM inherits every DCR risk and adds update/delete authority over existing clients.
- Client update is full-replacement PUT semantics, not partial PATCH. The
  client must present the current `client_id`; clients with a stored
  `client_secret` must also present the matching current secret.
- Server-managed fields are immutable from the client request:
  `registration_access_token`, `registration_client_uri`,
  `client_secret_expires_at`, and `client_id_issued_at`.
- A successful read preserves the authenticated registration access token but
  rotates a secret client's `client_secret`, because only keyed digests are
  stored and old plaintext cannot be recovered. A successful full replacement
  rotates both the registration access token and the client secret.
- DELETE deactivates the client, clears the registration access token hash,
  revokes active refresh-token rows for the client, and removes stored user
  grants. Existing self-contained access tokens remain bounded by their normal
  expiry and resource-side revocation checks.
- Successful read, update, and delete operations emit dynamic-client audit
  events with the client id, client type, grant types, token endpoint auth
  method, and source IP hash.

### Separately scoped behavior

- Software statement trust anchors and metadata merge policy.
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
  automatic or explicit registration.

## Client Onboarding Profiles

This table is the operator-facing registration contract for external clients.
The runtime must keep discovery metadata aligned with these boundaries.

| Profile | Registration fields | Client authentication | Metadata and enablement | Error semantics |
| --- | --- | --- | --- | --- |
| Baseline OIDC/OAuth client | `redirect_uris`, `response_types=["code"]`, `grant_types` limited to `authorization_code`, `refresh_token`, and `client_credentials` according to client type; `scope` limited to registered user/API scopes; optional inline `jwks` for key-based clients. | Public clients use `none` with S256 PKCE. Confidential baseline clients may use `client_secret_basic`, `client_secret_post`, `private_key_jwt`, mTLS methods, or sender-constrained token policy when registered. | `/register` and `registration_endpoint` appear only when an initial access token is configured. DCR materializes the versioned baseline `security_policy`. | Metadata validation failures use RFC 7591 style `invalid_client_metadata` or `invalid_software_statement`; missing or wrong initial/registration access tokens use `invalid_token`; disabled endpoints return `404`. |
| FAPI 2.0 Security client | Register through the admin API with `security_policy.assurance=fapi2`, confidential client type, exact redirect URI, sender-constrained access tokens, and FAPI-compatible client authentication. | `private_key_jwt` or mTLS. Client secret methods do not satisfy FAPI. DPoP or mTLS sender constraint is required for FAPI access tokens. | Composable discovery advertises server support; DCR-created clients do not automatically become FAPI clients. | Non-FAPI client auth, missing PAR, missing PKCE, wrong redirect URI, unsupported sender constraint, or wrong assertion audience fail at the relevant protocol boundary instead of being downgraded. |
| FAPI 2.0 Message Signing client | Same as FAPI Security plus any compatible combination of `require_signed_authorization_request`, `require_signed_authorization_response`, and `require_signed_introspection_response`. | `private_key_jwt` or mTLS, with registered signing keys and algorithm allowlists. | Discovery advertises executable signing capabilities; client policy selects which are mandatory. DCR cannot opt into elevated policy. | Unsupported request-object/JARM/introspection metadata is rejected; signing failures never downgrade to an unprotected response. |
| CIBA client | Register `poll` or `ping` metadata and grant plus `allow_cross_device_flows=true`. Ping requires an exact HTTPS notification endpoint and never carries tokens. | Confidential `private_key_jwt` or mTLS client authentication, signed backchannel requests, mTLS sender-constrained tokens for the FAPI-CIBA ID1 profile, and outbound Ping delivery with a TLS 1.2 minimum and TLS 1.3 support. | The CIBA runtime module is active by default on new databases; Push and `user_code` are rejected. The compatibility profile remains separate from internal `fapi2-ciba` hardening. | Invalid signatures/audiences/algorithms, polling violations, unsafe notification targets, TLS 1.1-or-older notification endpoints, redirects, expired `auth_req_id` values, and unbounded retries fail closed. |
| Device Authorization Grant client | Register `urn:ietf:params:oauth:grant-type:device_code` and set `allow_cross_device_flows=true`; do not infer device capability from public client type. | Public or confidential according to client registration; token polling still enforces the client boundary and interval policy. | The Device runtime module is active by default on new databases and discovery reflects its active state. | Pending requests return `authorization_pending`, excessive polling returns `slow_down`, denied or expired requests fail without revealing extra user-code state. |
| DCR / DCRM client lifecycle | DCR accepts bounded RFC 7591 metadata; DCRM uses `registration_client_uri`, `registration_access_token`, full replacement `PUT`, and `DELETE` deactivation for DCR-created clients only. | Registration requires the deployment initial access token. DCRM uses the bearer registration access token and, for secret clients, the matching current `client_secret` in update payloads. | DCR/DCRM routes exist only under the dynamic-registration feature gate. A read preserves its registration token while rotating a non-recoverable client secret; full replacement rotates both credentials. | Server-managed fields are immutable in `PUT`; stale or missing registration tokens return `invalid_token`; update/deletion failures do not leak whether an inactive or unknown client id exists. |

## Public applicant and approval control plane

The public application, administrator approval, one-time credential delivery,
and mTLS trust-review endpoints are product control-plane operations. They are
not advertised as OAuth or OpenID protocol endpoints.

The application list tells the authenticated request owner only that a delivery
is available. Claiming it submits the public application `request_id` in a
same-origin, CSRF-protected JSON `POST`; the browser never receives a separate
delivery capability. The server derives its internal storage locator from the
authenticated owner and request identifier, validates the approved request and
client binding, and removes the credential atomically after a successful read.
No secret is placed in a URI, redirect, browser history entry, or `Referer`.
This is a product security boundary rather than an extension of RFC 7591.
[RFC 9110 Section 17.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9)
warns that sensitive data in URIs is liable to disclosure, and the
[OWASP query-string exposure guidance](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
lists browser history, server/proxy logs, and Referer propagation as concrete
exposure paths.

- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) and
  [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) govern the client
  record and its protocol lifecycle after approval. RFC 7591 leaves the method
  of issuing an initial access token out of scope; it does not define an
  asynchronous human approval API.
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) governs mTLS client
  identity and certificate-bound tokens, but Section 7.3 leaves CA trust
  decisions to the deployment. [RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html)
  supplies trust-anchor-management requirements. The HTTP approval workflow is
  therefore product behavior with its own least-privilege boundary.
- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
  defines automatic and explicit registration through signed entity statements
  and trust chains. It is a possible future protocol, not a standards label for
  the current manual approval workflow.

The applicant must be an active owner of the approved client. A different
active administrator resolves each request. Approval and client creation use a
compare-and-swap transaction; losing concurrent decisions roll back. A secret
is staged before the database transaction, becomes claimable only after the
matching client commit, expires, and is consumed atomically by the same owner.
Cleanup uses the same public APIs to reject pending requests, deactivate
clients, and revoke trust anchors.

RFC 8705 Section 7.4 warns that a different trusted CA can issue a certificate
with the same subject. The public CA-approval path therefore requires
`tls_client_auth` clients to have an administrator-registered SHA-256 leaf
certificate pin in addition to the single RFC 8705 DN/SAN selector. Clients
authenticated by `private_key_jwt` that use mTLS only as a sender constraint do
not use the certificate as their authentication identity. CA inputs are still
bounded to one current RFC 5280 CA certificate, use two-person approval,
tenant-scoped serialization, quotas, revocation, bundle export, and append-only
audit.

## Device Authorization Grant

### Boundary

The Device Authorization Grant server module is active by default on new
databases. It fits CLI, TV, appliance, and constrained-input clients only when
the client registration explicitly allows
`urn:ietf:params:oauth:grant-type:device_code` and its policy sets
`allow_cross_device_flows=true`.

### Activation Criteria

- User code entropy, display format, expiry, brute-force limits, and replay behavior.
- Device code entropy, storage, expiry, and one-time completion.
- Polling interval enforcement, `slow_down`, expired token behavior, and client rate limits.
- Binding between the browser approval session, displayed client identity, requested scopes, `authorization_details`, resources, and the device code.
- Phishing-resistant UI language and audit events for approved, denied, expired, and rate-limited flows.
- Profile matrix changes for public versus confidential device clients.
- Discovery metadata must follow the immutable active runtime-module snapshot.

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
