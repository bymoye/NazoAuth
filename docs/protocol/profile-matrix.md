# Profile Matrix

## Scope

The profile matrix separates protocol conformance from product hardening.
Discovery metadata may advertise only behavior that the implementation and
deployment can satisfy.

## Summary

| Profile | Purpose | Status |
| --- | --- | --- |
| `oauth2-baseline` | General OAuth authorization server profile for authorization code, refresh token, client credentials, revocation, introspection, metadata, and JWKS. | Implemented and covered by local matrix tests |
| `oauth2-security-bcp` | OAuth baseline constrained by RFC 9700-style security defaults. | Policy defined; enforced through baseline controls and client/profile policy |
| `oidc-basic-op` | OpenID Connect Authorization Code OP with discovery, ID Token, JWKS, and JSON or per-client protected UserInfo. | OIDF-tested baseline; response crypto has local negative coverage |
| `oidc-config` | OIDC discovery/server metadata verification. | OIDF-tested |
| `fapi2-security` | Per-client FAPI2 assurance without forcing a message-signing option. | Versioned client policy implemented; OIDF-tested for recorded matrix variants |
| `fapi2-message-signing-authz-request` | FAPI2 assurance plus signed authorization requests at PAR. | Composable client-policy option implemented; OIDF-tested for recorded matrix variants |
| `fapi2-message-signing-jarm` | FAPI2 Message Signing authorization response signing option. | Composable client-policy option implemented; OIDF-tested for recorded matrix variant |
| `fapi2-message-signing-introspection` | FAPI2 Message Signing signed and optionally encrypted introspection response option. | Composable client-policy option implemented and advertised as a supported response capability |
| `fapi-ciba-id1` | OIDF FAPI-CIBA AS compatibility profile with orthogonal `private_key_jwt / mTLS` client authentication and `poll / ping` delivery. | CIBA server support is active by default on new databases; client grant, metadata, and cross-device policy are still required. Push and `user_code` are not implemented |
| `fapi2-ciba` | Internal CIBA hardening profile: CIBA Core + FAPI-CIBA compatibility + applicable FAPI2 Security controls. | Runtime CIBA security switch implemented; not an official OIDF certification profile name |

## `oauth2-baseline`

| Field | Policy |
| --- | --- |
| Grants | `authorization_code`, `refresh_token`, `client_credentials`, bounded RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange`; RFC 8628 `urn:ietf:params:oauth:grant-type:device_code` requires an active server module, the client grant allowlist, and `allow_cross_device_flows=true` |
| Response types | `code` |
| Client auth | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` |
| Token binding | Bearer, DPoP-bound, mTLS-bound |
| PKCE | S256 required for public, FAPI, sender-constrained, and non-OIDC authorization-code requests. Baseline confidential OIDC may omit PKCE only through the explicit per-client compatibility policy; any supplied challenge must be S256 |
| PAR | Supported, not globally required by default |
| JAR | Supported only as an asymmetric signed Request Object; `alg=none` is rejected |
| JARM | Supported as `response_mode=jwt` when negotiated; per-client metadata may select signing and nested JWE protection |
| RAR | RFC 9396-style `authorization_details` accepted on authorization, PAR, and signed request object inputs only when `ENABLE_AUTHORIZATION_DETAILS=true` |
| Refresh policy | Rotation by default for refresh-token grants |
| Token TTLs | Authorization code <= configured `AUTH_CODE_TTL_SECONDS`; access token <= configured `ACCESS_TOKEN_TTL_SECONDS` |
| Metadata | Generated as the union of active server capabilities; mTLS capabilities are advertised only when trusted proxy CIDRs are configured; client policy is enforced after discovery |

Refresh-token rotation follows the state machine in `docs/protocol/refresh-token-rotation.md`. The lost-response retry window is a compatibility recovery path, not a replay bypass.

Required negative tests:

- duplicate OAuth parameters
- unsafe redirect URI
- non-S256 PKCE
- omitted PKCE for public, FAPI, sender-constrained, and non-OIDC authorization-code clients
- `plain` PKCE for every client type
- mixed client authentication methods
- invalid client assertion audience
- access token transport ambiguity
- disabled, unknown, or malformed `authorization_details`
- disabled Device Authorization Grant metadata or token dispatch overclaim
- Token Exchange subject/actor token type, target, scope, and sender-constraint boundary violations

## Per-client OIDC response protection

| Field | Policy |
| --- | --- |
| UserInfo default | UTF-8 JSON with `application/json` when no response-protection metadata is registered |
| Signed UserInfo | `userinfo_signed_response_alg` selects an asymmetric JWS algorithm that the current Keyset snapshot can actually sign; signed claims include `iss` and client-bound `aud` |
| Encrypted UserInfo | `userinfo_encrypted_response_alg` values `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, and `ECDH-ES+A256KW` with `userinfo_encrypted_response_enc=A256GCM` require exactly one matching public `use=enc` JWK with `kid`; signing plus encryption produces a nested JWT |
| Encrypted JARM | A JARM response is signed first, then encrypted with the same client JWE policy when `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` are registered |
| Metadata surfaces | Admin client management and RFC 7591/7592 registration persist and return all six response-crypto metadata fields |
| Failure behavior | Metadata, key lookup, signing, and encryption failures return `server_error`; UserInfo never falls back to JSON and JARM never exposes a code/state in a plain query response |

For response encryption, keys are registered by value, validated as public
material, and selected only when the `use` and `alg` policy has exactly one
matching non-empty `kid`. Dynamic registration may resolve a client's
`jwks_uri` through the constrained HTTPS remote-document resolver for client
authentication and Request Object keys, but response-encryption key selection
still uses the persisted client JWK material and never falls back to an
unregistered remote document. UserInfo and authorization-response signing
algorithms advertised by discovery are the same Keyset-snapshot capabilities
accepted by registration and used by signing execution.

## Ecosystem Onboarding Surfaces

These surfaces are profile-scoped additions to baseline behavior. Detailed
client onboarding guidance lives in
[`docs/features/ecosystem-onboarding.md`](../features/ecosystem-onboarding.md).

| Surface | Profile boundary | Metadata rule |
| --- | --- | --- |
| Dynamic Client Registration / DCRM | Conditional RFC 7591 and RFC 7592 client lifecycle for DCR-created clients only; registration and management operations emit non-secret audit events. `jwks_uri` is accepted only when the constrained HTTPS remote-document resolver can fetch and validate the client JWK Set. | `registration_endpoint` appears only when an initial access token is configured; DCR-created clients receive baseline policy and cannot self-grant elevated capabilities. |
| Device Authorization Grant | Server support is default-on for new databases, but client use is default-deny. | Device endpoint and `device_code` grant metadata appear when the runtime module is active; a request still requires the client grant allowlist and `allow_cross_device_flows=true`. |
| Token Exchange local profile | Bounded RFC 8693 access-token to access-token exchange for locally issued subject/actor tokens and explicitly allowed targets. | The grant type is advertised only because the local profile is implemented; external, refresh-token, and ID-token exchange profiles are not implied. |
| Third-party JWT bearer assertion trust | Deferred profile for external assertion issuers and non-client subjects; the implemented JWT bearer grant remains client-bound. | No discovery metadata is advertised until issuer allowlists, subject mapping, replay, revocation, audit, and negative tests exist. |
| Third-party login RP providers | Product login surface for external OIDC, OAuth2 social, and SAML gateway providers. Provider registry is configuration-driven and default-closed; each provider has independent enablement, display metadata, adapter type, redirect URI, scope, endpoints, and claim mapping. | Third-party login is an RP/client capability and must not appear in OP discovery metadata. Public login metadata comes from `/auth/federation/providers`; admin onboarding metadata comes from `/admin/federation/providers` without secrets. |

## `oauth2-security-bcp`

`oauth2-security-bcp` is a policy profile layered onto baseline runtime
behavior. It is not a separate `AUTHORIZATION_SERVER_PROFILE` switch. High-risk
clients use the same protocol invariants through registration policy,
PAR/JAR/client-auth settings, sender constraints, and negative conformance
tests.

| Field | Policy |
| --- | --- |
| Grants | Authorization code and client credentials; no implicit or password grants |
| Response types | `code` only |
| Client auth | Public clients use `none` with PKCE; confidential clients must authenticate |
| PKCE | S256 required for every authorization code request |
| Token binding | Sender-constrained tokens preferred for high-risk clients |
| PAR | Recommended for high-risk clients |
| JAR | Signed JAR recommended for high-risk clients |
| Refresh policy | Rotation or sender constraint according to client risk |
| Metadata | Must not overclaim disabled high-security behavior |
| RAR and consent reuse | High-risk `authorization_details` require explicit transaction binding; silent consent reuse is bounded by stored scopes, resource indicators, and exact non-high-risk authorization-detail matching |

Required negative tests:

- authorization without required PKCE
- redirect URI mismatch
- stale authorization code
- authorization code replay
- refresh token reuse
- bearer use of sender-constrained token at protected resources

## `oidc-basic-op`

| Field | Policy |
| --- | --- |
| Grants | `authorization_code`, optional `refresh_token` |
| Response types | `code` |
| Client auth | Static clients, public or confidential according to registration |
| Token binding | Bearer, DPoP, or mTLS depending on client policy |
| DPoP nonce | Authorization-server and token endpoints use `DPOP_NONCE_POLICY=required` by default. The FAPI protected resource endpoint uses `FAPI_RESOURCE_DPOP_NONCE_POLICY=optional` by default because RFC 9449 makes resource nonces optional and the official FAPI2 DPoP resource tests exercise replay through `jti`, not a mandatory initial resource nonce challenge. |
| PAR | Optional unless client/profile requires it |
| JAR | Optional; signed request objects validated when supplied |
| ID Token | RS256 support must be real; active signing alg is advertised |
| UserInfo | Requires valid access token with `openid` scope |
| Logout | RP-Initiated Logout at `/logout`; exact `post_logout_redirect_uri` matching; durable Back-Channel Logout outbox with bounded retry for registered clients |
| Metadata | OIDC discovery must match runtime issuer and endpoints, including `end_session_endpoint` and back-channel logout support, and must not advertise unimplemented extensions |

Required negative tests:

- invalid issuer
- invalid ID Token signature alg
- missing or invalid nonce where required
- userinfo without `openid`
- unsupported prompt combinations
- unregistered `post_logout_redirect_uri`
- multi-audience `id_token_hint` without matching `client_id`
- logout token containing forbidden `nonce`
- discovery overclaim for unimplemented OAuth/OIDC/FAPI extensions

## `oidc-config`

| Field | Policy |
| --- | --- |
| Discovery | `/.well-known/openid-configuration` |
| OAuth metadata | `/.well-known/oauth-authorization-server` |
| Protected resource metadata | `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/fapi/resource` |
| JWKS | `/jwks.json` publishes active and previous non-retired keys |
| Metadata truth | Discovery values must correspond to real endpoint behavior |

Required negative tests:

- stale issuer
- advertised alg without usable key
- advertised auth method without working path
- disabled profile still advertised
- advertised logout endpoint without exact redirect validation or signed logout token support

## `fapi2-security`

| Field | Policy |
| --- | --- |
| Clients | Confidential clients only |
| Grants | Authorization code and client credentials variants covered by the OIDF plan set |
| Response types | `code` |
| Client auth | `private_key_jwt` or mTLS |
| Token binding | DPoP or mTLS sender-constrained access tokens |
| DPoP nonce | Authorization-server and token endpoints remain governed by `DPOP_NONCE_POLICY` and default to required. The protected resource endpoint is governed separately by `FAPI_RESOURCE_DPOP_NONCE_POLICY`; its default is optional for OIDF FAPI2 DPoP resource conformance while DPoP `jti` replay protection remains required. |
| PAR | Required; authorization requests that do not use PAR must be rejected |
| PKCE | S256 required for authorization code flow |
| Authorization code TTL | 60 seconds or less |
| JAR/JARM | Not required by this profile unless a Message Signing option is selected |
| Refresh policy | Sender-constrained tokens; no routine refresh-token rotation for FAPI2 Security by default |
| Metadata | Must reflect selected client auth and sender constraint behavior |

Deployments that enable refresh-token rotation for migration or compatibility
must document that exception and keep the replay-detection state machine from
`docs/protocol/refresh-token-rotation.md`.

Runtime enforcement is selected per client with
`security_policy.assurance=fapi2`. It forces PAR for that client, caps its
authorization code lifetime at 60 seconds, limits it to a confidential client,
allows only `private_key_jwt` or mTLS client authentication, and requires DPoP
or mTLS sender-constrained access tokens. Password grant requests are rejected
for every client. DPoP nonce enforcement is split by endpoint:
authorization-server and token endpoint checks use `DPOP_NONCE_POLICY`, while
the FAPI protected resource endpoint uses `FAPI_RESOURCE_DPOP_NONCE_POLICY`.

Required negative tests:

- public client usage
- non-PAR authorization request
- missing PKCE S256
- bearer token where sender-constrained token is required
- weak client authentication
- wrong client assertion audience
- DPoP proof mismatch or replay
- mTLS certificate mismatch

## CIBA Profiles

The CIBA runtime module enables the OpenID Connect CIBA poll/ping endpoint and
grant and is active by default on new databases. A client must still have CIBA
grant/metadata and `security_policy.allow_cross_device_flows=true`. CIBA uses
`CIBA_SECURITY_PROFILE` for CIBA-specific assurance because there is no
official OIDF profile named `FAPI2-CIBA`.

| Profile | Policy |
| --- | --- |
| `fapi-ciba-id1` | Preserves the OIDF FAPI-CIBA ID1 plain FAPI behavior across `private_key_jwt / mTLS` × `poll / ping`: signed backchannel authentication requests, endpoint-audience compatibility where explicitly registered, mTLS holder-of-key tokens, and authenticated ping carrying only `auth_req_id`. The former poll-specific value remains a migration alias. |
| `fapi2-ciba` | Requires confidential clients, `private_key_jwt` or mTLS client authentication, issuer-only private_key_jwt audience policy, signed backchannel authentication requests, strong CIBA JWT algorithms, and DPoP or mTLS sender-constrained access tokens. |

The internal `fapi2-ciba` profile applies only CIBA-applicable FAPI2 Security
hardening. It does not import authorization-code-only requirements into CIBA:
it does not require PAR, PKCE, `response_type=code`, or replacement of signed
backchannel authentication requests with PAR. Discovery metadata exposes only
standard CIBA and token endpoint capabilities, not the internal profile name.

## `fapi2-message-signing-authz-request`

| Field | Policy |
| --- | --- |
| Base | `fapi2-security` |
| PAR | Signed request object accepted and required at PAR |
| JAR claims | `aud` required, `nbf` required, `exp` required with lifetime <= 60 minutes |
| JAR header | Accept `typ=oauth-authz-req+jwt` |
| Request object `jti` | Optional by default for OIDF/FAPI compatibility; `REQUEST_OBJECT_JTI_POLICY=required-for-signed-jar` enables stricter product hardening |

Runtime enforcement is composed with
`security_policy.assurance=fapi2` and
`security_policy.require_signed_authorization_request=true`. Signed JAR
validation requires `aud`, `nbf`, and `exp`; the implementation
uses a 5-minute maximum lifetime, stricter than the FAPI2 Message Signing
60-minute ceiling. When a signed JAR request object carries `jti`, the server
stores it in the request-object replay cache and rejects replay. Deployments
that require mandatory request-object replay IDs can set
`REQUEST_OBJECT_JTI_POLICY=required-for-signed-jar`.

Required negative tests:

- unsigned JAR when signed JAR is required
- missing `aud`, `nbf`, or `exp`
- request object lifetime > 60 minutes
- request object/client mismatch
- parameter override after PAR

## `fapi2-message-signing-jarm`

| Field | Policy |
| --- | --- |
| Base | `fapi2-security` |
| Authorization response | Signed authorization response JWT; optionally signed then encrypted according to per-client JWE metadata |
| Metadata | `authorization_signing_alg_values_supported` must match active signing capability |
| Failure behavior | Signing, client-policy lookup, or encryption failure must not fall back to a plain query response |

Runtime enforcement is composed with
`security_policy.assurance=fapi2` and
`security_policy.require_signed_authorization_response=true`. It requires
signed authorization responses even when the request omits
`response_mode=jwt` or explicitly uses the default query mode. Composable
discovery advertises both baseline and JARM response modes; client policy
selects the required behavior.

Required negative tests:

- unsigned response where JARM is required
- wrong `iss` or `aud`
- missing `state` preservation
- fallback to plain query after signing failure
- wrong JWE key, incomplete JWE metadata, or fallback after encryption failure

## `fapi2-message-signing-introspection`

| Field | Policy |
| --- | --- |
| Base | `fapi2-security` |
| Response negotiation | JWT introspection is returned when the authenticated caller sends `Accept: application/token-introspection+jwt` or its policy sets `require_signed_introspection_response=true` |
| JWT envelope | Header `typ=token-introspection+jwt`; top-level `iss`, `aud`, and `iat`; JSON introspection body nested under `token_introspection` |
| JWE envelope | If the authenticated caller has supported client JWE metadata (`RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW`, or `ECDH-ES+A256KW` with `A256GCM`) and exactly one matching `use=enc` JWK, the signed JWT is returned as a nested compact JWE with `cty=JWT` |
| Audience | Authenticated introspection client/resource-server `client_id` |
| Metadata | Composable discovery advertises only the implemented introspection signing and encryption algorithms; authenticated client policy selects whether protection is mandatory |
| Non-goals | Normal OAuth error responses remain JSON |

Required negative tests:

- no JSON fallback when client policy requires a signed introspection response
- no encrypted introspection response unless the resource-server client metadata registers supported JWE response algorithms and a matching encryption key
- wrong response issuer/audience
- stale or revoked token reported active
- top-level token subject/expiry confusion in the signed response

## M8 emerging-protocol watchlist boundary

M8 is not an authorization-server runtime profile. Completing its governance
tasks does not add a profile name, endpoint, grant, authentication method,
token type, SCIM capability, credential role, or discovery field.

Separately admitted implementations may add their own default-closed module or
baseline capability after their entry gate is complete; this paragraph does
not override the implemented RFC 9865, RFC 9967, bounded HTTP Signatures, or
separately admitted OpenID4VC Issuer/Verifier surfaces described below.

The dated [M8 governance review](../conformance/2026-07-11-m8-watchlist-governance.md)
defines the admission and isolation requirements for FAPI HTTP Signatures,
RFC 9865/9967, browser-based application guidance, client attestation,
Transaction Tokens, Grant Management, and the historical OpenID4VC entry gate.
OpenID4VCI Issuer and OpenID4VP Verifier subsequently completed that separate
gate; their current boundary is documented in
[`openid4vc-final-matrix.md`](../conformance/openid4vc-final-matrix.md). Until a remaining candidate's
separate implementation and negative tests complete, all existing baseline,
FAPI2, Message Signing, CIBA, SCIM, and external-provider profile behavior must
be byte-for-byte unaffected by selecting any existing runtime profile.

RFC 9865 is the first admitted M8 candidate. Its completed implementation is
limited to SCIM `/Users` listing and `/ServiceProviderConfig`; it is not an
OAuth authorization-server profile and cannot change any profile selection or
OAuth/OIDC/FAPI metadata.

The dated
[Browser-Based Applications draft-27 audit](../conformance/2026-07-11-browser-based-applications-draft-27-audit.md)
is also complete as security evidence, not as a runtime profile. NazoAuthWeb is the first-party
same-origin authorization-server frontend with a server-managed session, not a BFF, and receives no OAuth tokens. A third-party
browser-only application remains a public `oauth2-oidc-baseline` client using
authorization code + S256 PKCE, exact redirects, and non-credentialed
endpoint-specific CORS. The final RFC requires a separate delta audit before
any final-standard claim.

FAPI HTTP Signatures is the second bounded M8 implementation candidate. It is
available only through `ENABLE_FAPI_HTTP_SIGNATURES=true` on `/fapi/resource`;
it is not an authorization-server profile, emits no metadata, and leaves every
existing profile unchanged while disabled. The implementation is pinned to the
OIDF working draft built 2026-06-26 and the RFC 9421/RFC 9530 primitives listed
in the [dated audit](fapi-http-signatures-draft-audit.md). No dedicated OIDF
plan exists, so local Rust vectors and real-HTTP positive/negative coverage are
evidence, not certification. A newer draft or Final Specification triggers a
fresh delta audit before any version claim changes.

RFC 9967 is the third admitted M8 candidate. It is a separate default-closed
SCIM runtime module, not an OAuth profile. It emits notice-only provisioning
SETs through a transactional outbox and RFC 8936 polling; it cannot alter OAuth,
OIDC, FAPI, CIBA, or browser metadata. Asynchronous SCIM requests remain out of
scope and are advertised as `none`.
