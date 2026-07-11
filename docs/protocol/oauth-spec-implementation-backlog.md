# OAuth, OpenID Connect, and FAPI Specification Backlog

Last reviewed: 2026-07-03.

This document records standards and active drafts that were found in the current
OAuth 2.x, OpenID Connect, and FAPI 2.0 specification landscape but are not
implemented by Nazo Auth Server at the code level.

The scan used primary sources only:

- IETF OAuth Working Group documents:
  <https://datatracker.ietf.org/wg/oauth/documents/>
- RFC Editor records for published OAuth-related RFCs:
  <https://www.rfc-editor.org/>
- OpenID Foundation specifications index:
  <https://openid.net/specs/>
- OpenID Foundation FAPI Working Group specifications:
  <https://openid.net/wg/fapi/specifications/>

The code comparison used route registration, discovery metadata, token
`grant_type` dispatch, client metadata validation, and protocol handlers as the
authority. README claims were not used as implementation evidence.

## Current Implemented Surface

The following capabilities are present in code and are used as implementation
evidence for the status table below:

| Area | Code evidence |
| --- | --- |
| Authorization Code flow, PKCE S256, refresh tokens, and client credentials | `src/bootstrap/routes.rs`, `src/http/token/dispatch.rs`, `src/http/token/authorization_code.rs`, `src/http/token/refresh.rs`, `src/http/token/client_credentials.rs` |
| OAuth Authorization Server Metadata and OpenID Provider Configuration | `src/http/well_known.rs` publishes `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` metadata |
| OAuth Protected Resource Metadata | `src/http/well_known.rs` publishes `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/fapi/resource`; authorization server metadata lists `protected_resources` |
| Revocation and introspection | `src/bootstrap/routes.rs`, `src/http/token/revoke.rs`, `src/http/token/introspect.rs` |
| PAR, JAR, JARM-style JWT authorization responses, and issuer identification | `src/http/authorization/par.rs`, `src/http/authorization/request.rs`, `src/http/well_known.rs` |
| Resource Indicators and Rich Authorization Requests | `resource`/`authorization_details` handling in `src/http/authorization`, `src/http/token`, and `src/resource_server.rs`, including PAR/request-object inputs and refresh-token resource narrowing |
| JWT access tokens and resource-server verification | `src/http/token/issue.rs`, `src/resource_server.rs` |
| DPoP and mTLS sender-constrained tokens | `src/support/dpop.rs`, `src/support/mtls.rs`, `src/http/token/authorization_code.rs`, `src/http/token/client_credentials.rs`, `src/http/fapi_resource.rs` |
| `private_key_jwt`, mTLS client authentication, and client secret auth methods | `src/http/token/client_auth.rs`, `src/support/oauth.rs`, `src/http/well_known.rs` |
| OIDC Core code flow, Discovery, UserInfo, RP-Initiated Logout, and Back-Channel Logout | `src/bootstrap/routes.rs`, `src/http/well_known.rs`, `src/http/userinfo.rs`, `src/http/profile/oidc_logout.rs` |
| FAPI 2.0 Security Profile and Message Signing profile controls | `src/http/well_known.rs`, `src/http/authorization/request.rs`, `src/http/token/dispatch.rs`, FAPI profile tests under `tests/in_source` |

## Backlog

Priority values describe expected project fit, not protocol importance.

| Priority | Specification or draft | Current code status | Required implementation work |
| --- | --- | --- | --- |
| P1 | [OAuth 2.1 Authorization Framework, `draft-ietf-oauth-v2-1-15`](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | Partially aligned. Code already uses code-only authorization responses, PKCE S256, no implicit grant, no resource owner password grant, and OAuth 2.1-style defaults. There is no dedicated OAuth 2.1 conformance matrix tracking the draft as a single profile. | Track the latest OAuth 2.1 draft as a profile audit item until it becomes an RFC. Add a test matrix that maps the final draft/RFC requirements to code and discovery metadata. |
| Done | [RFC 8628, OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628) | Implemented behind `ENABLE_DEVICE_AUTHORIZATION_GRANT`; default deployments do not advertise it. | Keep user-code UX, polling interval, `slow_down`, expiration, denial handling, rate limiting, token dispatch, and discovery metadata covered by local tests; add OIDF official suite coverage if the suite publishes AS-side RFC 8628 plans. |
| Done/bounded | [RFC 8693, OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) | Implemented as a bounded local access-token to access-token exchange for confidential clients explicitly registered with `urn:ietf:params:oauth:grant-type:token-exchange`. This is not a complete RFC 8693 token exchange implementation. | Keep subject/actor token validation, target restrictions, scope downscoping, `issued_token_type`, revocation checks, and delegation claim tests current; external token trust, refresh-token exchange, ID-token exchange, broader issued-token-type handling, and authorization-details propagation remain future profiles. |
| Done/default-closed | [RFC 7591, OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591) and [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | Implemented behind `ENABLE_DYNAMIC_CLIENT_REGISTRATION`; discovery advertises `registration_endpoint` only when enabled. The endpoint accepts standard metadata, returns created client metadata, supports optional initial access token enforcement, rejects unsupported `software_statement`, emits audit events, and does not claim remote `jwks_uri` fetching. | Keep metadata validation, redirect URI policy, default-low-privilege registration, initial access token enforcement, audit event allowlist, discovery truth tests, and OIDF dynamic-client plan coverage current; software statement trust and remote JWKS retrieval remain future profiles. |
| Done/default-closed | [RFC 7592, OAuth 2.0 Dynamic Client Registration Management](https://www.rfc-editor.org/rfc/rfc7592) | Implemented for DCR-created clients while `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`; responses include `registration_client_uri`, registration access tokens are stored as BLAKE3 hashes, GET and PUT rotate management credentials, PUT is full replacement, and DELETE deactivates the client plus revokes refresh-token rows and stored grants. | Keep registration access token lifecycle, read/update/delete semantics, management credential rotation, metadata validation, and dynamic-client audit events covered by local tests. |
| Done | [OpenID Connect Client-Initiated Backchannel Authentication Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | Implemented behind `ENABLE_CIBA=true` with poll mode, `backchannel_authentication_endpoint`, `auth_req_id`, user binding through `login_hint`, CSRF-protected approve/deny, polling interval enforcement, and discovery metadata. | Keep ping/push mode and `user_code` out unless product scope requires them; add official FAPI-CIBA matrix when enabled in certification runs. |
| Partial | [FAPI CIBA Profile](https://openid.net/specs/openid-financial-api-ciba.html) | CIBA token issuance preserves OIDF FAPI-CIBA ID1 compatibility and supports an internal `CIBA_SECURITY_PROFILE=fapi2-ciba` hardening mode for CIBA-applicable FAPI2 Security controls. This is an implemented compatibility/hardening profile, not a full FAPI-CIBA capability claim. | Keep FAPI-CIBA conformance matrix aligned with runtime feature gates; do not advertise an official “FAPI2-CIBA” profile; keep PAR, PKCE, and authorization-code-only requirements out of CIBA. |
| P2 | [Grant Management for OAuth 2.0](https://openid.net/specs/oauth-v2-grant-management-ID1.html) | Admin grant listing/revocation exists under `/api/admin/grants`, but no end-user or client-facing grant management endpoint, grant identifiers, or grant management metadata was found. | Add grant identifier model, grant management endpoint, partial grant revocation/update semantics, client/user authorization checks, and metadata. |
| Done/bounded | [RFC 7523 JWT Bearer Authorization Grant](https://www.rfc-editor.org/rfc/rfc7523) | Implemented as a bounded confidential-client self-assertion grant using registered client JWKs, issuer audience, expiry/iat/nbf limits, and jti replay protection. This does not implement third-party assertion issuer trust. | Third-party assertion issuer trust, subject mapping, revocation, and cross-issuer audit policy remain a deferred profile described in `docs/features/ecosystem-onboarding.md`. |
| P3 | [RFC 7522 SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7522) | External SAML federation login exists, but no SAML bearer OAuth client authentication or SAML bearer authorization grant was found. | Decide whether SAML bearer OAuth profiles are in scope. If adopted, add assertion validation, issuer trust configuration, replay protection, and grant dispatch. |
| P3 | [OAuth 2.0 Step Up Authentication Challenge Protocol, RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) | Authorization requests may carry authentication context inputs, but no protected-resource challenge protocol for step-up authentication was found. | Add resource challenge generation/validation, ACR/AMR policy integration, and tests spanning resource server to authorization server escalation. |
| Done | [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | Implemented behind `ENABLE_FRONTCHANNEL_LOGOUT=true` with metadata, DCR/admin client fields, iframe logout notification rendering, and `iss`/`sid` session correlation. | Keep browser/iframe tests and prefer back-channel logout where reliable server-side logout is required. |
| Done | [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) | Implemented behind `ENABLE_SESSION_MANAGEMENT=true` with `check_session_iframe`, authorization response `session_state`, and polling status endpoint. | Keep iframe behavior default-closed and do not treat it as the primary logout security boundary. |
| Deferred | [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) and [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) | Not implemented. The previous `/.well-known/openid-federation` self-issued entity statement endpoint and `ENABLE_OIDC_FEDERATION` gate have been removed because this project does not currently need OpenID Federation trust-chain ecosystem behavior. | Re-scope from the 1.1 specifications before implementation. A future implementation must cover trust anchors, trust chains, metadata policy, trust marks, federation fetch/list/resolve endpoints, key rollover, and OIDF conformance evidence before advertising Federation OP/RP support. |
| Done | [OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html) | Implemented behind `ENABLE_NATIVE_SSO=true`; authorization code issues `device_secret` with ID Token `ds_hash`/`sid`, and Native SSO token exchange validates ID Token binding, device secret state, refresh-family activity, and destination client `device_sso` scope. | Keep platform app-signing/device-attestation proof out until product scope defines a trust source; secure storage remains a native-app responsibility. |
| P3 | [OAuth 2.0 Attestation-Based Client Authentication, `draft-ietf-oauth-attestation-based-client-auth-09`](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) | Passkey/WebAuthn attestation exists for user authentication, and release provenance attestations exist in CI documentation. No OAuth client attestation authentication method was found. | Track the active OAuth WG draft. If adopted, add client attestation statement validation, nonce/challenge handling, trust store configuration, and token endpoint auth method metadata. |
| P3 | [Transaction Tokens, `draft-ietf-oauth-transaction-tokens-08`](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | No transaction token issuance or validation model was found. | Track the active OAuth WG draft and decide whether transaction-bound API authorization is in scope. |
| P3 | [FAPI 2.0 HTTP Signatures working draft](https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html) | FAPI 2.0 Message Signing support exists through signed authorization requests and JARM-style authorization responses. No HTTP Message Signatures implementation for arbitrary FAPI client, authorization server, or resource server HTTP messages was found. | Track whether this working draft remains part of the target FAPI 2.0 suite. If adopted, add HTTP message signature generation and verification, key binding, canonicalization tests, and resource-server integration. |
| P4 | [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | No credential issuer metadata, credential endpoint, deferred credential endpoint, nonce endpoint, or credential offer model was found. | Treat as a product-scope decision. If adopted, add credential issuer domain model, credential formats, proof validation, lifecycle policy, and conformance tests. |
| P4 | [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | No wallet/verifier presentation request or response processing model was found. | Treat as a product-scope decision. If adopted, add verifier endpoints, presentation definition handling, wallet response validation, nonce/state lifecycle, and trust policy. |

## Items Not Added As Missing Work

The following were checked but are already represented by existing code paths or
are informational/security guidance rather than standalone product features:

| Specification | Reason |
| --- | --- |
| RFC 7009 Token Revocation | `/revoke` exists. |
| RFC 7636 PKCE | S256 PKCE validation exists. |
| RFC 7662 Token Introspection | `/introspect` exists for authenticated JSON introspection. |
| RFC 9701 JWT Response for OAuth Token Introspection | Signed and nested encrypted JWT introspection responses are implemented under the signed-introspection profile, with content negotiation, issuer/audience binding, signing key selection, per-client JWE metadata, and negative tests. |
| RFC 8414 Authorization Server Metadata | `/.well-known/oauth-authorization-server` exists. |
| RFC 8705 mTLS | mTLS client authentication and certificate-bound access-token support exist. |
| RFC 8707 Resource Indicators | `resource` handling exists for authorization requests, PAR, token exchange, and refresh-token audience narrowing; JWT access-token `aud` is bound to the resulting resource set. |
| RFC 9068 JWT Access Tokens | Access tokens use JWT shape and resource-server verifier expects `typ=at+jwt`. |
| RFC 9101 JAR | Request object support exists where enabled. |
| RFC 9126 PAR | `/par` exists. |
| RFC 9207 Authorization Server Issuer Identification | Discovery advertises `authorization_response_iss_parameter_supported`. |
| RFC 9396 Rich Authorization Requests | `authorization_details` support exists behind configuration. |
| RFC 9449 DPoP | DPoP proof validation and sender-constrained token handling exist. |
| RFC 9728 OAuth 2.0 Protected Resource Metadata | `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/fapi/resource` publish resource metadata; authorization server metadata lists the configured protected resource identifier. |
| FAPI 2.0 Security Profile Final | Implemented as a runtime profile and covered by conformance-oriented tests. |
| FAPI 2.0 Message Signing Final | Implemented through signed authorization request and JWT authorization response support in the FAPI message-signing profile. |
| FAPI 2.0 Attacker Model | Used as security rationale for FAPI profiles; it is not an endpoint-level implementation item. |
