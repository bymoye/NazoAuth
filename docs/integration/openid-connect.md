# OpenID Connect Integration

This document is the entry point for integrating a relying party with this
OpenID Connect Provider. It is a project-specific integration reference: it
describes the implemented protocol surfaces, unsupported capabilities, and the
deployment flags that affect metadata.

Use `https://issuer.example` only as a placeholder in this document. Every
deployment and every conformance run must use its own public HTTPS issuer.

Status terms are literal. **Complete** means the capability is implemented for
the stated role/profile and is advertised only when its enablement conditions
are true. **Never supported** means no runtime flag, client metadata field, or
hidden compatibility path enables that capability; adding it would require an
explicit policy reversal backed by new standards and security evidence.
**Final RFC/Final audit pending** means current behavior covers the main draft
or Implementer's Draft behavior but does not claim final-specification
conformance. **Not supported (planned)** means the capability is accepted as
future work but is not currently executable or advertised. **Not supported**
means a standards-defined optional value is not currently advertised and has no
roadmap commitment. In all cases, discovery and registration metadata are the
executable allowlist.

## Standards and profile support

| Capability | Status | Enablement / advertisement condition | References | Notes |
| --- | --- | --- | --- | --- |
| OpenID Connect Core 1.0 | Complete | Always available for OIDC deployments; interactive login is Authorization Code only | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Tokens are signed and client-bound. |
| OpenID Connect Discovery 1.0 | Complete | Always available for OIDC deployments | [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Discovery metadata is generated from active server modules; client policy is enforced separately. |
| OAuth 2.0 Authorization Server Metadata | Complete | Available for OAuth/OIDC deployments | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) | OAuth metadata mirrors executable authorization-server behavior. |
| OAuth 2.0 Protected Resource Metadata | Complete | Available for configured protected-resource metadata surfaces | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Exposes generic and FAPI resource metadata surfaces. |
| OAuth 2.0 Form Post Response Mode | Complete | Advertised for baseline code-flow clients when the active profile allows `form_post` | [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) | Does not enable implicit or hybrid token delivery. |
| OpenID Connect Third-Party Initiated Login | Complete | Available through HTTPS `initiate_login_uri` client metadata | [OpenID Connect Third-Party Initiated Login 1.0](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html) | This is OP-side metadata support; the initiation URI itself is an RP endpoint. |
| Dynamic Client Registration | Complete | Advertised only when a non-empty initial access token is configured | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | DCR-created clients receive baseline policy and cannot self-grant elevated capabilities. |
| Dynamic Client Registration Management | Complete | Available for clients created through Dynamic Client Registration | [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | Uses protected `registration_client_uri` and registration access tokens. |
| OpenID Connect RP Metadata Choices | Complete | DCR is enabled and the corresponding single-valued metadata is supported | [OpenID Connect RP Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html) | All 19 choices fields are negotiated against executable server capabilities and persisted as single-valued client metadata. The selected ID Token, Request Object, client-assertion, UserInfo/JARM/CIBA, and introspection algorithms are enforced by their runtime consumers. Choice arrays are registration inputs only; registration responses return selected single values. |
| Pushed Authorization Requests | Complete | Required by FAPI profiles; available to baseline clients according to client policy | [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) | Baseline clients are not forced to use PAR unless client policy requires it. |
| JWT Secured Authorization Request | Complete | Accepted for signed Request Objects when client/profile policy allows JAR | [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | Unsigned Request Objects are rejected. |
| JWT Secured Authorization Response Mode / JARM | Complete | Advertised when the JARM module/profile/client metadata enables signed authorization responses | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | Used by message-signing profiles and client metadata that require it. |
| PKCE | Complete | S256 is enforced for public, FAPI, sender-constrained, and non-OIDC code-flow clients | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | New confidential OIDC integrations should also send S256 PKCE. |
| OAuth 2.0 Security Best Current Practice | Complete | Enforced as the security baseline for all OAuth/OIDC profiles | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Covers no implicit/password grants, exact redirect binding, PKCE/sender-constraint policy, token transport, refresh/replay handling, and client-authentication boundaries. |
| JSON Web Token Best Current Practices | Complete | Applies to ID Tokens, JWT access tokens, client assertions, Request Objects, JARM, DPoP proofs, and signed introspection | [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | Enforces algorithm allowlists, no `none`, key/alg/use binding, full cryptographic validation, and cross-JWT confusion defenses. |
| JWT Client Authentication and Authorization Grants | Supported; JWT bearer grant is bounded | `private_key_jwt` is available; the JWT bearer grant is limited to authenticated confidential-client self-assertion | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | Does not implement third-party assertion issuer trust, arbitrary subject mapping, or external issuer federation. |
| JWT Profile for OAuth 2.0 Access Tokens | Complete; current access-token profile | Current access tokens use `typ=at+jwt`, and resource-server verification checks issuer, audience, expiry, scope, and optional `cnf` | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) | This is the current JWT access-token profile; an opaque-token profile would require a separate introspection design. |
| OAuth 2.0 Demonstrating Proof of Possession | Supported | Enabled when clients and resource requests use DPoP sender constraints | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | Verifies proof signature, `htu`, `htm`, `iat`, `jti`, `ath`, nonce, and access-token `cnf.jkt` binding. |
| OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens | Supported | Trusted mTLS/proxy boundary configured and client metadata registered for mTLS authentication or sender constraints | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html), [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | Supports `tls_client_auth`, `self_signed_tls_client_auth`, and `x5t#S256` certificate-bound access tokens. PKI clients register exactly one subject selector. |
| Resource Indicators | Complete | Available for authorization, token, and refresh flows that carry resource indicators | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Uses repeated URI-valued `resource` parameters; JSON-array syntax is not accepted externally. |
| Token Introspection | Complete | Available through the introspection endpoint when client policy permits it | [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) | FAPI message-signing profiles can use protected introspection responses. |
| Token Revocation | Complete | Available through the revocation endpoint | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) | Revokes tokens according to token type and client policy. |
| Device Authorization Grant | Supported | Server support is active by default on new databases; use requires the client device-code grant and `allow_cross_device_flows=true` | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) | Runtime module state controls advertisement; client policy controls authority. |
| OpenID CIBA / FAPI-CIBA | Supported; ID1-compatible | Server poll/ping support is active by default on new databases; use requires CIBA client grant/metadata and `allow_cross_device_flows=true` | [OpenID CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html) | The FAPI-CIBA ID1 `private_key_jwt / mTLS` x `poll / ping` combinations are supported; the newer `fapi-ciba-03` working draft still requires a separate delta audit. Push is never supported. |
| FAPI 2.0 Security Profile | Complete | Enabled per client with `security_policy.assurance=fapi2` | [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html) | Requires confidential clients, PAR, sender constraints, and strong client authentication. |
| FAPI 2.0 Message Signing | Complete | Independent client-policy fields enable signed authorization requests, JARM, and signed introspection | [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-2_0-message-signing.html) | Compatible options may be enabled together and coexist with FAPI2 assurance. |
| OpenID4VCI 1.0 Final | Complete | Disabled by default; advertised through OpenID4VCI issuer metadata after enabling the Credential Issuer role and complete credential/trust configuration | [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html) | Not part of ordinary OIDC RP login. |
| OpenID4VP 1.0 Final | Complete | Disabled by default; advertised through OpenID4VP verifier metadata after enabling the Verifier role and complete trust configuration | [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | Not part of ordinary OIDC RP login. |
| OpenID4VC High Assurance Interoperability Profile 1.0 / HAIP | Complete | Disabled by default; enabled through HAIP-compatible Credential Issuer and Verifier role configuration, credential-format configuration, and trust configuration | [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html), [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html), [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | Profile-level support for high-assurance OpenID4VC issuance and presentation flows; it is separate from ordinary OIDC RP login. |
| OpenID Connect Native SSO for Mobile Apps | Supported; disabled by default; Final audit pending | Advertised only when the persisted `native_sso` module is enabled and the client has `device_sso` scope/policy | [OpenID Connect Native SSO](https://openid.net/specs/openid-connect-native-sso-1_0.html), [Second Implementer's Draft](https://openid.net/specs/openid-connect-native-sso-1_0-ID2.html) | Implements ID Token `ds_hash`, `device_secret`, refresh-family liveness checks, and destination-client binding. This is draft 07 / ID2 compatibility, not a Final Specification claim. |
| OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1 | Not supported (planned) | Not advertised; no Federation Entity Configuration or `/.well-known/openid-federation` endpoint | [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html), [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) | Planned as a separate federation trust-chain implementation, not as ordinary OIDC RP login. |
| OIDC Implicit OP | Never supported | No enablement switch; not advertised | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | Excluded by OAuth Security BCP / OAuth 2.1 direction. |
| OIDC Hybrid OP | Never supported | No enablement switch; not advertised | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OIDC Core defines Hybrid Flow, but it reintroduces front-channel ID Token/access-token delivery into an authorization-code interaction. RFC 9700 deprecates implicit front-channel token delivery; the supported interactive profile remains code flow plus PKCE/sender constraints. |
| Resource Owner Password Credentials | Never supported | No enablement switch; rejected if requested | [RFC 6749 Section 4.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.3), [RFC 9700 Section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OAuth Security BCP says the password grant MUST NOT be used. |
| Legacy OIDF Dynamic OP certification profile | Never supported | No enablement switch; the OIDF Dynamic OP plan is excluded from supported matrices | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | That certification profile requires implicit/hybrid metadata; RFC 7591/RFC 7592 dynamic registration remains supported. |

## Planned specifications and drafts

This section records standards work that is relevant to integration planning but
is not necessarily a current discovery or registration metadata claim.
`Supported` means the current implementation provides the behavior described by
that row's linked specification or draft. `Not supported (audit pending)` means
related stable specifications or adjacent flows may exist, but the linked draft
has not been audited requirement by requirement. `Not supported (planned)` means
no executable implementation or complete profile boundary is available yet.

| Specification or draft | Current status | Why it is not a current advertised capability | Completion condition |
| --- | --- | --- | --- |
| OAuth 2.1 Authorization Framework | Supported (draft-15-compatible implementation) | [draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) is still a draft, not a final RFC. The implementation already aligns with code flow, S256 PKCE, no implicit/password grants, exact redirect matching, and secure defaults. | After RFC publication, map every final requirement to code, metadata, negative tests, and conformance evidence. |
| OAuth 2.0 for Browser-Based Applications | Supported (audited against draft-27) | [draft-ietf-oauth-browser-based-apps-27](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) is in the RFC Editor queue. Current behavior already uses code + S256 PKCE, rejects implicit, avoids browser front-channel token delivery, and has a draft-27 delta audit. | Re-audit SPA, BFF, and browser-client guidance after RFC publication; do not add a false runtime profile or discovery claim. |
| Cross-Device Flows: Security BCP | Not supported (audit pending) | [draft-ietf-oauth-cross-device-security-16](https://datatracker.ietf.org/doc/draft-ietf-oauth-cross-device-security/) is a BCP for multiple flows, not a single endpoint. Device Grant, CIBA, and Native SSO exist as separate modules, but they have not been audited requirement by requirement against this BCP. | Apply the final BCP to those cross-device flows; do not automatically expand grant types. |
| OAuth Security BCP Update | Not supported (audit pending) | [draft-ietf-oauth-security-topics-update-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/) is an update track for [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html). RFC 9700 behavior is supported, but this update draft has not been audited requirement by requirement. | Treat it as an RFC 9700 delta audit; update behavior, metadata, tests, and documentation together. |
| JWT BCP / JWT Assertion bis | Not supported (audit pending) | [draft-ietf-oauth-rfc8725bis-07](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/) and [draft-ietf-oauth-rfc7523bis-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) are not final yet. Current behavior supports RFC 8725/RFC 7523, not these bis drafts. | Re-audit algorithm allowlists, audience, replay, key binding, cross-JWT confusion, and `private_key_jwt`. |
| OAuth Client Attestation | Supports the draft-07 version fixed by OpenID4VCI 1.0; disabled by default | [draft-ietf-oauth-attestation-based-client-auth-07](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07) is the version explicitly fixed by OpenID4VCI 1.0 Final. The implementation supports `attest_jwt_client_auth` and binds refresh tokens to the Client Instance `cnf` key. It is advertised only when the module is enabled and client policy requires it. | Later drafts and the eventual RFC require a separate delta audit; breaking syntax changes are not mixed into the HAIP 1.0 / OpenID4VCI 1.0 profile. |
| FAPI 2.0 HTTP Signatures | Experimental support; disabled by default; stable-spec audit pending | The [FAPI 2.0 HTTP Signatures working draft](https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html) is not a Final Specification. The persisted `http_message_signatures` module controls `/fapi/resource`, and there is no dedicated OIDF plan. | Decide whether to advertise only after the spec stabilizes or an adopter requires it; every newer draft or Final requires a delta audit. |
| Refresh Token and Authorization Expiration | Not supported (planned) | [draft-ietf-oauth-refresh-token-expiration-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-refresh-token-expiration/) requires explicit authorization and refresh-token lifetime modeling; current metadata does not claim these expiration semantics. | Define authorization lifetime, refresh-family state, revocation semantics, metadata, and E2E tests. |
| First-Party Applications | Not supported (planned) | [draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/) depends on same-party deployment assumptions that must not be generalized to third-party clients. | Define same-party/BFF boundaries and prove third-party client isolation remains intact. |
| Client ID Metadata Document | Not supported (planned) | [draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) implies remote public-client metadata retrieval; there is no trusted fetch, cache, or conflict model yet. | Define trusted sources, cache behavior, downgrade handling, conflicts, DCR interaction, and failure policy. |
| SPIFFE Client Authentication | Not supported (planned) | [draft-ietf-oauth-spiffe-client-auth-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) requires a deployed SPIFFE trust domain, which ordinary OAuth/OIDC deployments do not provide. | Add trust-bundle validation, certificate/identity lifecycle, resource-server verification, and metadata isolation. |
| Identity Assertion / Identity Chaining / Transaction Tokens | Not supported (planned) | These drafts cover cross-domain identity assertions, chained authorization, and workload call chains; there is no issuer/trust-anchor, subject-mapping, Transaction Token Service, or resource-server verification model yet. | Complete trust-domain, replay, audit, revocation, resource-server verification, and least-privilege propagation design. |
| Token Status List | Not supported (planned) | [draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) primarily fits OpenID4VC credential status; no credential status publication or privacy model is currently advertised. | Implement with the OpenID4VC issuer/verifier status model, not as a generic OAuth token-status endpoint. |

The following are watchlist items, not planned implementation commitments:

| Draft or protocol family | Status | Why it is watched |
| --- | --- | --- |
| GNAP Core / GNAP Resource Server Connections | Watch only | [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html) and [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html) are adjacent authorization protocols and useful design references, but they are not OAuth/OIDC switches. |
| Agent Authorization Profile | Watch only | [draft-aap-oauth-profile-01](https://datatracker.ietf.org/doc/draft-aap-oauth-profile/) is relevant to AI-agent delegated access but is not stable enough for an implementation claim. |
| Delegated Authorization / Actor Chain | Watch only | [draft-li-oauth-delegated-authorization-02](https://datatracker.ietf.org/doc/draft-li-oauth-delegated-authorization/) and [draft-mw-oauth-actor-chain-01](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/) overlap with token exchange, actor delegation, and audit chains. |
| Global Token Revocation | Watch only | [draft-parecki-oauth-global-token-revocation-06](https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/) is operationally useful for compromise response but needs strict blast-radius, audit, and multi-client policy. |
| RAR / Resource Metadata extensions | Watch only | [draft-zehavi-oauth-rar-metadata-05](https://datatracker.ietf.org/doc/draft-zehavi-oauth-rar-metadata/), [draft-skokan-oauth-resource-response-02](https://datatracker.ietf.org/doc/draft-skokan-oauth-resource-response/), and [draft-mcguinness-oauth-rfc9728bis-01](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-rfc9728bis/) may improve typed permissions and protected-resource metadata. |

## Discoverable endpoints

Relying parties should read endpoints from discovery. A baseline deployment can
expose the following endpoints when the matching modules are enabled:

| Endpoint | Path | Advertisement rule |
| --- | --- | --- |
| OIDC discovery | `/.well-known/openid-configuration` | Always present for OIDC deployments. |
| OAuth authorization-server metadata | `/.well-known/oauth-authorization-server` | Present for OAuth/OIDC deployments. |
| Protected resource metadata | `/.well-known/oauth-protected-resource` | Present for resource-server metadata. |
| FAPI resource metadata | `/.well-known/oauth-protected-resource/fapi/resource` | Present for the FAPI resource surface. |
| JWKS | `/jwks.json` | Publishes active non-retired signing keys and previous keys still in use. |
| Authorization | `/authorize` | Supports code-flow authorization requests. |
| PAR | `/par` | Advertised/required according to profile and client policy. |
| Token | `/token` | Handles supported grant types and client authentication methods. |
| UserInfo | `/userinfo` | Requires an access token with `openid` scope. |
| Introspection | `/introspect` | For protected resource validation and profile-specific protected responses. |
| Revocation | `/revoke` | For refresh/access token revocation where applicable. |
| Logout | `/logout` | RP-Initiated Logout with exact registered redirect URI validation. |
| Dynamic registration | `/register` | Advertised only when a non-empty initial access token is configured. |
| Device authorization | `/device_authorization` | Advertised when its runtime module is active; client use still requires grant and cross-device policy. |

Discovery metadata must be treated as authoritative. If a field is absent, the
deployment is not claiming that capability.

## Minimum supported integration

New integrations should use Authorization Code Flow with S256 PKCE.

| Field | Recommended value |
| --- | --- |
| Issuer | `https://issuer.example` |
| Discovery | `https://issuer.example/.well-known/openid-configuration` |
| JWKS | `https://issuer.example/jwks.json` |
| Authorization endpoint | `https://issuer.example/authorize` |
| Token endpoint | `https://issuer.example/token` |
| UserInfo endpoint | `https://issuer.example/userinfo` |
| Logout endpoint | `https://issuer.example/logout` |
| Response type | `code` |
| Response mode | `query`; `form_post` when the client and RP both require it |
| PKCE | `S256` |
| Scopes | Start with `openid`; add only the claims the RP actually needs |
| Client authentication | Public clients use `none` with PKCE; confidential clients should use `private_key_jwt`, mTLS, or `client_secret_basic` according to their risk profile |

The relying party should discover endpoints from metadata instead of hardcoding
paths. Hardcoded paths are shown only to make the integration shape explicit.

## Client registration

The provider supports two client onboarding models:

1. Static administrative registration.
2. RFC 7591 / RFC 7592 Dynamic Client Registration when an initial access
   token is configured.

Without an initial access token, dynamic registration is disabled. A
dynamically registered client receives a `registration_client_uri` and a
registration access token for its own management lifecycle, but only a
baseline security policy.

Accepted client metadata includes the usual OIDC/OAuth fields:

| Metadata | Status | References | Notes |
| --- | --- | --- | --- |
| `client_name` | Supported | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [OpenID Connect Registration](https://openid.net/specs/openid-connect-registration-1_0.html) | Display metadata; login UI reads authoritative server-side registration data. |
| `redirect_uris` | Required for authorization-code clients | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Exact matching. |
| `post_logout_redirect_uris` | Supported | [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | Exact matching for logout. |
| `response_types` | `["code"]` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Implicit and hybrid values are rejected. |
| `grant_types` | Per-client allowlist | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) | Must match implemented grants and client policy. |
| `scope` | Per-client allowlist | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Requests cannot widen beyond registration. |
| `token_endpoint_auth_method` | Supported methods listed below | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [OpenID Connect Registration](https://openid.net/specs/openid-connect-registration-1_0.html) | FAPI profiles narrow the acceptable set. |
| `jwks` | Supported | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) | Used for client signing, encryption, and self-signed mTLS certificate material. |
| `jwks_uri` | Supported under constrained remote-document policy | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | Only safe HTTPS sources accepted by policy. |
| `request_uris` | Supported under constrained baseline policy | [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | Exact HTTPS registration; FAPI profiles prefer PAR. |
| `userinfo_signed_response_alg` | Supported | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | The selected algorithm must be advertised and backed by an active key. |
| `userinfo_encrypted_response_alg` / `userinfo_encrypted_response_enc` | Supported with valid client encryption key | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | Uses the narrow JWE policy below. |
| `authorization_signed_response_alg` | Supported for JARM-capable clients/profiles | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | Must be executable by the active keyset. |
| `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc` | Supported for nested encrypted JARM | [JARM](https://openid.net/specs/oauth-v2-jarm.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | Requires a valid client encryption key. |
| `initiate_login_uri` | Supported; HTTPS only | [Third-Party Initiated Login](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html) | OP-side metadata for RP-initiated login initiation. |
| `software_statement` | Not supported | [RFC 7591 Section 2](https://www.rfc-editor.org/rfc/rfc7591.html#section-2) | RFC 7591 defines software statements as signed client metadata from a trusted statement issuer. No software-statement issuer, trust anchor, or verification policy is configured or advertised. |

Recommended baseline registration metadata:

```json
{
  "client_name": "Example Application",
  "redirect_uris": ["https://app.example/oauth/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

For public browser, native, or SPA clients:

```json
{
  "client_name": "Example Public Application",
  "redirect_uris": ["https://app.example/oauth/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
```

Public clients must send S256 PKCE. Baseline confidential OIDC code-flow
compatibility may accept a request without PKCE, but new integrations should
still send PKCE. FAPI, sender-constrained, public, and non-OIDC authorization
code clients must use S256 PKCE.

## Request, scope, and resource boundaries

The server applies subset rules at every step that can widen authority:

- a token request cannot widen the scopes or resource indicators granted by an
  authorization request;
- a refresh request cannot exceed the grant's stored scope/resource boundary;
- a client cannot request scopes or resources outside its current registration;
- resource indicators use RFC 8707 repeated `resource` parameters;
- the legacy OAuth `audience` parameter is not accepted for authorization or
  token requests outside the explicit Token Exchange profile.

Use the smallest scope set the application needs. Start with `openid`, then add
`profile`, `email`, `phone`, or API-specific scopes only when the RP consumes
those claims or resources.

Common OIDC scopes:

| Scope | Purpose |
| --- | --- |
| `openid` | Required for OIDC authentication and ID Token issuance. |
| `profile` | Enables standard profile claims when policy permits them. |
| `email` | Enables email claims when policy permits them. |
| `phone` | Enables phone claims when policy permits them. |
| `offline_access` | Enables refresh-token issuance only when the client and consent policy allow it. |

## ID Token, UserInfo, and access token audiences

The ID Token is for the relying party. Its `aud` identifies the client that
requested authentication.

Access tokens are for resource servers. A relying party should not infer access
token semantics from the ID Token. If a resource server needs to validate access
tokens, use the resource-server verifier guidance or introspection endpoint
appropriate for that deployment.

UserInfo requires an access token with `openid` scope. Per-client signed or
encrypted UserInfo can be configured when the client has registered the required
metadata and keys.

## Algorithms and request objects

The server advertises only algorithms that the active runtime keyset can execute.

Current integration rules:

- ID Token, UserInfo, JARM, and Request Object algorithms must be selected from
  discovery metadata and client registration policy;
- unsigned Request Objects (`alg=none`) are never supported;
- signed Request Objects use asymmetric algorithms and registered client keys;
- external `request_uri` is available only as a constrained baseline feature for
  exact HTTPS URIs registered through authenticated dynamic registration;
- FAPI profiles continue to use server-issued PAR request URIs instead of
  client-hosted `request_uri` documents;
- ID Token signing defaults should be read from discovery, not assumed by the
  RP.

For high-assurance clients, prefer PAR, signed Request Objects, JARM, DPoP, or
mTLS according to the selected profile.

Do not configure a relying party to require an algorithm that the current
discovery document does not advertise. Metadata truth is a hard contract in
this implementation: advertised algorithms must be executable, and unadvertised algorithms
must not be assumed.

The JOSE tables intentionally separate two cases: algorithms excluded by a
security boundary, and optional JOSE algorithms that are standards-defined but
not advertised by the current metadata. For optional unadvertised algorithms,
the cited RFC is the syntax reference, not a statement that the RFC forbids that
algorithm.

### JWT signing algorithms

The following table summarizes the JOSE signing algorithms supported
for OIDC/OAuth client-configurable surfaces. A deployment may advertise a subset
when the active keyset or runtime profile is narrower.

| Algorithm | Key type | Hashing algorithm | Use | Status / surfaces | References | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `EdDSA` | Ed25519 | EdDSA | `sig` | Supported for Request Objects, client assertions, UserInfo, JARM, introspection/revocation response JWTs where the surface is enabled | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | Requires an active Ed25519 signing key or registered client Ed25519 public key, depending on direction. |
| `RS256` | RSA | SHA-256 | `sig` | Supported for ID Token baseline compatibility, Request Objects, client assertions, UserInfo, JARM, introspection/revocation response JWTs where enabled | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Included for broad OIDC interoperability. RSA keys must meet the deployment key-strength policy. |
| `ES256` | ECDSA P-256 | SHA-256 | `sig` | Supported for Request Objects, client assertions, UserInfo, JARM, introspection/revocation response JWTs where enabled | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | Requires a P-256 key accepted by the active keyset/client JWK policy. |
| `PS256` | RSA-PSS | SHA-256 | `sig` | Supported for FAPI/FAPI-CIBA, Request Objects, client assertions, UserInfo, JARM, introspection/revocation response JWTs where enabled | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [FAPI 2.0 Security](https://openid.net/specs/fapi-2_0-security-profile.html) | Preferred/required by several high-assurance profiles. |
| `HS256`, `HS384`, `HS512` | Symmetric | SHA-256 / SHA-384 / SHA-512 | `sig` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [OpenID Connect Core Section 10.1](https://openid.net/specs/openid-connect-core-1_0.html#SigEnc), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | OIDC derives symmetric signing keys from `client_secret` and forbids symmetric signatures for public clients. Shared secrets are stored as verifier material and are not used as OP response-signing or Request Object-verification keys. |
| `RS384`, `RS512` | RSA | SHA-384 / SHA-512 | `sig` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional JOSE algorithms, but not advertised; clients must use the advertised algorithm allowlist. |
| `ES384`, `ES512` | ECDSA P-384 / P-521 | SHA-384 / SHA-512 | `sig` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional JOSE algorithms, but not advertised; clients must use the advertised algorithm allowlist. |
| `PS384`, `PS512` | RSA-PSS | SHA-384 / SHA-512 | `sig` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional JOSE algorithms, but not advertised; use `PS256` where RSA-PSS is required. |
| `none` | None | None | N/A | Never supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1), [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4) | Unsigned ID Tokens and unsigned Request Objects are never supported. Request Objects must be signed or signed and encrypted. |

### Request Object algorithms

Request Objects are accepted only when the client and runtime policy allow that
request path.

| Algorithm | Key type | Hashing algorithm | Use | Status / condition | References | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `EdDSA` | Ed25519 | EdDSA | `sig` | Accepted with registered client JWK or resolved `jwks_uri` key using `use=sig` and `alg=EdDSA` | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | Supported for signed Request Objects and client assertions. |
| `RS256` | RSA | SHA-256 | `sig` | Accepted with registered client JWK or resolved `jwks_uri` key using `use=sig` and `alg=RS256` | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | Baseline interoperability option. |
| `ES256` | ECDSA P-256 | SHA-256 | `sig` | Accepted with registered client JWK or resolved `jwks_uri` key using `use=sig` and `alg=ES256` | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | Supported asymmetric option. |
| `PS256` | RSA-PSS | SHA-256 | `sig` | Accepted with registered client JWK or resolved `jwks_uri` key using `use=sig` and `alg=PS256` | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | High-assurance/FAPI-compatible option. |
| `none` | None | None | N/A | Never supported | [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Rejected because signed Request Objects are required for protected request-object surfaces; expected OIDF skips for unsigned modules are bounded and explicit. |
| `HS*`, `RS384`, `RS512`, `ES384`, `ES512`, `PS384`, `PS512` | Various | Various | `sig` | Not accepted | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1), [RFC 9101 Section 6.1](https://www.rfc-editor.org/rfc/rfc9101.html#section-6.1) | Standards-defined JOSE algorithms, but not advertised for Request Objects. Request Object validation uses a strict per-client algorithm allowlist. |

External `request_uri` is not a general internet fetch feature. It is accepted
only for exact HTTPS URIs that were registered through authenticated client
metadata and that pass the deployment's remote-document safety policy. FAPI
profiles continue to prefer PAR and server-issued request URIs.

### JWE encryption algorithms

The provider deliberately exposes a narrow JWE set for client-encrypted UserInfo,
encrypted JARM, and other client-bound response JWT surfaces.

Key management algorithms:

| Algorithm | Key type | Use | Status / JWK condition | References | Notes |
| --- | --- | --- | --- | --- | --- |
| `RSA-OAEP-256` | RSA | `enc` | Supported; client JWK must contain an RSA public key with `use=enc`, `alg=RSA-OAEP-256`, and a `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | RSA-OAEP using SHA-256. |
| `ECDH-ES` | ECDH-ES with P-256 | `enc` | Supported; client JWK must contain a public P-256 EC key with `use=enc`, `alg=ECDH-ES`, and a `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | Direct ECDH key agreement for client response encryption. |
| `ECDH-ES+A256KW` | ECDH-ES with P-256 and AES-256 Key Wrap | `enc` | Supported; client JWK must contain a public P-256 EC key with `use=enc`, `alg=ECDH-ES+A256KW`, and a `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | Preferred ECDH key-wrap mode. |
| `ECDH-ES+A128KW` | ECDH-ES with P-256 and AES-128 Key Wrap | `enc` | Supported; client JWK must contain a public P-256 EC key with `use=enc`, `alg=ECDH-ES+A128KW`, and a `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | Compatibility ECDH key-wrap mode. |
| `RSA1_5` | RSA | `enc` | Never supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.2](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.2) | Rejected by the algorithm allowlist; do not configure clients to require it. |
| `RSA-OAEP` | RSA | `enc` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional JOSE algorithm, but not advertised; use `RSA-OAEP-256`. |
| `ECDH-ES+A192KW` | ECDH-ES with AES-192 Key Wrap | `enc` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional JOSE algorithm, but not advertised. |
| `A128KW`, `A256KW` | Symmetric AES Key Wrap | `enc` | Not supported (planned) | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [OpenID Connect Core Section 10.2](https://openid.net/specs/openid-connect-core-1_0.html#Encryption), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Planned only for confidential clients with a separate encrypted response-key model; current one-way client-secret storage must not be reused as a decryption key. |
| `A192KW`, `dir`, `PBES2-*` | Symmetric/password-based | `enc` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional JOSE algorithms, but not advertised by the response-encryption allowlist. |

Content encryption algorithms:

| Algorithm | Status | References | Notes |
| --- | --- | --- | --- |
| `A256GCM` | Supported | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | Required when encrypted client response JWTs are configured. |
| `A128GCM`, `A192GCM` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional content encryption algorithms, but not advertised; use `A256GCM`. |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | Not supported | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Standards-defined optional content encryption algorithms, but not advertised; use `A256GCM`. |

## Response types and response modes

Supported interactive response type:

| Name | Status | Value | References | Notes |
| --- | --- | --- | --- | --- |
| Authorization Code | Supported | `code` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) | The only interactive OIDC response type. Public clients, FAPI clients, sender-constrained clients, and non-OIDC code-flow clients must use S256 PKCE. |
| Implicit ID Token | Never supported | `id_token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core defines the value, but it delivers the ID Token through the browser front channel without a token-endpoint exchange. The interactive profile keeps ID Token issuance behind authorization-code exchange. |
| Implicit Access Token | Never supported | `token` | [RFC 6749 Section 4.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.2), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | Excluded because the implicit grant is deprecated by the OAuth Security BCP. |
| Implicit ID Token + Access Token | Never supported | `id_token token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | Excluded because it depends on implicit front-channel token delivery. |
| Hybrid Code + ID Token | Never supported | `code id_token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core defines the value, but it sends an ID Token through the browser front channel before token-endpoint exchange. That preserves the same exposure class RFC 9700 moves away from for implicit-style responses. |
| Hybrid Code + Token | Never supported | `code token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core defines the value, but it returns an access token through the browser front channel. RFC 9700 deprecates this exposure pattern. |
| Hybrid Code + ID Token + Token | Never supported | `code id_token token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | Combines both front-channel ID Token and access-token delivery with code flow; the supported interactive profile keeps those tokens behind the back-channel token endpoint. |

Supported response modes for baseline OIDC:

| Name | Status | Value | References | Conditions | Notes |
| --- | --- | --- | --- | --- | --- |
| Query String | Supported | `query` | [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html) | Baseline code flow and profiles that allow plain authorization responses | Default mode for `response_type=code` when no stricter profile applies. |
| OAuth 2.0 Form Post | Supported | `form_post` | [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) | Baseline code flow; not available for FAPI profiles that require stricter response policy | Returns a no-store, CSP-protected auto-submit HTML form to the registered redirect URI. |
| JARM | Supported | `jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | JARM module/profile/client metadata enabled | Signed authorization response JWT; may be nested JWE when client encryption metadata is valid. |
| Form Post JARM | Not supported | `form_post.jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | N/A | Standards-defined response mode, but not advertised; use `jwt` for JARM or `form_post` for plain code form-post. |
| Query JARM | Not supported | `query.jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | N/A | Standards-defined response mode, but not advertised as a distinct response mode. |
| Fragment JARM | Not supported | `fragment.jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | N/A | Standards-defined response mode, but not advertised. |
| Fragment | Never supported | `fragment` | [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | N/A | Front-channel token delivery is never supported. |

`form_post` does not enable implicit or hybrid token delivery. It is only a
browser transport for supported authorization responses.

## Grant types

| Grant type | Status | References | Advertisement / enablement rule | Notes |
| --- | --- | --- | --- | --- |
| `authorization_code` | Supported | [RFC 6749 Section 4.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Client grant allowlist includes it | Primary OIDC login grant. |
| `refresh_token` | Supported | [RFC 6749 Section 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) | Client policy, consent, and grant allow it | Never returned from implicit/front-channel flows. |
| `client_credentials` | Supported | [RFC 6749 Section 4.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4) | Client grant allowlist includes it | OAuth resource access only; not an OIDC login flow. |
| `urn:ietf:params:oauth:grant-type:device_code` | Supported | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) | Device Authorization Grant module enabled and client allowlist includes it | Disabled deployments do not claim this grant. |
| OpenID CIBA grant | Supported | [OpenID CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html) | CIBA module enabled and client registered for poll or ping delivery | FAPI-CIBA supports poll and ping only; push delivery mode is never supported. |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | Supported | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | Client grant allowlist includes it | JWT bearer grant for bounded resource access. |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Supported | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) | Explicit bounded local profile/client policy | Not a generic arbitrary delegation mechanism. |
| `password` | Never supported | [RFC 6749 Section 4.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.3), [RFC 9700 Section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4) | N/A | RFC 9700 says this grant MUST NOT be used. |
| `implicit` | Never supported | [RFC 6749 Section 4.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.2), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | N/A | OAuth Security BCP deprecates implicit front-channel token delivery. |

## Client authentication

| Method | Status | References | Client type / conditions | Notes |
| --- | --- | --- | --- | --- |
| `none` | Supported | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | Public clients only; S256 PKCE required | Not allowed for confidential-client grants. |
| `client_secret_basic` | Supported | [RFC 6749 Section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Confidential clients with stored secret | Baseline shared-secret method. |
| `client_secret_post` | Supported, compatibility only | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Confidential clients with stored secret; excluded by FAPI profiles | Prefer `client_secret_basic`, `private_key_jwt`, or mTLS. |
| `client_secret_jwt` | Not supported | [OpenID Connect Core Section 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), [RFC 9700 Section 2.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5) | N/A | Standards-defined for confidential clients, but not advertised. JWT client assertions use `private_key_jwt`; high-assurance clients should use asymmetric or sender-constrained authentication. |
| `private_key_jwt` | Supported | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | Client has a valid registered signing key | Supported signing algorithms are `EdDSA`, `RS256`, `ES256`, and `PS256`; high-assurance profiles may narrow this set. |
| `tls_client_auth` | Supported | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html), [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | Trusted mTLS/proxy boundary configured; client metadata contains exactly one certificate subject DN or SAN selector | DN values are parsed and canonically compared; IP SAN values are compared as binary addresses. An administrator certificate pin may only narrow this match. |
| `self_signed_tls_client_auth` | Supported | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) | Trusted mTLS/proxy boundary configured; client has registered self-signed certificate material | Advertised only when deployment mTLS support is active. |
| `attest_jwt_client_auth` | Supported | [OAuth Client Attestation draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) | Client-attestation module enabled and client policy requires it | Disabled deployments do not claim this client authentication method. |

High-assurance integrations should prefer asymmetric or sender-constrained
client authentication. FAPI profiles exclude shared-secret POST authentication.

For `private_key_jwt`, use the issuer or token endpoint audience accepted by
the deployment profile and keep assertion lifetimes short. For mTLS, register
the correct certificate-bound client metadata and make sure the deployment's
trusted proxy/mTLS termination boundary is configured before advertising mTLS
metadata.

### Deployment mTLS trust lifecycle

[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) defines client
authentication, certificate-subject metadata, and certificate-bound access
tokens. It does not define an operator approval endpoint or how a deployment
changes its reverse proxy trust store. [RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html)
provides the applicable trust-anchor-management security model, while the HTTP
control plane described here is product behavior rather than an OAuth endpoint.
RFC 8705 Section 7.4 also warns that a certificate with the same subject from a
different trusted CA can impersonate a PKI client unless the accepted CA set is
strictly constrained.

- An active user may apply only for a client granted to that user through the
  normal client-access workflow. The client must be active and use
  `tls_client_auth` or certificate-bound tokens.
- A `tls_client_auth` client using this public CA-approval path must also have
  an administrator-registered SHA-256 leaf-certificate pin. The pin narrows
  the RFC 8705 subject match and prevents another approved CA from minting a
  same-subject certificate that authenticates as that client. A client using
  `private_key_jwt` plus certificate-bound tokens does not use the certificate
  as its authentication identity and therefore does not require this extra
  pin merely to request sender-constrained tokens.
- The input is exactly one current RFC 5280 CA certificate, at most 16 KiB,
  with critical CA Basic Constraints, critical `keyCertSign`, and an accepted
  RSA or NIST-curve public key.
- A different active administrator approves or rejects the request. Rejection
  and revocation require bounded reasons; every state change is recorded in the
  same database transaction.
- A client may have at most 8 current anchors and 4 pending requests; one user
  may have 16 pending requests per tenant; and a tenant may have at most 128
  distinct current anchors. Creation and approval are serialized per tenant.
- The reverse proxy installs only the exported approved bundle. Application
  authentication still enforces the client's single registered RFC 8705
  subject selector and, for publicly approved PKI trust, its leaf-certificate
  pin. Self-signed clients remain bound to their registered certificate key.
  Trusting a CA at the TLS layer therefore does not authorize every certificate
  issued by it at the OAuth layer.
- Subject DNs must be valid RFC 4514 values and are compared with OpenSSL's
  canonical X.509 name comparison, following the RFC 4517
  `distinguishedNameMatch` requirement. DNS and email domains are
  case-insensitive, URI SANs are exact strings, and IP SANs are compared as
  parsed binary addresses. Malformed or ambiguous selector data fails closed.

## Logout and sessions

The provider supports RP-Initiated Logout at `/logout` and validates registered
`post_logout_redirect_uri` values exactly. Logout integrations should use
metadata discovery and register all post-logout redirect URIs explicitly.

Front-channel and session-management behavior is profile-tested in the OIDF
matrix. Browser-sensitive logout/session flows should be tested separately from
high-concurrency authorization matrices because they depend on shared browser
state.

## Third-party initiated login

The provider supports the OP-side metadata required for OpenID Connect
Third-Party-Initiated Login:

- `initiate_login_uri` can be registered through dynamic client metadata;
- the URI must be HTTPS;
- non-HTTPS metadata is rejected.

This profile does not add an OP-side initiation endpoint. The initiation URI is
an RP endpoint; the RP uses it to start a normal authorization request against
the provider.

## Dynamic registration is not legacy Dynamic OP

The provider implements secure RFC 7591 / RFC 7592 dynamic client registration, but
the legacy OIDF Dynamic OP certification profile is never supported. That
profile requires discovery metadata for implicit and hybrid flows, which are
excluded by RFC 9700 and the OAuth 2.1 direction described below.

Use this terminology precisely:

- "Dynamic Client Registration" means RFC 7591 / RFC 7592 client lifecycle
  support conditional on a configured initial access token.
- "Dynamic OP certification profile" is never supported.

## Specification-backed non-implementation boundaries

The following decisions are not local preferences. They are derived
from current IETF / OpenID security guidance and are encoded as implementation
boundaries.

| Capability | Status | Normative or current security source | Reason |
| --- | --- | --- | --- |
| Implicit grant and implicit OIDC response types | Never supported | [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OAuth Security BCP deprecates implicit because browser front-channel token delivery has weaker leakage and replay properties than code flow with PKCE. This boundary also excludes OIDC implicit ID Token responses from the supported interactive profile. |
| Hybrid response types | Never supported | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core defines Hybrid Flow, but it exposes ID Tokens and/or access tokens through the browser front channel before the token endpoint. RFC 9700 deprecates implicit front-channel token delivery; the supported interactive profile remains authorization code with PKCE/sender constraints where required. |
| Resource Owner Password Credentials | Never supported | [RFC 9700 Section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OAuth Security BCP states that the password grant MUST NOT be used because it exposes user credentials to clients and does not compose with modern MFA/passkey authentication. |
| Unsigned Request Objects (`alg=none`) | Never supported | [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | Protected request-object surfaces require signed Request Objects; JWT BCP requires applications to allow only algorithms that meet the application's security requirements. |
| Query-string bearer tokens | Never supported | [RFC 6750 Section 2.3](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.3), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | RFC 6750 documents the query method but says it is not recommended because URLs are commonly logged and leaked. |
| CIBA push mode | Never supported | [OpenID CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html) | The implemented and tested FAPI-CIBA support surface is poll and ping; push would introduce direct token delivery to the client callback and is outside the supported profile set. |

## Security boundaries

The following are permanently unsupported for new integrations:

- implicit grant;
- OIDC Implicit OP;
- OIDC Hybrid OP;
- Resource Owner Password Credentials grant;
- unsigned Request Objects;
- query-string bearer tokens;
- FAPI form-body bearer tokens;
- CIBA push mode.

These are specification-backed implementation boundaries, not missing configuration
switches. Do not attempt to enable them with hidden deployment options.

## Metadata truth and deployment flags

Several capabilities are controlled by runtime modules or profile settings. The
server must not advertise disabled or incomplete behavior.

| Capability | Required deployment state before advertising |
| --- | --- |
| Dynamic Client Registration | Non-empty `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`. |
| Device Authorization Grant | Active runtime module, client grant allowlist includes device code, and `allow_cross_device_flows=true`. |
| CIBA | Active runtime module, registered poll/ping metadata and grant, and `allow_cross_device_flows=true`. |
| mTLS client authentication / sender constraints | Trusted mTLS/proxy boundary configured and client metadata registered. |
| FAPI profiles | Per-client `security_policy.assurance=fapi2` plus sender constraints and compatible client authentication. |
| UserInfo/JARM encryption | Client metadata includes valid encryption preferences and exactly one usable public key for the selected algorithm. |
| OpenID4VCI / OpenID4VP | Corresponding runtime module enabled, credential/trust configuration complete, and public metadata generated from that configuration. |

## Integration checklist

Before putting a relying party into production:

1. Configure the client with a public HTTPS redirect URI.
2. Use `response_type=code`.
3. Send S256 PKCE, including for confidential clients.
4. Request only required scopes.
5. Discover endpoints from `/.well-known/openid-configuration`.
6. Validate ID Token `iss`, `aud`, `exp`, `iat`, `nonce` when used, and
   signature.
7. Do not treat the ID Token as an API access token.
8. Register post-logout redirect URIs exactly when logout is used.
9. Use `private_key_jwt`, mTLS, DPoP, PAR, or JARM for higher-risk clients.
10. Re-check discovery metadata after changing runtime-module state, then verify
    the target client's explicit policy.

## Normative references

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Third-Party Initiated Login 1.0](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591.html)
- [OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592.html)
- [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OAuth 2.0 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
- [JWT Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101.html)
