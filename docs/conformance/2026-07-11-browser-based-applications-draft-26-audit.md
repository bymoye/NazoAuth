# OAuth Browser-Based Applications Draft-26 Audit

Date: 2026-07-11

## Conclusion and claim boundary

NazoAuth was audited against `draft-ietf-oauth-browser-based-apps-26`, which
was still in the RFC Editor publication queue without an RFC number on the
review date. This is a dated security audit, not a final RFC conformance or
certification claim.

The audit confirms two intentionally different architectures:

- NazoAuthWeb is a same-origin first-party application using server-managed
  sessions. Unsafe authenticated `/auth/me/*` operations are CSRF-protected;
  unauthenticated `/auth/*` entry points retain their separate controls. The
  Web application does not receive or persist OAuth access tokens, refresh
  tokens, ID Tokens, client secrets, private keys, OIDF private configuration,
  or PKCE verifiers.
- Third-party browser applications are public OAuth clients. They use
  Authorization Code with S256 PKCE and exact redirect URIs; they cannot become
  confidential by embedding a static secret in JavaScript.

This change tightens `/token` and `/revoke` CORS to POST-only and removes the
session-only `X-CSRF-Token` header from public OAuth CORS. `/userinfo` retains
GET/POST bearer or DPoP access. None of these public OAuth routes authorize
browser credentials.

Primary source:

- <https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/26/>

Coordinated NazoAuthWeb evidence is pinned to commit
`304906b30340a735580edd18adb90e567c5a5f3d`, reviewed in
<https://github.com/nazozero/NazoAuthWeb/pull/3>. The coordinated server change
is <https://github.com/nazozero/NazoAuth/pull/53>.

## Requirement and evidence matrix

| Draft-26 area | NazoAuth role | Current control | Evidence | Outcome |
| --- | --- | --- | --- | --- |
| BFF architecture | First-party web/session backend | NazoAuthWeb receives an opaque secure session, not OAuth tokens; unsafe authenticated session writes require CSRF. | `logout_response_clears_session_and_csrf_cookies_without_cacheable_state`; `csrf_response_returns_token_body_and_matching_cookie`; NazoAuthWeb commit `304906b` | Covered for the first-party application. |
| Authorization endpoint | Authorization server | `/authorize` is a navigation endpoint and has no CORS middleware. | `authorization_endpoint_is_not_cors_enabled` | Covered. |
| Public browser client classification | Authorization server | A browser client is public and cannot authenticate with a bundled static secret. | `prepare_client_insert_rejects_secret_auth_for_public_clients`; `dynamic_registration_requires_pkce_for_public_or_sender_constrained_clients` | Covered. |
| Authorization Code + PKCE | Authorization server | Code-only flow and S256 PKCE for public clients; plain, missing, malformed, and wrong verifiers are rejected. | `authorization_request_requires_pkce_for_public_client`; `authorization_pkce_rejects_challenge_with_plain_method`; `token_authorization_code_marks_failed_states_for_redirect_pkce_and_audience_errors` | Covered. |
| PAR separation | Authorization server | PAR remains a backchannel endpoint with client authentication and no browser CORS; FAPI requirements do not become a browser shortcut. | `authorization_get_requires_par_before_untrusted_runtime_parameters`; `par_rejects_non_form_content_type_before_client_lookup`; `par_fapi2_rejects_shared_secret_client_auth_after_authentication` | Covered. |
| Token endpoint CORS | Authorization server | Exact configured origins, POST only, no credentials, no CSRF header, explicit DPoP/content-type support. | `browser_token_management_cors_allows_post_dpop_without_credentials`, `production_token_route_rejects_get_csrf_and_unknown_origins` | Tightened in this change. |
| Revocation CORS | Authorization server | Shares the POST-only non-credentialed token-management policy. | `production_browser_oauth_routes_expose_only_required_cors` | Covered. |
| UserInfo CORS | Authorization server/resource endpoint | Exact origins, GET/POST, Authorization/DPoP, no browser credentials. | `browser_userinfo_cors_allows_get_and_post_bearer_or_dpop`; `production_browser_oauth_routes_expose_only_required_cors` | Covered. |
| Cookie/OAuth credential separation | Authorization server | A valid first-party browser session cannot authenticate `/token`, `/revoke`, or `/userinfo`. | `valid_browser_session_cookie_cannot_authenticate_oauth_protocol_endpoints` | Covered by a real Valkey/PostgreSQL session test in the non-skippable CI environment. |
| Redirect attacks | Authorization server | Redirect URI is registered and matched exactly at authorization and code exchange. | `authorization_request_rejects_unregistered_redirect_uri_before_session_lookup`; `authorization_code_redirect_uri_matching_preserves_oauth_binding_rules`; `token_authorization_code_marks_failed_states_for_redirect_pkce_and_audience_errors` | Covered. |
| Authorization-code theft/replay | Authorization server | Code is short-lived, PKCE-bound, atomically consumed, and replay affects the associated refresh family. | `authorization_code_consumption_parser_maps_terminal_states_fail_closed`; `token_authorization_code_replay_revokes_previous_tokens_and_rejects_reuse`; `token_authorization_code_replay_fails_closed_when_replayed_client_lookup_errors` | Covered. |
| Refresh tokens | Authorization server | Issuance is client/policy gated; rotation, family binding, reuse detection, and fail-closed persistence are tested. | `refresh_grant_marks_family_reuse_and_revokes_active_family_tokens`; `refresh_grant_fails_closed_when_reuse_marker_cannot_be_persisted`; `refresh_token_rotation_failure_does_not_return_partial_credentials` | Covered. |
| DPoP and sender constraints | Authorization/resource server | DPoP remains independent of CORS and session cookies; nonce/replay and token binding are validated by the existing profile. | `browser_token_management_cors_allows_post_dpop_without_credentials`; `dpop_authorizer_rejects_invalid_proof_before_token_binding`; `dpop_proof_verifier_rejects_replayed_jti`; `dpop_proof_verifier_enforces_required_nonce` | Covered; no weaker browser-only DPoP path added. |
| Session fixation and CSRF | First-party session backend | Login creates fresh server session state; unsafe authenticated writes require CSRF and exact credentialed origin. | `login_form_request_creates_session_and_redirects_to_safe_next`; `cors_auth_api_credentials_are_limited_to_configured_origins_and_csrf_headers`; `mfa_totp_begin_rejects_session_request_without_csrf_before_enrollment_secret`; `mfa_totp_confirm_rotates_session_and_csrf_after_valid_code` | Covered for authenticated first-party operations. |
| Error and log redaction | Authorization server | Audited browser OAuth errors omit returned credentials, and PAR log metadata omits request objects and client secrets. | `par_error_log_fields_skip_success_and_include_only_safe_error_metadata`; `par_success_persists_request_uri_without_client_secret_material`; `token_endpoint_rejects_multiple_client_auth_methods_before_secret_verification`; `tests/in_source/src/http/token/tests/dispatch.rs::assert_token_error` | Covered for the audited browser OAuth paths. |
| Discovery truth | Authorization server | No draft runtime profile, grant, auth method, endpoint, or metadata field is advertised by this audit. | `discovery_does_not_advertise_unimplemented_protocol_extensions`; `discovery_fapi2_security_metadata_is_profile_scoped`; `discovery_baseline_advertises_unsigned_request_object_compatibility_only` | Covered. |
| Browser token storage | First-party app / third-party responsibility | NazoAuthWeb stores no OAuth credentials; arbitrary third-party SPA storage cannot be enforced by the AS. | NazoAuthWeb `scripts/check-browser-security.test.mjs` and `check-browser-security.mjs` at commit `304906b` | Bounded claim; third-party storage remains application responsibility. |
| Malicious JavaScript | BFF/public SPA | First-party tokens remain server-side; session/CSRF and response headers reduce impact. The AS cannot make arbitrary third-party JavaScript trustworthy. | `login_form_request_creates_session_and_redirects_to_safe_next`; `csrf_response_returns_token_body_and_matching_cookie`; NazoAuthWeb source, artifact, lint, TypeScript, and build gates at `304906b` | Covered for NazoAuth-controlled surfaces with stated residual risk. |
| Final RFC delta | Governance | The reviewed document has no RFC number. | IETF Datatracker status on 2026-07-11 | Re-audit required immediately after publication. |

## Threat review

### Malicious JavaScript and single token theft

The first-party application uses the BFF/session pattern, so its JavaScript has
no OAuth bearer token to exfiltrate. JavaScript can still act through the
current browser session; CSP, dependency integrity, output escaping, CSRF, and
short session lifetime therefore remain material controls. A compromised
third-party SPA can access any token available to that SPA; NazoAuth does not
claim to eliminate that application-local risk.

### Persistent token theft

NazoAuthWeb permits durable browser storage only for locale and a boolean
session hint. The hint is non-authoritative: the backend always checks the real
session. A coordinated source/build gate rejects new durable OAuth credential
storage. Third-party clients remain responsible for selecting a BFF,
token-mediating backend, or browser-only architecture appropriate to their risk.

### New-flow token acquisition and client hijacking

Authorization requests use registered exact redirects, one-time `state` at the
client, S256 PKCE, short-lived codes, and atomic code consumption. NazoAuth
does not accept an embedded browser secret as proof of confidentiality. OIDC
clients must use nonce to bind an ID Token to their authorization request.

### CSRF, CORS, and session confusion

The authorization endpoint is navigation-only and intentionally has no CORS.
Public OAuth protocol APIs use exact-origin, non-credentialed CORS and do not
accept the first-party CSRF header. Credentialed `/auth/me/*` operations are a
separate server-session surface and require the configured origin and CSRF on
unsafe requests. CORS does not replace OAuth client, token, redirect, issuer,
or audience validation.

### Refresh-token compromise

Refresh tokens are issued only under current client/scope policy. Rotation and
family reuse detection are server-side and fail closed when the reuse marker
cannot be persisted. Sender constraints remain available where selected by the
client/profile. This audit does not promise that arbitrary browser-only clients
can safely retain long-lived bearer refresh tokens.

## Architecture choices

| Pattern | NazoAuth position |
| --- | --- |
| BFF / same-origin session | Required architecture for NazoAuthWeb; recommended for first-party applications handling sensitive sessions. |
| Token-mediating backend | Compatible third-party architecture, but not implemented by NazoAuthWeb and not advertised as a distinct AS profile. |
| Browser-only public client | Supported at the AS boundary through code + S256 PKCE and minimal non-credentialed CORS; token storage and application compromise remain the client's responsibility. |

## Local verification

The focused audit commands are:

```powershell
cargo test --locked cors --lib
cargo test --locked authorization_pkce --lib
cargo test --locked redirect_uri --lib
cargo test --locked refresh --lib
cargo test --locked session --lib
cargo test --locked csrf --lib
cargo test --locked well_known --lib
cargo test --locked valid_browser_session_cookie_cannot_authenticate_oauth_protocol_endpoints --lib
```

The final cookie/OAuth separation test requires `DATABASE_URL` and `VALKEY_URL`;
it compiles but short-circuits in developer environments without both services.
The repository CI library-test gate supplies both services and must execute the
fixture rather than treating the local short-circuit as integration evidence.

The coordinated NazoAuthWeb change adds source and built-artifact checks to its
normal `npm test` gate. OIDC/FAPI local and official 19+2 matrices remain
regression evidence; the inspected OIDF suite has no dedicated Browser-Based
Applications OP plan.

## Publication re-entry trigger

After the RFC Editor assigns an RFC number:

1. compare the published RFC to draft-26 requirement by requirement;
2. update this matrix for normative or architectural differences;
3. implement and negatively test every concrete new server or first-party Web
   requirement;
4. re-check the official conformance suite for applicable plans; and
5. update public claims only after the delta audit and regression evidence pass.
