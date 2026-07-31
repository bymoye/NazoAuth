# OIDF Full Matrix

This document describes the repository-owned OpenID Foundation Conformance Suite matrix. The matrix is a 27-plan suite. New TP/PS and NI checks are mapped onto these plans instead of being added as a separate temporary matrix.

The execution entry point is `runtime/oidf/oidf-plan-set.json`. `scripts/prepare_oidf_black_box.py` also writes `runtime/oidf/oidf-plan-set-manifest.json` with a title, description, and coverage focus for every plan.

In `parallel-isolated` mode the 27 plans are executed as bounded public-suite batches: OIDC core (`2`), OIDC Form Post / Third-Party Initiated Login / Config (`3`), FAPI-CIBA (`4`, `--no-parallel`), FAPI message-signing plus mTLS/DPoP (`5`), three remaining FAPI groups (`3` each), and four isolated browser jobs for RP-Initiated Logout, Back-Channel Logout, Front-Channel Logout, and Session Management. This preserves full matrix coverage while avoiding suite-runner callback and browser-session contention.

The latest durable operator and official-suite evidence is the preceding 25-plan baseline in
[`2026-07-20-final-automated-oidf-results.md`](2026-07-20-final-automated-oidf-results.md).
It predates the independent RP-Initiated and Back-Channel Logout jobs and is not evidence that the 27-plan matrix has passed.

## Plan Index

| # | Title | Description |
| --- | --- | --- |
| 1 | OIDC Basic OP | Validates discovery, static client registration, and OIDC authorization-code interoperability for ID Token, UserInfo, and common login parameters. |
| 2 | OIDC Basic OP Dynamic Registration | Validates RFC 7591 dynamic client registration, discovery `registration_endpoint`, and OIDC authorization-code interoperability after dynamic registration. |
| 3 | OIDC Config OP | Validates provider metadata truth for the public issuer, including endpoint, algorithm, and session-capability advertisement. |
| 4 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / JARM | Uses `private_key_jwt` client authentication and DPoP sender constraint to cover signed Request Objects, PAR, JAR/JARM, PKCE, authorization-code replay, and OpenID Connect responses. |
| 5 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / plain response | Keeps the signed-request boundary from the JARM plan while using a plain code response, separating request-side message signing from response-mode behavior. |
| 6 | FAPI2 Security / mTLS client auth / DPoP / OpenID Connect / authorization code | Uses mTLS client authentication and DPoP-bound access tokens for OIDC authorization-code coverage, including PAR, PKCE, code replay, refresh tokens, and discovery. |
| 7 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / client credentials | Uses mTLS client authentication and DPoP-bound access tokens for client credentials, token endpoint, audience, and resource-access checks. |
| 8 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / authorization code | Uses mTLS client authentication and DPoP sender constraint for non-OIDC authorization-code coverage, including PAR, PKCE, code replay, and resource access. |
| 9 | FAPI2 Security / mTLS client auth / mTLS sender / OpenID Connect / authorization code | Covers mTLS client authentication plus mTLS sender-constrained tokens for OIDC authorization code and holder-bound resource access. |
| 10 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / client credentials | Uses mTLS for both client authentication and sender constraint in client credentials token issuance and resource access. |
| 11 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / authorization code | Uses mTLS for both client authentication and sender constraint in non-OIDC authorization-code, PAR, PKCE, code replay, and resource-access checks. |
| 12 | FAPI2 Security / private_key_jwt / DPoP / OpenID Connect / authorization code | Uses `private_key_jwt` and DPoP for OIDC authorization code. This is the primary single-plan regression for PAR `request_uri`, outer authorization parameters, and refresh-token behavior. |
| 13 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / client credentials | Uses `private_key_jwt` and DPoP for client credentials token endpoint, audience, and resource-access checks. |
| 14 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / authorization code | Uses `private_key_jwt` and DPoP for non-OIDC authorization-code coverage, including PAR, PKCE, code replay, and resource access. |
| 15 | FAPI2 Security / private_key_jwt / mTLS sender / OpenID Connect / authorization code | Uses `private_key_jwt` client authentication and mTLS sender-constrained tokens for OIDC authorization code and certificate-bound resource access. |
| 16 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / client credentials | Uses `private_key_jwt` client authentication and mTLS sender constraint for client credentials token issuance and certificate-bound resource access. |
| 17 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / authorization code | Uses `private_key_jwt` client authentication and mTLS sender constraint for non-OIDC authorization-code, PAR, PKCE, code replay, and resource-access checks. |
| 18 | OIDC RP-Initiated Logout OP | Validates GET and form POST logout, `id_token_hint` and `client_id` binding, exact post-logout redirect matching, state continuity, invalid inputs, and explicit End-User confirmation when the request is not bound to the current OP session. |
| 19 | OIDC Back-Channel Logout OP | Validates signed, explicitly typed Logout Tokens, required claims, `sid`/`sub` session binding, form-encoded RP callback delivery, and RP response handling. |
| 20 | OIDC Front-Channel Logout OP | Validates front-channel logout metadata, RP-initiated logout, iframe logout notification, `iss`/`sid` parameters, and `post_logout_redirect_uri`. |
| 21 | OIDC Session Management OP | Validates `check_session_iframe` metadata, authorization response `session_state`, registered parent-origin enforcement, and the session-state transition after RP-initiated logout. |
| 22 | FAPI-CIBA ID1 / private_key_jwt / poll / plain FAPI | Validates FAPI-CIBA AS discovery, the backchannel authentication endpoint, `private_key_jwt` client authentication, poll-mode token exchange, error handling, refresh tokens, and resource access. |
| 23 | FAPI-CIBA ID1 / mTLS / poll / plain FAPI | Validates mTLS client authentication and certificate-bound poll-mode token issuance. |
| 24 | FAPI-CIBA ID1 / private_key_jwt / ping / plain FAPI | Validates authenticated ping notification with the TLS 1.2 FAPI baseline and TLS 1.3 client support, token-endpoint retrieval, redirect rejection, and terminal 401 handling. |
| 25 | FAPI-CIBA ID1 / mTLS / ping / plain FAPI | Validates the same TLS 1.2-minimum/TLS 1.3-capable ping lifecycle with mTLS client authentication and holder-of-key tokens. |
| 26 | OIDC Form Post OP | Validates `response_mode=form_post` for successful and error authorization responses through the browser flow. |
| 27 | OIDC Third-Party Initiated Login OP | Validates dynamic registration round-trip of `initiate_login_uri` and rejection of non-HTTPS metadata. |

## TP/PS Coverage Boundary

The matrix covers the current TP/PS work through these paths:

- `OIDC Basic OP Dynamic Registration` covers RFC 7591 dynamic client registration and `registration_endpoint` metadata.
- OpenID Connect RP Metadata Choices 1.0 has no dedicated module in either
  the workflow-pinned suite revision `dee9a25160e789f0f80517674693ef7989ab9fa1`
  or official `master` at
  [`daf33d61b982d5d33d134b07e9a36f76176b3eff`](https://gitlab.com/openid/conformance-suite/-/commit/daf33d61b982d5d33d134b07e9a36f76176b3eff).
  The Dynamic Registration plan exercises related single-valued metadata, but
  it does not submit the 19 `*_values_supported` choice inputs, validate
  selection from their intersection, or check that choice arrays are absent
  from registration/read responses. Repository DCR tests are therefore the
  current evidence for this specification; an official plan must be added to
  the matrix when OIDF publishes one.
- Dynamic-registration extensions such as remote `jwks_uri`, exact registered external `request_uri`, signed Request Objects, signed UserInfo, and presentation metadata remain implemented behind their existing validation boundaries. They do not constitute a claim of the OIDF Dynamic OP certification profile.
- `OIDC Form Post OP` covers the HTML form-post response transport, including no-store and browser submission behavior.
- `OIDC Third-Party Initiated Login OP` covers `initiate_login_uri` metadata. This OP-side profile is registration metadata; it does not add an OP initiation endpoint.
- `OIDC Config OP` covers metadata truth and prevents discovery from advertising unsupported capabilities.
- FAPI2 Security and Message Signing plans cover PAR enforcement, `request_uri` expiry, `request_uri` replay, cross-client `request_uri` use, outer authorization request parameters, PKCE, redirect URI, audience, and client assertions.
- `private_key_jwt / DPoP / OpenID Connect / authorization code` is the closest single-plan regression for TP/PS change sets; full evidence comes from the 27-plan matrix.
- `OIDC RP-Initiated Logout OP` and `OIDC Back-Channel Logout OP` provide independent certification evidence rather than inferring their behavior from the other logout profiles.
- `OIDC Front-Channel Logout OP` covers NI-008.
- `OIDC Session Management OP` covers NI-009.
- Four FAPI-CIBA plans cover the orthogonal `private_key_jwt / mTLS` × `poll / ping` combinations. The [FAPI-CIBA profile](https://openid.net/specs/openid-financial-api-ciba.html) only supports poll and ping modes, so push mode is outside the supported FAPI-CIBA profile and is never supported.
- No dedicated official plan was found for NI-006 RFC 7523 third-party JWT bearer grant assertion trust. Existing OIDC/FAPI plans cover client assertion scenarios, and local tests cover the bounded JWT bearer grant.
- NI-010 tracks [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) and [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html). Those specifications define a federation trust-chain ecosystem with Entity Statements, Trust Anchors, metadata policy, Trust Marks, and Federation endpoints. Federation is **not supported (planned)**: it is not advertised, `/.well-known/openid-federation` is absent, and Federation plans are not must-pass matrix entries until a separate trust-chain implementation exists.
- No official OP plan was found for NI-011 Native SSO / `device_secret`; local tests cover device-secret lifecycle, `ds_hash` binding, token exchange, and refresh-family activity.

Targeted plan-sets are useful for development triage. Durable regression evidence should cite the full 27-plan matrix.

## Explicit NEVER SUPPORTED Boundary

The OIDF `oidcc-dynamic-certification-test-plan` is **NEVER SUPPORTED** and must
not appear in generated, local, or official plan sets. The official suite's
dynamic-profile discovery checks require all of `code`, `id_token`, and
`token id_token` response types and both `authorization_code` and `implicit`
grant types. Those requirements are visible in the suite's
[`OIDCCCheckDiscEndpointResponseTypesSupportedDynamic`](https://gitlab.com/openid/conformance-suite/-/blob/v5.2.0/src/main/java/net/openid/conformance/condition/client/OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.java)
and
[`OIDCCCheckDiscEndpointGrantTypesSupportedDynamic`](https://gitlab.com/openid/conformance-suite/-/blob/v5.2.0/src/main/java/net/openid/conformance/condition/client/OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.java)
conditions.

Implementing that certification profile would require advertising and enabling
implicit response modes. RFC 9700, section 2.1.2, says authorization servers
SHOULD NOT support the implicit grant. The interactive flow therefore remains
authorization code, and discovery metadata stays truthful. RFC 7591 dynamic
client registration remains implemented and is covered by `OIDC Basic OP
Dynamic Registration`; "dynamic registration" and the legacy OIDF "Dynamic OP"
certification profile are not the same support claim.

## Expected Skip Policy

The current official workflow allows eight explicit expected-skip records
across the static, dynamic-registration, and Form Post Basic OP configurations:

- `oidcc-idtoken-unsigned`
- `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`
- `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
- `oidcc-ensure-request-object-with-redirect-uri`

The skips reflect intentionally unsupported unsigned compatibility features:
unsigned ID Tokens and unsigned Request Objects are not advertised. The last
module name is broader than its actual precondition: OIDF suite v5.2.0 skips it
when `none` is absent from `request_object_signing_alg_values_supported`.
Signed Request Objects with `redirect_uri` remain implemented and tested in the
FAPI/JAR plans. A workflow run with those expected skips can be evidence for `0
failures` and `0 warnings`, but it is not zero-SKIPPED evidence.

## Expected Review Policy

The RP-Initiated Logout OP plan has exactly eight modules whose official-suite
result is `REVIEW` because certification requires a screenshot of the OP's
error or End-User confirmation page. The runner allowlist is bound to the
RP-Initiated configuration, exact plan name, and exact module names, with at
most one instance of each. These results are not skips: the captured evidence
must still be reviewed and included in a formal submission. Any additional
`REVIEW` result fails the run.

## Expected Warning Policy

The current matrix has 26 bounded expected warnings:
[`oidf-official-expected-warnings.json`](../../tests/contracts/oidf-official-expected-warnings.json).
Every record is tied to the exact FAPI-CIBA ping configuration, complete
variant, module, block, condition, and result. The only accepted condition is
`EnsureIncomingTls13` on the official suite's public CIBA ping callback ingress;
the companion TLS 1.2 secure-cipher condition still passes, and the
implementation separately proves TLS 1.3 client support while retaining the
FAPI-CIBA TLS 1.2 baseline. Unexpected warnings and missing expected records
both fail the workflow.
