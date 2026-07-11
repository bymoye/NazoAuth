# OAuth 2.1 and Best-Practice Audit

Audit date: 2026-06-08

## Scope

OAuth 2.1 is tracked as the IETF OAuth working group draft, not as a final RFC.
On the audit date, the Datatracker entry was
`draft-ietf-oauth-v2-1-15`, an active Internet-Draft from March 2026 that
expires on 2026-09-03. The audit treats OAuth 2.1 as the consolidated OAuth
2.0 security baseline and cross-checks it with the profile matrix, OAuth
Security BCP controls, OIDC conformance records, and FAPI2 profile boundaries.

References:

- OAuth 2.1 draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- OAuth 2.0 Security BCP / RFC 9700: https://datatracker.ietf.org/doc/rfc9700/
- DPoP / RFC 9449: https://datatracker.ietf.org/doc/html/rfc9449
- mTLS sender constraint / RFC 8705: https://datatracker.ietf.org/doc/html/rfc8705
- FAPI2 Security Profile: https://openid.net/specs/fapi-security-profile-2_0-final.html
- FAPI2 Message Signing: https://openid.net/specs/fapi-message-signing-2_0.html

## Core Protocol Status

| Area | Status | Evidence |
| --- | --- | --- |
| Authorization code grant | Implemented | `/authorize`, `/token`, PAR, signed request object handling, authorization code one-time consumption, and redirect matching tests. |
| PKCE | Implemented as default requirement | S256 is required by default; the only no-PKCE path is an explicit confidential-client legacy compatibility flag, and sender-constrained clients must use PKCE. |
| Refresh token grant | Implemented | Rotation, reuse detection, sender-constraint preservation, and documented lost-response retry state machine. |
| Client credentials grant | Implemented | Confidential client authentication, resource/audience binding, and no `openid` user-subject overclaim. |
| Implicit grant | Not supported | Discovery advertises `code`; no implicit response type is part of the profile matrix. |
| Resource owner password credentials | Not supported as core | Client metadata validation rejects unsupported grants; FAPI2 profiles explicitly reject `password`. |
| Redirect URI policy | Implemented | HTTPS, loopback/native exceptions, no fragments, no credentials, no wildcards, exact matching except public loopback runtime port. |
| Client authentication | Implemented | `client_secret_basic`, compatibility `client_secret_post`, `private_key_jwt`, `tls_client_auth`, and `self_signed_tls_client_auth`. |
| Metadata truth | Implemented | Discovery and OAuth metadata are profile/config scoped and covered by metadata truth tests. |
| Revocation and introspection | Implemented | Token revocation, JWT local validation, introspection fallback guidance, and revocation checks for resource endpoints. |

## Security BCP Alignment

| Control | Status | Evidence |
| --- | --- | --- |
| No bearer token in query at resource endpoints | Implemented | Resource, UserInfo, and resource-server verifier reject query-token use. |
| Sender-constrained tokens | Implemented | DPoP and mTLS-bound access tokens, UserInfo/resource checks, and resource-server verifier support. |
| DPoP proof replay protection | Implemented | AS-side DPoP proof `jti` cache and resource-server `DpopProofVerifier` replay cache. |
| mTLS proxy trust boundary | Implemented | Trusted proxy CIDRs, forwarded-certificate stripping/duplicate rejection, subject/SAN matching, and docs. |
| Audience/resource binding | Implemented | RFC 8707 `resource` support at authorization, PAR, token, and refresh-token boundaries; multi-audience JWT `aud`; ambiguous/duplicate resource rejection; refresh-token audience narrowing. |
| Signed request objects | Implemented | Signed JAR at PAR with profile-specific requirements; request object `jti` is product hardening, not misdocumented as FAPI normative. |
| PAR for high-security profiles | Implemented | `fapi2-security` requires client-authenticated PAR and rejects non-PAR authorization requests. |
| JWT signing key lifecycle | Implemented | Active/previous/retired JWKS handling, KMS/HSM/external signer backends, and external signer self-verification. |
| Operational security gates | Implemented | `conformance-security`, `release-security`, `cargo audit`, `cargo deny`, SBOM, image scan, and provenance docs. |

## OIDC and FAPI Status

| Profile | Status | Notes |
| --- | --- | --- |
| OIDC Basic OP | Implemented and OIDF-tested | Latest durable official record is `docs/conformance/2026-06-27-pr15-official-oidf-full-matrix.md`; implementation-affecting commits must be retested. |
| OIDC Config | Implemented and OIDF-tested | Discovery metadata is generated from runtime profile/config. |
| FAPI2 Security | Implemented and OIDF-tested | PAR, PKCE S256, confidential clients, sender-constrained tokens, and client auth policy are separated from Message Signing. |
| FAPI2 Message Signing authz request | Implemented and OIDF-tested | Signed request objects at PAR with `aud`, `nbf`, and bounded `exp`. |
| FAPI2 Message Signing JARM | Implemented and OIDF-tested where advertised | Signing failure must not fall back to plain query responses. |
| FAPI2 introspection JWT response option | Implemented/profile-scoped | Advertised only by `fapi2-message-signing-introspection`; signed JWT is always the base response, and JWE is used only when the authenticated caller has supported per-client encryption metadata. |

## Outside OAuth 2.1 Core

Product features outside the OAuth 2.1 core profile:

- Dynamic Client Registration / RFC 7591, implemented as a default-closed
  ecosystem feature.
- Client Configuration Management / RFC 7592.
- Device Authorization Grant.
- Token Exchange / RFC 8693.
- Dynamic request-level tenant or issuer routing.
- OAuth client-credentials or introspection-backed SCIM authorization.

They remain ecosystem or identity-platform features with separate threat models in `docs/features/ecosystem-onboarding.md`, `docs/features/tenancy.md`, and `docs/features/scim.md`.

## Evidence

Implementation and workflow evidence:

- Implementation HEAD `2773b28d8ddd062c0d4c5eecee953b393a0797fc` passed
  `conformance-security` run `27117658022` on 2026-06-08. That run covered
  `rust-gate`, `supply-chain-gate`, and `real-http-security-matrix`.
- The docs-only trigger boundary is now enforced by
  `.github/workflows/conformance-security.yml`: documentation-only commits do
  not run the expensive CI matrix, while code, dependency, migration, script,
  deploy, container, runtime config, and workflow changes still do.
- Latest implementation-affecting local gates were run before the OIDF proof
  update: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, `cargo test --all-targets --all-features --locked`, and `git diff
  --check`.

The latest retained official OIDF full matrix passed on runtime implementation
commit `be7ef9f6a9197520235a59d42866a0918a293014`, and the durable result index
is `docs/conformance/2026-06-27-pr15-official-oidf-full-matrix.md`.
Documentation-only commits can differ from the implementation commit under
test; implementation-affecting commits must rerun the official matrix and add a
fresh durable record.
