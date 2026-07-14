# OAuth Browser-Based Applications Draft-27 Delta Audit

Date: 2026-07-11

## Conclusion and corrected claim boundary

The authoritative IETF Datatracker record is
`draft-ietf-oauth-browser-based-apps-27`, published 2026-07-06 and updated in
the RFC Editor queue on 2026-07-09. The earlier draft-26 audit remains a dated
record of the implementation evidence used for pull request 53, but draft 26
is not the current pre-publication baseline.

NazoAuth's relevant roles are:

- an authorization server serving NazoAuthWeb as its same-origin frontend;
- a server-managed login/session surface for that frontend; and
- an authorization server for third-party public browser OAuth clients.

NazoAuthWeb is not a Backend for Frontend (BFF) as defined by this draft. It
does not act as a confidential OAuth client for the browser, hold the browser's
access/refresh tokens, or proxy browser resource requests while translating a
cookie into an access token. Earlier “BFF/session” wording is corrected by this
record and the active profile matrices.

Primary sources:

- <https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/27/>
- <https://datatracker.ietf.org/doc/draft-ietf-httpbis-layered-cookies/02/>

## Draft-26 to draft-27 delta

The normative implementation delta is in BFF Cookie Security, section 6.1.3.2:
the BFF SHOULD start cookie names with a prefix showing that the cookie was set
over HTTP, for example `__Host-Http-` from layered cookies draft 02. Draft 26
instead referred to `__Host`. Remaining changes are document metadata,
references, and editorial updates.

This SHOULD applies to BFF cookies associated with the user's OAuth tokens.
NazoAuth's login session is an authorization-server session and is not used to
obtain/proxy a user's tokens to resource servers. Renaming NazoAuth cookies
would therefore be independent defense-in-depth, not draft-27 BFF compliance,
and would invalidate active sessions without closing a demonstrated role gap.
No runtime cookie rename is made by this correction.

## Requirements retained from the draft-26 audit

The implementation evidence from
`2026-07-11-browser-based-applications-draft-26-audit.md` remains valid for:

- public-client classification and code + S256 PKCE;
- exact redirects and authorization-code replay protection;
- non-credentialed, endpoint-specific token/revocation/UserInfo CORS;
- separation of browser session cookies from OAuth protocol authentication;
- refresh-token rotation/reuse detection and optional sender constraints;
- server-side NazoAuthWeb sessions, CSRF controls, and absence of OAuth tokens
  from durable frontend storage; and
- truthful discovery with no draft-specific runtime profile.

Those controls are AS/frontend behavior, not a claim that NazoAuth implements
all BFF, token-mediating-backend, or third-party SPA responsibilities.

## Conformance and publication watch

OpenID conformance-suite release `v5.2.0`
(`dee9a25160e789f0f80517674693ef7989ab9fa1`) has no dedicated
Browser-Based Applications OP plan. Local security tests and the normal OIDC /
FAPI regression matrices remain the evidence source.

After an RFC number is assigned, compare the final RFC against draft 27,
re-audit applicable AS and first-party frontend requirements, inspect the then
latest conformance suite, and update claims only after concrete deltas pass
negative and regression tests.
