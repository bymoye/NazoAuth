# Browser-Based Applications Draft-26 Audit and Hardening Design

Date: 2026-07-11

## Purpose

Audit and harden NazoAuth and NazoAuthWeb against
`draft-ietf-oauth-browser-based-apps-26` without claiming compliance with a
final RFC that has not yet been published. The work preserves two distinct
browser integration models:

1. NazoAuthWeb is a same-origin first-party application backed by NazoAuth
   server sessions. It does not receive or persist OAuth access tokens,
   refresh tokens, client secrets, OIDF credentials, or PKCE verifiers.
2. Third-party browser applications are public OAuth clients using
   Authorization Code with S256 PKCE. They do not use a browser client secret,
   implicit flow, password flow, or cookie-authenticated token endpoint.

The audit is an evidence-producing security review plus repairs for concrete
gaps found during the requirements mapping. It does not introduce a draft
runtime profile or advertise a new standards claim.

## Standards status and evidence boundary

The design uses `draft-ietf-oauth-browser-based-apps-26`, dated 2025-12-04 and
intended for publication as a Best Current Practice. On 2026-07-11 the IETF
Datatracker still listed the document in the RFC Editor publication queue and
did not assign an RFC number. The implementation record must therefore say
"draft-26 audit" and must schedule a delta audit after RFC publication.

Primary source:

- https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/26/

The OpenID conformance suite has no dedicated Browser-Based Applications OP
plan in the repository revision recorded by the M8 governance review. Existing
OIDC and FAPI matrices are regression evidence only, not certification for this
draft.

## Scope

### NazoAuth authorization server

- Map draft requirements and threats to authorization, PAR, token, refresh,
  revocation, UserInfo, redirect, CORS, session, CSRF, response-header, and
  logging behavior.
- Preserve code-only authorization, exact redirect matching, S256 PKCE,
  authorization-code single use, bounded code lifetime, refresh-token rotation,
  refresh-family reuse detection, and absence of implicit/password grants.
- Verify that browser OAuth endpoints never rely on cookies for OAuth client or
  token authentication.
- Verify endpoint-specific CORS: no CORS on `/authorize`; minimal,
  non-credentialed CORS on browser-callable protocol endpoints; exact,
  credentialed CORS plus CSRF only on first-party session APIs.
- Repair only demonstrated gaps and add negative regression tests for every
  repair.
- Keep Discovery and protected-resource metadata limited to implemented facts.

### NazoAuthWeb first-party application

- Keep the application on the same-origin server-session model.
- Verify that authentication APIs use `credentials: include` only with the
  established CSRF boundary.
- Add an executable repository gate preventing sensitive OAuth material from
  being persisted to Web Storage, IndexedDB, caches, service-worker state, or
  other durable browser state in authentication and API code.
- Permit explicitly reviewed non-sensitive state such as locale and the
  boolean session hint. The session hint must remain non-authoritative and must
  never be treated as proof of authentication.
- Scan production artifacts for real secrets, private keys, test tokens, and
  private OIDF configuration.
- Repair only concrete gaps found by the audit.

### Third-party public browser clients

- Document and test Authorization Code with S256 PKCE as the supported browser
  model.
- Treat the browser client as public even if its JavaScript bundle contains a
  configured identifier or string called a secret.
- Require exact redirect matching and one-time `state`; require OIDC `nonce`
  when an ID Token is requested.
- Keep `state`, nonce, and PKCE verifier in ephemeral client-controlled state
  and discard them after callback completion.
- Issue refresh tokens only when current client policy permits them and the
  existing rotation/reuse-detection controls remain effective.

## Non-goals

- No implicit grant, password grant, or hybrid browser shortcut.
- No static browser client secret treated as confidential authentication.
- No access-token or refresh-token storage feature for NazoAuthWeb.
- No new service worker, browser token vault, iframe token broker, or silent
  authentication mechanism.
- No draft-named runtime profile or final RFC compliance claim.
- No redesign of unrelated NazoAuthWeb pages, visual presentation, device flow,
  or CIBA flow.
- No absorption of unrelated unmerged NazoAuthWeb branch work. The coordinated
  Web change must start from the repository's current main and incorporate
  other work only through its normal merge history.

## Architecture and trust boundaries

### First-party same-origin session flow

1. The browser loads NazoAuthWeb from the NazoAuth public origin.
2. Login and account operations use `/auth/*` session APIs.
3. The server establishes an opaque secure session cookie. JavaScript cannot
   read the cookie.
4. Unsafe session operations require both an allowed exact origin and a valid
   CSRF token.
5. NazoAuthWeb obtains the current user view, not OAuth bearer credentials.
6. Local UI hints may improve rendering but never authorize a request.

The server session is the sole authentication fact for NazoAuthWeb. Loss or
tampering of a UI hint can cause at most an extra session check or a cosmetic
change.

### Third-party public browser OAuth flow

1. The client generates high-entropy `state`, nonce, and PKCE verifier and
   derives an S256 challenge.
2. The browser navigates to `/authorize`; JavaScript does not call that endpoint
   through CORS.
3. NazoAuth authenticates the user and binds the authorization code to the
   client, exact redirect URI, and PKCE challenge.
4. The client validates `state` and exchanges the one-time code and verifier at
   `/token` without browser credentials.
5. NazoAuth validates the verifier, client policy, redirect binding, code
   lifetime, and code consumption atomically.
6. The client discards callback correlation material. Token storage and API
   architecture remain the responsibility of the third-party application and
   are not represented as NazoAuthWeb behavior.

### CORS separation

- Authorization/navigation endpoints: no CORS.
- Public OAuth protocol APIs intended for browser use: exact configured origins,
  protocol-required methods/headers, no cookies, and no wildcard-plus-
  credentials combination.
- First-party session APIs: exact configured origins, credentials allowed, and
  CSRF required for unsafe requests.
- Admin and SCIM APIs: retain their independent policies and are not broadened
  by this audit.

## Components

### 1. Dated audit matrix

Add a durable conformance/security record that maps every applicable draft-26
requirement and named attack class to one of:

- code and a passing automated test;
- deployment/configuration guidance;
- a concrete repair included in the change;
- not applicable, with a precise architectural reason; or
- deferred third-party application responsibility, without implying server
  enforcement.

The matrix must distinguish requirements for an authorization server, BFF,
token-mediating backend, and browser-only public client. It must not use a
passing server test to claim that arbitrary third-party JavaScript stores
tokens safely.

### 2. NazoAuth browser security regression gate

Extend existing focused tests rather than creating a parallel framework. The
gate covers:

- no CORS, credentialed CORS, or XHR exposure on `/authorize`;
- exact allowed-origin behavior and minimal preflight headers on `/token`,
  `/revoke`, and `/userinfo`;
- no cookie-based OAuth token authentication;
- public-client S256 PKCE success and missing/plain/wrong verifier rejection;
- exact redirect URI binding at authorization and token exchange;
- authorization-code expiry, one-time use, and replay handling;
- refresh rotation, family reuse detection, revocation, and client binding;
- session fixation prevention, cookie attributes, CSRF, and exact-origin
  behavior for `/auth/*`;
- sensitive error and log redaction; and
- unchanged Discovery metadata truth.

Where unit-level CORS constructors cannot prove route composition, add a real
HTTP application test using the production route assembly.

### 3. NazoAuthWeb persistence and artifact gate

Add a deterministic script or lint rule that examines authentication/API source
and the production build. It must fail on attempts to persist names or values
representing access tokens, refresh tokens, ID tokens, client secrets, PKCE
verifiers, private keys, or OIDF private configuration. Legitimate reviewed
uses of `localStorage` for locale and the non-authoritative session hint are
allowlisted by exact file and key, not by a broad pattern.

The gate is defense in depth. Runtime authorization continues to come from
server-side checks, not the scanner.

### 4. Coordinated smoke coverage

Add or update a reproducible browser/HTTP smoke procedure for:

- first-party login, CSRF-protected write, session refresh, and logout;
- public-client code + S256 PKCE success;
- invalid origin, missing CSRF, wrong verifier, redirect mismatch, code replay,
  and refresh reuse rejection; and
- inspection proving that Web Storage contains no OAuth credentials after the
  first-party flow.

## Error handling and failure policy

- Invalid, absent, expired, replayed, or context-mismatched authorization
  material fails closed using existing OAuth error semantics.
- Session API origin or CSRF failure returns a bounded denial without revealing
  authentication, token, or secret material.
- CORS misconfiguration never falls back to wildcard origins or browser
  credentials.
- Failure to load server-side session, replay, or refresh-family state does not
  produce a reduced-validation token or authenticated response.
- The NazoAuthWeb persistence gate fails CI before deployment. It has no runtime
  bypass.
- Audit uncertainty is recorded as a gap or third-party responsibility, not as
  compliance.

## Testing and acceptance

### NazoAuth

Run focused tests for CORS, authorization, PKCE, redirect binding, token issue,
refresh, session, CSRF, well-known metadata, and sensitive logging. Then run the
normal Rust formatting, compilation, clippy, library test, coverage, CodeQL,
supply-chain, and real-HTTP security gates.

Acceptance requires zero newly failing tests and explicit negative coverage for
every code change. The official and local OIDC/FAPI 19+2 matrices must remain
green after deployment; they are regression evidence and must be labelled as
such.

### NazoAuthWeb

`npm test` must pass, including ESLint, TypeScript, production build, the new
persistence gate, and artifact scan. Perform a browser smoke check against the
deployed coordinated server build and inspect Web Storage after the flow.

### Documentation

Update the Browser-Based Applications status in the roadmap, RFC compliance
matrix, profile guidance, configuration/deployment guidance, and the dated
audit evidence. State the exact draft revision and review date. Add a re-entry
trigger for the final RFC delta audit.

## Repository and release strategy

This subproject produces coordinated changes in two repositories:

1. NazoAuth server PR, containing the audit matrix, server tests, demonstrated
   server repairs, and documentation.
2. NazoAuthWeb PR, containing the persistence/artifact gate, demonstrated Web
   repairs, and Web-facing guidance.

Each PR records the other PR or exact commit. The server change is merged and
deployed first because the Web change must not depend on a weaker server
boundary. After both deployments:

- run first-party browser smoke checks;
- run the public-client negative matrix;
- verify production health and metadata;
- run the complete local OIDF matrix;
- request the official OIDF full matrix;
- wait for both repositories' checks; and
- merge only commits exactly covered by the evidence.

## Future RFC delta audit

When the RFC number is assigned:

1. compare the final RFC to draft-26;
2. update the audit matrix for normative and architectural differences;
3. implement and test concrete new requirements;
4. re-check official conformance coverage; and
5. only then update public standards claims.
