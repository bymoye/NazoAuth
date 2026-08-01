# NI-005 RFC 7592 OIDF Coverage Check

Date: 2026-07-02

## Scope

NI-005 implements RFC 7592 Dynamic Client Registration Management for clients
created through the default-closed DCR surface.

Implemented management behavior:

- `registration_client_uri` points to `/register/{client_id}`.
- `registration_access_token` is returned only in management responses and is
  stored server-side only as a BLAKE3 hash.
- GET reads current client metadata and preserves the authenticated registration access token.
- PUT performs full replacement, requires matching `client_id`, rejects
  client-controlled server-managed fields, and rotates credentials.
- DELETE deactivates the client, clears the registration token hash, revokes
  refresh-token rows, and removes user grants.

## OIDF Suite Mapping

The latest official repository evidence is:

- [2026-07-02 NI-004 official OIDF full matrix](2026-07-02-ni-004-official-oidf-full-matrix.md)
- Dynamic-client plan:
  <https://www.certification.openid.net/plan-detail.html?plan=k9vtssH5SjqqT>

That official 17-plan matrix ran against `https://issuer.example`, reported
`0 failures` and `0 warnings`, and included the OIDC Basic dynamic-client plan.
It also reported 2 expected `SKIPPED` modules in that plan, so it must not be
used as zero-SKIPPED evidence.

The OpenID Foundation conformance-suite source was rechecked on 2026-07-02 at
snapshot `21845642d279eacf627ed682094949050f1a88a4`. RFC 7592 management
coverage exists in Brazil DCR plans:

- `fapi1-advanced-final-brazil-dcr-test-plan`
- `fapi2-security-profile-final-brazil-dcr-test-plan`
- `fapi2-security-profile-id2-brazil-dcr-test-plan`

Those plans are Brazil profile tests and require profile semantics outside the
current NazoAuth RFC 7592 scope, including software statements, Brazil
directory assumptions, and mTLS/Brazil DCR policy. They should not be added to
the standard NazoAuth OIDF matrix merely to exercise RFC 7592 because that
would turn a protocol-management feature into a Brazil Open Finance product
claim.

No separate zero-SKIPPED generic RFC 7592 management-only official result is
recorded for this change. NI-005 is therefore covered by local protocol tests
and the existing official dynamic-client matrix evidence, with the SKIPPED
limitation called out explicitly.

## Repository Evidence

- `crates/http-actix/tests/unit/dynamic_client_registration.rs`
- `src/http/dynamic_client_registration.rs`
- `migrations/20260702000100_rfc7592_registration_management`

The local tests cover registration management response fields, registration
access token hash comparison, DCR insert-time token hashing, and PUT request
field constraints.
