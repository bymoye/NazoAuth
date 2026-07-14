# Account profile endpoints

The first-party account surface uses the authenticated browser session and is
separate from OAuth bearer-token endpoints. Its current route contract is:

- `GET /auth/me` reads the current account projection.
- `PATCH /auth/me` replaces the submitted profile fields and requires the CSRF
  cookie/header pair.
- `GET /auth/me/applications` lists clients previously authorized by the
  current account.

There is no account-delete route and no user-facing application-revocation
route in this surface. Refactoring must not add either route implicitly.

## Authentication states

A fully authenticated session receives the public profile fields and
`mfa_required: false`. A password-authenticated session that still requires MFA
receives only `id`, `email`, `mfa_required: true`, and the CSRF token needed to
continue the challenge. The reduced pending-MFA projection prevents profile,
role, phone, address, and authorized-client data from being exposed before
step-up completes.

Missing, expired, inactive, or otherwise invalid sessions preserve the
`login_required` response and clear both session cookies. Repository and store
failures remain distinct service-unavailable protocol responses and fail
closed.

## Response caching and cross-origin access

Successful profile and authorized-application responses deliberately include
`Cache-Control: no-store` and `Pragma: no-cache`. This is a security hardening
for personally identifiable and authorization-history data. Error status,
body, content type, cookie clearing, and pre-existing error headers remain
unchanged.

The routes are statically registered under the credentialed `/auth/me` CORS
policy. Allowed origins may send `GET` and CSRF-bearing `PATCH` requests with
cookies. The unregistered `POST /auth/me` route continues to return not found,
and `OPTIONS` is handled by the CORS policy without invoking profile operations.

## Update consistency

Profile persistence and the subsequent authorized-client count are two
separate PostgreSQL operations. If the write succeeds but the count read
fails, the endpoint returns a service-unavailable error even though the profile
change is already durable. Repeating the same full profile patch is
idempotent. Tests lock this partial-success and retry contract so callers do
not assume a rollback that did not occur.

The profile write is tenant-scoped and restricted to active users. A concurrent
account deactivation therefore causes the update to fail as login-required
instead of modifying an inactive account.
