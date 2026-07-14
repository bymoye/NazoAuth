# SCIM 2.0 Provisioning

## Scope

SCIM support is a default-tenant provisioning surface with database-backed SCIM
credentials. It is an identity-platform feature, not part of OAuth/OIDC or FAPI
conformance.

## Configuration

Preferred configuration uses rows in `scim_tokens`:

- Store only `blake3` hex in `token_hash`.
- Bind the credential to a `tenant_id`.
- Set `scopes` to an array containing `scim:read`, `scim:write`, or `scim:*`.
- Use `expires_at` for planned rotation windows.
- Set `revoked_at` to retire a credential.
- Use `label` for operator-facing rotation notes; do not store the raw token.

`SCIM_BEARER_TOKEN` remains a compatibility fallback for self-hosted deployments. It is compared in constant time against the `Authorization: Bearer` header and is treated as a legacy full-access credential with `scim:read` and `scim:write`. Prefer database tokens for new deployments.

Credential behavior:

- Raw SCIM bearer tokens are not stored in the database.
- Multiple database tokens are valid at the same time during rotation windows.
- Database tokens can expire or be revoked independently.
- Read endpoints require `scim:read` or `scim:*`.
- Create, replace, patch, and delete endpoints require `scim:write` or `scim:*`.
- Successful database-token use updates `last_used_at` and inserts `scim_audit_events`.
- Successful and denied SCIM token checks emit structured audit events without raw token material.
- `nazo_oauth_migrate` runs `nazo_oauth_cleanup_expired_security_state()`, which
  removes SCIM audit events older than 180 days together with expired security
  state. This keeps audit retention bounded while preserving a compromise
  investigation window.

Outside default SCIM:

- OAuth client-credentials or introspection-backed SCIM authorization.
- Per-tenant SCIM credential routing. The schema stores `tenant_id`; provisioning uses the default tenant boundary.

## Endpoints

- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/Users`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/{user_id}`
- `PUT /scim/v2/Users/{user_id}`
- `PATCH /scim/v2/Users/{user_id}`
- `DELETE /scim/v2/Users/{user_id}`

`DELETE` is a soft delete: it sets `active=false` and keeps the user record for audit and token-revocation continuity.

## Identity Mapping

SCIM `userName` maps to the local `users.email` login identifier. The primary
email must match `userName`; create, replace, and patch requests that split
these identities are rejected.

Provisioned users are created in the default tenant, realm, and organization. A
deployment with request-level tenant routing must select the tenant boundary
before creating, listing, updating, or deleting users.

## Supported Operations

Listing supports both index and RFC 9865 forward cursor pagination and supports
only `userName eq "email@example.com"` filters.

- Index pagination remains the default and accepts `startIndex` plus `count`.
- Cursor pagination is selected by an empty first-page `cursor` parameter and
  returns `nextCursor` on every non-final page.
- Cursor pages are ordered by `(created_at, id)` and do not return
  `startIndex` or the optional `previousCursor`.
- Cursors are stateless AES-256-GCM values with a fresh nonce, a domain-separated
  key derived from the stable client-secret pepper, and a 600-second lifetime.
- Each cursor is bound to the SCIM credential, tenant, exact filter, effective
  count, ordering policy, and last row. Every page repeats bearer, scope, and
  tenant authorization.
- Bearer authorization runs before raw query parsing. Malformed or duplicate
  pagination fields therefore retain the SCIM error envelope instead of being
  rejected by the framework's generic query extractor.
- Invalid or substituted cursors use `invalidCursor`, authenticated expired
  cursors use `expiredCursor`, and count changes use `invalidCount`.
- Results are a live ordered set rather than a database snapshot: later inserts
  after the marker may appear, deletes may reduce the remaining set, and an
  already returned unchanged row is not repeated.

`/ServiceProviderConfig` advertises the SCIM pagination and event capability
boundary explicitly:

- RFC 9865 cursor pagination and index pagination are supported; index remains
  `defaultPaginationMethod`, `cursorTimeout` is 600, and the maximum page size
  is 200.
- The default page size is 100 and the maximum page size is 200.
- RFC 9967 SCIM Security Event Tokens, event feeds, and asynchronous completion
  events are not supported; `securityEvents.asyncRequest` is `none` and
  `eventUris` is empty.

PATCH supports `replace` for:

- `userName`
- `active`
- `name.formatted`
- `name.givenName`
- `name.familyName`
- `emails`

Bulk operations, sorting, password changes, groups, and SCIM enterprise-user
extensions are not advertised.
