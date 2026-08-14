# Tenant, Realm, and Organization Boundaries

## Scope

The current runtime uses a tenant-aware schema with explicit tenant, realm, and
organization columns for core identity and OAuth records. Runtime routing is
single-tenant unless a deployment adds request-level tenant selection.

Dynamic multi-issuer realm routing is outside this boundary.

## Default Boundary

- Default tenant: `00000000-0000-0000-0000-000000000001`
- Default realm: `00000000-0000-0000-0000-000000000002`
- Default organization: `00000000-0000-0000-0000-000000000003`

Local registration, admin-created clients, access tokens, refresh tokens,
grants, SCIM users, federation links, and revocation records are written into
the default boundary unless a tenant resolver selects another boundary.

## Database Invariants

The migration `20260607000400_tenant_realm_organization_boundaries` adds:

- `tenants`, `realms`, and `organizations` tables.
- `tenant_id`, `realm_id`, and `organization_id` columns on users and OAuth clients.
- `tenant_id` columns on refresh tokens, grants, access-token revocations, and client access requests.
- Tenant-scoped uniqueness for user email/username, `client_id`, refresh-token hashes, access-token revocation JTIs, and pending access requests.
- Composite foreign keys that reject cross-tenant links between users, clients, tokens, grants, revocations, realms, and organizations.

## Token Boundary

JWT access tokens include a private `tenant_id` claim. Resource endpoints and token introspection use that claim to scope access-token revocation checks. Malformed or mismatched tenant claims fail closed instead of falling back to the default tenant.

## OAuth Client Read Boundary

OAuth client lookup by protocol identifier or internal identifier, administrative
pagination, registration-secret verification, and user-authorized application
listing all require an explicit tenant. The persistence adapter applies that
tenant to every participating client and grant predicate; a missing or incorrect
tenant returns no client, secret material, or authorized application.

Authorization and device-flow services use an immutable tenant-bound repository
instance instead of accepting tenant input on every domain-port method. The
adapter supplies its owned tenant to the same explicit client queries and rejects
writes for any other tenant. A request-level resolver must therefore select the
repository/service instance for the resolved tenant; it must never reuse the
default instance as a fallback.

## Product Boundaries

The default runtime remains single-tenant with tenant-aware data invariants.
SCIM provisioning, local registration, grant lookup paths, and
external OIDC/SAML federation still bind users and grants to the default tenant,
realm, and organization.

A full multi-tenant deployment needs request-level tenant resolution by host,
path, issuer, or another explicit deployment boundary. That resolver must run
before client lookup, authorization, token issuance, SCIM provisioning,
federation account linking, session creation, consent/grant lookup, revocation,
and resource-server introspection.
