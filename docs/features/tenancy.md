# Tenant, Realm, and Organization Boundaries

## Scope

The current runtime uses a tenant-aware schema with explicit tenant, realm, and
organization columns for core identity and OAuth records. Each process selects
one active tenant, realm, and organization at startup. Request-level routing is
not enabled yet.

Dynamic multi-issuer realm routing is outside this boundary.

## Default Boundary

- Default tenant: `00000000-0000-0000-0000-000000000001`
- Default realm: `00000000-0000-0000-0000-000000000002`
- Default organization: `00000000-0000-0000-0000-000000000003`

`TENANT_ID` selects the process-wide security and routing boundary.
`REALM_ID` and `ORGANIZATION_ID` select active defaults for identity placement
inside that tenant. They default to the identifiers above for backward
compatibility. Startup fails closed if any row is missing or inactive, or if
either placement belongs to another tenant. Local registration, admin-created
clients, sessions, authorization and device flows, CIBA, OpenID4VC, SCIM, and
federation services are composed from that same immutable context.

Realm and organization are not independent request authorization partitions in
this stage. Existing session, user, client, grant, and trust lookups enforce the
tenant boundary; they do not filter every operation by realm or organization.
Treating those placement defaults as stronger isolation would overstate the
implemented runtime contract.

## Database Invariants

The migration `20260607000400_tenant_realm_organization_boundaries` adds:

- `tenants`, `realms`, and `organizations` tables.
- `tenant_id`, `realm_id`, and `organization_id` columns on users and OAuth clients.
- `tenant_id` columns on refresh tokens, grants, access-token revocations, and client access requests.
- Tenant-scoped uniqueness for user email/username, `client_id`, refresh-token hashes, access-token revocation JTIs, and pending access requests.
- Composite foreign keys that reject cross-tenant links between users, clients, tokens, grants, revocations, realms, and organizations.

## Token Boundary

JWT access tokens include a private `tenant_id` claim. Resource endpoints and token introspection use that claim to scope access-token revocation checks. Malformed or mismatched tenant claims fail closed instead of falling back to the default tenant.

FAPI HTTP-signature replay markers use the same validated access-token tenant.
The replay fingerprint is stored under that tenant namespace, so an identical
signature fingerprint in another tenant does not create a false replay, while a
second use in the same tenant is rejected. The storage adapter does not infer or
default this tenant.

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

The runtime remains single-tenant with tenant-aware data invariants. Selecting
non-default identifiers changes the entire process boundary; it does not add
host- or request-level tenant routing. Protocol signing keys remain
process-wide and must not be shared between processes configured for different
tenants.

Valkey transient keys are not yet individually namespaced, so startup
permanently binds each Valkey logical database to its first active tenant.
Same-tenant replicas may share it; a different tenant is rejected. A
non-default tenant may claim only an empty logical database, while the legacy
default tenant may adopt an existing unmarked database during upgrade.
Reassigning a logical database requires an explicit destructive flush after all
old state has expired or been retired.

For a non-default tenant, an older NazoAuth binary that predates the ownership
preflight is not a safe rollback artifact: it ignores the marker and falls back
to the legacy default runtime context. Roll back by restoring the previous
tenant-matched binary and its dedicated Valkey logical database snapshot, or by
retiring and explicitly flushing the new tenant's transient state before any
boundary change. Never point an old binary at a logical database already
claimed by a non-default tenant.

The legacy in-process OIDF conformance lease/onboarding driver remains limited
to the default boundary and rejects an alternative active boundary. It is not a
general management path and is scheduled to move to the external controller;
ordinary runtime services do not inherit that restriction.

A full multi-tenant deployment needs request-level tenant resolution by host,
path, issuer, or another explicit deployment boundary. That resolver must run
before client lookup, authorization, token issuance, SCIM provisioning,
federation account linking, session creation, consent/grant lookup, revocation,
and resource-server introspection.
