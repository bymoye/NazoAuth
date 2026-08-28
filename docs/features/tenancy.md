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

## Local Registration State

The local registration service supplies its validated tenant to every email
verification state operation. Verification codes, per-email send cooldowns,
and per-peer send cooldowns use independent tenant namespaces in Valkey. The
same normalized email or peer in another tenant therefore cannot load, consume,
release, or suppress state owned by the first tenant. Email and peer subjects
are stored as digests in key names rather than raw identifiers.

## Product Boundaries

The runtime remains single-tenant with tenant-aware data invariants. Selecting
non-default identifiers changes the entire process boundary; it does not add
host- or request-level tenant routing. Protocol signing keys remain
process-wide and must not be shared between processes configured for different
tenants.

Every Valkey business key is scoped by deployment ID and UUIDv7 state epoch.
Startup rejects an unmarked nonempty logical database; it never claims or reads
unscoped state. A recovered deployment receives a new epoch and waits for the
signed token-invalidation deadline before public activation. Do not flush a
shared Valkey database as an install, update, rollback, or recovery shortcut.

A full multi-tenant deployment needs request-level tenant resolution by host,
path, issuer, or another explicit deployment boundary. That resolver must run
before client lookup, authorization, token issuance, SCIM provisioning,
federation account linking, session creation, consent/grant lookup, revocation,
and resource-server introspection.
