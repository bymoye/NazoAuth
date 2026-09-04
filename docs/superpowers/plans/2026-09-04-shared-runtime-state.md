# Shared runtime state implementation and acceptance

## Goal and boundaries

Provide browser-direct avatar uploads and database-authoritative signing keys
across disposable server instances. The core owns business state transitions;
ports express durable persistence, object storage and temporary upload state.
PostgreSQL, S3-compatible storage and Valkey are concrete adapters selected by
the executable composition root. Core crates depend on neither SQL/Diesel nor
S3 configuration or SDK types. Static dependency checks enforce this boundary.

Implementation work uses isolated branches `feat/shared-runtime-state` and
`feat/shared-key-install`; the original checkouts and their user files remain
unchanged. Hostinger verification uses isolated test services, never production
storage or the running OIDF environment.

## Delivered behavior

- Avatar authorization fixes the tenant, user, object, expiry and byte limit.
  Browsers upload directly to storage. Finalization decodes real image bytes,
  publishes the exact validated source version and compares/sets the database
  avatar reference. Shared leases allow another instance to finalize; retries
  and staging replay cannot replace accepted bytes. Local multipart storage
  remains its existing separate capability.
- `SigningKeyRepository` is the tenant-bound persistence port. The PostgreSQL
  adapter owns atomic create/CAS and the migration. AES-GCM encrypted generations
  authenticate tenant, revision and public metadata; private keys never enter
  the public projection. Concurrent initialization converges on one authority.
- Runtime and operator key operations load that same database authority.
  Startup performs due lifecycle maintenance. Prepublication, bounded signing
  snapshots and verification retention cover rotation. Expired snapshots stop
  signing; retired keys stop appearing in JWKS and lookup even in captured
  snapshots after their retirement deadline.
- `keys-import` is an explicit offline operation. It preserves original key IDs
  and material, leaves source files untouched, accepts compatible retries and
  rejects an unrelated database keyset. Ordinary startup has no file fallback.
- ctl clean install provisions a deployment wrapping root once and references a
  secret file. Updates require existing root/configuration/runtime access.
  Backup and recovery preserve the configured current/previous ring. Host wire
  schema 10 reflects the expanded install secret contract.
- The old ctl current-data copy mode is explicitly refused: copying a key
  directory cannot migrate the database authority. Existing deployments must
  import with the same wrapping root before managed update; a fresh install
  would generate a different root and is not a migration procedure.

## Verification record

The final commands, counts and proof boundaries are recorded in
`docs/operations/shared-runtime-state-verification.md` after Hostinger acceptance.
Targeted checks include real PostgreSQL concurrent initialization/CAS and restart,
wrong-root rejection and rewrapping; real Valkey lease transitions; real MinIO
signed PUT/conditional publication; and a combined A-authorize/B-finalize/B-read/
A-retry service test using all three concrete backends. HTTP authentication and
CSRF are covered separately by the server regression suite.

Review also corrected repeated configuration-extension fixtures, invalid PNG
fixtures, a stale S3 prefix assertion, and process tests that still assumed
filesystem signing keys. These fixes preserve meaningful validation instead of
weakening the production behavior.

## Operational limits and rollback

The combined avatar proof constructs independent service instances and uses a
real browser-style HTTP PUT to object storage; it does not launch two authenticated HTTP
server processes. Bucket CORS and lifecycle remain deployment configuration.

All instances must receive the same wrapping ring. Preserve original key files
and a database backup until migration acceptance; do not roll back the schema
while current writers use it. Avatar publication failure leaves the database
reference authoritative, and an uncertain database outcome never deletes a
possibly referenced final object.

mdoc IACA private keys, certificates and CRLs retain their distinct deployment
lifecycle and must be supplied consistently to each instance. This work does not
by itself establish that every requirement of Issue #108 is closed.

Code verification, Release-profile builds, publication and production deployment
are separate outcomes. No release publication, production cutover or issue
closure is implied by this implementation record.
