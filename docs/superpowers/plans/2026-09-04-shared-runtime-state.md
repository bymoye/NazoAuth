# Shared runtime state implementation plan

**Goal:** Deliver S3-compatible direct avatar upload and a database-authoritative signing-key lifecycle that works across disposable service instances.

**Architecture:** PostgreSQL owns durable avatar references and encrypted key generations. S3 owns immutable avatar objects; Valkey owns short-lived upload authorizations. NazoAuth owns validation and state transitions; ctl invokes existing operator contracts. Instances may cache keys in memory, but never require local key files for normal database-backed operation.

**Workspaces:** Integration and keys: `D:/self/NazoAuth-mdoc-cert-profile` (`feat/shared-runtime-state`). Avatar: `D:/self/NazoAuth-s3-avatar` (`feat/s3-avatar-direct-upload`). Preserve the primary checkout and all its untracked files. Hostinger is the integration build/test host; temporary test services must be isolated from production.

## Constraints and accepted decisions

- HARD BOUNDARY: NazoAuth and key-management business logic must not depend on PostgreSQL/SQL/Diesel or concrete database types. Declare ports at the existing abstract boundary, implement SQL and concurrency in the PostgreSQL adapter, and inject through the composition root. The current concrete database is an implementation choice, never a runtime-domain dependency.
- Preserve local avatar storage for single-instance deployments; S3 mode must not fall back to local storage.
- Direct upload authorizations bind a tenant/user, one server-generated object key, expiry, and an enforced size limit. Do not trust MIME declarations as image validation.
- Uploads land in private temporary storage. Finalization fixes the exact bytes before validation/publication so a reusable signed upload cannot replace the accepted avatar.
- The database alone selects the current avatar. Handle uncertain database outcomes without deleting a possibly referenced object. Garbage collection must not remove an upload still being published.
- Use existing maintained S3/crypto libraries where suitable; no cloud-vendor-specific event pipeline or separate image service.
- Database key metadata and encrypted private material are tenant/purpose scoped. Inject one deployment wrapping-key ring explicitly, with no per-instance generated replacement. Do not reuse client-secret pepper as an encryption key.
- Use the existing signing algorithms and external signing boundary. Do not introduce a mandatory KMS service.
- Key initialization and rotation must converge under concurrent instances. Public-key prepublication, bounded snapshot freshness and old-key retention must cover signing and verification windows.
- Import existing key material with its original kid and public keys; then use one authoritative backend. No ongoing file/database dual writes.
- Existing keyctl/operator operations must target the same database lifecycle; do not add a second ctl implementation of business rules.
- Root-secret consistency, mdoc certificate/CRL material and migration safety must be inspected alongside integration; do not claim Issue #108 fully closed while other necessary instance-local state remains.

## Task 1 — Direct avatar upload

Ownership: avatar-specific identity ports/service, server avatar HTTP/adapters, matching settings and composition, frontend consumers if present, upload-state adapter, avatar-specific migration if required, tests/docs and required dependency declarations. Record touched shared files before integration.

- [ ] Inspect current upload/read/delete consumers and write the concrete task design in the avatar worktree.
- [ ] Add behavior tests for direct-upload authorization, fixed key/size/expiry, tenant ownership, real image validation, repeated finalization, concurrent replacements, stale upload overwrite, expiration and cleanup.
- [ ] Implement immutable object operations shared by local and S3 paths, then authorization/finalization HTTP contracts and consumers. Use presigned POST when needed to enforce size before ingress; document the required S3 capability contract.
- [ ] Verify with a real isolated S3-compatible service, including cross-instance finalization; test failures must not silently skip.
- [ ] Commit the coherent avatar slice and report exact commands/results and integration touchpoints.

## Task 2 — Database signing keys

Ownership: `crates/key-management`, key persistence ports/PostgreSQL implementation and migration, server key composition/config/keyctl/operator integration, focused tests/docs. Coordinate Cargo.lock and shared settings files at integration.

- [ ] Inspect lifecycle, external signer, request-object decryption keys, purpose-scoped keys, current operator contract, tenant bootstrap and mdoc consumers; write a concrete key task design.
- [ ] Add failing tests for two managers sharing one database, encrypted persistence/AAD binding, initialization and rotation races, restart without key files, import preservation and bounded stale signing.
- [ ] Implement a database-backed key repository through the existing dependency direction. Keep crypto and lifecycle rules in key-management and atomic persistence in PostgreSQL.
- [ ] Wire production and operator operations to the same authority. Preserve imported key identity and supported algorithms; make missing wrapping material explicit.
- [ ] Verify focused crypto/key tests and real PostgreSQL lifecycle tests, then commit the coherent slice.

## Task 3 — Integration and acceptance

- [ ] Review both slices for correctness and unnecessary abstractions; resolve shared-file conflicts by preserving both features.
- [ ] Verify local/S3 mode configuration, ctl compatibility, secret injection, migration/import documentation and any remaining #108 boundaries.
- [ ] Run format, focused tests, workspace compile/clippy and applicable integration gates on Hostinger. Reuse build caches but never reuse a production database or bucket.
- [ ] Prove A-upload/B-finalize and B-read; two-instance key/JWKS convergence; concurrent rotation; restart after process loss; preservation of old-token verification.
- [ ] Report code, tests and operational proof separately. Do not claim deployment, release, remote push or Issue closure without performing the corresponding action.

Rollback: preserve imported source material and database backups; never delete original keys during import. Before schema rollback, stop writers and establish which code can read the persisted generation. Avatar failures before database publication leave the prior avatar authoritative.

Stop conditions: preserve user modifications; investigate failing gates rather than bypassing them; do not modify production services for acceptance testing.
