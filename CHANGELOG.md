# Changelog

Project changes are recorded in Keep a Changelog style. Versioned releases use
semantic versioning once public release tags are cut.

## 0.2.15 - 2026-09-06

### Fixed

- Preserve the configured mTLS listener port in each tenant's endpoint aliases.
- Accept root-owned Direct TLS keys readable only by the dedicated service
  group, while rejecting broader key access.
- Verify client-certificate possession during the TLS handshake and require
  deployment or currently approved client-specific CA trust for PKI mTLS
  authentication. Direct TLS and trusted RFC 9440 forwarding now apply the
  same client authorization checks; registered self-signed keys remain supported.
- Keep direct TLS and proxy-facing mTLS on the configured AEAD cipher policy.
- Reload server certificates when their configured paths change, preserving the
  previous working certificate if a replacement cannot be loaded.
- Preserve tenant identity in protocol security audit records, including key,
  client, and trust administration events.

## 0.2.14 - 2026-09-05

### Fixed

- Generate ISO/IEC 18013-5 mDL document signer and IACA certificates with a
  PrintableString country name, the mdlDS extended-key-usage identifier, and no
  document-signer Basic Constraints extension. Existing managed certificates
  require an explicit mdoc rotation to publish the corrected profile.

## 0.2.13 - 2026-09-05

### Fixed

- Align tenant key-generation results with the database keyset's canonical
  positive decimal revision. Tenant-scoped generation also rejects requests
  outside the OpenID4VC signing profile before any key material is created.
  This result contract requires NazoAuthCtl 0.2.26 or newer.

## 0.2.12 - 2026-09-05

### Added

- Persist managed OpenID4VC certificate, IACA and revocation material in the
  tenant's encrypted signing-key aggregate, and persist the audit-anchor
  checkpoint in PostgreSQL so every instance observes the same authority.

### Changed

- Replace managed OpenID4VC certificate and revocation files with explicit
  one-shot `keys-import` and `mdoc-import` migration commands for existing
  deployments. Pre-IACA bundles retain their old key and trust anchor through
  import, then use an explicit mdoc rotation to create current IACA material.
  Ordinary startup does not infer or copy legacy material.

### Fixed

- Apply pending database migrations and initialize the tenant directory before
  `keys-import` reads legacy keys. This allows an offline upgrade from a
  file-backed deployment whose database predates the signing-key table.

## 0.2.11 - 2026-09-04

### Added

- Persist encrypted tenant signing keysets through the database repository,
  with shared initialization, rotation and explicit import of existing keys.
- Support browser-direct signed PUT avatar uploads through an S3-compatible
  adapter, shared upload coordination and conditional final publication.
- Allow administrator-defined global avatar storage or complete per-tenant
  configurations, with tenant-isolated paths and optional storage access.

### Changed

- Require NazoAuthCtl 0.2.24 or newer to provision and recover deployment
  signing-key wrapping roots. Existing key material must be explicitly imported
  with the same root before updating an existing deployment; ordinary startup
  does not fall back to local signing-key files.
- Leave avatar storage disabled when neither global nor tenant configuration
  exists. Local storage must be explicitly selected and includes the tenant UUID
  in its path. Existing local avatars require manual migration before cutover.
- Report configured storage failures without silently switching backends.

See `docs/operations/avatar-direct-upload.md` and
`docs/operations/shared-runtime-state-verification.md` for migration steps and
verification boundaries. This release does not complete Issue #108's remaining
mdoc material and whole-system multi-instance acceptance work.

## 0.2.8 - 2026-09-02

### Added

- Add dynamic tenant directory control operations, tenant-local runtime
  generations, Direct TLS SNI/Host binding, and tenant-owned OpenID4VC secret
  and background-task lifecycles.

### Removed

- Remove third-party validator-specific leases, onboarding, provenance,
  OpenID4VP evidence receipts, migrations, and repository orchestration. An
  external validator now uses only ordinary public tenant/client behavior.

## 0.2.0 - 2026-08-24

### Changed

- Harden protocol policy, TLS, elliptic-curve, URI, client-authentication, and
  credential-validation boundaries against malformed or ambiguous inputs.
- Pin the embedded administration UI to an immutable, attested release artifact
  through the reviewed frontend descriptor chain.
- Update release, CI, container, and dependency controls to preserve exact-source
  provenance through published binaries and OCI images.
- Extend the explicit controller compatibility range through NazoAuthCtl 0.2.x
  while retaining protocol-version and signed-release checks.

### Fixed

- Close fail-open and replay gaps across OAuth/OIDC, FAPI, CIBA, OpenID4VC,
  operator tasks, onboarding, persistence, and key-management state transitions.

## 0.1.36 - 2026-08-13

### Fixed

- Validate BuildKit's current OCI artifact attestation manifests with a closed
  schema that binds the canonical empty config, artifact type, image subject,
  and exact SBOM and provenance predicates before publication.
- Pin release OCI exports to the reviewed artifact representation so runner
  defaults cannot silently change the publication contract.

## 0.1.35 - 2026-08-13

### Changed

- Strengthen OAuth, OIDC, FAPI, CIBA, OpenID4VC, operator-task, onboarding,
  storage, and key-management contract validation with behavior-focused
  regression coverage.
- Update reviewed Rust, Python, GitHub Actions, and container dependencies.

### Fixed

- Close fail-open and integrity gaps across management authentication,
  registration reservations, compact JWE parsing, runtime receipts, durable
  keyset writes, and protocol admission boundaries.

## 0.1.34 - 2026-08-12

- Remove the redundant supplementary keyless blob signature. The governed
  ReleaseManifest and standard build-provenance attestations already bind each
  immutable binary to public transparency evidence, while a third signature
  duplicated that proof and made retries dependent on cosign signing-config
  behavior.

## 0.1.33 - 2026-08-12

- Keep the supplementary keyless binary bundle offline because the public
  ReleaseManifest and build-provenance attestations already provide the
  transparency-log record; this makes immutable release retries idempotent.

## 0.1.0 - 2026-07-31

### Added

- Added the independently signed Rust `nazoauthctl` lifecycle binary with
  idempotent installation support for Podman, Docker,
  and Linux systemd deployments, with generated or operator-supplied
  PostgreSQL/Valkey connections, pre-migration backups, application-served
  signed UI assets, transactional host/container updates and rollback, and
  signed, replay-safe target-runtime delegation through the closed
  `nazoauth operator-task` entry point.
- Added RFC 9865 forward cursor pagination for SCIM user listing with index as
  the default, stateless AES-256-GCM actor/query-bound cursors, deterministic
  keyset traversal, exact pagination errors, and truthful capability metadata.
- Added a production deployment guide covering container deployment, reverse proxy boundaries, key rotation, database and Valkey operations, and live verification.
- Added `SECURITY.md` with reporting guidance, vulnerability classes, production boundaries, and disclosure expectations.
- Added `docs/project/roadmap.md` as the current scope record for implemented profiles, deployment controls, product boundaries, and evidence links.
- Added `docs/protocol/profile-matrix.md`, separating OAuth/OIDC, FAPI2 Security, FAPI2 Message Signing, deployment-security, and product-hardening requirements.
- Added `docs/security/threat-model.md` and `docs/protocol/refresh-token-rotation.md` for security boundaries and refresh-token state-machine behavior.
- Added `CHANGELOG.md`.
- Added token endpoint support for the standard RFC 8707 `resource` parameter as the normative single-resource input and removed the non-standard `audience` extension.
- Added supply-chain and release security gates with `cargo audit`, `cargo deny`, CycloneDX SBOM generation, Trivy image scanning, keyless artifact signing, and GitHub provenance attestations.
- Added README quality signals for CI quality gates, coverage, dependency review, CodeQL, conformance evidence, and release security controls.
- Added PostgreSQL and Valkey HA, backup, restore, timeout, and partial-outage operations guidance.
- Added bounded RFC 8693 Token Exchange support for locally issued access-token to access-token exchanges, including subject/actor token validation, target restrictions, scope downscoping, and `issued_token_type` responses.
- Added default-closed RFC 7591 Dynamic Client Registration behind the runtime-module policy, with optional initial access token enforcement.
- Added default-closed RFC 7592 Dynamic Client Registration Management for DCR-created clients, with hashed registration access tokens, GET/PUT credential rotation, full-replacement updates, and DELETE deactivation.
- Added dynamic-client lifecycle audit events and ecosystem onboarding documentation covering baseline, FAPI2, Message Signing, CIBA, Device Grant, DCR/DCRM, Token Exchange, and deferred third-party JWT bearer trust boundaries.
- Added modular third-party login provider registry with dynamic OIDC/OAuth2 social provider routes, QQ/WeChat social adapter presets, non-secret provider discovery, and admin onboarding metadata.

### Changed

- Replaced mutually exclusive global OAuth/FAPI message-signing selection for
  new clients with versioned composable client policy; stable server modules
  now default on for new databases while grants and elevated client authority
  remain deny-by-default. Existing inherited module and client behavior is
  preserved by an atomic compatibility migration.
- Completed the M8 emerging-protocol governance review with dated product,
  standards/conformance, local-test, and security-isolation decisions. This
  documentation change adds no candidate runtime capability or certification
  claim.
- Changed the project license metadata to AGPL-3.0-or-later and added the top-level
  license text.
- Reworked `README.md` and `README.zh-CN.md` into project-level entry points for scope,
  conformance, local setup, configuration, deployment, checks, and security
  boundaries.
- Sanitized generic OAuth JSON `error_description` values so protocol responses use ASCII-safe descriptions consistently.
- Made the Argon2 password hash policy explicit: Argon2id, version 19, 19456 KiB memory, time cost 2, parallelism 1.
- Tightened proxy-terminated mTLS handling so forwarded certificate evidence is accepted only from configured trusted proxy CIDRs and duplicate forwarded certificate headers must agree on the same SHA-256 thumbprint.
- Marked `client_secret_post` as a compatibility client authentication method in project documentation and recommended `private_key_jwt` or mTLS for high-security clients.
- Grouped GitHub Actions Dependabot updates, ignored `dtolnay/rust-toolchain` toolchain tags, and skipped Codecov upload when `CODECOV_TOKEN` is unavailable while retaining local coverage generation.
- Switched JWT signing and verification from the RustCrypto-backed `jsonwebtoken` provider to the AWS-LC-backed provider and removed the direct RustCrypto `rsa` dependency.

### Fixed

- Reject token requests that send conflicting `resource` and `audience` inputs.
- Reject token requests whose `resource` value is not an absolute URI or contains a fragment.
- Fixed refresh-token lost-response recovery to allow only a short post-rotation retry window instead of accepting old tokens only after the window had elapsed.
- Removed `session_id` from successful login JSON responses; the session identifier is carried only by the HTTPOnly session cookie.

### Ignored

- Added `.codex_remote_handoff/`, Python `__pycache__` directories, `code_review.md`, and `code_revioew.md` to `.gitignore`.

### Current Scope

- The current scope centers on the authorization-server surface: OAuth 2.1, OpenID Connect, PAR/JAR, FAPI2 Security, selected FAPI2 Message Signing behavior, DPoP, mTLS sender constraints, durable conformance evidence, and production deployment controls.
- Implemented product surfaces include TOTP MFA, WebAuthn/passkeys, external OIDC/SAML federation, default-tenant SCIM provisioning, tenant-aware schema boundaries, and Rust resource-server middleware.
- Dynamic Client Registration and Client Configuration Management are implemented behind an explicit feature gate; request-level dynamic tenant routing remains outside the default scope.
