# Changelog

Project changes are recorded in Keep a Changelog style. Versioned releases use
semantic versioning once public release tags are cut.

## Unreleased

### Added

- Added RFC 9865 forward cursor pagination for SCIM user listing with index as
  the default, stateless AES-256-GCM actor/query-bound cursors, deterministic
  keyset traversal, exact pagination errors, and truthful capability metadata.
- Added durable OpenID Foundation conformance evidence under `docs/conformance`, including retained full 16-plan matrix records, workflow URLs, artifact metadata, plan IDs, profile combinations, pass counts, and exported artifact filenames.
- Added a production deployment guide covering container deployment, reverse proxy boundaries, key rotation, database and Valkey operations, live verification, and OIDF readiness.
- Added `SECURITY.md` with reporting guidance, vulnerability classes, production boundaries, and disclosure expectations.
- Added `docs/project/roadmap.md` as the current scope record for implemented profiles, deployment controls, product boundaries, and evidence links.
- Added `docs/protocol/profile-matrix.md`, separating OAuth/OIDC, FAPI2 Security, FAPI2 Message Signing, deployment-security, and product-hardening requirements.
- Added `docs/security/threat-model.md` and `docs/protocol/refresh-token-rotation.md` for security boundaries and refresh-token state-machine behavior.
- Added `CHANGELOG.md`.
- Added token endpoint support for the standard RFC 8707 `resource` parameter as the normative single-resource input, while retaining the legacy `audience` parameter as an extension.
- Added supply-chain and release security gates with `cargo audit`, `cargo deny`, CycloneDX SBOM generation, Trivy image scanning, keyless artifact signing, and GitHub provenance attestations.
- Added README quality signals for CI quality gates, coverage, dependency review, CodeQL, conformance evidence, and release security controls.
- Added PostgreSQL and Valkey HA, backup, restore, timeout, and partial-outage operations guidance.
- Added bounded RFC 8693 Token Exchange support for locally issued access-token to access-token exchanges, including subject/actor token validation, target restrictions, scope downscoping, and `issued_token_type` responses.
- Added default-closed RFC 7591 Dynamic Client Registration behind `ENABLE_DYNAMIC_CLIENT_REGISTRATION`, with optional initial access token enforcement and OIDF dynamic-client plan coverage.
- Added default-closed RFC 7592 Dynamic Client Registration Management for DCR-created clients, with hashed registration access tokens, GET/PUT credential rotation, full-replacement updates, and DELETE deactivation.
- Added dynamic-client lifecycle audit events and ecosystem onboarding documentation covering baseline, FAPI2, Message Signing, CIBA, Device Grant, DCR/DCRM, Token Exchange, and deferred third-party JWT bearer trust boundaries.
- Added modular third-party login provider registry with dynamic OIDC/OAuth2 social provider routes, QQ/WeChat social adapter presets, non-secret provider discovery, and admin onboarding metadata.

### Changed

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
