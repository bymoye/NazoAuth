# M8 Watchlist Governance Completion Design

**Date:** 2026-07-11

**Status:** Approved for implementation

**Repository:** verified NazoAuth checkout

**Branch:** `codex/m8-watchlist`

## 1. Context

M8 is a governance milestone for emerging and adjacent protocol work. Its three
tasks are entry gates, not a request to implement every candidate protocol:

- M8-01 requires a concrete product need and ownership model.
- M8-02 requires an exact specification and conformance status.
- M8-03 requires an isolation argument that preserves every existing security
  profile.

The milestone currently lists FAPI HTTP message signatures, SCIM pagination and
security events, browser-based application guidance, attestation-based client
authentication, Transaction Tokens, Grant Management, and OpenID4VCI/OpenID4VP.
Some are final specifications, some are active drafts, and some have incomplete
or no conformance coverage. Specification maturity alone is not a product
requirement and must not cause NazoAuth to advertise or execute a new protocol.

## 2. Goals

1. Create one dated, source-backed watchlist record covering every M8 candidate.
2. Record the users, integration shape, threat model, metadata or configuration
   surface, failure modes, and operational owner required by M8-01.
3. Record exact official specification versions and maturity, OIDF/IETF status,
   available conformance coverage, and a future local-test strategy required by
   M8-02.
4. Define non-negotiable isolation rules for `oauth2-oidc-baseline`,
   `fapi2-security`, every `fapi2-message-signing-*` profile, CIBA, SCIM, and
   external-provider login as required by M8-03.
5. Give each candidate an explicit decision: defer, audit after a named event,
   or start a separate product discovery milestone.
6. Synchronize the roadmap, protocol/profile matrices, repository summaries,
   documentation indexes, and changelog without claiming runtime support.

## 3. Non-goals

- Adding endpoints, grants, token types, HTTP headers, metadata fields, feature
  flags, database migrations, or runtime dependencies.
- Implementing any M8 candidate merely because its specification is final.
- Adding draft capabilities to existing profiles or discovery documents.
- Claiming certification where the official suite has only partial coverage or
  no applicable test plan.
- Running an OIDF server matrix for behavior that is intentionally absent.
- Changing the independent `NazoAuthWeb` repository.

## 4. Selected Approach

Add a dedicated M8 watchlist evidence record under `docs/conformance/`. The
record is durable, date-scoped evidence rather than an implementation claim. It
contains a common decision schema and a row or section for every candidate.

This is preferred over embedding the full audit in the roadmap because the
roadmap should remain a scheduling summary. It is preferred over only checking
the boxes because M8-02 requires auditable sources and test-policy detail.

## 5. Evidence Model

Every candidate entry records the following fields:

| Field | Required content |
| --- | --- |
| Product demand | Named user class and a concrete workflow; otherwise state that no validated demand exists. |
| Integration boundary | NazoAuth role, endpoints or messages that a future implementation would add, and external dependencies. |
| Threats | Candidate-specific trust, replay, substitution, privacy, lifecycle, downgrade, and denial-of-service risks. |
| Metadata/configuration | Future discovery, registration, per-client, tenant, trust-anchor, or feature-gate surfaces; absence remains the current truth. |
| Failure/operations | Fail-closed behavior, key/trust lifecycle, monitoring, incident response, retention, and the owning operator role. |
| Specification status | Official source, exact version or RFC/final identifier, standards body, maturity, and review date. |
| Conformance status | Applicable official OIDF plan/module coverage found in the suite source, or an explicit no-plan result. |
| Local test strategy | Positive, negative, metadata-truth, replay/concurrency, interoperability, and profile-isolation tests required before implementation completion. |
| Decision | Deferred reason and the objective event that permits a new implementation proposal. |

Official IETF Datatracker, RFC Editor, OpenID Foundation specifications, and the
OpenID conformance-suite source are primary evidence. Search-engine snippets,
marketing pages, and remembered version numbers are not evidence.

The conformance-source review records the inspected suite commit and search
date. Existing OpenID4VCI/OpenID4VP plans and attestation-related coverage must
be distinguished from a standalone, general-purpose AS certification plan.
Absence findings are phrased narrowly: no applicable plan was found in the
inspected revision, not that no test can ever exist.

## 6. Candidate Decision Boundaries

The audit applies these decision rules:

1. **Final specification, no validated NazoAuth product demand:** remain
   deferred. RFC 9865, RFC 9967, OpenID4VCI, and OpenID4VP do not enter the
   runtime solely because they are final.
2. **Active or publication-queue draft:** remain watchlist-only. Browser-based
   application guidance is re-audited when an RFC number is assigned; active
   OAuth drafts are re-audited after RFC/final publication and a concrete
   adopter exists.
3. **Old or inactive ecosystem draft:** remain deferred until the owning
   standards group publishes a current stable specification and a real
   integration demand exists.
4. **Partial conformance support:** treat the tested profile as bounded. It
   cannot justify broader metadata or runtime claims.
5. **Separate product domain:** OpenID4VCI/OpenID4VP requires its own product
   discovery and architecture milestone because credential issuer, wallet,
   holder, and verifier responsibilities exceed the existing OP/AS surface.

## 7. Security Isolation Invariants

Completing M8 changes documentation state only. The following runtime
invariants remain unchanged:

- No candidate endpoint, grant, token type, authentication method, signing
  scheme, credential format, SCIM capability, or metadata value is advertised.
- Draft processing cannot be enabled through an existing compatibility flag.
- Existing client authentication, PAR/JAR/JARM, PKCE, DPoP, mTLS, CIBA, token
  audience, issuer, nonce, replay, and refresh-token requirements are not
  weakened.
- New trust anchors must never reuse external-login provider trust or the local
  OP signing-key trust boundary implicitly.
- New protocol state must have explicit expiry, replay, concurrency, storage,
  retention, and fail-closed behavior before implementation.
- SCIM pagination or event work must not broaden tenant visibility, filter
  authorization, event audience, or bearer-token acceptance.
- OpenID4VC work must use separate role, issuer, key, metadata, privacy,
  credential-status, and consent boundaries; ordinary OIDC identity claims are
  not automatically credentials.
- A future candidate implementation must add negative profile-isolation tests
  proving unchanged behavior for baseline, FAPI2, Message Signing, CIBA, SCIM,
  and external-provider login where applicable.

## 8. Documentation Changes

Implementation updates these files:

- create `docs/conformance/2026-07-11-m8-watchlist-governance.md`;
- update `docs/conformance/README.md` and
  `docs/conformance/README.zh-CN.md` with the evidence record;
- update `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md` to
  check M8-01 through M8-03 and state that candidates remain deferred;
- update `docs/protocol/rfc-compliance-matrix.md` with the watchlist boundary;
- update `docs/protocol/profile-matrix.md` with a non-runtime watchlist rule;
- update `README.md` and `README.zh-CN.md` so project status links to the audit
  without claiming candidate support;
- update `CHANGELOG.md` with a documentation/governance entry.

No source, test, workflow, configuration, schema, or dependency file changes.

## 9. Validation Strategy

Because the approved change does not alter runtime behavior, validation is
documentation-focused:

1. Verify every M8 candidate appears exactly once in the evidence decision
   matrix and has all required M8-01/02/03 fields.
2. Verify official URLs resolve and the recorded status/version matches the
   primary source on 2026-07-11.
3. Search the inspected OIDF suite revision for applicable plan and module
   coverage; record both positive and negative findings with the commit hash.
4. Search the NazoAuth diff for accidental runtime capability claims and for
   inconsistent unchecked M8 tasks or “M8 not started” summaries.
5. Run the repository's documentation validation commands if present; otherwise
   run whitespace/error checks and targeted link/path checks.
6. Inspect the final diff and confirm that no runtime file changed.

Rust tests and an OIDF execution are not completion evidence for this milestone:
there is intentionally no new behavior to execute. Future implementations must
define and pass their own local and official conformance gates.

## 10. Completion Criteria

M8 is complete when:

1. all seven candidate groups have a dated, primary-source-backed decision;
2. each decision covers product need, integration, threats, metadata/config,
   failures, operations, specification status, conformance, and local testing;
3. deferred items name a concrete re-entry condition;
4. the security isolation invariants are explicit and unchanged;
5. M8-01, M8-02, and M8-03 are checked only as completed governance work;
6. every summary states that no candidate runtime support was added;
7. all required indexes and protocol/status documents agree;
8. validation finds no runtime change, broken internal path, stale M8 status, or
   unsupported standards/certification claim.
