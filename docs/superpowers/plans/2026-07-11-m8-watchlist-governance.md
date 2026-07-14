# M8 Watchlist Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete M8-01 through M8-03 with a dated, primary-source-backed decision for every watchlist candidate while adding no runtime capability claim.

**Architecture:** A dedicated conformance evidence record owns detailed candidate status, product boundaries, threat analysis, conformance coverage, test policy, and re-entry conditions. Existing roadmap and status documents link to that record and summarize its decisions without duplicating the evidence or advertising deferred features.

**Tech Stack:** Markdown, Git, PowerShell 7, ripgrep, OpenID conformance-suite source inspection.

## Global Constraints

- Do not add endpoints, grants, token types, metadata, configuration, migrations, dependencies, or runtime code.
- Use only official IETF, RFC Editor, OpenID Foundation, and OpenID conformance-suite sources for standards and conformance claims.
- Distinguish final specifications, RFC Editor queue documents, active Internet-Drafts, and old ecosystem drafts precisely.
- Distinguish OpenID4VC and profile-specific attestation test coverage from a standalone general OAuth AS certification claim.
- Mark M8-01 through M8-03 complete only as governance work; all candidate runtime capabilities remain deferred unless separately designed and implemented.

---

### Task 1: Dated M8 Evidence Record

**Files:**
- Create: `docs/conformance/2026-07-11-m8-watchlist-governance.md`

**Interfaces:**
- Consumes: the M8 candidate list from `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`, official standards sources, and conformance-suite commit `33a724c7d809a6f9db05cbb513ff2a77cbac905e`.
- Produces: the canonical M8 decision record linked by all summary documents.

- [ ] **Step 1: Record the review method and evidence boundary**

Write the review date, suite commit, primary-source policy, and the rule that an absence result means only “not found in the inspected revision.”

- [ ] **Step 2: Record exact standards status**

Include these primary-source conclusions and verify their exact current identifiers before saving:

```text
FAPI 2.0 HTTP Signatures: OIDF working draft; separate from FAPI 2.0 Message Signing Final.
RFC 9865: Proposed Standard, cursor-based SCIM pagination.
RFC 9967: published SCIM profile for Security Event Tokens; do not mislabel it as a generic asynchronous-request protocol.
OAuth for Browser-Based Applications: draft-ietf-oauth-browser-based-apps-26 in the RFC Editor queue; no RFC number yet.
Attestation-Based Client Authentication: active draft-ietf-oauth-attestation-based-client-auth-10.
Transaction Tokens: active draft-ietf-oauth-transaction-tokens-09.
Grant Management: OIDF fapi-grant-management-01 from June 2021; no final-spec claim.
OpenID4VCI 1.0 and OpenID4VP 1.0: OpenID Final Specifications.
```

- [ ] **Step 3: Record product and security decisions**

For every candidate include user, integration boundary, threats, metadata/configuration, failure/operations ownership, local test strategy, decision, and a concrete re-entry condition. Final specifications without validated demand remain deferred.

- [ ] **Step 4: Record conformance coverage**

State that the inspected suite contains OpenID4VCI issuer/wallet and OpenID4VP verifier/wallet plans, plus attestation-related conditions within bounded profiles. Record that no applicable standalone plan was found for FAPI HTTP Signatures, RFC 9865/9967 SCIM, browser-app guidance, general OAuth client attestation, Transaction Tokens, or Grant Management.

- [ ] **Step 5: Validate completeness**

Run:

```powershell
rg -n "HTTP Signatures|RFC 9865|RFC 9967|Browser-Based|Attestation-Based|Transaction Tokens|Grant Management|OpenID4VCI|OpenID4VP" docs/conformance/2026-07-11-m8-watchlist-governance.md
```

Expected: every candidate group is present, with OpenID4VCI and OpenID4VP both named explicitly.

### Task 2: Status and Matrix Synchronization

**Files:**
- Modify: `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`
- Modify: `docs/protocol/rfc-compliance-matrix.md`
- Modify: `docs/protocol/profile-matrix.md`
- Modify: `docs/protocol/oauth-spec-implementation-backlog.md`

**Interfaces:**
- Consumes: the decision record from Task 1.
- Produces: consistent roadmap, profile, and backlog summaries that do not overclaim runtime support.

- [ ] **Step 1: Complete the three governance checkboxes**

Change M8-01, M8-02, and M8-03 to `[x]`, link the dated record, and explicitly say that completion means the entry gates are documented rather than that candidate features are implemented.

- [ ] **Step 2: Update roadmap status**

Replace “M8 not started” with a concise completion summary and keep every candidate classified as deferred or separately scoped.

- [ ] **Step 3: Add protocol/profile guardrails**

Add a watchlist row or section stating that absent runtime behavior must remain absent from discovery, client registration, SCIM capability documents, and profile claims.

- [ ] **Step 4: Refresh backlog identifiers**

Update the backlog review date and stale identifiers, including attestation draft `-10`, Transaction Tokens `-09`, and final OpenID4VCI/OpenID4VP status. Correct RFC 9967 wording so it describes SCIM Security Event Tokens rather than generic asynchronous SCIM requests.

- [ ] **Step 5: Check for contradictory status text**

Run:

```powershell
rg -n "M8.*(尚未开始|not started)|M8-0[123]|draft-ietf-oauth-attestation-based-client-auth-09|draft-ietf-oauth-transaction-tokens-08|RFC 9967.*async" docs
```

Expected: no stale “not started” statement, no unchecked M8 task, no stale draft identifier, and no RFC 9967 async misdescription.

### Task 3: Repository-Facing Documentation

**Files:**
- Modify: `docs/conformance/README.md`
- Modify: `docs/conformance/README.zh-CN.md`
- Modify: `docs/README.md`
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/features/scim.md`

**Interfaces:**
- Consumes: the canonical evidence record and synchronized protocol decisions.
- Produces: discoverable, bilingual project status without runtime overclaim.

- [ ] **Step 1: Index the evidence record**

Add the dated M8 document to both conformance indexes and the main documentation index.

- [ ] **Step 2: Add repository status links**

Add a short M8 governance/watchlist link to both root READMEs. State that no candidate protocol support is implied.

- [ ] **Step 3: Correct SCIM capability wording**

Keep `cursor: false`, `asyncRequest: none`, and an empty event URI list as current runtime truth, but describe RFC 9967 specifically as the SCIM Security Event Token profile.

- [ ] **Step 4: Add changelog entry**

Record completion of the M8 governance audit and the deliberate absence of new runtime claims.

- [ ] **Step 5: Verify internal paths**

Run a PowerShell path check for every new relative Markdown link to `2026-07-11-m8-watchlist-governance.md`.

Expected: every referenced local path exists.

### Task 4: Final Verification and Commit

**Files:**
- Verify all files changed by Tasks 1 through 3.

**Interfaces:**
- Consumes: the complete documentation diff.
- Produces: a clean, committed M8 governance baseline suitable for candidate-specific design work.

- [ ] **Step 1: Verify no runtime file changed**

Run:

```powershell
git diff --name-only ef341ba..HEAD
git status --short
```

Expected: only Markdown files under the approved documentation paths and this plan are changed.

- [ ] **Step 2: Verify formatting and placeholders**

Run:

```powershell
git diff --check
rg -n "T[B]D|T[O]DO|implement[[:space:]]later|fill[[:space:]]in[[:space:]]details" docs/conformance/2026-07-11-m8-watchlist-governance.md docs/protocol README.md README.zh-CN.md
```

Expected: no whitespace errors and no placeholders in the M8 material.

- [ ] **Step 3: Verify status consistency**

Run targeted searches for all eight named standards/candidate terms, all three M8 checkboxes, final/deferred wording, and the evidence link.

- [ ] **Step 4: Review the complete diff**

Confirm every standards claim is supported by the named primary source, all summaries agree, and no sentence implies implementation or certification.

- [ ] **Step 5: Commit the governance implementation**

```powershell
git add CHANGELOG.md README.md README.zh-CN.md docs
git commit -m "docs: complete M8 watchlist governance"
```

- [ ] **Step 6: Prepare candidate-specific follow-up**

Use the completed evidence decisions to select only candidates with stable specifications, a bounded product role, and tractable isolation. Each selected runtime candidate requires its own approved design and implementation plan before code changes.
