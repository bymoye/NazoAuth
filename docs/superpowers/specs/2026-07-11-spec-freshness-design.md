# Standards Freshness and Browser Draft-27 Correction Design

Date: 2026-07-11

## Outcome

NazoAuth will maintain a machine-readable inventory of every normative or
watchlist specification used by its active protocol documentation, verify that
inventory against official primary sources on a schedule, and correct the
current version drift. Historical evidence remains immutable and explicitly
records the version used at the time.

This correction also re-audits the only normative delta between
`draft-ietf-oauth-browser-based-apps-26` and `-27`. The new cookie-name prefix
recommendation is scoped to a Backend for Frontend (BFF). NazoAuthWeb is the
same-origin frontend of the authorization server: it uses a server-managed
login session, does not hold OAuth tokens, and does not proxy resource requests.
It must not be described as a BFF. Consequently, the delta changes the audit
classification and future re-entry baseline, but does not justify changing
NazoAuth's runtime cookie names or claiming BFF conformance.

## Source authority

Only these sources can establish current status:

- IETF Datatracker document records for active Internet-Drafts;
- RFC Editor canonical records for immutable RFCs;
- OpenID Foundation canonical specification pages for OIDF documents; and
- the official OpenID conformance-suite GitLab releases API and repository.

Search-engine indexes, repository prose, and previously downloaded suite
snapshots are discovery aids, never version authority.

## Inventory model

`requirements/spec-freshness.json` contains:

- a stable identifier and title;
- source kind (`ietf_draft`, `rfc`, `openid_document`, or `oidf_suite`);
- canonical official URL;
- expected current revision, status marker, release tag, and commit where
  applicable; and
- whether the item is active, final/immutable, or historical-only.

The inventory covers all active IETF drafts, OpenID specifications, RFCs, and
the conformance-suite cited by active protocol/profile/conformance guidance.
Historical dated evidence may cite older revisions, but active status tables,
workflows, and future test guidance must use the inventory baseline.

## Verification tool

`scripts/check_spec_freshness.py` has two modes:

1. Offline validation checks schema, unique identifiers and URLs, allowed
   official hosts, revision/tag formats, and active-document pins without
   network access. Unit tests use deterministic fixtures.
2. Online validation fetches official sources, confirms IETF `rev` values,
   required OpenID/RFC page markers, and the latest OIDF release tag/commit.
   Network errors are failures in the scheduled/manual job and are reported
   separately from version mismatches.

A dedicated GitHub workflow runs offline validation on relevant pull requests
and the online check weekly and on manual dispatch. This avoids turning every
unrelated PR into a dependency on external availability while still detecting
drift automatically.

## Known corrections

- Browser-Based Applications: `-26` to `-27`, published 2026-07-06.
- FAPI-CIBA: distinguish the implemented stable `ID1` / draft-02 compatibility
  target from the current `fapi-ciba-03` working copy dated 2026-06-26.
- Grant Management: old `fapi-grant-management-01` naming to the current
  `oauth-v2-grant-management-03` working copy built 2026-06-26; its stable
  `ID1` snapshot was approved as an Implementer's Draft.
- OIDF conformance-suite default: old commit to `release-v5.2.0` at
  `dee9a25160e789f0f80517674693ef7989ab9fa1`.
- Active candidate records must consistently use Client Attestation `-10` and
  Transaction Tokens `-09`.

The implementation must not rewrite dated result records that truthfully
describe an older suite commit. Instead, current guidance will distinguish
historical evidence from the latest required regression baseline.

## Verification and release

The change is accepted only after:

- unit and offline freshness checks pass;
- the online checker passes against primary sources;
- Browser `-26`/`-27` delta and active-doc scans are clean;
- repository formatting and relevant Rust regression tests pass;
- the deployed Hostinger instance passes the local 19 + Front-Channel Logout
  + Session Management matrix using conformance-suite `v5.2.0`; and
- the exact correction commit passes the official OIDF workflow and PR checks.
