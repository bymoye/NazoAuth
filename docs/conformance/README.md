# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Versioned evidence index

- Certification and conformance entry point: [Certification and conformance evidence](certification.md)
- Required public black-box run process: [OIDF public black-box conformance runbook](oidf-public-black-box-runbook.md)
- Certification baseline: [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- Matrix scope: [OIDF full matrix](oidf-full-matrix.md)
- Archived diagnostic full-matrix regression: [2026-07-01 TP/PS OIDF full matrix](2026-07-01-tp-ps-full-matrix.md)
- Archived M7 official full matrix: [2026-07-11 M7 encrypted response OIDF results](2026-07-11-m7-official-encrypted-responses-oidf-results.md)
- Latest RFC coverage check: [2026-07-02 NI-005 RFC 7592 OIDF coverage](2026-07-02-ni-005-oidf-coverage.md)
- Archived NI-006~NI-011 private targeted OIDF results: [2026-07-02 NI-006~NI-011 private OIDF results](2026-07-02-ni-006-011-private-oidf-results.md)
- Latest public NI-007 FAPI-CIBA targeted OIDF result: [2026-07-03 NI-007 public FAPI-CIBA OIDF results](2026-07-03-ni-007-public-ciba-oidf-results.md)
- Archived NI-006~NI-011 official parallel-isolated full matrix: [2026-07-03 NI-006~NI-011 official parallel-isolated OIDF results](2026-07-03-ni-006-011-official-parallel-isolated-oidf-results.md)
- Archived M2 official parallel-isolated full matrix: [2026-07-08 M2 official parallel-isolated OIDF results](2026-07-08-m2-official-parallel-isolated-oidf-results.md)
- Archived M6 FAPI-CIBA local and official full matrix: [2026-07-11 M6 FAPI-CIBA OIDF results](2026-07-11-m6-official-fapi-ciba-oidf-results.md)
- Latest encrypted-response coverage check: [2026-07-11 M7 encrypted response OIDF coverage](2026-07-11-m7-oidf-coverage.md)
- Latest emerging-protocol governance review: [2026-07-11 M8 watchlist governance](2026-07-11-m8-watchlist-governance.md)
- Latest M8 official-suite source coverage scan: [2026-07-11 OIDF v5.2.0 coverage](2026-07-11-m8-oidf-v5.2.0-coverage.md)
- Project-owned RFC 9967 regression scope: [RFC 9967 SCIM SET black-box matrix](rfc9967-scim-set-matrix.md)
- Latest OpenID4VC Final / HAIP alpha regression: [2026-07-16 OpenID4VC Final / HAIP OIDF results](2026-07-16-openid4vc-final-oidf-results.md)
- Historical public black-box full baseline: [2026-07-20 final automated OIDF results](2026-07-20-final-automated-oidf-results.md)

The latest retained historical public black-box baseline is the 2026-07-20 final run set.
The final production revision is
`0a747b42228962e562af012638297c56e3af5505`; GitHub Actions runs
[`29705159845`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845)
and [`29700527789`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789)
both succeeded. The operator public suite completed 25 OIDC/FAPI/FAPI-CIBA
plans and 17 OpenID4VC Final/HAIP plans. Public documents sanitize the actual
issuer as `https://issuer.example`. Raw suite ZIPs are not committable evidence;
that historical record accepts only credential-free manifests produced by the
automation, pinned suite/source revisions, run/job URLs, and exact
expected-result contracts.

Archived diagnostic records remain useful for debugging regressions, but they
are not current conformance evidence. The `25 + 17 = 42` baseline above also
does not satisfy the current `27 + 17 = 44` release gate; a new exact-release
record becomes current only after that entire host-local matrix completes.

The archived diagnostic full-matrix regression record is the 2026-07-01 TP/PS run
against `https://issuer.example` at runtime commit `31e8f9f`. It used the
repository 16-plan matrix, exported 16 plan archives, and reported 578 test
modules with `0 failures` and `0 warnings`.

The latest NI-006~NI-011 targeted diagnostic conformance run used diagnostic official suite
snapshot `edbf2514e1e5c850ccf28544953608bda50daf4d`. NI-007 FAPI-CIBA,
NI-008 Front-Channel Logout, and NI-009 Session Management passed with
`0 failures`, `0 warnings`, and `0 skipped modules`. The NI-008/NI-009
exported JSON logs contain informational optional-condition
`Skipped evaluation ...` entries; those are not module-level `SKIPPED` results.

The latest public NI-007 FAPI-CIBA targeted workflow ran against
`https://issuer.example` on 2026-07-03 at workflow head SHA
`0374141ae7aec76c573b06dc8406b10819915309`. GitHub Actions run
`28636561869` completed successfully. The exported suite artifact contains 35
module JSON logs, all `PASSED`, with 2768 condition successes, `0 failures`,
and `0 warnings`.

The latest NI-006~NI-011 official full-matrix regression ran against
`https://issuer.example` on 2026-07-03 at workflow head SHA
`056cf7f90061a9054394593ee1fa7b43f5e26b54`. GitHub Actions run
`28648656293` completed successfully. The workflow executed 18 concurrency-safe
plans in one job and isolated front-channel logout and session-management into
separate browser-sensitive matrix jobs.

The 2026-07-16 OpenID4VC Final / HAIP alpha record and the 2026-07-17 and
2026-07-19 public black-box records remain historical evidence. The current
production-equivalent evidence is the 2026-07-20 final run set above.

## Coverage Update Rule

Every newly supported RFC, OIDC/FAPI profile, or standards-track protocol
capability must trigger an OIDF suite coverage check. Search the OpenID
Foundation Conformance Suite official production/staging plans, public source,
and release notes for matching official tests.

If official coverage exists, update the repository OIDF matrix execution in the
same change, including the workflow/config inputs, plan list, matrix
documentation, and conformance record. If official coverage does not exist,
record the negative search result and date in the relevant implementation or
conformance record. Local positive, negative, metadata-truth, and
security-boundary tests remain mandatory either way.

## Record Format

- implementation commit SHA
- current documentation commit SHA, when different
- workflow name and run URL; diagnostic-only runs may be summarized without
  publishing local runner paths or host details
- job URL and matrix name, when applicable
- pass time and suite runtime
- profiles and feature combinations
- exported artifact name, digest, expiry, and zip filenames when applicable
- credential-free evidence-manifest digest; raw suite ZIPs retain only filename
  and SHA-256 metadata and are deleted after manifest generation
- plan IDs and plan detail URLs
- pass/failure/warning counts
- skipped-module counts and whether a zero-SKIPPED acceptance gate was met
- any allowed review states
- notes about the public issuer, UI boundary, and test environment

## Boundary

Official suite output is indexed here. The files are not OpenID Foundation
certification statements.

Raw suite ZIP `testInfo.config` values and log bodies can contain credentials,
so they must not enter Git or general-purpose artifacts. Durable results must be
reduced by `scripts/oidf_evidence.py` first.

## Request Object Policy

All Request Objects require an asymmetric signature. Baseline and FAPI metadata
never advertise `none`; the runtime rejects unsigned Request Objects for every
client profile. This follows RFC 9101 rather than preserving an OIDC test-only
compatibility path.

OIDC dynamic-registration compatibility has two logical expected official suite
skips in each dynamic configuration: unsigned ID Tokens and unsigned Request
Objects are not supported or advertised. Signed external Request Objects are
supported only through exact dynamically registered HTTPS `request_uri` values,
with hardened remote fetching; FAPI profiles remain PAR-only. These skips are
documented as reasonable for the current security posture, but
they must not be treated as zero-SKIPPED evidence.
