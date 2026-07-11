# Conformance Records

## Scope

Conformance records are the durable index for official suite evidence and
post-change suite regressions. GitHub Actions artifacts expire; these files keep
run metadata, plan IDs, artifact digests when available, and tested commit SHAs
in the repository.

## Current Evidence

- Certification baseline: [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- Matrix scope: [OIDF full matrix](oidf-full-matrix.md)
- Latest private full-matrix regression: [2026-07-01 TP/PS OIDF full matrix](2026-07-01-tp-ps-full-matrix.md)
- Latest official full matrix: [2026-07-02 NI-004 official OIDF full matrix](2026-07-02-ni-004-official-oidf-full-matrix.md)
- Latest RFC coverage check: [2026-07-02 NI-005 RFC 7592 OIDF coverage](2026-07-02-ni-005-oidf-coverage.md)
- Latest NI-006~NI-011 private targeted OIDF results: [2026-07-02 NI-006~NI-011 private OIDF results](2026-07-02-ni-006-011-private-oidf-results.md)
- Latest public NI-007 FAPI-CIBA targeted OIDF result: [2026-07-03 NI-007 public FAPI-CIBA OIDF results](2026-07-03-ni-007-public-ciba-oidf-results.md)
- Latest NI-006~NI-011 official parallel-isolated full matrix: [2026-07-03 NI-006~NI-011 official parallel-isolated OIDF results](2026-07-03-ni-006-011-official-parallel-isolated-oidf-results.md)
- Latest M2 official parallel-isolated full matrix: [2026-07-08 M2 official parallel-isolated OIDF results](2026-07-08-m2-official-parallel-isolated-oidf-results.md)
- Latest M6 FAPI-CIBA local and official full matrix: [2026-07-11 M6 FAPI-CIBA OIDF results](2026-07-11-m6-official-fapi-ciba-oidf-results.md)

The latest recorded official full-matrix suite run is the 2026-07-11 M6
parallel-isolated run against `https://auth.nazo.run`. It ran from workflow head
SHA `07e69855948ca0a12d4dcd26bb9372e3ea2d04d3`, deployed image
`localhost/nazo-oauth-server:m6-07e6985`, and completed the repository's
20-plan public OIDF matrix in the 18+2 layout with all GitHub Actions jobs
ending in `success`. The exported results contain 639 modules: 631 passed, 6
expected review states, 2 expected skips, and no failed module, condition
failure, or warning.

The latest private full-matrix regression record is the 2026-07-01 TP/PS run
against `https://auth.nazo.run` at runtime commit `31e8f9f`. It used the
repository 16-plan matrix, exported 16 plan archives, and reported 578 test
modules with `0 failures` and `0 warnings`.

The latest NI-006~NI-011 targeted private conformance run used local official suite
snapshot `edbf2514e1e5c850ccf28544953608bda50daf4d`. NI-007 FAPI-CIBA,
NI-008 Front-Channel Logout, and NI-009 Session Management passed with
`0 failures`, `0 warnings`, and `0 skipped modules`. The NI-008/NI-009
exported JSON logs contain informational optional-condition
`Skipped evaluation ...` entries; those are not module-level `SKIPPED` results.

The latest public NI-007 FAPI-CIBA targeted workflow ran against
`https://auth.nazo.run` on 2026-07-03 at workflow head SHA
`0374141ae7aec76c573b06dc8406b10819915309`. GitHub Actions run
`28636561869` completed successfully. The exported suite artifact contains 35
module JSON logs, all `PASSED`, with 2768 condition successes, `0 failures`,
and `0 warnings`.

The latest NI-006~NI-011 official full-matrix regression ran against
`https://auth.nazo.run` on 2026-07-03 at workflow head SHA
`056cf7f90061a9054394593ee1fa7b43f5e26b54`. GitHub Actions run
`28648656293` completed successfully. The workflow executed 18 concurrency-safe
plans in one job and isolated front-channel logout and session-management into
separate browser-sensitive matrix jobs.

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
- workflow name and run URL, or local suite runner path
- job URL and matrix name, when applicable
- pass time and suite runtime
- profiles and feature combinations
- exported artifact name, digest, expiry, and zip filenames when applicable
- plan IDs and plan detail URLs
- pass/failure/warning counts
- skipped-module counts and whether a zero-SKIPPED acceptance gate was met
- any allowed review states
- notes about the public issuer, UI boundary, and test environment

## Boundary

Official suite output is indexed here. The files are not OpenID Foundation
certification statements.

## Request Object Compatibility

Baseline OIDC metadata advertises `none` in
`request_object_signing_alg_values_supported` so the server can exercise OIDC
conformance tests for unsigned Request Objects. This is a compatibility feature,
not a high-security profile feature.

Unsigned Request Objects remain disallowed for FAPI2 profiles, clients that
require PAR request objects, and holder-bound clients. Those paths require
signed Request Objects or reject the request object fail closed.

OIDC dynamic-registration compatibility currently has two expected official
suite skips: unsigned ID Tokens are not supported or advertised, and the
`request_uri` parameter is not enabled (`request_uri_parameter_supported=false`).
These skips are documented as reasonable for the current security posture, but
they must not be treated as zero-SKIPPED evidence.
