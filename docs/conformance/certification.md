# Certification and Conformance Evidence

This page is the entry point for certification status and versioned official-suite
evidence. Detailed protocol support is documented in
[Standards and profile support](../integration/openid-connect.md).

## OpenID Foundation certification listing

The OpenID Foundation certification pages list `Nazo Auth Server 0.1.0`, dated
`09-Jun-2026`, for the certified profiles below:

| Profile | Evidence |
| --- | --- |
| OIDC Basic OP | [Plan result](https://www.certification.openid.net/plan-detail.html?plan=Srk6iaVDVcqO5) |
| OIDC Config OP | [Plan result](https://www.certification.openid.net/plan-detail.html?plan=fGiz8QZYR1LVy) |

Official listing pages:

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

## Historical public black-box baseline

The most recent retained historical baseline is recorded in
[2026-07-20 final automated OIDF results](2026-07-20-final-automated-oidf-results.md).
The run used an operator-provided production HTTPS issuer. Public documentation
uses `https://issuer.example` only as a sanitized placeholder. Repository
workflows require operators to provide their own externally reachable
`target_issuer` / `target_origin` workflow inputs, or their own repository
variables for private automation.

| Matrix | Result | Scope |
| --- | --- | --- |
| OIDC / FAPI / FAPI-CIBA | Success | 25 official public plans: 23 concurrent plans plus 2 browser-isolated plans |
| OpenID4VC Final / HAIP | Success | 17 official-suite regression plans |

Historical combined credential-free operator manifest:

| Metric | Value |
| --- | ---: |
| Plan executions | 42 |
| Module instances | 1,178 |
| Passed module results | 1,151 |
| Exactly registered failed modules | 2 |
| Condition successes | 96,805 |
| Exactly registered condition failures | 2 |
| Bounded condition warnings | 5 |
| Expected skips | 15 |
| Bounded review modules | 9 |

The two failed modules are the documented OpenID4VCI pre-authorized-code
one-time-use conflict in the upstream multiple-clients module. Bounded warnings,
reviews, and skips are documented in the linked evidence record. They are not
hidden and must not be described as zero-warning, zero-failure, or zero-skipped
evidence.

This 2026-07-20 `25 + 17 = 42` run is not evidence for the current fixed
`27 + 17 = 44` release gate. A release is current only after all 44 plans have
run against that exact deployed Release and the resulting suite revision,
plan/variant outcomes, and evidence paths have been recorded.

## Matrix scope

| Area | Scope document |
| --- | --- |
| OIDC / FAPI / FAPI-CIBA | [OIDF full matrix](oidf-full-matrix.md) |
| OpenID4VC Final / HAIP | [OpenID4VC Final matrix](openid4vc-final-matrix.md) |
| RFC 9967 SCIM SET local black-box regression | [RFC 9967 SCIM SET black-box matrix](rfc9967-scim-set-matrix.md) |

## Evidence boundary

Conformance claims for this repository must come from public black-box official
suite runs against an explicitly configured production issuer. Runs that depend
on non-public endpoints, private DNS names, private trust roots, local-only
callback origins, or suite-private hostnames are diagnostic runs and must not be
used as production conformance evidence.

OpenID4VC suite results are official-suite regression evidence. They are not an
OpenID Foundation certification listing unless the OpenID Foundation publishes a
matching certification result.
