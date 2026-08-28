# RFC 9967 SCIM SET Black-Box Matrix

## Evidence boundary

This is a project-owned, conformance-oriented regression matrix for the
[RFC 9967 SCIM Profile for Security Event Tokens](https://www.rfc-editor.org/rfc/rfc9967.html)
and its RFC 8936 poll delivery contract. It is not an OpenID Foundation test
plan, certification result, or certification claim.

The OpenID Foundation Conformance Suite `v5.2.0` contains generic Shared Signals
Framework transmitter coverage and recognizes SCIM event URIs, but it does not
contain an end-to-end SCIM provisioning/mutation plan that validates the RFC
9967 event payloads emitted by a SCIM service. Therefore generic SSF coverage is
insufficient evidence for this implementation.

## Executable matrix

The authoritative case registry is
[`tests/contracts/rfc9967-scim-set-matrix.json`](../../tests/contracts/rfc9967-scim-set-matrix.json).
CI executes it through
[`scripts/rfc9967_scim_set_e2e.py`](../../scripts/rfc9967_scim_set_e2e.py).

| Case | External behavior proved |
| --- | --- |
| `discovery_exact_event_uris` | Discovery advertises only the five deliverable notice/lifecycle event URIs and `asyncRequest=none`; the matrix separately exercises the poll endpoint. |
| `poll_authorization_boundaries` | Missing bearer, an unregistered bearer, missing scope, and missing receiver audience fail closed. |
| `create_notice_set_claims` | A SCIM create emits one signed `secevent+jwt` with issuer, audience, `jti`, `txn`, SCIM `sub_id`, and exact create-notice attributes. |
| `receiver_audience_and_ack_isolation` | Each receiver gets a separately audience-bound SET; one receiver's acknowledgement cannot consume another receiver's delivery. |
| `ack_is_terminal_for_receiver` | Acknowledged delivery is not returned again to that receiver. |
| `set_error_requires_content_language` | A described `setErrs` disposition requires `Content-Language` and becomes terminal only when accepted. |
| `patch_notice_and_deactivate_events` | An active-to-inactive patch emits the patch notice and deactivate event in one SET. |
| `put_notice_and_activate_events` | An inactive-to-active replacement emits the put notice and activate event in one SET. |
| `poll_pagination_preserves_order` | `maxEvents` bounds each page, `moreAvailable` is truthful, and acknowledgement advances to the next event. |
| `long_poll_wakes_on_new_event` | A bounded long poll wakes after a later SCIM mutation instead of waiting for its full timeout. |
| `invalid_poll_shapes_fail_closed` | Excessive bounds, duplicate acknowledgements, and unknown fields are rejected. |

## Hard test boundaries

- Production Rust sources under `crates/scim-events/src` and
  `crates/http-actix/src/scim.rs` may not contain test modules or test
  attributes. Domain tests live in `crates/scim-events/tests`; HTTP adapter
  tests live in `crates/http-actix/tests`.
- The black-box runner may seed and delete receiver credentials in
  `scim_tokens` and clean their credential-use audit rows, but it may not read
  or write event/outbox/receipt storage.
  Protocol evidence must come from HTTP responses, published JWKS, and verified
  SET signatures and claims.
- The JSON registry must contain exactly the required cases, without duplicate,
  missing, or silently unexecuted cases.
- `.github/workflows/conformance-security.yml` must enable SCIM Security Events
  and execute both the static policy test and the runtime matrix.

These constraints are enforced by `scripts/verify_static_contracts.py` and
`tests/unit/test_rfc9967_scim_set_e2e_source_policy.py`; they are not documentation-only
conventions.

## Running locally

The runtime matrix expects a migrated server with
the persisted `scim_security_events` module enabled, a PostgreSQL fixture connection, and the
same Python dependencies used by the repository E2E runner image:

```text
python scripts/rfc9967_scim_set_e2e.py --source-policy-check
python tests/unit/test_rfc9967_scim_set_e2e_source_policy.py
python scripts/rfc9967_scim_set_e2e.py
```

`E2E_BASE_URL`, `E2E_ISSUER_URL`, and `E2E_DATABASE_URL` select the isolated
test deployment. The runner creates scoped database credentials and removes
them after the matrix.
