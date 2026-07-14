# RFC 9865 SCIM Cursor Pagination Design

**Date:** 2026-07-11

**Status:** Approved for implementation

**Repository:** verified NazoAuth checkout

**Branch:** `codex/m8-watchlist`

## 1. Context

NazoAuth currently supports SCIM `GET /scim/v2/Users` with index pagination
through `startIndex` and `count`. `/ServiceProviderConfig` truthfully advertises
index pagination and `cursor: false`.

RFC 9865 is an IETF Standards Track extension for cursor-based SCIM pagination.
It requires opaque URL-safe cursors, `nextCursor` on every non-final cursor
page, stable query parameters between pages, explicit pagination errors, and
continuous authorization checks. It permits a service provider to support both
index and cursor methods and recommends retaining index as the default when it
was the existing behavior.

The M8 governance review selected RFC 9865 as the only immediately bounded
runtime candidate. No applicable RFC 9865 plan was found in OpenID
conformance-suite commit `33a724c7d809a6f9db05cbb513ff2a77cbac905e`, so local
positive, negative, security, and metadata-truth tests are the acceptance
evidence.

## 2. Goals

1. Support RFC 9865 forward cursor traversal for `GET /scim/v2/Users`.
2. Preserve index pagination as the default and as an explicitly selectable
   method.
3. Make cursor values opaque, tamper-evident, confidential, URL-safe, bounded
   in lifetime, and independent of server-side cursor storage.
4. Bind every cursor to the authenticated SCIM actor, tenant, exact filter,
   effective count, ordering policy, and last returned row.
5. Use deterministic keyset pagination over `(created_at, id)` rather than
   database offset for cursor traversal.
6. Re-authorize the SCIM credential and scope on every page request.
7. Return RFC 9865 `invalidCursor`, `expiredCursor`, and `invalidCount` error
   types without leaking whether a hidden row or page exists.
8. Advertise cursor support only after implementation and tests exist.

## 3. Non-goals

- Optional `previousCursor` reverse traversal.
- Cursor pagination for Schemas, ResourceTypes, Groups, or unsupported SCIM
  resources.
- SCIM `POST /Users/.search` or `POST /Groups/.search`.
- Sorting parameters beyond the server's deterministic internal order.
- RFC 9967 SCIM Security Event Tokens or asynchronous completion.
- Persisted cursor records, cursor revocation lists, or a new Valkey dependency.
- Changing the default pagination method from `index`.
- Removing or changing existing SCIM authentication, scopes, or index response
  semantics.

## 4. Selected Approach

Use a stateless, versioned cursor encrypted and authenticated with AES-256-GCM.
The cursor is compact base64url without padding and contains a random 96-bit
nonce followed by ciphertext and the 128-bit GCM authentication tag.

The AES key is derived at runtime from the existing stable
`CLIENT_SECRET_PEPPER` with HMAC-SHA-256 and the fixed domain-separation label
`nazo-scim-cursor-aes256gcm-v1`. The pepper is already required for non-loopback
production issuers and must remain stable across restarts. Domain separation
prevents the cursor encryption key from being used as a client-secret hash key.
The derived key is never logged or persisted.

This approach is preferred over Valkey-backed random cursor handles because it
does not allocate attacker-controlled cursor state and does not make list
pagination depend on Valkey availability. It is preferred over a signed but
readable token because RFC 9865 says cursor values should be obfuscated and
opaque to clients.

## 5. Cursor Payload and Cryptography

The encrypted JSON payload contains:

```text
v: 1
tenant_id: UUID
actor: "database:<token UUID>" or "legacy-env"
filter: exact optional query string
count: effective page size from 0 through 200
sort: "created_at,id"
last_created_at: RFC 3339 timestamp
last_id: UUID
issued_at: Unix seconds
expires_at: Unix seconds
```

The cursor lifetime is 600 seconds. `/ServiceProviderConfig` advertises
`cursorTimeout: 600`.

Encryption uses a fresh random nonce for every output cursor. AES-GCM additional
authenticated data is the ASCII string `nazo-scim-cursor-v1`. Decoding rejects:

- non-base64url or padded input;
- input outside a small fixed encoded-length ceiling;
- truncated nonce, ciphertext, or tag;
- authentication failure;
- malformed JSON;
- an unknown payload version or sort policy;
- malformed UUID or timestamp values;
- an `issued_at` more than 60 seconds in the future;
- `expires_at <= issued_at` or lifetime greater than 600 seconds;
- an expired `expires_at`.

Cryptographic or structural failures map to `invalidCursor`. A valid authenticated
payload whose `expires_at` has passed maps to `expiredCursor`. Logs may distinguish
internal reasons but responses do not expose payload contents or database state.

## 6. Actor and Query Binding

`require_scim_bearer` already returns a `ScimCredential`. The list handler keeps
that value instead of discarding it.

The actor binding is:

- `database:<token_id>` for a database-backed SCIM token;
- `legacy-env` for the single configured legacy bearer token.

The cursor tenant must equal both the authenticated credential tenant and the
served default tenant. A token rotation to a different database token does not
inherit a cursor, even when it has the same scopes. This supports the RFC 9865
requirement to apply authorization continuously and prevents cursors from
becoming bearer authorization artifacts.

The cursor stores the exact optional `filter` query value. Subsequent requests
must provide the same value and the same effective `count`. A mismatch in
`count` maps to `invalidCount`; actor, tenant, filter, sort, and other cursor
context mismatches map to `invalidCursor`.

For the first cursor page, `cursor` is present and empty. A non-empty cursor is
valid only as the output of a previous NazoAuth cursor response. Supplying both
`cursor` and `startIndex` is rejected as a SCIM `invalidValue` error because the
client must select one pagination method.

## 7. Pagination Semantics

The query structure gains `cursor: Option<String>`. Method selection is:

| Request | Method |
| --- | --- |
| no `cursor`, no `startIndex` | existing index default |
| `startIndex` only | existing index method |
| empty `cursor` | first cursor page |
| non-empty `cursor` | subsequent cursor page |
| both `cursor` and `startIndex` | HTTP 400 SCIM `invalidValue` |

Index behavior remains compatible, except its database order becomes
`created_at ASC, id ASC` so equal timestamps are deterministic.

Cursor behavior uses the same default page size of 100 and maximum page size of
200. On the first page, negative `count` is interpreted as zero as RFC 9865
requires; values above 200 return `invalidCount` rather than being silently
clamped. On later pages, the effective count must equal the cursor payload.

For a positive count, the database loads at most `count + 1` rows ordered by
`created_at ASC, id ASC`. A later page applies:

```text
created_at > last_created_at
OR (created_at = last_created_at AND id > last_id)
```

The extra row determines whether another page exists and is not returned. When
another page exists, `nextCursor` is produced from the last returned row. The
final page omits `nextCursor`. Cursor responses omit `startIndex` and never emit
`previousCursor`.

For `count=0`, the handler returns `totalResults`, `itemsPerPage: 0`, no
resources, and no `nextCursor`; this follows RFC 9865's zero-count semantics
without creating a cursor that cannot advance.

`totalResults` remains an accurate count at the time each page is requested.
Concurrent inserts after the last marker may appear on a later page; deletes may
reduce the total or remove future rows. Already returned rows are not repeated
as long as their `(created_at, id)` values do not change. These are documented
live-result-set semantics rather than snapshot isolation.

## 8. Response and Error Semantics

Cursor success responses contain:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 250,
  "itemsPerPage": 100,
  "nextCursor": "opaque-value",
  "Resources": []
}
```

`nextCursor` is omitted on the last page. `previousCursor` and `startIndex` are
omitted for every cursor response.

Errors use HTTP 400 and the existing SCIM error envelope:

| Condition | `scimType` |
| --- | --- |
| malformed, forged, context-mismatched, or unknown cursor | `invalidCursor` |
| authenticated cursor past its expiry | `expiredCursor` |
| first-page count above 200 or later-page count mismatch | `invalidCount` |
| both index and cursor parameters | `invalidValue` |

Database and connection failures retain HTTP 503 `server_error`. Authentication
and scope errors retain their current HTTP 401/403 behavior and happen before
cursor validation, preventing cursor validity from becoming an authorization
oracle.

## 9. File Boundaries

- Create `src/http/scim/cursor.rs` for payload types, key derivation,
  encryption/decryption, context validation, and cursor-specific errors.
- Modify `src/http/scim.rs` for query-method selection, deterministic database
  ordering, keyset queries, response construction, and capability advertising.
- Add focused unit tests at
  `tests/in_source/src/http/scim/tests/cursor.rs` through the existing in-source
  test module pattern.
- Modify `tests/in_source/src/http/tests/scim.rs` for handler/database,
  authorization, pagination, metadata, and error integration tests.
- Update `docs/features/scim.md`, the RFC/profile matrices, the M8 evidence
  decision, both root READMEs, and `CHANGELOG.md` only after tests pass.

No migration or new dependency is required. OpenSSL, HMAC, base64, serde, UUID,
and chrono are already direct dependencies.

## 10. TDD and Test Strategy

Implementation follows red-green-refactor. Each production behavior begins with
a failing test that fails for the missing behavior rather than a fixture error.

### Cursor codec tests

- encrypted output round-trips and is URL-safe without padding;
- the same payload produces different cursors because nonces differ;
- encoded content does not reveal tenant, token ID, email filter, timestamp, or
  database UUID strings;
- tampered nonce, ciphertext, and tag fail;
- malformed base64, padding, truncation, oversize input, malformed JSON,
  unsupported version/sort, invalid UUID/time, future issue time, invalid
  lifetime, and expiry map correctly;
- actor, tenant, filter, and count bindings are enforced;
- database-token and legacy-token actor identities remain distinct;
- key derivation is deterministic and domain separated.

### Handler and database tests

- index remains the default and explicit `startIndex` still works;
- both pagination methods order equal timestamps by UUID;
- empty cursor returns the first page and a `nextCursor` when more rows exist;
- subsequent cursor pages neither repeat nor skip the seeded deterministic set;
- the last page omits `nextCursor`;
- `count=0`, empty sets, exact page boundary, count 1, default count, and maximum
  count behave correctly;
- negative first-page count becomes zero and over-limit count is rejected;
- later count omission resolves to the original default only when equal, and a
  changed count returns `invalidCount`;
- filter, credential, tenant, or cursor substitution returns `invalidCursor`;
- expired cursor returns `expiredCursor`;
- simultaneous `startIndex` and `cursor` returns `invalidValue`;
- current authentication, read scope, token usage audit, and backend-failure
  behavior remain enforced on every page;
- concurrent insertion after the marker may appear later without repeating an
  earlier row, and deletion does not make an earlier row repeat.

### Metadata and regression tests

- `/ServiceProviderConfig` advertises `cursor: true`, `index: true`,
  `defaultPaginationMethod: index`, default/max page sizes, and
  `cursorTimeout: 600`;
- no RFC 9967 capability changes;
- SCIM create, get, replace, patch, delete, filter, credential scope, tenant,
  audit, and deprovisioning tests remain green;
- the complete library test suite and standard format/check/clippy gates pass.

## 11. Documentation and Conformance

After implementation passes local verification:

- update SCIM documentation from `cursor: false` to the exact supported
  forward-only, stateless behavior;
- update README and protocol/profile matrices without claiming OIDF
  certification;
- update the M8 evidence decision from “selected for design” to
  “implemented/local evidence”;
- record that no RFC 9865-specific OIDF plan was found in inspected suite commit
  `33a724c7d809a6f9db05cbb513ff2a77cbac905e`;
- do not add RFC 9865 to the OAuth/OIDC/FAPI official public matrix because the
  feature is SCIM and no applicable plan exists.

## 12. Completion Criteria

RFC 9865 cursor pagination is complete only when:

1. both index and cursor pagination work and index remains the default;
2. cursor tokens are confidential, authenticated, URL-safe, versioned, actor-
   and query-bound, and expire after 600 seconds;
3. every page re-runs SCIM bearer, scope, and tenant authorization;
4. keyset order is deterministic over `(created_at, id)`;
5. every non-final positive-count page returns `nextCursor` and the final page
   omits it;
6. error types match RFC 9865 without becoming an authorization oracle;
7. capability output advertises only the implemented behavior;
8. targeted cursor, SCIM regression, full library, format, check, and clippy
   commands pass with no new warnings;
9. documentation and M8 evidence describe the implemented boundary without an
   unsupported certification claim.
