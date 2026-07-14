# FAPI 2.0 HTTP Signatures Draft Resource Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a default-closed FAPI HTTP Signatures resource profile that verifies signed `/fapi/resource` requests, signs all resource responses, and exposes reusable client request/response helpers.

**Architecture:** A repository-local `nazo-http-signatures` crate owns RFC 9421/RFC 9530 canonicalization without network or key custody. The server adapter owns FAPI draft policy, binds parsed signatures to the authenticated tenant/client JWKS, the active server keyset, and Valkey replay state, then wraps the existing resource handler fail closed.

**Tech Stack:** Rust 2024, Actix Web, `httpsig` 0.0.24, `sfv` 0.15, SHA-256, existing JSON Web Key/keyset primitives, Diesel/PostgreSQL, Fred/Valkey.

## Global Constraints

- Target only the OpenID FAPI Working Group draft published 2026-06-26; never claim Final or certified support.
- `ENABLE_FAPI_HTTP_SIGNATURES` defaults to `false` and affects only `/fapi/resource`.
- `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS` defaults to 60 and accepts only 1 through 300.
- Keep OAuth access-token, audience, DPoP/mTLS, expiry, and revocation validation mandatory.
- Never log or persist authorization values, bodies, signature bytes, or private keys.
- Never return an unsigned normal response while the profile is enabled; signing failure returns a bounded 503.
- Do not advertise a non-standard metadata field.
- Follow RED-GREEN-REFACTOR for every production behavior.

---

### Task 1: RFC 9530 digest and RFC 9421 request helper core

**Files:**
- Create: `crates/http-signatures/Cargo.toml`
- Create: `crates/http-signatures/src/lib.rs`
- Create: `crates/http-signatures/src/digest.rs`
- Create: `crates/http-signatures/src/request.rs`
- Create: `crates/http-signatures/tests/request.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Produces: `content_digest(&[u8]) -> String`.
- Produces: `RequestInput`, `RequestPolicy`, `PreparedSignature`, and `prepare_request`.
- Produces: `PreparedSignature::finish(&[u8]) -> SignatureFields`.
- `PreparedSignature::signature_base()` is the exact byte slice the caller signs.

- [ ] **Step 1: Create the crate manifest and write failing digest/request tests**

Add the path dependency to the root package and create tests equivalent to:

```rust
use nazo_http_signatures::{
    content_digest, prepare_request, RequestInput, RequestPolicy,
};

#[test]
fn sha256_content_digest_uses_rfc9530_binary_value() {
    assert_eq!(
        content_digest(b"hello"),
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
    );
}

#[test]
fn request_helper_covers_the_fapi_request_components_in_order() {
    let prepared = prepare_request(
        RequestInput::new("POST", "https://api.example/fapi/resource")
            .header("authorization", "DPoP opaque")
            .header("dpop", "opaque-proof")
            .body(br#"{"amount":10}"#),
        RequestPolicy::new(1_720_000_000, "client-ed25519", "ed25519"),
    ).unwrap();
    let base = std::str::from_utf8(prepared.signature_base()).unwrap();
    assert!(base.contains("\"@method\": POST"));
    assert!(base.contains("\"@target-uri\": https://api.example/fapi/resource"));
    assert!(base.contains("\"authorization\": DPoP opaque"));
    assert!(base.contains("\"dpop\": opaque-proof"));
    assert!(base.contains("\"content-digest\": sha-256=:"));
    assert!(base.ends_with(";created=1720000000;keyid=\"client-ed25519\";alg=\"ed25519\";tag=\"fapi-2-request\""));
}
```

- [ ] **Step 2: Run the crate test and verify RED**

Run: `cargo test --manifest-path crates/http-signatures/Cargo.toml --test request`

Expected: dependencies resolve and compilation fails because the crate API is
not implemented. This first unlocked invocation intentionally refreshes
`Cargo.lock`; every later invocation is locked.

- [ ] **Step 3: Implement the minimal digest and request builder**

Use `httpsig`/`sfv` for RFC serialization. Normalize field names to lowercase,
reject duplicate covered field values, require Authorization, add DPoP only
when present, add the canonical digest for non-empty bodies, and create exactly
this parameter set:

```rust
pub struct RequestPolicy<'a> {
    pub created: i64,
    pub keyid: &'a str,
    pub algorithm: &'a str,
}

pub struct SignatureFields {
    pub signature_input: String,
    pub signature: String,
}

impl PreparedSignature {
    pub fn signature_base(&self) -> &[u8] { &self.base }
    pub fn finish(self, signature: &[u8]) -> SignatureFields { /* RFC 8941 bytes */ }
}
```

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `cargo test --locked --manifest-path crates/http-signatures/Cargo.toml --test request`

Expected: all digest and request preparation tests pass.

- [ ] **Step 5: Add negative property tests and refactor**

Cover invalid method/URI, missing Authorization, header injection, unsupported
algorithm, empty key ID, duplicate headers, body/digest conflicts, and
signature field encoding. Add a property test proving arbitrary bodies round
trip through `content_digest` without panics.

Run: `cargo test --locked --manifest-path crates/http-signatures/Cargo.toml`

Expected: all crate tests pass.

- [ ] **Step 6: Commit**

```text
feat: add FAPI HTTP request signature helper
```

### Task 2: Strict request parsing and verification policy

**Files:**
- Create: `crates/http-signatures/src/verify.rs`
- Create: `crates/http-signatures/src/error.rs`
- Create: `crates/http-signatures/tests/verify_request.rs`
- Modify: `crates/http-signatures/src/lib.rs`

**Interfaces:**
- Consumes: `content_digest`, request component construction, RFC structured fields.
- Produces: `parse_request_for_verification(input, fields, policy) -> VerifiedInput`.
- `VerifiedInput` exposes `signature_base`, `signature`, `keyid`, `algorithm`, `created`, and `replay_fingerprint`.

- [ ] **Step 1: Write failing strict-verifier tests**

Create a valid signed fixture through `prepare_request`, then assert:

```rust
let parsed = parse_request_for_verification(
    request,
    fields,
    VerificationPolicy { now: 1_720_000_030, max_age_seconds: 60, future_skew_seconds: 5 },
).unwrap();
assert_eq!(parsed.keyid(), "client-ed25519");
assert_eq!(parsed.algorithm(), "ed25519");
assert_eq!(parsed.created(), 1_720_000_000);
assert_eq!(parsed.signature_base(), prepared.signature_base());
```

Add one test per rejection: missing/mismatched label, multiple labels, wrong
tag, missing method/target/Authorization/DPoP/digest coverage, stale/future
created, expires before created, wrong digest, altered URI/method/header/body,
unknown algorithm, and malformed structured fields.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked --manifest-path crates/http-signatures/Cargo.toml --test verify_request`

Expected: compilation fails because `parse_request_for_verification` is absent.

- [ ] **Step 3: Implement strict parsing and policy checks**

Define stable errors without sensitive values:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    MissingSignature,
    MalformedSignature,
    AmbiguousSignature,
    UnsupportedAlgorithm,
    InvalidTag,
    MissingComponent,
    InvalidCreated,
    DigestMismatch,
}
```

Select exactly one common label, reconstruct the base from received message
values, compare the content digest in constant time, and compute the replay
fingerprint over the signature, key ID, method, target URI, and authenticated
Authorization field without exposing those values.

- [ ] **Step 4: Run focused and complete crate tests**

Run:

```text
cargo test --locked --manifest-path crates/http-signatures/Cargo.toml --test verify_request
cargo test --locked --manifest-path crates/http-signatures/Cargo.toml
```

Expected: all tests pass with no warnings.

- [ ] **Step 5: Commit**

```text
feat: enforce FAPI HTTP request signature policy
```

### Task 3: Response signing and client response-verification helper

**Files:**
- Create: `crates/http-signatures/src/response.rs`
- Create: `crates/http-signatures/tests/response.rs`
- Modify: `crates/http-signatures/src/lib.rs`

**Interfaces:**
- Consumes: original `RequestInput`, request signature fields, digest helper.
- Produces: `prepare_response(ResponseInput, OriginalRequest, ResponsePolicy) -> PreparedSignature`.
- Produces: `parse_response_for_verification(...) -> VerifiedInput` for clients.

- [ ] **Step 1: Write failing response-link tests**

Assert that a response with a body covers `@status`, response
`content-digest`, request `@method`;req, request `@target-uri`;req, and received
request `signature-input`;req and `signature`;req. Assert created, keyid, alg,
and `tag="fapi-2-response"`.

Also assert the client parser reconstructs the exact base only when given the
same original request and rejects a changed status, body, original URI,
request digest, or request signature field.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked --manifest-path crates/http-signatures/Cargo.toml --test response`

Expected: compilation fails because response APIs are absent.

- [ ] **Step 3: Implement response `req` canonicalization**

Use RFC 9421 Section 2.4 semantics. Require `@status`, `created`, and
`fapi-2-response`; require and validate response content digest for non-empty
bodies. Preserve component order and never canonicalize request values from
response headers.

- [ ] **Step 4: Run all crate tests and RFC example tests**

Run: `cargo test --locked --manifest-path crates/http-signatures/Cargo.toml`

Expected: request, response, digest, negative, and RFC vector tests all pass.

- [ ] **Step 5: Commit**

```text
feat: add FAPI HTTP response signature helper
```

### Task 4: Settings, key binding, and detached cryptography adapter

**Files:**
- Modify: `src/settings.rs`
- Modify: `tests/in_source/src/settings/tests/settings.rs`
- Modify: `src/domain/keyset.rs`
- Modify: `src/support/keyset.rs`
- Modify: `src/support/keyset/external.rs`
- Modify: `src/support/security.rs`
- Create: `src/support/fapi_http_signatures.rs`
- Create: `tests/in_source/src/support/tests/fapi_http_signatures.rs`
- Modify: `src/support/mod.rs`

**Interfaces:**
- Produces settings `enable_fapi_http_signatures: bool` and `fapi_http_signature_max_age_seconds: i64`.
- Produces `KeySet::sign_http_message(&[u8]) -> Result<HttpMessageSignature>`.
- Produces tenant/client JWK verification by exact `kid` and algorithm.

- [ ] **Step 1: Write failing configuration tests**

Assert defaults are disabled/60, accepted boundary values are 1 and 300, and
0/301/non-integer values fail Settings construction. Assert disabled settings
do not alter metadata JSON.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked settings::tests::settings --lib`

Expected: tests fail because the fields are absent.

- [ ] **Step 3: Implement settings and configuration validation**

Read the two exact environment/YAML keys from the design, enforce the numeric
bounds, and add the fields to every test fixture constructor.

- [ ] **Step 4: Write failing detached-signature and JWK-binding tests**

Test Ed25519, RSA-v1_5/SHA-256, and P-256/SHA-256 signing and verification;
PS256 active server key rejection; exact client/kid selection; wrong tenant;
duplicate kid; private JWK member; incompatible kty/curve/alg; RSA below 2048;
and external signer output verification.

- [ ] **Step 5: Run and verify RED**

Run: `cargo test --locked fapi_http_signatures --lib`

Expected: tests fail because the adapter is absent.

- [ ] **Step 6: Implement the adapter**

Map only:

```rust
EdDSA -> "ed25519"
RS256 -> "rsa-v1_5-sha256"
ES256 -> "ecdsa-p256-sha256"
```

Decode existing signing output to raw bytes. For verification, select one
public JWK by exact kid and use the existing vetted JSON Web Key conversion and
crypto backend with explicit algorithm binding. Reject PS256 and all unknown
algorithms without fallback.

- [ ] **Step 7: Run adapter, keyset, settings, and full library tests**

Run:

```text
cargo test --locked fapi_http_signatures --lib
cargo test --locked keyset --lib
cargo test --locked settings --lib
cargo test --locked --lib
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```text
feat: bind HTTP signatures to client and server keys
```

### Task 5: `/fapi/resource` verification, replay protection, and signed responses

**Files:**
- Modify: `src/http/fapi_resource.rs`
- Modify: `tests/in_source/src/http/tests/fapi_resource.rs`
- Modify: `src/support/redis_keys.rs`
- Modify: `tests/in_source/src/support/tests/redis_keys.rs`

**Interfaces:**
- Consumes: core request/response helpers and server crypto adapter.
- Produces: fail-closed signed resource endpoint behavior.
- Produces: hashed replay key `fapi_http_signature_replay:<blake3>` with bounded TTL.

- [ ] **Step 1: Write the failing disabled-compatibility and valid-flow tests**

Prove disabled requests return the pre-change response without signature
headers. Under enabled settings, create a valid access token and registered
client JWK, sign GET and POST requests through the client helper, and verify the
server response through the response helper.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked fapi_resource_http_signature --lib`

Expected: enabled valid-flow tests fail because the endpoint ignores HTTP
signature policy.

- [ ] **Step 3: Implement request verification and key lookup**

Preserve current token/binding/audience/tenant/revocation checks. Load the
tenant-scoped client row matching `claims.client_id`, parse the request, verify
the selected client key, and reject form-body token transport when enabled.

- [ ] **Step 4: Write failing replay and dependency-failure tests**

Assert the first signature is accepted, an exact replay is 401, a fresh
signature is accepted, and Valkey read/write failure is 503. Assert raw
signature/Authorization/body bytes do not occur in the key or log capture.

- [ ] **Step 5: Implement atomic replay consumption**

Use a single Valkey SET NX EX operation after cryptographic verification and
before protected work. The TTL equals the configured maximum age plus future
skew. Treat non-OK and transport errors as fail closed.

- [ ] **Step 6: Write failing signed-error and signing-failure tests**

Cover missing/invalid signature 401, token/audience/revocation errors,
DPoP nonce challenge, successful JSON, and simulated signer failure. Verify
each normal enabled response has a client-verifiable signature linked to the
original request; signer failure must return 503 without the protected body.

- [ ] **Step 7: Implement response finalization**

Collect the final Actix body bytes, compute Content-Digest, construct the
response base using original request values, sign with the active keyset, and
rebuild the response preserving status and security headers. Never return the
collected unsigned response after a signing error.

- [ ] **Step 8: Run focused and regression tests**

Run:

```text
cargo test --locked fapi_resource_http_signature --lib
cargo test --locked fapi_resource --lib
cargo test --locked dpop --lib
cargo test --locked --lib
```

Expected: all tests pass.

- [ ] **Step 9: Commit**

```text
feat: enforce signed FAPI resource exchanges
```

### Task 6: Real-HTTP coverage, documentation, and M8 closure

**Files:**
- Modify: `scripts/full_real_request_e2e.py`
- Modify: `.github/workflows/conformance-security.yml`
- Modify: `docs/operations/configuration.md`
- Modify: `docs/operations/deployment.md`
- Modify: `docs/operations/deployment.zh-CN.md`
- Modify: `docs/protocol/profile-matrix.md`
- Modify: `docs/protocol/rfc-compliance-matrix.md`
- Modify: `docs/protocol/oauth-spec-implementation-backlog.md`
- Modify: `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`
- Create: `docs/protocol/fapi-http-signatures-draft-audit.md`

**Interfaces:**
- Consumes: deployed resource profile and client helper behavior.
- Produces: reproducible signed real-HTTP matrix and dated M8-01/02/03 evidence.

- [ ] **Step 1: Add a failing source/syntax gate for the new real-HTTP cases**

Add test matrix cases for signed GET, signed POST, response verification,
tampered method/URI/Authorization/DPoP/body, stale/future created, replay,
wrong key/client, and unsigned fallback. Make the CI gate require each named
case before the implementation is wired.

- [ ] **Step 2: Run and verify RED**

Run:

```text
python -m py_compile scripts/full_real_request_e2e.py
python scripts/full_real_request_e2e.py --source-policy-check
```

Expected: the source-policy check fails because required signed cases are not
yet all implemented.

- [ ] **Step 3: Implement the real-HTTP cases using the core helper's exact vectors**

Keep credentials in environment/stdin fixtures, never command-line arguments
or output. Verify both signature fields and response/request binding, not only
HTTP status.

- [ ] **Step 4: Update documentation and governance evidence**

Record the exact draft date, users, threat model, configuration, failure and
operator responsibilities, lack of OIDF coverage, algorithm limits, no
metadata advertisement, default-closed scope, and future delta-audit triggers.
Mark M8-01/02/03 complete for this bounded candidate only.

- [ ] **Step 5: Run local quality and security gates**

Run:

```text
cargo fmt --check
cargo check --locked
cargo clippy --locked -- -D warnings
cargo test --locked --lib
cargo test --locked --manifest-path crates/http-signatures/Cargo.toml
python -m py_compile scripts/full_real_request_e2e.py
git diff --check origin/main...HEAD
```

Expected: every command exits 0 and the library test count has no failures.

- [ ] **Step 6: Commit**

```text
docs: record FAPI HTTP signatures draft evidence
```

### Task 7: Review, PR, deployment, matrices, and merge

**Files:**
- Modify only files required by verified review findings.

**Interfaces:**
- Consumes: exact reviewed branch head.
- Produces: merged PR and verified production deployment.

- [ ] **Step 1: Request independent code review**

Review correctness, RFC canonicalization, structured-field ambiguity, key
binding, replay races, response downgrade, sensitive logging, default-off
compatibility, tests, and standards claims. Fix only validated findings through
new failing tests.

- [ ] **Step 2: Push and create a draft PR**

Push `codex/m8-http-signatures`, create a draft PR, record exact head and all
local verification evidence, and wait for every repository check.

- [ ] **Step 3: Deploy the exact PR head to Hostinger**

Build and tag both server and seed images with the short commit, transfer by
digest, deploy with the feature disabled for regression first, verify health,
then enable only the signed `/fapi/resource` smoke configuration.

- [ ] **Step 4: Run deployed signed exchange and Hostinger-local OIDF matrix**

Verify positive and negative signed exchanges. Run 19 concurrent official-
layout plans, Front-Channel Logout, and Session Management against the deployed
exact head. Require completion with no failures.

- [ ] **Step 5: Run official OIDF matrix**

Generate the exact official public config artifact, seed production from that
same artifact, verify its public-key fingerprint, trigger the full 19+1+1
workflow on the exact PR head, and inspect result artifacts in addition to the
workflow conclusion.

- [ ] **Step 6: Mark Ready and merge with head guards**

After all checks and matrices pass, update PR evidence, mark Ready, merge using
`--match-head-commit`, fetch `main`, prove the reviewed head is an ancestor,
and re-verify production health and a signed exchange.

---

## Plan self-review

- Every design requirement maps to a task: core canonicalization (1-3), key and
  settings boundary (4), server/replay/fail-closed behavior (5), evidence and
  M8 governance (6), and release proof (7).
- No task changes the default OAuth/OIDC/FAPI metadata or routes outside
  `/fapi/resource`.
- The client helper is a usable library package rather than an inaccessible
  `pub(crate)` server module.
- All production behavior has an explicit RED command before implementation.
- Function/type names are consistent across tasks and no placeholder work is
  deferred inside the plan.
