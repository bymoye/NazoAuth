# FAPI 2.0 HTTP Signatures Draft Resource Profile Design

Date: 2026-07-11

## Purpose

Add an explicitly experimental, default-closed FAPI 2.0 HTTP Signatures
resource profile to NazoAuth. The built-in `/fapi/resource` endpoint will
verify client request signatures and sign its responses. A transport-neutral
Rust helper crate will expose the same request-signing and response-verification
operations to client implementations.

This work implements the previously approved resource-server and client-helper
scope. It does not extend HTTP signatures to authorization-server protocol
endpoints and does not claim conformance with a final OIDF standard.

## Standards and conformance status

The target document is **FAPI 2.0 Http Signatures (Draft)** published by the
OpenID FAPI Working Group on 2026-06-26:

- https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html

The draft says that it is not an OIDF International Standard and is subject to
change. It profiles the following final IETF standards:

- RFC 9421, HTTP Message Signatures:
  https://www.rfc-editor.org/rfc/rfc9421.html
- RFC 9530, Digest Fields:
  https://www.rfc-editor.org/rfc/rfc9530.html

The OpenID conformance-suite release used by NazoAuth has no HTTP Signatures
plan. Existing FAPI/OIDC plans are regression evidence only. Acceptance
therefore uses RFC examples, local positive and negative interoperability
tests, deployed real-HTTP tests, and the unchanged local and official OIDF
19+1+1 matrices.

## Product scope and users

The feature is for confidential FAPI clients calling NazoAuth's built-in
resource endpoint when an ecosystem requires application-level
non-repudiation in addition to TLS and sender-constrained access tokens.

The integration has two roles:

1. A client signs the resource request using a registered public-key pair.
   NazoAuth resolves the public key from the authenticated client's registered
   JWKS and verifies the signature.
2. NazoAuth signs the resource response using its active server signing key.
   The client helper verifies the response and its cryptographic link to the
   original request.

Operators own feature enablement, client key registration, active server key
availability, clock synchronization, and retention policy for any signed
messages stored outside NazoAuth. NazoAuth does not persist request or response
bodies for non-repudiation evidence.

## Approaches considered

### Direct handler integration

Calling an RFC 9421 crate directly from `fapi_resource` has the smallest diff,
but mixes canonicalization, draft policy, Actix extraction, key lookup, replay
state, and client-facing helper behavior in one endpoint. It is difficult to
test independently and cannot be consumed by a client.

### Reusable core crate plus server adapter (selected)

A repository-local `nazo-http-signatures` crate owns structured-field
parsing, signature-base construction, digest handling, and client helper APIs.
NazoAuth owns FAPI coverage policy, access-token authentication, client/key
resolution, cryptographic key custody, replay storage, and Actix response
adaptation. This keeps draft churn isolated while giving server and client
code the same canonicalization implementation.

### Reverse proxy or sidecar

A gateway can sign and verify HTTP messages without changing the application,
but it cannot safely bind `keyid` to the tenant-scoped `client_id` established
by NazoAuth's JWT or introspection result. Replicating that trust and key state
would increase deployment, rotation, and audit risk, so this approach is not
selected.

## Configuration and default posture

Add two settings:

- `ENABLE_FAPI_HTTP_SIGNATURES=false`
- `FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS=60`

The maximum age is valid from 1 through 300 seconds. The feature is rejected at
startup when enabled with an unsupported active server signing algorithm or
without usable server signing key material.

The flag affects only `/fapi/resource`. When disabled, current behavior and all
metadata remain byte-for-byte compatible apart from unrelated runtime values.
The draft defines no protected-resource metadata field for this capability, so
NazoAuth does not invent or advertise one.

## Request verification

When enabled, a signed request must:

- carry exactly matching `Signature-Input` and `Signature` labels;
- use one supported signature selected by policy, with no ambiguous fallback;
- cover `@method`, `@target-uri`, and `authorization`;
- include `created` no more than the configured age in the past and no later
  than the bounded clock-skew allowance;
- include `tag="fapi-2-request"`;
- cover `dpop` whenever the DPoP header is present;
- carry and cover `content-digest` whenever the body is non-empty;
- have a valid RFC 9530 SHA-256 content digest; and
- verify with the tenant-scoped authenticated client's registered public JWK
  identified by `keyid`.

The HTTP-signature check runs only after the access token has been
cryptographically decoded enough to establish `client_id` and tenant, but
before the protected operation and before a success response. Normal token,
audience, DPoP/mTLS, revocation, and expiry checks remain mandatory. The
signature never substitutes for OAuth authentication or sender constraint.

The profile requires the Authorization header to be covered. Consequently,
form-body access-token transport is rejected while the feature is enabled.
This restriction is profile-scoped and does not change the disabled path.

After successful cryptographic verification, NazoAuth stores a BLAKE3 digest
of the signature and authenticated context in Valkey with NX semantics for the
configured validity window. A duplicate is rejected as a replay. Cache
unavailability fails closed; signatures, authorization values, and bodies are
never logged or used directly as cache keys.

## Response signing

When enabled, every `/fapi/resource` response, including bounded OAuth errors,
is signed after its final status, headers, and body are known. The signature:

- covers `@status`;
- includes `created` and `tag="fapi-2-response"`;
- adds and covers a SHA-256 `content-digest` for a non-empty body;
- uses RFC 9421 `req` components to cover the request's `@method` and
  `@target-uri`;
- covers the request `content-digest` with `req` when present; and
- covers the received request `signature-input` and `signature` with `req`
  when both were present.

The response uses one label, `nazo`, and identifies the active server key by
its published JWKS `kid`. The active JWT algorithms EdDSA, RS256, and ES256 map
to the RFC 9421 algorithms `ed25519`, `rsa-v1_5-sha256`, and
`ecdsa-p256-sha256`. PS256 has no equivalent with identical hash parameters in
RFC 9421 and is rejected for this profile rather than silently remapped.

If signing fails, NazoAuth returns a bounded 503 response without the protected
payload. It never downgrades to an unsigned success or unsigned normal error
while the feature is enabled.

## Client helper API

Create `crates/http-signatures` as a normal Rust library package and add it
as a path dependency of the server. Its public API is transport-neutral:

- `content_digest(body)` returns the canonical RFC 9530 SHA-256 field value;
- `prepare_request(input, policy)` validates inputs and returns the exact
  signature base plus parameters;
- `finish_signature(prepared, signature_bytes)` returns `Signature-Input` and
  `Signature` field values;
- `prepare_response_verification(response, original_request, policy)` returns
  the exact response signature base and parsed signature bytes; and
- parsed results expose `keyid`, algorithm, created time, tag, covered
  components, and a replay fingerprint without exposing authorization values.

The crate performs no network calls, database lookup, clock reading, logging,
or private-key loading. Callers provide the current time and cryptographic
sign/verify operation. This makes policy and canonicalization deterministic and
lets client applications keep keys in their own HSM, KMS, or secure process.

## Key binding and algorithms

The server selects a client JWK by exact `kid` from the already authenticated
client's tenant-scoped database row. It rejects duplicate `kid`, private JWK
members, keys not allowed for signature verification, incompatible key types,
and any JWK `alg` that conflicts with the selected HTTP algorithm. A JWK with no
`alg` may be used when its key type and curve match the HTTP algorithm.

The first profile supports:

- `ed25519` with OKP/Ed25519 keys;
- `rsa-v1_5-sha256` with RSA keys of at least 2048 bits; and
- `ecdsa-p256-sha256` with EC/P-256 keys.

HMAC, RSA keys below 2048 bits, unknown algorithms, algorithm confusion,
multiple matching keys, and private JWK material are rejected. Additional
algorithms require a separate threat review and test vectors.

## Failure semantics

- Missing, malformed, stale, future-dated, replayed, incorrectly tagged,
  insufficiently covered, digest-mismatched, key-mismatched, or
  cryptographically invalid request signatures return HTTP 401.
- OAuth access-token transport conflicts continue to return their existing
  bounded errors before protected data is released.
- Key database or replay-store failure returns 503 and does not execute the
  protected operation.
- Response signing failure returns 503 and discards the unsigned response
  body.
- Error descriptions do not reveal which client key, signature byte, digest,
  or authorization value failed.

## Threat model

The profile addresses modification of meaningful HTTP components after TLS
termination, replay of an otherwise valid signed request, signature wrapping
through multiple labels, key confusion between clients or tenants, body
substitution, response substitution, and a client denying the use of its
registered signing key.

It does not prove which real-world end user initiated a request, protect data
that was deliberately left outside the covered component set, make stored
messages safe to retain, or replace TLS, OAuth authorization, DPoP/mTLS sender
constraint, access-token audience checks, and revocation checks.

## Testing and acceptance

The core crate must include RFC 9421/RFC 9530 examples plus deterministic
canonicalization tests for request and response `req` components. Every policy
requirement receives a positive test and a focused negative test.

Server tests cover disabled-path compatibility, valid signatures for each
supported algorithm, wrong client and tenant, duplicate key IDs, stale and
future timestamps, missing coverage, DPoP coverage, body digest mismatch,
replay, storage failure, signed success, signed OAuth errors, response/request
binding, and fail-closed response signing.

Real-HTTP tests exercise a signed GET, signed POST, DPoP request, response
verification through the client helper, tampered body/header/URI, replay, and
unsigned fallback rejection. Normal formatting, compilation, clippy, unit,
coverage, CodeQL, dependency, and security gates remain required.

After deployment to `auth.nazo.run`, acceptance requires:

1. deployed signed-request/signed-response smoke tests;
2. Hostinger-local OIDF 19-plan matrix plus Front-Channel Logout and Session
   Management;
3. the official OIDF 19+1+1 workflow on the exact PR head; and
4. all PR checks passing before merge.

The OIDF runs prove that the default OAuth/OIDC/FAPI surfaces did not regress;
they are not HTTP Signatures certification.

## Documentation and M8 governance

Update the roadmap, backlog, RFC compliance matrix, configuration reference,
deployment guidance, and test evidence to record:

- the exact 2026-06-26 draft and review date;
- the intended clients, threat model, integration, failures, and operator
  responsibilities (M8-01);
- the normative sources, draft status, lack of an OIDF plan, and local test
  strategy (M8-02); and
- the default-closed route scope, no metadata overclaim, and unchanged baseline
  profile behavior (M8-03).

The re-entry trigger is a new OIDF draft, Implementer's Draft, Final
Specification, registered metadata, or official conformance plan. Each trigger
requires a delta audit before changing the standards claim.
