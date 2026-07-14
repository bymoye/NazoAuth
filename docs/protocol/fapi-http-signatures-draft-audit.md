# FAPI 2.0 HTTP Signatures Draft Audit

## Decision and source boundary

NazoAuth implements a bounded, experimental resource profile against the
OpenID FAPI 2.0 HTTP Signatures working draft built on 2026-06-26. It is not an
OIDF Final Specification and is distinct from FAPI 2.0 Message Signing Final.
The implementation uses RFC 9421 HTTP Message Signatures and RFC 9530
`Content-Digest` primitives. A newer working draft, Implementer's Draft, or
Final Specification requires a normative delta audit before changing this
claim or behavior.

## M8-01: product and threat boundary

The intended user is a registered confidential resource client that needs
application-layer evidence binding an access-token exchange to the exact
method, target URI, selected Authorization/DPoP fields, and body. The feature
addresses intermediary or application-layer mutation, replay, wrong-client or
wrong-key use, and unsigned-response downgrade. It does not replace TLS,
sender-constrained tokens, access-token audience checks, or authorization.

The only runtime gate is `ENABLE_FAPI_HTTP_SIGNATURES`, default `false`; the
only affected route is `/fapi/resource`. No discovery, authorization-server,
protected-resource, registration, or algorithm metadata is advertised.
Existing OAuth/OIDC, FAPI2 Security, Message Signing, CIBA, and SCIM behavior
is unchanged while the gate is off.

Operators own client public-key provisioning and revocation, server signing
key custody and rotation, clock synchronization, Valkey durability and
availability for atomic replay consumption, log redaction, incident handling,
and signed-evidence retention. Key lookup is bound to the access token's tenant
and `client_id`; request `keyid` never selects another client's key.

## Cryptographic and protocol limits

The accepted request and generated response algorithms are:

- `ed25519` with an Ed25519 OKP key;
- `rsa-v1_5-sha256` with an RSA public key of at least 2048 bits;
- `ecdsa-p256-sha256` with a P-256 public key.

Private JWK members, a JWK `use` other than the string `sig`, any present
`key_ops` value other than the exact one-element string array `["verify"]`,
unsupported curves, key/alg
mismatch, ambiguous fields or keys, malformed structured fields, missing
required covered components, invalid body digests, stale/future creation times,
and replay all fail closed. The required profile components are validated as a
set while safe, unique ordinary header components may be selected explicitly
and are reconstructed in received RFC 9421 identifier order. Responses cover
status, physical response digest, final `Content-Type` and
`X-Fapi-Interaction-Id` values when present, request method and target URI, the
semantic request digest when present, and the exact received request
`Signature-Input` and `Signature` fields. Signing or replay-store failure cannot
downgrade to an unsigned success, and external signer stderr is not logged.
Reserved `Signature` and `Signature-Input` fields cannot be selected as extras,
preventing self-referential signature bases. The server captures safe request
header context once per request using lowercase unique names and valid
control-free text; ambiguous or non-text values are unavailable to component
reconstruction and therefore fail closed if selected.

## M8-02: evidence and conformance status

The Rust crate is the canonical canonicalization and cryptographic vector
implementation. Its tests cover GET/POST, structured-field ambiguity, digest,
time, algorithm/key policy, replay fingerprints, request binding, response
binding, and altered inputs. `scripts/full_real_request_e2e.py` mirrors the
fixed Ed25519 wire vector only to exercise the deployed HTTP boundary; it is
guarded by a syntax/source-policy check and is not an independent
cryptographic truth source.

The real-HTTP matrix covers signed GET and POST, a successful DPoP-bound
resource request whose HTTP signature covers the nonce-bearing DPoP proof,
client verification of the server signature and request binding, tampered
method/URI/Authorization/DPoP/body, tampered signed response `Content-Type` and
`X-Fapi-Interaction-Id`, stale and future creation times, replay, wrong key,
wrong client, and the unsigned legacy path on a separately started default-off
server. The matrix also exercises a successful request covering `Content-Type`
and an idempotency header plus rejection after that extra field is changed.
The executable registry contains 19 exact HTTP-signature cases. Test
keys are generated in memory. No credential is accepted through command-line
arguments or printed in output.

The inspected OIDF conformance suite has no dedicated FAPI HTTP Signatures
plan. These local tests are implementation evidence, not OIDF certification.

## M8-03: isolation and future delta audit

The feature is default-off, route-local, non-advertised, and tested alongside
an unsigned default-off server. This closes M8-01, M8-02, and M8-03 only for
this bounded candidate. It does not change the status of any other M8 item.

For every newer publication, compare covered components, structured-field
rules, time and replay requirements, key discovery, algorithm requirements,
response/request binding, error signing, metadata, and conformance plans. Any
normative delta requires new failing tests, updated operational ownership, and
fresh real-HTTP evidence before adoption.
