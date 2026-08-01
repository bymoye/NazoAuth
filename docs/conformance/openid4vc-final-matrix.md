# OpenID4VC Final conformance matrix

This implementation provides the **Credential Issuer** role from OpenID for
Verifiable Credential Issuance 1.0 Final and the **Verifier** role from OpenID
for Verifiable Presentations 1.0 Final. It does not implement or advertise a
Wallet role.

The implementation is split into four protocol boundaries:

- `nazo-digital-credentials`: DCQL, SD-JWT VC, ISO mdoc, JOSE/COSE and trust ports.
- `nazo-openid4vci`: issuer metadata, offers, proof validation contracts,
  immediate/batch/deferred issuance, nonces and notifications.
- `nazo-openid4vp`: verifier request policy, transaction state and DCQL-bound
  presentation verification.
- `nazo-openid4vc-http-actix`: HTTP transport and management adapters only.

Persistence, key management, subject data and HTTP are adapters behind those
domain ports. Tests live under each crate's `tests/` directory; static CI
rejects test code in the production source trees.

## Supported final boundary

The issuer supports `dc+sd-jwt` and `mso_mdoc`, authorization-code and
pre-authorized-code grants, wallet- and issuer-initiated flows, credential
offers by value or reference, S256/DPoP and client-attestation HAIP paths,
one-time proof nonces, JWT and key-attestation proofs, immediate and deferred
issuance, batch issuance, notifications, signed metadata, and ECDH-ES/A256GCM
credential request/response encryption with optional `DEF` compression.

For HAIP issuance, wallet applications are registered for authenticated PAR,
S256 PKCE and DPoP. They are not made to require a JAR Request Object merely
because wallet attestation is used. HAIP 1.0 applies the FAPI 2.0 Security
Profile to this flow, while the requirement to put every PAR authorization
parameter in a signed Request Object belongs to the separate FAPI 2.0 Message
Signing profile. An ecosystem may opt into Message Signing independently, but
the HAIP client-attestation profile does not silently enable it.

The verifier supports DCQL for `dc+sd-jwt` and `mso_mdoc`, `redirect_uri`,
`x509_san_dns`, and `x509_hash` Client Identifier Prefixes,
`direct_post`/`direct_post.jwt`, URL-query and signed request-URI retrieval
(GET and POST), encrypted responses with per-transaction keys, transaction
data, SD-JWT KB-JWT verification, and the final OpenID4VP mdoc session
transcript. HAIP is restricted to `x509_hash`, a signed request URI, and
`direct_post.jwt`.

Unsupported optional mechanisms are not advertised: Wallet behavior,
Digital Credentials API transport, DID client identifiers, verifier
attestation client identifiers, and unbound mdoc credentials.

## Signing-key boundary

OpenID4VC signing uses an ES256 local key scoped only to `credential` and
`presentation_request`. It is generated through the existing atomic key store:

```text
sudo nazoauthctl keys generate-local --alg ES256 \
  --purposes credential,presentation_request --yes
```

The persisted `purposes` field is fail-closed. A purpose-scoped key is excluded
from OIDC rotation and cannot sign access tokens, ID Tokens, JARM, logout
tokens, HTTP messages or security events. On a `standards-full` first install,
the authenticated key task creates an in-memory local CA and signs a leaf that
matches this exact scoped key and carries the current issuer hostname as a DNS
SAN. It atomically replaces one leaf-plus-CA PEM bundle; both certificate
settings reference it and the runtime accepts only its CA certificates as
trust anchors. The CA private key is never persisted and onboarding material
cannot replace that local trust boundary. Startup fails if the chain, anchor,
DNS SAN, or key binding is invalid. Operators must not edit `keyset.json`
manually.

## OIDF suite coverage

The repository pins OIDF Conformance Suite commit
`dee9a25160e789f0f80517674693ef7989ab9fa1` (v5.2.0) and runs these upstream
plans:

- `oid4vci-1_0-issuer-test-plan`
- `oid4vci-1_0-issuer-haip-test-plan`
- `oid4vp-1final-verifier-test-plan`
- `oid4vp-1final-verifier-haip-test-plan`

The bounded registry is
[`tests/contracts/openid4vc-oidf-matrix.json`](../../tests/contracts/openid4vc-oidf-matrix.json).
It expands the plans into 17 executions covering both credential formats and
the supported security/transport axes. Management automation can only create
offers or presentation transactions; it cannot inspect protocol persistence,
so results are black-box evidence.

Official-suite execution uses bounded 4-plan groups. This is a runner
scheduling boundary, not a protocol exemption: every one of the 17 generated
plan expressions is still executed against the same operator-supplied public
issuer, and each group receives only bounded expected-result records that
match that group's configuration files. The grouping prevents issuer/verifier
driver-triggered `WAITING` modules from overloading the official control-plane
API while preserving black-box protocol coverage.

The upstream v5.2.0 suite has no modules for the unsupported combination
`mso_mdoc` + `redirect_uri` client identifier prefix + signed request URI +
`direct_post.jwt`; `mso_mdoc` encrypted-response coverage is therefore exercised
through the supported x509-prefixed signed-request variants instead.

The HAIP issuer configurations issue refresh tokens for authorized Credential
Types without adding the OIDC-only `offline_access` scope. When Wallet
Attestation is used, each refresh token is bound to the Client Instance public
key from the attestation `cnf.jwk`; refresh requests must authenticate with the
same key. No HAIP refresh-token warning or skip is accepted by the matrix.

The two standard VCI pre-authorized-code configurations also register one exact
expected failure for
`oid4vci-1_0-issuer-happy-flow-multiple-clients`. That upstream module accepts
one Credential Offer but redeems the same `pre-authorized_code` again with its
second client, whereas OpenID4VCI 1.0 Final section 4.1.1 requires the code to be
short-lived and single-use. The server must not permit per-client replay to make
the test pass. This expected failure is bound to the two exact pre-authorized-code
configurations, full variants, the `Second client: Verify token endpoint response`
block, and the `CheckTokenEndpointHttpStatus200` condition. The authorization-code
variants of the same module still run and must pass. Any other failure, warning,
or skip remains a failure.

The upstream plan display names explicitly call these tests **alpha** and say
they are incomplete/incorrect or not currently part of the certification
program. A green run is therefore official-suite regression evidence: it is
not an OpenID Foundation certification claim. No documentation or UI may use the
OpenID Certified mark on the basis of these runs.

Latest durable evidence:

- [2026-07-20 final automated OIDF results](2026-07-20-final-automated-oidf-results.md)
- [2026-07-16 OpenID4VC Final / HAIP OIDF results](2026-07-16-openid4vc-final-oidf-results.md) (historical)
- Diagnostic official-suite debugging used an operator-provided
  production target, sanitized in this repository as `https://issuer.example`,
  and completed all 17 plan executions with zero failures. It is useful
  debugging evidence, not the default target for repository users.
- GitHub official run
  [#29700527789](https://github.com/nazozero/NazoAuth/actions/runs/29700527789)
  completed successfully against the same production origin.

Normative sources:

- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VC HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)
