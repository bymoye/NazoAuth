# M8 Emerging Protocol Watchlist Governance Review

Date: 2026-07-11

## Scope and conclusion

This record completes the product, standards/conformance, and security-entry
gates in roadmap tasks M8-01 through M8-03. The governance review itself added
no runtime capability or certification claim. RFC 9865 was then implemented in
a separately approved, designed, and verified follow-up recorded below.

The review produced these decisions:

| Candidate | Standards status on 2026-07-11 | NazoAuth decision |
| --- | --- | --- |
| FAPI 2.0 HTTP Signatures | OIDF working draft dated 2026-06-26; not an OIDF Final Specification | Defer until the profile stabilizes and a resource-API non-repudiation customer exists. |
| RFC 9865 cursor pagination | IETF Standards Track RFC, published 2025-10 | Implemented after this governance review with local codec, handler, metadata, security, and SCIM regression evidence; no applicable OIDF plan was found. |
| RFC 9967 SCIM SET profile | IETF Standards Track RFC, published 2026-05 | Defer pending a defined event consumer, delivery topology, trust model, and retention owner. |
| OAuth for Browser-Based Applications | `draft-ietf-oauth-browser-based-apps-27`; RFC Editor queue in progress, no RFC number yet | The corrected pre-publication draft-27 audit is recorded in `2026-07-11-browser-based-applications-draft-27-audit.md`; repeat the delta audit after RFC publication and do not add a draft profile switch. |
| Attestation-Based Client Authentication | active `draft-ietf-oauth-attestation-based-client-auth-10` | Defer while the draft and attester trust ecosystem remain unsettled. |
| Transaction Tokens | active `draft-ietf-oauth-transaction-tokens-09` | Defer until NazoAuth has a trusted-domain workload call-chain product requirement. |
| Grant Management | OIDF working draft `oauth-v2-grant-management-03`, rolling copy built 2026-06-26; its `ID1` snapshot is an approved Implementer's Draft, with no Final status | Keep the existing admin grant controls; defer protocol metadata and a client-facing API. |
| OpenID4VCI 1.0 / OpenID4VP 1.0 | OIDF Final Specifications, published 2025-09-16 and 2025-07-09 | Treat as a separate credential product program, not an extension of the current OP/AS profile. |

No endpoint, grant, authentication method, token type, SCIM capability,
credential role, feature flag, or metadata field is added by M8 completion.

## Evidence method

Standards status was checked against primary sources:

- [OIDF FAPI 2.0 HTTP Signatures working draft](https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html)
- [RFC 9865](https://www.rfc-editor.org/info/rfc9865)
- [RFC 9967](https://www.rfc-editor.org/info/rfc9967)
- [OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)
- [OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)
- [Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
- [Grant Management for OAuth 2.0 draft 03](https://openid.bitbucket.io/fapi/oauth-v2-grant-management.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

OIDF coverage was re-inspected in OpenID conformance-suite release `v5.2.0` at
commit `dee9a25160e789f0f80517674693ef7989ab9fa1` (2026-07-06). An absence statement
below means that no applicable plan was found in that revision. It does not
predict future suite coverage.
The candidate-by-candidate source findings are recorded in
`2026-07-11-m8-oidf-v5.2.0-coverage.md`.

The local code boundary was checked from route registration, well-known and
SCIM capability output, token dispatch, client authentication, grant storage,
and resource-server verification. Documentation claims were not treated as code
evidence.

## Common admission rules

A candidate may enter an implementation roadmap only when all of these are
recorded in a candidate-specific design:

1. a named adopter and concrete workflow;
2. NazoAuth's exact protocol role and trust boundary;
3. feature, tenant, client, and metadata gates that default closed;
4. key, issuer, audience, replay, expiry, concurrency, revocation, retention,
   privacy, and denial-of-service behavior where applicable;
5. fail-closed error semantics and an operator responsible for trust anchors,
   keys, monitoring, incident response, and retained evidence;
6. local positive, negative, metadata-truth, downgrade, and isolation tests;
7. applicable official conformance evidence or a dated statement that no plan
   exists; and
8. proof that baseline OAuth/OIDC, FAPI2 Security, FAPI2 Message Signing, CIBA,
   SCIM provisioning, and external-provider login retain their current default
   security properties.

Final publication satisfies only the specification-maturity part of this gate.

## Candidate reviews

### FAPI 2.0 HTTP Signatures

**Product demand and integration.** The intended users are FAPI clients and
resource servers that require non-repudiation for resource requests and
responses. NazoAuth currently supplies an authorization server and resource
server verification libraries, but no customer or first-party resource API has
defined evidence retention, dispute resolution, or client/resource signing-key
discovery. There is therefore no validated product demand.

**Specification and conformance.** The OIDF page is a working draft dated
2026-06-26 and explicitly says it is not an OIDF International Standard. It
profiles RFC 9421 and RFC 9530 for resource requests and responses and is
separate from FAPI 2.0 Message Signing Final. The inspected conformance-suite
revision contains no `Signature-Input` implementation or dedicated HTTP
Signatures plan.

**Threat and operations boundary.** A future implementation must prevent
signature-base confusion, unsigned covered-component substitution, stale
signatures, body digest substitution, DPoP/Authorization header detachment,
request/response misbinding, ambiguous key selection, and unbounded retention
of signed personal data. Operators must own client and resource-server key
registration, rotation, revocation, clock skew, evidence access, and retention.

**Metadata/config and failure policy.** No current metadata or profile claims
HTTP Signatures. A future profile must be separate from existing Message
Signing profiles, default closed, and bound to explicit resource servers and
keys. Missing, stale, ambiguous, or invalid signatures and digests fail closed;
they never downgrade to unsigned FAPI resource access.

**Local test strategy.** Test RFC 9421 canonicalization and covered components,
content digests, request/response linkage, key/algorithm mismatch, time bounds,
duplicate headers, proxy transformations, DPoP and mTLS combinations, evidence
redaction, and unchanged non-HTTP-signature FAPI behavior.

**Decision and re-entry.** Deferred. Re-enter after an OIDF Implementer's Draft
or Final Specification exists, the suite publishes applicable coverage or a
documented replacement strategy exists, and a resource API adopter accepts the
key-discovery and evidence-retention operating model.

### RFC 9865 cursor-based SCIM pagination

**Product demand and integration.** SCIM provisioning clients listing a changing
or large user directory benefit from stable cursor traversal. NazoAuth already
implements `GET /scim/v2/Users`, database-backed tenant-scoped SCIM credentials,
bounded page sizes and filtering. The follow-up implementation now advertises
cursor support while retaining index as the default. This was the narrowest
candidate with a mature specification and an existing product surface.

**Specification and conformance.** RFC 9865 is an IETF Standards Track RFC
published in October 2025 and updates RFC 7643 and RFC 7644. The inspected OIDF
suite contains no `nextCursor` code or RFC 9865-specific plan.

**Threat and operations boundary.** A cursor must be opaque, integrity-protected,
bound to tenant, filter, sort/order policy, and page-size policy, and rejected
after a bounded lifetime. It must not expose database keys or permit cross-tenant
enumeration, filter substitution, page-size bypass, cursor forgery, or unlimited
server-side cursor state. Key rotation and invalid-cursor telemetry need an
operator-owned policy.

**Metadata/config and failure policy.** Only `/ServiceProviderConfig` changes,
and only when the implementation and negative tests exist. Index pagination
remains supported unless a later product decision removes it. Invalid, expired,
tampered, or context-mismatched cursors return the RFC-defined SCIM error and
never fall back to a broader query.

**Local test strategy.** Cover forward traversal under deterministic ordering,
last-page behavior, concurrent insert/delete behavior, empty sets, filter and
count binding, tampering, expiry, tenant mismatch, malformed/duplicate
parameters, maximum page size, capability truth, and unchanged write/auth rules.

**Decision and evidence.** Implemented as forward-only stateless cursor
pagination. AES-256-GCM cursors expire after 600 seconds and bind credential,
tenant, exact filter, effective count, ordering policy, and the last
`(created_at, id)` row. Local evidence covers codec tampering and context
binding, handler errors, authentication before raw-query parsing, malformed and
duplicate parameter mapping, metadata truth, SCIM regression, and a PostgreSQL
isolated-schema traversal test. The database test exercises equal timestamps,
zero/exact-boundary pages, filter/count/credential substitution, and concurrent
insert/delete behavior. It was executed locally against PostgreSQL 18 on
2026-07-11, and the non-skippable CI library-test gate supplies `DATABASE_URL`.
No RFC 9865-specific OIDF plan was found in the inspected suite revision, so
this is not an OIDF certification claim.

### RFC 9967 SCIM Security Event Tokens and asynchronous completion

**Product demand and integration.** Potential users are downstream provisioning
or security systems that need SCIM change events, feed membership events, or
asynchronous request completion. NazoAuth has no configured SET receiver,
delivery stream, event feed, or consumer contract. Structured local audit events
are not a substitute for RFC 9967 delivery.

**Specification and conformance.** RFC 9967 is an IETF Standards Track RFC
published in May 2026. It profiles Security Event Tokens for SCIM provisioning,
feed, and asynchronous-response events and defines `Set-Txn` for accepted
asynchronous requests. The inspected suite includes alpha OpenID Shared Signals
Framework transmitter/receiver plans and recognizes RFC 9967 SCIM event URI
values, but no RFC 9967-specific end-to-end SCIM plan was found. SSF alpha
coverage is not evidence that NazoAuth implements RFC 9967.

**Threat and operations boundary.** A future transmitter or receiver must handle
SET issuer/audience/key validation, `jti` replay, event ordering and
idempotency, subject authorization, tenant separation, delivery authentication,
retry/backoff, dead-letter state, retention, privacy minimization, deletion
events, and SSRF-safe receiver configuration. Asynchronous requests additionally
need durable job state, cancellation/expiry, result authorization, and bounded
queues.

**Metadata/config and failure policy.** Current capability output remains
`asyncRequest: none` with no event URIs. A future feature must separately gate
event generation, delivery method, receiver allowlists, signing keys, audience,
and asynchronous processing. Event delivery failure must not silently report
provisioning success, and retry behavior must not duplicate state changes.

**Local test strategy.** Test every supported event shape, SET cryptography,
issuer/audience/time/replay errors, feed authorization, tenant leakage, delivery
retries, poison events, queue limits, async `Set-Txn` correlation, audit
redaction, and disabled metadata.

**Decision and re-entry.** Deferred. Re-enter when a named event consumer and
delivery topology exist, operational ownership for keys/queues/retention is
assigned, and the implementation can be scoped independently from cursor
pagination.

### OAuth 2.0 for Browser-Based Applications

**Product demand and integration.** This document guides browser OAuth clients
and the authorization server behavior they depend on. NazoAuthWeb is a
same-origin first-party UI using server sessions; it is not evidence that a
third-party SPA token architecture is supported. NazoAuth already has code-only
flows, PKCE, no password/implicit grants, exact redirect policy, scoped CORS,
refresh protection, and sender-constrained token support.

**Specification and conformance.** `draft-ietf-oauth-browser-based-apps-27` is
in the RFC Editor publication queue with state “In Progress” on the review date,
but no RFC number has been assigned. It is intended as a Best Current Practice.
No dedicated browser-app plan was found in conformance-suite `v5.2.0`. The only
normative change from `-26` is a BFF cookie-name SHOULD that points to the
`__Host-Http-` prefix in `draft-ietf-httpbis-layered-cookies-02`.

**Threat and operations boundary.** The final audit must cover malicious
JavaScript, single and persistent token theft, new-flow token acquisition,
client hijacking, CSRF, redirect and postMessage validation, CORS, refresh-token
rotation or sender constraint, and differences among BFF, token-mediating
backend, and browser-only public clients.

**Metadata/config and failure policy.** Guidance does not justify inventing a
runtime profile name. Public browser clients cannot be made confidential by a
static secret. Existing per-client redirect, PKCE, CORS, token lifetime, and
refresh controls remain authoritative and fail closed.

**Local test strategy.** After RFC publication, map every AS requirement to
authorization, PAR, token, refresh, CORS, redirect, cookie/session, and metadata
tests; separately audit NazoAuthWeb architecture without conflating it with
third-party SPA support.

**Decision and re-entry.** The corrected pre-publication audit maps draft-27 to
the current server and first-party Web architecture. NazoAuthWeb is the
same-origin authorization-server frontend, not a BFF: it does not proxy resource
requests or hold OAuth tokens. The new BFF cookie-prefix SHOULD is therefore
recorded but not misapplied as a runtime requirement. Publication watch remains:
re-audit immediately after an RFC number is assigned and implement only
concrete gaps found in the final requirements delta.

### OAuth 2.0 Attestation-Based Client Authentication

**Product demand and integration.** The likely users are native or wallet
client instances that can obtain platform/backend attestations. NazoAuth has no
client attester contract, trust-anchor registry, attestation policy, or supported
platform evidence formats. WebAuthn user attestation and CI provenance are
different trust domains and cannot be reused.

**Specification and conformance.** The current OAuth WG document is active
`draft-ietf-oauth-attestation-based-client-auth-10`, dated July 2026. The
inspected suite contains attestation headers, challenge checks, metadata checks,
and bounded uses in FAPI/OpenID4VC paths, but no standalone general-purpose OAuth
AS certification plan was found. Profile-specific conditions do not establish a
complete NazoAuth integration contract.

**Threat and operations boundary.** A future design must define attester trust,
attestation freshness and challenge binding, client-instance key binding,
algorithm and `typ` policy, replay, revocation, compromised-device response,
privacy/linkability, DPoP interaction, refresh-token binding, and trust-anchor
rollover. Operators must own platform attester onboarding and emergency removal.

**Metadata/config and failure policy.** No attestation auth method or challenge
endpoint is advertised. A future method must be per-client/profile gated and
must not cause fallback to secret, `private_key_jwt`, or unauthenticated access
after attestation failure.

**Local test strategy.** Cover signature, type, algorithm, audience, challenge,
freshness, key binding, replay, attester chain, revocation, metadata truth,
DPoP/mTLS combinations, refresh behavior, and downgrade rejection.

**Decision and re-entry.** Deferred until the document reaches RFC or another
stable adoption milestone and a platform-specific attester plus client adopter
is selected.

### Transaction Tokens

**Product demand and integration.** Transaction Tokens propagate identity and
authorization context through a workload call chain inside a trust domain. The
current product is an authorization server and verifier library, not a defined
Transaction Token Service with an owned workload mesh. No validated trust-domain
or call-chain adopter exists.

**Specification and conformance.** The active OAuth WG document is
`draft-ietf-oauth-transaction-tokens-09`, dated July 2026. No `Txn-Token` code or
plan was found in the inspected OIDF suite.

**Threat and operations boundary.** A future service must prevent input-token
confusion, authorization-context expansion, audience escape, replay, call-chain
forgery, workload identity substitution, privacy over-sharing, signing-key
confusion, and propagation beyond the trust domain. Operators must own the trust
domain, workload identity source, signing keys, policy, and incident revocation.

**Metadata/config and failure policy.** No transaction-token endpoint, service
metadata, header, or claim is present. A future TTS must be independently gated
and cannot reinterpret ordinary access tokens as transaction tokens. Invalid or
untrusted context fails closed without minting a reduced-validation token.

**Local test strategy.** Cover input token types, workload/client authorization,
scope and context non-expansion, audience, expiry, issuer/key rotation, replay,
replacement semantics if retained by the final document, cross-domain rejection,
privacy minimization, and service-discovery truth.

**Decision and re-entry.** Deferred until the draft is stable and a concrete
trusted-domain workload architecture requires NazoAuth to act as the TTS.

### Grant Management for OAuth 2.0

**Product demand and integration.** Administrators can already list and revoke
stored user-client grants through `/api/admin/grants`. The old OIDF draft instead
defines client-visible grant identifiers, lifecycle actions, an API, and
authorization-server metadata. No client adopter requires that protocol, and no
policy defines partial updates or grants shared across related client IDs.

**Specification and conformance.** The current working document is
`oauth-v2-grant-management-03`, whose rolling copy was built 2026-06-26. Its `ID1` snapshot was
approved as an Implementer's Draft on 2023-07-10. It is not a Final
Specification. No `grant_management` code or plan was found in
conformance-suite `v5.2.0`.

**Threat and operations boundary.** A future API must prevent grant identifier
enumeration, cross-user/client access, privilege expansion during update or
replace, confused delegation across related client IDs, stale consent reuse,
revocation races, and leakage of authorization details or resource indicators.
Operators must define shared-client ownership and audit/retention policy.

**Metadata/config and failure policy.** No grant-management metadata or endpoint
is advertised. Admin controls remain an internal product API and are not draft
compliance. A future protocol endpoint must require an explicit client/user
authorization model and use atomic grant plus token-family revocation.

**Local test strategy.** Cover opaque identifiers, query/revoke/update/create
authorization, exact scope/resource/authorization-details bounds, shared client
groups, concurrent revocation and token refresh, audit redaction, metadata truth,
and admin API isolation.

**Decision and re-entry.** Deferred until OIDF publishes a current stable draft
or Final Specification and a client adopter needs protocol-level grant control.
A first-party end-user consent-management UI may be designed separately without
claiming this draft.

### OpenID4VCI 1.0 and OpenID4VP 1.0

**Product demand and integration.** OpenID4VCI introduces a Credential Issuer,
credential offers, nonce, credential, deferred credential, notification, and
credential metadata surfaces. OpenID4VP introduces Wallet and Verifier roles,
presentation requests/responses, response transport, and credential validation.
NazoAuth has no credential format, schema, status, wallet, holder, verifier,
trust framework, or issuance-policy product. Ordinary OIDC claims must not be
promoted into credentials automatically.

**Specification and conformance.** OpenID4VCI 1.0 became an OIDF Final
Specification on 2025-09-16. OpenID4VP 1.0 is Final, published 2025-07-09. The
inspected suite contains issuer and wallet plans for OpenID4VCI and verifier and
wallet plans for OpenID4VP, including HAIP variants:

- `VCIIssuerTestPlan` and `VCIIssuerTestPlanHaip`;
- `VCIWalletTestPlan` and `VCIWalletTestPlanHaip`;
- `VP1FinalVerifierTestPlan` and `VP1FinalVerifierTestPlanHaip`;
- `VP1FinalWalletTestPlan` and `VP1FinalWalletTestPlanHaip`.

The existence of plans does not select a credential format, trust framework, or
NazoAuth product role.

**Threat and operations boundary.** A future program must address credential
issuer/verifier impersonation, wallet binding, proof replay, nonce lifecycle,
credential substitution, format and algorithm confusion, holder correlation,
over-disclosure, presentation replay, status/revocation, deferred issuance,
pre-authorized code theft, trust lists, schema/version changes, key separation,
and personal-data retention. Operators must own issuer/verifier accreditation,
credential schemas, keys, status services, privacy requests, and incident
revocation.

**Metadata/config and failure policy.** Credential issuer, wallet, and verifier
metadata must use separate roles and keys from normal OP discovery unless a
future approved design proves a safe relationship. Every role and credential
format defaults closed. Unsupported formats, proofs, encryption, trust chains,
or response modes fail closed without falling back to an ordinary ID Token.

**Local test strategy.** In addition to the official plans, test role and key
separation, issuer/verifier metadata truth, format allowlists, nonce/replay,
proof/key binding, offers, pre-authorized and authorization-code flows, deferred
state, status/revocation, presentation definitions, response modes, privacy and
claim minimization, tenant isolation, and unchanged OAuth/OIDC/FAPI behavior.

**Decision and re-entry.** Create a separate product-discovery milestone only
after selecting the first NazoAuth role, credential format, trust framework,
schema, adopter, and operational owner. Do not implement a nominal endpoint set
without that product contract.

## M8-03 profile isolation checklist

Every future candidate implementation must prove all applicable rows below:

| Existing surface | Required invariant |
| --- | --- |
| `oauth2-oidc-baseline` | No new grant, endpoint, auth method, token interpretation, redirect relaxation, CORS expansion, or metadata claim unless the candidate is explicitly enabled. |
| `fapi2-security` | Confidential-client, PAR, PKCE, sender constraint, JWT/JWKS, issuer/audience, nonce, replay, and metadata-truth requirements remain unchanged. |
| `fapi2-message-signing-*` | Draft HTTP signatures or credential messages are not conflated with JAR, JARM, signed introspection, or ID Token requirements. |
| CIBA/FAPI-CIBA | Poll state, client authentication, sender constraint, metadata, and official compatibility behavior remain isolated from candidate flows. |
| SCIM | Existing bearer credential scopes, default tenant, filtering, page bounds, provisioning atomicity, and capability truth remain unchanged. |
| External-provider login | Provider issuer, redirect, state/nonce, account-linking, and secret boundaries are not reused as candidate trust anchors. |
| Key management | OP signing keys are not silently reused for client attestation, transaction tokens, SCIM SETs, HTTP signatures, credentials, or presentations. |
| Operations | Candidate state, replay markers, queues, evidence, keys, and personal data have explicit bounded retention and failure ownership. |

## Review outcome

M8-01, M8-02, and M8-03 can be marked complete as governance gates because
product boundaries, exact standards/conformance status, local test policy, and
security isolation are now explicit. The candidate features themselves remain
absent except for the separately designed and locally verified RFC 9865 SCIM
cursor implementation. OpenID4VCI/OpenID4VP require a separate product program;
the remaining items stay on the dated watchlist until their named re-entry
conditions are met.
