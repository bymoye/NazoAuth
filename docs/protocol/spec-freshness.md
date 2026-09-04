# Protocol Source Freshness

Last online verification: 2026-07-17.

NazoAuth tracks official protocol sources in
`requirements/spec-freshness.json`. Search indexes and previously cloned test
suites are not version authorities.

## Current mutable baseline

| Source | Current official baseline |
| --- | --- |
| OAuth 2.1 | `draft-ietf-oauth-v2-1-15` |
| Browser-Based Applications | `draft-ietf-oauth-browser-based-apps-27` |
| Attestation-Based Client Authentication | `draft-ietf-oauth-attestation-based-client-auth-10` |
| Transaction Tokens | `draft-ietf-oauth-transaction-tokens-09` |
| Client ID Metadata Document | `draft-ietf-oauth-client-id-metadata-document-02` |
| Security BCP Update | `draft-ietf-oauth-security-topics-update-03` |
| Refresh Token and Authorization Expiration | `draft-ietf-oauth-refresh-token-expiration-03` |
| First-Party Applications | `draft-ietf-oauth-first-party-apps-04` |
| Identity and Authorization Chaining Across Domains | `draft-ietf-oauth-identity-chaining-17` |
| Token Status List | `draft-ietf-oauth-status-list-21` |
| JWT Best Current Practices bis | `draft-ietf-oauth-rfc8725bis-07` |
| SPIFFE Client Authentication | `draft-ietf-oauth-spiffe-client-auth-02` |
| Identity Assertion JWT Authorization Grant | `draft-ietf-oauth-identity-assertion-authz-grant-04` |
| JWT Client Authentication and Assertion-Based Grants bis | `draft-ietf-oauth-rfc7523bis-11` |
| Cross-Device Flows Security BCP | `draft-ietf-oauth-cross-device-security-16` |
| SD-JWT VC | `draft-ietf-oauth-sd-jwt-vc-17` |
| Agent Authorization Profile | `draft-aap-oauth-profile-01` |
| Delegated Authorization | `draft-li-oauth-delegated-authorization-02` |
| Mission-Bound Authorization | `draft-mcguinness-oauth-mission-00` |
| Client Instance Assertion | `draft-mcguinness-oauth-client-instance-assertion-01` |
| Actor Profile / Proofs / Receipts | `draft-mcguinness-oauth-actor-profile-00`, `draft-mcguinness-oauth-actor-proofs-00`, `draft-mcguinness-oauth-actor-receipts-00` |
| Actor Chain | `draft-mw-oauth-actor-chain-01` |
| Authorization Evidence | `draft-liu-oauth-authorization-evidence-01` |
| Global Token Revocation | `draft-parecki-oauth-global-token-revocation-06` |
| RAR and Resource Metadata watchlist | `draft-zehavi-oauth-rar-metadata-05`, `draft-skokan-oauth-resource-response-02`, `draft-mcguinness-oauth-rfc9728bis-01` |
| Sender-Constraint watchlist | `draft-mw-oauth-tls-session-bound-tokens-07`, `draft-richer-oauth-httpsig-02` |
| Browser Session Handoff | `draft-moros-oauth-browser-session-handoff-00` |
| Layered Cookies | `draft-ietf-httpbis-layered-cookies-02` |
| FAPI 2.0 HTTP Signatures | working draft dated 2026-06-26 |
| FAPI-CIBA | working draft `fapi-ciba-03` dated 2026-06-26; implemented compatibility target remains stable `ID1` / draft 02 |
| Grant Management | working draft `oauth-v2-grant-management-03` built 2026-06-26; approved stable snapshot `ID1` |
| OpenID Connect Native SSO | draft 07 / Second Implementer's Draft |

The inventory also verifies the canonical pages and status markers for OIDC,
FAPI 2.0, OpenID4VC, OpenID Federation, and every immutable RFC used by active
protocol documentation.

## Checks

Offline schema and active-document validation:

```powershell
python scripts/check_spec_freshness.py --offline
```

Online validation against IETF Datatracker, RFC Editor, and upstream specification publishers:

```powershell
python scripts/check_spec_freshness.py
```

Pull requests touching protocol sources run the offline gate. A weekly and
manual workflow runs the online gate. When it reports drift, update the
inventory only after reviewing the normative delta and its implementation,
metadata, documentation, and conformance consequences.
