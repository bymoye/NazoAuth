# Protocol Source Freshness

Last online verification: 2026-07-11.

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
| Layered Cookies | `draft-ietf-httpbis-layered-cookies-02` |
| FAPI 2.0 HTTP Signatures | working draft dated 2026-06-26 |
| FAPI-CIBA | working draft `fapi-ciba-03` dated 2026-06-26; implemented compatibility target remains stable `ID1` / draft 02 |
| Grant Management | working draft `oauth-v2-grant-management-03` built 2026-06-26; approved stable snapshot `ID1` |
| OpenID Connect Native SSO | draft 07 / Second Implementer's Draft |
| OpenID conformance-suite | `release-v5.2.0` at `dee9a25160e789f0f80517674693ef7989ab9fa1` |

The inventory also verifies the canonical pages and status markers for OIDC,
FAPI 2.0, OpenID4VC, OpenID Federation, and every immutable RFC used by active
protocol documentation. Dated result records intentionally retain the exact
older source or suite revision that produced those results.

## Checks

Offline schema and active-document validation:

```powershell
python scripts/check_spec_freshness.py --offline
```

Online validation against IETF Datatracker, RFC Editor, OpenID Foundation, and
the official OIDF GitLab release API:

```powershell
python scripts/check_spec_freshness.py
```

Pull requests touching protocol sources run the offline gate. A weekly and
manual workflow runs the online gate. When it reports drift, update the
inventory only after reviewing the normative delta and its implementation,
metadata, documentation, and conformance consequences.
