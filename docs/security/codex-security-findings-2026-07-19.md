# Codex Security Findings Disposition — 2026-07-19

This record documents the disposition of the 82 findings exported from Codex
Security on 2026-07-19. A finding is classified from the protocol requirement,
the current implementation, and a reproducible failure condition. Scanner
wording alone is not treated as evidence.

## Normative basis

The protocol decisions in this review use the published or current official
specification text:

- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) for DPoP nonce and
  refresh-token sender constraints.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) for OAuth security BCP
  and PKCE requirements.
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) for token-exchange
  target policy.
- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html),
  [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html), and
  [draft-ietf-oauth-rfc8725bis-07](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/)
  for JWT assertion and cross-JWT confusion boundaries.
- [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) and
  [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) for JAR and PAR.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) for access-token
  audience validation.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  and [Native SSO draft 07](https://openid.net/specs/openid-connect-native-sso-1_0.html)
  for claims, consent, nonce, and native-session semantics.
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
  and [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
  for pre-authorized-code and holder-binding requirements.
- [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
  for backchannel request-object requirements.

`Fixed` means the reported failure condition existed and is eliminated by the
review branch. `Closed — current behavior` means the exported finding describes
code that is no longer present or already has the required boundary. `Closed —
specification` means the requested change would impose a requirement that the
governing specification does not impose, or would break a permitted profile.

## High severity

| # | Finding | Disposition | Evidence and reason |
| --- | --- | --- | --- |
| 01 | [Untrusted deployed SHA](https://chatgpt.com/codex/cloud/security/findings/6b913ba140148191a78741c56a666866) | Fixed | Conformance jobs now check out the trusted default branch and require the supplied deployed commit to be its ancestor before secrets are available. |
| 02 | [Workflow input command injection](https://chatgpt.com/codex/cloud/security/findings/cbad12641880819188b2dce8116a4d36) | Fixed | Dispatch inputs enter shell steps through environment variables and are quoted; direct expression interpolation in shell source was removed. |
| 03 | [OpenID4VC management-token target](https://chatgpt.com/codex/cloud/security/findings/00ebab994c7c8191959ef0ca3cbf2662) | Fixed | The workflow requires HTTPS and an exact trusted target origin configured in the protected environment. |
| 05 | [CIBA CA bundle as global roots](https://chatgpt.com/codex/cloud/security/findings/e68e60868d6c8191a26bcfe405a851c4) | Fixed | `SSL_CERT_FILE` mutation was removed; the CIBA ping client consumes its own `CIBA_PING_TLS_TRUST_BUNDLE`. |
| 06 | [Pre-authorized-code replay by client change](https://chatgpt.com/codex/cloud/security/findings/00ae7043ad308191b87fa965ee5bc5e3) | Fixed | Offer consumption is an atomic, global single-use state transition, independent of the presented `client_id`, as required by OpenID4VCI. |
| 07 | [mDL holder-binding fallback](https://chatgpt.com/codex/cloud/security/findings/1d3f91b8cc208191ac4a04db84bf6c06) | Fixed | mdoc verification requires a device signature and a valid issuer chain; no unsigned fallback remains. |
| 08 | [mdoc holder-binding bypass](https://chatgpt.com/codex/cloud/security/findings/98ba6d0c46fc81918d9d0aba5efc5dbf) | Fixed | OpenID4VP now defaults `require_cryptographic_holder_binding` to true and rejects missing holder proof. |
| 09 | [Credential endpoint ignores token audience](https://chatgpt.com/codex/cloud/security/findings/4adfb835ef7c819191b21ffb8ce580b2) | Fixed | JWT access tokens are accepted only when `aud` contains the credential issuer/resource identifier, consistent with RFC 9068. |
| 10 | [Refresh replay detection bypass](https://chatgpt.com/codex/cloud/security/findings/6eb92ec66b9c819192bd31cb0202104d) | Closed — specification | RFC 9449 deliberately does not bind refresh tokens issued to confidential clients to a DPoP key because client authentication is the sender constraint. Rotation/reuse detection remains authoritative. |
| 11 | [Public artifact with private test keys](https://chatgpt.com/codex/cloud/security/findings/66661425c59c81919b73ac7c0d16b40a) | Fixed | The live GitHub artifact was verified, deleted, and rechecked as absent. Public documentation no longer publishes its locator; full runner exports are no longer uploaded. The affected static CIBA client identifiers are not present in the current production database. |
| 13 | [CIBA automation approval hook](https://chatgpt.com/codex/cloud/security/findings/3b6b058b6e7c81919d4474642abf9b5f) | Closed — current behavior | This is an explicitly enabled conformance control plane, disabled by default and protected by a separately configured high-entropy token. It is not an end-user CIBA authorization path or a production default. |
| 14 | [Expired Native SSO ID token](https://chatgpt.com/codex/cloud/security/findings/fa5c474568fc8191aece3f73935cdfa2) | Closed — specification | Native SSO draft 07 explicitly permits the ID token to be expired at use; the required checks are signature, `device_secret`, `ds_hash`, `sid`, and client-sharing policy. |
| 15 | [Token-exchange audience escalation](https://chatgpt.com/codex/cloud/security/findings/2335bba1bc708191af1ed7527c6d78fc) | Closed — specification | RFC 8693 leaves target authorization to AS policy; it does not require the requested audience to be a subset of the subject token audience. This implementation restricts targets to the authenticated client's explicit audience allowlist and tenant. |
| 16 | [Confidential DPoP refresh rebind](https://chatgpt.com/codex/cloud/security/findings/ad86c910d5d88191be1c9e85f8e76608) | Closed — specification | This is the same RFC 9449 confidential-client rule as item 10. Adding DPoP-key binding here would contradict the specified refresh-token model. |

## Medium severity

| # | Finding | Disposition | Evidence and reason |
| --- | --- | --- | --- |
| 17 | [Seed tools in production image](https://chatgpt.com/codex/cloud/security/findings/528c312b44048191a72009d0cf5564f9) | Closed — current behavior | Production seed binaries have been retired and are excluded from the product image. |
| 18 | [Public seeding default account](https://chatgpt.com/codex/cloud/security/findings/293d9cdbd2488191bc39a8a13054a017) | Closed — current behavior | The public seed path and deterministic login account no longer exist. |
| 19 | [FAPI DPoP nonce optional](https://chatgpt.com/codex/cloud/security/findings/89089b1706b881918b365f73d06beede) | Closed — specification | RFC 9449 defines nonce issuance as an optional server policy; the FAPI finding does not cite a profile requirement that overrides it. |
| 20 | [User-selected checkout with login secrets](https://chatgpt.com/codex/cloud/security/findings/b1f2244892408191830b2bf5c28827d8) | Fixed | The secret-bearing workflow executes only code from the trusted default branch and validates the deployed revision separately. |
| 21 | [User-selected repository code with secrets](https://chatgpt.com/codex/cloud/security/findings/6dbb8d6f13408191b3ef7eb56546c854) | Fixed | Same trust-boundary repair as item 20; a dispatch parameter can no longer replace workflow code. |
| 22 | [Preauth `private_key_jwt` replay](https://chatgpt.com/codex/cloud/security/findings/9e10094185b481918ab30b1dc459c47b) | Fixed | Validated assertions are consumed through the replay store before a credential offer can be redeemed. |
| 23 | [`issuer_state` replay](https://chatgpt.com/codex/cloud/security/findings/b74f945d9cc08191a263ee81c2caae28) | Fixed | Authorization offers use the same atomic global single-use transition as pre-authorized offers. |
| 24 | [Hardcoded mDL driving claims](https://chatgpt.com/codex/cloud/security/findings/d5b4980f2f4881918b3bf7d53c9eed5b) | Closed — current behavior | Hardcoded credential claims were removed; issued claims come from the tenant-bound authoritative dataset. |
| 25 | [OpenID4VC key isolation](https://chatgpt.com/codex/cloud/security/findings/2af3753a89b0819184a6bfe17577b853) | Fixed | Credential and presentation-request purposes cannot select the active OIDC signing key or the legacy shared auxiliary key path. |
| 26 | [Confidential OIDC without PKCE/nonce](https://chatgpt.com/codex/cloud/security/findings/5122a2ab0d808191870451d84ff8ceb9) | Closed — specification | Baseline confidential OIDC code flow without PKCE is permitted; public clients still require S256 and any supplied challenge is enforced. Requiring PKCE here would reject the OIDC Basic confidential-client profile. |
| 27 | [Confidential OIDC PKCE bypass](https://chatgpt.com/codex/cloud/security/findings/fdc33bd2ac408191b2a4572873083ff6) | Closed — specification | No stored challenge is being bypassed. RFC 9700 requires downgrade protection when PKCE is used and mandates it for public clients; both boundaries remain enforced. |
| 28 | [IPv4-mapped IPv6 SSRF](https://chatgpt.com/codex/cloud/security/findings/d95e0510a61c8191b905ef75ade19e58) | Fixed | IPv4-mapped IPv6 addresses are normalized and checked by the IPv4 local/private-address policy before DCR fetches. |
| 29 | [Deployment omits frontend build](https://chatgpt.com/codex/cloud/security/findings/236ca989d52081919bf4ae1f140a711a) | Fixed | Deployment deletes stale exported output and requires a successful frontend build before accepting the artifact. |
| 30 | [Git in untrusted sibling repositories](https://chatgpt.com/codex/cloud/security/findings/f1bba5f131748191b3c7f02e7cd26849) | Fixed | Automatic sibling-repository discovery was removed; only the canonical frontend path or an explicit operator path is inspected, with unsafe Git caches disabled. |
| 31 | [PAR flag enables direct JAR](https://chatgpt.com/codex/cloud/security/findings/5b7f90aaf0588191834e548f4ac43def) | Fixed | Direct `request=` admission now requires the direct request-object feature; PAR-contained objects remain independently controlled. |
| 32 | [Renovate code receives CI secrets](https://chatgpt.com/codex/cloud/security/findings/c0ce574f76e08191922054528c2c5d1c) | Fixed | Secret-bearing conformance jobs no longer check out pull-request or dependency-update code. |
| 33 | [Grant tenant scope dropped](https://chatgpt.com/codex/cloud/security/findings/285fcf7c11588191bfb0abcc7841e042) | Fixed | Grant lookup/count APIs require tenant identity and all authorization/profile callers pass the bound tenant. |
| 34 | [Seed upsert keeps stale mTLS SAN](https://chatgpt.com/codex/cloud/security/findings/cfcdb0c09c2c819193a60a7db15a638e) | Closed — current behavior | The seed-upsert mechanism was retired rather than extended with another compatibility path. |
| 35 | [`PasswordHashInput` debug disclosure](https://chatgpt.com/codex/cloud/security/findings/13f9094b2f8c8191b80deba94f75a85b) | Fixed | The type has an explicit redacted `Debug` implementation. |
| 36 | [Non-canonical response fingerprint](https://chatgpt.com/codex/cloud/security/findings/2ccb72e7e8e08191b0cacafbd1dc5431) | Fixed | Replay identity is the SHA-256 digest of the verified canonical signature base plus key identity, not raw URI/signature bytes. |
| 37 | [Unbounded JWE RSA key](https://chatgpt.com/codex/cloud/security/findings/e0f356e885a88191b0b964c1ad061955) | Fixed | Client RSA keys must be 2048–8192 bits with a valid odd exponent; the same policy is reused at all affected verification/encryption boundaries. |
| 39 | [Local RS256 fallback with external signer](https://chatgpt.com/codex/cloud/security/findings/f6f1202fa84c819197afb33546ff58d9) | Fixed | An active external backend never creates a local signing fallback. Local RS256/PS256 bootstrap occurs only for the local backend. |
| 40 | [CIBA request-object replay](https://chatgpt.com/codex/cloud/security/findings/938334950c50819180380a00b7a4a705) | Fixed | CIBA `jti` is consumed through a fail-closed Valkey replay key after validation and before request state is created. |
| 41 | [Registration-token rotation race](https://chatgpt.com/codex/cloud/security/findings/dfa9a0dd178c8191b30de8ebb2ba13a6) | Fixed | Replace, rotate, and deactivate use compare-and-swap on the authenticated token hash; stale credentials map to `invalid_token` and cannot mutate or revoke state. |
| 42 | [Kidless DCR client resists deactivation](https://chatgpt.com/codex/cloud/security/findings/1f5c330b9ec8819181dda28b73899f11) | Closed — current behavior | Existing kidless keys are preserved under the DCR compatibility rule during lifecycle operations; deactivation does not require replacing the JWKS. |
| 43 | [JWT bearer accepts client assertions](https://chatgpt.com/codex/cloud/security/findings/38cfa5c672188191981527faa092d784) | Fixed | The JWT bearer grant requires the dedicated `oauth-jwt-bearer+jwt` type, preventing cross-JWT substitution with `private_key_jwt`. |
| 44 | [Resource indicators bypass consent](https://chatgpt.com/codex/cloud/security/findings/8136bc1754a0819196f374cf18807f83) | Closed — current behavior | Resource indicators are stored in and compared with the tenant/user/client grant; token issuance cannot add an unconsented resource. |
| 45 | [Codecov token job-wide](https://chatgpt.com/codex/cloud/security/findings/6174b71ff75c81918698370bc7a6eff1) | Fixed | The Codecov credential is scoped to the upload step, not build or test steps. |
| 46 | [`prompt=none` leaks new claims](https://chatgpt.com/codex/cloud/security/findings/69104f15cf1c8191af0dfcd387551eda) | Fixed | Silent authorization returns `consent_required` when requested ID-token or UserInfo claims are not already covered by granted scopes. |
| 47 | [JAR replay protection optional](https://chatgpt.com/codex/cloud/security/findings/07806461af388191acf3f4ae5f86eeb6) | Closed — specification | RFC 9101 does not require `jti` or server-side one-time use for every signed request object. Deployments can select the stricter project policy without making it a baseline protocol requirement. |
| 48 | [Pairwise metadata with public subjects](https://chatgpt.com/codex/cloud/security/findings/ea95ff6597b081919e0c72cc944411ee) | Fixed | Discovery advertises both `public` and `pairwise` while public-subject clients remain accepted; it no longer claims pairwise-only behavior. |
| 50 | [CI path filter misses Rust build inputs](https://chatgpt.com/codex/cloud/security/findings/60ad1c54d1d8819183be7d8692591ba9) | Closed — current behavior | Workflow filters include `build.rs`, `.cargo`, manifests, lock files, crates, migrations, and build scripts. |
| 51 | [`sid` gating breaks logout correlation](https://chatgpt.com/codex/cloud/security/findings/c3c3505161448191a18c74067f4a8ed5) | Closed — current behavior | OIDC session correlation uses the authoritative session `sid`; logout tokens and ID tokens remain correlated. |
| 52 | [Sender constraint checks only `cnf`](https://chatgpt.com/codex/cloud/security/findings/801a9955f9e08191b64f00432ff9e940) | Closed — current behavior | Runtime validation checks the presented DPoP proof or mTLS certificate thumbprint against `cnf`; presence alone is not accepted. |
| 53 | [Mutable release code with OIDC signing rights](https://chatgpt.com/codex/cloud/security/findings/344db70e1f9481918cbc9a717048ad96) | Fixed | Build/test and signing are separate jobs; only the signing job receives `id-token: write`, and actions are pinned. |
| 54 | [Silent auth ignores claim consent](https://chatgpt.com/codex/cloud/security/findings/3b467d2ed8648191b923434110286466) | Fixed | Same `consent_required` repair and regression coverage as item 46. |
| 55 | [Signed request-object replay](https://chatgpt.com/codex/cloud/security/findings/bc85c85bf15481918bfd633e8e383799) | Closed — specification | Same RFC 9101 decision as item 47: `jti` is optional, while the stricter one-time policy remains available. |
| 56 | [PAR reuse until decision](https://chatgpt.com/codex/cloud/security/findings/2bcf21470bb48191be04062f0778d982) | Closed — specification | RFC 9126 says the AS should treat a `request_uri` as one-time but explicitly permits duplicate browser requests for reload. State remains client/digest/redirect bound and is consumed at the authorization decision. |
| 57 | [Claims parameter bypasses consent](https://chatgpt.com/codex/cloud/security/findings/7bab4913606c819185ce5d5425a06dc9) | Closed — current behavior | OIDC permits individual claims through `claims`; the consent response exposes requested UserInfo and ID-token claim names, and silent requests cannot add unconsented claims. |
| 58 | [`profile` scope releases profile claims](https://chatgpt.com/codex/cloud/security/findings/42f6f067278481919724c3940a8e05bd) | Closed — specification | OIDC Core section 5.4 defines `profile` to request the standard profile claim set, including `gender`, `birthdate`, `zoneinfo`, and `locale`. Treating those claims as outside `profile` would be non-conformant. |
| 59 | [Predictable live-test admin cleanup](https://chatgpt.com/codex/cloud/security/findings/b4d9ec674da0819185467f549f4eaff7) | Fixed | The live test uses an independent random password and unconditional `finally` cleanup for database and Valkey state. |
| 60 | [RSA DPoP verification DoS](https://chatgpt.com/codex/cloud/security/findings/f60c0cea88448191b4988379a56b1cdd) | Fixed | DPoP RSA keys use the shared 2048–8192-bit/exponent validation policy before expensive verification. |
| 61 | [Proxy-wide email cooldown DoS](https://chatgpt.com/codex/cloud/security/findings/0712ebc1a5c48191b61a7b2217f4c4e0) | Fixed | The global email-only limiter was removed; failed-login state is scoped to the source boundary and email pair. |

## Low and informational severity

| # | Finding | Disposition | Evidence and reason |
| --- | --- | --- | --- |
| 64 | [Token exchange skips PoP](https://chatgpt.com/codex/cloud/security/findings/72bf73b29e2c8191819201962ac32e0e) | Fixed | A bound subject token requires an exact presented DPoP JKT or mTLS thumbprint before exchange. |
| 65 | [Delivery token in cacheable GET](https://chatgpt.com/codex/cloud/security/findings/099a7b9d19448191be89ebfa49a36be6) | Closed — current behavior | Delivery uses authenticated POST with session, CSRF, and request ID; no delivery token is returned in a query string or cacheable GET response. |
| 66 | [Weak external-signer RSA key](https://chatgpt.com/codex/cloud/security/findings/1cb27395d99c8191a6c8decc733e0346) | Fixed | External signer public keys use the same bounded RSA size and exponent policy as local/client keys. |
| 67 | [ECDSA malleability bypasses replay](https://chatgpt.com/codex/cloud/security/findings/84e3179fcab48191a4d0ba4eef219f9e) | Fixed | Replay identity is derived from the verified canonical signature base and key ID, so alternate ECDSA encodings cannot produce a new replay key. |
| 68 | [Targeted account lockout](https://chatgpt.com/codex/cloud/security/findings/4f5aac121648819187f1042d53508257) | Fixed | The email-global counter was removed; one source cannot create a global victim-account lockout. |
| 70 | [Front-channel logout wait bypass](https://chatgpt.com/codex/cloud/security/findings/6f779c9693948191908787168fd68d2e) | Fixed | Each iframe completion is counted once using per-frame identity; redirects/reloads cannot decrement the global counter repeatedly. |
| 71 | [Missing PS256 issuance key](https://chatgpt.com/codex/cloud/security/findings/3af44bccbb0c8191bd5ae22990abc59e) | Fixed | A local keyset guarantees RS256 and PS256 availability and reloads before selection; an external backend never creates a local substitute. |
| 73 | [Pre-auth DPoP code oracle](https://chatgpt.com/codex/cloud/security/findings/8e69b79f55748191aa57473e79b4e935) | Closed — current behavior | Authorization codes are 256-bit random, short-lived, single-use values and the path does not provide a feasible enumeration primitive or disclose the code. |
| 74 | [PAR reuse during login](https://chatgpt.com/codex/cloud/security/findings/75af4ae26d2c8191b05fef3aba7d53cf) | Closed — specification | Same RFC 9126 reload exception as item 56. Introducing a second continuation protocol solely to eliminate permitted duplicate browser navigation would add state and failure modes without a normative requirement. |
| 75 | [Stale deploy assertion](https://chatgpt.com/codex/cloud/security/findings/839f0688b3608191bde309a33add7e12) | Closed — current behavior | The deployment test already follows the current checked SSH invocation and passes. |
| 77 | [REVIEW rerun-selector crash](https://chatgpt.com/codex/cloud/security/findings/195f7ec43fe48191ae78e0385939b5a1) | Closed — current behavior | The selector passes the complete alias/plan/allowlist context to the helper; regression tests pass. |
| 78 | [Device redemption during drain](https://chatgpt.com/codex/cloud/security/findings/c65496ae4e7481919f0abfae26ecd7b8) | Fixed | Device-code redemption requests the existing-transaction capability, so in-flight grants complete while new grants remain blocked. |
| 79 | [Stale snapshot acquires lease](https://chatgpt.com/codex/cloud/security/findings/b26665dd5cc081918f14bd3d054eb97f) | Fixed | The lease tracker records a closed-through generation watermark; publication closes the old generation before exposing the new snapshot. |
| 80 | [DCR PUT returns non-persisted ID](https://chatgpt.com/codex/cloud/security/findings/8846dcaede3c81919de59649648db35b) | Fixed | Replacement is a CAS transaction and returns the row read from PostgreSQL after update; a generated replacement `client_id` cannot escape in the response. |
| 81 | [Naive draft-expiry timestamp](https://chatgpt.com/codex/cloud/security/findings/1019a7bf878c8191bf9f5e3519497afe) | Fixed | Naive official timestamps are assigned UTC before comparison and malformed inputs remain controlled validation failures. |
| 82 | [Final check accepts `SKIPPED`](https://chatgpt.com/codex/cloud/security/findings/544288b4be90819182c716a8933c3978) | Fixed | Required final modules accept only successful terminal results; `SKIPPED` is not treated as success. |

## Verification

The review branch is accepted only when all of the following are green:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --all-targets --locked --no-fail-fast`
- PostgreSQL integration tests with current migrations
- workflow unit tests, static contracts, and offline specification inventory
- `git diff --check`

Online specification freshness additionally reported the official
`draft-ietf-oauth-rfc8725bis` revision change from 06 to 07. The official
revision diff was reviewed: it strengthens the no-allowlist SSRF resolution
check to `MUST` and clarifies several `SHOULD` statements. The implementation
already applies the required local/private-address rejection, and the project
specification inventory is pinned to revision 07.
