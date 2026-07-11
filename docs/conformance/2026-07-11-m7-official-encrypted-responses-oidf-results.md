# M7 Encrypted Responses Local and Official OIDF Full Matrix

Date: 2026-07-11

## Result

M7 passed both required conformance gates against the deployed public issuer
`https://auth.nazo.run`:

| Gate | Result |
| --- | --- |
| Hostinger local official-suite matrix | `success` |
| GitHub official parallel-isolated matrix | `success` |
| Matrix layout | 19 concurrency-safe plans + front-channel logout + session management |
| Module results, each gate | 640 total: 632 `PASSED`, 6 allowed `REVIEW`, 2 expected `SKIPPED`, 0 `FAILED` |
| Local condition results | 43,490 `SUCCESS`, 0 `FAILURE`, 0 `WARNING` |
| Official condition results | 45,117 `SUCCESS`, 0 `FAILURE`, 0 `WARNING` |

The six `REVIEW` modules are the expected screenshot-review modules
`oidcc-prompt-login`, `oidcc-max-age-1`, and
`oidcc-ensure-registered-redirect-uri` in both static and dynamic OIDC plans.
The two expected skips are `oidcc-idtoken-unsigned` and
`oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`
in the dynamic-registration plan. This evidence proves zero failures and
warnings, but it is not zero-SKIPPED evidence.

## Tested Deployment

| Field | Value |
| --- | --- |
| Implementation commit | `371b4f6e61674c4d1bd9ace7ba5b518314c8ff0f` |
| Backend image | `localhost/nazo-oauth-server:m7-371b4f6` |
| Backend container address | `10.101.0.20:8000` behind Angie |
| Public issuer | `https://auth.nazo.run` |
| Hostinger result directory | `/root/oauth2_server/NazoAuth-m7-abb652e/runtime/oidf/results-m7-371b4f6` |
| Local suite commit | `f326f6aa25d6a2b8f1ae30a6ec80a57e342333ce` |
| Official workflow suite ref | `33a724c7d809a6f9db05cbb513ff2a77cbac905e` |
| Exported suite version | `5.2.0` |
| Official workflow | [`oidf-conformance-full` run 29138366781](https://github.com/nazozero/NazoAuth/actions/runs/29138366781) |
| Main official job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29138366781/job/86506891126) |
| Front-channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29138366781/job/86506891130) |
| Session-management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29138366781/job/86506891125) |

The deployed discovery document advertised the exact active response
protection capabilities: `RS256` and `PS256` for UserInfo and authorization
response signing, plus `RSA-OAEP-256` and `A256GCM` for encryption.

## Plan IDs

| Plan | Hostinger local | Official |
| --- | --- | --- |
| OIDC Basic static | `AfU06eKtIznOi` | [`zY9tHiTZzUtc3`](https://www.certification.openid.net/plan-detail.html?plan=zY9tHiTZzUtc3) |
| OIDC Basic dynamic | `NSgoZdWMpgn6a` | [`ewZhWOXdwJb17`](https://www.certification.openid.net/plan-detail.html?plan=ewZhWOXdwJb17) |
| OIDC Dynamic Signed UserInfo | `9gHQ1b160R9Nt` | [`Nlb3jLoapc4jB`](https://www.certification.openid.net/plan-detail.html?plan=Nlb3jLoapc4jB) |
| OIDC Config | `HnVvuPFccgAfp` | [`fSApfHMOSoEBo`](https://www.certification.openid.net/plan-detail.html?plan=fSApfHMOSoEBo) |
| FAPI-CIBA ID1 poll | `JGQixOATSrQcY` | [`E2zMAnewnygAm`](https://www.certification.openid.net/plan-detail.html?plan=E2zMAnewnygAm) |
| FAPI2 Message Signing, JARM | `PU6EHPdBSVV1V` | [`s6NHqtoQ79Ssn`](https://www.certification.openid.net/plan-detail.html?plan=s6NHqtoQ79Ssn) |
| FAPI2 Message Signing, plain response | `EaQp5vX0o4Yxy` | [`6jLtoxNMdWcaW`](https://www.certification.openid.net/plan-detail.html?plan=6jLtoxNMdWcaW) |
| mTLS auth, DPoP, OIDC | `98uNHi2RN5r1I` | [`IHXBC4QlmZtmo`](https://www.certification.openid.net/plan-detail.html?plan=IHXBC4QlmZtmo) |
| mTLS auth, DPoP, client credentials | `nMNWsnldpEc0E` | [`mNltuTouvjbxd`](https://www.certification.openid.net/plan-detail.html?plan=mNltuTouvjbxd) |
| mTLS auth, DPoP, plain OAuth code | `sjf6AwQ1Px3mH` | [`30FnrqiIwiw8x`](https://www.certification.openid.net/plan-detail.html?plan=30FnrqiIwiw8x) |
| mTLS auth, mTLS sender, OIDC | `eGwgyJzhv11K8` | [`0QTVdtyhU7B4d`](https://www.certification.openid.net/plan-detail.html?plan=0QTVdtyhU7B4d) |
| mTLS auth, mTLS sender, client credentials | `cjwzDjl0bFeMn` | [`ICLdDEB3u1OK1`](https://www.certification.openid.net/plan-detail.html?plan=ICLdDEB3u1OK1) |
| mTLS auth, mTLS sender, plain OAuth code | `jL7omvK6aXyxG` | [`YvPCvmWQTvYnm`](https://www.certification.openid.net/plan-detail.html?plan=YvPCvmWQTvYnm) |
| private_key_jwt, DPoP, OIDC | `F4VQXBziIssdG` | [`UPvMQLm2XDKhk`](https://www.certification.openid.net/plan-detail.html?plan=UPvMQLm2XDKhk) |
| private_key_jwt, DPoP, client credentials | `MZJUIXcfKoRpG` | [`1zytqVvb5EOkP`](https://www.certification.openid.net/plan-detail.html?plan=1zytqVvb5EOkP) |
| private_key_jwt, DPoP, plain OAuth code | `vdHBLUaC16GLv` | [`Z1whmYHBY5Yfy`](https://www.certification.openid.net/plan-detail.html?plan=Z1whmYHBY5Yfy) |
| private_key_jwt, mTLS sender, OIDC | `yCJf5vTigfL9c` | [`M30wnFmjsPPyH`](https://www.certification.openid.net/plan-detail.html?plan=M30wnFmjsPPyH) |
| private_key_jwt, mTLS sender, client credentials | `8dZf7LNRN9Qn6` | [`GItnFkTbnPjPF`](https://www.certification.openid.net/plan-detail.html?plan=GItnFkTbnPjPF) |
| private_key_jwt, mTLS sender, plain OAuth code | `dAFqg38PFjHak` | [`8kvCjV1sI9xLB`](https://www.certification.openid.net/plan-detail.html?plan=8kvCjV1sI9xLB) |
| Front-Channel Logout | `p5ruriG9bDSmS` | [`EwdMCYZkkkCOv`](https://www.certification.openid.net/plan-detail.html?plan=EwdMCYZkkkCOv) |
| Session Management | `HfjOCIL1yjzw8` | [`DCSnDM24hUHTP`](https://www.certification.openid.net/plan-detail.html?plan=DCSnDM24hUHTP) |

The selected signed UserInfo plan completed its official
`oidcc-userinfo-rs256` module successfully. It does not claim the legacy
dynamic OP profile, whose complete plan also requires implicit and hybrid
flows that this issuer deliberately does not implement.

## Official Artifacts

| Artifact | ID | Size | SHA-256 digest | Expires |
| --- | --- | ---: | --- | --- |
| `oidf-conformance-results-concurrent` | `8244438981` | 17,954,109 bytes | `0ce9434cc5326fffa40ca5712b93e17779f34d0517cef757f3d0f86548cd44ff` | 2026-10-09 |
| `oidf-conformance-results-frontchannel` | `8244321779` | 31,193 bytes | `d844034f318eeb36f21ca1e3c86d2e4655e4a8b57709ebd567014db2eedcc931` | 2026-10-09 |
| `oidf-conformance-results-session-management` | `8244322421` | 26,309 bytes | `12f4dbc912ce6bae4b4e56d135f4be38e7d567b131737b102c09e3ea3b0d4f09` | 2026-10-09 |
| `oidf-public-plan-configs` | `8244320743` | 51,729 bytes | `f34be3170dc21c53cd2eb5e113e12ef4986d5e61712266480e5cf1ffccc55c41` | 2026-10-09 |

## Public Seed Consistency

The first diagnostic attempt, run
[`29137838307`](https://github.com/nazozero/NazoAuth/actions/runs/29137838307),
proved that the live database had been seeded from a different rendered key
set than the workflow's public-only artifact. The browser-isolated jobs passed,
but FAPI clients failed at client-assertion verification before protocol
processing. That run is not acceptance evidence.

Before the final run, the live test clients were reseeded from the exact
`oidf-public-plan-configs` artifact for implementation commit `371b4f6`. All 38
expected client JWK rows matched the database, and the final workflow regenerated
byte-identical public configuration files. The final run then completed all
three jobs successfully.

## Coverage Boundary

The official suite snapshot contains an OP-side signed UserInfo module, which
is included in this 21-plan matrix. It has no OP-side module that requests
encrypted UserInfo or encrypted JARM. Local positive, negative, metadata-truth,
key-ambiguity, DCR/DCRM round-trip, decryption, and fail-closed tests therefore
remain the authoritative evidence for those two encryption paths.

This record indexes regression evidence. It is not a new OpenID Foundation
certification statement.
