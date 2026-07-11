# M6 FAPI-CIBA Local and Official OIDF Full Matrix

Date: 2026-07-11

## Result

M6 passed both required conformance gates against the deployed public issuer
`https://auth.nazo.run`:

| Gate | Result |
| --- | --- |
| Hostinger local official-suite matrix | `success` |
| GitHub official parallel-isolated matrix | `success` |
| Matrix layout | 18 concurrency-safe plans + front-channel logout + session management |
| Module results, each gate | 639 total: 631 `PASSED`, 6 allowed `REVIEW`, 2 expected `SKIPPED`, 0 `FAILED` |
| Local condition results | 43,415 `SUCCESS`, 0 `FAILURE`, 0 `WARNING` |
| Official condition results | 45,039 `SUCCESS`, 0 `FAILURE`, 0 `WARNING` |

The six `REVIEW` modules are the expected screenshot-review modules
`oidcc-prompt-login`, `oidcc-max-age-1`, and
`oidcc-ensure-registered-redirect-uri` in both static and dynamic OIDC plans.
The two expected skips are `oidcc-idtoken-unsigned` and
`oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`
in the dynamic-registration plan. This evidence therefore proves zero
failures and warnings, but it is not zero-SKIPPED evidence.

## Tested Deployment

| Field | Value |
| --- | --- |
| Implementation commit | `07e69855948ca0a12d4dcd26bb9372e3ea2d04d3` |
| Backend image | `localhost/nazo-oauth-server:m6-07e6985` |
| Backend container address | `10.101.0.20:8000` behind Angie |
| Public issuer | `https://auth.nazo.run` |
| Local suite commit | `f326f6aa25d6a2b8f1ae30a6ec80a57e342333ce` |
| Official workflow suite ref | `33a724c7d809a6f9db05cbb513ff2a77cbac905e` |
| Exported suite version | `5.2.0` |
| Official workflow | [`oidf-conformance-full` run 29131918401](https://github.com/nazozero/NazoAuth/actions/runs/29131918401) |
| Main official job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29131918401/job/86488754851) |
| Front-channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29131918401/job/86488754846) |
| Session-management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29131918401/job/86488754853) |

## Plan IDs

| Plan | Hostinger local | Official |
| --- | --- | --- |
| OIDC Basic static | `ampOh31JYd6Ae` | [`uy25zwms5OTxa`](https://www.certification.openid.net/plan-detail.html?plan=uy25zwms5OTxa) |
| OIDC Basic dynamic | `y6pv0z6AUm0qf` | [`wqeK8msLxAdCm`](https://www.certification.openid.net/plan-detail.html?plan=wqeK8msLxAdCm) |
| OIDC Config | `jUm1IQBF3TW8a` | [`FDTAyE4otGAnC`](https://www.certification.openid.net/plan-detail.html?plan=FDTAyE4otGAnC) |
| FAPI2 Message Signing, JARM | `YyZQyUHKyHqv7` | [`0USqvrNF15dpB`](https://www.certification.openid.net/plan-detail.html?plan=0USqvrNF15dpB) |
| FAPI2 Message Signing, plain response | `p4IAKmlznWMfm` | [`6ue44ArLogUOi`](https://www.certification.openid.net/plan-detail.html?plan=6ue44ArLogUOi) |
| mTLS auth, DPoP, OIDC | `LlY1ErqOH6Li2` | [`YO8K0e5dpu1yw`](https://www.certification.openid.net/plan-detail.html?plan=YO8K0e5dpu1yw) |
| mTLS auth, DPoP, client credentials | `qZjgWzX29s157` | [`8sy9Q9H6nA9pQ`](https://www.certification.openid.net/plan-detail.html?plan=8sy9Q9H6nA9pQ) |
| mTLS auth, DPoP, plain OAuth code | `MQZZPTT31Vmws` | [`5AMdOcxjxEvRd`](https://www.certification.openid.net/plan-detail.html?plan=5AMdOcxjxEvRd) |
| mTLS auth, mTLS sender, OIDC | `HXxrwM9zYNmA1` | [`dbIwzOhUFCGWD`](https://www.certification.openid.net/plan-detail.html?plan=dbIwzOhUFCGWD) |
| mTLS auth, mTLS sender, client credentials | `LJVQMWammZqXJ` | [`BGkg7jSLdXDmD`](https://www.certification.openid.net/plan-detail.html?plan=BGkg7jSLdXDmD) |
| mTLS auth, mTLS sender, plain OAuth code | `hAHlJjnddpUa2` | [`km9NvcqRSUq90`](https://www.certification.openid.net/plan-detail.html?plan=km9NvcqRSUq90) |
| private_key_jwt, DPoP, OIDC | `HxVEkLZEOzXC6` | [`ElRlE15151xEK`](https://www.certification.openid.net/plan-detail.html?plan=ElRlE15151xEK) |
| private_key_jwt, DPoP, client credentials | `MFfSBkp2QerzS` | [`QM4jXzw8GW0JB`](https://www.certification.openid.net/plan-detail.html?plan=QM4jXzw8GW0JB) |
| private_key_jwt, DPoP, plain OAuth code | `9CgCKcL5wQ4zs` | [`OR03IUz3A7p2d`](https://www.certification.openid.net/plan-detail.html?plan=OR03IUz3A7p2d) |
| private_key_jwt, mTLS sender, OIDC | `h7M6Wnhg2hBkv` | [`W35spDzQnl8M8`](https://www.certification.openid.net/plan-detail.html?plan=W35spDzQnl8M8) |
| private_key_jwt, mTLS sender, client credentials | `f41gl6zrESm1A` | [`ew8p7jewjyquy`](https://www.certification.openid.net/plan-detail.html?plan=ew8p7jewjyquy) |
| private_key_jwt, mTLS sender, plain OAuth code | `rW5CeIfprlDNB` | [`q5Ob3A3utR8e5`](https://www.certification.openid.net/plan-detail.html?plan=q5Ob3A3utR8e5) |
| Front-Channel Logout | `Jr1pkcVsLVej9` | [`fzpyqaYbKzhgI`](https://www.certification.openid.net/plan-detail.html?plan=fzpyqaYbKzhgI) |
| Session Management | `xWhnr5TohgtU0` | [`JeQi5UqwJmRMk`](https://www.certification.openid.net/plan-detail.html?plan=JeQi5UqwJmRMk) |
| FAPI-CIBA ID1 poll | `HsXzg21D7hIOn` | [`NAmq89dbswTTn`](https://www.certification.openid.net/plan-detail.html?plan=NAmq89dbswTTn) |

The CIBA plan alone completed 35/35 modules with 2,660 local and 2,782
official condition successes, with no failure, warning, skip, or review state.

## Official Artifacts

| Artifact | SHA-256 digest | Expires |
| --- | --- | --- |
| `oidf-conformance-results-concurrent` | `8ffdfb03a8b224c17f14f7003f292332bed5876c95d34f197c91165aabda0092` | 2026-10-09 |
| `oidf-conformance-results-frontchannel` | `771ac17ddaa7122a852a75226ce0d1de5bc500aa43d93c604f0ae6fd261ad7ed` | 2026-10-09 |
| `oidf-conformance-results-session-management` | `b3f681180fe4353e29bf7d20fc14fd4a30a802b8f4c7910f0bf6040f4ed84089` | 2026-10-09 |
| `oidf-public-plan-configs` | `fbcb2c93a0f6f23b1864418be346689c4eb8a49bfb3bf203e60547d6a2a42d11` | 2026-10-09 |

## mTLS Proxy Boundary

The official CIBA configuration uses two public client leaf certificates.
Angie accepts untrusted client certificates at the TLS handshake boundary but
maps only the exact two published SHA-1 leaf fingerprints to proxy
verification `SUCCESS`; all other untrusted certificates remain `FAILED`.
The Rust service then independently parses the forwarded PEM certificate and
matches its SHA-256 thumbprint to the registered client. This preserves the
trusted-proxy and per-client certificate-binding checks while allowing the
official static CIBA clients to reach the protocol endpoint.

This record indexes regression evidence. It is not a new OpenID Foundation
certification statement.
