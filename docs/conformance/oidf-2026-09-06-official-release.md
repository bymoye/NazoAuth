# OIDF and transport acceptance: official releases, 2026-09-06

Status: engineering acceptance complete for the identified published artifacts.
This is not official OIDF certification. Original Suite classifications are retained.

## Published artifacts and installation

| Component | Release | Source commit | Tested Linux GNU x86_64 SHA-256 |
|---|---|---|---|
| NazoAuth | [v0.2.15](https://github.com/nazozero/NazoAuth/releases/tag/v0.2.15) | `3bc257fc74bf1d21d03f4bb6083c088c09c9349a` | `6046d995138f04d4b21e8cfef16836d9a20d64cbd062fcfb45560bfa017d0869` |
| NazoAuthCtl | [v0.2.27](https://github.com/nazozero/NazoAuthCtl/releases/tag/v0.2.27) | `0cafa7a09f96de9ce064d5d1772a7893d8b4613f` | `668c1eef5e633ece5c35dde98be951b57625bac082545ad989c22944a695fbef` |

Both artifacts were downloaded from their published Releases. GitHub artifact
attestations were checked against the exact repository, release workflow, source
tag and commit, rejecting self-hosted runners. The official controller installer
and ordinary server update installed the tested files. Runtime `/proc/PID/exe`
hashes bind both deployment modes to the same server artifact; version strings
are not substituted for executable identity.

The server [release workflow](https://github.com/nazozero/NazoAuth/actions/runs/34019462510)
passed all eight binary targets and container/signing publication. The controller
[release workflow](https://github.com/nazozero/NazoAuthCtl/actions/runs/34019688526)
passed all ten jobs, including six binary targets and server compatibility.
Public black-box acceptance below exercised Linux GNU x86_64; it does not claim
that each published target ran the live matrix.

## Complete matrix

| Mode | Instantiated / terminal | PASSED | REVIEW | SKIPPED | Failed / warning / incomplete | Cleanup |
|---|---:|---:|---:|---:|---:|---|
| Direct TLS | 1198 / 1198 | 1145 | 42 | 11 | 0 / 0 / 0 | complete |
| Trusted proxy | 1198 / 1198 | 1145 | 42 | 11 | 0 / 0 / 0 | complete |

No plan or module was excluded. Both runs used the same ctl-bundled matrix
`877f669e6d5f57fd5f8c6a4237910ff1a85462a44374fe18e8f20ddbfae95769` and driver
`c9886feb4116fceeb46384e5fa0979e6739d677381b8cb144fe152b95ab7dbb1`. Every module reported external Suite
`info.version = 5.2.4`. The artifact's 5.2.2 revision and image digest describe its
declared reference build. No independent attestation of the external Suite's
running image digest is claimed.

All 84 REVIEW records and 22 SKIPPED explanations were individually examined.
Per mode, evidence comprises 14 HTML snapshots, three JSON snapshots and 25 live
WebDriver PNGs. All PNG file sizes, hashes and individual module/variant bindings
were checked. Within each run, the 25 PNGs have identical bitmap content, so that
content was opened once in full for visual inspection. This does not imply 25
separate image opens. Both inspected contents display `Presentation verified`
and the successful credential-verification message. Nine PNG records per mode
cover positive `iso_mdl` cases. These are screenshots, not runtime-signed VP receipts.

Six login/max-age responses per mode show a second login form. Three redirect
responses explicitly return `invalid_request` for an unregistered redirect URI.
Eight logout responses retain local signed-out state. Seven cases record a local
confirmation page and confirmation control; the valid-hint/no-redirect case
succeeds directly and explicitly skips the optional confirmation click.

The logout review applies the [RP-Initiated Logout specification](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout):
invalid redirect data cannot authorize a redirect, while a separate user-confirmed
local logout is permitted. The record therefore describes the observed local
confirmation flow rather than claiming the generic error page suggested by some
Suite prompts. Raw REVIEW values remain unchanged.

Eight skips per mode concern an unadvertised `none` algorithm. Three require the
encrypted VCI variant while the selected variant is plain. All remain SKIPPED.

## Transport, tenant and controller independence

Fresh requests in each mode prove tenant-scoped client and token namespaces,
same-kid key separation, PKIX certificate/trust isolation, DPoP nonce and replay
namespaces, opaque PAR state rejection across tenants, and tenant-bound audit
events. Temporary tenants were deleted through ordinary management APIs.

With no ctl process present, fresh requests exercise password/TOTP login, consent,
authorization code with PKCE and state, ID-token signature/nonce/identity,
userinfo, refresh, introspection and revocation. The sequence is repeated after
certificate restoration. The Direct TLS sequence connects to the verified
NazoAuth-owned TLS socket while retaining the original URL, Host, SNI and
certificate validation; it bypasses every proxy. The trusted-proxy sequence
uses the public endpoint. These bounded checks are distinct from the full Suite
matrix and do not imply that every protocol was rerun during ctl absence.

The same official controller performs ordinary deployment configuration updates
between Direct TLS and trusted proxy. Both modes use the same immutable server
binary and publicly validate their HTTPS endpoints.

## Certificates and recovery

The [candidate evidence](oidf-2026-09-06-dual-mode-candidate.md) retains real ACME
initial issuance, renewal with key change, validity and mismatch rejection,
reload/public-verification failures, forced interruption, fencing and ordinary
recovery in both modes; the proxy also exercises native syntax and rollback
failure. Four certificates were issued in that candidate phase.

The published artifacts separately activate an already issued alternate
certificate and key in each mode, verify the actual public leaf, and restore the
prior certificate/key identity. Server PID, executable digest and installed
configuration remain unchanged through each certificate transaction. Each
restoration is followed by fresh ctl-absent protocol requests. This phase makes
zero new ACME orders and does not relabel candidate fault injection as a fresh
official-release fault-injection run.

An initial `--from-acme-current` plan correctly rejected the old ACME receipt's
deployment declaration revision with `side_effects = none`. Its raw failure and
original harness are retained. The subsequent ordinary external-material import
uses the already issued files under the current declaration; no old receipt was
edited and no revision check was disabled.

## Source checks and cleanup

All six governed server workflows passed on the exact release source commit.
The [workspace test job](https://github.com/nazozero/NazoAuth/actions/runs/34018469111)
records 2746 passed, zero failed and five ignored tests, with PostgreSQL and
Valkey. Clippy, migration/recovery coverage and the other governed checks retain
their own CI records. The controller [four-platform workspace CI](https://github.com/nazozero/NazoAuthCtl/actions/runs/34018619817)
passed on its exact release source. These source checks and published-artifact
verification are distinct from the public matrix.

Both Suite runs reached terminal state, settled Suite resources and completed
temporary deployment cleanup. Shared ingress was restored to its 13 original
configuration hashes; the task-only SNI route was removed. Existing site responses
were checked against observed baselines, including the documented pre-existing
502/504 variation. The existing authentication service's health endpoint returned
200 over IPv4 and IPv6 after restoration and final fixture cleanup.

Final cleanup retired four task deployments, eight task containers, their isolated
network and the task native proxy. Unrelated container identities remained
unchanged. Operation journals, raw evidence, external TLS material and two private
test-data volumes are retained as operator evidence; they are not running services.

## Signed evidence

The private archive contains all 2396 original module JSON logs and 50 PNGs,
their manifests, individual engineering review bindings, installation/attestation
records, protocol request evidence, certificate transactions and ingress recovery.
The raw manifests and index have detached Ed25519 signatures. The exact archive
was independently checked locally, including every indexed file and raw binding.

- Archive: `official-release-acceptance-signed-v1.tar.gz`
- Archive SHA-256: `1b1ed3f703313000d29b1840fd4f91cab6af10b0f1470cbeefc9e109bd0972b3`
- Index SHA-256: `58a0f76a64cc0438ef866c6e5cfa2d44d2da9ca6fba81b562340f29c9c60ad8a`
- Verification key SHA-256: `c3f408729e22ca93d9c95c246711e96a58e27ecceeeb54534235457218ad1b8e`
- Final fixture-cleanup index SHA-256: `ffe7578167635fd2e6d0aacf27aa7bc0f0510e47a9c0bfdb3f2718e5b61e6c5c`
- Final fixture-cleanup archive: `official-release-fixture-cleanup-v1.tar.gz`
- Final fixture-cleanup archive SHA-256: `467510ae2b138a43eac1879d95b1e46c90033e41c7f0d7e5d02d347e3a2b6071`

Verification key:

```pem
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlRkaBe3T9ql+R0J4xMymzX+mjKO49k4ivpswPMs9Gxs=
-----END PUBLIC KEY-----
```

Detached Ed25519 signature of the exact acceptance `index.json`, base64:

```text
leb91bU9KCMCFAZ1RYu/6mH/KizAME67GxSbLWnvXgduue/ean01MHQusOqAAGEq6Mh56oWm2YcBQX/2r4S2AA==
```

Detached signature of the separate final fixture-cleanup index, base64:

```text
S5Wp5GkR+SRePz38j2GhE9ykaguWHp4diOKzuEE+zLiYx6RX3KeRvvZi3al8xEx9GsuHTOOeehgD+ku4IAKzCQ==
```

Raw archives are private because they contain protocol and infrastructure records.
Obtain them from the acceptance operator using task record
`nazoauth-130-acceptance-20260906`; check the archive hash, verify the index signature,
then verify each indexed size/hash and raw manifest signature before its module/PNG
bindings. The archive does not contain the signing private key. The signature is
engineering provenance, not third-party certification.

This Markdown is retained in NazoAuth as product validation evidence. The Suite
and ctl remain external clients of ordinary protocol and administration APIs;
the evidence adds no Suite-specific server route, schema, configuration or
authentication behavior. Driver and matrix updates ship with ctl independently
of NazoAuth releases.

## Direct review bindings

Run JTI: `01a075ed-d95a-7fb2-9fff-7487ae770310`.

Report SHA-256: `205e36726ce4266e04eb3ef5c83861e1b4039b7406b478b17017b0e13094e5bf`.

Raw manifest SHA-256: `ad2ec926363cd3307a4d27eb2a9106d7720d1f630f5747ea08cdb0a51f4de80c`.

Each row remains REVIEW. The raw digest binds its complete variant and response or PNG.

| Module ID | Test | Variant | Evidence | Raw log SHA-256 |
|---|---|---|---|---|
| `xnOwPqJGwukCuBd` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `9ea318d4c2b29260900bbc357cdbe7599445e7e7b26806506bbd25a27697c084` |
| `tpbAZcvmUz8m0qG` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `2c9646686a86f4b2cd111a6f8291909eb942fa1e9c32f5fc784fb96aa0d73c1e` |
| `LNups5i9grgW5wE` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `253cf7372afbf9389456ccb09ad693dba3563b6c601d7b13c781c740366c32f9` |
| `NLwqXqT5f1VSPIH` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `866321108b4a6708088718c18a76ed476f11faf389e9a69dd9b82abcc3498e65` |
| `4AejjL8DmLDf7LA` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `c5f225fae878b386b541979119b687d3889205784fd825b867097451438f9f0e` |
| `RDl4txXIg85bbrv` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `ce64b6841b2e6efd97fc2bfdf38c12a6c5bfda248b756c1daecea3621f5539ef` |
| `TzNYPCspNKyNV9p` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `1df940bfc4eb727bf5266449f22337832ecf33bf752601c4c994907cad962f46` |
| `xtyym4IgSGe31Yf` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `c1d6c75848fafca3bc570be66f890372f707a0bcf20ab2c36e9376e4246044d0` |
| `w7xDDejAaLi1CVn` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `28202cb50396f92df91effac187e3d5a4d0017b27b4133eaa6c91f6491933fe8` |
| `BL91Hea4XbapxDy` | oidcc-rp-initiated-logout-bad-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `7568b50bd2e766aa3b2b7d6d2ce66baa52714167e7e196782f3b280a303154e0` |
| `oC1Xzr04FRLRz5M` | oidcc-rp-initiated-logout-modified-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `40b97bf62c6c577419b7a861673cbf1adcfaf1770b7d5379026a846cdd5d04aa` |
| `QoFuSTqu80jRJJB` | oidcc-rp-initiated-logout-no-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `baf5487541d4c540a1f8623fa7d2a35ef5d8e3cd15831d81b6307209f769ed52` |
| `OQilJmUozfRvrcP` | oidcc-rp-initiated-logout-no-params | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `cbddd4cea8f09198da5682290ecb749169ed36a9ccc901ad768c4e65667f52cf` |
| `SlVuj32gXzpipNB` | oidcc-rp-initiated-logout-no-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `2499c93d95a1446ad1a378b396f97677c09bb51efefd68b701518f13448c49fa` |
| `HVuYRDpCO29BwLn` | oidcc-rp-initiated-logout-only-state | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `71ac7091819067ffa58d0e5b78065db8e3b838a624bdd984e27d237c02127bdf` |
| `rVKsPbSxkPgfcBT` | oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `e0ae6a415c52400e7898572ae356aca2483f13922f41b15a90762ae9e79eea04` |
| `ykQgC4Ucz3TtcRD` | oidcc-rp-initiated-logout-bad-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `c06cc3bc2a14b1e0ec0800fd366ab21ed78fd7955f76dfa92912beb38916d5e1` |
| `n6gzZbgnUdPtt5T` | oid4vp-1final-verifier-happy-flow | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `dc214e820b26e33103794c3d6c404dfd5291c83c976d24afe6f22a32197be336` |
| `WH1cJGwduiy8wlb` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `d1bdf35786048886cb33be8beb18a5cc25617bc25c097f4147242b18b56c55b3` |
| `xg3LMRALH9QuI8G` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `147a652836b3bc781646b6730d7beb75d9e2bcc72ef21cf5a7d450a9bb68e471` |
| `B4hcI1GBGKNHczs` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `b566c5449dd26a1ceb6fccec387c0324d6f821348535656b56252c990be8d9a3` |
| `GMl7xgL55p5Bmbx` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `792c280837c3df9649e413e6ee77a93ae9c3edc355d2d66e721c43c89cbf07f1` |
| `BJoEZYRH9MU7uls` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `4b3dba955b6442641ffd1e4bdb4b9788b782cc42d34bea4b98e68801e80a7792` |
| `s1UvRGJ4ndWDsFi` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `c112e22ccc80c2ad707bcbb3c67cc67931d3eeb8513d6080be7b8715b03a6cba` |
| `wamMbjRYoIPYcFM` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `3700368a75e3351687cf5ee33bd0abe4dbc9e5695e7e4b42013d51786407380e` |
| `Rd4VSlgqswUSiMS` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `8a3c35a277412673e883a47c82eb496cb2f924013d304356dd839f262df7134c` |
| `fEWIj49JS5DapI2` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `e6180ad13763bb815801bcd6a7cad972f8bcb0d29f6f339e1def72483540b752` |
| `YpbWNxlxgOvIWwy` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `fb112e2d33d8bcc9fce14474b50cadcece793b73c5c76eb23da25fdd3f741a73` |
| `2a4BbvNe60Uv50K` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `517ec1f5055eb984012e42e7223be05f7188d5d790c342dc92e065fabdf45c23` |
| `UMUAfgNbrG0MdQH` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `6b56ef93b9eff6749e21c62cc2226c75a999efb161b70fba54659af121a5ba4a` |
| `IOtVo0qvI3BRz60` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `8ef8c18527111d15ae60c3cf354bd1a31c77893baf1a876b2e8d4f73d2057e27` |
| `BvTrVIZpn043vsf` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `2b390bec944d59e2d699181d6048be2e4a147927710fee3525a3c221d2f9f9df` |
| `lWOf0qa0EnMw3Yh` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `37685bd799d5fc36387968786b25a7a31eff33864bd1b38e5383aacacc0300ef` |
| `Z3thO3BWOSBBL1B` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `9190374bc8d25aab8511085a462aa9de73f793a8267a46b2135b3b199969be29` |
| `D4mBTRB8aZdSqLy` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `550944dc8870ab6791a1dda40d8e6aabb7c3a4f9405cb58fe0072da0524edc3d` |
| `A85YnKTfrWQpX4L` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `5ef56dbd4df5aaceda87db8aab8b5e596805465495caa75924b7293027486739` |
| `0aX0hdwkjjkQ2V4` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `703f2514fcf73b768fef21dd5a808e4c88bd5cb7dcee6bfd9f5aab6dda5ae73f` |
| `GMZfMalex59qnNw` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `6f3a305b8aeb712bda920bd8cc14bd2d82e76f65d7724f7869c933f0096aa2fa` |
| `UOX0vRqYR9WXnOJ` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `0ed67db3c3f2c600465051ce6417eade60af9922e79a61aad0e87094a41bc853` |
| `VImuA9T5OWGGrx6` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `a87eb20f6f0530988f01414cb03055dc80e5c298365212f182fb6569f7d39c2d` |
| `aFB5QyTEfAcUjEL` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `a855c2128d8605cd93c753d9397796165bea103775c2a0d9b69e8f205364ebae` |
| `s0EZRCd8BFwBmK9` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `d67972cdc00d4453a7a8f1ca233c216d4b0041ab2c949ae12cc01087dafb5375` |

### Original skip bindings

| Module ID | Test | Reason | Raw log SHA-256 |
|---|---|---|---|
| `iBqRvkO4XtCwU4S` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `882fcce328b7819fce67a7e6001183f5b52ba56273cf450354af00e0a6a4c25c` |
| `InxgwOoa9h4eoVk` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `71641409e4ce7e7e9babed7a79c2cc39fe7c3b6834bd8e03cd07688d02b75be1` |
| `hjbDEs8aaEGOc8x` | oidcc-idtoken-unsigned | Unadvertised none algorithm | `1853a432fc68578019742992e9580156ab1b35662c8a353828341e023639e48f` |
| `IXHFc0oSEk1utHg` | oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `4b7b04350ec0f0f9dad182668162bff75542a1901bf4c7192b82a7080bd67591` |
| `hxPE6WuDPmdrgzU` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `108683d222ea14c67785a0e18a6ab2a36992e419931075ae0f8c5661d3fdd83c` |
| `zYfF5xn9Vrx9mHz` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `fb0c6a12bf6c42d3f9333fdb7a51af1e0263b9451270fd5aa344f0c5813a8bcc` |
| `BOpCQnS4Ysc3iXz` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `61ace3dd91217d43c137d100bc6e41fbbd3fdcb89875fc9dad8aa12328a784cf` |
| `dPhTfHs8hkUoTMO` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `a1f5bb0d260c6ee64dbcd132cb2d06334ff1b356716e9f20878042c14f94f414` |
| `O40A3jS2QyqvNjQ` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected plain | `6bc6e3599f970871e3c0d43f1f5195823f1d66c4b5645a895a509910cfb04e3e` |
| `DDuhYdVgYtgYpSg` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected plain | `9609e167823d67bb55a1670b676a72800f65c930c8fe0e43758e806460e9dcd8` |
| `VAEscjh9lNLKKnL` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected plain | `17183829cb846feeeb9c428f56bc5c2c0020c2f86c2b0cd0dc47f688d43c3179` |

## Proxy review bindings

Run JTI: `01a07611-4068-7ff3-8357-4f079ef4c06d`.

Report SHA-256: `f8ea0ed49740355c7e7467ee7b7f29e644c0f7e5d910fa66c2f84b389bcda05d`.

Raw manifest SHA-256: `d7c7085a26c1bab2409df0d7c2cc7c8bf08d8ac919b57a8232a68b8c7d5643de`.

Each row remains REVIEW. The raw digest binds its complete variant and response or PNG.

| Module ID | Test | Variant | Evidence | Raw log SHA-256 |
|---|---|---|---|---|
| `G1ynmkgYYwRZzWZ` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `caba2a5f71e0d773a57833c9f800f79be724bdd87bdcb4bc546a05a5c456bf1a` |
| `gtoDG64qz4c9hZO` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `38e978f6b53297de333fc979e6a42d5a4cffb5d15d0024f3011a19138063709b` |
| `OtQcTOyobJlzm2N` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `aded3b89cee8ea6d947d47fa2f97f18ae68ceac762ec568eda4526d575acd836` |
| `GzvJegaBmpisLmW` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `9c422d532e4de9cba2f7cae58f9e8cf3bd57d15d1a2f1d52c92aca45b2686e2e` |
| `39UA2pDr6Fs5KNQ` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `a942083f65ff88630cb64523a1c311839319826eb23cf4089a19995f7c672a88` |
| `d1VNYxRslP0Audq` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `0c58565fce25dcd471a403363cef378b3b0ab5a72ffc20f89d7dbeb3ac209371` |
| `39wqP8U6YRF0Ol2` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `f63682c5d64292b143270e80b73f00d631cff1fc9f3ae2eb661f8b5c17dd8d6c` |
| `GINzYfe3JmJeBGP` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `f9b3f644a04da45cc83b4dd38c011d4d469eff8f200f2930c96d713b429640a0` |
| `8qVQQfBxj6Yi0IF` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `8fcbe5021b070b531ab7fe9c2132d49086aa58d0310326b06a46b01baf03156a` |
| `RNZfoy1rHr7sGxZ` | oidcc-rp-initiated-logout-bad-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `f3f7a2cdad95885d0b81d43ccd687bb0cd7d123b9ee91dd9d4659b528e93a761` |
| `5TOB6N6KgGDIC4V` | oidcc-rp-initiated-logout-modified-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `abdd25b0ed403a95de4c2cda6d223e162b94ea50ba16c60dd5d7ea9f5f5a03b6` |
| `oVRFuzKhyp7PTGJ` | oidcc-rp-initiated-logout-no-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `1c52309b4f73b8e78fa010a88d6574b6ec781f04f6c34e94f27b0f2fa2af9e4a` |
| `P6CwQwW96T6FxYF` | oidcc-rp-initiated-logout-no-params | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `2760d5fb694a7da7b15eb0fc5e8e469412acf8aa8c5c953dedc903b655cf255b` |
| `jHnmGQQUR08VB9Q` | oidcc-rp-initiated-logout-no-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `310ca4fd0938709ab8f4b6002b2e90e547cf640bc143136d63d4ae4ee219fa18` |
| `dkdNo6z8ynIstT3` | oidcc-rp-initiated-logout-only-state | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `23b9cd0b628f90313f222011fc768ec5a4b19cecccc9ccd3eda1006b945cfbeb` |
| `mnNAIPhHXv62B96` | oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `e96ca8e77aa861bffe4d77503d4d74dfc01cddc1e3c4e6f06cbc52405433fc6a` |
| `ZKX8BgyOl5XhCMg` | oidcc-rp-initiated-logout-bad-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `50f0577c073ad037224bf85fc286d7bd783652036e96f6b16139768fb4afbecd` |
| `reX6EIinoe9ociw` | oid4vp-1final-verifier-happy-flow | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `5e6f4c7e9596507de04cc9f9e7d8c911b17f5d63e5fad7c410c97ff7394ea817` |
| `YsSW20nwc2AT41b` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `e3fa586641e788615d4df7334e4e34eb7c9ec7a175449b8124ea9e3b3911faac` |
| `fSzvFWWJ0scNgZW` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `1b707ff4f92b656234b82919e750c8e33a084b39caf5a0b466997a821cf38cba` |
| `m9oj1fSpoqa1gLX` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `da898ae863c1aa50030b43b3ef7166bb2fc71c671fdc5162ae4ce6954be882ce` |
| `CiCOKQcGXrnmEQg` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `75550280353d39a990fc428d2669744c68199d2a3c8f11da7a81639a60671348` |
| `dSqbd7aWcxH8YRP` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `9e5368eac0d365e5bf2cbb20730ee71ce991b8ed6b7f81a20960406883440d80` |
| `3FdT0Qho1QDjEwt` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `11b2a0d2545c62eec85d12feb60d9466226c7fc3925f4c9853113fff262b60a2` |
| `KOOgZ2G3SG2Io2n` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `aebe86de1cb7bbc733f1a5d411ffb5ada57066730dbe7efede77e1afe637444b` |
| `PYccqOoqTECruy7` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `56aed6e6e84a982dab5d4508bcf65b3b972752e03d637ddae677699152a27153` |
| `hIohKBCdcQIDmVA` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `0c62d82c6b8ab3b018b112fda31eac7ae234f58495ea2c692a4b320fe688e1e3` |
| `kVVZHoP24ozsuUp` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `5985734dcc907dd0f5f4edb6ac0a63448eab885d2726ea165d689cfeb5e1e8b7` |
| `C0idsrvI23ZhnYJ` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `1e706434041e7eab5a7276e6db4b83df4f2978a0c80417e10bf1047f0804d800` |
| `m4dTsKSPDhgMXF1` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `d2cb25c824dfd22d69391b0cbcb0a5c02c17cfc875b36fe906607ad24fad2b08` |
| `gksmmxZvCbW6hoM` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `97087caa23a8490ce24fa4361eb9b5829e0d6304a01588b616fa0428123e21df` |
| `oPAJypwAdyQOLsY` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `d7b5db4ac0ee5bc73c4c1073aa15e584d0ed0a2edeafe517f9ea084a334adfba` |
| `QERc5IzGbsmsA1O` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `edbe47e86c0bd6bdd5a044301d508309d830629fc4b3b04f13f37c5eb915a090` |
| `S1Kgu0eEeFsi2xi` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `d8eb6a2ee88067a0f317606bbfe88a4049f8823c777e0afeaf6f7802de215d55` |
| `WegQQONiGzHVXF4` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `e9661d294d172a4a1fabfd13ade3e2d74de0cac303be0ab0d2dcbc4198cfdef1` |
| `87epY9nuIU1S0rK` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `f33844125b4fc377b3e371125f505f83373874619c246860013eb0a75a6b33a9` |
| `3haDjO0KC2faZvf` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `84db9ee45d2f4308c613006e624cb256adc25a98b6573dc8538e87aef90f9cc4` |
| `Lk1JTblSyoQV7QW` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `41df2eaba32bebd05bef257d8bd42faf1b6ca2fd4a7aac6182c88484e805893d` |
| `5kgEdgFHNcChvjF` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `0a4acb95d421da18d19ef8b0ea1f971de14fb46b80597bd0ff4ce835718df839` |
| `X6alnGwZo1UjN5U` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `f288d0bb9d3c1725962c7e9665401fc54426c58a5889f4d0b109cbc1935d0cc2` |
| `xPabzqISgAvUPTR` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `de9fc256784d68bbc76e8344482d50bb81009a9d7215fbc9c92ce75d2410be25` |
| `w2t3Xh878WMQely` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `3e6454ebdd0d0816d017c6ea168ead40e79da0c6cd283d090d7d203d089463fa` |

### Original skip bindings

| Module ID | Test | Reason | Raw log SHA-256 |
|---|---|---|---|
| `F7PgNT94TNZAZL2` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `a65cabd7018f0cf0e684c78fc850f2bd2bbafba890934ee25e3cd9eaa58824f5` |
| `sAYx3EktmJgzaLW` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `f3cc0955a30d35020f17b37bcbbad432c3a1cadfbe497d5756e5fa0825b503ba` |
| `omBAGEJlPMAlRzd` | oidcc-idtoken-unsigned | Unadvertised none algorithm | `beeec7ceb8dd5369c92d67d2a4416721b2ebb375f05011e86840baef5159854f` |
| `aiR6feNHkr8qswT` | oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `cd7c86ce1cd8112e0d2d693aa8750e56142810a5e151e36cdcd531d58bdc80d6` |
| `1fY6P5VnDGDQ5Co` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `b908fe6341a919fa40dbc268e0b548cb0875d0090a012c2fb6c259e7639d1739` |
| `c3IErfMfiYjKOXT` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `b2c08e554013418b19fe225ffe0ab402390de1d789026eae8aa67921d561774f` |
| `IcpiE4rH1BIx0zF` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `893b8b3d4fcefe0adf40c107da4cdcc11e55442b75daf98db6460e1b0e6805b1` |
| `Vtber9wKAiJbDL1` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `a1325a70f3e6932c145e64f68ca55180d47e609680564db54ac519341f55cdfd` |
| `f5kV22RQLg30IcC` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected plain | `9129f50184fa2cba9b352c526d90dc38e84507e79b656061905f3338f9db6ca9` |
| `ADBjOHe7x7HmJWI` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected plain | `f96df85e7742d3b9db47efe5b56930500bd308e9ed40676696c7a0ecb4eceb78` |
| `BvVEPSjiCH2LpBg` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected plain | `376c8be5993f82e24b4d29ea55ef0a97e5b68551d7e976228439adef926cb99d` |
