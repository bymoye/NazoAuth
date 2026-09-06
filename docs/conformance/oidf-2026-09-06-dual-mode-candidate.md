# OIDF and transport acceptance: Hostinger candidate, 2026-09-06

Status: candidate engineering acceptance complete. Distributed Release acceptance, final CI and issue closure remain pending.

Server SHA-256: `b59be9638241f46b5dfbd1c9904a7d6e014ba781757e891974569e128c74464e`.
Controller SHA-256: `10832978b3b36c120142325230d147ea3f2ee51ab7c9554094ae42338cc8b97e`.
These are the binaries actually used; release version metadata is not substituted for their identity.

| Mode | Instantiated / terminal | PASSED | REVIEW | SKIPPED | Failed / warning / incomplete | Cleanup |
|---|---:|---:|---:|---:|---:|---|
| Direct TLS, matrix-direct-v4 | 1198 / 1198 | 1145 | 42 | 11 | 0 / 0 / 0 | complete |
| Trusted proxy, matrix-proxy-v5 | 1198 / 1198 | 1145 | 42 | 11 | 0 / 0 / 0 | complete |

All 84 REVIEW records were individually examined. Each mode has 25 actual VP PNGs, 14 HTML response snapshots and three JSON response snapshots. All 50 PNGs were opened and visually reviewed. The logout confirmation branches and all 22 raw SKIPPED explanations were also reviewed. Original Suite classifications remain unchanged.

Both modes passed fresh tenant-boundary requests, controller-absent protocol requests, and protocol requests after certificate transactions. Temporary tenants and clients were removed through ordinary APIs. Public certificate evidence covers import/bootstrap, real ACME initial issuance and renewal with key rotation, deadline and mismatch rejection, reload failure, public endpoint failure, forced controller termination, fencing and ordinary recovery. The native proxy transaction additionally exercised invalid native syntax and rollback failure followed by recovery. Four real certificates were issued across the two modes. Historical harness failures and corrected resumptions are retained.

Shared Angie configuration was restored: the 13 original configuration hashes match their baseline, the two task-owned shared ingress configurations were retired, native validation succeeded, existing site responses remained within observed baseline, and production `auth.nazo.run/health` returned 200 through IPv4 and IPv6.

The two raw manifests were checked against 2396 original module log files and 50 PNGs, then signed with a task-owned Ed25519 key. The signed index covers 27 exported evidence files. The private key is excluded from the archive.

- Archive: `candidate-acceptance-signed-v5.tar.gz`
- Archive SHA-256: `f64f530dd1f0b98f559be09dc0d68a37687e197d26045366c28d8c9d5568a5b8`
- Index SHA-256: `8c5cc7243fc9f7811b886c566b0d2487a7e1a2ed78e34627808f847c6dca7c28`
- Verification key SHA-256: `c3f408729e22ca93d9c95c246711e96a58e27ecceeeb54534235457218ad1b8e`

The matrix digest is `877f669e6d5f57fd5f8c6a4237910ff1a85462a44374fe18e8f20ddbfae95769`. Every raw module reports Suite `info.version = 5.2.4`. The bundled artifact's 5.2.2 revision and image digest describe its declared reference build, not independently attested runtime identity of the external Suite service. No remote running image digest is claimed.

The signature is engineering evidence provenance, not OIDF certification or a runtime-signed VP result. The first-generation closed-port rollback case retains its earlier isolated native-listener proof. Full candidate tests, focused tests, CI, published artifact verification and public black-box results remain distinct evidence categories.

Final cleanup of task-owned deployment services and validation fixtures will follow distributed Release verification; private evidence and failed recovery journals are retained. No unrelated deployment or workload is included in that cleanup.

## Evidence ownership and black-box boundary

This Markdown record belongs to NazoAuth and is retained with its source. The
OIDF Suite and ctl exercised public production protocol and ordinary administration
interfaces. They are external test clients; this evidence adds no Suite-specific
runtime route, database field, configuration or authentication behavior.

The archive and private raw manifests are retained by the acceptance operator
under the task record `nazoauth-130-acceptance-20260906`. The repository keeps this
redacted Markdown record and cryptographic identities; raw logs can include
short-lived authentication material and are not committed. The task signature
establishes integrity for this evidence set, not third-party certification.

## Manual review decision

Engineering semantic review satisfied for both final runs. Per mode:

- Six prompt-login/max-age responses contain the second login page with email,
  password and submit controls.
- Three unregistered redirect requests retain `invalid_request` and the specific
  unregistered redirect explanation.
- Eight logout records retain a local signed-out page. Seven invalid/missing-hint,
  invalid-redirect, no-parameter and state-only cases retain a confirmation page
  and confirmation click. A valid-hint/no-post-logout-redirect request succeeds
  directly. This is an explicit local logout confirmation flow; the record does
  not mislabel it as the generic error page suggested by some Suite prompts.
- Twenty-five actual VP PNGs were individually opened. They display
  `Presentation verified` and a successful verification message. Nine are mdoc
  `iso_mdl` positive cases covering x509_san_dns/plain, x509_hash/plain and
  x509_hash/HAIP. The earlier candidate's signer/MSO validity failure did not recur.
- Eight skips concern the unadvertised `none` algorithm. Three VCI skips require
  the encrypted variant while the selected variant is plain. These stay SKIPPED;
  no defined module was removed from either run.

The 17 OIDC/logout records per mode are HTML/JSON response snapshots, not browser
screenshots. The 25 VP records per mode are live WebDriver PNGs, not runtime-signed
VP receipts. Identical rendered images do not replace individual module binding.

## Signed evidence verification

Verification key, SHA-256
`c3f408729e22ca93d9c95c246711e96a58e27ecceeeb54534235457218ad1b8e`:

```pem
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlRkaBe3T9ql+R0J4xMymzX+mjKO49k4ivpswPMs9Gxs=
-----END PUBLIC KEY-----
```

Detached Ed25519 signature of the exact archived `index.json`, base64:

```text
UCVVaaVhBNxLSa73JdJ72g21epR9qgK1BIr/cbQKAoiUzAT4DkxpD1BjzJ3euxSgczlGkhMyTLjWQlcCUnJxCQ==
```

After obtaining the archive from the acceptance operator, check its SHA-256,
then follow `VERIFY.txt`: verify the index signature, every listed file's SHA-256
and size, and each private raw manifest signature before its module/PNG hashes.
The archive does not contain the private signing key.

## direct-v4 review bindings

Run JTI: `01a07532-7418-75f1-8b05-c0479b795b8d`.

Report SHA-256: `d94914f796dfb02c8263b13e54ffe668a9f9e8ecf48b9ec1dffc458b857b5d9f`.

Raw manifest SHA-256: `30eb6d8a6e973e00693d165807edcd04f64fd15f182bd720f9c671151be5cdfa`.

Each row remains REVIEW. The raw log digest binds the response or PNG to its
original module and complete variant.

| Module ID | Test | Variant | Evidence kind | Raw log SHA-256 |
|---|---|---|---|---|
| `svtQzZv9QRkabYr` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `93dd69b322a583c7d3e237f891bcc34221b46bb97189b2c1ae1adbad76d957cf` |
| `8ZK25u35FPHMNy6` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `eb8870d3ba13a6eebb3d04c12a95136cc43a4701a150ee75a3f4100110d08ea9` |
| `gs8N0OfPo45e1e7` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `3e88d9a8b6067d9069b12c4e9ea1d12d2ec6fdae69ce9c1665ffbd291c1b0d2e` |
| `2nEfupgP5D3Yb64` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `914c9dcfaacefe217b4289bdffa9bc5828254ff6807c96ce5e4df0f69d8da199` |
| `j5zgMQdNrOWZDYu` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `4254b8feafa82cfa462309342442206717673bd4364ecd0040c6ddd077f3b219` |
| `S0rzCOoI084TYsX` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `721bb20ff3cc9d42c8f7e296abaeabaeafafcb9f38a21e950de3f6f93ce91f0f` |
| `prEgHo7Vs2Ii8LQ` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `b6f9030ad6699d303777291c0cc57ca854211259fe93eb5326484608b0fa84d5` |
| `4IaaZquMSnpRKRf` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `80498c6e2a8e7fea7935cdb12a7ee3c4b938caafe7c38f7fb73a4631b9414860` |
| `UWXCMbjQEnWNVEz` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `c28394f3845b623fd1645927a1b97dad420b98c12ddc7d33c8a036ea3585a8c5` |
| `95RLRlm5mHgKApI` | oidcc-rp-initiated-logout-bad-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `f439e94e6ca0b3465455e69dd3645e3bc047411295f219215d251b933644f729` |
| `6poTsIpSamZZNXo` | oidcc-rp-initiated-logout-modified-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `9aaa060ac059bc58dbb564f43736872f35eb7b8a34b72e6fef1858a153374548` |
| `o93f0VN5HkVnuzg` | oidcc-rp-initiated-logout-no-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `b3388b81f2026963906414b002bf8b67455fe35426eb39e43abcf59aa7af8791` |
| `6CgEeVyavNZvMBQ` | oidcc-rp-initiated-logout-no-params | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `59001e557094458be86219676cf1b82057d52dd0c7934cf78633adf7256b9f26` |
| `iETIeOCox39IyJX` | oidcc-rp-initiated-logout-no-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `39a562ff7e57aa2836505b2f39f3cf47c365f3c5f3c6e48eeb68af8d52affa02` |
| `ajZbxnGKZuKeYxK` | oidcc-rp-initiated-logout-only-state | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `b7a0f5d5e79ae5601c2ecc0c0945f8d442f7dbc066fa74646a35cee1a72fbce7` |
| `SnXYAyD9fBsh4AD` | oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `8584f33694f52cbd0ae751bfe39f675c86f06546de129399ef1f92ba90d6c3fb` |
| `8fNVTPlH1GMIqtO` | oidcc-rp-initiated-logout-bad-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `7aeb21f4b0c3fe6d7e756c27c6c2ddd064c853c2d79a928e3ed5910816294611` |
| `ew1T9QG9a0KWhar` | oid4vp-1final-verifier-happy-flow | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `78f600621783633b9d373f3046ae9a6ebc277d984c10b002177cfba6f5ef9a96` |
| `m8JUn4YxMHeUPQH` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `eb7a7dbf068f40528eca115c1fc6a51de3dde541b710350403e7fecc8af9d86a` |
| `aALT3s4NcD3rsam` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `69afdead7f10028e131b9a4d096e1fb682dd2826c20417983a93d7aa4c7fbd14` |
| `HuuIBA6cyI18UkA` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `a96583f0265c0c1d7c13d9ed4d9c1ee5d38952d392ebf84cc704910d996b8df6` |
| `YWP61KidB4dmX5r` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `db570dbbadb0ab94f9a4dc96326d5087ebf0eb1c33028451c5a48fd9dfc4fd1b` |
| `ZgTBliWVvjb5Wnr` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `498952e7fd17efdd3d1a6f0a7caa651cac227d93ec3cbf905e725e049986e1d6` |
| `qNm2sYllZ9V1xwu` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `dd63c571c8612daa1adcf7cc7a8312bee8e33001a4a7b74d9c6fa258d7c15f52` |
| `0YD2tg12KFZJyJH` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `646207326c248df532dd2c164e3151926c46834495c1664e684919e22d17abcc` |
| `kX63iHr8ueslcBQ` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `f776718bb6c889e81ae5e67c3586707b79e3b447054c68bf4ebd8380dd9bc4d7` |
| `NUTwnwxdUJyb7c5` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `3e8dbe0c5b07621c2a66b3028136cc862fa5c6b94ae808c5143473590acecde2` |
| `LjMgwmzqaaEII2r` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `0da510f5f1ed545a6573ad1c42d42910bd9a343374dd4755c6afc4c12eb419a1` |
| `cXPwwUKrlDGIgfn` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `6019bb17ff3092bb98b06f3daa112a8140479609417a4088775cf3247ff275ae` |
| `UVB1gWLg2ewO4uq` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `5288ad2f5ba9a85ecc73fc4b7064992bab4377bc884147d2164acc8295b3c533` |
| `2oV5Rn9X8OMoX3u` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `39952e502648a8e400457f73ce190905b4996cc4e70c54ab44796c2b21a95ff6` |
| `YEXIFRbzxcX2AkS` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `85f41f7238c584094ac237595eebb359bf03abdce2146b4e2eda4541bf2c1879` |
| `6WSJCGIijFh87d4` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `f4a54c212b43a748d5324fe80d20a3cde0360229fd11562b5c07d99cce50269e` |
| `bFDHniYBc8f1vID` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `e5de01bcf40ab81dfe97d92f93dd32e0b375186efc3a2cbd85017cca1a948ba7` |
| `9FdPgHwczqK1jSd` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `b9e263aa6b8b698723db40d9f9d2d181e92aefd60e60b88ca32512078368fd0f` |
| `H2UQC3VrdQ9G8G2` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `8d7142a87f90c70b1f714858434ddb71cf0e9a09a5ff578b7654512f5f729fe8` |
| `Y6W9DcySG2yjDDw` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `5b6d64173a2b0735c1c6356d39fd699a761d9ad51160981bc99ded2c0a372b6b` |
| `XLBxXXsPQnO8U7q` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `1f04da088cf1093d8790ce6f7ddbdb42a1d51b556ebb2634fdab9987dfd4a83c` |
| `hVKDiFerK2Kf6if` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `e806b04c29b87fe4384826c01d5eca1dd5f004f5230914a8cdcd127915ea03e0` |
| `G6x03zQpJDR08nu` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `837c90705b856a8ef67385fb82071af8ebd058f61fe2e35448777efbf3964fc0` |
| `GmEyfZ8Pg9XaZaS` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `260d6eaea3e931108f5a19e6a234e68194fb61da82daa20b94b9d100996a48d6` |
| `BcJWhl47fT9PyHH` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `eeddad2184551e05a30de43a0633338d1920abb5266673602af84907a50d4316` |

### Original skip bindings

| Module ID | Test | Reason | Raw log SHA-256 |
|---|---|---|---|
| `XlmWDF1s6BSnUM4` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `3f549664bfa8359fabf1eae2a6e9fcacabf79b48310faf3033454f440c9be82f` |
| `8DWoN1PWSkzJt62` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `1bc3bd702b07886112588ade54332a7e039958f8d610c88aa7a5e3f53d8c0327` |
| `92x5g9ZIw02xqXr` | oidcc-idtoken-unsigned | Unadvertised none algorithm | `340edb97b638346353ffba6297d7758a5dcec11081cddd2db8bf0464dcc9e04d` |
| `Shy7dDHM5ewbqKG` | oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `fb328f0f1fa3d2fa470c75a5c2633900d7d27eae1aba1872a1a1dafd5af5a87c` |
| `lRfb7ndD8VduMGf` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `502c99903d10acd6ed3aadd7417fc28ed74213774263d2e0f527975b04167b48` |
| `4tZIFi8nwgTK9lL` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `6732d3d094bced8f9b1a52448e79a1434037a83b5dae9ff3b8e76cdbfffb186b` |
| `SuOLAOXl0lU6u11` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `8744315066a5ea7242f168b75276b9a8b9fea954dc51503cf98c44b8086f6f17` |
| `J1l6YBUU2BSTdSh` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `f87fb515eda5af933280b62504d93b408805eb6357bebcecb9594883c9823469` |
| `wV4ugxpAtWPNu6W` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected variant plain | `adf60edaa98d87f054a4ce579e5d1c7447c42579ec6a8272112c66dd404f5d80` |
| `Q5Ml6EdeuiqpVyu` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected variant plain | `760939a34d5f792592d567866bd6fdc9c68b016b26a78c2cebd2b5542fd2fed8` |
| `KjamUtqD5LNzvdq` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected variant plain | `0b9efc8b9aebc35889930fc76744c4369133a99f09b69d12ed033b5828de5763` |

## proxy-v5 review bindings

Run JTI: `01a07553-b93b-70a2-9656-c95c632d9746`.

Report SHA-256: `9d2b81cf7f11b9e7fb60630d53ec13dbe7db969900d340a5b4e89ac67693ec89`.

Raw manifest SHA-256: `961f84bf5f43acdb8b14d31671206582f19cb89ce0b7266756f053ee6baa4a30`.

Each row remains REVIEW. The raw log digest binds the response or PNG to its
original module and complete variant.

| Module ID | Test | Variant | Evidence kind | Raw log SHA-256 |
|---|---|---|---|---|
| `flRyT2DEbrOv9AU` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `d9522bd072d9a498f5db06fa89c032aa1bd698551705b41b0c2d64590d9bec0d` |
| `5KIaXtDODsg0XA1` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `92cc6b77743916f707f4b37b2ed9f2dad4f264d89aeb615629c9c6123876ea99` |
| `iBBkH08GKFAXQjM` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `675a4d1a11323218a3c6c4a5083381ba95c4ef59fc00115e0272c643a181d2fc` |
| `zgVvgzPUz9QN1AH` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `6f8075a61f91e9e5c670cc4ba51e4f77180114f5810e2139e5b7b8f14a83acdd` |
| `NV4VyQ4HDcJuEBV` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `bc1bb1caf81f7fc27271258c4761b0d054e9920ba3eadaa40ddb58897286cda1` |
| `AhV403JCPkn4VYI` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=dynamic_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `ab0418d2eee5b1da7a1e37d12bd1b3d0d79c9603901aea860641b2f6f2476e79` |
| `eu4O4buL7Vjgh51` | oidcc-prompt-login | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `5bec57d47b45e9ec87bf511ea529a36b546203b7088233a71fa64be8b0df0dd5` |
| `ef0aiacfmqjUCGs` | oidcc-max-age-1 | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `793aa170d8857fca98c532e7a35a91942074724ccfc227e7360e15269ef5d097` |
| `hn48JzgPfNAPNL5` | oidcc-ensure-registered-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=form_post, response_type=code, server_metadata=discovery | HTML/JSON response | `51a63bc92049e03feae1cd170e9bae6a45e135c2d315021a6f8e14ab2bcb224a` |
| `kUH6CXtEm6svKOE` | oidcc-rp-initiated-logout-bad-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `4ac0355cbb8c4054ad7814fce091ec660390d04e1a4a04f5d8dcce77e432893d` |
| `Re4BW9EiaYbiYD6` | oidcc-rp-initiated-logout-modified-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `0be68fea0a46639de057ae50d51e00ec83b2c1b1dbb74235f85dd0636739d8b4` |
| `c6XMLLce7HhYWsg` | oidcc-rp-initiated-logout-no-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `97c8b47ae2cae1fb3325c54e069da96a5d734e26d60bc6e31f3094f269b4ed7c` |
| `rS7VNblWf4T9jAU` | oidcc-rp-initiated-logout-no-params | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `7970fc4ad83ac3b32cda5cd1ce512c5e1d66405e530bc9bd3aaa1cc9422de3d7` |
| `wKh2HwSIUa4zZO7` | oidcc-rp-initiated-logout-no-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `49910cae4e4b3d31276e6d7bbf19e668695dcb16147142a49fdadd01c29f3238` |
| `gFdT8MV6rgZ3rAG` | oidcc-rp-initiated-logout-only-state | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `2a2ecbf13aaf6bf256eb6f7370eb40e1dedece072615a539516b75a99fa6e50d` |
| `xeTxP3MjWw0Eo2w` | oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `72479a516a471562f16a1948fdd191e420bcc84e12bfd19bc9d11cdfa680ecdc` |
| `I5ZQMv74ib2zc4X` | oidcc-rp-initiated-logout-bad-id-token-hint | client_auth_type=client_secret_basic, client_registration=static_client, response_mode=default, response_type=code, server_metadata=discovery | HTML/JSON response | `1637b84baef5922883c6a733474bab3d8a9da90a58a45b3abcdde4a9db41c99a` |
| `yqcUPiXZ7kqaYoM` | oid4vp-1final-verifier-happy-flow | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `1803227a13ca8987e28a24986e7808b2d339f2d7daaa243672e752f7059e5ba0` |
| `vG9uYttrbxD403C` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `ea1baa724e5d7179d54cc69323e2d0e5dc20e3d8ae3ca526bd4ba3643ceb068e` |
| `gjLG4gh9IWkEGyi` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `99775e196c140a3b10ec2d66446118874af8e9f66803fe3d1565872d93436625` |
| `Zm6IrIb1IkOQ4Gg` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=redirect_uri, credential_format=sd_jwt_vc, request_method=url_query, response_mode=direct_post, vp_profile=plain_vp | PNG | `7a952f4eb758f119ee1bef8dcc82243290fd99e2654f73f8f9b2369f3d9a932a` |
| `UTXp10S6JEVDXZk` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `9b812ccb8e3b712c6b23e1ee19872b3c0fd277df56344a94c3bf1c11d6e571f7` |
| `t3rKcQc7MqpQe5Y` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `c9d0ea4e6ab057a1961b5e331cf8f835f501b07f976b9aac0ce01e308845b45d` |
| `6h5JdxvIbcYXw2F` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `40b6b014d0ef72994a7624f85ab882a6bbdfcbe9b31f6a0a54321666fd8ec5a6` |
| `Z6HLLPzz9nDJGTp` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `f404d69ee0d369bfbe583efb34b74d4e8b6350253575c5b56241c71a7d353796` |
| `OKlbTUXfo40yiW5` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `b288a7c9639ae5dd66c65b001e78c6f6968bec1400c4271ca76d2805864bd569` |
| `r06XYiIQXDuMc2h` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `ee07b2cf1c1dc22d99dae576a765c6cd5f0215d1aee8a9081129ccefbcfd86a8` |
| `m8dbhJV8AyDraij` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_san_dns, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `a6563a545b42a5a9dba3767faa6ff7f209037d5b9b2f565b10cb3b70093d44d3` |
| `b0yTtII3kgtNiev` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `304cbd7a249f6809967eae3ca5a821fc8908437b3708a084467caef7aacd9a37` |
| `dWWfB3RXkFhEm5P` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `b741b18c786ca40a063022e5a21bd6b06a1db2d1c1558f5aed16cfb88127f69a` |
| `PPhbweDAa6JD8nX` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `f91f2eb953366414f5e14adfdbef85cf5ee8b71fb1eeb91aa87c77963b63f381` |
| `o6yI8ZKdJ6Qap3u` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=plain_vp | PNG | `3764786ff523e56d8aca8f92b4e86c08d0e7405db7a2c4579607ff9e6821d6e8` |
| `G9f7TQKAD4MPPit` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `6559952967f8ba0d55b4bc6c821e5158e36d96b1574c2a74b4fecaef3f55a735` |
| `XObwZCKTPhZ2BXy` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `84c99b3ff9f8e262d505ecf06201084119a9a1139d0a05e76fa36d1ca9f0b554` |
| `sI6Ml8porLUM1TK` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post, vp_profile=plain_vp | PNG | `915ec74280aab9917c146ae7ab4ff52a7e5959c84ee4c622aa9720bd4c352399` |
| `RllkqZ6UfBfamjY` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `74330412199f227a2987be9a814387e06555cd31f64459f2a07fc591c2a2c2d7` |
| `dICq8Td7kvbZ0xg` | oid4vp-1final-verifier-minimal-cnf-jwk | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `5bfc68f6cd2b8403b06973a32052f11d364260c3e20e472ac874a69446431108` |
| `M9hgyUyEdtMLRWc` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `659d59bc0bb05fec8770ad2a044ff4b845b031195c1fdf2d222a2db54e31d35d` |
| `JnTEhBBAvjQ2Bzu` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=sd_jwt_vc, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `390fa42dce5bb25d078f297994839fc7161acb63fb4c1eea07723c2de853654c` |
| `pKxZtI40DLoFWrZ` | oid4vp-1final-verifier-happy-flow | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `d57018dbb265e21a545dc74b8fb9fcaef6e90b81b6118d2ec0ec1adee8c178f5` |
| `JPzKKpf5Ko0jaEb` | oid4vp-1final-verifier-request-uri-method-post | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `ab2c9914dc52308c525b4d6bc6dadbb3883f092cfd4e27a27bbb32975b5dda0a` |
| `0eUGrwnHzJLbqSx` | oid4vp-1final-verifier-request-uri-fetched-twice | client_id_prefix=x509_hash, credential_format=iso_mdl, request_method=request_uri_signed, response_mode=direct_post.jwt, vp_profile=haip | PNG | `25e8938f921f066f5542b4babd5d37915e7ebbc2eb2ea246f2c192a0bc6fddf7` |

### Original skip bindings

| Module ID | Test | Reason | Raw log SHA-256 |
|---|---|---|---|
| `5KTzZDlf68oTe4y` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `9dc52caa0ed166f593162cb99fe10a061ee6bc56f33275819501dbe4b06a3126` |
| `dnaJgb81z9h72BY` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `da2409de15eff226ca5fed9be40edf5257a2bcdc964b6b4fa9bd7800c5fc1eda` |
| `iewuweVbmt8a517` | oidcc-idtoken-unsigned | Unadvertised none algorithm | `895600668c4558f7931cc6b8f2279f2066a1d8129bd87afc2ed752c06b9944d7` |
| `9VCJb4EnXXHGXUB` | oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `67801f3a8fe72ea81c2d93987c1fa55da74f61afc64b6fc5c998a94aabe19822` |
| `DFzX8s9EX2ZpmrA` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `d724623e1e88f9ab930c61849cdc7acb7bc540a6ed013d55f90f46198881872f` |
| `LFJ8whXzJtL4iZa` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `0e608df90c95d2f85c127b9c819aac16b701b2edee721d8658c97679a015fc71` |
| `lf7d9yppxgwPF3B` | oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported | Unadvertised none algorithm | `b4aa6ffb0f087a96aeb2e44b7c5f53e31a9922ae62799617f05a104044e8ca08` |
| `AD9hoXdZWWgbQQM` | oidcc-ensure-request-object-with-redirect-uri | Unadvertised none algorithm | `a30cf77a9d8824bb7ac0ab672db7a848656c12711f258301ec216dfa53ac1798` |
| `HVxlMSJ54wUtaet` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected variant plain | `9d629713527eb968d2ebbbfc82a1e0e5bfc75853d5682c5cadcb98651ebea8de` |
| `Y7Yj6coB7mu4wxz` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected variant plain | `2b0ac6a20b1cf602a87558c90a224cb5b406411db34e13ffcf197dc7490b750b` |
| `9cOPozvUkTrAn1G` | oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm | Encrypted VCI required; selected variant plain | `ccf2f1cc0f84dcb02a88aa5fa575f4f0c45c515659027dc8e9f46cde7d20cc6e` |
