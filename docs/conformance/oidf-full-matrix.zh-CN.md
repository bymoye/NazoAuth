# OIDF 完整矩阵

本文说明仓库维护的 OpenID Foundation Conformance Suite 完整矩阵。矩阵包含 21 个 plan；针对 TP/PS 的新增检查应映射到这些 plan 的覆盖范围，而不是另开一个临时矩阵。

执行入口仍然是 `runtime/oidf/oidf-plan-set.json`。`scripts/setup_local_oidf_podman.py` 会同时生成 `runtime/oidf/oidf-plan-set-manifest.json`，用于记录每个 plan 的标题、描述和覆盖重点。

## Plan 目录

| # | 标题 | 描述 |
| --- | --- | --- |
| 1 | OIDC Basic OP | 验证 public issuer 的 discovery、静态客户端注册和 OIDC 授权码互操作，包括 ID Token、UserInfo 和常见登录参数。 |
| 2 | OIDC Basic OP Dynamic Registration | 验证 RFC 7591 动态客户端注册、`registration_endpoint` metadata，以及动态注册后的 OIDC 授权码互操作。 |
| 3 | OIDC Config OP | 验证 provider metadata 是否真实反映当前实现，避免声明未实现的 endpoint、算法或会话能力。 |
| 4 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / JARM | 使用 `private_key_jwt` 客户端认证和 DPoP sender constraint，验证签名 Request Object、PAR、JAR/JARM、PKCE、授权码重放和 OpenID Connect 响应。 |
| 5 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / plain response | 与 JARM 计划相同的签名请求边界，但授权响应保持普通 code response，用于区分 message-signing 请求侧和响应侧行为。 |
| 6 | FAPI2 Security / mTLS client auth / DPoP / OpenID Connect / authorization code | 使用 mTLS 做客户端认证、DPoP 绑定访问令牌，验证 OIDC 授权码流程中的 PAR、PKCE、授权码重放、刷新令牌和 discovery。 |
| 7 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / client credentials | 使用 mTLS 客户端认证和 DPoP 绑定访问令牌，验证 client credentials grant、audience、token endpoint 和资源访问约束。 |
| 8 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / authorization code | 使用 mTLS 客户端认证和 DPoP sender constraint，验证非 OIDC 授权码流程的 PAR、PKCE、授权码重放和资源访问。 |
| 9 | FAPI2 Security / mTLS client auth / mTLS sender / OpenID Connect / authorization code | 同时覆盖 mTLS 客户端认证和 mTLS sender-constrained token，验证 OIDC 授权码流程及 holder-bound 访问令牌。 |
| 10 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / client credentials | 使用 mTLS 作为客户端认证和 sender constraint，验证 client credentials grant 的证书绑定和资源访问。 |
| 11 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / authorization code | 使用 mTLS 作为客户端认证和 sender constraint，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码和资源访问边界。 |
| 12 | FAPI2 Security / private_key_jwt / DPoP / OpenID Connect / authorization code | 使用 `private_key_jwt` 客户端认证和 DPoP sender constraint，验证 OIDC 授权码流程，是 PAR `request_uri`、外层参数和刷新令牌行为的主要回归 plan。 |
| 13 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / client credentials | 使用 `private_key_jwt` 和 DPoP，验证 client credentials grant 的 token endpoint、audience 和资源访问约束。 |
| 14 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / authorization code | 使用 `private_key_jwt` 和 DPoP，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码重放和资源访问。 |
| 15 | FAPI2 Security / private_key_jwt / mTLS sender / OpenID Connect / authorization code | 使用 `private_key_jwt` 客户端认证和 mTLS sender-constrained token，验证 OIDC 授权码流程及证书绑定资源访问。 |
| 16 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / client credentials | 使用 `private_key_jwt` 客户端认证和 mTLS sender constraint，验证 client credentials grant 的证书绑定 token 和资源访问。 |
| 17 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / authorization code | 使用 `private_key_jwt` 客户端认证和 mTLS sender constraint，验证非 OIDC 授权码流程中的 PAR、PKCE、授权码重放和资源访问。 |
| 18 | OIDC Front-Channel Logout OP | 验证 OP discovery 中 front-channel logout metadata、RP-initiated logout、前通道 iframe 通知、`iss`/`sid` 参数和 `post_logout_redirect_uri`。 |
| 19 | OIDC Session Management OP | 验证 `check_session_iframe` metadata、授权响应 `session_state`、RP-initiated logout 后的会话状态变化。 |
| 20 | FAPI-CIBA ID1 / private_key_jwt / poll / plain FAPI | 验证 FAPI-CIBA AS discovery、backchannel authentication endpoint、`private_key_jwt` 客户端认证、poll token exchange、错误处理、refresh token 和资源访问。 |
| 21 | OIDC Dynamic Registration / Signed UserInfo | 只运行官方 `oidcc-userinfo-rs256` 模块，动态注册 `userinfo_signed_response_alg=RS256` 并验证签名 UserInfo 的序列化、content type 和 claims；不声明旧版 dynamic certification profile 所需的 implicit flow。 |

## TP/PS 覆盖边界

本矩阵中与当前 TP/PS 工作直接相关的覆盖点包括：

- `OIDC Basic OP Dynamic Registration` 覆盖 RFC 7591 动态客户端注册和 `registration_endpoint` metadata。
- `OIDC Dynamic Registration / Signed UserInfo` 只选择官方 OP 侧 `oidcc-userinfo-rs256` 模块。完整的旧版 dynamic-certification plan 还要求 implicit flow，而本项目有意不实现也不声明该能力。suite snapshot `f326f6aa25d6a2b8f1ae30a6ec80a57e342333ce` 没有 encrypted UserInfo 或 encrypted JARM 的 OP 模块，因此这两项仍以本地负向测试为事实源。
- `OIDC Config OP` 覆盖 metadata truth，防止 discovery 暴露未实现能力。
- FAPI2 Security 和 Message Signing plans 覆盖 PAR 强制、`request_uri` 过期、`request_uri` 重用、跨客户端 `request_uri` 使用、外层授权请求参数、PKCE、redirect URI、audience 和 client assertion。
- `private_key_jwt / DPoP / OpenID Connect / authorization code` 是 TP/PS 改动面的主要单 plan；完整回归以 21-plan 矩阵为准。
- `OIDC Front-Channel Logout OP` 覆盖 NI-008。
- `OIDC Session Management OP` 覆盖 NI-009。
- `FAPI-CIBA ID1 / private_key_jwt / poll / plain FAPI` 覆盖 NI-007 的 FAPI-CIBA AS 面。
- NI-006 未发现 RFC 7523 third-party JWT bearer grant 专项官方 plan；现有覆盖来自 OIDC/FAPI 中的 client assertion 场景和本地 RFC 7523 tests。
- NI-010 跟踪 OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1。本项目当前不实现该 trust-chain 生态能力，且已不暴露 `/.well-known/openid-federation`，因此 Federation plans 不纳入必跑矩阵。
- NI-011 未发现 Native SSO / `device_secret` 官方 OP plan；保留本地 device-secret lifecycle、`ds_hash` 绑定、token exchange 与 refresh-family tests。

因此，临时 targeted plan-set 只适合开发期间快速定位问题；正式回归和证据记录应引用 21-plan 完整矩阵。

## Expected Skip 策略

当前官方 workflow 在通用 OIDC dynamic-registration plan 中允许 2 个
expected skips：

- `oidcc-idtoken-unsigned`
- `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`

这些跳过项对应当前有意不支持的可选兼容能力：服务不声明 unsigned ID Token，
也未启用 OIDC `request_uri` 参数。包含这些 expected skips 的 workflow run
可以作为 `0 failures`、`0 warnings` 的证据，但不能作为 zero-SKIPPED 证据。
