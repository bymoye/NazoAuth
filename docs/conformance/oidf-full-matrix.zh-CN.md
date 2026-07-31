# OIDF 完整矩阵

本文说明仓库维护的 OpenID Foundation Conformance Suite 完整矩阵。矩阵包含 27 个 plan；针对 TP/PS 的新增检查应映射到这些 plan 的覆盖范围，而不是另开一个临时矩阵。

执行入口为 `runtime/oidf/oidf-plan-set.json`。`scripts/prepare_oidf_black_box.py` 会同时生成 `runtime/oidf/oidf-plan-set-manifest.json`，用于记录每个 plan 的标题、描述和覆盖重点。

在 `parallel-isolated` 模式下，27 个 plan 按有界公网套件批次执行：OIDC core（`2`）、OIDC Form Post / Third-Party Initiated Login / Config（`3`）、FAPI-CIBA（`4`，`--no-parallel`）、FAPI message-signing 与 mTLS/DPoP（`5`）、其余三个 FAPI 分组（各 `3`），以及 RP-Initiated Logout、Back-Channel Logout、Front-Channel Logout、Session Management 四个独立浏览器 job。这样保留完整矩阵覆盖，同时避免 suite runner 的回调状态和浏览器会话状态互相争用。

最新的操作者与官方套件持久证据仍是此前的 25-plan 基线：
[`2026-07-20-final-automated-oidf-results.zh-CN.md`](2026-07-20-final-automated-oidf-results.zh-CN.md)。
该证据早于 RP-Initiated 与 Back-Channel 两个独立 job，不能作为 27-plan 已通过的证据。

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
| 18 | OIDC RP-Initiated Logout OP | 验证 GET 与 form POST、`id_token_hint`/`client_id` 绑定、精确回跳匹配、state 连续性、无效输入，以及请求无法绑定当前 OP 会话时的显式用户确认。 |
| 19 | OIDC Back-Channel Logout OP | 验证已签名且显式类型化的 Logout Token、必需 claims、`sid`/`sub` 会话绑定、form 编码 RP callback 投递与响应处理。 |
| 20 | OIDC Front-Channel Logout OP | 验证 OP discovery 中 front-channel logout metadata、RP-initiated logout、前通道 iframe 通知、`iss`/`sid` 参数和 `post_logout_redirect_uri`。 |
| 21 | OIDC Session Management OP | 验证 `check_session_iframe` metadata、授权响应 `session_state`、父页面注册 Origin 强制，以及 RP-initiated logout 后的会话状态变化。 |
| 22 | FAPI-CIBA ID1 / private_key_jwt / poll / plain FAPI | 验证 FAPI-CIBA AS discovery、backchannel authentication endpoint、`private_key_jwt` 客户端认证、poll token exchange、错误处理、refresh token 和资源访问。 |
| 23 | FAPI-CIBA ID1 / mTLS / poll / plain FAPI | 验证 mTLS 客户端认证和证书绑定的 poll token 签发。 |
| 24 | FAPI-CIBA ID1 / private_key_jwt / ping / plain FAPI | 验证带 Bearer 鉴权、TLS 1.2 FAPI 基线并支持 TLS 1.3 的 ping 通知、token endpoint 取令牌、拒绝重定向和 401 终态处理。 |
| 25 | FAPI-CIBA ID1 / mTLS / ping / plain FAPI | 验证相同的 TLS 1.2 最低版本、支持 TLS 1.3 的 ping 生命周期与 mTLS 客户端认证、持有者绑定令牌的组合。 |
| 26 | OIDC Form Post OP | 通过浏览器流程验证成功与错误授权响应的 `response_mode=form_post`。 |
| 27 | OIDC Third-Party Initiated Login OP | 验证 `initiate_login_uri` 动态注册回读，以及非 HTTPS 元数据拒绝。 |

## TP/PS 覆盖边界

本矩阵中与当前 TP/PS 工作直接相关的覆盖点包括：

- `OIDC Basic OP Dynamic Registration` 覆盖 RFC 7591 动态客户端注册和 `registration_endpoint` metadata。
- OpenID Connect RP Metadata Choices 1.0 在 workflow 锁定的 suite revision
  `dee9a25160e789f0f80517674693ef7989ab9fa1` 与官方 `master`
  [`daf33d61b982d5d33d134b07e9a36f76176b3eff`](https://gitlab.com/openid/conformance-suite/-/commit/daf33d61b982d5d33d134b07e9a36f76176b3eff)
  中都没有专项模块。Dynamic Registration plan 会测试相关单值元数据，但
  不会提交 19 个 `*_values_supported` choices、验证交集选择，也不会检查
  注册/读取响应不得回显 choices 数组。因此当前规范证据来自仓库 DCR
  tests；OIDF 发布官方 plan 后必须把它加入矩阵。
- 远程 `jwks_uri`、精确注册的外部 `request_uri`、签名 Request Object、签名 UserInfo 和展示元数据等动态注册扩展仍按现有安全边界实现；这些能力不构成 OIDF Dynamic OP 认证档案的支持声明。
- `OIDC Form Post OP` 覆盖安全 HTML form-post 响应及浏览器提交。
- `OIDC Third-Party Initiated Login OP` 覆盖 `initiate_login_uri` 注册元数据；该 OP profile 不新增 OP 侧发起端点。
- `OIDC Config OP` 覆盖 metadata truth，防止 discovery 暴露未实现能力。
- FAPI2 Security 和 Message Signing plans 覆盖 PAR 强制、`request_uri` 过期、`request_uri` 重用、跨客户端 `request_uri` 使用、外层授权请求参数、PKCE、redirect URI、audience 和 client assertion。
- `private_key_jwt / DPoP / OpenID Connect / authorization code` 是 TP/PS 改动面的主要单 plan；完整回归以 27-plan 矩阵为准。
- `OIDC RP-Initiated Logout OP` 与 `OIDC Back-Channel Logout OP` 提供独立认证证据，不再从其他 Logout Profile 的结果推断其正确性。
- `OIDC Front-Channel Logout OP` 覆盖 NI-008。
- `OIDC Session Management OP` 覆盖 NI-009。
- 四个 FAPI-CIBA plans 覆盖 `private_key_jwt / mTLS` × `poll / ping` 的正交组合。[FAPI-CIBA profile](https://openid.net/specs/openid-financial-api-ciba.html) 只支持 poll 与 ping，因此 push mode 不属于受支持的 FAPI-CIBA profile，并且永不支持。
- NI-006 未发现 RFC 7523 third-party JWT bearer grant 专项官方 plan；现有覆盖来自 OIDC/FAPI 中的 client assertion 场景和仓库 RFC 7523 tests。
- NI-010 跟踪 [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) 与 [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)。这两份规范定义的是包含 Entity Statement、Trust Anchor、metadata policy、Trust Mark 和 Federation endpoints 的 federation trust-chain 生态。Federation 当前是**不支持（待实现）**：不宣告、没有 `/.well-known/openid-federation`，在独立 trust-chain 实现完成前，Federation plans 不纳入必跑矩阵。
- NI-011 未发现 Native SSO / `device_secret` 官方 OP plan；保留仓库级 device-secret lifecycle、`ds_hash` 绑定、token exchange 与 refresh-family tests。

因此，临时 targeted plan-set 只适合开发期间快速定位问题；正式回归和证据记录应引用 27-plan 完整矩阵。

## 明确的“永不支持”边界

OIDF `oidcc-dynamic-certification-test-plan` 明确为**永不支持**，不得出现在生成、诊断或官方的 plan set 中。官方套件的 dynamic profile discovery 检查要求同时支持 `code`、`id_token`、`token id_token` 三种 response type，以及 `authorization_code`、`implicit` 两种 grant type；证据见官方套件的 [`OIDCCCheckDiscEndpointResponseTypesSupportedDynamic`](https://gitlab.com/openid/conformance-suite/-/blob/v5.2.0/src/main/java/net/openid/conformance/condition/client/OIDCCCheckDiscEndpointResponseTypesSupportedDynamic.java) 和 [`OIDCCCheckDiscEndpointGrantTypesSupportedDynamic`](https://gitlab.com/openid/conformance-suite/-/blob/v5.2.0/src/main/java/net/openid/conformance/condition/client/OIDCCCheckDiscEndpointGrantTypesSupportedDynamic.java)。

实现该认证档案意味着声明并启用 implicit response；RFC 9700 第 2.1.2 节要求授权服务器 SHOULD NOT 支持 implicit grant。因此交互流程保持为 authorization code，并保持 discovery 如实声明。RFC 7591 动态客户端注册仍完整实现并由 `OIDC Basic OP Dynamic Registration` 覆盖；“动态注册”不等于旧的 OIDF “Dynamic OP”认证档案。

## Expected Skip 策略

当前官方 workflow 在 Basic OP 静态、动态注册与 Form Post 配置中明确允许 8 条 expected-skip 记录：

- `oidcc-idtoken-unsigned`
- `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported`
- `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
- `oidcc-ensure-request-object-with-redirect-uri`

这些跳过项对应当前有意不支持的 unsigned 兼容能力：服务不声明 unsigned ID Token
和 unsigned Request Object。最后一个模块的名称比实际前置条件更宽；OIDF suite
v5.2.0 在 `request_object_signing_alg_values_supported` 不含 `none` 时会跳过它。
带 `redirect_uri` 的签名 Request Object 仍由 FAPI/JAR plans 验证。包含这些
expected skips 的 workflow run 可以作为 `0 failures`、`0 warnings` 的证据，
但不能作为 zero-SKIPPED 证据。

## Expected Review 策略

RP-Initiated Logout OP plan 恰有 8 个模块因正式认证要求上传 OP 错误页或用户确认页
截图而返回 `REVIEW`。runner allowlist 同时绑定 RP-Initiated 配置、精确 plan 名和精确
module 名，并限制每个模块最多出现一次。这些结果不是 skip：确认/错误页面证据仍必须
经过人工复核并进入正式提交材料；任何额外 `REVIEW` 都会使运行失败。

## Expected Warning 策略

当前矩阵包含 26 条有界 expected warning：
[`oidf-official-expected-warnings.json`](../../tests/contracts/oidf-official-expected-warnings.json)。
每条记录都绑定精确的 FAPI-CIBA ping 配置、完整 variant、模块、block、condition
和 result。唯一允许的 condition 是官方套件公网 CIBA ping 回调入口上的
`EnsureIncomingTls13`；对应的 TLS 1.2 安全套件检查仍通过，实现本身也单独证明
支持 TLS 1.3 客户端能力，同时保留 FAPI-CIBA 的 TLS 1.2 基线。出现额外 warning
或缺少预期记录都会让 workflow 失败。
