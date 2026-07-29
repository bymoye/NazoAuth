# OpenID Connect 集成

本文是 Relying Party 接入本 OpenID Connect Provider 的入口文档。它说明已实现的协议面、不支持的能力、以及会影响发现元数据的部署开关。

本文中的 `https://issuer.example` 只是占位符。每个部署和每次一致性测试都必须使用自己的公网 HTTPS issuer。

状态术语按字面理解：**完整支持**表示该能力已按所列角色/profile 实现，
并且只有满足启用条件时才会宣告；**永不支持**表示没有运行时开关、客户
端元数据字段或隐藏兼容路径可以启用该能力，未来若要加入必须先有新的
规范和安全证据，并显式推翻现有策略；**待最终 RFC/Final 审计**表示当前
实现已经覆盖对应草案或 Implementer's Draft 的主要行为，但不能宣称最终
规范一致性；**不支持（待实现）**表示该能力已
进入路线图，但当前不可执行、也不会宣告；**不支持**表示标准定义了该可
选值，但当前不宣告，也没有路线图承诺。所有情况下，discovery 与
registration metadata 都是可执行 allowlist。

## 规范与 Profile 支持

| 能力 | 状态 | 启用 / 宣告条件 | 规范依据 | 说明 |
| --- | --- | --- | --- | --- |
| OpenID Connect Core 1.0 | 完整支持 | OIDC 部署始终可用；交互式登录仅使用 Authorization Code | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token 会签名并绑定客户端。 |
| OpenID Connect Discovery 1.0 | 完整支持 | OIDC 部署始终可用 | [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Discovery 元数据由活跃的服务端模块生成；客户端授权策略独立执行。 |
| OAuth 2.0 Authorization Server Metadata | 完整支持 | OAuth/OIDC 部署可用 | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) | OAuth 元数据必须反映授权服务器实际可执行行为。 |
| OAuth 2.0 Protected Resource Metadata | 完整支持 | 配置对应 protected-resource metadata 表面后可用 | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | 提供通用和 FAPI 资源元数据面。 |
| OAuth 2.0 Form Post Response Mode | 完整支持 | active profile 允许 `form_post` 时为基线 code-flow 客户端宣告 | [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) | 不启用 implicit 或 hybrid 前通道令牌交付。 |
| OpenID Connect Third-Party Initiated Login | 完整支持 | 通过 HTTPS `initiate_login_uri` 客户端元数据提供 | [OpenID Connect Third-Party Initiated Login 1.0](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html) | 这是 OP 侧元数据支持；initiation URI 本身是 RP 端点。 |
| Dynamic Client Registration | 完整支持 | 仅在配置非空 initial access token 时宣告 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | DCR 创建的客户端只获得 baseline 策略，不能自行提升能力。 |
| Dynamic Client Registration Management | 完整支持 | 对通过 Dynamic Client Registration 创建的客户端可用 | [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | 使用受保护的 `registration_client_uri` 和 registration access token。 |
| Pushed Authorization Requests | 完整支持 | FAPI profile 必需；基线客户端按客户端策略可用 | [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) | 基线客户端不强制使用 PAR，除非客户端策略要求。 |
| JWT Secured Authorization Request | 完整支持 | 客户端/profile 策略允许 JAR 时接受签名 Request Object | [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | unsigned Request Object 会被拒绝。 |
| JWT Secured Authorization Response Mode / JARM | 完整支持 | JARM 模块/profile/客户端元数据启用签名授权响应时宣告 | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | 用于 message-signing profile 和要求 JARM 的客户端元数据。 |
| PKCE | 完整支持 | public、FAPI、sender-constrained、非 OIDC code-flow 客户端强制 S256 | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | 新 confidential OIDC 集成也应发送 S256 PKCE。 |
| OAuth 2.0 Security Best Current Practice | 完整支持 | 作为所有 OAuth/OIDC profile 的安全基线执行 | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | 包括禁用 implicit/password、精确 redirect、PKCE/sender constraint 策略、token transport、refresh/replay 和客户端认证边界。 |
| JSON Web Token Best Current Practices | 完整支持 | 适用于 ID Token、access token JWT、client assertion、Request Object、JARM、DPoP proof 和 signed introspection | [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) | 强制算法 allowlist、拒绝 `none`、key/alg/use 绑定、完整密码学验证和 cross-JWT confusion 防护。 |
| JWT Client Authentication and Authorization Grants | 支持；JWT bearer grant 有边界 | `private_key_jwt` 可用；JWT bearer grant 仅限已认证 confidential client 自断言 | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | 不实现第三方 assertion issuer trust、任意 subject mapping 或外部 issuer federation。 |
| JWT Profile for OAuth 2.0 Access Tokens | 完整支持；当前 access-token profile | 当前访问令牌为 `typ=at+jwt`，资源服务器 verifier 按 issuer、audience、expiry、scope 和可选 `cnf` 验证 | [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) | 这是当前 JWT access-token profile；未来若引入 opaque token，必须独立建 introspection profile。 |
| OAuth 2.0 Demonstrating Proof of Possession | 支持 | 客户端和资源请求使用 DPoP sender constraint 时启用 | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | 验证 proof 签名、`htu`、`htm`、`iat`、`jti`、`ath`、nonce 和 access-token `cnf.jkt` 绑定。 |
| OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens | 支持 | 可信 mTLS/proxy 边界配置完成，并且客户端元数据注册 mTLS 认证或 sender constraint | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)、[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html)、[RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | 支持 `tls_client_auth`、`self_signed_tls_client_auth` 和 `x5t#S256` 证书绑定访问令牌；PKI 客户端只能登记一个 subject selector。 |
| Resource Indicators | 完整支持 | authorization、token、refresh 流程携带 resource indicators 时可用 | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | 使用重复 URI 形式 `resource` 参数；外部协议输入中的 JSON 数组语法永不支持。 |
| Token Introspection | 完整支持 | introspection endpoint 可用，受客户端策略限制 | [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) | FAPI message-signing profile 可使用受保护 introspection 响应。 |
| Token Revocation | 完整支持 | revocation endpoint 可用 | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) | 按 token 类型和客户端策略撤销 token。 |
| Device Authorization Grant | 支持 | 新数据库默认开启服务端支持；客户端还必须登记 device-code grant 并设置 `allow_cross_device_flows=true` | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) | 运行时模块决定是否宣告，客户端策略决定是否有权使用。 |
| OpenID CIBA / FAPI-CIBA | 支持；ID1 兼容 | 新数据库默认开启 poll/ping 服务端支持；客户端还必须具备 CIBA grant/元数据并设置 `allow_cross_device_flows=true` | [OpenID CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html) | FAPI-CIBA ID1 的 `private_key_jwt / mTLS` × `poll / ping` 组合已支持；更新的 `fapi-ciba-03` working draft 仍需单独 delta audit。push 永不支持。 |
| FAPI 2.0 Security Profile | 完整支持 | 按客户端设置 `security_policy.assurance=fapi2` | [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html) | 要求 confidential client、PAR、sender constraint 和强客户端认证。 |
| FAPI 2.0 Message Signing | 完整支持 | 由独立客户端策略字段启用签名授权请求、JARM 与签名 introspection | [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-2_0-message-signing.html) | 兼容选项可以同时启用，并与 FAPI2 assurance 共存。 |
| OpenID4VCI 1.0 Final | 完整支持 | 默认关闭；启用 Credential Issuer 角色并完成 credential/trust 配置后，通过 OpenID4VCI issuer metadata 宣告 | [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html) | 不属于普通 OIDC RP 登录。 |
| OpenID4VP 1.0 Final | 完整支持 | 默认关闭；启用 Verifier 角色并完成 trust 配置后，通过 OpenID4VP verifier metadata 宣告 | [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | 不属于普通 OIDC RP 登录。 |
| OpenID4VC High Assurance Interoperability Profile 1.0 / HAIP | 完整支持 | 默认关闭；通过 HAIP-compatible Credential Issuer 和 Verifier 角色配置、credential-format 配置、trust 配置启用 | [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html), [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html), [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | 面向高保障 OpenID4VC 签发和出示流程的 profile 级支持；不属于普通 OIDC RP 登录。 |
| OpenID Connect Native SSO for Mobile Apps | 支持；默认关闭；待 Final 审计 | 仅在 `ENABLE_NATIVE_SSO=true` 且客户端具备 `device_sso` 范围/策略时宣告 | [OpenID Connect Native SSO](https://openid.net/specs/openid-connect-native-sso-1_0.html), [Second Implementer's Draft](https://openid.net/specs/openid-connect-native-sso-1_0-ID2.html) | 已实现 ID Token `ds_hash`、`device_secret`、refresh-family 活性校验和目标客户端绑定；当前是 draft 07 / ID2 兼容，不宣称 Final Specification。 |
| OpenID Federation 1.1 / OpenID Federation for OpenID Connect 1.1 | 不支持（待实现） | 不宣告；没有 Federation Entity Configuration 或 `/.well-known/openid-federation` endpoint | [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html), [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) | 将作为独立 federation trust-chain 能力实现，不属于普通 OIDC RP 登录。 |
| OIDC Implicit OP | 永不支持 | 无启用开关；不宣告 | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | 由 OAuth Security BCP / OAuth 2.1 方向排除。 |
| OIDC Hybrid OP | 永不支持 | 无启用开关；不宣告 | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OIDC Core 定义了 Hybrid Flow，但它把 ID Token / access token 前通道交付重新带入 authorization-code 交互。RFC 9700 已弃用 implicit 前通道 token 交付；支持的交互式 profile 保持为 code flow + PKCE / sender constraint。 |
| Resource Owner Password Credentials | 永不支持 | 无启用开关；请求时拒绝 | [RFC 6749 Section 4.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.3), [RFC 9700 Section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OAuth Security BCP 明确 password grant MUST NOT be used。 |
| 旧 OIDF Dynamic OP 认证 profile | 永不支持 | 无启用开关；OIDF Dynamic OP plan 不进入支持矩阵 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | 该认证 profile 要求 implicit/hybrid 元数据；RFC 7591/RFC 7592 动态注册仍支持。 |

## 规划中的规范与草案

本节用于说明已经进入路线图、但当前不会在 discovery 或 registration
metadata 中宣告的能力。它不是当前部署能力清单。状态为“支持”的项目表示
当前实现已按该行链接的规范或草案提供对应行为；状态为“不支持（待审计）”
表示相关稳定规范或相邻流程可能已经存在，但尚未按该行链接的草案逐条审计；
状态为“不支持（待实现）”的项目还缺少可执行实现或完整 profile 边界。

| 规范或草案 | 当前状态 | 为什么现在不作为可宣告能力 | 后续完成条件 |
| --- | --- | --- | --- |
| OAuth 2.1 Authorization Framework | 支持（按 draft-15 兼容实现） | [draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) 仍是草案，不是最终 RFC；因此不能宣称 OAuth 2.1 final conformance。当前实现已经对齐 code flow、S256 PKCE、禁用 implicit/password、精确 redirect 和安全默认值。 | 等最终 RFC 发布后做逐条审计，并把最终要求映射到代码、metadata、负向测试和一致性证据。 |
| OAuth 2.0 for Browser-Based Applications | 支持（按 draft-27 已审计） | [draft-ietf-oauth-browser-based-apps-27](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) 已在 RFC Editor 队列；当前实现已经采用 code + S256 PKCE、禁用 implicit、避免浏览器前通道 token 交付，并完成 draft-27 delta audit。 | RFC 发布后复审 SPA/BFF/browser-client 要求；不新增虚假的 runtime profile 或 discovery claim。 |
| Cross-Device Flows: Security BCP | 不支持（待审计） | [draft-ietf-oauth-cross-device-security-16](https://datatracker.ietf.org/doc/draft-ietf-oauth-cross-device-security/) 是跨设备安全 BCP，不是单个端点；Device Grant、CIBA、Native SSO 已作为独立模块存在，但尚未按该 BCP 做逐条一致性审计。 | 用最终 BCP 复审这些跨设备流程；不会自动扩大 grant type。 |
| OAuth Security BCP Update | 不支持（待审计） | [draft-ietf-oauth-security-topics-update-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/) 是 [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) 的增量更新方向。当前支持 RFC 9700，但尚未按该更新草案做逐条差异审计。 | 作为 RFC 9700 delta audit；任何行为变化都必须同步 metadata、测试和文档。 |
| JWT BCP / JWT Assertion bis | 不支持（待审计） | [draft-ietf-oauth-rfc8725bis-07](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/) 与 [draft-ietf-oauth-rfc7523bis-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/) 尚未完成最终发布。当前支持的是 RFC 8725/RFC 7523 行为，不宣称支持这两个 bis 草案。 | 完成算法 allowlist、audience、replay、key binding、cross-JWT confusion 和 `private_key_jwt` 复审。 |
| OAuth Client Attestation | 支持 OpenID4VCI 1.0 固定引用的 draft-07；默认关闭 | [draft-ietf-oauth-attestation-based-client-auth-07](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07) 是 OpenID4VCI 1.0 Final 明确固定的版本；当前实现支持 `attest_jwt_client_auth`，并将 refresh token 绑定到 Client Instance `cnf` 公钥。只有模块启用且客户端策略要求时才宣告。 | 后续草案及最终 RFC 必须作为独立 delta audit；不能把更新草案的破坏性语法变化混入 HAIP 1.0 / OpenID4VCI 1.0 profile。 |
| FAPI 2.0 HTTP Signatures | 实验性支持；默认关闭；待稳定规范审计 | [FAPI 2.0 HTTP Signatures working draft](https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html) 不是 Final Specification；当前只在 `ENABLE_FAPI_HTTP_SIGNATURES=true` 时保护 `/fapi/resource`，且没有 OIDF 专项 plan。 | 规范稳定或有 adopter 后再决定是否宣告；每个新草案/Final 都必须做 delta audit。 |
| Refresh Token and Authorization Expiration | 不支持（待实现） | [draft-ietf-oauth-refresh-token-expiration-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-refresh-token-expiration/) 要求把授权关系和 refresh token 生命周期显式建模；当前 metadata 不宣告这类过期语义。 | 定义授权有效期、refresh-family 状态、撤销语义、metadata 和端到端测试。 |
| First-Party Applications | 不支持（待实现） | [draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/) 依赖同方/同源部署假设；当前不能把它泛化到第三方客户端。 | 明确 same-party/BFF 边界，并证明不会削弱第三方客户端隔离。 |
| Client ID Metadata Document | 不支持（待实现） | [draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) 涉及 public client 元数据远程获取；当前没有可信获取、缓存和冲突处理模型。 | 定义可信来源、缓存、降级、冲突、动态注册交互和失败策略。 |
| SPIFFE Client Authentication | 不支持（待实现） | [draft-ietf-oauth-spiffe-client-auth-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) 需要部署方提供 SPIFFE trust domain；普通 OAuth/OIDC 部署不具备该前提。 | 建立 trust bundle 验证、证书/身份生命周期、资源服务器验证和 metadata 隔离。 |
| Identity Assertion / Identity Chaining / Transaction Tokens | 不支持（待实现） | 这些草案覆盖跨域身份断言、链式授权和工作负载调用链；当前缺少 issuer/trust anchor、subject mapping、Transaction Token Service 和资源服务器验证模型。 | 完成信任域、replay、审计、撤销、资源服务器验证和最小权限传播设计。 |
| Token Status List | 不支持（待实现） | [draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) 更适合 OpenID4VC 凭证状态；当前没有凭证状态发布和隐私模型。 | 随 OpenID4VC issuer/verifier 状态模型实现，不作为通用 OAuth token status endpoint。 |

以下方向目前只是观察项，不属于“待实现”：

| 草案或协议族 | 状态 | 观察原因 |
| --- | --- | --- |
| GNAP Core / GNAP Resource Server Connections | 观察中 | [RFC 9635](https://www.rfc-editor.org/rfc/rfc9635.html) 和 [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767.html) 是相邻授权协议；可作为后续 grant negotiation 设计参考，但不是 OAuth/OIDC 开关。 |
| Agent Authorization Profile | 观察中 | [draft-aap-oauth-profile-01](https://datatracker.ietf.org/doc/draft-aap-oauth-profile/) 对 AI agent delegated access 有参考价值；尚不能作为实现承诺。 |
| Delegated Authorization / Actor Chain | 观察中 | [draft-li-oauth-delegated-authorization-02](https://datatracker.ietf.org/doc/draft-li-oauth-delegated-authorization/) 和 [draft-mw-oauth-actor-chain-01](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/) 与 token exchange、actor delegation、审计链相关。 |
| Global Token Revocation | 观察中 | [draft-parecki-oauth-global-token-revocation-06](https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/) 对账号失陷和事故响应有价值，但需要严格 blast-radius、审计和多客户端策略。 |
| RAR / Resource Metadata 扩展 | 观察中 | [draft-zehavi-oauth-rar-metadata-05](https://datatracker.ietf.org/doc/draft-zehavi-oauth-rar-metadata/)、[draft-skokan-oauth-resource-response-02](https://datatracker.ietf.org/doc/draft-skokan-oauth-resource-response/) 和 [draft-mcguinness-oauth-rfc9728bis-01](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-rfc9728bis/) 可能改善 typed permissions 与 protected-resource metadata。 |

## 可发现端点

客户端应从 discovery 读取端点。启用相应模块时，基线部署可以暴露以下端点：

| 端点 | 路径 | 宣告规则 |
| --- | --- | --- |
| OIDC discovery | `/.well-known/openid-configuration` | OIDC 部署始终存在。 |
| OAuth authorization-server metadata | `/.well-known/oauth-authorization-server` | OAuth/OIDC 部署存在。 |
| Protected resource metadata | `/.well-known/oauth-protected-resource` | 资源服务器元数据存在。 |
| FAPI resource metadata | `/.well-known/oauth-protected-resource/fapi/resource` | FAPI 资源面存在。 |
| JWKS | `/jwks.json` | 发布活跃未退役签名密钥，以及仍在使用的前序密钥。 |
| Authorization | `/authorize` | 支持 code-flow 授权请求。 |
| PAR | `/par` | 按 profile 和客户端策略宣告/要求。 |
| Token | `/token` | 处理支持的 grant type 和客户端认证方式。 |
| UserInfo | `/userinfo` | 需要带 `openid` scope 的 access token。 |
| Introspection | `/introspect` | 用于资源服务器验证和 profile-specific 受保护响应。 |
| Revocation | `/revoke` | 用于适用的 refresh/access token 撤销。 |
| Logout | `/logout` | RP-Initiated Logout，严格校验已注册 redirect URI。 |
| Dynamic registration | `/register` | 仅在配置非空 initial access token 时宣告。 |
| Device authorization | `/device_authorization` | 运行时模块活跃时宣告；客户端使用仍需 grant 与跨设备策略授权。 |

Discovery 元数据是权威信息。字段缺失时，该部署没有声明对应能力。

## 最小推荐集成

新集成应使用 Authorization Code Flow + S256 PKCE。

| 字段 | 推荐值 |
| --- | --- |
| Issuer | `https://issuer.example` |
| Discovery | `https://issuer.example/.well-known/openid-configuration` |
| JWKS | `https://issuer.example/jwks.json` |
| Authorization endpoint | `https://issuer.example/authorize` |
| Token endpoint | `https://issuer.example/token` |
| UserInfo endpoint | `https://issuer.example/userinfo` |
| Logout endpoint | `https://issuer.example/logout` |
| Response type | `code` |
| Response mode | `query`；需要时可使用 `form_post` |
| PKCE | `S256` |
| Scopes | 从 `openid` 开始，只增加 RP 实际需要的 claims |
| Client authentication | public client 使用 `none` + PKCE；confidential client 按风险选择 `private_key_jwt`、mTLS 或 `client_secret_basic` |

客户端应通过元数据发现端点，不应硬编码路径。表中的路径仅用于说明集成形态。

## 客户端注册

支持两种客户端接入方式：

1. 静态管理注册。
2. 配置 initial access token 后使用 RFC 7591 / RFC 7592 动态客户端注册。

未配置 initial access token 时动态注册关闭。动态注册客户端会收到
`registration_client_uri` 和 registration access token，用于管理自己的
生命周期；它们只获得 baseline 安全策略，不能自行提升能力。

接受的客户端元数据包括：

| 元数据 | 状态 | 引用 | 说明 |
| --- | --- | --- | --- |
| `client_name` | 支持 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [OpenID Connect Registration](https://openid.net/specs/openid-connect-registration-1_0.html) | 展示元数据；登录 UI 只读取服务端权威注册数据。 |
| `redirect_uris` | authorization-code 客户端必填 | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 精确匹配。 |
| `post_logout_redirect_uris` | 支持 | [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | Logout 精确匹配。 |
| `response_types` | `["code"]` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 拒绝 implicit 和 hybrid 值。 |
| `grant_types` | 每客户端 allowlist | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) | 必须匹配已实现 grant 和客户端策略。 |
| `scope` | 每客户端 scope allowlist | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 请求不能超出注册范围。 |
| `token_endpoint_auth_method` | 支持的方法见下文 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [OpenID Connect Registration](https://openid.net/specs/openid-connect-registration-1_0.html) | FAPI profile 会收窄可接受集合。 |
| `jwks` | 支持 | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) | 用于客户端签名、加密和 self-signed mTLS 证书材料。 |
| `jwks_uri` | 在受限远程文档策略下支持 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | 仅接受策略允许的安全 HTTPS 来源。 |
| `request_uris` | 在受限基线策略下支持 | [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | 精确 HTTPS 注册；FAPI profile 优先使用 PAR。 |
| `userinfo_signed_response_alg` | 可执行时支持 | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 必须被 discovery 宣告并有活跃密钥支持。 |
| `userinfo_encrypted_response_alg` / `userinfo_encrypted_response_enc` | 有有效客户端加密密钥时支持 | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | 使用下文的窄 JWE 策略。 |
| `authorization_signed_response_alg` | JARM-capable 客户端/profile 支持 | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | 必须可由活跃 keyset 执行。 |
| `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc` | nested encrypted JARM 支持 | [JARM](https://openid.net/specs/oauth-v2-jarm.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) | 需要有效客户端加密密钥。 |
| `initiate_login_uri` | 支持；仅 HTTPS | [Third-Party Initiated Login](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html) | RP 发起登录初始化的 OP 侧元数据。 |
| `software_statement` | 不支持 | [RFC 7591 Section 2](https://www.rfc-editor.org/rfc/rfc7591.html#section-2) | RFC 7591 将 software statement 定义为由受信 statement issuer 签发的客户端元数据。当前没有配置或宣告 software-statement issuer、trust anchor 或验证策略。 |

推荐的基线注册元数据：

```json
{
  "client_name": "Example Application",
  "redirect_uris": ["https://app.example/oauth/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

public 浏览器、原生或 SPA 客户端：

```json
{
  "client_name": "Example Public Application",
  "redirect_uris": ["https://app.example/oauth/callback"],
  "response_types": ["code"],
  "grant_types": ["authorization_code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "none"
}
```

public client 必须发送 S256 PKCE。基线 confidential OIDC code-flow 为兼容性可以接受无 PKCE 请求，但新集成仍应发送 PKCE。FAPI、sender-constrained、public、非 OIDC authorization-code 客户端必须使用 S256 PKCE。

## 请求、Scope 与 Resource 边界

所有可能扩大权限的位置都会执行 subset 规则：

- token request 不能扩大 authorization request 已授权的 scopes 或 resource indicators；
- refresh request 不能超出 grant 存储的 scope/resource 边界；
- 客户端不能请求当前注册之外的 scopes 或 resources；
- resource indicators 使用 RFC 8707 的重复 `resource` 参数；
- 除显式 Token Exchange profile 外，legacy OAuth `audience` 参数永不支持。

应用应使用最小 scope 集。从 `openid` 开始，仅在 RP 实际消费相关 claims 或资源时增加 `profile`、`email`、`phone` 或 API-specific scopes。

常见 OIDC scopes：

| Scope | 用途 |
| --- | --- |
| `openid` | OIDC 认证和 ID Token 签发必需。 |
| `profile` | 策略允许时启用标准 profile claims。 |
| `email` | 策略允许时启用 email claims。 |
| `phone` | 策略允许时启用 phone claims。 |
| `offline_access` | 仅在客户端和 consent 策略允许时启用 refresh token。 |

## ID Token、UserInfo 与 Access Token Audience

ID Token 面向 RP。其 `aud` 表示发起认证的客户端。

Access token 面向资源服务器。RP 不应从 ID Token 推断 access token 语义。资源服务器需要验证 access token 时，应使用对应部署的资源服务器 verifier 或 introspection endpoint。

UserInfo 需要带 `openid` scope 的 access token。客户端注册必要元数据和密钥后，可以配置每客户端 signed / encrypted UserInfo。

## 算法与 Request Object

服务端只宣告当前运行 keyset 可执行的算法。

当前集成规则：

- ID Token、UserInfo、JARM 和 Request Object 算法必须来自 discovery 元数据和客户端注册策略；
- 不支持 unsigned Request Object（`alg=none`）；
- signed Request Object 使用非对称算法和已注册客户端密钥；
- external `request_uri` 仅作为受限基线能力，用于经过认证动态注册的精确 HTTPS URI；
- FAPI profile 继续使用服务端签发的 PAR request URI，而不是 client-hosted `request_uri` 文档；
- RP 应读取 discovery 获取 ID Token 签名默认值，不应自行假设。

高保障客户端应按所选 profile 使用 PAR、signed Request Object、JARM、DPoP 或 mTLS。

不要把 RP 配置为要求当前 discovery 未宣告的算法。元数据真实性是硬契约：宣告的算法必须可执行，未宣告的算法不应被假设可用。

JOSE 表格刻意区分两类情况：一类算法被安全边界排除；另一类是标准定义的
可选 JOSE 算法，但当前元数据不宣告。对后一类，引用的 RFC 是语法依据，
不是“该 RFC 禁止此算法”的意思。

### JWT 签名算法

下表概括 OIDC/OAuth 可由客户端配置的 JOSE 签名算法。部署可能因为活跃 keyset 或运行 profile 更窄而只宣告子集。

| Algorithm | Key type | Hashing algorithm | Use | 状态 / 表面 | 引用 | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| `EdDSA` | Ed25519 | EdDSA | `sig` | 支持 Request Object、client assertion、UserInfo、JARM、introspection/revocation response JWT 等已启用表面 | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 需要活跃 Ed25519 签名密钥或已注册客户端 Ed25519 公钥，取决于方向。 |
| `RS256` | RSA | SHA-256 | `sig` | 支持 ID Token 基线兼容、Request Object、client assertion、UserInfo、JARM、introspection/revocation response JWT 等已启用表面 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 用于广泛 OIDC 互操作；RSA 密钥必须满足部署密钥强度策略。 |
| `ES256` | ECDSA P-256 | SHA-256 | `sig` | 支持 Request Object、client assertion、UserInfo、JARM、introspection/revocation response JWT 等已启用表面 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 需要活跃 keyset / client JWK 策略接受的 P-256 密钥。 |
| `PS256` | RSA-PSS | SHA-256 | `sig` | 支持 FAPI/FAPI-CIBA、Request Object、client assertion、UserInfo、JARM、introspection/revocation response JWT 等已启用表面 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [FAPI 2.0 Security](https://openid.net/specs/fapi-2_0-security-profile.html) | 多个高保障 profile 偏好或要求。 |
| `HS256`, `HS384`, `HS512` | Symmetric | SHA-256 / SHA-384 / SHA-512 | `sig` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [OpenID Connect Core Section 10.1](https://openid.net/specs/openid-connect-core-1_0.html#SigEnc), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | OIDC 从 `client_secret` 派生对称签名密钥，并禁止 public client 使用对称签名。client secret 作为验证材料保存，不作为 OP 响应签名或 Request Object 验证密钥。 |
| `RS384`, `RS512` | RSA | SHA-384 / SHA-512 | `sig` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选 JOSE 算法，但当前不宣告；客户端必须使用已宣告算法 allowlist。 |
| `ES384`, `ES512` | ECDSA P-384 / P-521 | SHA-384 / SHA-512 | `sig` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选 JOSE 算法，但当前不宣告；客户端必须使用已宣告算法 allowlist。 |
| `PS384`, `PS512` | RSA-PSS | SHA-384 / SHA-512 | `sig` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选 JOSE 算法，但当前不宣告；需要 RSA-PSS 时使用 `PS256`。 |
| `none` | None | None | N/A | 永不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1), [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4) | unsigned ID Token 和 unsigned Request Object 永不支持。Request Object 必须签名或签名后加密。 |

### Request Object 算法

Request Object 仅在客户端和运行策略允许该请求路径时接受。

| Algorithm | Key type | Hashing algorithm | Use | 状态 / 条件 | 引用 | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| `EdDSA` | Ed25519 | EdDSA | `sig` | 接受已注册 client JWK 或解析后的 `jwks_uri` key，要求 `use=sig` 且 `alg=EdDSA` | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | 支持 signed Request Object 和 client assertion。 |
| `RS256` | RSA | SHA-256 | `sig` | 接受已注册 client JWK 或解析后的 `jwks_uri` key，要求 `use=sig` 且 `alg=RS256` | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | 基线互操作选项。 |
| `ES256` | ECDSA P-256 | SHA-256 | `sig` | 接受已注册 client JWK 或解析后的 `jwks_uri` key，要求 `use=sig` 且 `alg=ES256` | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | 支持的非对称选项。 |
| `PS256` | RSA-PSS | SHA-256 | `sig` | 接受已注册 client JWK 或解析后的 `jwks_uri` key，要求 `use=sig` 且 `alg=PS256` | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) | 高保障 / FAPI-compatible 选项。 |
| `none` | None | None | N/A | 永不支持 | [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 受保护 Request Object 表面要求签名；OIDF unsigned 模块 expected skip 是精确白名单。 |
| `HS*`, `RS384`, `RS512`, `ES384`, `ES512`, `PS384`, `PS512` | Various | Various | `sig` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1), [RFC 9101 Section 6.1](https://www.rfc-editor.org/rfc/rfc9101.html#section-6.1) | 标准定义的 JOSE 算法，但当前不为 Request Object 宣告；Request Object 验证使用严格的每客户端算法 allowlist。 |

External `request_uri` 不是通用互联网抓取能力。它只接受经过认证客户端元数据精确注册的 HTTPS URI，并且必须通过部署的远程文档安全策略。FAPI profile 继续优先使用 PAR 和服务端签发的 request URI。

### JWE 加密算法

对 client-encrypted UserInfo、encrypted JARM 和其他 client-bound response JWT 表面，只暴露窄 JWE 集合。

Key management algorithms：

| Algorithm | Key type | Use | 状态 / JWK 条件 | 引用 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `RSA-OAEP-256` | RSA | `enc` | 支持；client JWK 必须包含 RSA 公钥、`use=enc`、`alg=RSA-OAEP-256` 和 `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 使用 SHA-256 的 RSA-OAEP。 |
| `ECDH-ES` | ECDH-ES with P-256 | `enc` | 支持；client JWK 必须包含 P-256 EC 公钥、`use=enc`、`alg=ECDH-ES` 和 `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 直接 ECDH key agreement，用于客户端响应加密。 |
| `ECDH-ES+A256KW` | ECDH-ES with P-256 and AES-256 Key Wrap | `enc` | 支持；client JWK 必须包含 P-256 EC 公钥、`use=enc`、`alg=ECDH-ES+A256KW` 和 `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 推荐的 ECDH key-wrap 模式。 |
| `ECDH-ES+A128KW` | ECDH-ES with P-256 and AES-128 Key Wrap | `enc` | 支持；client JWK 必须包含 P-256 EC 公钥、`use=enc`、`alg=ECDH-ES+A128KW` 和 `kid` | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 兼容性 ECDH key-wrap 模式。 |
| `RSA1_5` | RSA | `enc` | 永不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.2](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.2) | 被算法 allowlist 拒绝；不要配置客户端要求它。 |
| `RSA-OAEP` | RSA | `enc` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选 JOSE 算法，但当前不宣告；使用 `RSA-OAEP-256`。 |
| `ECDH-ES+A192KW` | ECDH-ES with AES-192 Key Wrap | `enc` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选 JOSE 算法，但当前不宣告。 |
| `A128KW`, `A256KW` | Symmetric AES Key Wrap | `enc` | 不支持（待实现） | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [OpenID Connect Core Section 10.2](https://openid.net/specs/openid-connect-core-1_0.html#Encryption), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 仅计划用于 confidential client，并且必须先建立独立 encrypted response-key 模型；当前单向哈希保存的 client secret 不能复用为解密密钥。 |
| `A192KW`, `dir`, `PBES2-*` | Symmetric/password-based | `enc` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选 JOSE 算法，但响应加密 allowlist 不宣告。 |

Content encryption algorithms：

| Algorithm | 状态 | 引用 | 说明 |
| --- | --- | --- | --- |
| `A256GCM` | 支持 | [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) | 配置 encrypted client response JWT 时必需。 |
| `A128GCM`, `A192GCM` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选内容加密算法，但当前不宣告；使用 `A256GCM`。 |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | 不支持 | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 标准定义的可选内容加密算法，但当前不宣告；使用 `A256GCM`。 |

## Response Types 与 Response Modes

支持的交互式 response type：

| 名称 | 状态 | Value | 引用 | 说明 |
| --- | --- | --- | --- | --- |
| Authorization Code | 支持 | `code` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) | 唯一交互式 OIDC response type。public、FAPI、sender-constrained、非 OIDC code-flow 客户端必须使用 S256 PKCE。 |
| Implicit ID Token | 永不支持 | `id_token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core 定义了该值，但它不经过 token endpoint 兑换，而是通过浏览器前通道交付 ID Token。支持的交互式 profile 将 ID Token 签发保持在 authorization-code 兑换之后。 |
| Implicit Access Token | 永不支持 | `token` | [RFC 6749 Section 4.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.2), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OAuth Security BCP 已弃用 implicit grant。 |
| Implicit ID Token + Access Token | 永不支持 | `id_token token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | 排除原因是它依赖 implicit 前通道 token 交付。 |
| Hybrid Code + ID Token | 永不支持 | `code id_token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core 定义了该值，但它会在 token endpoint 兑换之前通过浏览器前通道发送 ID Token，保留了 RFC 9700 希望从 implicit-style response 中移除的暴露面。 |
| Hybrid Code + Token | 永不支持 | `code token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core 定义了该值，但它通过浏览器前通道返回 access token；RFC 9700 已弃用这种暴露模式。 |
| Hybrid Code + ID Token + Token | 永不支持 | `code id_token token` | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | 同时组合前通道 ID Token 与 access-token 交付；支持的交互式 profile 将这些 token 保持在后端 token endpoint 兑换路径中。 |

基线 OIDC response modes：

| 名称 | 状态 | Value | 引用 | 条件 | 说明 |
| --- | --- | --- | --- | --- | --- |
| Query String | 支持 | `query` | [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html) | 基线 code flow 和允许 plain authorization response 的 profile | `response_type=code` 且无更严格 profile 时的默认模式。 |
| OAuth 2.0 Form Post | 支持 | `form_post` | [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) | 基线 code flow；要求更严格响应策略的 FAPI profile 不使用 | 返回 `no-store`、CSP 保护的自动提交 HTML 表单到已注册 redirect URI。 |
| JARM | 支持 | `jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | JARM 模块/profile/客户端元数据启用 | 签名 authorization response JWT；客户端加密元数据有效时可 nested JWE。 |
| Form Post JARM | 不支持 | `form_post.jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | N/A | 标准定义的 response mode，但当前不宣告；JARM 使用 `jwt`，plain code form-post 使用 `form_post`。 |
| Query JARM | 不支持 | `query.jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | N/A | 标准定义的 response mode，但当前不作为独立 response mode 宣告。 |
| Fragment JARM | 不支持 | `fragment.jwt` | [JARM](https://openid.net/specs/oauth-v2-jarm.html) | N/A | 标准定义的 response mode，但当前不宣告。 |
| Fragment | 永不支持 | `fragment` | [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | N/A | 前通道令牌交付永不支持。 |

`form_post` 不启用 implicit 或 hybrid token delivery。它只是受支持授权响应的浏览器传输方式。

## Grant Types

| Grant type | 状态 | 引用 | 宣告 / 启用规则 | 说明 |
| --- | --- | --- | --- | --- |
| `authorization_code` | 支持 | [RFC 6749 Section 4.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 客户端 grant allowlist 包含它 | 主要 OIDC 登录 grant。 |
| `refresh_token` | 支持 | [RFC 6749 Section 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) | 客户端策略、consent 和 grant 允许 | 永远不从 implicit/front-channel flow 返回。 |
| `client_credentials` | 支持 | [RFC 6749 Section 4.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4) | 客户端 grant allowlist 包含它 | 仅 OAuth 资源访问；不是 OIDC login flow。 |
| `urn:ietf:params:oauth:grant-type:device_code` | 支持 | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html) | Device Authorization Grant 模块启用且客户端 allowlist 包含 | 禁用部署不声明该 grant。 |
| OpenID CIBA grant | 支持 | [OpenID CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html) | CIBA 模块启用且客户端注册 poll 或 ping delivery | FAPI-CIBA 只支持 poll 与 ping；push delivery mode 永不支持。 |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | 支持 | [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | 客户端 grant allowlist 包含它 | 用于有边界的资源访问。 |
| `urn:ietf:params:oauth:grant-type:token-exchange` | 支持 | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) | 显式 bounded local profile / client policy | 不是通用任意委托机制。 |
| `password` | 永不支持 | [RFC 6749 Section 4.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.3), [RFC 9700 Section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4) | N/A | RFC 9700 明确该 grant MUST NOT be used。 |
| `implicit` | 永不支持 | [RFC 6749 Section 4.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.2), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | N/A | OAuth Security BCP 已弃用 implicit 前通道 token 交付。 |

## 客户端认证

| Method | 状态 | 引用 | 客户端类型 / 条件 | 说明 |
| --- | --- | --- | --- | --- |
| `none` | 支持 | [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | public client；必须使用 S256 PKCE | 不允许用于 confidential-client grant。 |
| `client_secret_basic` | 支持 | [RFC 6749 Section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | 有存储 secret 的 confidential client | 基线 shared-secret method。 |
| `client_secret_post` | 支持，仅兼容用途 | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | 有存储 secret 的 confidential client；FAPI profile 排除 | 优先使用 `client_secret_basic`、`private_key_jwt` 或 mTLS。 |
| `client_secret_jwt` | 不支持 | [OpenID Connect Core Section 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication), [RFC 9700 Section 2.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5) | N/A | 标准为 confidential client 定义了该方法，但当前不宣告。JWT client assertion 使用 `private_key_jwt`；高保障客户端应使用非对称或 sender-constrained 认证。 |
| `private_key_jwt` | 支持 | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) | 客户端有有效注册签名密钥 | 支持签名算法为 `EdDSA`、`RS256`、`ES256`、`PS256`；高保障 profile 可收窄。 |
| `tls_client_auth` | 支持 | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)、[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html)、[RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | 配置可信 mTLS/proxy 边界；客户端元数据只能包含一个证书 subject DN 或 SAN selector | DN 先解析再规范比较；IP SAN 按二进制地址比较。管理员证书 pin 只能进一步收紧匹配。 |
| `self_signed_tls_client_auth` | 支持 | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) | 配置可信 mTLS/proxy 边界；客户端注册 self-signed certificate material | 仅在部署 mTLS 支持激活时宣告。 |
| `attest_jwt_client_auth` | 支持 | [OAuth Client Attestation draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/) | Client Attestation 模块启用且客户端策略要求 | 禁用部署不声明该客户端认证方式。 |

高保障集成应优先使用非对称或 sender-constrained 客户端认证。FAPI profile 排除 shared-secret POST 认证。

`private_key_jwt` 应使用部署 profile 接受的 issuer 或 token endpoint audience，并保持 assertion lifetime 较短。mTLS 需要注册正确的证书绑定客户端元数据，并在宣告 mTLS 元数据之前完成可信 proxy/mTLS termination 边界配置。

### 部署 mTLS 信任生命周期

[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html) 定义客户端认证、证书主体元数据和证书绑定访问令牌，但没有定义运维审批端点，也没有规定部署如何修改反向代理信任库。[RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html) 提供适用的信任锚管理安全模型；这里说明的 HTTP 控制面属于产品行为，不是 OAuth 协议端点。

RFC 8705 第 7.4 节还指出：如果授权服务器信任多个 CA，攻击者可能用另一个受信 CA 签发同 subject 的证书冒充 PKI 客户端，因此必须严格限制受信 CA 集合。

- 有效用户只能为通过正常客户端申请流程分配给自己的客户端提交信任申请；客户端必须处于启用状态，并使用 `tls_client_auth` 或证书绑定令牌。
- 通过公网 CA 审批流程使用 `tls_client_auth` 的客户端还必须登记由管理员确认的 SHA-256 叶证书 pin。该 pin 只能收紧 RFC 8705 subject 匹配，防止另一个已批准 CA 签发同 subject 证书后冒充该客户端。使用 `private_key_jwt` 认证、仅用 mTLS 绑定访问令牌的客户端不以证书作为认证身份，因此申请 sender constraint 所需 CA 时不要求这项额外 pin。
- 输入必须是恰好一张当前有效的 RFC 5280 CA 证书，最大 16 KiB，包含 critical CA Basic Constraints、critical `keyCertSign`，并使用允许的 RSA 或 NIST 曲线公钥。
- 必须由另一名有效管理员批准或拒绝。拒绝和撤销必须提供有界原因；每次状态变化与持久化审计在同一数据库事务完成。
- 单客户端最多保留 8 个当前有效信任锚和 4 个待审批申请，单用户在每个租户最多保留 16 个待审批申请，单租户最多保留 128 个不同的当前有效信任锚；创建和审批按租户串行化。
- 反向代理只能安装从控制面导出的已批准 bundle。应用认证仍校验客户端唯一登记的 RFC 8705 subject selector；经公网审批的 PKI 信任还必须匹配叶证书 pin。self-signed 客户端继续绑定其登记证书 key。因此 TLS 层信任某个 CA，不代表 OAuth 层授权该 CA 签发的全部证书。
- subject DN 必须是合法 RFC 4514 值，并通过 OpenSSL 的 X.509 名称规范比较满足 RFC 4517 `distinguishedNameMatch` 要求。DNS 和邮件域名不区分大小写，URI SAN 精确匹配，IP SAN 解析后按二进制地址比较；非法或歧义 selector 一律拒绝。

## Logout 与 Session

支持 `/logout` 上的 RP-Initiated Logout，并严格校验已注册 `post_logout_redirect_uri`。

Front-channel 和 session-management 行为由 OIDF 矩阵验证。浏览器敏感的 logout/session 流程应与高并发 authorization 矩阵分开测试，因为它们依赖共享浏览器状态。

## Third-Party Initiated Login

支持 OpenID Connect Third-Party-Initiated Login 所需的 OP 侧元数据：

- `initiate_login_uri` 可通过动态客户端元数据注册；
- URI 必须是 HTTPS；
- 非 HTTPS 元数据会被拒绝。

该 profile 不增加 OP 侧 initiation endpoint。initiation URI 是 RP 端点；RP 使用它启动一次普通 authorization request。

## Dynamic Registration 不是 legacy Dynamic OP

实现的是安全的 RFC 7591 / RFC 7592 动态客户端注册；legacy OIDF Dynamic OP certification profile 永不支持。该 profile 要求 implicit 和 hybrid flow 的 discovery 元数据，而这些能力被 RFC 9700 和 OAuth 2.1 方向排除。

术语应精确使用：

- “Dynamic Client Registration” 指由 initial access token 前提控制的 RFC 7591 / RFC 7592 客户端生命周期支持。
- “Dynamic OP certification profile” 永不支持。

## 规范支撑的永不支持边界

以下决定不是本地偏好，而是来自当前 IETF / OpenID 安全指导，并作为实现边界编码。

| 能力 | 状态 | 规范或当前安全来源 | 原因 |
| --- | --- | --- | --- |
| Implicit grant 和 implicit OIDC response types | 永不支持 | [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OAuth Security BCP 弃用 implicit；浏览器前通道 token 交付的泄漏和重放属性弱于 code flow + PKCE。该边界也把 OIDC implicit ID Token response 排除在受支持交互式 profile 之外。 |
| Hybrid response types | 永不支持 | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 9700 Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | OIDC Core 定义了 Hybrid Flow，但它会在 token endpoint 之前通过浏览器前通道暴露 ID Token 和/或 access token。RFC 9700 已弃用 implicit 前通道 token 交付；支持的交互式 profile 保持 authorization code，并在需要时叠加 PKCE / sender constraint。 |
| Resource Owner Password Credentials | 永不支持 | [RFC 9700 Section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4), [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | OAuth Security BCP 明确 password grant MUST NOT be used，因为它把用户凭据暴露给客户端，也无法自然组合现代 MFA/passkey 认证。 |
| Unsigned Request Objects（`alg=none`） | 永不支持 | [RFC 9101 Section 4](https://www.rfc-editor.org/rfc/rfc9101.html#section-4), [RFC 8725 Section 3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | 受保护 Request Object 表面要求签名；JWT BCP 要求应用只允许满足自身安全要求的算法。 |
| Query-string bearer tokens | 永不支持 | [RFC 6750 Section 2.3](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.3), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | RFC 6750 虽记录 query method，但明确不推荐，因为 URL 很容易进入日志并泄漏。 |
| CIBA push mode | 永不支持 | [OpenID CIBA Core](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html), [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba.html) | 已实现并验证的 FAPI-CIBA 支持面是 poll 和 ping；push 会把 token 直接交付到客户端回调，不在当前支持的 profile 集中。 |

## 安全边界

以下能力明确永不支持：

- implicit grant；
- OIDC Implicit OP；
- OIDC Hybrid OP；
- Resource Owner Password Credentials grant；
- unsigned Request Object；
- query-string bearer token；
- FAPI form-body bearer token；
- CIBA push mode。

这些是有规范依据的实现边界，不是隐藏配置开关。不要尝试用未公开部署选项重新启用。

## 元数据真实性与部署开关

多个能力受运行模块或 profile 设置控制。服务端不能宣告未启用或不完整的行为。

| 能力 | 宣告前所需部署状态 |
| --- | --- |
| Dynamic Client Registration | 配置非空 `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`。 |
| Device Authorization Grant | 运行时模块活跃、客户端 grant allowlist 包含 device code，并且 `allow_cross_device_flows=true`。 |
| CIBA | 运行时模块活跃、已注册 poll/ping grant 与元数据，并且 `allow_cross_device_flows=true`。 |
| mTLS 客户端认证 / sender constraints | 可信 mTLS/proxy 边界已配置，且客户端元数据已注册。 |
| FAPI profiles | 按客户端设置 `security_policy.assurance=fapi2`，同时配置 sender constraint 与兼容的强客户端认证。 |
| UserInfo/JARM encryption | 客户端元数据包含有效加密偏好，并且选定算法只有一个可用公钥。 |
| OpenID4VCI / OpenID4VP | 对应运行模块启用，credential/trust 配置完整，并基于该配置生成公网元数据。 |

## 集成检查清单

上线 RP 前：

1. 使用公网 HTTPS redirect URI 配置客户端。
2. 使用 `response_type=code`。
3. 发送 S256 PKCE，包括 confidential client。
4. 只请求必要 scopes。
5. 从 `/.well-known/openid-configuration` 发现端点。
6. 校验 ID Token 的 `iss`、`aud`、`exp`、`iat`、使用时的 `nonce`，以及签名。
7. 不要把 ID Token 当作 API access token。
8. 使用 logout 时精确注册 post-logout redirect URI。
9. 高风险客户端使用 `private_key_jwt`、mTLS、DPoP、PAR 或 JARM。
10. 修改运行时模块状态后重新检查 discovery 元数据，并核对目标客户端的显式策略。

## 规范引用

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Third-Party Initiated Login 1.0](https://openid.net/specs/openid-connect-3rd-party-initiated-login.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html)
- [OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591.html)
- [OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592.html)
- [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OAuth 2.0 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
- [JWT Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101.html)
