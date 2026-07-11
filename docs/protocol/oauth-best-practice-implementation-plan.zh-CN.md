# NazoAuth OAuth/OIDC/FAPI 最佳实践未来路线图

Last reviewed: 2026-07-11.

## 文档定位

本文件是 NazoAuth 的 OAuth/OIDC/FAPI 能力未来路线图，用于指导后续实现顺序、
profile 边界、验收标准和文档同步要求。它不是 conformance 结果报告，也不是完整的
当前实现清单；当前实现状态只在附录中保留摘要，详细目标矩阵仍以
`docs/protocol/rfc-compliance-matrix.md` 为准。

路线图的核心目标是：在不降低安全标准的前提下，尽可能广地支持 OAuth 2.x /
OAuth 2.1 draft / OIDC / FAPI 2.0 / FAPI-CIBA / CIBA 相关能力，并同时支持两类产品场景：

- **别人接入我们平台**：NazoAuth 作为 Authorization Server / OpenID Provider，
  对外提供类似“Google 登录”的标准接入能力。
- **我们接入第三方登录**：NazoAuth 作为 Relying Party / Client，允许用户通过
  QQ、微信、Google、Microsoft 等外部 provider 登录我们的平台。

本文件使用 checkbox 作为路线任务追踪。`[x]` 只能表示路线任务已经完整实现、
测试和文档同步完成；部分完成、profile-scoped、默认关闭但仍缺标准能力、外部边界、
内部强化 profile 和草案跟踪项均不得勾选。

## 路线原则

1. **FAPI 2.0 是现代高安全默认链路**：高价值 API 默认面向 FAPI 2.0 Security Profile Final；
   FAPI 2.0 Message Signing 是可组合增强项，不能和 FAPI 1.0 习惯混用。
2. **兼容 profile 必须隔离**：FAPI 1.0、FAPI-CIBA、CIBA、普通 OAuth/OIDC 和
   FAPI 2.0 profile 必须通过 issuer、client profile 或显式 profile gate 隔离。
3. **metadata truth 优先于功能广告**：Discovery、README、profile 文档只能声明运行时
   真实启用且已测试的能力。
4. **外部 provider 采用模块化接入**：QQ、微信、Google、Microsoft、企业 SAML 等 provider
   默认关闭，由管理员选择性启用并填写完整配置；provider 差异限制在 adapter 内。
5. **草案能力只做 watchlist 或内部 profile**：Internet-Draft、Implementer's Draft 或
   OIDF draft 不得写成最终标准支持。
6. **新增能力必须先有威胁模型和负向测试**：涉及 redirect、PKCE、PAR/JAR/JARM、DPoP、
   mTLS、audience、issuer、nonce、refresh token、JWT/JWKS、client assertion、provider
   token 或 metadata 的变更，必须包含负向测试和 metadata overclaim 测试。

## 标准基线

| 类别 | 当前基线 | 路线处理 |
| --- | --- | --- |
| OAuth 安全基线 | RFC 9700 OAuth 2.0 Security BCP；OAuth 2.1 仍是 `draft-ietf-oauth-v2-1-15`。 | 以 RFC 9700 和 OAuth 2.1 草案方向作为默认安全约束；不得声明 OAuth 2.1 final RFC 合规。 |
| FAPI 2.0 | FAPI 2.0 Security Profile Final；FAPI 2.0 Message Signing Final。 | 作为高价值 API 主线；Message Signing 选项单独 gating。 |
| OIDC | Core、Discovery、DCR、RP-Initiated Logout、Back-Channel Logout、Front-Channel Logout、Session Management 等 OIDF 规范。 | 我们作为 OP 时只广告已实现能力；我们作为 RP 时通过 provider adapter 接入外部登录。 |
| CIBA / FAPI-CIBA | OpenID Connect CIBA Core 1.0 为 Final；FAPI-CIBA 仍按官方 Draft-02 兼容 profile 处理。 | CIBA 默认关闭；FAPI-CIBA 做兼容 profile；`fapi2-ciba` 只表示内部强化 profile。 |
| OpenID Federation | OpenID Federation 1.1 与 OpenID Federation for OpenID Connect 1.1 是当前规范线。 | 当前非目标；第三方登录不依赖 OpenID Federation 信任链。 |
| Browser-based apps | OAuth 2.0 for Browser-Based Applications 仍是 draft。 | 默认偏向 BFF/same-site session；纯 SPA token storage 是产品/部署边界。 |
| 新兴草案 | Attestation-Based Client Authentication、Transaction Tokens、Grant Management、OpenID4VCI/VP、HTTP message signatures 等。 | 进入 watchlist；没有明确产品需求、威胁模型、metadata gating 和测试前不实现。 |

## 目标能力架构

| 能力面 | 目标 | 安全边界 |
| --- | --- | --- |
| Public OP/AS | 对外提供 authorization code + PKCE、Discovery/JWKS、UserInfo、logout/session、DCR/DCRM、resource metadata、FAPI2 high-security API profile。 | 禁止 implicit/password；Discovery 只来自 runtime facts；FAPI2 client 必须 confidential、PAR、S256、sender-constrained token、严格 JWT/JWKS。 |
| FAPI2 high-security | 默认高价值 API profile。 | `fapi2-security` 是主线；`fapi2-message-signing-*` 分别控制 signed request object、JARM、RFC 9701 introspection 和 ID Token signing。 |
| CIBA / FAPI-CIBA | 支持 decoupled authentication。 | 默认关闭；官方 FAPI-CIBA 兼容 profile 与内部 `fapi2-ciba` 强化 profile 分开；不把 PAR/PKCE/`response_type=code` 等 authorization-code-only 规则套用到 CIBA。 |
| Third-party login RP | 模块化 provider 登录：QQ、微信、Google、Microsoft、企业 SAML 等。 | provider 默认关闭；每个 provider 独立 enable/config/redirect/secret/claim mapping；OIDC、OAuth2 social、SAML adapter 分离。 |
| Compatibility | 必要时支持 FAPI 1.0 或生态特定 profile。 | 仅限明确生态需求；不得和 `fapi2-security` 同 client 混用。 |

## Profile 策略

| Profile | 用途 | 默认姿态 |
| --- | --- | --- |
| `oauth2-oidc-baseline` | 普通 Web、Native、BFF、API client。 | OAuth 2.1-aligned：authorization code + PKCE、truthful metadata、refresh rotation、无 implicit/password。 |
| `fapi2-security` | 现代高安全默认链路。 | FAPI 2.0 Security Final：PAR、S256、confidential client、private_key_jwt/mTLS、DPoP 或 mTLS sender constraint、严格 JWT/JWKS。 |
| `fapi2-message-signing-*` | FAPI2 Message Signing 独立选项。 | signed request object、JARM、RFC 9701 signed/nested introspection、ID Token signing 按选项启用；失败 fail closed。 |
| `fapi-ciba-id1-plain-private-key-jwt-poll` | 官方 FAPI-CIBA 兼容 profile。 | 只表示 CIBA/FAPI-CIBA 兼容，不表示 FAPI 2.0 CIBA。 |
| `fapi2-ciba` | 本项目内部 CIBA 强化 profile。 | 将适用于 CIBA 的 FAPI2 控制叠加到 CIBA；不得作为官方 FAPI2-CIBA 标准广告。 |
| `external-provider-login-rp` | 我们作为 RP 接入第三方登录。 | provider 默认关闭，按 provider id 单独启用；OIDC issuer、OAuth2 endpoint、SAML metadata 均须 allowlist。 |

## 路线总览

| 里程碑 | 主题 | 主要任务 | 完成标志 |
| --- | --- | --- | --- |
| M0 | 路线治理和声明真实性 | 保持目标矩阵、路线图、profile 文档和 README 一致。 | 没有 metadata overclaim；路线图和状态摘要同步。 |
| M1 | Public OP/AS 基线硬化 | BP-029 浏览器、安全响应、限速、日志和错误语义。 | CORS/session/CSRF/rate-limit/logging/error tests 覆盖完整。 |
| M2 | FAPI2 默认高安全链路 | PS-001 / NI-001 FAPI2 Message Signing 与 RFC 9701 状态收口。 | Message Signing 每个选项独立 gating，证据足够后才可标为完成。 |
| M3 | 第三方客户端接入我们平台 | NI-004 / NI-005 DCR/DCRM 和 client onboarding。 | 外部开发者可按 profile 安全注册和管理 client。 |
| M4 | Delegation / token trust | NI-003 Token Exchange、NI-006 JWT bearer external trust。 | 跨服务或跨 issuer trust 不影响 baseline/FAPI2 默认链路。 |
| M5 | 我们使用第三方登录 | RP-001 到 RP-006：OIDC、QQ、微信、Google、Microsoft、SAML provider 模块。 | provider 默认关闭，启用需完整配置；登录、绑定、注销和审计有 E2E 与负向测试。 |
| M6 | CIBA / FAPI-CIBA | NI-007 CIBA poll mode、FAPI-CIBA 兼容、内部强化 profile。 | 官方兼容 profile 与内部强化 profile 文档、metadata 和 conformance 证据隔离。 |
| M7 | 加密响应与可选互操作 | NI-012 UserInfo signing/encryption、NI-013 JARM/JWE。 | cryptographic metadata、per-client key policy 和负向测试完整。 |
| M8 | 草案和相邻生态 | NI-014、NI-015、Browser draft final audit、Attestation、Transaction Tokens、OpenID4VC。 | 只在规范稳定或产品明确需要时进入实现路线。 |

## M0：路线治理和声明真实性

目标：保持路线图、实现状态、目标矩阵和公开文档一致，避免把未来目标写成当前能力。

涉及文件：

- `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`
- `docs/protocol/rfc-compliance-matrix.md`
- `docs/protocol/profile-matrix.md`
- `README.md`
- `README.zh-CN.md`
- `docs/conformance/*`

任务：

- [x] **M0-01：维护路线图和状态摘要分离**
  - 路线图正文只写未来目标、实施顺序和验收标准。
  - 当前状态只放在“当前状态摘要”附录，不在正文里展开长状态清单。
- [x] **M0-02：维护 metadata truth gate**
  - 每次新增或调整公开能力时，同步检查 Discovery、README、profile matrix 和 conformance 记录。
  - 禁止只更新 README 或 Discovery 而没有实现、测试和配置 gate。
- [x] **M0-03：维护 OIDF 覆盖检索记录**
  - 每个新增 OAuth/OIDC/FAPI profile 都要查 OIDF conformance suite。
  - 有官方 plan 时加入本仓库执行矩阵；没有官方 plan 时记录检索日期和缺口。

本次 M0 交付：

- README / README.zh-CN 的路线图入口已从“实施任务书”改为“未来路线图”。
- README / README.zh-CN 已避免把 OAuth 2.1 draft、模块化第三方登录和外部 federation 写成当前默认能力。
- Back-Channel Logout 公开表述已从 best-effort 更新为 signed logout token + durable outbox delivery。
- M0 验收命令已通过；命令见下方验收块。

验收：

```powershell
git diff --check
rg -n "FAPI2-CIBA 支持|FAPI 2\.1|OpenID Federation.*已实现|implicit grant.*支持|password grant.*支持" README.md README.zh-CN.md docs --glob '!docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md'
rg -n "^- \[x\].*(部分完成|profile-scoped|外部边界|未实现)|^\s+- 状态：完成 /" docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md
```

## M1：Public OP/AS 基线硬化

目标：先把“别人接入我们平台”的默认 OAuth/OIDC Provider 面做成可公开、可维护、可测试的安全默认值。

优先任务：

- [x] **M1-01：完成 BP-029 浏览器与平台安全边界**
  - 覆盖 CORS、cookie/session、CSRF、rate limit、错误语义和敏感日志约束。
  - 维持 authorization endpoint 无 CORS、BFF/same-site session 默认边界和 no implicit/password。
- [x] **M1-02：补齐错误语义和日志脱敏回归**
  - token、authorization code、client assertion、DPoP proof、raw certificate、third-party provider token、secret reference 不得进入日志、错误响应或测试快照。
- [x] **M1-03：补齐运行时配置文档**
  - 配置文档必须说明生产 TLS/HSTS、reverse proxy、trusted mTLS header、CORS 和 cookie policy 边界。

当前完成范围：

- 安全响应头由 bootstrap middleware 统一加固，`check_session` iframe 只保留必要的 frame 例外。
- CORS 按 endpoint policy 拆分：well-known、browser OAuth、auth API、admin 和 SCIM 使用独立策略；authorization endpoint 不暴露 CORS。
- session cookie、CSRF、rate limit、OAuth 错误语义和敏感材料不外泄已有回归覆盖；`cors_auth_api` 额外覆盖 credentialed CORS 只允许配置 origin 和 CSRF 头。
- `docs/operations/configuration.md` 已记录生产 TLS/HSTS、reverse proxy、trusted mTLS header、CORS 和 cookie policy 边界。

预计涉及：

- `src/bootstrap/routes.rs`
- `src/config.rs`
- `src/settings.rs`
- `tests/in_source/src/bootstrap/tests/cors.rs`
- `tests/in_source/src/http/authorization/tests/*`
- `docs/operations/configuration.md`

验收：

```powershell
cargo fmt --check
cargo check --locked
cargo clippy -- -D warnings
cargo test --locked cors --lib
cargo test --locked authorization --lib
```

## M2：FAPI 2.0 默认高安全链路

目标：将高价值 API 默认定位为 FAPI 2.0 Security Profile Final，并把 FAPI 2.0 Message Signing
做成独立可组合选项。

优先任务：

- [x] **M2-01：复核 PS-001 / NI-001 完成标准**
  - signed request object、JARM、signed introspection、nested encrypted introspection、ID Token signing 必须分别确认实现、metadata、测试和 conformance 证据。
  - 只有每个子项都没有已知协议缺口时，相关任务才能改为 `[x]`。
- [x] **M2-02：隔离 FAPI 1.0 与 FAPI 2.0**
  - `fapi2-security` 不接受 FAPI 1.0 的 `code id_token`、全局 JARM 强制、外部 `request_uri` 或非 sender-constrained 习惯。
  - 不在同一 client 上同时声明 `fapi1_advanced` 与 `fapi2_security`。
- [x] **M2-03：保持 FAPI2 precision regression**
  - 继续覆盖 PAR、S256、confidential client、sender constraint、issuer、audience、JWT/JWKS、code TTL、PAR TTL、authorization endpoint 参数限制和 303 redirect。

当前复核状态：

| 子项 | 当前事实源 | M2 状态 |
| --- | --- | --- |
| FAPI2 Security Final | `fapi2-security` runtime profile 已强制 PAR、S256、confidential client、FAPI client auth、sender-constrained token、code TTL 与 PAR TTL；`tests/in_source/src/http/authorization/tests/par.rs`、`tests/in_source/src/http/token/tests/dispatch.rs` 和 `tests/in_source/src/http/tests/well_known.rs` 保持对应负向测试。 | 已由官方 `oidf-conformance-full.yml` run `28953799865` 在 18+2 `parallel-isolated` 矩阵中验证。 |
| Signed request object | `fapi2-message-signing-authz-request` 独立 profile 要求 PAR 中 signed request object；`src/http/authorization/jar.rs` 与 PAR/JAR 测试覆盖 `aud`、`nbf`、`exp`、client 绑定和 replay 边界。 | profile-scoped；不并入 base `fapi2-security`。 |
| JARM | `fapi2-message-signing-jarm` 独立 profile 继承 FAPI2 Security，并在 request 省略 `response_mode=jwt` 或显式使用默认 query mode 时仍强制签名授权响应；base `fapi2-security` 仍只在协商 `response_mode=jwt` 时签名，不强制全局 JARM。 | profile-scoped；不并入 base `fapi2-security`。 |
| Signed / nested encrypted introspection | `fapi2-message-signing-introspection` 独立 profile 才发布 RFC 9701 signed introspection 与 JWE metadata；base `fapi2-security` 不发布这些字段。 | profile-scoped；不得在 base profile 中广告。 |
| ID Token signing | OIDC ID Token 始终签名，metadata 来自活跃签名能力并保留 RS256 基线兼容。 | 属于 OIDC 基线能力，不作为额外 FAPI2 Message Signing profile 勾选。 |
| FAPI1 / FAPI2 隔离 | DCR 与 authorization endpoint 只接受 `response_type=code`；FAPI2 profile 不接受 hybrid `code id_token`、外部 `request_uri` 或 bearer-only FAPI client policy。 | 已有负向测试，并由 M2 远端容器 regression 与官方 18+2 run `28953799865` 保持验证。 |

预计涉及：

- `src/http/authorization/*`
- `src/http/token/introspect.rs`
- `src/http/well_known.rs`
- `src/settings/profile.rs`
- `tests/in_source/src/http/authorization/tests/*`
- `tests/in_source/src/http/token/tests/introspect.rs`
- `tests/in_source/src/http/tests/well_known.rs`

验收：

```powershell
cargo test --locked fapi --lib
cargo test --locked introspect --lib
cargo test --locked well_known --lib
```

## M3：第三方客户端接入我们平台

目标：让外部开发者能够安全接入 NazoAuth OP/AS，并按 baseline、FAPI2、Message Signing、
CIBA 等 profile 明确注册、测试和运维。

优先任务：

- [x] **M3-01：收口 NI-004 Dynamic Client Registration**
  - 明确 `software_statement`、远端 `jwks_uri`、client metadata trust、注册审计和默认权限边界。
  - 默认注册出来的 client 不得自动获得 FAPI、高权限 scope、CIBA 或管理能力。
- [x] **M3-02：保持 NI-005 DCR Management 完成状态**
  - registration access token 轮换、client secret 轮换、PUT 全量替换、DELETE 撤销链路继续有测试覆盖。
- [x] **M3-03：新增 client onboarding 文档**
  - 分别说明 baseline、FAPI2、FAPI2 Message Signing、CIBA、Device Grant、DCR/DCRM 的注册字段、认证方式、metadata 和错误语义。

预计涉及：

- `src/http/dynamic_client_registration.rs`
- `src/http/admin/clients/create.rs`
- `src/http/well_known.rs`
- `tests/in_source/src/http/tests/dynamic_client_registration.rs`
- `docs/operations/configuration.md`
- `docs/protocol/profile-matrix.md`

验收：

```powershell
cargo test --locked dynamic_client_registration --lib
cargo test --locked well_known --lib
```

## M4：Delegation / Token Trust 扩展

目标：在需要跨服务、跨 issuer 或第三方 assertion 的场景中扩展授权能力，同时不污染
baseline 和 FAPI2 默认链路。

优先任务：

- [x] **M4-01：收口 NI-003 RFC 8693 Token Exchange local profile**
  - 当前 local access-token exchange 必须明确支持边界：本 AS 签发 token、显式 target、scope downscope、revocation、actor token。
  - 外部 issuer、refresh-token exchange、ID-token exchange、`authorization_details` 传播作为独立 profile，不混入 local profile。
- [x] **M4-02：设计 NI-006 third-party JWT bearer assertion trust**
  - 只有业务需要第三方 assertion issuer 时实施。
  - 必须包含 issuer allowlist、subject mapping、audience、`jti` replay、撤销、审计事件和负向测试。

预计涉及：

- `src/http/token/token_exchange.rs`
- `src/http/token/jwt_bearer.rs`
- `src/http/token/dispatch.rs`
- `tests/in_source/src/http/token/tests/token_exchange.rs`
- `tests/in_source/src/http/token/tests/jwt_bearer.rs`

验收：

```powershell
cargo test --locked token_exchange --lib
cargo test --locked jwt_bearer --lib
```

## M5：模块化第三方登录

目标：NazoAuth 作为 RP/client 支持用户通过第三方 provider 登录本平台。该能力必须模块化、
默认关闭、按 provider 独立配置，不能把 provider 差异扩散到核心登录会话模型。

Provider 分类：

| 分类 | 示例 | 接入方式 | 安全边界 |
| --- | --- | --- | --- |
| 标准 OIDC provider | Google、Microsoft、企业 OIDC | 通用 OIDC adapter + provider 配置。 | issuer allowlist、PKCE、state、nonce、JWKS cache、ID Token 校验、`sub` + issuer 绑定。 |
| OAuth2 social provider | QQ、微信等 | provider-specific adapter。 | 固定 endpoint、固定 scope、provider-specific openid/unionid/userinfo 归一化；不伪装成 OIDC。 |
| SAML provider | 企业 SSO | SAML adapter。 | per-tenant metadata allowlist、签名断言、AudienceRestriction、Recipient、Destination、NotOnOrAfter、重放缓存。 |

优先任务：

- [x] **M5-01：Provider registry 和配置模型**
  - 每个 provider 必须有 `provider_id`、`enabled`、display name、adapter type、client id、secret reference、redirect URI、scope、endpoint/issuer、claim mapping、icon/display ordering。
  - provider 默认关闭；配置不完整时 fail closed；未启用 provider 不显示登录入口。
- [x] **M5-02：OIDC provider adapter**
  - 支持 Google、Microsoft 等标准 OIDC provider 作为配置实例。
  - 校验 state、nonce、PKCE、ID Token `iss`/`aud`/`azp`/`exp`/`iat`/`nonce`、JWKS key rotation、`sub` + issuer identity key。
- [x] **M5-03：OAuth2 social provider adapters**
  - QQ、微信等 provider-specific 登录通过独立 adapter 实现。
  - 每个 adapter 显式声明 authorization endpoint、token endpoint、openid/unionid/userinfo 获取方式、scope、错误码映射和 token 过期处理。
  - 第三方 access token 只用于获取外部身份，不得成为本平台 access token 或长期权限凭据。
- [x] **M5-04：Account linking 和 claim normalization**
  - 外部身份与本地用户显式绑定；email 只作为可验证 claim，不作为唯一身份根。
  - 支持 unlink/relink 审计；处理 email 变更、未验证 email、同一 email 多 provider 和账号接管风险。
- [x] **M5-05：External provider session/logout**
  - 本地 session 是 NazoAuth 的事实源；外部 provider logout 失败不得伪造远端已登出状态。
  - 支持登录 CSRF 防护、session fixation 防护、provider callback 重放防护。
- [x] **M5-06：Admin-managed provider onboarding**
  - 管理端只允许高权限操作者启停 provider、填写配置、查看回调地址、执行测试登录、审计变更和回滚。
  - secret/key material 不进入日志、前端配置、错误响应或测试快照。

预计涉及：

- `src/http/profile/*` 或新增 `src/http/external_login/*`
- `src/settings.rs`
- `src/settings/profile.rs`
- `src/bootstrap/routes.rs`
- `src/http/well_known.rs` 之外的 RP 配置文档；第三方登录不应进入 OP Discovery metadata
- `tests/in_source/src/http/profile/tests/*` 或新增 `tests/in_source/src/http/external_login/tests/*`
- `docs/operations/configuration.md`
- `docs/protocol/profile-matrix.md`

验收：

```powershell
cargo fmt --check
cargo check --locked
cargo clippy -- -D warnings
cargo test --locked external_login --lib
cargo test --locked session --lib
```

## M6：CIBA / FAPI-CIBA

目标：保留 CIBA 作为 decoupled authentication 产品面，兼容官方 FAPI-CIBA profile，同时提供
内部 `fapi2-ciba` 强化 profile。

优先任务：

- [x] **M6-01：补齐 CIBA poll mode 的产品边界**
  - 用户确认 UI、审计、错误语义、token binding、interval/slow_down 和 auth_req_id lifecycle 必须完整。
- [x] **M6-02：隔离 FAPI-CIBA 与内部 `fapi2-ciba`**
  - `fapi-ciba-id1-plain-private-key-jwt-poll` 保持官方 FAPI-CIBA 兼容 profile。
  - `fapi2-ciba` 只声明为内部强化 profile，不在 OIDF/README 中作为官方标准广告。
- [x] **M6-03：保持 CIBA metadata truth**
  - 只有 `ENABLE_CIBA=true` 且 client 注册 CIBA grant 时才广告和执行。
  - 不把 authorization-code-only 的 PAR、PKCE、`response_type=code` 要求套用到 CIBA。

预计涉及：

- `src/http/token/ciba.rs`
- `src/http/token/dispatch.rs`
- `src/http/well_known.rs`
- `src/settings/profile.rs`
- `tests/in_source/src/http/token/tests/ciba.rs`
- `tests/in_source/src/http/tests/well_known.rs`

验收：

```powershell
cargo test --locked ciba --lib
cargo test --locked well_known --lib
```

## M7：加密响应与可选互操作

目标：实现确有生态价值且不会降低默认安全边界的 OIDC/FAPI 加密与互操作能力。

优先任务：

- [x] **M7-01：NI-012 UserInfo signing/encryption**
  - per-client signing/encryption metadata、JWS/JWE alg allowlist、claim minimization、negative tests。
- [x] **M7-02：NI-013 JARM/JWE encrypted authorization responses**
  - JWE alg/enc policy、key management、metadata gating、decryption negative tests。
- [x] **M7-03：更新 OIDF matrix**
  - 若 OIDF suite 有对应 OP plan，加入 full matrix；若没有，记录检索日期和缺口。

验收：

```powershell
cargo test --locked userinfo --lib
cargo test --locked jarm --lib
cargo test --locked well_known --lib
```

## M8：草案和相邻生态 watchlist

目标：跟踪新兴规范，但不把草案能力误写成当前或最终标准能力。

候选项：

- NI-014 FAPI / HTTP message signatures。
- NI-015 RFC 9865 cursor pagination / RFC 9967 async SCIM or SCIM Security Events。
- OAuth 2.0 for Browser-Based Applications draft 最终 RFC 发布后的审计。
- OAuth 2.0 Attestation-Based Client Authentication。
- Transaction Tokens。
- Grant Management。
- OpenID4VCI / OpenID4VP。

进入实现路线的前置条件：

- [ ] **M8-01：产品需求明确**
  - 必须说明谁会使用、接入方式、威胁模型、metadata 或配置面、失败场景和运维责任。
- [ ] **M8-02：规范和 conformance 状态明确**
  - 标准源、草案版本、OIDF/IETF 状态、conformance suite 覆盖和本地测试策略必须记录。
- [ ] **M8-03：不会降低主线安全边界**
  - 不能影响 `oauth2-oidc-baseline`、`fapi2-security`、`fapi2-message-signing-*`、CIBA 和 external provider login 的默认安全属性。

## 当前状态摘要

本摘要只用于帮助排期，不替代测试结果、conformance 记录或代码事实源。

| 类别 | 当前状态 |
| --- | --- |
| 已具备的 OP/AS 基线 | BP-001 到 BP-028 已作为当前基础能力维护；TP-001 到 TP-008 已作为精确测试包维护。 |
| Public OP/AS 基线硬化 | M1 / BP-029 已完成；后续新增 endpoint 必须复用同等 CORS、cookie/session、CSRF、rate limit、日志脱敏和错误语义门禁。 |
| 当前优先缺口 | M7 已完成；M8 watchlist 保持 deferred，尚未开始。 |
| FAPI2 / Message Signing | M2 已完成；后续新增 FAPI / Message Signing 行为必须继续保持 profile-scoped metadata truth 与负向测试。 |
| DCR / DCRM | M3 已完成；NI-004 / NI-005 以 default-closed DCR/DCRM、管理凭据轮换、非秘密审计事件和 onboarding 文档维护。 |
| Token trust | M4 已完成；NI-003 是 bounded local Token Exchange，NI-006 是第三方 JWT bearer trust 设计完成且实现 deferred，外部 issuer trust 不属于当前默认能力。 |
| CIBA | M6 已完成；官方 FAPI-CIBA poll profile 与内部 `fapi2-ciba` 已隔离，状态生命周期、并发轮询、审计提交点和 metadata truth 已通过本地与官方全矩阵回归。 |
| 加密响应 | M7 已完成；UserInfo 支持 JSON、JWS、JWE 和 nested JWS/JWE，JARM 支持 per-client 签名与 nested JWE；OIDF signed UserInfo 模块及本地与官方 19+2 全矩阵已纳入验收。 |
| 外部第三方登录 | M5 已完成为配置驱动的热插拔 provider registry；外部 OIDC、OAuth2 social、SAML gateway、非敏感 admin onboarding 和本地 session 边界已实现。 |
| 非目标 | NI-010 OpenID Federation 当前不实现；第三方登录不依赖 OpenID Federation。 |
| 可选未来项 | NI-014、NI-015 和 M8 watchlist 仍为 deferred，不属于当前实现范围。 |

## 更新规则

当任何路线任务状态变化时，必须同步更新：

- `docs/protocol/rfc-compliance-matrix.md`
- `docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md`
- `docs/protocol/profile-matrix.md`
- `README.md`
- `README.zh-CN.md`
- 对应 conformance 记录或本地测试证据
- 涉及第三方登录时，同步 provider 配置文档、账号绑定说明、登录 E2E/负向测试、管理端启停流程和审计事件说明

每新增一个 RFC、OIDC/FAPI profile 或标准协议能力支持时，必须额外执行 OIDF 一致性套件覆盖检查：

- 检索 OpenID Foundation Conformance Suite 的官方 production/staging 计划、公开源代码和 release notes。
- 如果 OIDF 已有对应官方测试、计划或矩阵，必须在同一变更中更新本仓库的 OIDF 执行内容。
- 如果 OIDF 暂无对应官方测试，必须在任务证据或 conformance 记录中写明检索结论和日期。
- OIDF 官方套件覆盖是额外证据，不替代本地正向、负向、安全边界和 metadata truth 测试。

不得只改 README 或 Discovery metadata 而不补实现与测试。
