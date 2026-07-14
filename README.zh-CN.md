<p align="center">
  <img src="docs/assets/nazo-auth-cover.png" alt="Nazo Auth 封面">
</p>

# Nazo Auth Server

[![code-quality](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml)
[![oidf-conformance-full](https://github.com/nazozero/NazoAuth/actions/workflows/oidf-conformance-full.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/oidf-conformance-full.yml)
[![codecov](https://codecov.io/gh/nazozero/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/nazozero/NazoAuth)

[English](README.md) · [文档](#文档) · [快速启动](#快速启动) · [安全策略](SECURITY.md)

Nazo Auth Server 是一个用 Rust 写的自托管 OAuth 2.x / OAuth 2.1-aligned / OpenID Connect 授权服务器。它面向同域部署：issuer、浏览器 UI、passkey、CORS、cookie 和协议端点共享同一个公开 origin。

项目包含授权服务器、小型 identity/admin 管理面、本地签名密钥管理、WebAuthn/passkeys、MFA、SCIM，以及 Rust resource-server verifier。模块化第三方 provider 登录属于未来路线图能力，不作为当前默认能力广告。PostgreSQL 保存持久状态，Valkey 保存短生命周期协议状态。

## 状态

| 项目 | 值 |
| --- | --- |
| 包名 | `nazo-oauth-server` |
| 版本 | `0.1.0` |
| 许可证 | AGPL-3.0-or-later |
| 语言 | Rust 2024 |
| 运行依赖 | PostgreSQL、Valkey |
| 已认证公开 issuer | `https://auth.nazo.run` |
| 默认部署模型 | 同域 |

## 质量信号

项目质量用直接、可审计的检查来表达，不使用综合评分：

| 信号 | 证据 |
| --- | --- |
| Rust 质量门禁 | `code-quality` 中的 `cargo fmt --check`、`cargo check --workspace --all-targets --all-features --locked`、`cargo clippy -D warnings`、迁移和完整 workspace tests。 |
| 静态安全分析 | CodeQL Rust analysis，启用 `security-extended` 和 `security-and-quality` queries。 |
| 依赖策略 | GitHub dependency review、`cargo audit`、`cargo deny`，覆盖 advisories、bans、licenses 和 sources。 |
| 运行时安全行为 | `conformance-security` 中的真实 HTTP E2E、load/race gate、Valkey outage injection。 |
| 协议一致性 | OIDF/FAPI conformance workflows，以及已归档的官方 21-plan matrix 证据。 |
| 覆盖率趋势 | 专用 coverage workflow 上传 Codecov LCOV。 |
| 发布来源证明 | CycloneDX SBOM、Trivy image scan、Sigstore signing、GitHub artifact attestations。 |

## 标准

Nazo Auth Server 实现了现代授权服务器需要的核心标准。兼容性例外会明确写在文档里，不靠 discovery metadata 模糊带过。

IETF 和 RFC：

| 标准 | 实现 |
| --- | --- |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), Token Revocation | `/revoke` |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), JWT Client Authentication 和 JWT Bearer Grant | `private_key_jwt`，以及绑定客户端自身身份的 JWT bearer grant |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), PKCE | S256 PKCE |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), Token Introspection | `/introspect` |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), OAuth 2.0 for Native Apps | public native app redirect URI 策略：claimed HTTPS、private-use scheme、允许端口变化的 loopback HTTP |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), Authorization Server Metadata | `/.well-known/oauth-authorization-server` |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628), Device Authorization Grant | `/device_authorization`、`/device` 和 `device_code` token grant，由 `ENABLE_DEVICE_AUTHORIZATION_GRANT` 控制 |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693), Token Exchange | 面向已注册 `urn:ietf:params:oauth:grant-type:token-exchange` 客户端的受限本地 access-token exchange |
| [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705), OAuth 2.0 mTLS | mTLS client auth 和 sender-constrained token |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), Resource Indicators | authorization/PAR/token `resource` 处理、JWT `aud` 绑定，以及 refresh token audience 收窄 |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), JWT Access Tokens | 面向 resource server 的 JWT access token |
| [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101), JAR | 启用后支持 signed request object |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126), PAR | `/par` |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396), Rich Authorization Requests | 由 `ENABLE_AUTHORIZATION_DETAILS` 控制 |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), DPoP | proof 校验和 sender-constrained token |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), OAuth 2.0 Security BCP | code-only authorization response、无 password/implicit grant、PKCE、redirect URI 绑定、bearer token 防护和 sender-constrained token 加固 |
| [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701), JWT Response for OAuth Token Introspection | profile-gated signed 和 nested encrypted introspection response |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), Protected Resource Metadata | `/.well-known/oauth-protected-resource` 和 `/.well-known/oauth-protected-resource/fapi/resource` |
| OAuth 2.1 draft 方向 | OAuth 2.1 风格默认值，兼容例外需要显式开关 |

OpenID Foundation：

<p align="center">
  <a href="https://openid.net/certification/certified-openid-providers-profiles/">
    <img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png" alt="OpenID Certified" width="140">
  </a>
</p>

| 规格 | 实现 |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | ID Token、JSON/signed/encrypted UserInfo、claims、authorization code flow |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout` |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | signed logout token + durable outbox delivery |
| [JWT Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html) | active profile 或请求选择 JARM 时支持签名响应，并支持可选 per-client nested JWE |
| [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-security-profile-2_0-final.html) | `fapi2-security` profile |
| [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-message-signing-2_0-final.html) | signed authorization request、JARM 和 signed introspection profile support |

其他协议能力：

| 标准 | 实现 |
| --- | --- |
| SCIM 2.0 provisioning，包含 [RFC 9865](https://www.rfc-editor.org/rfc/rfc9865) / [RFC 9967](https://www.rfc-editor.org/rfc/rfc9967) 能力发现 | 默认 tenant 的 user provisioning；index pagination 仍为默认方法，forward cursor pagination 使用 10 分钟有效、绑定 actor/query 的不透明 cursor；RFC 9967 Security Events 仍关闭 |
| WebAuthn | passkey 注册和登录 |

新兴协议由 [M8 watchlist 治理审计](docs/conformance/2026-07-11-m8-watchlist-governance.md)
跟踪。该记录完成产品与 conformance 准入门禁，不表示 deferred 候选项已经获得运行时支持。

## 认证

Nazo Auth Server 已列入 OpenID Foundation 认证列表，名称为
`Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`。

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

OpenID Foundation Conformance Suite 结果 URL：

| 结果 | URL |
| --- | --- |
| OIDC Basic OP | <https://www.certification.openid.net/plan-detail.html?plan=Srk6iaVDVcqO5> |
| OIDC Config OP | <https://www.certification.openid.net/plan-detail.html?plan=fGiz8QZYR1LVy> |
| 最新 21-plan 官方矩阵 | [docs/conformance/2026-07-11-m7-official-encrypted-responses-oidf-results.md](docs/conformance/2026-07-11-m7-official-encrypted-responses-oidf-results.md#plan-ids) |
| OIDF 矩阵范围 | [docs/conformance/oidf-full-matrix.zh-CN.md](docs/conformance/oidf-full-matrix.zh-CN.md) |
| 最新私有 full-matrix 回归 | [docs/conformance/2026-07-01-tp-ps-full-matrix.md](docs/conformance/2026-07-01-tp-ps-full-matrix.md) |

最新官方 full matrix 针对 `https://auth.nazo.run` 执行，workflow head SHA 为
`371b4f6e61674c4d1bd9ace7ba5b518314c8ff0f`。该运行以 19+2
parallel-isolated 形式完成 21 个 plan，导出 640 个模块：632 个 `PASSED`、6 个
预期 `REVIEW`、2 个预期 `SKIPPED`，没有失败模块、condition failure 或
warning，因此不能作为 zero-SKIPPED 证据。

最新私有 full-matrix 回归针对 runtime commit `31e8f9f` 执行，跑完全部 16 个 plan、578 个模块，结果为 `0 failures`、`0 warnings`。

## 功能

- Authorization code + PKCE、refresh token、client credentials、受限 JWT bearer grant、受限 Token Exchange、revocation、introspection、signed/encrypted introspection、discovery、protected resource metadata、JWKS、JSON/signed/encrypted UserInfo、signed/encrypted JARM、PAR、JAR、DPoP、mTLS。
- Runtime profile：`oauth2-baseline`、`fapi2-security`、`fapi2-message-signing-authz-request`、`fapi2-message-signing-jarm`、`fapi2-message-signing-introspection`。
- 本地用户、资料、OAuth client、grant、access request、TOTP MFA、backup code、remembered MFA、WebAuthn/passkeys、SCIM provisioning。
- 本地签名密钥生命周期，包含 prepublish、active、grace、retired 状态。也可以用 external-command signer 接 KMS/HSM。
- 与 Web 框架无关的 Rust resource-server verifier，以及项目使用的 Actix
  HTTP 集成；不再提供历史 Axum/Tower 和 tonic adapter。
- 发布安全 workflow：CodeQL、dependency review、cargo audit、cargo deny、SBOM、Trivy image scanning、keyless signing、provenance attestation。

## 快速启动

需要：

- `rust-toolchain.toml` 精确锁定的 Rust stable 版本
- PostgreSQL 18 或兼容版本
- Valkey 8 或兼容 Redis protocol 的服务
- Docker 或 Podman

用 Docker Compose 启动：

```sh
cp .env.yaml.example .env.yaml
docker compose up -d nazo_oauth_server
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/.well-known/openid-configuration
```

如果直接在宿主机运行，先把 `.env.yaml` 里的 PostgreSQL 和 Valkey 地址改成可访问的服务：

```sh
cargo run --bin nazo-oauth-migrate
cargo run --bin nazo-oauth-server
```

## 配置

新部署只需要少量启动配置：

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
RUST_LOG: "info"
```

`PUBLIC_BASE_URL` 派生同域默认值：

| 值 | 默认规则 |
| --- | --- |
| `ISSUER` | `PUBLIC_BASE_URL` |
| `FRONTEND_BASE_URL` | `PUBLIC_BASE_URL + "/ui/"` |
| `CORS_ALLOWED_ORIGINS` | `PUBLIC_BASE_URL` 的 origin |
| `COOKIE_SECURE` | HTTPS issuer 下为 `true` |
| `PASSKEY_ORIGIN` 和 `PASSKEY_RP_ID` | 从 issuer 派生 |
| `PROTECTED_RESOURCE_IDENTIFIER` | `ISSUER + "/fapi/resource"` |

`DATA_DIR` 派生本地持久化路径：

| 值 | 默认规则 |
| --- | --- |
| `JWK_KEYS_DIR` | `DATA_DIR + "/keys"` |
| `AVATAR_STORAGE_DIR` | `DATA_DIR + "/avatars"` |

高级配置仍然保留，用于兼容旧部署和特殊环境。详见
[docs/operations/configuration.md](docs/operations/configuration.md)。

## 默认边界

以下能力不属于默认授权服务器表面；只有在实现、测试并显式启用后才会对外声明：

- Dynamic Client Registration / RFC 7591 和 Client Configuration Management
  / RFC 7592，除非 `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`；公开注册部署应使用 initial access token 保护 `/register`。
- Device Authorization Grant / RFC 8628，除非 `ENABLE_DEVICE_AUTHORIZATION_GRANT=true`。
- 外部 token、refresh token 或 ID token 的 Token Exchange profile。
- QQ、微信、Google、Microsoft、企业 SAML 等模块化第三方登录 provider；在 provider-specific adapter、配置 gate、账号绑定、E2E 和负向测试完成前仅属于路线图能力。
- 请求级动态 tenant 或 issuer routing。
- signed-introspection profile 外，或未配置 per-client JWE response metadata 的 RFC 9701 encrypted introspection response。
- 未配置受支持的 per-client JWE metadata 与唯一匹配公开加密密钥时的 UserInfo 或 JARM 加密。

当前范围见 [docs/project/roadmap.md](docs/project/roadmap.md)。

## 文档

| 主题 | 链接 |
| --- | --- |
| 文档索引 | [docs/README.md](docs/README.md) |
| Workspace 架构 | [docs/project/architecture.md](docs/project/architecture.md) |
| 配置 | [docs/operations/configuration.md](docs/operations/configuration.md) |
| 部署 | [docs/operations/deployment.zh-CN.md](docs/operations/deployment.zh-CN.md) |
| 英文部署文档 | [docs/operations/deployment.md](docs/operations/deployment.md) |
| Conformance 记录 | [docs/conformance](docs/conformance) |
| 性能基准 | [docs/performance/performance-capacity-curve.md](docs/performance/performance-capacity-curve.md) |
| OAuth/OIDC/FAPI best-practice matrix | [docs/protocol/rfc-compliance-matrix.md](docs/protocol/rfc-compliance-matrix.md) |
| OAuth/OIDC/FAPI 未来路线图 | [docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md](docs/protocol/oauth-best-practice-implementation-plan.zh-CN.md) |
| Profile matrix | [docs/protocol/profile-matrix.md](docs/protocol/profile-matrix.md) |
| Ecosystem client onboarding | [docs/features/ecosystem-onboarding.md](docs/features/ecosystem-onboarding.md) |
| Threat model | [docs/security/threat-model.md](docs/security/threat-model.md) |
| 发布安全 | [docs/operations/release-security.md](docs/operations/release-security.md) |
| PostgreSQL 和 Valkey 运维 | [docs/operations/ha-operations.md](docs/operations/ha-operations.md) |
| Resource server verifier | [docs/features/resource-server-verifier.md](docs/features/resource-server-verifier.md) |
| SCIM | [docs/features/scim.md](docs/features/scim.md) |
| Federation | [docs/features/federation.md](docs/features/federation.md) |
| Passkeys | [docs/features/passkeys.md](docs/features/passkeys.md) |
| MFA | [docs/features/mfa.md](docs/features/mfa.md) |
| 安全策略 | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## 开发

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

HTTP 和并发检查：

```sh
python scripts/full_real_request_e2e.py
python scripts/full_real_request_load.py
```

Windows coverage 见
[docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md)。

## 许可证

AGPL-3.0-or-later。详见 [LICENSE](LICENSE)。
