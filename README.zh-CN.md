<p align="center">
  <img src="docs/assets/nazo-auth-cover.png" alt="Nazo Auth 封面">
</p>

# Nazo Auth Server

[![code-quality](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/code-quality.yml)
[![codeql](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/codeql.yml)
[![dependency-review](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/dependency-review.yml)
[![conformance-security](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml/badge.svg?branch=main)](https://github.com/nazozero/NazoAuth/actions/workflows/conformance-security.yml)
[![codecov](https://codecov.io/gh/nazozero/NazoAuth/branch/main/graph/badge.svg)](https://app.codecov.io/gh/nazozero/NazoAuth)

[English](README.md) · [文档](#文档) · [快速启动](#快速启动) · [安全策略](SECURITY.md)

Nazo Auth Server 是一个用 Rust 写的自托管 OAuth 2.x / OAuth 2.1-aligned / OpenID Connect 授权服务器。它面向同域部署：issuer、浏览器 UI、passkey、CORS、cookie 和协议端点共享同一个公开 origin。

项目包含授权服务器、小型 identity/admin 管理面、本地签名密钥管理、WebAuthn/passkeys、MFA、SCIM，以及 Rust resource-server verifier。模块化第三方 provider 登录属于未来路线图能力，不作为当前默认能力广告。PostgreSQL 保存持久状态，Valkey 保存短生命周期协议状态。

## 状态

| 项目 | 值 |
| --- | --- |
| 包名 | `nazo-oauth-server` |
| Workspace 版本 | `0.2.3` |
| 许可证 | AGPL-3.0-or-later |
| 语言 | Rust 2024 |
| 运行依赖 | PostgreSQL、Valkey |
| 一致性测试 issuer | 操作者提供的公网 HTTPS origin |
| 默认部署模型 | 同域 |

## 质量信号

项目质量用直接、可审计的检查来表达，不使用综合评分：

| 信号 | 证据 |
| --- | --- |
| Rust 质量门禁 | `code-quality` 中的 `cargo fmt --check`、`cargo check --workspace --all-targets --all-features --locked`、`cargo clippy -D warnings`、迁移和完整 workspace tests。 |
| 静态安全分析 | CodeQL Rust analysis，启用 `security-extended` 和 `security-and-quality` queries。 |
| 依赖策略 | GitHub dependency review、`cargo audit`、`cargo deny`，覆盖 advisories、bans、licenses 和 sources。 |
| 运行时安全行为 | `conformance-security` 中的真实 HTTP E2E、load/race gate、Valkey outage injection。 |
| 外部协议一致性 | NazoAuthCtl 负责已签名 Suite 制品、外部执行、证据与清理；服务端只通过公开协议和 tenant-resource 接口接受黑盒验证。 |
| 覆盖率趋势 | 专用 coverage workflow 上传 Codecov LCOV。 |
| 发布来源证明 | CycloneDX SBOM、Trivy image scan、Sigstore signing、GitHub artifact attestations。 |

## 标准

📚 [标准与 Profile 支持](docs/integration/openid-connect.zh-CN.md)

## 认证

🏅 一致性套件由 NazoAuthCtl 作为外部黑盒控制器执行。

## 功能

- Authorization code + PKCE、refresh token、client credentials、受限 JWT bearer grant、受限 Token Exchange、revocation、introspection、signed/encrypted introspection、discovery、protected resource metadata、JWKS、JSON/signed/encrypted UserInfo、signed/encrypted JARM、PAR、JAR、DPoP、mTLS。
- Runtime profile：`oauth2-baseline`、`fapi2-security`、`fapi2-message-signing-authz-request`、`fapi2-message-signing-jarm`、`fapi2-message-signing-introspection`。
- 本地用户、资料、OAuth client、grant、access request、TOTP MFA、backup code、remembered MFA、WebAuthn/passkeys、SCIM provisioning。
- 本地签名密钥生命周期，包含 prepublish、active、grace、retired 状态。也可以用 external-command signer 接 KMS/HSM。
- 与 Web 框架无关的 Rust resource-server verifier，以及项目使用的 Actix
  HTTP 集成；不再提供历史 Axum/Tower 和 tonic adapter。
- 发布安全 workflow：CodeQL、dependency review、cargo audit、cargo deny、SBOM、Trivy image scanning、keyless signing、provenance attestation。

## 快速开始

先按[已验证的 bootstrap 流程](docs/operations/one-click-update.zh-CN.md)从不可变
GitHub Release 安装签名的 `nazoauthctl`，然后执行：

```sh
nazoauthctl host add production-host --ssh production --privilege sudo
nazoauthctl install --host production-host --name production \
  --public-url https://auth.example.com --runtime podman \
  --database-host db.internal --database-port 5432 --database-name oauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password
nazoauthctl bootstrap-admin --instance production
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl status --instance production
nazoauthctl doctor --instance production
```

runtime 必须明确选择 `podman`、`docker` 或 `host`。NazoAuthCtl 不会为外部
PostgreSQL 或 Valkey 创建凭据。lifecycle PostgreSQL role 负责迁移、备份与恢复；
长期运行服务只拿权限更低的 runtime role。目标机私有边界可检查
`http://127.0.0.1:8000/health` 和
`http://127.0.0.1:8000/.well-known/openid-configuration`。数据、签名密钥、应用
secret 和头像会持久保存。当前格式导入与备份策略见
[受管安装、更新与恢复](docs/operations/one-click-update.zh-CN.md)。

数据库还没有管理员时，`nazoauthctl bootstrap-admin` 会读取 runtime 所有、且不会被
打印的一次性 claim。交互模式只通过 TTY 提示；自动化必须通过 stdin 或专用文件描述符
提交封闭的凭据文档。token、凭据或携带 token 的 URL 都不得进入 argv、普通环境变量、
日志或审计记录。

公开部署时传入 `--public-url https://auth.example.com`；TLS 入口要求见
[部署指南](docs/operations/deployment.zh-CN.md)。`compose.yml` 仅保留为源码树开发沙箱，
使用开发 operator identity，不是生产生命周期边界。

直接运行二进制时，首次启动保护保持不变：

```sh
nazoauth server
```

如果当前目录没有 `.env.yaml`，该命令会创建最小配置，生成持久化应用秘密与签名密钥，
然后使用安全默认值继续启动。显式 YAML 和环境配置仍然优先。受管部署的 schema
变更只在精确验证 Release 的签名 install、update 或 recover 生命周期操作内执行；
长期运行的服务身份不持有 DDL 权限。

## 配置

新部署只需要少量启动配置：

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.example.com"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "disabled"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
RUST_LOG: "info"
```

不使用反向代理时，设置 `TRANSPORT_MODE: "direct-tls"`，并按
[`docs/operations/configuration.md`](docs/operations/configuration.md) 配置服务端证书、
私钥、mTLS 客户端 CA 和独立 mTLS 监听地址。

部署使用可组合的服务端能力与显式、版本化的按客户端策略。每个 OAuth client 都必须
持有当前 `security_policy`；服务不会从进程级 preset 推断缺失策略。

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

高级配置用于明确的特殊部署。详见
[docs/operations/configuration.md](docs/operations/configuration.md)。

## 默认边界

新数据库会同时开启稳定且不冲突的服务端处理器，包括签名 Request Object、
JARM、Device Grant、CIBA poll/ping、受限 Token Exchange 与 JWT Bearer
Grant、SCIM、Front-Channel Logout 和 Session Management。服务端支持不等于
客户端获权；grant allowlist、注册元数据、sender constraint 与版本化
`security_policy` 仍然默认拒绝。

以下能力仍有前提或明确排除：

- Dynamic Client Registration / RFC 7591 和 RFC 7592 需要配置非空
  `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`。
- OpenID4VCI、OpenID4VP、SCIM Security Events、Native SSO、RAR 与实验性
  HTTP Signatures 需要各自完整的角色或部署前提。
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
| 可组合能力策略 | [docs/protocol/composable-capability-policy.md](docs/protocol/composable-capability-policy.md) |
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

Coverage 运行说明见
[docs/coverage/codecov-docker-runbook.md](docs/coverage/codecov-docker-runbook.md)。

## 许可证

公开源码采用 [AGPL-3.0-or-later](LICENSE)，个人和企业遵守 AGPL 时适用同一许可。
符合条件的闭源使用可以另行签署商业许可；仓库本身不自动授予商业权利。详见
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) 和 [CONTRIBUTING.md](CONTRIBUTING.md)。
