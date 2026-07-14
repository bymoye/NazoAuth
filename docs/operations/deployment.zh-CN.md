# 部署指南

## 范围

生产部署中，Nazo Auth Server 运行在 TLS 终止反向代理之后。PostgreSQL 保存持久状态，Valkey 保存短生命周期协议状态。公开 issuer 必须是 HTTPS origin，并与 Discovery metadata、README、OIDF 测试配置保持一致。

当前公开部署：

| 项目 | 值 |
| --- | --- |
| Issuer | `https://auth.nazo.run` |
| 前端 UI | `https://auth.nazo.run/ui/` |
| Health | `https://auth.nazo.run/health` |
| Discovery | `https://auth.nazo.run/.well-known/openid-configuration` |

## 部署模型

必要组件：

- `nazo-oauth-server` HTTP 进程
- `nazo-oauth-migrate` 数据库迁移命令
- PostgreSQL 数据库
- Valkey 实例
- 持久化 JWT key 目录
- 持久化头像目录
- HTTPS 反向代理

服务本身监听 HTTP，通常是 `0.0.0.0:8000`。反向代理负责公开 HTTPS issuer。

## 上线前检查

1. 创建 PostgreSQL 数据库和用户。
2. 创建 Valkey 实例，并确定持久化 / HA 策略。
3. 分配持久化数据目录。
4. 在仓库之外创建 `.env.yaml`。
5. 将 `PUBLIC_BASE_URL` 设置为精确公开 HTTPS origin，不带结尾斜杠。
6. `TRUSTED_PROXY_CIDRS` 只包含你控制的反向代理地址。
7. 在代理正确清洗 forwarded headers 之前，保持 `CLIENT_IP_HEADER_MODE=none`。
8. 先执行迁移，再切流量。

## 配置基线

```yaml
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "https://auth.nazo.run"
DATABASE_URL: "postgresql://nazo_oauth:<password>@postgres.example.internal:5432/oauth"
VALKEY_URL: "redis://valkey.example.internal:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<random 32+ byte secret>"
AUTHORIZATION_SERVER_PROFILE: "oauth2-baseline"
TRUSTED_PROXY_CIDRS: "10.0.0.0/24"
CLIENT_IP_HEADER_MODE: "forwarded"
RUST_LOG: "info"
```

不要把生产 secret 提交到 Git。非 loopback issuer 必须显式配置
`CLIENT_SECRET_PEPPER`；它用于保护已存储的 confidential-client secret，
并且重启后必须保持稳定。

`ISSUER`、`FRONTEND_BASE_URL`、`CORS_ALLOWED_ORIGINS`、`COOKIE_SECURE`、
`PASSKEY_ORIGIN`、`PASSKEY_RP_ID`、`JWK_KEYS_DIR`、`AVATAR_STORAGE_DIR`
默认由 `PUBLIC_BASE_URL` 和 `DATA_DIR` 派生。高级配置见
[configuration.md](configuration.md)。

## Profile 选择

`AUTHORIZATION_SERVER_PROFILE=fapi2-security` 只适用于能满足以下要求的 client 群体：

- confidential-client-only
- PAR-only authorization request
- PKCE S256
- `private_key_jwt` 或 mTLS client authentication
- DPoP 或 mTLS sender-constrained token

当 signed request object 是强制要求时，使用 `fapi2-message-signing-authz-request`；当所有授权响应都必须签名时，使用 `fapi2-message-signing-jarm`；当需要 RFC 9701 signed introspection 和 nested encrypted introspection response 时，使用 `fapi2-message-signing-introspection`。Discovery metadata 会反映当前 profile；除非配置了可信代理，否则不会发布 mTLS 能力。

## 构建和运行容器

构建镜像：

```sh
docker build -f Containerfile -t nazo-oauth-server:$(git rev-parse --short=7 HEAD) .
```

执行迁移：

```sh
docker run --rm \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-migrate
```

启动服务：

```sh
docker run -d --name nazo-oauth-server \
  --network <deployment-network> \
  -v /opt/nazo-oauth/.env.yaml:/app/.env.yaml:ro \
  -v /opt/nazo-oauth/runtime/keys:/var/lib/nazo_oauth/keys:rw \
  -v /opt/nazo-oauth/runtime/avatars:/var/lib/nazo_oauth/avatars:rw \
  nazo-oauth-server:<tag> \
  nazo-oauth-server
```

`compose.yml` 面向本地集成，不是完整生产拓扑。

## 在线部署脚本

仓库提供 [scripts/deploy_live.ps1](../../scripts/deploy_live.ps1)。脚本要求后端和前端 worktree 均干净且 HEAD 与指定完整 SHA 一致，并固定核对分支 `codex/modular-workspace-architecture` 以及精确 HTTPS origin `https://github.com/nazozero/NazoAuth[.git]`、`https://github.com/nazozero/NazoAuthWeb[.git]`。它读取前端已提交的 `packageManager`，要求匹配的 `package-lock.json` 和精确 npm 版本，执行 `npm ci` 及 `package.json` 中实际存在的聚合验证脚本，只接受该门禁生成的 `dist`。随后脚本校验 `dist` 摘要，从已验证的后端 worktree 构建镜像，并在远端加载后再次校验不可变 image ID。UI release 发布到 Angie worker 可遍历的独立静态目录，并在切换前后以 worker 身份校验可读性。切换应用容器前，脚本会为应用、PostgreSQL 和 Valkey 设置 `unless-stopped` restart policy，并启用 `podman-restart.service`，从而覆盖进程退出和主机重启两类恢复场景。远端事务状态持久化后立即启动独立于 SSH 会话的 watchdog，因此租约覆盖制品 staging、镜像加载、数据库迁移、容器切换和公网验证；只有公网 health、discovery、`/ui/auth` 及其引用的至少一个 `/ui/assets/...` 制品全部返回非空 HTTP 200 后，部署才会提交租约。

默认 live 假设：

| 设置 | 默认值 |
| --- | --- |
| 远端主机 | 必填 `-RemoteHost` 参数 |
| 后端 commit | 必填完整 `-BackendCommit` SHA |
| 前端 commit | 必填完整 `-FrontendCommit` SHA |
| 后端 worktree | 默认 `.`，必须干净且位于后端 commit |
| 前端 worktree | 默认发现 sibling `NazoAuthWeb`，也可用 `-LocalFrontendWorktree` 指定；必须干净且位于前端 commit |
| 容器名 | `nazo-oauth-server` |
| 网络 | `nazo_oauth_net` |
| 网络 subnet | `10.101.0.0/24` |
| 网络 gateway | `10.101.0.1` |
| 容器 IP | `10.101.0.20` |
| 宿主机端口发布 | 默认不发布；Angie 直接反代容器 IP |
| 远端配置 | `/opt/nazo-oauth/.env.yaml` |
| Keys 路径 | `/opt/nazo-oauth/runtime/keys` |
| Avatars 路径 | `/opt/nazo-oauth/runtime/avatars` |
| Health URL | `https://auth.nazo.run/health` |
| Discovery URL | `https://auth.nazo.run/.well-known/openid-configuration` |
| Expected issuer | `https://auth.nazo.run` |
| UI 路径 | `/usr/local/angie/html/auth/ui` |
| UI release | `/usr/local/angie/html/auth-releases/<frontend-sha>` |
| Angie worker | `www` |
| 公网 UI 探针 | `https://auth.nazo.run/ui/auth` 及其引用的一个 `/ui/assets/...` 制品 |
| 验证租约 | 默认 120 秒，可通过 `-VerificationLeaseSeconds` 调整 |
| 部署记录 | `/opt/nazo-oauth/deployments/<backend-sha>-<frontend-sha>-<deployment-id>.json` |

示例：

```powershell
pwsh scripts/deploy_live.ps1 `
  -RemoteHost <ssh-host> `
  -BackendCommit (git rev-parse HEAD) `
  -FrontendCommit (git -C $frontendWorktree rev-parse HEAD) `
  -LocalBackendWorktree . `
  -LocalFrontendWorktree $frontendWorktree `
  -LocalUiDist (Join-Path $frontendWorktree dist)
```

省略 `-LocalFrontendWorktree` 时脚本会从解析后的后端 Git 根目录发现 sibling
`NazoAuthWeb` 仓库；无论自动发现还是显式指定，脚本都会核对 origin、branch、HEAD 和
工作区状态（包括未跟踪文件）。脚本不会依赖本机绝对路径，也不会接受只是同名但 remote
不匹配的目录。前端包管理器必须以仓库实际提交的 lockfile 为准，验证命令必须来自
`package.json` 中真实存在的 scripts；不得假设存在 `npm test`。若缺少必要的 lint、单元测试、
浏览器安全、delivery 或 build gate，应先在前端仓库补充真实检查，不能静默跳过。
生产部署禁止使用 `-SkipBuild` 或
`-SkipFrontendBuild`，这两个参数只用于测试中渲染远端脚本。每次部署使用
backend SHA、frontend SHA 和 deployment ID 组成唯一记录文件名，不会覆盖既有成功记录；
`current.json` 通过临时 symlink 和 `mv -T` 原子切换。

只有旧不可变镜像、UI target、部署指针和应用 health 全部恢复并验证成功，脚本才会写入
`rolled-back` 并清理事务。任一步骤失败都会非零退出、写入 `rollback-failed`，且保留 state、
远端脚本、lease marker、active owner 和部署记录供人工恢复。state 使用 schema 校验的 JSON，
通过同目录 mode `0600` 临时文件完整写入后原子 rename；缺失、部分写入、损坏或 owner 不匹配
均 fail closed。

该脚本通过指定的 SSH 目标部署 `auth.nazo.run` 环境。迁移到其他主机前，必须重新检查监听器、反向代理、容器网络、TLS 设置和 expected issuer。

### 固定内网 IP 与 Angie 反代

`auth.nazo.run` live 路径固定使用 Podman bridge 网络 `nazo_oauth_net`、subnet
`10.101.0.0/24`、gateway `10.101.0.1`，应用容器固定为
`10.101.0.20`。部署脚本要求现有网络的 subnet/gateway 精确匹配（存在额外或不同
subnet 时 fail closed），启动容器后校验实际 IP，并从宿主机直连
`http://10.101.0.20:8000/health` 和 discovery。

Angie 配置应直接反代到固定容器 IP，不再依赖 `127.0.0.1:8000` 端口发布：

```nginx
proxy_pass http://10.101.0.20:8000;
```

如果 Angie 与应用同在宿主机，应用看到的可信代理来源通常是 bridge gateway
`10.101.0.1`；`TRUSTED_PROXY_CIDRS` 应只包含该地址或实际受控代理地址，例如
`10.101.0.1/32`。不要把不受控的容器网段整体加入可信代理范围。

## 反向代理边界

反向代理要求：

- 使用公开 issuer 域名终止 TLS。
- 禁用 TLS 1.0 和 TLS 1.1；公开 issuer 监听器只允许 TLS 1.2 或 TLS 1.3。
- 只向应用转发经过清洗的代理头。
- 删除客户端传入的 `Forwarded`、`X-Forwarded-*`、mTLS 和证书相关头，再由代理写入可信值。
- `TRUSTED_PROXY_CIDRS` 只包含允许转发 client IP 和 mTLS 证书信息的代理地址。
- 保护代理到应用之间的链路；转发证书元数据只在可信内部通道上有意义。
- 保持 OAuth endpoint 路径精确不变。
- 禁止协议端点被错误缓存，除非端点明确可缓存。
- 确保 `/.well-known/openid-configuration`、`/.well-known/oauth-authorization-server`、`/.well-known/oauth-protected-resource`、`/.well-known/oauth-protected-resource/fapi/resource`、`/jwks.json`、`/authorize`、`/par`、`/token`、`/userinfo`、`/introspect`、`/revoke` 可按预期访问。

mTLS sender constraint 和 mTLS client authentication 依赖可信反向代理完成客户端证书校验，并转发证书证据。应用只接受来自 `TRUSTED_PROXY_CIDRS` 的证书元数据；其他来源视为没有已验证证书。

## 密钥轮换

首次启动时，如果 keyset 不存在，服务会创建本地 RS256 签名密钥。本地 PEM
keyset 在服务启动和 keyset 加载时自动维护生命周期：active key 进入预发布窗口后，
服务通过进程内生命周期任务定期刷新运行时 keyset 快照；active key 进入预发布窗口后，
服务会生成并发布下一把本地 key；预发布窗口结束且 active key 到达轮换周期后，服务
自动激活下一把 key；上一把 active key 会继续发布到 JWKS，直到
`max(ACCESS_TOKEN_TTL_SECONDS, ID_TOKEN_TTL_SECONDS)` 对应的宽限窗口结束。

默认生命周期配置：

- `SIGNING_KEY_ROTATION_INTERVAL_SECONDS=7776000`（90 天）
- `SIGNING_KEY_PREPUBLISH_SECONDS=86400`（1 天）

预发布窗口必须为正数，并且必须短于轮换周期。运行时刷新间隔由预发布窗口派生，最长
不超过一小时。部署或恢复备份后可校验 keyset：

```sh
nazo-oauth-keyctl validate
```

`validate` 会拒绝格式错误的 `retire_at`，也会拒绝 active key 携带
`retire_at`。应定期备份 key 目录。丢失 active private key 会破坏 token 签名连续性。

## 数据库和 Valkey

PostgreSQL 保存用户、client、grant、token、撤销状态等持久数据。生产要求：

- 自动备份
- 恢复演练
- migration rollback 计划
- 复制延迟和存储容量监控

迁移 `20260712000050_social_federation_provider_type` 只扩展外部身份 provider
约束，不改变已有 OIDC / SAML link。只要仍存在 `oauth2_social` link，其 down
迁移就会按设计失败；回滚前必须先迁移或明确删除这些 link，避免静默丢失联合身份。
`20260712000100` 时间戳继续保留给 runtime desired-state 迁移。

Valkey 保存短生命周期 session、授权码、PAR handle、DPoP / client assertion replay 状态和 rate limit counter。生产要求：

- 有界内存策略
- 延迟监控
- 与风险模型匹配的持久化或 HA
- 明确的故障处理预期

Valkey 不可用时，敏感协议路径应 fail closed，以 OAuth error 返回，而不是降低 replay 或 rate limit 保护。

## 部署后验证

```sh
curl -fsS https://auth.nazo.run/health
curl -fsS https://auth.nazo.run/.well-known/openid-configuration
curl -fsS https://auth.nazo.run/.well-known/oauth-authorization-server
curl -fsS https://auth.nazo.run/.well-known/oauth-protected-resource
curl -fsS https://auth.nazo.run/.well-known/oauth-protected-resource/fapi/resource
curl -fsS https://auth.nazo.run/jwks.json
```

检查 discovery 的 `issuer` 必须精确等于 `PUBLIC_BASE_URL`，除非显式覆盖了
`ISSUER`。

若启用实验性的 FAPI HTTP Signatures 资源 profile，还必须发送带签名的 GET、POST
探针，并使用当前服务端 JWKS 验证响应签名；method、target URI、Authorization、
DPoP、body、时间、重放、client 与 key 任一被篡改时都应 fail closed。只有在 client
JWK 轮换、时钟监控、Valkey 重放存储、服务端签名密钥托管和证据留存均有明确责任人后，
才可开启该开关。此 profile 默认关闭、不发布 metadata，且当前没有 OIDF 专用测试计划。

## OIDF 准备

启动 OpenID Foundation conformance run 前，固定按以下顺序执行，不从失败的 run
里倒推 seed 输入：

1. 确定要测的精确 commit，要求工作区干净且没有混入无关部署补丁。修改生产前，先保留
   当前不可变镜像、UI release、部署记录、数据库备份及其他可验证回滚所需材料。
2. 对该精确 head 运行 `oidf-public-seed-configs` workflow，并下载
   `oidf-public-plan-configs` artifact。该 artifact 同时包含公开 plan JSON、
   `oidf-mtls-ca-bundle.pem` 以及绑定 source commit、文件树与 CA DER 指纹的确定性 manifest，
   绝不包含 mTLS 私钥。关联保存 workflow run ID、workflow head SHA、平台 artifact digest、
   下载后 artifact digest、manifest digest 和 CA bundle digest；artifact
   head 与待部署 commit 不一致时必须拒绝。
3. 确认 Angie 已反代到固定容器 IP `10.101.0.20:8000`，且 `.env.yaml`
   的可信代理范围只包含实际受控代理地址。
4. 使用 `scripts/deploy_live.ps1 -OidfPublicSeedArtifactArchive <下载后的-artifact.zip>
   -OidfPublicSeedWorkflowRunId <run-id>
   -OidfPublicSeedArtifactId <artifact-id> -OidfPublicSeedArtifactDigest sha256:<digest>` 将同一 commit
   部署到公网入口。真实部署强制提供全部 artifact 身份参数；脚本先核验 GitHub run 结果、分支、
   head、artifact 身份和下载归档 digest，解压到私有快照，并要求 manifest head 等于 backend
   commit。随后现有部署事务共同验证公开 JSON 与 CA bundle，将暂存和安装后的 bundle 绑定到同一
   SHA-256 digest，备份当前 Angie CA 文件及 hash，在同目录原子替换，校验并 reload Angie；部署或
   验证回滚时恢复原字节和文件元数据。`-OidfPublicSeedArtifactDirectory` 仅供 render-only 测试夹具
   使用。整个过程沿用现有部署锁和 verification lease，不得建立独立的手工 CA 安装通道。
5. 将同一个精确 artifact 放到 live 环境的 OIDF runtime 目录，并使用同一 commit 的
   `oidf-seed` image / `nazo_oauth_seed_oidf` binary，对公网入口
   `auth.nazo.run` 实际使用的数据库执行 seed。不要 seed
   `compose.oidf.local.yml` 的 9443 专用栈后去跑官方公网测试。
6. 先核对实际运行 head、artifact digest 和 CA bundle digest，再从公网校验 health、
   discovery、JWKS、mTLS alias、证书转发和 Angie 配置；discovery `issuer` 必须是
   `https://auth.nazo.run`。信任来源必须是精确 head artifact 中经过验证的 CA chain，
   不得改用叶证书 fingerprint allowlist。
7. 先运行 `.github/workflows/oidf-conformance.yml` 的单 plan。单 plan workflow
   默认关闭 early-stop monitor，以便失败时上传完整 artifact。
8. 单 plan 通过后，才运行 `.github/workflows/oidf-conformance-full.yml` 全矩阵。默认全矩阵保持
   `OIDF_NO_PARALLEL=true`。如需验证 runner 并发，使用 `runner_mode=parallel-isolated`
   触发同一 workflow；该模式会让并发安全的 plan set 不带 `--no-parallel` 执行，同时把
   logout 和 session-management 放到独立 matrix job 中运行，使它们拥有独立 runner/浏览器环境。
9. 在 artifact 过期前保存最终结果到 `docs/conformance`，并关联保存 deployed head、
   workflow run 与 plan ID、artifact digest、CA bundle digest 和最终 PR Checks head。

## 运维检查清单

- 生产只使用 HTTPS issuer。
- 同域 `PUBLIC_BASE_URL`。
- Secure cookie 已启用。HTTPS `PUBLIC_BASE_URL` 会默认开启。
- CORS 暴露最小化。
- 严格限制可信代理 CIDR。
- 不存在 proxy header spoofing 路径。
- PostgreSQL 备份与恢复演练完成。
- Valkey 可用性和内存受监控。
- 签名密钥备份和轮换计划明确。
- 审计日志被采集和保留。
- 管理员账号完成加固。
- 发布流程保留 SBOM、镜像签名和 provenance attestation。
- OIDF conformance 证据在 artifact 过期前更新。
