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

仓库提供 [scripts/deploy_live.ps1](../../scripts/deploy_live.ps1)，用于构建镜像、传输到远端、执行迁移、替换 Podman 容器，并校验 health 与 discovery。

默认 live 假设：

| 设置 | 默认值 |
| --- | --- |
| 远端主机 | 必填 `-RemoteHost` 参数 |
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

示例：

```powershell
pwsh scripts/deploy_live.ps1 `
  -RemoteHost <ssh-host> `
  -ImageRepository localhost/nazo-oauth-server `
  -ImageTag main-$(git rev-parse --short=7 HEAD)
```

该脚本通过指定的 SSH 目标部署 `auth.nazo.run` 环境。迁移到其他主机前，必须重新检查监听器、反向代理、容器网络、TLS 设置和 expected issuer。

### 固定内网 IP 与 Angie 反代

`auth.nazo.run` live 路径固定使用 Podman bridge 网络 `nazo_oauth_net`、subnet
`10.101.0.0/24`、gateway `10.101.0.1`，应用容器固定为
`10.101.0.20`。部署脚本会创建或校验该网络，启动容器后校验实际 IP，并从宿主机直连
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

## OIDF 准备

启动 OpenID Foundation conformance run 前，固定按以下顺序执行，不从失败的 run
里倒推 seed 输入：

1. 确定要测的精确 commit，并确认工作区没有混入无关部署补丁。
2. 确认 Angie 已反代到固定容器 IP `10.101.0.20:8000`，且 `.env.yaml`
   的可信代理范围只包含实际受控代理地址。
3. 使用 `scripts/deploy_live.ps1` 部署同一 commit 到公网入口；该步骤会执行
   migration，并确认 Podman 容器 IP 为 `10.101.0.20`。
4. 运行 `oidf-public-seed-configs` workflow，下载 `oidf-public-plan-configs`
   artifact；这是服务端 seed 的唯一官方同源输入。
5. 将该 artifact 放到 live 环境的 OIDF runtime 目录，并使用同一 commit 的
   `oidf-seed` image / `nazo_oauth_seed_oidf` binary，对公网入口
   `auth.nazo.run` 实际使用的数据库执行 seed。不要 seed
   `compose.oidf.local.yml` 的 9443 专用栈后去跑官方公网测试。
6. 从公网校验 health、discovery、JWKS、mTLS alias 和证书转发；discovery
   `issuer` 必须是 `https://auth.nazo.run`。
7. 先运行 `.github/workflows/oidf-conformance.yml` 的单 plan。单 plan workflow
   默认关闭 early-stop monitor，以便失败时上传完整 artifact。
8. 单 plan 通过后，才运行 `.github/workflows/oidf-conformance-full.yml` 全矩阵。默认全矩阵保持
   `OIDF_NO_PARALLEL=true`。如需验证 runner 并发，使用 `runner_mode=parallel-isolated`
   触发同一 workflow；该模式会让并发安全的 plan set 不带 `--no-parallel` 执行，同时把
   logout 和 session-management 放到独立 matrix job 中运行，使它们拥有独立 runner/浏览器环境。
9. 在 artifact 过期前保存最终结果到 `docs/conformance`。

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
