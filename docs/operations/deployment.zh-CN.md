# 部署指南

NazoAuth 在所有受支持的操作平台上使用同一套 Docker Compose 接口。特定宿主机
的发布脚本只是内部实现，不属于对外部署契约。

## 快速开始

只需要：

- Docker Engine，或兼容 Compose 的容器运行时；
- Docker Compose v2。

在仓库根目录执行：

```sh
docker compose up -d --build
docker compose ps
```

Compose 会启动 PostgreSQL 和 Valkey，执行一次 `nazoauth migrate`，然后启动
`nazoauth server`。可直接打开：

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/.well-known/openid-configuration`

首次源码构建需要联网下载 Rust 依赖；后续构建会复用本地容器缓存。

默认配置只用于 loopback 本地体验。PostgreSQL、Valkey、签名密钥和头像均使用
命名卷，执行 `docker compose down` 后仍会保留。除非明确要删除全部本地数据，
不要执行 `docker compose down -v`。

## 公开部署

以 `.env.yaml.example` 为基础创建私有 `.env.yaml`，再通过 Compose 变量
`NAZOAUTH_CONFIG` 选择该文件。至少修改：

```yaml
PUBLIC_BASE_URL: "https://auth.example.com"
DATABASE_URL: "postgresql://<user>:<password>@postgres:5432/oauth"
VALKEY_URL: "redis://valkey:6379/0"
DATA_DIR: "/var/lib/nazo_oauth"
CLIENT_SECRET_PEPPER: "<至少 32 字节且长期稳定的随机秘密>"
RUST_LOG: "info"
```

新部署不需要选择单一的全局授权服务器 profile；提升后的行为由运行时模块与
显式的按客户端 `security_policy` 配置。

该文件不得进入版本控制。`PUBLIC_BASE_URL` 必须是用户实际访问的 HTTPS origin，
且不带结尾斜杠。`CLIENT_SECRET_PEPPER` 在重启和升级后必须保持不变。
如果继续使用 Compose 内置 PostgreSQL，还必须让 `POSTGRES_DB`、
`POSTGRES_USER`、`POSTGRES_PASSWORD` 与 `DATABASE_URL` 一致；密码在 URL 中
需要进行百分号编码。生产环境更适合使用独立管理的 PostgreSQL 和 Valkey。

仍然使用同一个启动命令：

```sh
docker compose up -d --build
docker compose ps
```

Compose 只把 NazoAuth 发布到宿主机 loopback 的 `8000` 端口。可使用任意符合要求
的 TLS 反向代理，把公开 HTTPS 流量转发到 `http://127.0.0.1:8000`。
`TRUSTED_PROXY_CIDRS` 只能包含受控代理地址；在代理正确清洗 forwarded headers
之前，保持 `CLIENT_IP_HEADER_MODE=none`。

宿主机端口需要变化时设置 `NAZOAUTH_PORT`。该变量只改变本机监听端口，不改变
issuer；`PUBLIC_BASE_URL` 仍必须等于客户端看到的公开 HTTPS 地址。

## 验证

满足以下条件后才算启用：

1. `docker compose ps` 显示 PostgreSQL、Valkey 和 `server` 正常运行；
2. 一次性 `migrate` 服务成功退出；
3. `/health` 返回 HTTP 200；
4. `/.well-known/openid-configuration` 返回配置的 issuer；
5. 反向代理通过公开 HTTPS origin 提供相同接口；
6. 服务重启后签名密钥和头像卷仍保持挂载。

失败时查看：

```sh
docker compose logs migrate
docker compose logs server
```

## 升级和回滚

升级：

```sh
docker compose build --pull
docker compose up -d
docker compose ps
```

Compose 会先运行迁移，再替换服务。生产版本应固定到已审查的镜像 digest 或精确
源码提交，不能依赖无边界 tag。

应用回滚时恢复上一个镜像或源码版本，再执行 `docker compose up -d`。数据库回滚
是独立操作：迁移可能只能向前，因此每次生产升级前必须创建并验证 PostgreSQL
备份。

## 生产边界

仓库内置的是单节点拓扑。用于生产前还需要：

- 替换示例数据库凭据；
- 建立可验证的备份和恢复流程；
- 监控 PostgreSQL、Valkey、磁盘空间和 `/health`；
- 将签名密钥和头像放在持久存储上；
- 需要 HA 时改用外部 PostgreSQL/Valkey 或编排平台；
- 对精确提交执行
  [release-security.md](release-security.md) 中的安全与一致性闸门。

如需有意清空数据面并以 OIDF 作为启用闸门，请使用
[全新环境部署与生产启用](fresh-production-activation.zh-CN.md)。高级配置见
[configuration.md](configuration.md)。
