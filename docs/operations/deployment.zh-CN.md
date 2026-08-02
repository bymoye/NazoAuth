# 部署指南

NazoAuth 提供两条明确的部署契约：源码开发使用 Compose；独立 Linux 生产部署
使用经过签名验证的 `nazoauthctl`，支持 Podman、Docker 和宿主机 systemd。

## 源码树开发沙箱

只需要：

- Docker Engine，或兼容 Compose 的容器运行时；
- Docker Compose v2。

在仓库根目录执行：

```sh
docker compose up -d --build
docker compose ps
```

Compose 将初始化脚本和安全默认配置随构建上下文放入镜像，不要求 Docker daemon
能够直接读取 CLI 所在主机的源码绝对路径。使用远端 Docker context 或容器化 WebIDE
时仍不得添加手工秘密初始化步骤。需要改变宿主机端口和浏览器看到的公开 origin 时执行：

```sh
NAZOAUTH_PORT=443 \
NAZOAUTH_BIND_ADDRESS=0.0.0.0 \
NAZOAUTH_PUBLIC_BASE_URL=https://auth.example.com \
NAZOAUTH_BUILD_REVISION="$(git rev-parse HEAD)" \
NAZOAUTH_BUILD_ID="source:$(git rev-parse HEAD)" \
docker compose up -d --build
```

这仍是源码开发沙箱，不是经过签名 attestation 验证的正式 Release 安装。

当容器化 WebIDE 或平台端口映射通过非 loopback 接口访问宿主机发布端口时，必须设置
`NAZOAUTH_BIND_ADDRESS=0.0.0.0`。如果由同一宿主机上的反向代理终止 TLS，则保留默认的
`127.0.0.1`。只有平台或防火墙能够限制明文端口的直接访问时，才能绑定所有接口。

Compose 会先在私有命名卷中生成 PostgreSQL 和 Valkey 凭据，再启动两项服务，并用
短生命周期的开发 operator identity 通过同一个签名 `nazoauth operator-task` 入口执行
迁移。该 identity 明确不是生产信任根。任务把本地自动化 actor 标识为
`docker-compose`，并把预期 embedded release、revision 和 build ID 绑定到编译镜像时使用的
同一组值；它不会联系或冒充 GitHub Actions。可直接打开：

- `http://127.0.0.1:8000/ready`：依赖就绪探针
- `http://127.0.0.1:8000/live`：进程存活探针
- `http://127.0.0.1:8000/.well-known/openid-configuration`

首次源码构建需要联网下载 Rust 依赖；后续构建会复用本地容器缓存。

默认配置只用于 loopback 本地体验。PostgreSQL、Valkey 和应用状态（包括签名密钥、头像、
生成的秘密、bootstrap 状态及 UI release 缓存）均使用命名卷，执行
`docker compose down` 后仍会保留。除非明确要删除全部本地数据，不要执行
`docker compose down -v`。

新数据库没有管理员时，服务会在私有 bootstrap 状态中创建限时、单次使用的 token，
但不会打印 token 或携带 token 的 URL。正式受管流程通过 `nazoauthctl bootstrap-admin`
验证并读取私有的 runtime-owned 状态；授权服务器只暴露 JSON `POST /auth/bootstrap-admin` API，不再提供
后端内嵌初始化页面。

## 公开部署

正式发布优先使用生命周期入口：

```sh
sudo nazoauthctl install \
  --runtime auto \
  --public-url https://auth.example.com
sudo nazoauthctl bootstrap-admin
```

`auto` 优先使用 Podman，其次使用 Docker。已有 PostgreSQL/Valkey、宿主机安装、
秘密生成和备份边界见[一键安装与升级](one-click-update.zh-CN.md)。

`nazoauthctl` 自动生成私有服务配置、依赖凭据、deployment identity、签名 identity
和恢复状态，并只把 NazoAuth 发布到选定的宿主机 loopback 端口。可使用任意符合要求
的 TLS 反向代理，把公开 HTTPS 流量转发到 `http://127.0.0.1:8000`。
`TRUSTED_PROXY_CIDRS` 只能包含受控代理地址；在代理正确清洗 forwarded headers
之前，保持 `CLIENT_IP_HEADER_MODE=none`。

宿主机端口需要变化时设置 `NAZOAUTH_PORT`。该变量只改变本机监听端口，不改变
issuer；`PUBLIC_BASE_URL` 仍必须等于客户端看到的公开 HTTPS 地址。

## 验证

满足以下条件后才算启用：

1. `sudo nazoauthctl status` 报告签名 Release 和双层 target identity；
2. `sudo nazoauthctl doctor` 验证审计、readiness、target digest 和 runtime DDL 边界；
3. `/ready` 返回 HTTP 200；
4. `/.well-known/openid-configuration` 返回配置的 issuer；
5. 反向代理通过公开 HTTPS origin 提供相同接口；
6. 服务重启后签名密钥和头像卷仍保持挂载。

查看脱敏后的部署与审计状态：

```sh
sudo nazoauthctl status
sudo nazoauthctl audit show
```

## 升级和回滚

正式发布的独立安装使用同一个生命周期入口：

```sh
sudo nazoauthctl update
```

该命令校验标签级 Sigstore 身份和不可变制品摘要，创建恢复备份，执行迁移，
替换应用，检查 readiness 与公网 Discovery；验证失败时自动恢复旧应用镜像和
应用持久目录。完整边界见[一键安装与升级](one-click-update.zh-CN.md)。

源码 Compose 仍可用于开发，但不再是生产环境的日常升级路径。数据库恢复保持
独立，因为迁移可能是单向的；只有签名发布明确声明迁移集合可重新启动上一应用
版本时，更新器才接受自动应用回滚。

## 生产边界

仓库内置的是单节点拓扑。用于生产前还需要：

- 备份 Compose 自动生成的数据库、Valkey 和应用秘密，或接入外部秘密管理；
- 建立可验证的备份和恢复流程；
- 监控 PostgreSQL、Valkey、磁盘空间和 `/ready`；仅用 `/live` 判断是否应重启进程；
- 将签名密钥和头像放在持久存储上；
- 需要 HA 时改用外部 PostgreSQL/Valkey 或编排平台；
- 对精确提交执行
  [release-security.md](release-security.md) 中的安全与一致性闸门。

如需有意清空数据面并以 OIDF 作为启用闸门，请使用
[全新环境部署与生产启用](fresh-production-activation.zh-CN.md)。高级配置见
[configuration.md](configuration.md)。
