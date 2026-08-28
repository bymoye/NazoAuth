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
NAZOAUTH_TRANSPORT_MODE=trusted-proxy \
NAZOAUTH_TRUSTED_PROXY_CIDRS=<NazoAuth实际看到的入口代理CIDR> \
NAZOAUTH_MTLS_CERTIFICATE_SOURCE=disabled \
NAZOAUTH_BUILD_REVISION="$(git rev-parse HEAD)" \
NAZOAUTH_BUILD_ID="source:$(git rev-parse HEAD)" \
docker compose up -d --build
```

这仍是源码开发沙箱，不是经过签名 attestation 验证的正式 Release 安装。

当容器化 WebIDE 或平台端口映射通过非 loopback 接口访问宿主机发布端口时，必须设置
`NAZOAUTH_BIND_ADDRESS=0.0.0.0`。如果由同一宿主机上的反向代理终止 TLS，则保留默认的
`127.0.0.1`。只有平台或防火墙能够限制明文端口的直接访问时，才能绑定所有接口。

必须把 `<NazoAuth实际看到的入口代理CIDR>` 替换为 TLS 终止入口的精确地址。Compose
路径属于 trusted-proxy 部署，不会挂载 Direct TLS 所需的服务端证书和客户端 CA 文件。

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
nazoauthctl host add production-host --ssh production --privilege sudo
nazoauthctl install \
  --host production-host --name production \
  --runtime podman --public-url https://auth.example.com \
  --database-host db.internal --database-port 5432 \
  --database-name oauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password
nazoauthctl bootstrap-admin --instance production
```

runtime 必须明确选择 `podman`、`docker` 或 `host`。两套 PostgreSQL role 与
Valkey 凭据必须已经存在；NazoAuthCtl 不会为外部服务创建凭据。目标机当前格式
数据导入与备份边界见[一键安装与升级](one-click-update.zh-CN.md)。

`nazoauthctl` 生成私有服务配置、deployment identity、签名 identity、应用 secret
和恢复状态，并只把 NazoAuth 发布到选定的宿主机 loopback 端口。可使用任意符合要求
的 TLS 反向代理，把公开 HTTPS 流量转发到 `http://127.0.0.1:8000`。
`TRUSTED_PROXY_CIDRS` 只能包含受控代理地址；在代理正确清洗 forwarded headers
之前，保持 `CLIENT_IP_HEADER_MODE=none`。

宿主机端口需要变化时设置 `NAZOAUTH_PORT`。该变量只改变本机监听端口，不改变
issuer；`PUBLIC_BASE_URL` 仍必须等于客户端看到的公开 HTTPS 地址。

### 反向代理与 mTLS

启用 RFC 8705 或完整 OIDF profile 时，TLS 终止代理必须请求客户端证书，并通过
RFC 9440 `Client-Cert` header 转交。NazoAuth 再根据客户端注册信息认证该证书；
代理不得接受公网客户端自行提交的 `Client-Cert` 或 `Client-Cert-Chain`。服务配置
使用 `MTLS_CERTIFICATE_SOURCE=rfc9440`，`TRUSTED_PROXY_CIDRS` 只填写 NazoAuth
实际看到的精确代理地址。一个宿主地址足够时，不得信任整个容器网段。

NazoAuthCtl 一致性测试每轮都会生成新的 CA 与叶证书，因此测试部署前的代理不能向
客户端公布过期的固定 client-CA 列表。开始创建 Suite module 前，必须安装本轮生成的
公开 CA bundle，并在同一次运行的 cleanup 中恢复旧 bundle。直接使用经过审查的
[`deploy/proxy/haproxy-rfc9440.cfg`](../../deploy/proxy/haproxy-rfc9440.cfg)：它把
普通 HTTPS 与 `verify required` 的独立 mTLS listener 分开，清除所有入站 forwarding
和证书 header，并且只写入从已验证 TLS peer 得到的单例 RFC 9440 `Client-Cert`。

叶证书的 subject DN 必须与 CA 的 subject DN 不同，其 issuer DN 则必须匹配该 CA。
预检必须执行 `openssl verify -CAfile run-ca.pem client.pem`；否则，不同密钥却复用同一
subject/issuer DN 的叶证书可能被 OpenSSL/HAProxy 判为自签证书并拒绝握手。

客户端证书必须能链接到本轮 active bundle。NazoAuth 仍会验证注册的 subject/SAN
和可选证书摘要。同时还必须满足：

- HAProxy 先删除公网请求中的证书 header，再写入自己从 TLS 连接取得的证书；
- 明文 upstream 只绑定 loopback，或以其他方式确保公网客户端无法直连；
- NazoAuth 只信任精确代理地址，并按已注册证书身份验证收到的叶证书；
- TLS 1.2 与 TLS 1.3 分别限制为批准的 AES-GCM cipher suite。

本轮 bundle 只能来自 active lease 绑定的公开 `mtls_trust_anchor_pem`。必须原子写入、
校验整个 bundle、重载代理，并在创建 Suite module 前核对 digest。即使运行被中断，
cleanup 也必须恢复旧 bundle 并再次重载。共享代理必须串行执行 install/restore；除非
每轮拥有独立 listener 和 CA bundle，否则不能并发改变代理信任。严禁用
`ca-ignore-err all` 或 `crt-ignore-err all` 代替安装本轮 CA：这会把全部证书链信任
委托给应用，并可能削弱只按标准 subject selector 注册的 RFC 8705 客户端。

普通生产客户端若由固定 CA 签发，应把该 CA 安装进 HAProxy，并在独立 mTLS listener
使用 `verify required`。除非控制面能原子安装并恢复每轮 CA，否则不得让该 listener
同时承担动态一致性测试证书。

重载前必须使用相同 HAProxy 镜像或二进制执行
`haproxy -c -f /path/to/candidate.cfg`，并保存 root-only 的旧配置。重载后验证
`/ready`、Discovery、Suite 未授权边界、AES-GCM 握手成功，以及 CBC 与 CHACHA20
被拒绝。任一检查失败都应立即恢复旧配置并再次重载。

## 验证

满足以下条件后才算启用：

1. `nazoauthctl status` 报告签名 Release 和双层 target identity；
2. `nazoauthctl doctor` 验证审计、readiness、target digest 和 runtime DDL 边界；
3. `/ready` 返回 HTTP 200；
4. `/.well-known/openid-configuration` 返回配置的 issuer；
5. 反向代理通过公开 HTTPS origin 提供相同接口；
6. 服务重启后签名密钥和头像卷仍保持挂载。

查看脱敏后的部署与审计状态：

```sh
nazoauthctl status
nazoauthctl operation --instance production --limit 20
```

## 升级和回滚

正式发布的独立安装使用同一个生命周期入口：

```sh
nazoauthctl update --instance production --yes
```

该命令校验标签级 Sigstore 身份和不可变制品摘要，在同一签名事务中执行迁移与
激活，再检查 readiness 与公网 Discovery。需要备份硬闸门时显式配置：

```sh
nazoauthctl policy backup-before-update require --instance production \
  --max-age-seconds 86400
```

缺少精确、未过期且通过 restore-test 的 snapshot 时，更新会被拒绝。不可逆迁移
一旦应用，制品回滚会被拒绝，writer 保持停止，直至 `nazoauthctl recover` 从已验证
snapshot 恢复。完整边界见[一键安装与升级](one-click-update.zh-CN.md)。

源码 Compose 仍可用于开发，但不是生产升级路径。数据库恢复保持独立，因为迁移
可能是单向的。

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
