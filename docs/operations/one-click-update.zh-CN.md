# 一键安装与升级

`nazoauthctl` 是独立 Linux 部署的正式生命周期入口。它只消费不可变的标签发布
制品，不在生产主机克隆源码，也不要求 Rust、Node.js 或镜像构建环境。它本身是
Rust 二进制，与 `nazoauth` 在同一个发布中分别构建、签名和出具 SBOM。

## 首次安装

先从同一个不可变 GitHub Release 下载 `install_nazoauthctl.sh` 及其 `.bundle`，用
Cosign 校验该标签的精确工作流身份，再执行已经验证的本地脚本。脚本安装前还会再次
验证 `nazoauthctl` bundle；出于信任自举原因，正式文档不提供 `curl | sh` 路径。

例如，先固定一个不可变 Release，校验 bootstrap 后再执行：

```sh
version=v1.2.3
base="https://github.com/nazozero/NazoAuth/releases/download/$version"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output install_nazoauthctl.sh "$base/install_nazoauthctl.sh"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output install_nazoauthctl.sh.bundle "$base/install_nazoauthctl.sh.bundle"
cosign verify-blob --bundle install_nazoauthctl.sh.bundle \
  --certificate-identity \
  "https://github.com/nazozero/NazoAuth/.github/workflows/release-security.yml@refs/tags/$version" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  install_nazoauthctl.sh
sudo sh ./install_nazoauthctl.sh --version "$version"
```

默认只需要选择运行方式。`auto` 优先使用已安装的 Podman，其次使用 Docker：

```sh
sudo nazoauthctl install --runtime auto
```

未指定公网地址时，服务安全地只发布到
`http://127.0.0.1:8000`。安装器自动生成 PostgreSQL、Valkey 和应用秘密，创建
持久卷、配置、备份目录、签名前端，并验证 readiness、Discovery 和 `/ui/`。

可显式选择运行方式：

```sh
sudo nazoauthctl install --runtime podman
sudo nazoauthctl install --runtime docker
sudo nazoauthctl install --runtime host
```

`host` 把签名的 `nazoauth` 二进制安装成 systemd 服务。没有外部数据库时，它仍
使用本机已有的 Podman 或 Docker 托管 PostgreSQL 和 Valkey。当前独立发布物只
支持 Linux x86_64；宿主机模式还会实际执行候选二进制的 `--help`，动态链接不
兼容时在修改服务前失败。

安装器不会猜测 DNS 或证书归属。提供 HTTPS origin 时，DNS 和 TLS 入口必须已经
把该 origin 转发到安装端口；安装只有在公网 Discovery 返回相同 issuer 后才成功：

```sh
sudo nazoauthctl install \
  --runtime docker \
  --public-url https://auth.example.com
```

### 使用已有 PostgreSQL 和 Valkey

用户配置的是 URL；root 管理的秘密文件只是安装器内部的安全落盘方式。交互输入
不会回显：

```sh
sudo nazoauthctl install --runtime host --external-dependencies
```

自动化环境通过安全 stdin 或已打开的 FD 传入严格 JSON，URL 不允许进入 argv 或普通环境变量：

```sh
secret-provider read nazoauth/dependencies | sudo nazoauthctl install \
  --runtime docker --external-dependencies --secrets-stdin
```

JSON 只允许 `database_url`、`migration_database_url` 和 `valkey_url` 三个字段。
运行时 PostgreSQL 账号不得有 DDL 权限，独立 migration URL 只挂载给一次性迁移任务。
外部依赖模式不会创建数据库或缓存容器；首次迁移和每次
升级前，更新器都必须成功生成并校验 PostgreSQL custom-format dump 与 Valkey
RDB。纯宿主机模式因此需要 `cosign`、`pg_dump`、`pg_restore` 和 `valkey-cli`。

## 日常操作

```sh
sudo nazoauthctl status
sudo nazoauthctl doctor
sudo nazoauthctl check
sudo nazoauthctl update --plan
sudo nazoauthctl update --yes --to v1.2.3
sudo nazoauthctl rollback --yes
sudo nazoauthctl recover --yes
sudo nazoauthctl migrate --yes
sudo nazoauthctl keys list
sudo nazoauthctl keys validate
sudo nazoauthctl audit verify
sudo nazoauthctl audit show [--request-id REQUEST_ID]
sudo nazoauthctl identity rotate --yes
sudo nazoauthctl break-glass recover-controller --reason lost --yes
```

文件型 break-glass 私钥与 controller/audit key 独立，并且从不挂载进应用或任务容器。
安装后应将加密副本导出到离线托管。当前文件型流程仍需要 root-owned 宿主机副本；在未来
接入真实 secret provider 前不能删除它。文件权限不能抵抗宿主机 root。每次 break-glass
恢复都由旧恢复身份签署 transition，并原子
替换 controller、audit 和 break-glass 三类身份；下一次事故前必须先归档新的离线恢复材料。

`install` 是幂等入口：检测到由它管理且已经 ready 的实例时不会重建或升级。
`check` 只验证可用发布，`update` 更新到最新正式标签，`--to` 固定不可变版本。

自动化可以依赖退出码：`0` 表示成功，`2` 表示 CLI 用法被拒绝，`1` 表示生命周期、信任、
授权、健康、备份或恢复的 fail-closed 失败。在 clean-install 验收中，任何非零结果都不得从
失败步骤继续。

`nazoauthctl` 虽然运行在宿主机，但不会进入容器可写层修改应用状态。Docker 或
Podman 模式会使用当前或候选版本镜像启动一次性任务容器，接入部署网络，并挂载
操作所需的最小配置和状态，固定执行 `nazoauth operator-task`，并从 stdin 接收
有效期 60 秒的 Ed25519 JWS。JWS 只提供来源认证和完整性，不提供机密性；秘密只走
安全 stdin/FD、secret mount 或 secret provider，不进入 argv、普通环境、日志、审计或
持久化 envelope。最终签名收据同时绑定 ctl 验证的 OCI/宿主机 digest 与应用验证的
embedded build identity；应用不伪称能自行证明 OCI digest。

## 信任与事务边界

每个正式标签由 `release-security` 发布后端镜像、`nazoauth`、`nazoauthctl`、
两份 SBOM、签名前端，以及包含全部制品大小和 SHA-256 的 schema-3 清单。控制器
先用 Cosign 校验清单，
证书身份必须精确匹配
`release-security.yml@refs/tags/<version>`，然后才解析和下载制品。

容器模式在没有本地 Cosign 时，使用按 OCI digest 固定的官方多架构 Cosign
镜像；完全不使用容器的宿主机模式必须预先安装 Cosign。

安装和升级事务会：

1. 获取主机排他锁；
2. 验证签名清单及所需制品；
3. 准备并验证候选制品，然后停止当前应用写入者；
4. 备份并校验 PostgreSQL 和 Valkey，同时快照签名密钥、生成秘密和初始化状态；
5. 校验镜像 revision 或实际执行宿主机二进制；
6. 执行迁移并启动候选版本；
7. 原子切换签名前端，必要时重启应用以重新绑定前端目录；
8. 验证 readiness、Discovery 和 `/ui/`；
9. 写入部署记录并从同一签名发布更新 `nazoauthctl`。

`update --plan` 分别展示制品回滚、schema 兼容回滚、备份/PITR 恢复和不可逆
migration barrier。控制器绝不把数据库恢复描述为自动行为；只有签名策略确认 schema
兼容时才自动恢复旧制品，数据库必须通过显式 `recover --yes` 从已验证备份恢复。
managed 模式会先停止唯一的受管应用写入者，再依次生成两个备份；恢复 Valkey 仍可能令临时
会话失效。external 模式只能停止本实例，部署者必须静止其他写入者并负责已声明的备份/PITR
流程。`update --plan` 会输出这个边界，不会伪称两个数据系统具有跨存储事务快照。

## 前置条件和配置

基础条件是 Linux x86_64、root、`curl`，以及本地 Cosign 或能够运行固定 Cosign
镜像的容器引擎。容器模式需要 Docker 或 Podman；纯宿主机模式需要 systemd（包括
`systemd-run`）；外部 PostgreSQL/Valkey 还需要 `pg_dump`、`pg_restore` 和
`valkey-cli`。自动部署的 PostgreSQL 和 Valkey 镜像固定到经过评审的多架构 OCI
digest。纯宿主机任务通过 `systemd-run` transient sandbox 执行。正式执行前，应从目标 GitHub Release 下载
`nazoauthctl` 及其 Sigstore bundle，并按该标签的精确工作流身份校验后安装到
`/usr/local/sbin/nazoauthctl`。

安装器生成 root 所有、不可被组/其他用户写入的
`/etc/nazoauth/update.json`。已有的手工部署可以从
`deploy/update/update.example.json` 接入，但 `install` 不会接管没有
`managed_install` 标记的运维配置。

默认不启用定时自动升级。认证基础设施应由运维人员显式执行升级，或另行评审
维护窗口自动化。
