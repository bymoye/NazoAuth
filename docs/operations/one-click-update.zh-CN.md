# 一键安装与升级

`nazoauthctl` 是独立 Linux 部署的正式生命周期入口。它只消费不可变的标签发布
制品，不在生产主机克隆源码，也不要求 Rust、Node.js 或镜像构建环境。它本身是
Rust 二进制，由独立的
[`NazoAuthCtl` 仓库](https://github.com/nazozero/NazoAuthCtl)构建、签名和发布。

## 首次安装

控制器仓库中的 bootstrap 脚本使用 GitHub CLI 下载精确 Release，验证其 GitHub
build-provenance attestation 与精确 tag、控制器 Release 工作流和托管 runner 的绑定，
执行 help 冒烟测试，之后才原子安装为普通非符号链接文件。正式文档不提供
`curl | sh` 信任路径。

从同一个不可变源码 tag 下载并审阅这个小型 bootstrap，然后固定该 tag 执行：

```sh
# 将 vX.Y.Z 替换为你选择的精确不可变 Release tag。
version=v0.1.23
curl --fail --silent --show-error --location --proto '=https' \
  --output install_nazoauthctl.sh \
  "https://raw.githubusercontent.com/nazozero/NazoAuthCtl/$version/scripts/install_nazoauthctl.sh"
less install_nazoauthctl.sh
sudo sh install_nazoauthctl.sh --version "$version"
```

bootstrap 需要 `gh`、`install` 和标准 POSIX 工具。GitHub CLI 必须已经完成认证，
或能以其他方式读取公开 Release 与 attestation API。验证失败或触发速率限制时，
安装会在替换现有文件前封闭失败。

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

全新安装完成后，以交互方式创建首任管理员：

```sh
sudo nazoauthctl bootstrap-admin
```

控制器会提示邮箱，并以无回显方式读取密码。它根据受管 runtime 的 bootstrap mount
定位宿主机源目录，验证目录和 token 都是私有普通文件，并由精确 runtime UID 持有
（容器为 `10001`，host 为配置的 systemd service UID），再将一次性 token
和凭据仅通过子进程 stdin 放入 HTTPS 请求体。它们不会进入 argv、普通环境变量、配置、
日志、审计记录或命令输出。自动化只接受恰好包含 `email`、`password` 的封闭 JSON：

```sh
secret-provider read nazoauth/initial-admin | \
  sudo nazoauthctl bootstrap-admin --credentials-stdin --yes
```

`--yes` 只跳过确认提示；命令仍会验证精确 HTTP 201 响应契约、`/ui/auth` 后续路径，
以及本地一次性 token 已耐久消费。

控制器只持久化非秘密 request ID、使用部署 secret revision 计算的规范化邮箱 HMAC、
recovery epoch、已验证的应用 receipt identity，以及封闭状态。因此 controller 或
break-glass key 轮换不会使未决请求失去恢复能力。若数据库已经提交但 HTTP 响应丢失，
下次执行会复用原 request ID，取回同一个
数据库权威 receipt，而不会创建第二个管理员。网络或异常响应窗口在确认匹配 receipt 前
记为 outcome-unknown；密码、邮箱和 token 都不会进入该恢复状态。

`host` 把签名的 `nazoauth` 二进制安装成 systemd 服务。没有外部数据库时，它仍
使用本机已有的 Podman 或 Docker 托管 PostgreSQL 和 Valkey。独立发布物支持 Linux
x86_64 和 Arm64；musl 发行版应选择对应的 musl target。宿主机模式还会实际执行
候选二进制的 `--help`，动态链接不兼容时在修改服务前失败。

安装器不会猜测 DNS 或证书归属。提供 HTTPS origin 时，DNS 和 TLS 入口必须已经
把该 origin 转发到安装端口；安装只有在公网 Discovery 返回相同 issuer 后才成功：

```sh
sudo nazoauthctl install \
  --runtime docker \
  --public-url https://auth.example.com
```

默认 `baseline` 是面向通用部署的安全基线。项目正式声明的完整 OIDF 一致性矩阵必须
显式选择 `standards-full`。正式 public onboarding workflow 会直接产出受 manifest
绑定、可立即使用的 `standards-full-profile.json`，正常流程不需要手工拼装：

```sh
python3 scripts/oidf_onboarding_bundle.py verify \
  --artifact-directory /absolute/oidf-public-onboarding-material \
  --expected-source-commit "$source_commit" \
  --expected-target-issuer https://auth.example.com \
  --expected-suite-base-url https://suite.example \
  --expected-onboarding-profile official
sudo nazoauthctl install --runtime podman \
  --public-url https://auth.example.com --profile standards-full \
  --profile-material \
  /absolute/oidf-public-onboarding-material/standards-full-profile.json
```

workflow 先证明 `source_commit` 是精确不可变 Release tag 指向的 commit。尚未进入默认
分支的 commit，只有在公开非草稿 Release 及其绑定该 tag、由 GitHub-hosted runner 生成的
attestation 验证通过后才被接受；随后 workflow 切换到该精确 commit 生成所有材料。
artifact manifest 同时绑定源码 commit、目标 issuer、套件 origin 和每个文件摘要。接入
其他标准套件的高级用户仍可使用 `build_oidf_full_install_profile.py` 的显式输入模式。

material 是字段封闭、只含公开信息的信任/配置文档；私有 JWK 成员、私钥、非 HTTPS
origin、未知字段、符号链接和相对路径都会被拒绝。DCR、CIBA、OpenID4VC 管理/加密
秘密由 `nazoauthctl` 在本机生成并且只落入受管 secret file；匹配的 credential 签名
密钥和 PKI 则在启动前通过已认证的一次性应用任务生成：任务只在内存中创建本地 CA，
为当前 HTTPS issuer hostname 的 DNS SAN 签发叶证书，并原子替换一个“叶证书+CA”
PEM bundle。两个 OpenID4VC certificate 配置都指向这个 bundle，运行时只将其中
`CA:TRUE` 的证书视为 trust anchor；CA 私钥绝不落盘。onboarding material 不能提供该
request-object trust anchor；套件公钥也不会被猜测。因此 `standards-full` 必须显式
提供 material，baseline 也不会静默启用它。

默认情况下，四个 standards-full bearer token 由本机生成。自动化运维也可以提供精确
值，但它们不能进入 argv、普通环境、profile material、配置、审计记录或 task envelope。
输入 JSON 是字段封闭的，只允许
`dynamic_registration_initial_access_token`、`ciba_automated_decision_token`、
`openid4vci_management_token`、`openid4vp_management_token`；每个值必须为
32–4096 bytes，且不得含 CR、LF 或 NUL。当还要传外部依赖 URL 时，必须使用不同的
已继承 FD；`--secrets-stdin` 和 `--profile-secrets-stdin` 不能同时消费同一个 stdin：

```sh
secret-provider read nazoauth/standards-full-profile | \
  sudo nazoauthctl install --runtime podman --public-url https://auth.example.com \
    --profile standards-full --profile-material /absolute/standards-full-profile.json \
    --profile-secrets-stdin
```

失败安装的重试中，提供的值必须与已安全落盘的值精确一致，避免重试时静默轮换正在使用的
协议凭据。未提供 override 时，仍由同一个 root-only secret mount 写入本机生成的值。

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
sudo nazoauthctl recover-update --yes
sudo nazoauthctl recover-identity --yes
sudo nazoauthctl migrate --yes
sudo nazoauthctl keys list
sudo nazoauthctl keys validate
sudo nazoauthctl keys export-openid4vc-trust --output /etc/nazoauth/public/vp-request-object-anchor.pem
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
配置读取本身也不允许产生副作用。存在未完成的 update journal 或 identity transition 时，
`status`、`doctor`、`check`、`update --plan` 和审计查看都会 fail closed；只有显式确认的
`recover-update --yes` 与 `recover-identity --yes` 可以收敛对应状态。独立的
`recover --yes` 只负责已声明的数据库备份和上一制品恢复，绝不是隐式 update journal
恢复入口。

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

对 `standards-full` 安装，`keys export-openid4vc-trust` 是 host-local OIDF
OpenID4VP runner 获取公开 trust anchor 的正式入口。它会验证活动的受管“leaf+CA”
bundle，严格只接受一个非 CA leaf 和一个 `CA:TRUE` certificate，并以原子方式只写出
CA certificate 到绝对路径。输出父目录必须已经存在且为真实目录；已有输出必须是普通
非符号链接文件。leaf 与任何私钥都会被拒绝，导出尝试也会进入已签名 management audit
chain。

## 信任与事务边界

每个正式标签的 GitHub Release 发布 8 个带平台后缀的 `nazoauth` 可执行文件和匹配
版本的 `nazo-operator-protocol` 包。每个 server subject 的 schema 5 GitHub
attestation 绑定其二进制 digest、已签名多架构 OCI index、独立 attestation 的
NazoAuthWeb descriptor、operator protocol 与 ctl 兼容范围，以及回滚边界。
控制器必须先验证证书身份精确匹配
`release-security.yml@refs/tags/<version>`，再解析封闭 predicate 和下载制品。SBOM、
predicate、签名 bundle 和 OCI archive 只作为 CI evidence 保留，不进入 GitHub Release。

NazoAuthCtl 的构建、签名、自更新和回退属于独立的 `nazozero/NazoAuthCtl` 发布域。
本仓库暂时保留的旧 ctl 源码只用于迁移核对，不再构成耦合发布契约。

容器模式在没有本地 Cosign 时，使用按 OCI digest 固定的官方多架构 Cosign
镜像；完全不使用容器的宿主机模式必须预先安装 Cosign。

安装和升级事务会：

1. 获取主机排他锁；
2. 验证 subject attestation、封闭 manifest predicate 和所需制品；
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
`20260801000100` receipt migration 是 additive，上一应用无需 schema downgrade 即可继续
运行，所以制品回滚仍是 schema-compatible；但它的 down migration 在已经产生新 receipt
或应用审计证据时会明确拒绝删除证据。这个条件式 schema downgrade barrier 与制品回滚、
显式已验证备份恢复是三个不同边界；`update --plan` 通过签名 migration floor 和 policy
rationale 如实展示。
受管数据库恢复在修改 PostgreSQL 或 Valkey 前，会先持久轮换 bootstrap recovery epoch，
使本地缓存的初始管理员成功收据失效。因此恢复后不能把旧成功当成当前事实，也不能删除新生成
的 bootstrap token。external PITR 如果绕过受管恢复流程改变了数据库状态，ctl 会通过
runtime token 的 HMAC 绑定识别变化并 fail closed，不会伪报成功。
managed 模式会先停止唯一的受管应用写入者，再依次生成两个备份；恢复 Valkey 仍可能令临时
会话失效。external 模式只能停止本实例，部署者必须静止其他写入者并负责已声明的备份/PITR
流程。`update --plan` 会输出这个边界，不会伪称两个数据系统具有跨存储事务快照。

## 前置条件和配置

基础条件是 Linux x86_64 或 Arm64、root、`curl`、`python3`、`sha256sum` 和
`install`，以及本地 Cosign 或能够运行固定 Cosign 镜像的容器引擎。自举使用匿名
GitHub API，不需要 GitHub CLI 或账号 token。容器模式需要 Docker 或 Podman；纯宿主机模式
需要 systemd（包括 `systemd-run`）；外部 PostgreSQL/Valkey
还需要 `pg_dump`、`pg_restore` 和 `valkey-cli`。自动部署的 PostgreSQL 和 Valkey
镜像固定到经过评审的多架构 OCI digest。纯宿主机任务通过 `systemd-run` transient
sandbox 执行。正式执行前，应从目标 GitHub Release 下载 `nazoauthctl`，按上文校验
其自定义 attestation，再安装到 `/usr/local/sbin/nazoauthctl`。

生命周期控制器只接受 Linux `x86_64` 和 `aarch64`（云厂商界面通常称为 Arm64），
其他操作系统或 CPU 组合会在创建部署状态前被拒绝。宿主机模式下载并验证与当前架构
完全匹配的 Release 二进制；Podman 和 Docker 模式分别绑定签名 Release 中的
`linux/amd64` 或 `linux/arm64` platform manifest digest，不会把 OCI index digest
伪装成实际运行制品的 digest。

安装器生成 root 所有、不可被组/其他用户写入的
`/etc/nazoauth/update.json`。已有的手工部署可以从
`deploy/update/update.example.json` 接入，但 `install` 不会接管没有
`managed_install` 标记的运维配置。

默认不启用定时自动升级。认证基础设施应由运维人员显式执行升级，或另行评审
维护窗口自动化。
