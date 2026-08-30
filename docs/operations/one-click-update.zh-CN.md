# 受管安装、更新与恢复

NazoAuthCtl v0.2 只支持当前 protocol 2 谱系。控制端 Registry 负责主机与实例清单；目标机 `DeploymentState` 是 runtime、制品、配置、资源、journal 与备份事实的唯一权威。已删除的控制器状态、task envelope、旧命令和 secret-provider 入口不会被读取或转换。

## 全新安装

先注册目标主机。SSH 主机使用本机现有的 OpenSSH Host 别名，远端 helper 必须与控制端是完全相同的 NazoAuthCtl 构建。

安装需要明确给出公网 issuer 以及外部 PostgreSQL、Valkey 的连接事实。密码只从受限私有文件读取，不接受 argv 明文：

```sh
nazoauthctl install \
  --host production-host \
  --name production \
  --public-url https://auth.example.com \
  --to v0.2.3 \
  --runtime podman \
  --database-host db.internal \
  --database-port 5432 \
  --database-name nazoauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal \
  --valkey-port 6379 \
  --valkey-password-file ./valkey-password
```

Ctl 会先验证官方 Release 与不可变 runtime 制品，再为每个 deployment 生成独立、非空的 UUIDv7 state epoch，按目标机 OS 的路径语义写入配置和 secret，启动 runtime、检查本地健康、提交 `DeploymentState`，最后才注册实例。SSH 响应丢失时，prepared-install journal 会重放同一个 deployment ID 与 operation ID，不会安装第二个实例。

runtime 与 lifecycle PostgreSQL role 必须不同。服务进程只拿 runtime URL；迁移、备份与恢复使用 lifecycle role。PostgreSQL 与 Valkey 属于 external/shared 资源；Ctl 记录其所有权边界，但不创建、替换或删除它们。

若要从目标机上已经停止写入的当前格式数据建立全新 deployment，必须同时追加：

```sh
  --import-data-root /srv/nazoauth-import/data \
  --import-mfa-key-file /srv/nazoauth-import/mfa-totp-key
```

这两个绝对目标机路径不可拆分。导入只复制当前 allowlist 内的数据、签名密钥、应用 secret 与 MFA key；旧 DeploymentState、控制端状态、管理员创建状态、UI cache 和旧命令格式都不会被读取。

## Controller 绑定与管理员创建

```sh
nazoauthctl bind --instance production --label operations \
  --output-secret-file ./production-recovery-secret
nazoauthctl admin create --instance production
```

首次 bind 会在同一事务注册 Controller Key 与 Recovery Root。Recovery Secret 必须在提交前离线保存。若提交中断，owner-only pending 记录只保留这一份已交付的 proposal 与 secret，重试不会悄悄生成另一份；终态对账后立即删除。

自动化通过 stdin 提交严格的 `email`/`password` JSON：

```sh
printf '%s' '{"email":"admin@example.com","password":"..."}' | \
  nazoauthctl admin create --instance production --credentials-stdin
```

命令会调用目标 runtime 内的 `nazoauth admin-provision` 一次性命令。凭据只通过
controller 的受保护凭据路径交付，不进入 argv、普通环境变量、Registry 或日志。

## 更新与回滚

```sh
nazoauthctl update --instance production --to v0.2.6
nazoauthctl rollback --instance production
```

更新只解析并验证一个不可变制品，签发一个 canonical `ControlOperation`，并在激活前通过目标机 journaled lifecycle 执行迁移。durable `ControlResult` 必须同时绑定 operation ID、request hash、typed payload、目标制品与配置 revision。响应丢失只会重放同一操作。

回滚仅在签名 release policy 与实时 schema 事实允许时切换 runtime 制品。不可逆迁移一旦应用，`rollback` 会返回 `ROLLBACK_RECOVERY_REQUIRED`、保持 writer 停止，并要求从已验证 snapshot 执行 `recover`；它不会暗示数据库已回滚。

## 备份与恢复实证

```sh
nazoauthctl backup snapshot --instance production
nazoauthctl backup restore-test --instance production
nazoauthctl policy backup-before-update require --instance production \
  --max-age-seconds 86400
nazoauthctl backup copy --instance production --to-host recovery-host
nazoauthctl backup show --instance production
```

snapshot 将 PostgreSQL custom-format dump、deployment data、secrets、配置、runtime 制品摘要、release 版本、schema、MFA/JWKS 事实与数据库 sentinel 绑定到同一个不可变 manifest。restore-test 使用隔离数据库和 runtime。`require` 会在该精确 manifest 缺失、未通过 restore-test 或超过最大时效时阻断更新。off-host copy 在两端使用同一 ExecutionTarget 抽象，因此任一端都可以是本地或 SSH 注册主机；两端必须是不同主机，并各自持久化字节级校验 receipt。同机文件不算异机证据。

## 灾难恢复

```sh
nazoauthctl recover --instance production
```

只有恢复后的 Controller Registry 返回 `CONTROLLER_KEY_UNAUTHORIZED`，Ctl 才会读取 owner-only Recovery Secret 文件并进入 break-glass ceremony：

```sh
nazoauthctl recover --instance production --recovery-secret-file ./recovery-secret
```

网络错误、5xx、unknown outcome 和其他拒绝码都不会降级为恢复。恢复流程会停止原 runtime，恢复已验证 snapshot，启动仅 loopback 可达的候选，并通过进程独占的目标侧本地通道访问 `/controller-recovery/challenges` 与 `/controller-recovery/recover`；该通道不发送 Cookie/CSRF，也不开放公网入口。

恢复后的 Controller 使用新的 UUIDv7 Valkey state epoch 签发 `RecoveryInvalidate`。NazoAuth 撤销 refresh token，并返回覆盖 access/ID token 最大 TTL 与时钟偏差的绝对 `not_before`。控制端与目标机都在原 runtime 保持停止时校验期限；期限后才以恢复的制品、配置和数据替换并启动原 runtime，再按不可变 ID 清理候选。任何失败均保持公网闭合，并从持久化阶段继续。

不可逆迁移后 `rollback` 会被拒绝。只能从持久化 `recover` 事务及其已验证 snapshot 继续；不得手工重启 writer，也不得清空共享 Valkey。

## 信任边界

激活前必须验证 Release bytes、attestation、Sigstore identity、manifest 与 OCI digest。应用直接用正在执行的二进制或镜像摘要验证签名 ControlOperation，Ctl 从 runtime 观测同一个内容身份。

公网引导对经过 attestation 验证的 Release reader 采取失败关闭，并且只接受公开非草稿 Release。操作端必须具备 GitHub CLI、`python3`、`sha256sum` 与 `install`；缺少 reader 或验证工具时直接失败，不允许退回到未验证制品。

命令面以 `nazoauthctl --help` 和各子命令 help 为唯一权威；本文只描述 v0.2 当前模型。
