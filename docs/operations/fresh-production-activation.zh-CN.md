# 全新生产部署与最终验收

本手册用于有意执行真正的 NazoAuth 全新部署。它是同一次任务内连续完成的验收顺序，
不是分阶段交付合同。普通首次安装和升级统一使用
[`nazoauthctl`](one-click-update.zh-CN.md)。

## 前置条件

- 已审查 commit 已生成仅含平台二进制的不可变标签 Release、精确 workflow identity
  的 schema 4 GitHub attestation，以及已签名的多架构 OCI index；其中绑定的
  NazoAuthWeb descriptor 指向独立 attestation 的前端 Release。
- 已精确盘点 NazoAuth 容器、volume、文件、反向代理引用、端口和远端本地 OIDF Suite
  状态；主机无关资源明确排除在操作范围外。
- 需要保留时已备份旧 NazoAuth；全新安装演练不得复用该状态。
- 目标 public issuer 的 TLS ingress 已存在，安装器必须从公网 Discovery 验证它。

## 单次连续验收顺序

1. 记录 commit、Release/build identity、签名 manifest、制品 digest、现状清单、命令、
   退出码、时间和证据路径。
2. 仅删除清单中的 NazoAuth 应用/依赖容器、volume、配置、部署记录、应用状态、
   controller/receipt/audit/break-glass identity 和审计链；再次盘点证明无关服务未变化。
3. 从同一不可变 Release 安装已验证的 `nazoauthctl`，执行：

   ```sh
   sudo nazoauthctl install --runtime auto --public-url https://auth.example.com \
     --profile standards-full \
     --profile-material /absolute/oidf-public-onboarding-material/standards-full-profile.json \
     --to vX.Y.Z
   secret-provider read nazoauth/initial-admin | \
     sudo nazoauthctl bootstrap-admin --credentials-stdin --yes
   sudo nazoauthctl status
   sudo nazoauthctl doctor
   ```

   使用正式 public onboarding workflow 针对该精确源码 commit、issuer 和套件 origin
   生成并校验过的 `standards-full-profile.json`。它只含公开信任/配置材料，不来自被删除
   的旧部署；全部安装秘密和匹配的本地签名身份都由正式安装流程重新生成。
   首任管理员 token 只从本轮生成的私有 runtime-owned mount 定位，不打印、不复用旧状态，
   也不进入 argv 或普通环境变量。

4. 只通过公开命令依次演练 `update --plan`、update、制品 rollback、显式 backup
   recovery、migrate、keys 查询/验证/变更、audit show/verify、正常 identity rotation、
   break-glass controller recovery、中断重试和重启恢复。`--yes` 只能跳过交互，不能
   跳过签名、授权、防重放、审计、备份、健康检查、回滚政策或 migration barrier。
5. 验证应用使用非 root UID、零 capability、只读 rootfs；任务 mount/network 与操作匹配；
   managed runtime PostgreSQL 无 DDL；argv、普通 env、inspect、journal、日志、审计和
   持久 envelope 均无秘密；raw `nazoauth migrate`/`keyctl` 被拒绝；intent/receipt 重试
   幂等，签名审计链和 trust transition 可验证。
6. 使用远端主机本地 OIDF Conformance Suite，对该实例运行项目当前声明的完整
   plan/variant 矩阵。禁止抽样、关闭能力、修改判定或增加无规范依据的 expected skip。

任一步报错、超时、需要人工修复、直接改内部状态、扩大权限、绕过安全控制、证据不完整
或 OIDF 失败，都使本次尝试无效。修复代码并发布新的不可变 Release 后，必须再次删除
NazoAuth，从第 1 步重新执行。

## 完成记录

唯一成功结论是 `PASSED`，并附 commit、Release 和 embedded build identity、实际
OCI/二进制 digest、完整命令与退出码、request ID、远端证据路径、OIDF Suite 版本和
全部 plan/variant 结果。否则只能报告 `FAILED` 或 `BLOCKED`，两者都不代表完成。

协议不变量、恢复边界、故障窗口和任务矩阵见
[operator-task 计划书](../security/operator-task-protocol-plan.zh-CN.md)与
[实施任务书](../project/operator-task-protocol-implementation-task.zh-CN.md)。
