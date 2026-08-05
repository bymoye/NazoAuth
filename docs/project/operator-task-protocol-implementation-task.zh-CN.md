# NazoAuth Operator Task Protocol 实施任务书

状态：实施中；远端代码门禁已通过当前候选改动；正式双 Release 与第 18 节唯一远端验收尚未完成
日期：2026-08-01
设计计划：[operator-task-protocol-plan.zh-CN.md](../security/operator-task-protocol-plan.zh-CN.md)  
源代码基线：`codex/cosign-private-staging` 当前工作树；`v0.1.8`、`v0.1.9` 测试发布均被 `release-security` 封闭拒绝，`v0.1.10` 的私有服务器零状态安装在受管 Valkey 备份检查中封闭失败，修复后的安装验收版本为 `v0.1.11`，最终 SHA 只由正式 Release 固定

## 1. 任务目标

把 `nazoauthctl` 与目标版本 `nazoauth` 的普通参数委派改造成一次性、带签名、部署与制品
绑定、防重放、操作级最小权限并具有闭环审计的本地任务协议；同时把 ctl 的安装、诊断、
升级、密钥和审计操作整理为低认知负担、默认安全、可脚本化的稳定用户界面。

最终交付仍是两个二进制：

- `nazoauth`：服务器和版本耦合的应用任务执行者；
- `nazoauthctl`：宿主机生命周期和用户操作入口。

允许新增一个同时被二者真实使用的 `nazo-operator-protocol` 库 crate，只承载稳定协议类型和
验证规则。不得引入常驻控制服务、任意命令总线、第二套迁移或密钥实现。

## 2. 执行纪律

### 2.1 第一性原则

- 每项权限从实际数据和依赖流推导，不能从“生产容器已有这些权限”推导。
- 每个状态只有一个真实所有者；ctl 不复制迁移、密钥或 OAuth 规则。
- 默认值只自动生成本地可安全生成的事实；外部信任事实不能猜。
- 易用性缺陷按安全缺陷处理：正确路径不能要求用户手工拼容器参数或秘密文件。
- 不添加没有真实消费者的 abstraction、provider、RPC 或未来占位实现。
- 不以 root 权限、签名日志或 OIDF 回归中的任意一个单独宣称交互安全完成。

### 2.2 完成标记规则

本文的 OTP 编号只表示同一次任务内的依赖顺序，不是分批交付承诺。实施开始后必须连续完成
代码、legacy 收口、文档、本地全量门、正式 Release、远端零状态验收和完整 OIDF 矩阵；
任何中间双栈、候选 Release 或局部绿色结果都不得宣布为完成。

任务只有同时满足以下条件才能从 `[ ]` 改为 `[x]`：

1. 代码或文档交付存在且被真实路径消费；
2. 本任务列出的正向、负向和失败注入验收通过；
3. 证据路径、命令和结果被记录；
4. 没有用 mock/fake runtime 结果替代要求的真实 Docker、Podman 或 systemd 结果；
5. 没有用本地协议测试替代公网、签名 Release 或 OIDF 证据；
6. 遗留限制和未执行边界被明确写出。

### 2.3 证据分层

| 层级 | 能证明什么 | 不能替代什么 |
| --- | --- | --- |
| Source/contract | 类型、依赖和静态禁止项存在 | 真实进程权限和秘密暴露 |
| Unit/property | 验签、解析、状态机和负面输入 | 容器/systemd 行为 |
| Fake runtime transaction | ctl 事务命令和回滚分支 | 真实 engine、内核、SELinux |
| Real local runtime | Docker、Podman、systemd 的真实隔离和进程观察 | 签名 tagged Release 和公网 |
| Signed Release | 发布制品、manifest、升级兼容和供应链 | 公网 DNS/TLS 与 OIDF |
| Public black-box | 公网 health/Discovery/TLS/升级 smoke | 本地控制面内部安全细节 |
| OIDF matrix | 对外 OAuth/OIDC/FAPI 无回归 | ctl/app 本地任务协议 |

## 3. 里程碑与依赖

```text
OTP-000 基线与契约
  ├─ OTP-100 共享协议
  ├─ OTP-200 安装身份与本地账本
  └─ OTP-300 ctl 用户与执行入口
       └─ OTP-400 app 验证与执行入口
            ├─ OTP-500 状态所有者防重放
            └─ OTP-600 操作级沙箱
                 ├─ OTP-700 审计与外部检查点
                 ├─ OTP-800 批准、轮换与恢复
                 └─ OTP-900 发布、升级与兼容
                      ├─ OTP-1000 UX 收口与文档
                      └─ OTP-1100 完整验证与正式验收
```

共享协议和身份可以并行开发，但 app/ctl 联调只能在两者契约冻结后开始。沙箱模板必须在
每个 operation 的真实依赖已经收窄后实现，不能先复制完整挂载再称为 profile。

## 4. OTP-000：基线、威胁模型与架构契约

目标：在写代码前固定当前事实、目标不变量、发布兼容和残余风险。

### 任务

- [ ] `OTP-001` 记录实施开始时的 Git revision、dirty diff、关键源文件 SHA-256 和当前测试
  基线；若与计划书证据发生相关漂移，先更新计划书。
- [ ] `OTP-002` 扩展 `docs/security/threat-model.md`，加入 ctl、控制器身份、容器引擎、
  systemd transient unit、任务容器、外部批准和审计 sink 边界。
- [ ] `OTP-003` 扩展 `docs/project/architecture.md`，记录 `nazo-operator-protocol` 的双消费者
  边界以及 ctl/app/状态所有者的禁止职责。
- [ ] `OTP-004` 为计划书 `INV-01` 至 `INV-18` 建立测试/证据追踪表；每项至少有一个负向
  验证。
- [ ] `OTP-005` 记录 managed、unmanaged/dev、online approval、offline recovery 四种模式的
  明确差异，禁止隐式降级。
- [ ] `OTP-006` 决定并记录 server auto-migrate 到 managed signed migration 的兼容窗口和
  runtime/migration PostgreSQL role 分离策略。

### 验收

- [ ] 当前设计图、目标设计图、信任根和 out-of-scope root/engine compromise 在文档中一致。
- [ ] 没有把“root 调用”“镜像已签名”或“日志有 hash”单独描述为端到端可信。
- [ ] 所有后续任务都能追踪到计划书不变量，且不存在无消费者的预留组件。

## 5. OTP-100：共享协议 crate

目标：让 ctl 和 app 使用同一个封闭协议契约，不重复 JOSE、操作类型、错误码和风险分类。

### 任务

- [ ] `OTP-101` 新增 workspace crate `crates/operator-protocol`，Cargo package 命名为
  `nazo-operator-protocol`；同时接入 `nazoauthctl` 与 authorization-server 两个真实消费者。
- [ ] `OTP-102` 定义 `TaskEnvelopeClaims`、`TaskOperation`、`TaskTarget`、`ActorEvidence`、
  `RuntimeTargetIdentity`、`EmbeddedBuildIdentity`、`CanonicalConfigManifest`、`SecretRevisionBinding`、
  `TaskResult`、`TaskStatus`、`OperatorErrorCode`、`RiskClass` 和 `CapabilityProfile`。
- [ ] `OTP-103` 所有 wire type 使用封闭 enum、长度有界的构造函数和 unknown-field rejection；
  不在协议内部保留任意 `serde_json::Value`、`HashMap<String, Value>` 或 `Vec<String>` 命令。
- [ ] `OTP-104` 实现固定 `EdDSA` 的严格 JWS sign/verify；trust key 来自调用者提供的本地
  key registry，不接受远程 `jku/x5u`、请求提供 JWK 或算法降级。
- [ ] `OTP-105` 验证 `typ`、`kid`、protocol version、issuer、deployment audience、`jti`、
  `iat/nbf/exp`、runtime target identity claim、embedded build expectation、版本化规范非秘密 config
  manifest、opaque secret revision/HMAC binding 和最大接受时钟偏差。
- [ ] `OTP-110` 定义规范 config manifest：仅允许封闭非秘密字段；秘密明文不得进入 digest，
  低熵 secret version 只能以 opaque revision 或 deployment-keyed HMAC 绑定。
- [ ] `OTP-106` 实现请求/结果的最大 64 KiB contract、单消息 contract 和稳定 schema/error
  code；错误不包含原始 payload 或秘密。
- [ ] `OTP-107` 提供跨二进制 golden vectors，包括有效请求和每类单字段篡改请求。
- [ ] `OTP-108` 增加 property/fuzz tests：重复字段、未知字段、错误类型、超长输入、Unicode
  边界、无效 Base64、签名 malleability、算法混淆、尾随数据和资源耗尽。
- [ ] `OTP-109` 确认共享 crate 不依赖 Actix、Diesel、Fred、Docker/systemd、Settings、
  KeyManager 或文件布局。

### 验收

- [ ] ctl 生成的每个 golden request 均由 app consumer 验证，反向兼容向量结果一致。
- [ ] 任何 signed bytes 或 claim 变化都使验证失败；错误不会回显受保护负载。
- [ ] 编译期 dependency test 证明协议 crate 只承担共享契约。
- [ ] 对应 `INV-02`、`INV-03`、`INV-04`、`INV-16`、`INV-17` 有自动化证据。

## 6. OTP-200：部署身份、控制器身份和本地 intent/receipt 账本

目标：首次安装自动建立本部署的请求与审计信任根，不增加用户手工配置。

### 任务

- [ ] `OTP-201` 首次 managed install 原子生成 deployment ID、controller Ed25519 keypair 和
  独立 audit checkpoint keypair；key ID 稳定且不泄露私钥材料。
- [ ] `OTP-202` 文件 provider 强制 root owner、目录 `0700`、私钥 `0600`、非 symlink、
  regular-file、原子 create-new 和 fsync；拒绝不安全的现有文件。
- [ ] `OTP-203` 将 controller public key、deployment ID 和 protocol policy 作为只读 trust
  配置提供给 app task；私钥绝不进入 runtime/task mount。
- [ ] `OTP-204` 定义 provider 接口时只实现文件 provider 和至少一个测试 provider；没有
  真实 TPM/PKCS#11 consumer 前不提交空硬件实现。
- [ ] `OTP-205` 实现 root-only intent/receipt 账本：原子记录、hash chain、前序 hash、
  request ID 唯一、fsync 和恢复扫描。
- [ ] `OTP-206` intent 在启动 task 前提交；mutation intent 写入失败必须 fail closed。
- [ ] `OTP-207` 实现 audit checkpoint 独立签名和本地 verify；请求签名键与审计签名键不可
  跨用途复用。
- [ ] `OTP-208` install 重试识别已完整、部分生成和冲突身份，不能静默覆盖或生成第二套身份。

### 验收

- [ ] clean install 不要求用户生成、复制或编辑身份文件。
- [ ] 权限、symlink、partial write、磁盘满、并发 install 和 crash 注入均 fail closed 或安全恢复。
- [ ] 用 canary secret 扫描 private key 未出现在 config JSON、argv、env、inspect、日志和审计。
- [ ] 对应 `INV-02`、`INV-05`、`INV-09`、`INV-10`、`INV-11`、`INV-14` 有自动化证据。

## 7. OTP-300：nazoauthctl 类型化命令和私密执行通道

目标：ctl 成为稳定、顺手的用户入口，并且不再把任意字符串转发给 app。

### 任务

- [ ] `OTP-301` 将 `Command::Keys(Vec<String>)` 改为类型化子命令和参数；所有敏感输入明确
  标记，禁止进入 display/debug/error。
- [ ] `OTP-302` 新增 `doctor`、`update --plan`、`rollback`、`audit`、`identity` 命令层级；
  保留 `check` 兼容别名并输出稳定弃用提示。
- [ ] `OTP-303` 扩展 Process 执行边界，支持有界 stdin、分离且有界 stdout/stderr、timeout、
  kill/reap 和结构化 exit outcome；命令显示永不包含 secret values。
- [ ] `OTP-304` 解析目标 Release/digest 和 effective config 后构造 TaskEnvelope；先写 intent，再
  完成 Release/制品/网络/挂载/沙箱/secret channel 准备；在 task 启动前最后签发 60 秒
  TaskEnvelope，并在退出后再次观察实际容器/二进制 identity。准备失败不得预签 envelope。
- [ ] `OTP-305` JSON 输出只在 stdout 输出单个 versioned object；进度与诊断写 stderr；human
  输出稳定显示阶段、request ID、回滚状态和下一步。
- [ ] `OTP-306` 实现计划书最小稳定退出码契约；操作细节通过脱敏错误、request ID 和签名
  审计表达，不复制一套会与真实状态漂移的通用 machine error taxonomy。
- [ ] `OTP-307` `--yes` 只跳过交互确认，不能跳过签名、批准策略、防重放、备份或审计。
- [ ] `OTP-308` 默认 file provider 的 status/doctor/audit 通过 `sudo` 读取 root-only 配置、信任和
  备份证据；未来只有真实 operator group/provider 能完整约束文件访问时才允许无 root，不能为
  “只读易用”放宽私钥或 secret path 权限。
- [ ] `OTP-309` PostgreSQL/Valkey 自定义支持无回显 prompt、安全 stdin/FD 和未来真实
  secret-provider 自动化；用户界面不要求 `url-file`，也不接受 secret argv/普通 env。
- [ ] `OTP-310` 对 direct secret argv 直接拒绝并给出安全 stdin/FD 提示；秘密不向子进程、
  持久配置、日志或审计传播。

### 验收

- [ ] 仓库静态搜索证明 managed app task 不再由任意 `Vec<String>` 构造。
- [ ] 使用推荐的无回显/stdin/secret-provider 输入时，`ps`、`/proc`、Docker/Podman inspect 和
  错误输出中找不到 canary secrets；direct secret argument 单独证明有警告且不向子进程、
  持久配置或审计继续传播。
- [ ] JSON 型 `status`/plan/audit 与 human 型 doctor/mutation snapshot、exit code、TTY/非 TTY、
  SIGINT、timeout 和重复执行测试通过。
- [ ] 对应 `INV-01`、`INV-04`、`INV-05`、`INV-09`、`INV-14`、`INV-17` 有证据。

## 8. OTP-400：nazoauth operator-task 验证和执行入口

目标：app 在接触状态前独立验证控制器能力，并将封闭 operation 分派给现有真实所有者。

### 任务

- [ ] `OTP-401` 新增固定 CLI 入口 `nazoauth operator-task`，只从 stdin 读取一个有界 JWS；
  不接受 operation argv。
- [ ] `OTP-402` 严格按“读取 → header → trust key → signature → claims → replay → operation”
  顺序实现；测试证明失败前不会初始化写路径或打开无关 secret。
- [ ] `OTP-409` 编译时嵌入 release、Git revision、operator protocol 和 binary build identity；
  app 验证自身 embedded identity 与请求预期一致，但不声称自行证明 OCI digest。
- [ ] `OTP-403` 将 `migrate.apply` 委派给现有 `nazo-postgres` migration owner，将 key operations
  委派给 `nazo-key-management`；不复制实现。
- [ ] `OTP-404` 为 keyctl 提供仅加载 KeySettings 所需字段的配置路径，避免为了密钥操作加载
  PostgreSQL、Valkey、avatars、UI 或完整 server Settings。
- [ ] `OTP-405` 返回单个封闭 TaskResult；stdout 不混入 tabular/debug 输出，legacy human
  presenter 与 operator result presenter 分离；结果携带 embedded identity 和 runtime target
  claim，最终 ctl receipt 另行绑定执行前后实测 OCI/binary digest。
- [ ] `OTP-406` managed trust policy 存在时，直接 legacy state-changing `keyctl`/`migrate`
  不能绕过同一 authorization/audit 边界。
- [ ] `OTP-407` 为 unmanaged/dev 模式定义显式、可审计、无隐式降级的兼容行为。
- [ ] `OTP-408` 解析和错误路径全面应用 zeroization/secret wrapper；禁止派生 Debug 泄漏。

应用侧的部署绑定实现约束：签名验证后必须读取本机只读部署身份，并逐字段
比较 `deployment_id`、`iss=controller:<deployment_id>` 和
`aud=runtime:<deployment_id>`。运行时已有
`DATA_DIR/instance/deployment-id` 或 operator-state 锚点时必须逐一比对；首次
`migrate-apply` 尚未建立任一锚点时，才能使用已纳入 config manifest 的
`DEPLOYMENT_ID` 作为显式 bootstrap 来源，并原子持久化 operator-state 锚点；
其他操作必须已有该锚点。
缺少两者或两者冲突均 fail closed；该校验不依赖 NazoAuthCtl 在线可用。

### 验收

- [ ] forged、expired、wrong deployment/target/config、unknown operation 和 replay request 在任何
  状态变化前失败。
- [ ] app 只打开 operation profile 声明的配置和状态路径。
- [ ] legacy bypass negative tests 覆盖 managed container 和 host 两种模式。
- [ ] 对应 `INV-02`、`INV-03`、`INV-04`、`INV-11`、`INV-12`、`INV-18` 有证据。

## 9. OTP-500：状态所有者防重放、幂等和执行收据

目标：重试、并发和崩溃不会产生重复逻辑变更，且收据与真实状态一致。

### 任务

- [ ] `OTP-501` 定义 request lifecycle：`requested`、`accepted`、`in_progress`、`succeeded`、
  `failed_retryable`、`failed_terminal`，明确允许的状态转换。
- [ ] `OTP-502` KeyManager 将 request ID/result digest 与 keyset generation 绑定；本地密钥创建、
  registry 变更和收据使用可恢复的原子提交协议。
- [ ] `OTP-503` 同 request ID 的 generate/register 重试返回原结果，不生成第二个 kid/私钥。
- [ ] `OTP-504` 测试 private-key-created/keyset-not-committed 等中间崩溃状态，清理孤儿或安全
  完成，不把半状态作为成功。
- [ ] `OTP-505` migration 使用 PostgreSQL advisory lock、Diesel ledger 和 ctl intent；并发执行
  有界等待或明确冲突，数据库 session 的 `lock_timeout`/`statement_timeout` 必须小于 ctl
  transport timeout，并在成功、失败和取消路径释放 advisory lock；已完成迁移返回结构化
  `applied=false` no-op。
- [ ] `OTP-505a` task lock 也必须有界（不超过 30 秒）；claim 前的锁竞争必须在 ctl 300 秒
  kill 前以 transport 失败返回并保留 intent，不能写一个未持久化的 final receipt（锁持有者
  可能随后发布同一 JTI 的成功 receipt）。锁已取得后的数据库锁/语句超时属于已 claim 请求的
  执行失败，必须输出可验证 `RuntimeReceipt` 的 `TaskOutcome::Failed`，而不是让 transport
  进程因业务失败退出非零。
- [ ] `OTP-505b` 同一 JTI 的 `migrate-apply` 在 `Executing` 且无 receipt 时只允许依据 Diesel
  migration ledger 幂等重入；其他 operation 仍 fail closed。完整可验签且绑定 request/deployment
  的 receipt 临时文件可以原子收敛；不完整或不匹配的临时文件必须保留并拒绝恢复。Prepared
  生命周期与等价临时副本可清理后继续。
- [ ] `OTP-506` migration 完成后写应用收据；首次创建收据 schema 的 bootstrap 例外按计划书
  明确处理，不伪造跨数据库/宿主机事务。
- [ ] `OTP-507` update/rollback lifecycle journal 可以从最后提交阶段恢复，收据永不因 rollback
  被删除。

### 验收

- [ ] 线程并发、双 ctl 进程、task kill、ctl kill、engine restart 和主机重启矩阵均满足一次
  逻辑转换。
- [ ] 重放返回原结果或稳定 replay/in-progress 状态，并产生审计事件。
- [ ] key store、migration ledger、ctl journal 三者没有相互冒充状态所有者。
- [ ] 对应 `INV-06`、`INV-09`、`INV-11`、`INV-12`、`INV-13` 有证据。

任务 transport 退出码与签名结果状态必须分别记录：有效请求的业务失败应由 stdout
`TaskOutcome::Failed` 表达并保持 transport 成功退出；验签/绑定/签名密钥等前置失败才是
没有可验证 receipt 的 transport 失败。ctl 超时或 kill 只说明未收到 transport 结果，不能据此
断言迁移未执行。

## 10. OTP-600：Docker、Podman 与 systemd 操作级沙箱

目标：从实际 operation 依赖生成最小运行边界，不再继承生产容器全部权限。

### 任务

- [ ] `OTP-601` 将 production runtime mounts 与 operator capability profiles 分成不同类型；
  禁止 task runner 接收完整 runtime mounts。
- [ ] `OTP-602` 为五种 v1 operation 定义精确 read-only/read-write mount、user、network、
  address family、tmpfs 和 timeout contract。
- [ ] `OTP-603` Docker 与 Podman runner 使用 `--rm -i --read-only --cap-drop=ALL`、
  `no-new-privileges`、非 root、无端口、无 engine socket 和有界 tmpfs。
- [ ] `OTP-609` 瞬时秘密只通过受限 stdin/FD、只读 secret mount 或真实 secret provider
  传递；JWS 明确只签名不加密，秘密不得进入持久 envelope、argv、普通 env、日志或审计。
- [ ] `OTP-604` managed PostgreSQL/Valkey 使用明确 internal dependency network；migration task
  只加入数据库所需网络，key local operations 默认无网络。
- [ ] `OTP-605` external dependency 模式只实施实际可证明的网络控制；无法目标级限制时 doctor
  和审计明确报告 external boundary，禁止过度声明。
- [ ] `OTP-606` host runner 改用 systemd transient unit，实施 User、ProtectSystem、PrivateTmp、
  NoNewPrivileges、ReadOnlyPaths、ReadWritePaths 和按操作网络属性。
- [ ] `OTP-607` SELinux `:Z`、rootless Podman UID mapping、Docker daemon 模式和 host 文件 owner
  分别验证，不用一个 engine 的结果替代另一个。
- [ ] `OTP-608` task timeout/SIGINT/kill 后可靠 reap 并删除容器/transient unit；持久状态和收据
  保持可恢复。

### 验收

- [ ] 实际 task inspect 与 capability snapshot 精确匹配，未声明 mount/network/capability 不存在。
- [ ] keys task 读取 avatars/UI/bootstrap 和 migration 读取 keys/Valkey secret 的攻击测试失败。
- [ ] 容器内 uid 非 0、rootfs 写入失败、无 published port、所有 capabilities 为空。
- [ ] Docker、Podman、systemd 三个真实运行时分别通过，不以 fake command matrix 代替。
- [ ] 对应 `INV-07`、`INV-08`、`INV-13` 有证据。

## 11. OTP-700：闭环审计与外部检查点

目标：每次操作都可通过 request ID 追踪 intent、应用决定和结果，同时不记录秘密。

### 任务

- [ ] `OTP-701` 扩展封闭 audit taxonomy，加入计划书定义的 `operator_lifecycle` 事件和 allowlist。
- [ ] `OTP-702` requested intent 记录 controller/actor/deployment/operation/target/config 摘要；
  accepted/rejected/result 共享 request ID 和 request digest。
- [ ] `OTP-703` 任何自由文本、stdout/stderr、env、URL、key ref、approval token 和私钥字段均
  无法通过类型或数据库 CHECK 进入永久审计。
- [ ] `OTP-704` `nazoauthctl audit show` 提供封闭 JSON 查询，`audit verify` 提供简短 human
  结论；默认不展示受保护文件内容。
- [ ] `OTP-705` `nazoauthctl audit verify` 验证 hash chain、检查点签名、key rotation、导出和
  retention continuity，返回稳定 exit/error code。
- [ ] `OTP-706` 定义可选 audit sink contract；先实现一个真实消费者再保留接口，避免空泛
  plugin 系统。
- [ ] `OTP-707` sink 发送采用有界重试/队列，不阻塞 read-only 操作；security-critical 操作的
  fail policy 显式配置并在执行前展示。
- [ ] `OTP-708` 记录“本地篡改可见”和“已外部见证”两个不同 assurance，不把二者混称不可变。

### 验收

- [ ] 正常、拒绝、重放、失败、rollback、break-glass、key rotation 均有闭环事件。
- [ ] 删除、修改、重排、截断、错误 key 和中断 rotation 都被 verify 检测。
- [ ] canary secret corpus 扫描本地 journal、应用日志、JSON 输出和远程 sink 为零命中。
- [ ] 外部 sink 在真实独立进程/存储中验证一个检查点；未配置 sink 时输出边界准确。
- [ ] 对应 `INV-05`、`INV-09`、`INV-10`、`INV-11`、`INV-15` 有证据。

## 12. OTP-800：风险批准、身份轮换和 break-glass

目标：高风险操作有合适的人类/机器授权，同时保留服务离线时的可恢复性。

### 任务

- [ ] `OTP-801` 将 operation 映射到 Read、Routine mutation、Security critical、Recovery 四类；
  policy 是封闭配置且有安全默认。
- [ ] `OTP-802` 交互确认展示 deployment、operation、target、影响和可恢复性；不展示秘密。
- [ ] `OTP-803` actor evidence 区分 controller service、local root、online admin 和 break-glass；
  不从可伪造 env 单独推导自然人身份。
- [ ] `OTP-804` 若实现 online approval，必须是短时、deployment/operation/request digest 和 PoP
  绑定的证明；它是可选真实消费者，不成为离线恢复依赖。
- [ ] `OTP-805` 实现正常 controller/audit key rotation：旧 key 授权封闭 transition、staging
  配对验证、原子切换，旧 key 只保留历史验签；切换后以真实任务验证新 key。
- [ ] `OTP-806` 实现显式 break-glass 恢复：独立恢复材料、强确认、无静默降级、高优先级审计、
  完成后强制轮换。
- [ ] `OTP-807` clone/restore 时默认生成新 deployment identity；保留身份需要显式参数和审计。
- [ ] `OTP-808` 高保证 provider 只有在 TPM/PKCS#11/HSM 真实环境测试后才标记支持。
- [ ] `OTP-809` 分离 Release trust 与 controller trust：固定 workflow identity、manifest/
  artifact/OCI/SBOM/provenance、protocol floor 和 deployment trust generation 均进入防降级判断。
- [ ] `OTP-810` 实现 controller key 丢失协议：冻结 mutation、break-glass recovery、提升 trust
  generation、新 key 验证、旧 key 退役和恢复材料轮换。
- [ ] `OTP-811` 实现 controller key 被盗/疑似被盗协议：标记 compromised、拒绝旧 generation、
  核对外部检查点之后的全部 request IDs，并按影响轮换应用/依赖 credentials。
- [ ] `OTP-812` 对正常轮换、丢失、被盗、旧 key 重放、Release/protocol/schema 降级和 break-glass
  进行真实演练，保留 request ID 和签名检查点。

### 验收

- [ ] `--yes`、非 TTY 和 automation 均不能跳过要求的批准证明。
- [ ] NazoAuth 完全离线时 migrate/recovery 可按 policy 完成并留下 break-glass 证据。
- [ ] 正常轮换、旧 key 请求即时拒绝、丢失私钥和恢复后 break-glass 再轮换矩阵通过。
- [ ] 对应 `INV-02`、`INV-03`、`INV-13`、`INV-15` 有证据。

## 13. OTP-900：Release manifest、升级桥接和运行角色收敛

目标：从现有部署安全迁移到新协议，并保持签名发布、回滚和版本兼容。

### 任务

- [ ] `OTP-901` 提升 Release manifest schema，声明 operator protocol min/max、ctl/app artifacts、
  image digest、revision、SBOM 和签名身份。
- [ ] `OTP-902` ctl 在下载/执行前验证 manifest、artifact、workflow identity 和 protocol overlap；
  不兼容时只输出升级路径，不修改状态。
- [ ] `OTP-903` 新 ctl 为旧部署原子建立 identity/trust 配置，再用支持 v1 的候选镜像执行签名
  migrate；旧运行容器在候选验证前不替换。
- [ ] `OTP-904` managed server 默认关闭 auto-migrate，只检查 schema compatibility；migration
  task 使用专用 DDL role，server runtime role 无 DDL 权限。
- [ ] `OTP-905` 设计 additive schema/key-store 迁移和回滚窗口；rollback 不删除新收据或身份。
- [ ] `OTP-910` 将恢复明确建模为 artifact rollback、schema-compatible rollback、database
  backup/PITR restore 和 irreversible migration barrier 四种状态；禁止通用“数据库自动回滚”。
- [ ] `OTP-911` 为 migration metadata 定义 compatibility range、reversibility、barrier、备份/
  PITR prerequisite 和 runtime role requirement；缺少信息时 update plan fail closed。
- [ ] `OTP-906` legacy mutation 只在明确 compatibility policy 下存在；一个完整签名发布窗口的
  clean install/upgrade/rollback 证据通过后再移除。
- [ ] `OTP-907` release-export 继续提供两个二进制，runtime image 只包含 `nazoauth`；两个二进制
  和 protocol crate 依赖进入 SBOM/provenance。
- [ ] `OTP-908` update 自身保持一键事务：verify/prepare → stop writer → backup → authorize → migrate → switch →
  readiness/Discovery → commit；只在明确可恢复边界内自动 artifact/schema rollback，越过 barrier
  后只执行已验证的 restore/forward recovery，绝不笼统承诺数据库自动 rollback。
- [ ] `OTP-909` `update --plan` 精确展示 migration、barrier、artifact rollback、schema compatibility、
  backup/PITR readiness、数据丢失/停机边界和失败后的唯一允许动作。

### 验收

- [ ] old ctl/old app、new ctl/old app、new ctl/new app、rollback app 的兼容矩阵结果明确且符合 policy。
- [ ] protocol mismatch、manifest 篡改、wrong workflow identity 和 digest mismatch 在修改前失败。
- [ ] runtime DB role 执行 DDL 被真实 PostgreSQL 拒绝，migration role 正常完成升级。
- [ ] signed tagged Release 的 Docker、Podman、host clean install 与 upgrade/rollback 通过。
- [ ] 对应 `INV-01`、`INV-11`、`INV-16`、`INV-18` 有证据。

## 14. OTP-1000：UX 收口、帮助、诊断和文档

目标：用户无需理解内部容器路径和密码学细节，也能始终走正确路径。

### 任务

- [ ] `OTP-1001` 统一 command tree、help、示例和错误建议；顶层 help 只展示用户意图，不暴露
  内部 `operator-task` 协议细节。
- [ ] `OTP-1002` `doctor` 检查 runtime、文件 owner/mode、identity、protocol compatibility、
  dependency、network isolation、audit continuity、external sink 和 public readiness/Discovery。
- [ ] `OTP-1003` doctor 每个失败给出原因、影响、是否安全自动修复和精确下一步；修复必须
  显式执行，read-only doctor 不偷偷改变状态。
- [ ] `OTP-1004` install 默认自动生成所有本地秘密和身份；只要求用户提供无法推断的 public
  URL 或外部系统事实。
- [ ] `OTP-1005` doctor/mutation 的 human output 简短稳定，status/plan/audit 的 JSON output
  使用封闭字段；敏感值、内部 stack/debug 和原始命令不进入普通输出。
- [ ] `OTP-1006` 为 install、status、doctor、update plan/update、rollback、migrate、keys、audit、
  identity 编写中英文操作文档和典型恢复路径。
- [ ] `OTP-1007` 更新 `docs/README.md`、架构、威胁模型、security events、部署、one-click update、
  release security 和 CHANGELOG。
- [ ] `OTP-1008` 进行新用户可用性走查：仅给受试者二进制和 `--help`，观察完成规定旅程的
  摩擦点；记录事实并修复阻塞，不编造耗时指标。

### 验收

- [ ] managed clean install 零秘密输入、零手工文件，production 形态最多要求 public URL。
- [ ] 用户不需要知道 `url-file`、容器 mount path、controller key path 或 JWS 字段。
- [ ] 每个 mutation 完成或失败都提供 request ID、状态修改/回滚事实和下一步。
- [ ] 文档中的命令全部由 CLI contract test 或真实 smoke 覆盖。
- [ ] 对应 `INV-14`、`INV-15`、`INV-16`、`INV-17` 有证据。

## 15. OTP-1100：完整测试、安全验证和正式验收

目标：按风险分层完成所有证据，形成可审阅的最终验收报告。

### 任务

- [ ] `OTP-1101` 运行 protocol、ctl、authorization-server、key-management、persistence focused
  unit/property/integration tests。
- [ ] `OTP-1102` 运行完整 workspace test、all-target/all-feature Clippy `-D warnings`、fmt、静态
  合同、`cargo deny`、`cargo audit`、release governance 和 workflow lint。
- [ ] `OTP-1103` 运行 forged/tampered/expired/replay/algorithm confusion/unknown field/oversize/
  path traversal/symlink/output injection/canary secret 安全矩阵。
- [ ] `OTP-1111` parser fuzzing、跨二进制 golden vectors 和 property tests 在 CI 中有固定入口、
  corpus/regression 保留及资源上限；不得只运行一次本地随机测试。
- [ ] `OTP-1104` 对 intent、验签、replay consume、key commit、migration、task exit、health、
  switch、rollback 和 audit sink 逐阶段做 failure injection。
- [ ] `OTP-1112` 对防重放/receipt 状态机做线程与进程并发、kill -9、ctl/task/engine/host restart、
  fsync 前后、rename 前后、锁获取/释放和响应丢失窗口测试。
- [ ] `OTP-1105` 真实 Docker、Podman、systemd 检查 `/proc`、inspect、mount、uid、capability、
  network、rootfs、port、cleanup 和 secret scan。
- [ ] `OTP-1106` 测量 envelope size、sign/verify time、task startup time、peak RSS 和恢复耗时；
  与当前一次性任务基线比较，不使用未经测量的百分比宣传。
- [ ] `OTP-1107` 通过正式签名 tagged Release 完成每个声明支持模式的 clean install、upgrade、
  failed update rollback、identity rotation、break-glass 和 audit restore。
- [ ] `OTP-1108` 检查当前 OIDF suite matrix 是否含本地控制面相关测试，记录具体计划/模块或
  “无覆盖”；运行适当 OAuth/OIDC/FAPI 回归证明对外行为无退化。
- [ ] `OTP-1109` 在公共部署执行 health、Discovery、TLS、UI 和一次真实安全升级 smoke，保留
  前后版本、request ID 和 rollback 准备证据。
- [ ] `OTP-1110` 编写最终验收报告，逐项映射计划书第 18 节和 `INV-01` 至 `INV-18`，列出实际
  数量、环境、版本、失败、跳过与未验证边界。
- [ ] `OTP-1113` 通过私有部署服务器的 SSH 别名只读盘点 NazoAuth 服务、容器、镜像、network、volume、
  systemd、端口、反向代理引用、配置/数据/identity/keys/audit 路径和本地 OIDF suite；保存
  非秘密现状与归属证据。
- [ ] `OTP-1114` 逐个验证绝对路径和资源标签后，彻底删除且只删除 `auth.nazo.run` 的现有
  NazoAuth 服务、部署、PostgreSQL/Valkey 数据、配置、身份、密钥和审计状态；证明无关服务
  未受影响，旧状态不可用于新安装。
- [ ] `OTP-1115` 仅使用本次正式公开 Release，从零执行 install、status、doctor、update plan、
  update、rollback、migrate、keys、audit、identity rotation、break-glass 和故障恢复；普通
  确认使用 `--yes`/正式非交互接口，不跳过任何安全门。
- [ ] `OTP-1116` 从远端清理开始的任一错误、卡住、超时、人工内部修复、扩大权限或安全绕过
  都将该轮标记 FAILED；修复代码并完成本地门后，重新删除全部 NazoAuth 专属状态，从 install
  重新执行，不从失败步骤续跑。
- [ ] `OTP-1117` 管理与安全旅程全部通过后，使用同机私有 OIDF suite 串行运行项目当前
  正式声明的完整 plan/variant 矩阵；不得抽样、关闭能力、改判定或添加无规范依据 skip。
- [ ] `OTP-1118` 最终报告包含 commit、Release/build identity、artifact/OCI/binary digest、完整
  命令、退出码、request IDs、远端证据、OIDF suite 版本、全部 plan/variant/module 结果和路径，
  并且结论严格为 PASSED、FAILED 或 BLOCKED。

### 验收

- [ ] 计划书第 18 节全部勾选，且每项链接到对应证据。
- [ ] 没有测试失败、未解释的跳过或预期失败被隐藏在汇总数字中。
- [ ] fake runtime、真实 runtime、signed Release、公网和 OIDF 结果分别报告。
- [ ] 最终报告明确残余 root/engine risk、外部依赖网络边界和本地/外部审计保证差异。
- [ ] 所有测试容器、网络、volume、临时密钥和 canary 数据按记录清理，保留的证据已脱敏。
- [ ] 远端零状态安装、全部公开管理旅程、全部安全验证、完整 OIDF 矩阵和最终证据五项同时
  成立；否则不得使用 PASSED 或宣布任务完成。

## 16. 最终验收旅程

以下旅程必须由正式发布制品在真实环境完成，不接受仅调用内部 API 的测试替代。

### Journey A：零秘密首次安装

```bash
sudo nazoauthctl install --public-url https://auth.example.com
sudo nazoauthctl status
sudo nazoauthctl doctor
sudo nazoauthctl audit verify
```

预期：无需用户生成秘密、编辑文件或理解容器挂载；服务 ready，Discovery issuer 正确，身份
和审计链有效，输出给出下一步。

### Journey B：一键安全升级

```bash
sudo nazoauthctl update --plan
sudo nazoauthctl update --yes
sudo nazoauthctl status
sudo nazoauthctl audit show --request-id REQUEST_ID
```

预期：签名验证、备份、任务授权、迁移、切换、健康检查和 commit 全部可见；秘密不泄露；
同一请求重试不重复变更。

### Journey C：密钥检查与生成

```bash
sudo nazoauthctl keys list
sudo nazoauthctl keys generate-local --alg ES256 --purposes credential --yes
sudo nazoauthctl keys validate
```

预期：只读操作无写权限；生成任务只有 key store 写权限；返回一个 kid 和 request ID；kill/
重试不会产生第二把逻辑密钥。

### Journey D：失败和自动回滚

在候选健康检查前注入可控失败，再执行：

```bash
sudo nazoauthctl update --yes
sudo nazoauthctl recover-update --yes
sudo nazoauthctl status
sudo nazoauthctl audit show --request-id REQUEST_ID
```

预期：仅在 artifact/schema compatibility 已证明时恢复上一版本 ready，输出明确“制品已回滚、
schema 是否变化、是否触及 barrier”；审计保留失败候选、双层 target identity 和恢复结果，
不删除失败证据。另行演练 backup/PITR restore 和不可逆 migration barrier，二者不得显示为
普通数据库自动回滚。

所有观察命令在持久 update journal 或 identity transition 未收敛时必须保持只读并 fail
closed，分别指向 `recover-update --yes` 或 `recover-identity --yes`；不得通过读取配置隐式
继续任务、启动/停止 runtime、归档密钥、写审计或删除 journal。

### Journey E：离线恢复与身份轮换

在 NazoAuth server 停止、在线批准不可用时执行文档化 break-glass，恢复后轮换 controller
和 audit key，再验证旧 key 请求被拒绝。

预期：恢复不依赖运行中服务；break-glass 有高优先级证据；新 key 完成真实任务后旧 key
退役；审计链跨轮换可验证。

## 17. 最终交付清单

- [ ] `nazo-operator-protocol` 共享 crate 和两个真实消费者。
- [ ] 新 `nazoauth operator-task` 封闭执行入口。
- [ ] 类型化、稳定、易用的 `nazoauthctl` 命令树。
- [ ] 自动 deployment/controller/audit identity 和可恢复轮换。
- [ ] operation-specific Docker、Podman、systemd sandbox。
- [ ] key/migration 防重放与持久执行收据。
- [ ] 闭环脱敏审计、离线 verify 和可选外部检查点。
- [ ] Release protocol compatibility 和安全升级桥接。
- [ ] 中英文用户文档、威胁模型、架构和运维文档。
- [ ] 分层测试与真实环境验收报告。

在以上项目未全部完成前，本任务状态必须保持“实施中”或“部分完成”，不能表述为完整安全
控制面支持。
