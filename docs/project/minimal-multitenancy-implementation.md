# NazoAuth 动态多租户完整实施总纲

本文是动态多租户后续工作的唯一主计划。子任务只描述各自独立的责任和验收边界，不重复本文中的全局原则。

## 当前结论

代码基线 `668ef495` 已交付动态多租户基础并删除 revision-0 静态兼容态，但还没有完成 [GitHub #144](https://github.com/nazozero/NazoAuth/issues/144) 的全部验收：

- 已有 PostgreSQL 权威目录、Valkey 派生快照和进程内 `ArcSwap<TenantHostIndex>`；
- 请求按规范 Host 从本机不可变索引取得 `TenantRuntime`，不查询目录数据库或缓存；
- 租户可动态新增、更新和禁用，目录候选失败时保留 last-good；
- 控制租户、系统管理员和租户管理员已有明确边界；
- 目录模式支持 loopback-http 与 trusted-proxy，并明确拒绝动态 Direct TLS；
- 目录模式当前明确拒绝 OpenID4VC；
- 首次安装固定执行 `migrate → tenant-bootstrap → server`；migrate 只维护 schema，server 不隐式写目录；
- 受限 conformance tenant 的完整创建、配额、到期、清理和 NazoAuthCtl 黑盒链路尚未交付。

因此当前状态是 **FOUNDATION DELIVERED / EPIC INCOMPLETE**，不能关闭 #144。

## 第一原则：先证明必要，再实施

任何子任务、迁移、抽象、配置、后台任务或兼容层开始前，必须回答以下问题：

1. 它解决哪一项当前可复现的用户需求、安全不变量或验收缺口？
2. 当前代码为什么不能在不修改的情况下满足？证据路径或测试是什么？
3. 最少需要改变哪个权威状态、生命周期或协议边界？
4. 谁是当前真实消费者？没有当前消费者的扩展点不创建。
5. 删除该步骤后，哪项验收会失败？如果没有明确答案，该步骤标记为 `NOT NEEDED` 并停止。

“未来可能支持第二种实现”“看起来更分层”“顺手统一”都不构成必要性。严禁：

- 为 PostgreSQL、Valkey、TLS、OpenID4VC 再套无消费者的通用 Provider/Repository；
- 建立第二套租户、角色、权限、配置或 revision 事实源；
- 将任意 URL、文件路径或自由 JSON 链路引入目录，只为绕过明确的数据所有权；
- 为每种持久数据库和 KV 组合生成不同产物；仍然只构建一个总包；
- 在 handler 中重复解析 tenant，或在请求路径读取目录 DB/Valkey；
- 为兼容未发布方案保留双路由、双字段、双状态机；
- 创建无法停止、无法归属 tenant、失败时无法保留 last-good 的后台任务；
- 把 OIDF Suite、plan、module、WebDriver 或测试专用行为放回 NazoAuth。

## 不变量与状态所有权

| 层 | 唯一职责 | 允许 | 禁止 |
|---|---|---|---|
| PostgreSQL | 租户目录及其单调 revision 的权威 | 原子 mutation、约束、审计、权威 snapshot | 服务每个请求；接受 Valkey 反写为权威 |
| Valkey | deployment/state-epoch 下的派生目录快照 | 低延迟传播、损坏快照修复、租户业务状态命名空间 | 决定租户真相；与持久数据库 launcher 耦合 |
| 进程内索引 | 当前进程的请求路由快照 | `Host/SNI -> Arc<TenantRuntime>`；原子发布 | 外部 I/O；部分发布；跨进程协调 |
| `TenantRuntime` | 一个 tenant 的服务图与后台生命周期 | tenant-scoped DB/KV、key、trust、OpenID4VC、stop handles | process-global 可变配置；跨 tenant 共享秘密状态 |
| 控制面 | 低频、鉴权、审计的租户/material mutation | deployment/tenant/revision 绑定的幂等任务 | 参与在线 token/authorization 判断 |

请求路径固定为：

```text
transport identity
  -> canonical SNI/Host
  -> local immutable tenant index
  -> Arc<TenantRuntime>
  -> existing Actix app-data and protocol handlers
```

未知、重复或不一致的 SNI、Host、issuer、tenant、material revision 必须失败关闭。

## 主任务与依赖顺序

只保留五个具有独立状态所有权和验收边界的子任务：

1. [运行时目录与生命周期](multitenancy/runtime-directory-lifecycle.md)
2. [控制面与管理员权限](multitenancy/control-plane-and-admin.md)
3. [动态 Direct TLS](multitenancy/direct-tls.md)
4. [租户级 OpenID4VC](multitenancy/openid4vc.md)
5. [受限 conformance tenant 与 NazoAuthCtl](multitenancy/conformance-tenant-and-ctl.md)

依赖关系：

```text
T1 运行时目录与生命周期
        |
        v
T2 控制面与管理员权限
      /   \
     v     v
T3 Direct TLS    T4 OpenID4VC
      \           /
       v         v
T5 conformance tenant + NazoAuthCtl
```

T3 与 T4 只有在 T1/T2 的 tenant、revision、material 和 lifecycle 契约稳定后才可并行。T5 不得通过测试专用接口绕过前四项。

## 当前事实与剩余缺口

| 能力 | 当前事实 | 剩余工作 | 状态 |
|---|---|---|---|
| 动态目录 | DB 权威、Valkey 缓存、本机索引已实现；revision-fenced 目录 mutation 原子边界已交付 | 多进程收敛黑盒证据已建立；证书/密钥/凭证等非路由 material 尚未进入 binding snapshot | PARTIAL |
| 管理权限 | control tenant 与 `admin_level >= 2` 系统管理员；已有跨租户 admin PATCH | 统一 tenant lifecycle 操作、审计 receipt、并发/幂等验收 | PARTIAL |
| trusted proxy / loopback | 动态 Host 路由已支持 | 与动态 Direct TLS 的同租户一致性矩阵 | PARTIAL |
| Direct TLS | process-global TLS snapshot 代码仍存在，但目录 runtime 明确拒绝激活 | SNI 时选择完整 tenant TLS context，并绑定 HTTP Host | NOT STARTED |
| OpenID4VC | 协议实现与部分 tenant predicate 已存在，但目录 runtime 明确拒绝激活 | crypto/trust/config/background 全部进入 `TenantRuntime` | NOT STARTED |
| conformance tenant | #144 定义了目标 | 普通 tenant 的配额、expiry、cleanup receipt 和 ctl 黑盒链路 | BLOCKED BY T1-T4 |

## 实施纪律

每个子任务必须按同一最短闭环执行：

1. 读取子文档列出的当前代码路径并复核事实；
2. 写出必要性结论：`REQUIRED` 或 `NOT NEEDED`；
3. 若为 `REQUIRED`，先增加能暴露真实缺口的行为测试或可执行契约；
4. 只修改使该测试和验收成立的最小生产路径；
5. 运行聚焦验证，再运行受影响边界的集成验证；
6. 记录精确提交、命令、退出码、通过数、未验证项和回滚点；
7. 当前子任务未达到完成条件时，不启动依赖它的后续任务。

不要以文件数量、trait 数量或“层次完整”作为产出。产出只能是已满足的不变量和可复核证据。

## 全局验证矩阵

最终验收必须分别报告以下证据，不能互相替代：

- 静态：格式、Clippy、依赖边界、迁移校验；
- 单元：canonical identity、revision fence、authorization、lifecycle state machine；
- PostgreSQL：mutation/revision/约束/事务/并发；
- Valkey：派生缓存、损坏修复、stale/ahead revision、tenant namespace；
- HTTP：双租户相同标识隔离、system-only route、CORS、metadata；
- TLS：真实 SNI、证书、mTLS client trust、reload、SNI/Host mismatch；
- OpenID4VC：VCI/VP/attestation/revocation 的跨租户隔离与动态启停；
- 多进程：新增、更新、禁用、缓存不可用、DB 对账、last-good；
- 控制面：幂等、stale revision、错误 deployment/tenant、审计 receipt；
- 黑盒：NazoAuthCtl 创建普通受限 tenant，运行外部 OIDF driver，并完成可复核清理。

完整工作区测试不等于真实 TLS、多进程或公开黑盒；公开黑盒也不替代迁移恢复和并发验证。

## 完成条件

只有同时满足以下条件，主任务才可关闭：

1. 动态 tenant 在 trusted-proxy 与 Direct TLS 下解析到同一 tenant，或失败关闭；
2. OAuth/OIDC、CIBA、OpenID4VC、mTLS、Valkey、审计和后台任务均证明跨租户隔离；
3. tenant create/update/disable/delete、key/trust rotation 有确定、幂等、可审计的生命周期；
4. conformance tenant 有配额、expiry、显式 cleanup 和签名 receipt；
5. NazoAuthCtl 完成外部黑盒运行，其他 tenant 的可观测状态保持不变；
6. NazoAuth 不包含 OIDF Suite 专用资源、路由、schema 或行为；
7. 所有证据针对同一精确提交，并明确记录未覆盖边界。

## 回滚原则

- 每个子任务独立提交，后续任务不得把未验收状态作为新事实源；
- schema 变更必须先保证旧二进制不会误读，再提供可验证的前向恢复路径；
- runtime candidate 失败保留 last-good，禁止发布半成品 index；
- material rotation 失败保留最后有效 revision，禁止回退旧 writer；
- 回滚二进制时必须同时核对 migration floor、state epoch 和 material revision，不能只替换可执行文件。

## 当前验证证据

代码提交 `4a3447fd`、CI 修复 `668ef495`（GitHub 对应 `91687e1`、`8c935556`）已完成：

- `cargo fmt --all -- --check`：通过；
- `git diff --check origin/main...HEAD`：通过；
- `cargo check --locked --offline -p nazo-oauth-server -p nazo-oauth-server-postgres -p nazo-postgres -j1`：通过；
- `cargo test --locked -p nazo-oauth-server --lib bootstrap::startup::tenant_runtime::tests:: -j1`：13 通过。
- `cargo test --locked --offline -p nazo-postgres --test tenancy -j1`：1 通过，覆盖首次初始化并发、幂等与冲突；
- `cargo test --locked --offline -p nazo-postgres --test admin_provision -j1`：2 通过；
- `cargo clippy --workspace --all-targets --all-features --locked --offline -j1 -- -D warnings -A linker_messages`：通过；
- 总包真实命令链：migrate 后 `revision=0/bindings=0`，tenant-bootstrap 后 `revision=1/bindings=1`；相同输入重放不推进 revision，不同 issuer 失败关闭；
- GitHub `8c935556`：release-policy、code-quality、conformance-security 全部通过；真实安全矩阵覆盖双非 root 实例、RFC 9967、负载/竞态和 Valkey 故障注入；其父提交 `f029d12a` 的 CodeQL 与 Codecov 通过；
- NazoAuthCtl `6c31c7b0`：容器与 systemd 均在启动前执行 tenant-bootstrap，本地 16 项测试与 GitHub 四平台 CI 全部通过。

未完成：真实 Valkey 多进程收敛、动态 Direct TLS、动态 OpenID4VC 和 NazoAuthCtl 端到端部署验证。

## T1 运行时目录与生命周期：已交付证据

实现提交（分支 `feat/dynamic-multitenancy`）在现有 `TenantDirectoryRepository` 上补齐了
revision-fenced 权威 mutation 原子边界（`provision_tenant_binding`、
`update_tenant_binding`、`set_tenant_runtime_status`、`remove_tenant_binding`）。
每个操作在一个 PostgreSQL 事务内完成：`FOR UPDATE` 锁定目录 state 行 →
比对 expected revision（stale 返回 Conflict）→ 校验 boundary 归属与 active 状态 →
应用变更 → 触发器推进 revision → 读取新 revision 后提交。
相同输入重放为有界 no-op（不推进 revision）；不同输入对已初始化目录失败关闭；
路由身份（canonical host、issuer host 一致性）在写入前按运行时快照同一规则校验。

验证证据（本地 PostgreSQL 18.4 / Valkey 8.1.8 容器，分支 `feat/dynamic-multitenancy`）：

- `cargo fmt --all -- --check`：通过；
- `cargo clippy --locked --offline -p nazo-postgres -p nazoauth --all-targets -j1 -- -D warnings -A linker_messages`：通过；
- `cargo test --locked --offline -p nazo-postgres --test tenant_directory -j1`（DATABASE_URL 指向真实实例）：6 通过——
  provisioning 推进 revision 且幂等重放不推进、stale expected revision 返回 Conflict、
  update/disable/finalize 幂等语义、unbound/unknown tenant 失败关闭、
  并发写者经 revision fence 序列化（恰好一个成功）、受限 runtime 角色无法直写 revision state
  （trigger 为唯一写路径）；
- `cargo test --locked --offline -p nazoauth --test tenant_directory_convergence -j1`
  （真实 PG + Valkey + 两个真实 `nazoauth server` 进程 + migrate/tenant-bootstrap 命令链）：1 通过，37.9s——
  两进程在窗口内收敛新增（A 3.5–4.5s / B 亚秒）、host 更新旧值失败关闭、
  Valkey 代理完全中断时 5 秒 DB 对账仍送达 mutation（A ~6s）、
  高 revision 毒化快照经 DB 权威修复、disable 后两进程停止路由且 baseline/system tenant 可观测状态不变；
- 既有 13 个 refresher 单元测试（stale/equal/ahead、candidate 失败保留 last-good、
  Arc 复用、in-flight 请求）与本改动共存通过。

未验证边界：目录 mutation 的 HTTP/控制器入口（T2 交付）； Valkey 故障注入期间的真实多实例
安全矩阵（CI `conformance-security` 后续按 exact-head 复核）；按 tenant 的非路由 material
（证书/OpenID4VC）revision 绑定（T3/T4 交付）。
