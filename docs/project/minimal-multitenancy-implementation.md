# NazoAuth 动态多租户：最终实施方案与状态

工作分支：`feature/minimal-multitenancy`  
Worktree：`D:\self\NazoAuth-multitenancy`  
状态：实施中；代码已分 workstream 落盘，尚未取得一次覆盖全部变更的统一编译、测试和真实多实例验证结论。

## 目标与第一性原则

新增、更新、禁用租户是目录数据变更，不是进程配置变更：不重启进程、不生成组合包、不让请求读取 PostgreSQL 或 Valkey。

租户目录的唯一权威是 PostgreSQL。Valkey 只传播已知目录 snapshot；本机内存只服务请求。三个层次职责不可互换：

| 层 | 所有权 | 可做的事 | 不可做的事 |
|---|---|---|---|
| PostgreSQL | active tenant/realm/organization/binding 与单调 revision | 动态 SQL 写入、权威读取、审计与状态约束 | 直接服务每个 HTTP 请求 |
| Valkey | deployment/state-epoch 下的派生 snapshot | 1 秒级加速跨进程传播、缓存修复 | 成为权威、反写到 PostgreSQL、决定请求租户 |
| `ArcSwap<TenantHostIndex>` | 单一进程 | Host 到完整 `TenantRuntime` 的无锁快照解析 | DB/KV I/O、部分更新、跨进程协调 |

请求路径固定为：`canonical Host → ArcSwap immutable index → Arc<TenantRuntime> → Actix app-data`。未知 Host 直接 404；所有既有 handler 仍提取已有 `web::Data<T>`，不增加 `X-Tenant-ID` 或 handler 级 tenant 参数。

## 动态目录与可见性

动态操作直接写 PostgreSQL 的租户目录：创建/更新 binding，或变更 tenant、realm、organization 的 active 状态。目录 mutation 与 revision 更新必须在同一数据库事务中完成；进程不读取或写回 `TENANTS_JSON`。

```text
DB authority snapshot (revision R)
  ├─ 启动：读完整 snapshot，所有 candidate 成功后一次性发布本机 index
  ├─ 每 5 秒：读 DB revision；与 last_database_revision 或本机 index 不一致时
  │            读完整权威 payload、build+swap，并可 publish_authoritative 到 Valkey
  │
Valkey derived snapshot (revision R)
  └─ 每 1 秒：较新的有效 revision 可先 build+swap；miss/corrupt/unavailable 回退 DB

ArcSwap<TenantHostIndex>
  └─ 每个请求只读一次 immutable snapshot；不访问 DB/Valkey
```

因此可见性是有界而非瞬时：正常 cache 传播目标约 1 秒；cache 丢失、损坏、不可用或被拒绝时由 5 秒 DB 对账恢复（另加一次 candidate build 时间）。DB 永远纠正 cache：cache 发布不推进 `last_database_revision`；DB 会验证同 revision 的完整 payload；cache revision 超前 DB 时恢复 DB snapshot 并隔离该 cache revision，直到 DB 追上。只有 DB 读取的 snapshot 可调用 Valkey `publish_authoritative`，cache candidate 永不回写。

## 目录、构造与生命周期不变量

1. `external_host` 必须已是 `canonical_tenant_host` 的规范形式；issuer URL host 必须相同，issuer 端口不参与路由。
2. 一张 snapshot 不允许重复 tenant ID、规范 issuer 或 Host；任一 binding 无效、candidate 无法构造或 lifecycle 无法启动，整张 last-good index 不替换。
3. 目录管理模式只能使用 trusted-proxy。DB directory 已有历史但部署为 Direct TLS 时不发布动态 candidate；保留空/last-good index 并明确报错。
4. 动态 tenant 的 key 与 avatar 目录固定派生为 `DATA_DIR/tenants/{tenant_id}/{keys|avatars}`；目录模式拒绝 `JWK_KEYS_DIR` 和 `AVATAR_STORAGE_DIR` 覆盖。
5. KeyManager、tenant DB boundary、tenant Valkey namespace 与服务图一起由 `TenantRuntime` 所有。相同 tenant 的 binding 更新复用其 key/lifecycle Arc，避免两个 key lifecycle 并发写同一 keyset；新 tenant 才建立新 lifecycle。
6. 发布顺序是“全部 candidate 可用 → 原子 swap → retire 不再被新图复用的旧 lifecycle”。删除先从 index 消失；KeyManager cooperative stop 并等待，CIBA worker abort+await；旧请求仍持有旧 Arc 至完成。
7. backchannel logout outbox 是进程级 DB 队列，只启动一个 worker；不能按 tenant 重复 claim。
8. CORS 按 Host 从同一内存 registry 读取该 tenant origins，不使用 process baseline 的 origins，也不在 CORS/request 路径读外部存储。

## 部署级控制面与系统管理员

部署级控制不是“任一 tenant admin”能力。每个进程在 `ProcessRuntime.control_tenant_id` 中只保存一个控制租户：

- revision-0 legacy bootstrap：沿用已解析 Settings 的 `TENANT_ID`，兼容现有自定义控制租户；
- DB dynamic directory：固定 `DEFAULT_TENANT_ID`，绝不由 directory 或 `TENANTS_JSON` 排序决定；若没有其 active Host binding，部署级 HTTP control 自然不可路由。

`/.well-known/nazoauth-control`、runtime modules、controller registry/recovery、controller slots 与 perf metrics 等部署级 route 必须同时满足：请求 Host 已解析到 control tenant、请求 tenant context 等于 `control_tenant_id`，以及业务授权要求。它们还必须绑定当前 `deployment_id`，不能通过 URL/请求参数跨 deployment 访问状态。

系统管理员不是额外的角色事实源：定义为“control tenant 的有效 admin，且 `admin_level >= 2`”。普通 tenant 的 admin（无论其 level）只拥有本 tenant 范围。跨 tenant 管理采用独立端点 `PUT/DELETE /admin/tenants/{tenant_id}/admins/{user_id}`，而不把跨 tenant 语义塞进原 tenant-local user PATCH：

1. 在一个事务中锁定 actor/target，重新验证 actor 是系统管理员；
2. 验证 target 属于显式 target tenant，且 target 不是系统 tenant；
3. grant 写精确 `admin/level 1`，revoke 写精确 `user/level 0`；
4. 用户状态与带 actor/target tenant 的安全审计同事务提交。

该端点、deployment binding 和对应数据库约束/测试目前由 `system_admin_impl` workstream 实施；在其完成前不可宣称跨租户管理员管理已交付。

## legacy 兼容与明确限制

当 DB directory revision 为 0 且没有 active binding，保留现有单租户/TENANTS_JSON Settings 仅作为 revision-0 bootstrap：直接用已解析 Settings 构造初始 runtime，以保留 Direct TLS、自定义 JWK 目录与现有 OpenID4VC 行为。

一旦 DB directory 有历史，DB 是完整运行期目录；legacy 配置只提供稳定的进程 baseline（静态 route 集合、control discovery、模块初始化），不再决定请求 tenant。首版目录模式不支持 Direct TLS 或 OpenID4VC 的动态 tenant 图；这是明确拒绝而非悄悄降级。

## 文件责任与当前进度

| 范围 | 状态 | 当前责任 |
|---|---|---|
| identity DTO、PostgreSQL directory port/migration/revision | 实施中 | directory contract workstream |
| Valkey directory cache semantic port | 已落盘，待统一验证 | transient-state workstream |
| Settings directory binding 与 tenant 路径 | 已落盘，待统一验证 | dynamic runtime workstream |
| `tenant_runtime.rs` registry/refresher/lifecycle | 已落盘，待统一验证 | dynamic runtime workstream |
| Actix Host binder、CORS、control tenant guard | 已落盘，待 HTTP 验证 | Actix workstream |
| deployment-bound system admin 管理端点 | 实施中 | `system_admin_impl` workstream |
| PostgreSQL/Valkey storage invariants | 实施中 | storage workstreams |
| runtime/settings/HTTP tests | 已新增或扩展，待统一 Cargo 结果 | test workstreams |

## 验证边界与停止条件

当前已做的静态证据是最近一次 `cargo fmt --all -- --check` 与 `git diff --check` 通过；它们不代表编译或行为正确。当前统一 Cargo 运行期间不并发修改生产代码。

完成条件至少包括：

1. 当前精确 worktree 的 Rust 编译和相关 unit/integration tests 通过；
2. runtime tests 覆盖 cache 新/旧/equal revision、DB fallback、同 revision DB 纠正、cache 超前回滚、candidate failure last-good、in-flight Arc 与 disable；
3. settings 测试覆盖 host/issuer/duplicate、trusted-proxy、动态 key/avatar 路径；
4. Actix Host A/B HTTP 测试证明 tenant `Data<T>`、CORS、system-only 404 和 legacy custom control tenant；
5. PostgreSQL mutation/revision 与 Valkey cache contract tests 通过；
6. 至少一次真实多进程收敛与 cache unavailable 恢复验证。

在这些命令和场景实际成功前，整体状态为 **INCOMPLETE**。回滚在未合并前仅需丢弃该 worktree/branch；部署回滚必须同时恢复旧二进制与匹配的 Valkey state epoch，不能混用新旧 namespace。
