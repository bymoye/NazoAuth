# T1：运行时目录与生命周期

## 必要性判断

状态：`REQUIRED / PARTIAL`。

必要原因不是“需要一层租户 Repository”，而是后续 Direct TLS、OpenID4VC 和控制面都必须依赖同一个动态 tenant 真相与确定的发布/退役时序。当前基础已存在，但仍缺真实 mutation、多进程和完整生命周期证据。

若现有实现和测试已经覆盖某一项，则直接保留，不重写。不得为了文档对称再造第二套目录接口。

## 当前代码事实

主要路径：

- `crates/authorization-server/src/bootstrap/startup/tenant_runtime.rs`
- `crates/authorization-server/src/bootstrap/startup/configuration.rs`
- `crates/authorization-server/src/bootstrap/transient_state.rs`
- `crates/identity/src/tenancy.rs`
- `crates/persistence-postgres/src/repositories/tenancy.rs`
- `crates/state-store-valkey/src/tenant_directory.rs`
- `migrations/20260831000100_dynamic_tenant_directory/`
- `migrations/20260831000200_fix_tenant_runtime_directory_trigger/`

当前模型：

```text
PostgreSQL authoritative snapshot + revision
        -> Valkey derived snapshot
        -> candidate TenantRuntime graph
        -> atomic ArcSwap<TenantHostIndex>
```

请求只读本机索引。正常 Valkey 检查间隔为 1 秒，DB revision 对账间隔为 5 秒。cache miss、损坏、语义非法或超前时由 DB 权威纠正；候选构造失败时不替换 last-good。

## 本任务边界

本任务只负责：

1. tenant binding 的权威数据和 revision；
2. snapshot 校验、传播、构造和原子发布；
3. `TenantRuntime` 的创建、复用、替换和停止；
4. mutation 后的有界可见性与故障恢复；
5. 为 T2-T4 提供稳定的 tenant/material/lifecycle 契约。

不负责：

- HTTP/Operator 的身份认证和授权；
- TLS ClientHello/SNI 处理；
- OpenID4VC 协议配置细节；
- OIDF Suite 编排；
- 每个请求的 tenant 参数传递。

## 最短实施路径

### 1. 复核目录契约

确认一张权威 snapshot 至少保证：

- `external_host` 已 canonicalize；
- issuer 为合法 HTTPS URL，且 host 与 binding host 一致；
- tenant、realm、organization 归属一致且均 active；
- tenant ID、canonical host、canonical issuer 在 snapshot 内唯一；
- revision 单调，运行角色不能直接修改 revision state；
- `TRUNCATE` 和所有有效 mutation 都推进 revision；revision 0 只表示尚未初始化，server 必须失败关闭。

已有约束满足时只补测试，不新建 validator 层。

首次安装只有一条入口：`nazoauth tenant-bootstrap`。它固定使用 system tenant/realm/organization，在目录 state 行锁事务内写入首条 binding；相同 binding 重放成功，不同 binding 或其他目录历史失败。`nazoauth migrate` 保持 schema-only，server 只读权威目录，不存在静态配置回退。

### 2. 固定 mutation 原子性

目录写入必须在一个 PostgreSQL 事务内完成：

```text
lock/recheck current revision
  -> validate referenced tenant/realm/org
  -> apply binding or status change
  -> database trigger advances revision
  -> commit
```

不得先写 Valkey。Valkey 只由读取到的 DB 权威 snapshot 发布。

本步骤只提供一个具体的 PostgreSQL 原子操作边界，供 T2 的真实控制面消费者使用；如果现有 port 已能表达，不创建新的通用 repository。

### 3. 完成 runtime 发布时序

一次 refresh 必须遵守：

1. 读取完整 candidate；
2. 校验全部 binding；
3. 构造或复用全部 `TenantRuntime`；
4. 所有新 lifecycle 启动成功；
5. 一次 `ArcSwap` 发布完整 index；
6. 再停止未被新图引用的旧 lifecycle。

同 tenant 未改变的资源必须复用，避免两个 key/revocation/CIBA worker 同时写同一状态。删除或禁用 tenant 后，新请求不可再命中；已经持有旧 `Arc<TenantRuntime>` 的请求允许完成。

### 4. 为后续 material 建立最小 revision 契约

T3/T4 需要知道“哪个 tenant runtime 使用哪一版 material”，但本任务不预建通用 material provider。

仅在真实字段确定后，将具体 material/profile revision 纳入 binding snapshot 与 candidate equality：

- revision 改变才重建相关 runtime；
- digest/revision 不匹配时 candidate 失败；
- 未改变的 runtime 不重启；
- stale writer 不能覆盖新 revision。

### 5. 验证真实传播

至少启动两个服务进程，共享 PostgreSQL/Valkey：

- 新增 tenant：两个进程在有界时间内可路由；
- 更新 issuer/host：旧值失败、新值生效；
- disable/delete：两个进程均停止接受新请求；
- Valkey 不可用：DB 对账恢复；
- 高 revision 坏 cache：DB snapshot 可修复；
- 一个进程 candidate 构造失败：该进程保留 last-good，不影响另一进程。

## 明确不做

- 不创建 PostgreSQL launcher 与 Valkey launcher 的共同 storage 抽象；
- 不把 `pgsql_url`、`valkey_url` 改成额外文件/URL indirection；
- 不引入事件总线；1 秒缓存传播和 5 秒 DB 对账已满足动态目录目标；
- 不为强一致请求路由加入每请求 DB 查询；
- 不支持同一 Host 映射多个 tenant，也不做“默认 tenant”回退；
- 不为未出现的第二目录实现预建 trait。

## 验收

- 单元：revision stale/equal/ahead、candidate failure、Arc 复用、in-flight request；
- PostgreSQL：事务、触发器、约束、并发 revision、权限；
- Valkey：wire schema、损坏修复、CAS、namespace；
- 多进程：上述新增/更新/禁用/故障场景；
- 性能：请求路径目录 DB/KV 调用计数为 0。

完成报告必须给出精确提交、真实服务数量、间隔配置、命令、退出码和未覆盖边界。

## 停止与回滚

- 无真实 T2/T3/T4 消费字段时，不增加 material 字段；
- candidate 无法全量构造时停止发布并保留 last-good；
- 迁移失败时停止启动，不通过空目录继续运行；
- 回滚必须核对 migration floor 和 Valkey state epoch。
