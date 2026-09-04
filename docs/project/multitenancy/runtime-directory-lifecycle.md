# T1：运行时目录与生命周期

## 状态

状态：`IMPLEMENTED / LOCALLY VALIDATED`。

## 权威模型

```text
PostgreSQL authoritative snapshot + revision
        -> Valkey derived snapshot v2
        -> complete TenantRuntime candidate
        -> atomic ArcSwap<TenantHostIndex>
```

请求只读本机索引。Valkey 快照损坏、缺失或超前时由 PostgreSQL 权威纠正；数据库定时对账保证缓存不可用时仍能收敛。candidate 任一租户构造失败时不替换 last-good。

## binding 契约

每个 `TenantDirectoryBinding` 包含 tenant/realm/organization、canonical host、HTTPS issuer 与正整数 `runtime_revision`。PostgreSQL、Valkey wire schema、进程快照和控制协议共同校验：

- tenant、realm、organization 归属且 active；
- host、issuer host、tenant ID 在快照中唯一并一致；
- global directory revision 单调；
- tenant-local runtime revision 为正数；
- runtime 数据库角色不能直接修改 revision state。

Valkey schema 已硬切为 v2，不保留 v1 兼容读取。

## 发布与退役

1. 读取完整 candidate。
2. 校验全部 binding。
3. binding 完全相同时复用整个 `Arc<TenantRuntime>`。
4. binding 或 `runtime_revision` 改变时构造新服务图及 lifecycle。
5. 一次发布完整 Host index。
6. 再停止不被新图引用的旧 lifecycle。

禁用/移除后新请求不可命中；已持有旧 `Arc` 的请求允许完成。新 runtime 构造失败时旧 runtime 与 worker 继续服务。

## 权威 mutation

create/update/disable/reload/finalize 都在 PostgreSQL 事务内锁定并复核 expected revision，应用目录变更后由数据库 trigger 推进 revision。Valkey 永远不参与写入决策，也不能反写数据库。

`reload` 是唯一通用材料重建信号；它不携带路径、URL、类型或 provider。没有真实第二实现，因此不增加 material repository。

## 明确不做

- 不创建 PostgreSQL launcher 与 Valkey launcher 的共同抽象。
- 不把 `pgsql_url`、`valkey_url` 改成文件或 URL indirection。
- 不在每个请求查询 DB/KV。
- 不引入事件总线或默认 tenant 回退。
- 不为外部测试工具增加任何目录字段或生命周期。

## 最终验收

- 单元：stale/equal/ahead、candidate failure、Arc 复用、in-flight request。
- PostgreSQL：事务、trigger、约束、并发 revision 和权限。
- Valkey：v2 wire、CAS、损坏修复、state epoch 与 namespace。
- 双进程：新增、更新、禁用、reload、缓存不可用与高 revision 坏快照。
- 请求路径目录 DB/KV 调用计数为 0。

## 回滚

迁移失败则停止启动。回滚必须核对 migration head、Valkey state epoch 与 runtime revision；candidate 失败始终保留 last-good。
