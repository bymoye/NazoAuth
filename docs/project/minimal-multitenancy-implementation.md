# NazoAuth 动态多租户实施总纲

本文是动态多租户的主实施文档。NazoAuth 只实现生产租户能力；任何一致性工具都通过公开协议作为普通外部客户端使用，不进入产品代码、数据库或控制协议。

## 第一性原则

1. PostgreSQL 是租户目录的唯一权威，Valkey 只是可重建缓存。
2. 请求只读取进程内不可变租户索引，不在热路径访问 PostgreSQL 或 Valkey。
3. 持久数据库、KV、TLS 与协议运行时分别负责各自状态，不建立组合抽象或组合产物。
4. 只构建和发布一个总包；配置直接使用现有环境变量，不增加 URL 文件链路。
5. 只有当前生产消费者需要的字段和操作才实现，不建立预留 Provider、通用 material 表或测试专用租约。
6. 动态更新失败时保留 last-good；未知 Host、SNI、tenant、revision 或跨租户状态失败关闭。

## 权威状态与请求路径

```text
PostgreSQL tenant directory + monotonic revision
    -> Valkey derived snapshot
    -> candidate TenantRuntime graph
    -> atomic in-process Host index
    -> existing protocol handlers
```

`TenantRuntime` 拥有该租户的服务图、密钥、OpenID4VC 状态和后台任务。目录 binding 的 `runtime_revision` 是通用重建代次：运维先更新确定性本地材料，再通过签名 `reload` 操作推进代次；各进程据此只重建目标租户。

## 子任务与顺序

1. [T1 运行时目录与生命周期](multitenancy/runtime-directory-lifecycle.md)
2. [T2 控制面与管理员权限](multitenancy/control-plane-and-admin.md)
3. [T3 动态 Direct TLS](multitenancy/direct-tls.md)
4. [T4 租户级 OpenID4VC](multitenancy/openid4vc.md)

```text
T1 directory/lifecycle
        |
        v
T2 signed control operations
      /   \
     v     v
T3 TLS    T4 OpenID4VC
```

外部黑盒验证不是第五个服务器任务。它只创建普通租户、注册普通客户端并调用公开协议，不获得专用 schema、route、header、receipt 或清理语义。

## 已实现路径

- T1：动态目录、Valkey v2 缓存、进程内原子发布、last-good、多进程收敛与 `runtime_revision`。
- T2：签名 create/update/disable/reload/finalize/describe；目录 mutation、审计与幂等 outcome ledger 同一 PostgreSQL 事务提交；系统管理员与租户管理员权限保持分离。
- T3：部署级证书与 client CA 继续由 listener 持有；TLS 连接记录规范化 SNI，HTTP binder 在租户查找前强制 SNI 与 Host 相等。可覆盖新 Host 的 SAN/通配符证书无需重启。
- T4：每租户确定性 OpenID4VC 目录、从部署 root 派生的独立数据密钥和管理令牌、租户拥有的 revocation worker，以及 reload 驱动的动态重建。
- 已删除服务器内的外部测试专用租约、来源、OpenID4VP evidence/receipt 协议与对应迁移链。

## 明确不做

- 不把 Valkey 放入 PostgreSQL launcher，也不建立统一 Storage/KV Provider。
- 不存储任意 `pgsql_url`、`valkey_url`、证书路径或 OpenID4VC 路径 indirection。
- 不为数据库或 KV 组合生成多个发布产物。
- 不实现每租户 TLS listener、证书 Provider 或 client CA 池；当前部署证书边界已能满足动态 Host。
- 不为外部测试创建租约、到期清理器、runner、plan 或验证回执。
- 不为未出现的第二实现预留 trait。

## 最终验证顺序

所有编写完成后一次性执行：

1. 格式、静态契约、迁移清单与 Clippy；
2. 受影响 crate 的单元与 PostgreSQL/Valkey 集成测试；
3. 双进程动态目录与 reload 收敛；
4. 真实 TLS 的 SNI/Host 一致与错误组合；
5. 双租户 OpenID4VC 密钥、令牌、状态和后台生命周期隔离；
6. 全工作区测试与总包构建。

外部黑盒结果只能证明公开协议行为，不能替代跨租户、迁移、并发或生命周期证据。

## 完成条件

- 新增、更新、禁用、重载和移除租户均无需服务重启，并在多进程中有界收敛。
- SNI 与 Host 指向同一租户；不一致在任何业务处理前失败。
- OpenID4VC 数据密钥、管理令牌、文件和后台任务按 tenant 隔离。
- PostgreSQL、Valkey 与本机索引的权威关系保持单向，缓存损坏可由数据库修复。
- 仓库不存在外部一致性工具专用生产代码、schema、route、配置或控制操作。
- 所有证据针对同一提交，并明确报告未验证边界。

## 本地验证结果

- fresh PostgreSQL 18 数据库完整应用当前迁移链；迁移测试 15 项通过。
- PostgreSQL 目录控制 4 项、Valkey 62 项、签名目录控制进程与双进程动态收敛各 1 项通过。
- authorization server 全特性串行测试 1372 项通过、5 项按既有条件忽略。
- 全工作区全目标全特性 `cargo check`、Clippy `-D warnings`、静态契约、Python 96 项和总包构建通过。
- 外部公网 TLS、部署升级和生产负载不属于本地证据，仍需在目标环境独立验证。

## 回滚

候选构建或材料加载失败时不发布新索引。二进制回滚前必须同时核对 migration head、Valkey state epoch 与 tenant runtime revision；不得仅替换可执行文件后继续使用不匹配的状态。
