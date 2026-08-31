# T2：控制面与管理员权限

## 状态与边界

状态：`IMPLEMENTED / LOCALLY VALIDATED`。

动态目录需要低频、鉴权、幂等且可审计的生产管理入口。它不需要第二套角色系统、管理 UI、CommandBus 或测试租约。

## 权限

- tenant admin 只能管理本 tenant 的用户和客户端。
- system admin 必须同时属于 control tenant、有效且 `admin_level >= 2`。
- 现有 `PATCH /admin/tenants/{tenant_id}/users/{user_id}/admin` 是系统管理员管理普通 tenant admin 的唯一 HTTP 入口；CSRF、近期 MFA、actor/target 锁后复核与耐久审计保持不变。
- 租户生命周期由现有签名 controller task 承担，不增加第二套 HTTP lifecycle route。

## 签名目录操作

控制协议现在提供：

- `tenant-directory-create`
- `tenant-directory-update`
- `tenant-directory-disable`
- `tenant-directory-reload`
- `tenant-directory-finalize`
- `tenant-directory-describe`

每个 mutation 绑定 deployment、operation JTI、request hash、target tenant 与 expected global directory revision。repository 在单一 PostgreSQL 事务中完成：

```text
lock operation identity and directory revision
    -> reject replay conflict or stale revision
    -> apply authoritative mutation
    -> append security audit
    -> persist replay-safe outcome
    -> commit
```

相同 JTI 与相同 request hash 返回已记录 outcome；相同 JTI 携带不同请求永久冲突。`describe` 返回全局 revision 及每个 binding 的 `runtime_revision`。

`reload` 不理解 TLS、OpenID4VC 或文件路径。它只把目标租户 `runtime_revision + 1`，由普通目录触发器推进全局 revision；各进程随后按同一 candidate 流程重建目标租户。

## 明确不做

- 不新增 `system_admin` 字段、角色表或 RBAC 引擎。
- 不让普通 tenant 的高 `admin_level` 获得系统权限。
- 不让 NazoAuthCtl 成为在线请求依赖。
- 不新增 stage/activate/revoke 通用 material 模型；当前确定性文件加 reload 已满足真实消费者。
- 不创建外部测试专用租户类型、租约、配额或清理器。
- 不物理删除 tenant 业务数据；`finalize` 只在上层确认依赖清理后移除目录 binding。

## 最终验收

- 签名、expiry、JTI replay、deployment/tenant mismatch 与 stale revision。
- create/update/disable/reload/finalize/describe 的 PostgreSQL 原子性、审计及 crash 后重试。
- system admin、tenant admin、跨租户和并发降权安全矩阵。
- mutation 后两个服务进程有界收敛，reload 只替换目标 tenant runtime。

## 回滚

控制 operation ledger 与审计是已发生事实，不因二进制回滚删除。回滚前必须确认旧二进制理解当前 operation schema 和 migration head。
