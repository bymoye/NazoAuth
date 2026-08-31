# T2：控制面与管理员权限

## 必要性判断

状态：`REQUIRED / PARTIAL`。

动态读取目录已经存在，但普通用户不能通过直接 SQL 承担租户生命周期。[GitHub #144](https://github.com/nazozero/NazoAuth/issues/144) 的 conformance tenant 也需要一个低频、幂等、可审计的真实管理入口。该入口是必要的；新管理框架、第二套角色模型或管理 UI 不是必要条件。

## 当前代码事实

- 每个进程有唯一 `control_tenant_id`；目录模式固定使用 `DEFAULT_TENANT_ID`；
- 部署级路由先通过 control tenant guard；
- 系统管理员定义为 control tenant 中有效的 admin 且 `admin_level >= 2`；
- 普通 tenant admin 无论等级都只能管理本 tenant；
- 当前跨租户管理员端点是：

```http
PATCH /admin/tenants/{tenant_id}/users/{user_id}/admin
```

请求体只包含 `admin_level`。`0` 表示降为普通用户，正数表示目标管理员等级。端点要求 control tenant Host、CSRF、近期 MFA 和系统管理员权限；数据库事务重新锁定并校验 actor/target，同时写身份安全事件和耐久审计。

- controller registry/recovery 已校验当前进程 `deployment_id`，调用方声明不匹配时在 repository I/O 前失败。

## 权限矩阵

| 操作 | tenant user | tenant admin | system admin | 签名 controller task |
|---|---:|---:|---:|---:|
| 管理本 tenant 用户/客户端 | 否 | 是 | 仅通过显式目标 tenant 语义 | 可选，若已有真实运维消费者 |
| 设置普通 tenant admin | 否 | 否 | 是 | 否，除非明确要求无人值守恢复 |
| 创建/更新/禁用 tenant | 否 | 否 | 可提供人工入口 | 是，NazoAuthCtl 的主要入口 |
| 安装/轮换 transport 或 OpenID4VC material | 否 | 否 | 可发起 | 是 |
| 修改 control tenant/system admin | 否 | 否 | 不通过跨租户端点 | 仅走现有受保护 bootstrap/recovery |

不要让 `admin_level` 单独决定系统权限；必须同时验证 actor 所属 control tenant。

## 最短实施路径

### 1. 先复核现有入口是否足够

在添加 route/operation 前检查现有 controller protocol、admin route 和 repository transaction：

- 如果现有操作能表达相同目标并满足 tenant/deployment/revision 绑定，直接复用；
- 如果只有测试专用 conformance lease 能表达，不复用该语义；
- 如果没有真实调用方，不创建预留操作。

### 2. 建立一个共享的权威 mutation

人工 HTTP 与 NazoAuthCtl 可以有不同认证适配器，但最终必须调用同一个事务规则，不能各写一份 SQL：

```text
authenticated actor/controller
  -> deployment + target tenant + expected revision
  -> one PostgreSQL transaction
  -> directory/material mutation + audit/outbox
  -> signed or durable receipt
```

只有存在 HTTP 和 controller 两个真实消费者时，才提取一个窄的 application command；不要创建通用 CommandBus。

### 3. tenant lifecycle 操作

最少需要：

- create：创建或绑定已有 tenant/realm/org，写 canonical host/issuer；
- update：以 expected revision 更新可变字段；
- disable：立即阻止新请求，保留审计和可恢复数据；
- delete/finalize：只在依赖资源清理完成后移除 binding；
- describe/list：让 controller 能恢复中断任务并判断当前 revision。

create/update/disable 必须幂等；相同 operation JTI 返回相同结果，stale expected revision 失败关闭。delete 不等于立刻物理清库，物理回收必须由已证明必要的资源清单驱动。

### 4. material 操作

T3/T4 只需要具体操作：stage、activate、revoke、describe。每个任务绑定：

- deployment ID；
- tenant ID；
- operation JTI；
- expected current revision；
- new material revision 和 digest；
- usage、not-before、expiry；
- operator identity。

NazoAuthCtl 不读取 NazoAuth 协议私钥。未知 capability、错误签名、跨 tenant material 或 stale revision 必须拒绝。

### 5. 管理员语义收口

保留当前唯一 PATCH 路由，不再增加旧文档曾设想的 `PUT/DELETE /admins/{user_id}` 双语义。

补齐测试：

- control tenant level 2 可设置普通 tenant admin；
- control tenant level 1 被拒绝；
- 非 control tenant 即使 level 很高也被拒绝；
- target tenant 与用户真实 tenant 不一致时零写入；
- 不能用该入口提升 control tenant 用户；
- actor 并发降权时，以事务锁后的状态为准；
- 幂等重放不产生错误最终状态或重复副作用。

## 审计与 receipt

每次成功或失败的高权限 mutation 至少记录：

- deployment、operation JTI；
- actor/controller identity；
- target tenant 和资源；
- previous/new revision 与 material digest；
- action、reason、时间；
- 可验证的最终状态。

浏览器操作使用现有耐久审计；controller 操作返回现有协议可验证 receipt。没有必要同时建立第三套审计表。

## 明确不做

- 不新增 `system_admin` 字段、角色表或 RBAC 引擎；
- 不让普通 tenant 的高 `admin_level` 获得系统权限；
- 不让 NazoAuthCtl 成为在线请求依赖；
- 不创建管理 UI 作为后端正确性的前置；
- 不保留两套 tenant lifecycle route；
- 不按产品 semver 猜测协议兼容性，使用 capability/protocol negotiation；
- 不把 tenant 生命周期伪装成 OIDF conformance lease。

## 验收

- HTTP 安全矩阵与真实 CSRF/MFA；
- controller 签名、expiry、JTI replay、deployment/tenant mismatch；
- PostgreSQL 并发、expected revision、事务审计；
- 服务崩溃后 describe/retry 返回一致结果；
- 操作完成后 T1 的两个进程在有界时间内收敛。

## 停止与回滚

- 没有真实调用方的操作不实现；
- 现有协议能表达时不新增版本；
- mutation 与审计不能同事务时停止交付；
- 回滚必须保留 receipt 和审计，不删除已经发生的历史。
