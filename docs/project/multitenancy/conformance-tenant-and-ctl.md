# T5：受限 conformance tenant 与 NazoAuthCtl

## 必要性判断

状态：`REQUIRED / BLOCKED BY T1-T4`。

[GitHub #144](https://github.com/nazozero/NazoAuth/issues/144) 要求控制器能创建一个普通、受限、可过期且可清理的 tenant，用同一生产 NazoAuth Release 运行外部 OIDF 黑盒，同时不改变其他 tenant。该能力是明确验收目标。

但是，在 T1-T4 完成前创建测试专用 lease、隐藏 route 或服务器内 OIDF runner 不是必要步骤，且会破坏架构边界。本任务只能消费普通生产 tenant lifecycle。

## 所有权边界

### NazoAuth

只负责通用生产能力：

- tenant create/describe/update/disable/finalize；
- 普通 client/user/trust/material 管理；
- tenant-scoped quota/rate limit/resource ownership；
- expiry 状态、幂等 cleanup 操作和可验证 receipt；
- 正常 OAuth/OIDC/FAPI/CIBA/OpenID4VC 行为。

### NazoAuthCtl / 外部 driver

负责：

- 获取并验证签名 OIDF driver/matrix artifact；
- 生成本次运行的 plan、client、wallet、user 和测试输入；
- 通过普通管理协议 provision；
- 执行浏览器/HTTP 黑盒；
- 保存原始、可复核、签名证据；
- 在 `finally` 中枚举、撤销、清理并核对 receipt；
- 中断后按 operation JTI/revision 恢复。

NazoAuth 不得知道 Suite 版本、plan/module ID、WebDriver、固定 matrix 或测试 origin。

## 最短实施路径

### 1. 先证明普通 lifecycle 足够

在 NazoAuth 增加任何字段前，用 T2 的普通 API 列出 conformance 运行真实需要的资源：tenant、host/issuer、client、user、trust/material、quota、expiry。

对每个拟新增字段执行必要性判断：

- 已有通用字段可表达：复用；
- 只为 OIDF Suite 命名或分支：拒绝；
- 对普通短期 tenant 也有独立生产价值：可加入通用模型；
- 没有当前 driver 消费：`NOT NEEDED`。

### 2. provision

NazoAuthCtl 使用唯一 operation group：

1. 查询 capability；
2. 创建带 quota/expiry 的普通 tenant；
3. stage 并 activate transport/OpenID4VC material；
4. 创建普通 client/user/trust；
5. 等待所有 NazoAuth 实例报告目标 revision 可用；
6. 只有此时启动外部黑盒。

每步持久记录 operation JTI、resource ID、tenant ID、revision 和 receipt。失败时从已记录资源反向清理，不依赖内存列表。

### 3. 配额与资源隔离

只在真实资源消耗点实施最小限制：

- tenant-scoped request/rate limit；
- client/user/credential/session 等资源数量上限；
- 昂贵后台任务和队列的 tenant 并发上限；
- 运行总时长和 tenant expiry；
- 必要时为 DB pool/worker queue 设置 tenant admission，而不是复制整套服务。

“专用容量”不默认等于独立数据库、独立 Valkey 或独立进程。只有负载证据证明共享 admission 无法隔离时，才评审物理隔离。

### 4. expiry 与 cleanup

expiry 只是控制器崩溃后的安全网：

- 到期后立即禁止新授权/签发/管理 mutation；
- 后台清理可重试并按稳定顺序撤销资源；
- 显式 controller cleanup 仍是成功运行的必须步骤；
- cleanup 操作幂等；重复调用返回相同最终状态；
- 最终 receipt 列出已删除、已撤销、保留审计和仍阻塞的资源。

不得把“等待过期”当作完成清理。

### 5. 黑盒与不干扰证明

运行前后为一个普通生产 tenant 记录可观测基线：metadata、client/session/token 行为、key/trust revision、rate-limit budget、审计 head。

对 conformance tenant 运行完整外部矩阵后证明：

- 其他 tenant 的资源/revision 没有被修改；
- 相同 client ID、kid、nonce、state、certificate digest 不串扰；
- conformance 流量不能耗尽其他 tenant 的 admission budget；
- cleanup 后公共 endpoint、目录和后台任务中不再存在该 tenant；
- 审计历史和签名证据仍可复核。

Direct TLS 与 trusted-proxy 应对同一不可变 NazoAuth Release 串行运行完整矩阵，避免共享浏览器/session 状态造成假结果。

## 明确不做

- 不恢复 `conformance_lease` 或换名后的测试租约；
- 不在 NazoAuth 内嵌 OIDF matrix/driver；
- 不添加 Suite 专用 route/header/origin/decision；
- 不把 expiry 当作唯一 cleanup；
- 不默认创建独立 DB/KV/二进制组合；
- 不为了未来其他测试平台创建通用测试编排框架；
- 不在没有负载证据时实现复杂容量调度器。

## 验收

- controller 中断前后均可恢复并完成幂等清理；
- quota/expiry/admission 有真实并发和越界测试；
- cleanup receipt 与实际 PostgreSQL、Valkey、material、runtime 状态一致；
- 另一 tenant 的前后黑盒行为和资源 revision 不变；
- Direct TLS/trusted-proxy 两种模式完成外部 OIDC/FAPI/CIBA/OpenID4VC 验证；
- NazoAuth 生产代码、resource、route、schema 中没有 OIDF Suite 专用知识。

## 停止与回滚

- T1-T4 任一项未完成，不通过测试 seam 开始本任务；
- 普通 API 无法安全表达时，先回到 T2 补通用能力；
- cleanup receipt 与实际状态不一致时，任务为失败，不关闭主 Issue；
- driver/matrix 更新不得要求重新发布 NazoAuth；
- 回滚 NazoAuthCtl 不得影响已运行 NazoAuth 的在线数据面。
