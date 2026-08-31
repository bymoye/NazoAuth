# T4：租户级 OpenID4VC

## 必要性判断

状态：`REQUIRED / NOT STARTED`。

[GitHub #144](https://github.com/nazozero/NazoAuth/issues/144) 明确要求 OpenID4VC 的跨租户隔离，且受限 conformance tenant 必须能运行外部 OpenID4VC 黑盒验证。当前目录模式直接拒绝 OpenID4VC，因此必须实施；但只需把现有生产能力纳入 tenant runtime，不需要新协议框架。

## 当前代码事实与根因

OpenID4VC 持久层已有部分 tenant predicate，但 runtime 仍有 process-global 状态：

- data encryption key；
- signing certificate chain；
- trust anchors；
- credential configurations 和 wallet origins；
- revocation snapshot/reloader；
- attestation JWKS/management token；
- OpenID4VP verification signer 与部分 discovery/config。

这些资源由全局 `Settings` 和 process startup 构造。若直接允许动态 tenant，多个 tenant 会共享 crypto、trust、metadata 和后台 lifecycle。tenant-aware SQL 不能消除该风险。

## 最小目标结构

在现有 `TenantRuntime` 中增加可选的具体资源图：

```text
TenantRuntime
  -> Option<Arc<TenantOpenId4VcRuntime>> {
       validated profile/config,
       tenant crypto and signing material,
       trust/attestation policy,
       revocation state,
       lifecycle stop handles
     }
```

所有 VCI/VP route 仍使用现有 handler，只是从当前 tenant app-data 取得资源。未启用的 tenant 不挂载或失败关闭相关能力。

## 最短实施路径

### 1. 枚举真实 process-global 资源

从以下路径逐项追踪到 handler/background consumer：

- `crates/authorization-server/src/settings/config_loader.rs`
- `crates/authorization-server/src/bootstrap/startup/services/dependencies/openid4vc.rs`
- `crates/authorization-server/src/bootstrap/startup/background.rs`
- `crates/authorization-server/src/bootstrap/routes.rs`
- OpenID4VC VCI/VP/attestation/revocation handler 与 persistence port

只有被真实 handler 或后台任务消费的资源进入 tenant graph。未被消费的配置直接删除或标记 `NOT NEEDED`，不迁移成新字段。

### 2. 建立具体 tenant profile

目录 binding 只引用一个已验证的 OpenID4VC profile revision；具体 profile 只包含当前协议需要的字段：

- 启用的 VCI/VP 模块；
- credential configurations；
- wallet/origin policy；
- signing/encryption material revision；
- trust/attestation/revocation material revision。

公共配置和 trust metadata 可存 PostgreSQL；秘密材料继续由现有 tenant key/material 生命周期持有。禁止使用自由命名的 provider map 或任意 URL 配置链。

如果首个动态租户只需要一套 profile，也仍以 tenant ID 和 revision 绑定，但不预建多 provider 插件系统。

### 3. 将构造移入 `TenantRuntime`

扩展现有 `TenantRuntimeBuilder`，在 candidate 发布前：

1. 加载该 tenant profile；
2. 校验 crypto/certificate/trust 的 tenant、usage、digest 和 revision；
3. 构造 VCI/VP/attestation/revocation 资源；
4. 启动并记录 tenant-owned lifecycle handles；
5. 任一步失败则整张 candidate 不发布。

现有 `OPENID4VC_*` 全局 Settings 不能再通过 revision-0 静态图激活。只有 tenant profile 及其 material 全部进入 `TenantRuntime` 后，才能解除目录模式的明确拒绝。

### 4. 动态 route 与 metadata

- discovery/issuer metadata 只能从当前 tenant runtime 生成；
- VCI/VP endpoint availability 由当前 tenant profile 决定；
- 不能以 process baseline 决定所有 tenant 的 route 行为；
- nonce、offer、deferred credential、presentation、attestation、revocation cache 全部 tenant-scoped；
- 相同 kid、nonce、opaque state 或 credential configuration ID 在不同 tenant 下可独立存在但不能互认。

### 5. lifecycle 与 rotation

- profile update 只重建目标 tenant 的 OpenID4VC graph；
- 未改变 revision 的 tenant 复用现有 graph；
- revocation/trust reload task 必须由 tenant runtime 持有 stop handle；
- disable 先从新 index 移除，再停止后台任务；
- rotation 失败保留 last-good；
- background job 的每条 payload 必须携带并验证 tenant ID，不能依赖当前全局 Settings。

## 明确不做

- 不复制 VCI/VP handler；
- 不建立通用 `CryptoProvider`/`TrustProvider` 插件框架，除非当前已有第二个真实实现；
- 不为每个 tenant 启动 process-global worker 的副本；只有 tenant-owned 工作才按 tenant 启动；
- 不把 OIDF dataset、plan、module、Suite origin 或测试凭据加入 profile；
- 不把全局环境变量静默当作所有动态 tenant 的默认配置；
- 不因数据库已有 tenant predicate 就删除 fail-closed 检查。

## 验收

至少覆盖两个同时启用 OpenID4VC 的 tenant：

- metadata、credential configurations 和 wallet policy 各自独立；
- 相同 kid/nonce/offer/state 在另一 tenant 被拒绝；
- tenant A trust anchor/attestation key 不能验证 tenant B；
- VCI pre-authorized/authorization-code、deferred credential、VP presentation、revocation 全链路隔离；
- 动态 enable/disable/profile rotation 无重启生效；
- 一个 tenant profile 损坏时保留整张 last-good index；
- background reload 停止后无继续写入；
- revision 0 仍拒绝启动；已初始化目录不再触发当前 OpenID4VC 拒绝。

最后运行外部 OpenID4VC 黑盒，但该结果不能替代跨租户负向测试。

## 停止与回滚

- 任一 process-global crypto/trust consumer 未迁移时，不解除目录模式拒绝；
- tenant background task 没有明确 owner/stop handle 时不启动；
- profile/material revision 不一致时保留 last-good；
- 回滚时 profile revision、key material 和数据库 schema 必须匹配。
