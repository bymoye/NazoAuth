# T4：租户级 OpenID4VC

## 必要性与状态

状态：`IMPLEMENTED / LOCALLY VALIDATED`。

OpenID4VC 的 SQL 已带 tenant predicate，但此前 crypto、trust、管理令牌与 revocation reloader 由进程全局配置构造。仅删除目录模式拒绝会造成秘密和后台任务跨租户共享，因此必须将真实资源纳入每租户 `TenantRuntime`。

## 最短实现

没有新增 profile 表、Provider map 或任意文件 URL。目录 binding 只增加通用正整数 `runtime_revision`；每个租户使用确定性位置：

```text
DATA_DIR/tenants/{tenant_uuid}/openid4vc/
  signing-certificate-chain.pem
  trust-anchors.pem
  revocation-snapshot.json   # 仅启用吊销检查时需要
```

部署级 `OPENID4VC_DATA_ENCRYPTION_KEY` 是 root，不直接供所有租户使用。每个 tenant 使用现有 HKDF 边界按 tenant UUID 和独立 purpose 派生：

- OpenID4VC data-encryption key；
- VCI management token；
- VP management token。

公共协议配置仍来自同一部署配置，但在构造时复制到各租户不可变服务图；秘密状态不共享。

## 生命周期

- `load_revocation_policy` 只加载状态，不再产生无 owner 的任务。
- 每个启用 revocation 的 `TenantRuntime` 启动自己的 reloader handle。
- runtime 被替换或禁用时，先从新索引移除，再 abort 并 await 旧 worker。
- binding 未变化时复用整个 runtime；`runtime_revision` 改变时重建目标租户完整服务图，不复用旧 keyset 或 lifecycle。
- 新材料加载失败时 candidate 不发布，继续服务 last-good。

运维更新材料的最短路径：原子替换目标租户确定性文件，然后提交签名 `tenant-directory-reload`。该操作只推进 tenant-local runtime revision 与全局目录 revision，不引入 material 类型、路径或 digest 的通用数据库模型。

## 明确不做

- 不复制 VCI/VP handler。
- 不创建 `CryptoProvider`、`TrustProvider` 或 profile 插件框架。
- 不把测试计划、runner、测试凭据或验证证据加入运行时。
- 不静默共享数据密钥或管理令牌。
- 不为文件更新建立 URL indirection。

## 最终验收

- 两个租户派生不同的数据密钥及 VCI/VP 管理令牌。
- 同名 nonce、offer、state、kid 和 credential configuration 不跨租户互认。
- trust anchor、attestation、VP result 与 revocation state 跨租户失败关闭。
- 文件替换加 `reload` 无重启生效，其他 tenant runtime 不重建。
- 损坏材料保留 last-good；disable 后 worker 停止且不再写入。
- OpenID4VC discovery 与端点行为来自当前 tenant runtime。

外部客户端按标准公开协议进行黑盒验证，不获得任何内部测试接口。

## 回滚

恢复目标租户上一个确定性文件集合并再次推进 `runtime_revision`。如果旧二进制不理解当前 migration head，则不得只回滚二进制。
