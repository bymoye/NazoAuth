# T4：租户级 OpenID4VC

## 必要性与状态

状态：`IMPLEMENTED / LOCALLY VALIDATED`。

OpenID4VC 的 SQL 已带 tenant predicate。签发证书链、IACA 私钥、信任锚与本地撤销事实属于同一 tenant 的加密 signing-key generation；运行时只能从该 generation 获取它们。

## 最短实现

没有新增 profile 表、Provider map 或任意文件 URL。证书和撤销 material 与私钥 keyset 一起通过现有加密 JSON/CAS 持久化；公开投影不含 IACA 私钥。

部署级 `OPENID4VC_DATA_ENCRYPTION_KEY` 是 root，不直接供所有租户使用。每个 tenant 使用现有 HKDF 边界按 tenant UUID 和独立 purpose 派生：

- OpenID4VC data-encryption key；
- VCI management token；
- VP management token。

外部 wallet/client 的只读 scoped trust policy 仍独立保存；它不承载本地 IACA 私钥、签发证书或撤销事实。

## 生命周期

- KeyManager refresh publishes a whole generation. Signing takes one lease, pinning its ES256 key, leaf/x5c and `kid` through the completed signature.
- Verification reads the current public generation on each request. It derives revocation policy from that generation and fails closed when enabled facts are absent or stale; no revocation reload task or file I/O exists.
- Historical IACA roots and local revocation records remain in managed material while credentials can still validate against them.

运维通过 `nazoauth mdoc-import`、`mdoc-rotate`、`mdoc-revoke` 对同一 tenant generation 提交 CAS 更新。运行中的 KeyManager lifecycle 读取并发布提交后的 generation。命令和迁移步骤见 [Managed OpenID4VC state](../../operations/mdoc-shared-state.md)。

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
- generation 更新无重启生效，签名中的 key、certificate 和 `kid` 不跨 generation 混用。
- 损坏或过期的 managed material 不发布为健康 generation。
- OpenID4VC discovery 与端点行为来自当前 tenant runtime。

外部客户端按标准公开协议进行黑盒验证，不获得任何内部测试接口。

## 回滚

升级前备份数据库、wrapping root 和原有 mdoc 文件。需要退回文件存储版本时，停止相关实例，按同一备份点恢复数据库、配置、文件和对应二进制；不得只回滚二进制，或在撤销后恢复旧快照而丢失撤销事实。
