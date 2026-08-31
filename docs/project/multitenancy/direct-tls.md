# T3：动态 Direct TLS

## 必要性与边界

状态：`IMPLEMENTED / LOCALLY VALIDATED`。

动态租户必须在 Direct TLS 与 trusted-proxy 下得到同一 Host 语义。第一性原则是先判断 TLS 材料的真实所有者：当前证书、私钥和握手期 client CA 属于 deployment/listener，不属于业务 tenant。为每个 tenant 构造 `ServerConfig`、证书 Provider 和第二个 SNI 索引没有当前消费者，只会复制目录事实。

## 实现

- rustls resolver 不再用启动时 Host 白名单阻止后来加入目录的规范化 SNI；实际证书覆盖仍由 TLS 客户端的 SAN/通配符校验决定。
- 缺失或非法 SNI 仍在握手期失败。
- TLS acceptor 将 rustls 已接受的 server name 写入连接级只读扩展。
- HTTP tenant binder 在读取租户索引前比较规范化 SNI 与 Host；不一致返回 `421 Misdirected Request`。
- trusted-proxy/loopback 没有 Direct TLS SNI context，继续只使用其受信任 transport identity 与 Host 规则。

```text
ClientHello SNI
    -> deployment certificate validation
    -> connection DirectTlsServerName
    -> canonical SNI == canonical HTTP Host
    -> local TenantHostIndex lookup
```

该路径允许已覆盖新 Host 的 SAN/通配符证书在目录新增租户后立即工作，无需重启。若需要新证书，证书文件本身仍由现有 deployment reload 机制管理，而不是通过租户目录传递路径。

## 明确不做

- 不创建每租户 TLS Provider、`ServerConfig` 或 client CA pool。
- 不把证书路径、私钥或 CA 路径写入租户目录。
- 不接受 `X-Tenant-ID`，不为未知 SNI 回退默认租户。
- 不复制 OAuth/mTLS handler；握手后的协议权限仍由 tenant runtime 与 tenant-scoped trust policy 决定。

## 最终验收

- 真实 TLS：正确 SNI/Host 成功，SNI A + Host B、缺失 SNI、非法 SNI失败。
- 新目录 Host 在证书覆盖范围内无需重启即可路由。
- 证书不覆盖 Host 时由客户端验证失败，不被应用层绕过。
- HTTP/1.1、HTTP/2 与 trusted-proxy 对同一 Host 得到同一 tenant。
- listener 材料 reload 失败保留 last-good。

## 回滚

回滚只涉及同一 deployment TLS 配置与二进制。目录不持有 TLS 路径，因此不存在需要同步回滚的第二套证书事实源。
