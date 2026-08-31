# T3：动态 Direct TLS

## 必要性判断

状态：`REQUIRED / NOT STARTED`。

[GitHub #144](https://github.com/nazozero/NazoAuth/issues/144) 要求 Direct TLS 与 trusted-proxy 解析同一 tenant；NazoAuth 也承诺不依赖 Nginx/Angie 才能完整运行。因此这不是“未来可能支持”的预留能力，而是明确验收缺口。

当前拒绝是正确的临时 fail-closed 行为，不能通过删除配置检查来宣称支持。

## 当前代码事实与根因

目录 tenant 在 HTTP 层根据 Host 解析；Direct TLS 的 tenant 选择必须发生在 HTTP 之前的 TLS ClientHello/SNI 阶段。

当前 Direct TLS runtime 只有一个 process-global snapshot：

- 一套 server certificate/private key；
- 一套 client CA verifier；
- 多个允许的 endpoint name 最终仍返回同一个 `CertifiedKey`；
- HTTP Host 解析结果没有与握手选择的 tenant 做强一致校验。

所以当前实现无法安全支持：

- 每 tenant 服务器证书；
- 每 tenant mTLS client trust；
- 动态 SNI 新增/禁用；
- SNI tenant 与 HTTP Host tenant 不一致时失败关闭。

## 最小目标结构

只增加一个本机不可变 TLS 索引，不创建通用 TLS 框架：

```text
ArcSwap<SniTenantTlsIndex>
  canonical SNI
    -> TenantTlsContext {
         tenant_id,
         material_revision,
         Arc<rustls::ServerConfig>
       }
```

每个 `ServerConfig` 同时拥有该 tenant 的服务器证书/私钥和 mTLS client verifier。不能只动态选择 `CertifiedKey` 后继续共享全局 client CA。

## 最短实施路径

### 1. 明确 transport material 所有权

- 公网服务器 TLS 私钥属于 deployment/hostname；
- tenant directory 只保存 host、material revision、digest 和激活状态，不保存任意 URL/路径链；
- 复用当前 Direct TLS 证书解析、匹配、权限和 last-good reload 规则；
- 首个实现只支持部署本地、按 tenant/revision 确定性派生的 material 位置，或现有 controller artifact 安装通道；没有真实第二实现时不创建 `TlsProvider`；
- material 必须先 stage 并验证，再通过 T2 原子 activate；目录不得先指向不存在的文件。

如果部署拓扑证明本地 material 分发不能满足当前真实需求，再单独评审 KMS/HSM；不得在本任务预建。

### 2. 在 ClientHello 时选择完整配置

Direct TLS acceptor 必须：

1. 读取 ClientHello SNI；
2. canonicalize；
3. 从当前 `SniTenantTlsIndex` 精确命中一个 tenant；
4. 选择该 tenant 的完整 `ServerConfig`；
5. 未知、缺失、重复或非法 SNI 时终止握手；
6. 将已选择的 `tenant_id` 放入连接级只读 context。

不能回退到 control tenant 或任意默认证书。

### 3. 强制 SNI/Host/issuer 同一性

HTTP 请求进入现有 Host binder 时同时验证：

```text
connection tenant == canonical Host tenant == runtime issuer tenant
```

任何不一致在 CORS、session、client lookup 和 handler 前失败关闭。trusted-proxy 没有 TLS SNI context，但必须使用受信任 external host 得到相同 canonical tenant。

### 4. 动态发布和退役

T1 candidate 构建时验证新 tenant 的完整 TLS context；所有 context 成功后与 `TenantHostIndex` 同 revision 发布。

- stage 失败：不改变当前索引；
- activate 失败：保留 last-good；
- rotation：旧新重叠窗口只由显式 revision/时间决定；
- disable：新握手立即不可命中；既有 TLS 连接可按明确 drain policy 完成；
- delete：连接 drain 后才回收旧 material；
- stale writer：不能覆盖更高 material revision。

Host index 与 SNI index 必须来自同一 candidate revision，不能分别成功发布。

### 5. 保持 trusted-proxy 语义一致

不复制 OAuth/FAPI/mTLS 状态机。两种 transport mode 只产生同一个规范化 transport identity，后续协议路径完全共享。

## 明确不做

- 不内置 ACME client；证书申请/分发属于 NazoAuthCtl 或外部运维；
- 不实现 HTTP/3、WAF 或边缘多站点代理；
- 不创建 Direct TLS 专用 OAuth handler；
- 不接受 `X-Tenant-ID`；
- 不信任外部 forwarded/client-cert header；
- 不为未知 SNI 返回默认证书；
- 不把所有 tenant client CA 合并为一个全局 trust pool。

## 验收

真实 HTTPS/mTLS 集成矩阵至少覆盖：

- 两个 tenant 使用不同 server cert 和 client CA；
- 正确 SNI/Host 成功；SNI A + Host B 失败；
- 未知/缺失 SNI 失败；
- tenant A client cert 不能用于 tenant B；
- 同一 client ID/cert digest 在不同 tenant 不串扰；
- 新 tenant 和证书 rotation 无重启生效；
- 无效证书、私钥不匹配、过期、权限错误、reload 失败保留 last-good；
- HTTP/1.1、HTTP/2；
- 与 trusted-proxy 的 discovery、metadata、token、mTLS alias 和错误语义一致。

测试必须使用真实 TLS 握手，不能只调用 resolver 函数。

## 停止与回滚

- 无法在握手前选择 tenant-specific verifier 时，不发布动态 Direct TLS；
- SNI index 与 Host index 不能原子同 revision 时停止；
- reload 失败保留旧 context；
- 回滚必须恢复匹配的二进制、directory revision 和 material revision。
