# OpenID Connect RP Metadata Choices 1.0 完整支持任务

状态：实现与本地验证完成

## 完成定义

- [x] 规范定义的 19 个多值 choices 元数据全部被解析、校验和协商。
- [x] 每个 choices 字段都有对应的单值客户端状态，并能跨 DCR 创建、读取、更新和服务重启持久化。
- [x] choices 只作为注册输入；注册响应和读取响应只返回最终选中的单值字段。
- [x] 单值与 choices 同时出现时，单值必须包含在 choices 中。
- [x] 服务端与客户端没有共同值时返回 `invalid_client_metadata`。
- [x] ID Token 签名和加密实际使用协商结果。
- [x] Request Object 签名校验和加密 Request Object 解密实际使用协商结果。
- [x] `private_key_jwt` 客户端断言实际受协商签名算法约束。
- [x] JWT Introspection 响应签名和加密实际使用协商结果。
- [x] Discovery、DCR 与运行时从同一个真实算法能力来源派生，不能各自维护漂移列表。
- [x] 未提供新元数据的既有客户端保持现有兼容行为。

## 规范字段

- [x] `subject_types_supported`
- [x] `id_token_signing_alg_values_supported`
- [x] `id_token_encryption_alg_values_supported`
- [x] `id_token_encryption_enc_values_supported`
- [x] `userinfo_signing_alg_values_supported`
- [x] `userinfo_encryption_alg_values_supported`
- [x] `userinfo_encryption_enc_values_supported`
- [x] `request_object_signing_alg_values_supported`
- [x] `request_object_encryption_alg_values_supported`
- [x] `request_object_encryption_enc_values_supported`
- [x] `token_endpoint_auth_methods_supported`
- [x] `token_endpoint_auth_signing_alg_values_supported`
- [x] `backchannel_authentication_request_signing_alg_values_supported`
- [x] `authorization_signing_alg_values_supported`
- [x] `authorization_encryption_alg_values_supported`
- [x] `authorization_encryption_enc_values_supported`
- [x] `introspection_signing_alg_values_supported`
- [x] `introspection_encryption_alg_values_supported`
- [x] `introspection_encryption_enc_values_supported`

## 验证边界

- [x] 领域协商与无共同算法的负向测试。
- [x] PostgreSQL 迁移、仓储往返和旧行兼容测试。
- [x] DCR 创建、读取和 choices 不回显测试。
- [x] 四条运行时 JOSE 消费链路测试。
- [x] Discovery 与实际密钥/模块一致性测试。
- [x] 全工作区测试、Clippy、格式和静态契约。

## 证据记录

### 实现证据

- 19 个 choices 在同一领域测试中全部完成交集选择；无交集以及单值不在
  choices 中均拒绝为 `invalid_client_metadata`。
- HTTP DCR 测试一次提交全部 19 个 choices，验证返回对应单值，并逐项
  验证 choices 不出现在创建响应中。
- 8 个新增单值列通过 migration、Diesel schema、客户端仓储、访问申请批准
  写入路径和仓储往返测试；列均可空，旧客户端保留既有默认行为。
- ID Token 实际选择注册签名算法并可生成嵌套加密 JWT；Request Object
  使用独立持久化 RSA recipient key 解密后继续执行签名校验；
  `private_key_jwt` 与 JWT introspection 都强制执行注册签名算法。
- 旧 signing keyset 首次加载时会原子补建
  `request-object-encryption.pem`，无需用户新增配置；该密钥与签名用途隔离。

### 验证结果

- 聚焦 Rust：`465 passed`，30 suites。
- PostgreSQL adapter：`86 passed`，13 suites。
- 全工作区：`1968 passed`，87 suites。
- Clippy：workspace、all targets、all features、`-D warnings` 通过。
- `cargo fmt --check`、静态契约和 migration checksum 通过。

上述结果证明当前源码与本地测试路径；不把本地测试结果表述为外部认证。
