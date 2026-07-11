# M7 加密响应与可选互操作实施计划

## 目标

完成 NI-012 与 NI-013：让 UserInfo 响应和 JARM 授权响应按客户端注册元数据选择签名、加密或嵌套签名后加密，并保持未配置客户端的现有协议行为不变。所有算法、密钥和 Discovery 声明必须来自同一运行时事实源，任何加密或签名失败均不得降级为明文响应。

规范基线：

- OpenID Connect Core 1.0 incorporating errata set 2，第 5.3.2 节；
- OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 2，第 2 节；
- JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) incorporating errata set 1，第 2 至 4 节；
- RFC 7515、RFC 7516、RFC 7517、RFC 7518、RFC 7519 与 RFC 8725。

## 数据模型

在 `oauth_clients` 增加六个可空且逐客户端生效的不可混用元数据字段：

- `userinfo_signed_response_alg`
- `userinfo_encrypted_response_alg`
- `userinfo_encrypted_response_enc`
- `authorization_signed_response_alg`
- `authorization_encrypted_response_alg`
- `authorization_encrypted_response_enc`

签名 allowlist 使用当前 Keyset 快照中实际可签名的非对称 JWT 算法集合；禁止 `none` 和 HMAC。活跃签名后端与已加载的本地辅助签名密钥共同构成该集合，Discovery、注册校验和签发必须读取同一快照，不得在请求处理中重新从磁盘推导另一组能力。JWE 初始策略只允许项目已经验证的 `RSA-OAEP-256` + `A256GCM`。启用加密必须同时存在 alg、enc，并且每个配置的 alg 必须且只能匹配一个 `use=enc`、含 `kid` 的 RSA 公钥；JWK Set 不得包含私钥或对称密钥。

字段必须贯穿迁移、Diesel schema、`ClientRow`、管理端 create/patch/detail 与 DCR/DCRM create/read/update。DCR POST 以及 DCRM GET/PUT 响应必须回显全部已配置字段，使 GET 表示在移除服务端管理字段后可安全用于 PUT，不得静默清除响应保护策略。任何入口都复用同一 `validate_client_metadata` 规则。

## 响应语义

### UserInfo

1. access token 完整验证、撤销检查、sender constraint、scope 和 subject 检查全部成功后，按 token 中的 tenant/client 绑定加载当前有效客户端。
2. 先由现有 claim minimization 逻辑生成唯一的 UserInfo claim 集合；不得把 access token 内部字段复制到响应。
3. 未配置签名或加密时返回现有 `application/json`。
4. 仅配置签名时返回 `application/jwt` JWS，并强制加入 `iss` 与 `aud=client_id`。
5. 仅配置加密时返回 `application/jwt` compact JWE；明文是最小化 claim JSON。
6. 同时配置签名与加密时先签名后加密，JWE protected header 使用 `cty=JWT`。
7. 客户端不存在、停用、元数据失效、密钥缺失或密码学操作失败时 fail closed，返回 `503 server_error`，不得回退 JSON/JWS。

### JARM

1. 仅在 `response_mode=jwt` 或运行时 profile 强制 signed authorization response 时进入 JARM。
2. 每次响应前按 `client_id` 加载当前有效客户端元数据；数据库失败或客户端消失时 fail closed。
3. `authorization_signed_response_alg` 选择 JWS 算法；未配置时保留当前已验证的 active signing algorithm 行为。
4. 配置 JWE 时先生成有效 JARM JWS，再使用客户端 `use=enc` 公钥生成 nested compact JWE；不得返回未签名的 JARM。
5. 签名或加密失败返回 `503 server_error`，不得把 code、state 或 error 放回明文 query。

## Discovery truth

只有当前 Keyset 快照实际可签名或代码与密钥策略实际支持时才发布：

- `userinfo_signing_alg_values_supported`
- `userinfo_encryption_alg_values_supported`
- `userinfo_encryption_enc_values_supported`
- `authorization_encryption_alg_values_supported`
- `authorization_encryption_enc_values_supported`

`userinfo_signing_alg_values_supported` 与 `authorization_signing_alg_values_supported` 使用同一运行时可签名算法集合；注册校验只接受该集合，签发直接使用快照中已经加载并验证的密钥材料。负向测试必须证明只有公钥、已退役、非本地辅助或其他不可用能力不会被误报或接受注册。

## 测试顺序

1. 先补 client metadata RED 测试：合法组合、孤立 alg/enc、不支持算法、`none`/HMAC、缺失或错误用途 JWK、私钥材料。
2. 提取现有 RFC 9701 JWE 代码为通用 JOSE helper，并保持 introspection 测试全绿。
3. 补 UserInfo RED 测试：JSON、JWS、JWE、nested JWT、claim minimization、错误客户端/密钥、绝不降级。
4. 补 JARM RED 测试：显式签名算法、nested JWE 可解密、错误元数据/密钥、绝不泄漏明文 code/state。
5. 补 admin、DCR/DCRM、view、migration、well-known 和 OIDF matrix materializer 测试。
6. 运行 `cargo fmt --check`、`cargo check --all-targets --all-features`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --locked`，并以 Docker 环境覆盖 PostgreSQL/Valkey 测试。

## OIDF 覆盖

检索日期为 2026-07-11，官方 conformance-suite 快照为 `f326f6aa25d6a2b8f1ae30a6ec80a57e342333ce`：

- `oidcc-dynamic-certification-test-plan` 包含 `oidcc-userinfo-rs256`；full matrix 通过模块选择器只运行该 signed UserInfo 模块并纳入并行集合，不声明或伪造完整 dynamic certification profile 所需的 implicit-flow 能力；
- 当前快照没有面向 OP 的 encrypted UserInfo 或 encrypted JARM 独立 plan/module；保留带日期的覆盖缺口，使用本地协议测试验证 compact JWE、嵌套顺序、header、alg/enc、密钥选择与 fail-closed。

## 交付门禁

实现提交后按 M6 相同流程执行：双远端 push、Hostinger 精确 SHA 部署、远端本地 OIDF 全矩阵（并行集合加新增动态认证 plan，frontchannel/session 串行隔离）、官方全矩阵、正式 PR checks、修复所有失败后合并 main。
