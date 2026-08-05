# OIDF 公网黑盒一致性测试流程

本文规定唯一受支持的 OIDF 一致性测试流程。被测对象是正常的公网生产部署；测试工具不得获得数据库访问权、私有服务网络地址、特权运行时挂载或另一套协议行为。

## 四步复现

生产接入的安全边界不能省略，但操作者入口固定为四步：

1. 部署一个精确且不可变的 Release tag，并同时记录 tag 与其完整源码 commit SHA。
2. 运行 `oidf-conformance-full.yml`，输入 `release_tag`、`deployed_sha`、
   `target_issuer`，并将 `onboarding_material_only` 设为 `true`；下载并校验生成的 bundle。
3. 由普通申请人与不同的审批人，通过 `apply_public_conformance_onboarding.py`
   和正式公开控制面完成接入。禁止数据库 seed 和私有网络访问。
4. 使用相同输入、将 `onboarding_material_only` 设为 `false` 运行 27-plan
   OIDC/FAPI/FAPI-CIBA/Logout 矩阵，再运行 17-plan OpenID4VC Final/HAIP 矩阵。
   workflow 会检出已部署 SHA、克隆精确官方套件提交，并在发现受版本控制的修改时拒绝运行。

`--ref` 只选择要运行的 workflow 定义，不是源码信任 allowlist。两个 workflow 都会先
要求所给 tag 解引用后精确等于所给 commit。若该 commit 不是默认分支的祖先，还必须确认
GitHub Release 存在且不是 draft，下载当前 runner 对应的 Linux `nazoauthctl` bootstrap
制品，并用 GitHub attestation 精确验证
`release-security.yml@refs/tags/<release-tag>` 证书身份、source ref、source digest、
自定义 Release predicate 和 hosted-runner 策略。全部证明通过后才允许检出或执行目标
commit 的源码；不存在按分支名称放行的例外。

所需 Secret 名称和轮换规则见
[`GitHub Actions Secrets`](../operations/github-actions-secrets.zh-CN.md)。每个 fork 必须提供自己的
issuer、账号、客户端材料和 suite token；仓库不提供共享被测部署。

## 规范面与控制面边界

| 能力 | 规范依据 | 必须遵守的边界 |
|---|---|---|
| OAuth 客户端注册与管理 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html)、[RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | 一致性测试客户端与普通客户端走同一套申请、审批、凭据交付、注册和管理流程。 |
| RP-Initiated Logout | [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | 同时接受 GET 与 form POST；回跳地址必须精确匹配注册值；请求没有与当前 OP 会话绑定的 hint 时必须显式取得用户确认。无效 RP 数据永不用于回跳。 |
| CIBA 令牌生命周期 | [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | CIBA 成功令牌响应可以包含 refresh token，因此客户端注册允许 `ciba + refresh_token`，不虚构对 authorization code 的依赖；运行时仍要求客户端登记该 grant 并满足 `offline_access` 策略。 |
| Logout 客户端元数据 | [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)、[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | 两个 `*_logout_session_required` 的规范默认值都是 `false`；需要 `sid` 的客户端必须登记对应 URI 并显式启用。Back-Channel 投递禁止重定向、阻断未经批准的私网 DNS 结果、仅接受 `200`/`204`，并且只重试可恢复的传输或 HTTP 失败。 |
| Session Management | [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) | `session_state` 绑定客户端与 redirect Origin；OP iframe 拒绝格式错误的消息，以及不属于活动客户端已注册 redirect URI 的父页面 Origin。 |
| mTLS 客户端认证和证书绑定访问令牌 | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)、[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html)、[RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | `tls_client_auth` 与证书绑定令牌是两个独立能力；授权服务器要求唯一 subject selector、规范 DN 匹配和按类型匹配 SAN。公网 CA 审批流程还要求 `tls_client_auth` 登记叶证书 pin，以落实 RFC 8705 第 7.4 节的跨 CA 冒充防护。 |
| X.509 验证 | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | 只有当前有效、使用受支持公钥、带 critical CA Basic Constraints 和 critical `keyCertSign` 的 CA 证书才能提交信任申请。 |
| 信任锚管理 | [RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html) | RFC 6024 提供信任锚管理的安全模型：认证并授权来源、保护完整性、检测重放、限制信任用途并保留恢复能力。产品控制面另行强制不同人员审批、有界原因、追加式审计和撤销。 |
| OpenID4VC 签发与出示 | [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)、[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | 协议端点按正式规范实现。OpenID4VCI 没有定义签发方数据集管理 API，因此该能力只能位于带管理员认证和 CSRF 防护的控制面，不能宣告为协议端点。 |

规范没有定义运维 API，并不意味着可以提供无边界接口。非标准控制面必须满足最小权限、同源、身份认证、CSRF 防护、结构与大小限制、租户绑定、失败关闭和持久化审计。

部署安全策略将单租户当前有效的不同信任锚限制为 128 个，单客户端限制为 8 个；单客户端最多保留 4 个待审批申请，单用户在每个租户最多保留 16 个待审批申请。创建和审批都会获取租户级数据库 advisory lock，因此并发请求也不能绕过上限。这些数值属于产品资源边界，不宣称是 RFC 8705 或 RFC 6024 的规范要求。

## 硬性不变量

- 发行方和套件地址由运行者输入，必须是公网 HTTPS origin；仓库不提供任何部署域名默认值。
- Discovery 中的 `issuer` 必须等于被测公网 origin。
- 套件只能访问公网 HTTPS。禁止私有 DNS、裸 IP、loopback、容器服务名和关闭 TLS 校验。
- 产品逻辑不得根据 plan 名称、suite alias、callback path、测试 header 或 conformance 编译开关分支。
- 准备工具不得执行 SQL，也不得加载生产 server crate。
- 申请人与审批人必须是两个不同的有效账号；审批人的 `admin_level` 必须大于 0。自动化账号仍遵守正常账号生命周期和 MFA 策略。
- 每次运行使用独立命名空间；运行结束后停用所有新建客户端并撤销本次批准的信任锚。
- expected skip/review 必须精确绑定 configuration、plan、variant 和 module；任何额外 skip、review、warning 或 failure 都使运行失败。
- 公网套件必须关闭 development-mode 身份注入；未携带套件 API token 的 `/api/*` 请求必须返回 `401`。

## 0. 保护公网套件操作员入口

套件的 OIDC 操作员客户端与其他机密客户端走同一套申请和审批流程。只登记套件提供的公网 HTTPS 登录回调；不得额外登记内部端口、裸 IP 或容器主机名。完整反向代理链必须保留浏览器实际使用的公网 scheme、host 和 port，确保 Spring 生成的回调和登录后地址与公网地址一致。

公网开放前必须关闭套件的 development profile。普通非管理员用户随后通过 OIDC 登录，并从套件正式 `/api/token` 端点创建短期 API token。该 token 只保存在 root 可读的运行时 secret 文件中。创建 plan 前同时验证两个边界：携带 Bearer token 的请求返回 `200`，不携带 token 的相同 API 请求返回 `401`。禁止直接向 MongoDB 写入套件 token、禁止把产品管理员 session 当成套件 Bearer token，也不得依赖源码托管平台账号。

## 推荐入口：单次可逆运行

操作者公网 OIDC/FAPI/FAPI-CIBA 矩阵应使用统一入口，不应手工拼接后续各节的内部命令。运行前只准备两个彼此独立的生产身份、CIBA 决策令牌和公网套件短期 API token；动态注册初始 token 由 runner 为每条租约单独生成：

```sh
secret-provider read nazoauth/oidf-run-secrets | \
python scripts/run_public_oidf_conformance.py --secrets-stdin \
  --deployed-sha <已部署-sha> \
  --target-issuer https://issuer.example \
  --conformance-server https://suite.example \
  --suite-dir /opt/oidf/conformance-suite \
  --suite-revision "$(git -C /opt/oidf/conformance-suite rev-parse HEAD)" \
  --work-dir /var/lib/nazo-oidf/runs/<run-id> \
  --export-dir /var/lib/nazo-oidf/results/<run-id> \
  --run-namespace <run-id> \
  --proxy-trust-bundle /etc/proxy/oidf-mtls-ca.crt \
  --proxy-executable /usr/sbin/nginx \
  --nazoauthctl /usr/local/bin/nazoauthctl \
  --nazoauthctl-config /etc/nazoauth/update.json \
  --lease-ttl-seconds 28800
```

输入必须是严格 JSON，且字段恰好为 `oidf_applicant_email`、
`oidf_applicant_password`、`oidf_admin_email`、`oidf_admin_password`、
`oidf_admin_totp_secret` 和 `oidf_conformance_token`。也可通过
`--secret-fd N` 或当前用户/root 所有、单硬链接、权限为 `0600` 的
`--secret-file` 提供（仅 POSIX）。Windows 的 mode bits 不能证明 DACL，因此必须使用
stdin 或继承 FD。所有秘密都没有 argv 或环境变量回退。

该入口硬性校验产品提交、显式指定的官方套件提交和干净源码树；随后自动生成 source-bound 材料，并先通过 `nazoauthctl` 创建有时效的 conformance lease，把本轮分别随机生成的动态注册 token、CIBA 自动决策 token 的 SHA-256 与全部临时 client 绑定到同一租约。两个 token 只能操作该租约拥有的 DCR/CIBA 事务，并在租约过期或吊销后立即失效。官方套件会在并发模块间共享浏览器 cookie/session，因此所有驱动浏览器的模块和 plan 组均串行执行。它通过不同身份完成申请、审批、一次性交付和信任审批，原子安装已批准的信任 bundle，验证套件 API 的 `401/200` 边界，并执行 27 个 plan。无论成功或失败，均通过公网控制面停用本次客户端、撤销并物理清理租约数据、撤销信任并恢复代理原配置。私密运行材料保留在独立工作目录；套件原始 ZIP 会自动归约为 `evidence-manifest.json` 后删除，不会把凭据或日志正文作为结果留存。

私有预发布门禁可以在同一 runner 中同时传入
`--candidate-release`、`--candidate-revision`、`--candidate-build-id` 和
`--candidate-oci-digest`。四项缺一即失败；运行中的容器必须使用同一
digest 固定的镜像引用，二进制内嵌身份也必须逐项匹配。该例外只作用于
`conformance lease` 和显式 `nazoauthctl migrate --yes` 候选迁移。候选迁移同样
必须同时传入四项绑定，并且只能通过签名 operator task 执行；不得使用原始 SQL
或旧服务端命令。它不会改写已签名 active Release，也不能作为发布、
provenance 或官方认证证据。未传这些参数时，所有控制器命令仍严格绑定
已签名 Release manifest。

最后一组完成后，驱动会立即复查本轮全部 alias 的全部模块，等待 45 秒让异步回调与投递 worker 稳定，再复查一次完整矩阵。早期分组的任何晚到状态变化都会令整轮失败；单个分组的导出结果本身不能作为全矩阵成功证据。

审批仍是正式、可审计的授权事件；自动化只消除文件复制、路径推断、命令拼接和恢复操作，不绕过申请人与审批人分离。

统一 runner 会通过管理员登录、CSRF 和公网 `POST /admin/users` 幂等创建 applicant，
随后再以普通公网登录验证 applicant 凭据。浏览器凭据只会写入权限为 `0600` 的私有
plan 文件；子进程只会收到封闭环境白名单，不会复制任何未知父进程环境项。

## 1. 生成不可变的 runner 材料

检出待部署的精确 commit，并确保工作区干净。由运行者设置公网地址和账号：

```sh
export OIDF_TARGET_ISSUER=https://issuer.example
export OIDF_MTLS_TARGET_ISSUER=https://mtls.issuer.example
export OIDF_SUITE_BASE_URL=https://suite.example
secret-provider mount nazoauth/oidf-preparation /run/secrets/nazoauth-oidf-preparation.json
chmod 0600 /run/secrets/nazoauth-oidf-preparation.json
python scripts/prepare_oidf_black_box.py \
  --secret-file /run/secrets/nazoauth-oidf-preparation.json
```

该 preparation 文档是封闭的四字段 JSON，只包含 `oidf_applicant_email`、
`oidf_applicant_password`、`oidf_dynamic_registration_initial_access_token` 和
`oidf_ciba_automated_decision_token`。准备完成后立即移除 provider mount；若 provider
能够安全流式提供该封闭文档，也可使用 `--secrets-stdin` 或 `--secret-fd N`。

命令只在 `runtime/oidf` 生成 runner 配置、密钥、证书、onboarding manifest 以及精确的 plan/skip/review 清单。这些是测试输入，不是生产记录，也不具备修改生产数据库的权限。

若官方 runner 配置保存在仓库的加密材料中，可使用仅导出模式，在不创建套件 plan 的情况下生成接入材料：

```sh
run_url="$(gh workflow run oidf-conformance-full.yml \
  --ref <workflow-定义-ref> \
  -f release_tag=<精确-release-tag> \
  -f deployed_sha=<已部署-sha> \
  -f target_issuer=https://issuer.example \
  -f credential_holder_email_sha256=<全新申请人邮箱的-sha256> \
  -f onboarding_material_only=true)"
run_id="${run_url##*/}"
test -n "$run_id"
gh run watch "$run_id" --exit-status
gh run download "$run_id" \
  --name oidf-public-onboarding-material \
  --dir runtime/official-onboarding
```

该模式调用可复用的接入材料 workflow，先把精确 Release tag 与已部署源码 commit 绑定，
再在不暴露邮箱或密码哈希的前提下绑定全新申请人
邮箱承诺，校验 bundle 并上传私有 artifact；两个一致性测试 job 都不会执行。捕获 dispatch
返回的 URL 可以把下载绑定到本次精确 run；不得按分支或 workflow 名称选择“最新”运行。
进入第 3 步前，必须按相同 source commit 校验已下载 artifact。artifact 本身仍不具有生产权限：
客户端创建和 CA 审批必须由不同身份通过公网控制面完成。

使用以下命令把已校验的官方 artifact 转换为生产申请，不得重新生成客户端、密钥或证书：

```sh
python scripts/prepare_official_oidf_public_onboarding.py \
  --artifact-directory runtime/official-onboarding \
  --expected-source-commit <已部署-sha> \
  --target-issuer "$OIDF_TARGET_ISSUER" \
  --suite-base-url "$OIDF_SUITE_BASE_URL" \
  --applicant-email "$OIDF_APPLICANT_EMAIL" \
  --output-dir runtime/official-onboarding-apply
```

转换器会再次校验 artifact manifest 和证书 bundle，核对申请人邮箱承诺，并为当前完整 OIDC/FAPI/CIBA/Logout/OpenID4VC 矩阵生成恰好 55 个不重复申请。该步骤不访问数据库，也不创建客户端。

官方 OpenID4VC mTLS 身份必须单独保存在仓库 Secret `OPENID4VC_OIDF_MTLS_CONFIG_JSON` 中。其结构为一张 `ca` 证书，以及各自包含 `cert` 和 `key` 的 `mtls`、`mtls2` 对象；基础协议配置不得重复保存这组可轮换身份。接入材料导出与官方 runner 必须覆盖同一份 Secret，避免已审批 CA、导出的叶证书与套件实际使用的私钥发生漂移。公开 artifact 会移除全部私钥，并在上传前对每张叶证书执行 CA 链验证。

OIDC/FAPI mTLS 身份保存在 age 加密的仓库文件
`docs/conformance/oidf-mtls-material.json.age` 中，解密身份只保存在仓库 Secret
`OIDF_MTLS_MATERIAL_AGE_IDENTITY`。公开 plan 模板不得包含任何环境证书或私钥；
接入材料导出和官方 runner 必须在所有 FAPI-CIBA 派生配置生成后覆盖同一份材料。
该材料只包含一个专用 CA，以及每个逻辑 mTLS 客户端各自的客户端证书和私钥，
使客户端标识、证书和私钥作为同一组 source-bound 材料轮换。

`scripts/generate_oidf_mtls_material.py` 只用于受控的客户端身份轮换。它生成带
critical `CA:TRUE` 和 critical `keyCertSign` 的 RSA-3072 CA，以及限制为
`clientAuth` 的 RSA-2048 终端证书。输出必须立即加密，并删除明文与 CA 私钥。
该工具只生成外部测试客户端的密码学身份，不创建生产客户端，也不授予 CA 信任；
生产接入和信任仍必须经过申请人与审批人流程。artifact 导出与生产信任申请采用同一
CA 边界：缺失 `keyCertSign`、扩展非 critical，或 Basic Constraints 不合格时均拒绝。

每次运行都必须从当前检出的产品提交重新生成 OpenID4VC 材料，不得把上一轮的 `openid4vc-plan-configs.json`、driver 或预期结果清单复制到新运行目录。公开接入会把逻辑钱包标识替换为审批后签发的客户端标识，因此已经 apply 的配置是运行输出，不是下一轮的输入。安装 credential dataset 或创建套件 plan 之前，OpenID4VC wrapper 会硬性核对当前 17 个 plan、对应的 17 个配置、driver alias 集合、7 条有界 skip 和 4 条 HAIP warning；跨轮次或过期材料会在任何生产写入前失败。

## 2. 部署精确提交

部署该 commit 的正常 runtime 镜像和 UI。不得通过 SQL、迁移、专用预置二进制或特殊容器入口安装客户端、credential dataset 或 CA。核对运行镜像的 OCI revision、健康端点、Discovery issuer、JWKS、UI 静态资源和回滚记录。

## 3. 通过生产控制面完成客户端接入

先在部署宿主机创建有时效的租约。manifest 是公开接入材料；只把原样文件复制到宿主机，
不得混入 runner 私钥或已交付的 client secret：

```sh
sudo nazoauthctl conformance lease create \
  --profile oidf-full \
  --material /run/nazoauth/oidf-onboarding-manifest.json \
  --ttl-seconds 28800 \
  --yes
```

记录返回的 `lease_id`，再执行：

```sh
secret-provider read nazoauth/oidf-operator-credentials | \
python scripts/apply_public_conformance_onboarding.py apply --credentials-stdin \
  --target-issuer "$OIDF_TARGET_ISSUER" \
  --lease-id "$OIDF_CONFORMANCE_LEASE_ID" \
  --manifest runtime/official-onboarding-apply/oidf-onboarding-manifest.json \
  --plan-configs runtime/official-onboarding-apply/oidf-plan-configs.json \
  --delivered-client-material runtime/official-onboarding-apply/oidf-delivered-client-material.json \
  --state-file runtime/official-onboarding-apply/oidf-onboarding-state.json \
  --trust-bundle runtime/official-onboarding-apply/approved-mtls-trust-anchors.pem \
  --no-runner-env
```

签名 Operator Task 只保存 manifest SHA-256 和租约元数据；该命令不会把 runner 私钥或
明文 client secret 交给服务端。每个通过正式控制面审批创建的客户端都会在同一数据库
写入语句中绑定有效租约。凭据输入是严格 JSON，并且只能包含 `applicant_email`、`applicant_password`、
`admin_email` 和 `admin_password`。自动化也可使用 `--credentials-fd N`；工具不提供
密码环境变量或 argv 回退路径。

每个客户端都执行普通运行者可用的正式流程：

1. 申请人登录；
2. 提交客户端接入申请；
3. 由不同管理员审批；
4. 申请人领取一次性客户端凭据；
5. 用实际交付的客户端标识替换 runner 中的逻辑标识；
6. 需要 mTLS 的客户端提交 CA 信任申请；
7. 由不同管理员审批；
8. 从公网服务导出当前已经批准的租户信任 bundle。

凭据交付必须使用普通用户可用的正式 UI/API：申请人先读取自己的已批准申请，再通过带
CSRF 防护的 JSON `POST` 提交公开的 `request_id`。服务器根据当前已认证用户和申请标识
推导私有存储定位值，浏览器不会收到额外的领取凭据。申请列表和交付响应均带
`Cache-Control: no-store`；敏感凭据不得进入 URL。该约束落实了
[RFC 9110 第 17.9 节](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9)
对 URI 敏感数据泄露的警告，并避免
[OWASP](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
列出的浏览器历史、代理日志和 Referer 泄露路径。系统不保留 GET 兼容入口。

所有请求都必须是精确同源 HTTPS 请求：启用正常证书校验、禁止重定向、限制响应大小、校验 JSON Content-Type，并在变更请求中携带 CSRF token。输出的状态文件与 bundle 均属于私密运行材料。

apply 成功后，通过标准输入把交付映射保存为仓库私密 Secret `OIDF_DELIVERED_CLIENT_MATERIAL_JSON`。官方 OIDC 与 OpenID4VC workflow 缺少该 Secret 时必须拒绝启动，并同时校验目标 issuer 与 suite origin。该映射只包含实际客户端标识和少量签发的 client secret，只能替换私密 runner 配置中的精确 `client_id` 字段；它不是服务端 seed，cleanup 后必须删除。

状态文件会在第一次公网变更前创建，并在每次申请、审批、凭据交付和信任决策后原子更新。apply 失败或中断后，必须先执行 cleanup，不能直接覆盖重跑。cleanup 会通过同一公网控制面拒绝已记录的待审批申请、撤销已批准信任锚并停用已交付客户端。

## 4. 只安装已经批准的信任 bundle

使用部署系统正常的原子配置流程，把 `runtime/oidf/approved-mtls-trust-anchors.pem` 安装到公网反向代理的客户端证书信任库。记录 bundle SHA-256，建立回滚副本，验证完整代理配置，reload 后从公网验证 mTLS alias。不得直接安装 runner 生成目录中的 CA 文件。

代理负责验证证书链；授权服务器仍会按 RFC 8705 验证客户端登记的 subject selector 和客户端策略。经公网审批的 `tls_client_auth` 客户端还必须匹配管理员登记的叶证书 pin。代理信任一个 CA 不等于 OAuth 层授权该 CA 签发的所有证书。

## 5. 通过管理员 API 安装专用 OpenID4VC 数据

OpenID4VC runner 只能使用明确标记的专用 conformance 用户。driver 通过同一个公网发行方以管理员身份登录，只能向该 subject 写入有界数据：
`/admin/openid4vci/credential-datasets/{subject}/{configuration}`。

该端点要求管理员 session 和 CSRF token，按 credential format、有效期、保留 claim、JSON 大小/深度进行验证，并在同一事务中写入数据和追加式审计事件。它是签发方控制面，不是 OpenID4VCI 协议端点。driver 必须在 `finally` 中删除数据；清理失败即测试失败。

## 6. 执行完整公网矩阵

完整仓库矩阵必须针对公网发行方运行。并发安全的 plan 可以并发；logout、session management 以及其他共享浏览器状态的 plan 必须使用隔离 job。延长终态等待只用于吸收套件完成传播延迟，不能放宽任何协议断言。

预期 warning 是绑定具体环境的证据，不是全局兼容清单。每一条 warning 都必须精确绑定实际产生它的套件 origin、configuration、plan、variant 和 module。尤其是：如果公网套件入口可以成功协商 TLS 1.3，就必须使用不允许 TLS 1.3 warning 的清单；仅适用于无法协商 TLS 1.3 的官方入口的有界 warning，不得复制到该公网套件运行中。清单中登记的 warning 如果没有出现，同样判定为 runner contract 失败，因为这说明证据已经过期或绑定范围错误。

定向 plan 只用于诊断，不能代替全矩阵证据。必须保存精确 target commit、公网 origin、plan ID、module 结果、expected skip/review 匹配和 runner 版本。

## 7. 执行官方套件

只有同一精确部署提交的完整公网黑盒矩阵通过后，才可请求官方 OIDF 运行。官方配置也必须经过相同的生产接入流程；不得用本地 runner 材料覆盖现有客户端凭据或信任记录。

直接观察官方套件的 module 终态。CI 是交付证据，但不能替代官方套件的最终 module 结果。

完成一次接入后，标准自动化入口为：

```sh
gh workflow run oidf-conformance-full.yml \
  --ref <workflow-定义-ref> \
  -f release_tag=<精确-release-tag> \
  -f deployed_sha=<已部署-sha> \
  -f target_issuer=https://issuer.example \
  -f runner_mode=parallel-isolated \
  -f onboarding_material_only=false

gh workflow run openid4vc-conformance.yml \
  --ref main \
  -f deployed_sha=<已部署-sha> \
  -f target_origin=https://issuer.example
```

GitHub Actions 平台没有原生继承 FD 输入，因此仓库 Secret 只暴露给一个短生命周期的
materializer step。只有该进程拥有秘密环境项；它把内容写入 `RUNNER_TEMP` 下权限为
`0600` 的文件，后续 step 只接收路径或继承 FD，并通过 `if: always()` 删除目录。该方案
缩小了暴露窗口，但不会伪称消除了 GitHub runner 信任边界。OIDC/FAPI 的并发组、四个 CIBA 组以及两个浏览器敏感
plan 由 workflow 自动隔离；OpenID4VC 按有界 group 执行 17 个 plan。操作者不应手工
拆 plan、复制配置或修改 runner 并发策略。

## 8. 清理和证据留存

无论运行结果如何，均执行：

```sh
secret-provider read nazoauth/oidf-operator-credentials | \
python scripts/apply_public_conformance_onboarding.py cleanup \
  --credentials-stdin --target-issuer "$OIDF_TARGET_ISSUER"

sudo nazoauthctl conformance lease revoke \
  --lease-id "$OIDF_CONFORMANCE_LEASE_ID" --yes
sudo nazoauthctl conformance lease cleanup --yes
```

公网清理先撤销信任申请并停用本次客户端；租约撤销会原子停用全部绑定客户端，随后删除其
token、grant、revocation、access request、mTLS 信任事件和客户端记录。若显式清理未能执行，
服务会在租约期限到达时立即拒绝这些客户端，并由周期性幂等清理器完成相同的数据库删除；
只保留不含秘密的租约墓碑用于审计。已有 Valkey 协议瞬态状态在客户端过期后不可用，并按
各自 TTL 到期；当前实现不会扫描共享 Valkey 命名空间。只有代理回滚流程确认旧信任配置恢复后，
才能删除安装的 CA。留存脱敏后的结果、精确 commit、plan manifest、bundle digest、审批/撤销审计 ID 和官方 run ID；文档中严禁保存密码、私钥、session cookie、CSRF token、client secret 或一次性交付 token。

套件导出的原始 ZIP 不是脱敏证据：其中的 `testInfo.config` 和日志正文可能包含
浏览器密码、client secret、token 或私钥。仓库 runner 会在正常或可处理的异常退出路径中生成
credential-free `evidence-manifest.json`，仅保留 archive 名称和 SHA-256、plan/module
标识、variant、终态、签名文件存在性和 condition 结果计数，然后删除原始 ZIP。
workflow 的 artifact 路径必须精确指向该 manifest，禁止上传整个结果目录。
