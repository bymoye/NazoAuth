# GitHub Actions Secrets

仓库 Secret 是执行边界，不是配置归档。只有当前 workflow 实际引用的 Secret 才应保留；
任何值都不得写入文档、日志、artifact、仓库 Variable 或 PR 描述。

## 当前清单

| Secret | 用途 | 轮换条件 |
|---|---|---|
| `CODECOV_TOKEN` | 认证覆盖率上传。 | Codecov 仓库 token 轮换或疑似泄露。 |
| `OIDF_CONFORMANCE_TOKEN` | 访问公网官方套件 API 的短期 token。 | 到期、套件账号变化或操作者规定的短期轮换周期。 |
| `OIDF_USER_EMAIL`、`OIDF_USER_PASSWORD` | 官方计划使用的普通非管理员浏览器身份。 | 账号或密码生命周期变化、疑似泄露。 |
| `OIDF_ADMIN_EMAIL`、`OIDF_ADMIN_PASSWORD` | 需要正常管理员审批时使用的独立审批身份。 | 账号或密码生命周期变化、疑似泄露。 |
| `OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN` | 部署要求初始 access token 时，用于 RFC 7591 注册。 | 被测部署轮换该 token。 |
| `OIDF_CIBA_AUTOMATED_DECISION_TOKEN` | 把官方 CIBA 自动决策绑定到本轮部署，禁止复用上一部署的 token。 | 每次全新安装或目标 token 轮换。 |
| `OIDF_PLAN_CONFIG_AGE_IDENTITY` | 解密版本化 OIDC/FAPI runner 私密配置覆盖层。 | 重新加密或 recipient key 轮换。 |
| `OIDF_MTLS_MATERIAL_AGE_IDENTITY` | 解密版本化 OIDC/FAPI 外部测试客户端 mTLS 身份。 | CA、客户端身份或加密密钥轮换。 |
| `OIDF_DELIVERED_CLIENT_MATERIAL_JSON` | 把审批后的生产客户端映射到 runner alias。 | 每轮接入或 cleanup；客户端停用后不得复用。 |
| `OPENID4VC_OIDF_BASE_CONFIG_JSON` | 私密 OpenID4VC runner 基础配置。 | 数据集、issuer、wallet 或 suite 配置变化。 |
| `OPENID4VC_OIDF_DRIVER_CONFIG_JSON` | 私密 OpenID4VC driver 配置。 | driver 身份或 plan 配置变化。 |
| `OPENID4VC_OIDF_MTLS_CONFIG_JSON` | OpenID4VC 外部测试客户端 CA 和叶证书身份。 | CA、客户端身份轮换或疑似泄露。 |

仓库 Variable 只保存非敏感 runner 行为：`OIDF_EXPORT_RESULTS`、
`OIDF_MONITOR_INTERVAL_SECONDS` 和 `OIDF_RUN_TIMEOUT_SECONDS`。被测 issuer、部署
commit 和 plan 必须由 workflow 输入，不能成为仓库默认值。

## 审计流程

1. 从 `.github/workflows` 提取所有 `secrets.NAME` 引用。
2. 与 `gh secret list --repo <owner>/<repo>` 逐项比较。
3. 删除当前 workflow 没有引用的名称。
4. workflow 引用缺少仓库 Secret 时直接失败；若由组织或 Environment 提供，必须显式记录。
5. 保留项只能从权威提供方轮换。GitHub 不允许读取现有值，因此不能仅凭名称或更新时间宣称值仍然有效。

组织 Secret 需要组织管理员权限单独审计。当前仓库没有使用 GitHub Environment。
