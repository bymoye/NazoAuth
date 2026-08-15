# GitHub Actions Secrets

仓库 Secret 是执行边界，不是配置归档。只有当前 workflow 实际引用的 Secret 才应保留；
任何值都不得写入文档、日志、artifact、仓库 Variable 或 PR 描述。

## 当前清单

| Secret | 用途 | 轮换条件 |
|---|---|---|
| `CODECOV_TOKEN` | 认证覆盖率上传。 | Codecov 仓库 token 轮换或疑似泄露。 |
## 审计流程

1. 从 `.github/workflows` 提取所有 `secrets.NAME` 引用。
2. 与 `gh secret list --repo <owner>/<repo>` 逐项比较。
3. 删除当前 workflow 没有引用的名称。
4. workflow 引用缺少仓库 Secret 时直接失败；若由组织或 Environment 提供，必须显式记录。
5. 保留项只能从权威提供方轮换。GitHub 不允许读取现有值，因此不能仅凭名称或更新时间宣称值仍然有效。

组织 Secret 需要组织管理员权限单独审计。当前仓库没有使用 GitHub Environment。
