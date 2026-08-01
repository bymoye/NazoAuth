# 认证与一致性证据

本文是认证状态和版本化官方套件证据的入口。协议能力明细见
[标准与 Profile 支持](../integration/openid-connect.zh-CN.md)。

## OpenID Foundation 认证列表

OpenID Foundation 认证页面列出了 `Nazo Auth Server 0.1.0`，日期为
`09-Jun-2026`，对应认证 profile 如下：

| Profile | 证据 |
| --- | --- |
| OIDC Basic OP | [Plan 结果](https://www.certification.openid.net/plan-detail.html?plan=Srk6iaVDVcqO5) |
| OIDC Config OP | [Plan 结果](https://www.certification.openid.net/plan-detail.html?plan=fGiz8QZYR1LVy) |

官方列表页面：

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

## 历史公网黑盒基线

最近保留的历史基线记录在
[2026-07-20 自动化 OIDF 最终结果](2026-07-20-final-automated-oidf-results.zh-CN.md)。
运行目标是操作者提供的生产 HTTPS issuer。公开文档中的
`https://issuer.example` 只是脱敏占位符。仓库 workflow 要求操作者提供自己的公网可达
`target_issuer` / `target_origin` workflow 输入，或在自己的仓库中配置私有自动化变量。

| 矩阵 | 结果 | 范围 |
| --- | --- | --- |
| OIDC / FAPI / FAPI-CIBA | 成功 | 25 个官方公网 plan：23 个并发 plan，加 2 个浏览器隔离 plan |
| OpenID4VC Final / HAIP | 成功 | 17 个官方套件回归 plan |

历史合并操作者脱敏 manifest：

| 指标 | 值 |
| --- | ---: |
| Plan executions | 42 |
| 模块实例 | 1,178 |
| Passed 模块结果 | 1,151 |
| 精确预登记的 failed 模块 | 2 |
| 成功条件 | 96,805 |
| 精确预登记的 failure 条件 | 2 |
| 有界 warning 条件 | 5 |
| 预期 skips | 15 |
| 受限 review 模块 | 9 |

两个 failed 模块来自 OpenID4VCI pre-authorized code 一次性使用规范与上游
multiple-clients 模块的冲突；有界 warning、review 和 skip 均记录在链接的证据文档中。
它们不是隐藏项，不能描述为 zero-warning、zero-failure 或 zero-skipped 证据。

这组 2026-07-20 的 `25 + 17 = 42` 运行不能作为当前固定
`27 + 17 = 44` Release 门禁的证据。只有针对精确部署 Release 完成全部 44 个 plan，
并记录 suite revision、全部 plan/variant 结果和证据路径后，才能称为该 Release 的当前证据。

## 矩阵范围

| 领域 | 范围文档 |
| --- | --- |
| OIDC / FAPI / FAPI-CIBA | [OIDF full matrix](oidf-full-matrix.zh-CN.md) |
| OpenID4VC Final / HAIP | [OpenID4VC Final matrix](openid4vc-final-matrix.md) |
| RFC 9967 SCIM SET 本地黑盒回归 | [RFC 9967 SCIM SET black-box matrix](rfc9967-scim-set-matrix.md) |

## 证据边界

本仓库的一致性声明必须来自针对明确配置的生产 issuer 执行的公网黑盒官方套件运行。
依赖非公网 endpoint、私有 DNS、私有信任根、本地专用 callback origin 或
suite-private hostname 的运行只能作为诊断记录，不能作为生产一致性证据。

OpenID4VC 套件结果是官方套件回归证据。除非 OpenID Foundation 发布对应认证结果，
否则它不是 OpenID Foundation 认证列表。
