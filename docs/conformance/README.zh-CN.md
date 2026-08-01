# Conformance 记录

## 范围

本目录保存 OpenID Foundation Conformance Suite 的长期证据索引。GitHub Actions artifact 会过期，因此仓库内记录保留 run metadata、plan ID、artifact digest 和被测试 commit SHA。

## 版本化证据索引

- 认证与一致性入口：[认证与一致性证据](certification.zh-CN.md)
- 必须遵守的公网黑盒运行流程：[OIDF 公网黑盒一致性测试流程](oidf-public-black-box-runbook.zh-CN.md)
- 认证基线：[2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- 矩阵范围说明：[OIDF 完整矩阵](oidf-full-matrix.zh-CN.md)
- 已归档诊断 full-matrix 回归：[2026-07-01 TP/PS OIDF full matrix](2026-07-01-tp-ps-full-matrix.md)
- 已归档 M7 官方 full matrix：[2026-07-11 M7 encrypted response OIDF results](2026-07-11-m7-official-encrypted-responses-oidf-results.md)
- 最新 RFC 覆盖检查：[2026-07-02 NI-005 RFC 7592 OIDF coverage](2026-07-02-ni-005-oidf-coverage.md)
- 已归档 NI-006~NI-011 私有 OIDF targeted 结果：[2026-07-02 NI-006~NI-011 private OIDF results](2026-07-02-ni-006-011-private-oidf-results.md)
- 最新 public NI-007 FAPI-CIBA targeted 结果：[2026-07-03 NI-007 public FAPI-CIBA OIDF results](2026-07-03-ni-007-public-ciba-oidf-results.md)
- 已归档 NI-006~NI-011 官方 parallel-isolated full matrix：[2026-07-03 NI-006~NI-011 official parallel-isolated OIDF results](2026-07-03-ni-006-011-official-parallel-isolated-oidf-results.md)
- 已归档 M2 官方 parallel-isolated full matrix：[2026-07-08 M2 official parallel-isolated OIDF results](2026-07-08-m2-official-parallel-isolated-oidf-results.md)
- 已归档 M6 FAPI-CIBA 诊断与官方 full matrix：[2026-07-11 M6 FAPI-CIBA OIDF results](2026-07-11-m6-official-fapi-ciba-oidf-results.md)
- 最新 M7 encrypted-response 覆盖检查：[2026-07-11 M7 encrypted response OIDF coverage](2026-07-11-m7-oidf-coverage.md)
- 最新 M8 新兴协议治理与覆盖检查：[2026-07-11 M8 watchlist governance](2026-07-11-m8-watchlist-governance.md)
- 项目自有 RFC 9967 回归范围：[RFC 9967 SCIM SET 黑盒矩阵](rfc9967-scim-set-matrix.md)
- 最新 OpenID4VC Final / HAIP alpha 回归：[2026-07-16 OpenID4VC Final / HAIP OIDF results](2026-07-16-openid4vc-final-oidf-results.md)
- 历史公网黑盒完整基线：[2026-07-20 自动化 OIDF 最终结果](2026-07-20-final-automated-oidf-results.zh-CN.md)

`2026-06-09` full matrix 是已发布 OIDF 认证列表对应的历史认证证据，针对 `https://issuer.example` 执行，覆盖 OIDC Basic、OIDC Config、FAPI2 Security Profile Final、FAPI2 Message Signing Final、mTLS、DPoP、`private_key_jwt`、client credentials 变体。结果为全计划完成，`0 failures`，`0 warnings`。

最近保留的历史公网黑盒 OIDF 基线是 2026-07-20 最终运行组。最终生产 revision 为 `0a747b42228962e562af012638297c56e3af5505`；GitHub Actions runs [`29705159845`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845) 和 [`29700527789`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789) 均成功。操作者公网套件完成 25 个 OIDC/FAPI/FAPI-CIBA plan 和 17 个 OpenID4VC Final/HAIP plan。公开文档将实际 issuer 脱敏为 `https://issuer.example`。原始套件 ZIP 不属于可提交证据；该历史记录只接受由自动化生成的无凭据 manifest、固定 suite/source revision、run/job URL 和精确 expected-result 契约。

已归档的诊断记录仍可用于调试回归，但不是当前一致性证据。上面的 `25 + 17 = 42`
历史基线同样不满足当前 `27 + 17 = 44` Release 门禁；只有完整 host-local 矩阵针对精确
Release 全部完成后，新记录才可标为当前证据。

已归档诊断 full-matrix 回归记录是 2026-07-01 TP/PS 运行，测试对象为 `https://issuer.example`，runtime commit 为 `31e8f9f`。该运行使用仓库原有 16-plan 完整矩阵，导出 16 个 plan archives，共执行 578 个测试模块，结果为 `0 failures`、`0 warnings`。

最新 NI-006~NI-011 诊断一致性 targeted 运行使用 official suite 快照
`edbf2514e1e5c850ccf28544953608bda50daf4d`。NI-007 FAPI-CIBA、NI-008
Front-Channel Logout 和 NI-009 Session Management 均通过，结果为
`0 failures`、`0 warnings`、`0 skipped modules`。NI-008/NI-009 runs 的 JSON
日志包含信息级 optional-condition `Skipped evaluation ...` 消息；它们不是
module-level `SKIPPED` 结果。

最新 public NI-007 FAPI-CIBA targeted workflow 于 2026-07-03 针对
`https://issuer.example` 执行，workflow head SHA 为
`0374141ae7aec76c573b06dc8406b10819915309`。GitHub Actions run
`28636561869` 成功完成；导出的 suite artifact 包含 35 个 module JSON log，
全部为 `PASSED`，condition 统计为 2768 个 `SUCCESS`、`0 failures`、`0 warnings`。

最新 NI-006~NI-011 官方 full-matrix 回归于 2026-07-03 针对
`https://issuer.example` 执行，workflow head SHA 为
`056cf7f90061a9054394593ee1fa7b43f5e26b54`。GitHub Actions run
`28648656293` 成功完成；workflow 将 18 个可并发计划放在同一个 job 中执行，
并将 front-channel logout 与 session-management 分拆到独立 browser-sensitive
matrix job 中隔离执行。

2026-07-16 OpenID4VC Final / HAIP alpha、2026-07-17 和 2026-07-19 公网黑盒记录保留为历史证据。当前生产等价证据以 2026-07-20 最终运行组为准。

所有 profile 的 Request Object 都必须使用非对称签名。baseline 与 FAPI metadata 均不声明 `none`，运行时对任何客户端都拒绝 unsigned Request Object；项目遵循 RFC 9101，不保留仅为一致性套件服务的兼容旁路。

## 覆盖更新规则

每新增一个 RFC、OIDC/FAPI profile 或标准协议能力支持，都必须检查 OIDF 一致性套件覆盖。检查范围包括 OpenID Foundation Conformance Suite 的官方 production/staging 计划、公开源代码和 release notes，确认是否已有对应官方测试。

如果已有官方覆盖，必须在同一变更中更新本仓库的 OIDF 矩阵执行内容，包括 workflow/config 输入、plan 列表、矩阵文档和 conformance 记录。如果暂无官方覆盖，必须在对应实现记录或 conformance 记录中写明未发现官方覆盖的检索结论和日期。无论 OIDF 是否已有覆盖，仓库级正向、负向、metadata truth 和安全边界测试仍然必须保留。

## 记录格式

每份记录应包含：

- implementation commit SHA
- 文档 commit SHA，如果与实现 commit 不同
- workflow 名称和 run URL
- job URL 和 matrix 名称
- 通过时间和 suite 运行时间
- profiles 和 feature combinations
- artifact 名称、digest、过期时间、zip 文件名
- credential-free evidence manifest 的 digest；原始套件 ZIP 只记录文件名和
  SHA-256，生成 manifest 后立即删除
- plan ID 和 plan detail URL
- failure / warning 计数
- skipped module 计数，以及是否满足 zero-SKIPPED 验收门槛
- 允许的 review 状态
- public issuer 与测试环境说明

## 边界

本目录索引的是 suite 输出和工程证据。官方认证状态以 OpenID Foundation 公布页面为准。

原始套件 ZIP 的 `testInfo.config` 与日志正文可能包含凭据，因此不得进入 Git 或
通用 artifact。可持久留存的结果必须先由 `scripts/oidf_evidence.py` 归约。

## 兼容性跳过项

当前两个 OIDC dynamic 配置中各有相同的 2 个逻辑 expected official suite
skips：服务不支持也不声明 unsigned ID Token 和 unsigned Request Object。签名外部
Request Object 仅允许通过精确动态注册的 HTTPS `request_uri` 与受约束远程获取；
FAPI profile 仍只允许 PAR。这两个跳过项符合当前安全边界，
但不能视为 zero-SKIPPED 证据。
