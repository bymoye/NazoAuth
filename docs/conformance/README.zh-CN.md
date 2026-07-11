# Conformance 记录

## 范围

本目录保存 OpenID Foundation Conformance Suite 的长期证据索引。GitHub Actions artifact 会过期，因此仓库内记录保留 run metadata、plan ID、artifact digest 和被测试 commit SHA。

## 当前认证状态

Nazo Auth Server 已发布在 OpenID Foundation 官方认证列表中：

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

认证部署名为 `Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`。

## 当前证据

- 认证基线：[2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- 矩阵范围说明：[OIDF 完整矩阵](oidf-full-matrix.zh-CN.md)
- 最新私有 full-matrix 回归：[2026-07-01 TP/PS OIDF full matrix](2026-07-01-tp-ps-full-matrix.md)
- 最新官方 full matrix：[2026-07-02 NI-004 official OIDF full matrix](2026-07-02-ni-004-official-oidf-full-matrix.md)
- 最新 RFC 覆盖检查：[2026-07-02 NI-005 RFC 7592 OIDF coverage](2026-07-02-ni-005-oidf-coverage.md)
- 最新 NI-006~NI-011 私有 OIDF targeted 结果：[2026-07-02 NI-006~NI-011 private OIDF results](2026-07-02-ni-006-011-private-oidf-results.md)
- 最新 public NI-007 FAPI-CIBA targeted 结果：[2026-07-03 NI-007 public FAPI-CIBA OIDF results](2026-07-03-ni-007-public-ciba-oidf-results.md)
- 最新 NI-006~NI-011 官方 parallel-isolated full matrix：[2026-07-03 NI-006~NI-011 official parallel-isolated OIDF results](2026-07-03-ni-006-011-official-parallel-isolated-oidf-results.md)
- 最新 M2 官方 parallel-isolated full matrix：[2026-07-08 M2 official parallel-isolated OIDF results](2026-07-08-m2-official-parallel-isolated-oidf-results.md)
- 最新 M6 FAPI-CIBA 本地与官方 full matrix：[2026-07-11 M6 FAPI-CIBA OIDF results](2026-07-11-m6-official-fapi-ciba-oidf-results.md)

`2026-06-09` full matrix 是当前官方认证证据，针对 `https://auth.nazo.run` 执行，覆盖 OIDC Basic、OIDC Config、FAPI2 Security Profile Final、FAPI2 Message Signing Final、mTLS、DPoP、`private_key_jwt`、client credentials 变体。结果为全计划完成，`0 failures`，`0 warnings`。

最新记录的官方 full-matrix suite run 是 2026-07-11 M6 parallel-isolated 官方运行，针对 `https://auth.nazo.run` 执行。该运行使用 workflow head SHA `07e69855948ca0a12d4dcd26bb9372e3ea2d04d3`，部署镜像为 `localhost/nazo-oauth-server:m6-07e6985`，以 18+2 形式完成仓库 20-plan public OIDF 矩阵，三个 GitHub Actions jobs 均为 `success`。导出结果包含 639 个模块：631 个 `PASSED`、6 个预期 `REVIEW`、2 个预期 `SKIPPED`，没有失败模块、condition failure 或 warning。

最新私有 full-matrix 回归记录是 2026-07-01 TP/PS 运行，测试对象为 `https://auth.nazo.run`，runtime commit 为 `31e8f9f`。该运行使用仓库原有 16-plan 完整矩阵，导出 16 个 plan archives，共执行 578 个测试模块，结果为 `0 failures`、`0 warnings`。

最新 NI-006~NI-011 私有一致性测试环境 targeted 运行使用本地 official suite 快照
`edbf2514e1e5c850ccf28544953608bda50daf4d`。NI-007 FAPI-CIBA、NI-008
Front-Channel Logout 和 NI-009 Session Management 均通过，结果为
`0 failures`、`0 warnings`、`0 skipped modules`。NI-008/NI-009 runs 的 JSON
日志包含信息级 optional-condition `Skipped evaluation ...` 消息；它们不是
module-level `SKIPPED` 结果。

最新 public NI-007 FAPI-CIBA targeted workflow 于 2026-07-03 针对
`https://auth.nazo.run` 执行，workflow head SHA 为
`0374141ae7aec76c573b06dc8406b10819915309`。GitHub Actions run
`28636561869` 成功完成；导出的 suite artifact 包含 35 个 module JSON log，
全部为 `PASSED`，condition 统计为 2768 个 `SUCCESS`、`0 failures`、`0 warnings`。

最新 NI-006~NI-011 官方 full-matrix 回归于 2026-07-03 针对
`https://auth.nazo.run` 执行，workflow head SHA 为
`056cf7f90061a9054394593ee1fa7b43f5e26b54`。GitHub Actions run
`28648656293` 成功完成；workflow 将 18 个可并发计划放在同一个 job 中执行，
并将 front-channel logout 与 session-management 分拆到独立 browser-sensitive
matrix job 中隔离执行。

baseline OIDC metadata 会在 `request_object_signing_alg_values_supported` 中声明 `none`，用于 unsigned Request Object 的 OIDC 兼容路径。该能力不是高安全 profile 能力；FAPI2 Security Profile Final、FAPI2 Message Signing Final、要求 PAR request object 的客户端以及 holder-bound token 客户端仍然 fail closed，必须使用签名 Request Object 或被拒绝。

## 覆盖更新规则

每新增一个 RFC、OIDC/FAPI profile 或标准协议能力支持，都必须检查 OIDF 一致性套件覆盖。检查范围包括 OpenID Foundation Conformance Suite 的官方 production/staging 计划、公开源代码和 release notes，确认是否已有对应官方测试。

如果已有官方覆盖，必须在同一变更中更新本仓库的 OIDF 矩阵执行内容，包括 workflow/config 输入、plan 列表、矩阵文档和 conformance 记录。如果暂无官方覆盖，必须在对应实现记录或 conformance 记录中写明未发现官方覆盖的检索结论和日期。无论 OIDF 是否已有覆盖，本地正向、负向、metadata truth 和安全边界测试仍然必须保留。

## 记录格式

每份记录应包含：

- implementation commit SHA
- 文档 commit SHA，如果与实现 commit 不同
- workflow 名称和 run URL
- job URL 和 matrix 名称
- 通过时间和 suite 运行时间
- profiles 和 feature combinations
- artifact 名称、digest、过期时间、zip 文件名
- plan ID 和 plan detail URL
- failure / warning 计数
- skipped module 计数，以及是否满足 zero-SKIPPED 验收门槛
- 允许的 review 状态
- public issuer 与测试环境说明

## 边界

本目录索引的是 suite 输出和工程证据。官方认证状态以 OpenID Foundation 公布页面为准。

## 兼容性跳过项

当前 OIDC dynamic-registration 兼容矩阵中有 2 个 expected official suite
skips：服务不支持也不声明 unsigned ID Token；`request_uri` 参数未启用
（`request_uri_parameter_supported=false`）。这两个跳过项符合当前安全边界，
但不能视为 zero-SKIPPED 证据。
