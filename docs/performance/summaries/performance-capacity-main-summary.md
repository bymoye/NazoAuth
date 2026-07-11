# NazoAuth 主容量矩阵测试总结

Generated at: `2026-07-06 13:03:57 UTC`

本文汇总主容量矩阵结果。主矩阵用于观察默认 OAuth/OIDC/FAPI2 主路径在短测与 30 分钟 sustained 测试下的吞吐、延迟和资源占用。

## 覆盖范围

- 短测：冷登录、已登录授权码、刷新令牌轮换、Token-only、FAPI2 已登录高安全路径，用于快速确认阈值门禁与路径正确性。
- 长测：Token-only、已登录授权码、刷新令牌轮换、FAPI2 已登录高安全路径，每个阶段 30 分钟。
- 冷登录长测未纳入主长测矩阵，因为密码哈希并发门禁会主动限流；其容量应通过短测和独立安全限流测试解释，不应与可水平扩展的热路径混算。

## 汇总结果

| 矩阵 | 场景 | 通过阶段 | 实例数 | 目标速率 | 最高通过阶段 | HTTP RPS | p95 ms | p99 ms | 错误率 | App CPU cores | PG CPU | Valkey CPU | PG stmt ms | DB wait ms | Valkey 命中 | 首个未通过阶段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 主矩阵 / 短测 | [Token-only: client_credentials 短测](../reports/main/performance-capacity-curve-token-only-short.md) | 9/9 | 1,2,4 | 1000,2500,5000 | 4x / 5000 flow/s | 4999.963 | 2.768 | 5.893 | 0.0000% | 6.187 | 108.256% | 17.714% | 0.022 | 0.203 | 99.9998% | - |
| 主矩阵 / 短测 | [OIDC: 冷登录 + 刷新短测](../reports/main/performance-capacity-curve-oidc-cold-login-short.md) | 8/9 | 1,2,4 | 16,32,64 | 4x / 64 flow/s | 383.814 | 152.931 | 171.195 | 0.0000% | 10.058 | 35.097% | 7.415% | 0.046 | 0.159 | 89.4691% | 1x / 64 flow/s / threshold_failed |
| 主矩阵 / 短测 | [OIDC: 已登录授权码短测](../reports/main/performance-capacity-curve-oidc-logged-in-short.md) | 9/9 | 1,2,4 | 16,32,64 | 4x / 64 flow/s | 256.429 | 5.433 | 7.338 | 0.0000% | 0.446 | 17.071% | 5.143% | 0.035 | 0.119 | 99.8932% | - |
| 主矩阵 / 短测 | [OIDC: 仅刷新令牌轮换短测](../reports/main/performance-capacity-curve-oidc-refresh-only-short.md) | 9/9 | 1,2,4 | 250,500,1000 | 4x / 1000 flow/s | 999.986 | 8.825 | 15.197 | 0.0000% | 2.729 | 171.931% | 6.341% | 0.046 | 0.174 | 99.9992% | - |
| 主矩阵 / 短测 | [FAPI2: 已登录高安全短测](../reports/main/performance-capacity-curve-fapi2-logged-in-high-security-short.md) | 9/9 | 1,2,4 | 16,32,64 | 4x / 64 flow/s | 320.415 | 7.274 | 9.604 | 0.0000% | 0.698 | 29.660% | 6.700% | 0.043 | 0.134 | 99.9075% | - |
| 主矩阵 / 长测 | [Token-only: client_credentials](../reports/main/performance-capacity-curve-token-only.md) | 15/15 | 1,2,4 | 1000,2500,5000,7500,10000 | 4x / 10000 flow/s | 9972.883 | 4.439 | 32.441 | 0.0000% | 11.803 | 193.865% | 29.809% | 0.017 | 0.447 | 99.9999% | - |
| 主矩阵 / 长测 | [OIDC: 已登录授权码](../reports/main/performance-capacity-curve-oidc-logged-in.md) | 15/15 | 1,2,4 | 16,32,64,128,256 | 4x / 256 flow/s | 1023.732 | 6.805 | 12.307 | 0.0269% | 1.330 | 66.207% | 14.075% | 0.034 | 0.165 | 99.9654% | - |
| 主矩阵 / 长测 | [OIDC: 仅刷新令牌轮换](../reports/main/performance-capacity-curve-oidc-refresh-only.md) | 15/15 | 1,2,4 | 250,500,1000,1500,2000 | 4x / 2000 flow/s | 1996.388 | 13.778 | 56.414 | 0.0000% | 5.378 | 348.654% | 9.175% | 0.061 | 0.357 | 99.9996% | - |
| 主矩阵 / 长测 | [FAPI2: 已登录高安全](../reports/main/performance-capacity-curve-fapi2-logged-in-high-security.md) | 15/15 | 1,2,4 | 16,32,64,128,256 | 4x / 256 flow/s | 1279.754 | 8.981 | 19.428 | 0.0133% | 2.279 | 104.431% | 19.108% | 0.034 | 0.176 | 99.9754% | - |

## 分场景状态

| 场景 | JSON | 详细报告 | 持续时间 | 状态分布 |
| --- | --- | --- | --- | --- |
| Token-only: client_credentials 短测 | [`capacity-token-only-short.json`](../../../perf/results/capacity-token-only-short.json) | [`performance-capacity-curve-token-only-short.md`](../reports/main/performance-capacity-curve-token-only-short.md) | 5m | passed: 9 |
| OIDC: 冷登录 + 刷新短测 | [`capacity-oidc-cold-login-short.json`](../../../perf/results/capacity-oidc-cold-login-short.json) | [`performance-capacity-curve-oidc-cold-login-short.md`](../reports/main/performance-capacity-curve-oidc-cold-login-short.md) | 5m | passed: 8, threshold_failed: 1 |
| OIDC: 已登录授权码短测 | [`capacity-oidc-logged-in-short.json`](../../../perf/results/capacity-oidc-logged-in-short.json) | [`performance-capacity-curve-oidc-logged-in-short.md`](../reports/main/performance-capacity-curve-oidc-logged-in-short.md) | 5m | passed: 9 |
| OIDC: 仅刷新令牌轮换短测 | [`capacity-oidc-refresh-only-short.json`](../../../perf/results/capacity-oidc-refresh-only-short.json) | [`performance-capacity-curve-oidc-refresh-only-short.md`](../reports/main/performance-capacity-curve-oidc-refresh-only-short.md) | 5m | passed: 9 |
| FAPI2: 已登录高安全短测 | [`capacity-fapi2-logged-in-high-security-short.json`](../../../perf/results/capacity-fapi2-logged-in-high-security-short.json) | [`performance-capacity-curve-fapi2-logged-in-high-security-short.md`](../reports/main/performance-capacity-curve-fapi2-logged-in-high-security-short.md) | 5m | passed: 9 |
| Token-only: client_credentials | [`capacity-token-only.json`](../../../perf/results/capacity-token-only.json) | [`performance-capacity-curve-token-only.md`](../reports/main/performance-capacity-curve-token-only.md) | 30m | passed: 15 |
| OIDC: 已登录授权码 | [`capacity-oidc-logged-in.json`](../../../perf/results/capacity-oidc-logged-in.json) | [`performance-capacity-curve-oidc-logged-in.md`](../reports/main/performance-capacity-curve-oidc-logged-in.md) | 30m | passed: 15 |
| OIDC: 仅刷新令牌轮换 | [`capacity-oidc-refresh-only.json`](../../../perf/results/capacity-oidc-refresh-only.json) | [`performance-capacity-curve-oidc-refresh-only.md`](../reports/main/performance-capacity-curve-oidc-refresh-only.md) | 30m | passed: 15 |
| FAPI2: 已登录高安全 | [`capacity-fapi2-logged-in-high-security.json`](../../../perf/results/capacity-fapi2-logged-in-high-security.json) | [`performance-capacity-curve-fapi2-logged-in-high-security.md`](../reports/main/performance-capacity-curve-fapi2-logged-in-high-security.md) | 30m | passed: 15 |

## 测试环境索引

| 场景 | Source commit | Runner | CPU 型号 | 逻辑 CPU | 进程可见 CPU | CPU set | CPU set size | Docker | Compose | 环境文件 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Token-only: client_credentials 短测 | 1df921b3a7f254ea50e8624e90699df901edbde7 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 48-59 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-token-only-short.md`](../../../perf/results/cnb-environment-token-only-short.md) |
| OIDC: 冷登录 + 刷新短测 | 1df921b3a7f254ea50e8624e90699df901edbde7 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 60-63,336-343 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-oidc-cold-login-short.md`](../../../perf/results/cnb-environment-oidc-cold-login-short.md) |
| OIDC: 已登录授权码短测 | 1df921b3a7f254ea50e8624e90699df901edbde7 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 344-355 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-oidc-logged-in-short.md`](../../../perf/results/cnb-environment-oidc-logged-in-short.md) |
| OIDC: 仅刷新令牌轮换短测 | 1df921b3a7f254ea50e8624e90699df901edbde7 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 356-367 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-oidc-refresh-only-short.md`](../../../perf/results/cnb-environment-oidc-refresh-only-short.md) |
| FAPI2: 已登录高安全短测 | 1df921b3a7f254ea50e8624e90699df901edbde7 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 368-379 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-fapi2-logged-in-high-security-short.md`](../../../perf/results/cnb-environment-fapi2-logged-in-high-security-short.md) |
| Token-only: client_credentials | 354dd98f223e38f7f5e8538876eeb881e9a1c5fa | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 48-59 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-token-only.md`](../../../perf/results/cnb-environment-token-only.md) |
| OIDC: 已登录授权码 | 354dd98f223e38f7f5e8538876eeb881e9a1c5fa | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 344-355 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-oidc-logged-in.md`](../../../perf/results/cnb-environment-oidc-logged-in.md) |
| OIDC: 仅刷新令牌轮换 | 354dd98f223e38f7f5e8538876eeb881e9a1c5fa | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 356-367 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-oidc-refresh-only.md`](../../../perf/results/cnb-environment-oidc-refresh-only.md) |
| FAPI2: 已登录高安全 | 354dd98f223e38f7f5e8538876eeb881e9a1c5fa | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 48-63,336-383 | 368-379 | 12 | 27.5.1 | 2.33.0 | [`cnb-environment-fapi2-logged-in-high-security.md`](../../../perf/results/cnb-environment-fapi2-logged-in-high-security.md) |

## 解释口径

- `目标速率` 是 k6 constant-arrival-rate 的 flow/s 目标；部分场景一个 flow 会产生多次 HTTP 请求，因此 `HTTP RPS` 可能高于目标速率。
- `最高通过阶段` 仅表示该矩阵中已执行并满足阈值的最高目标点，不等同于系统极限容量。
- `首个未通过阶段` 为空时，表示该场景在本次矩阵覆盖的所有目标点均通过；不表示更高压力一定通过。
- CPU 指标来自 Docker stats 聚合；PostgreSQL、DB pool、Valkey 指标来自 benchmark 采集器。
