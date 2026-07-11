# NazoAuth 扩展容量矩阵测试总结

Generated at: `2026-07-06 13:03:57 UTC`

本文汇总扩展容量矩阵结果。扩展矩阵用于覆盖主矩阵之外的安全协议面和特殊访问模式，避免把所有协议能力压入一张难以解释的主容量表。

## 覆盖范围

- 安全协议面：mTLS、PAR/JAR signed request object、opaque token introspection、revocation、metadata/JWKS、CIBA private_key_jwt + DPoP + poll。
- 会话路径：已登录会话 + PAR authorize。
- 同用户压力：同一用户 refresh rotation、introspection、authorize PAR session，用于观察热点用户或自动化滥用下的状态竞争和资源占用。

## 汇总结果

| 矩阵 | 场景 | 通过阶段 | 实例数 | 目标速率 | 最高通过阶段 | HTTP RPS | p95 ms | p99 ms | 错误率 | App CPU cores | PG CPU | Valkey CPU | PG stmt ms | DB wait ms | Valkey 命中 | 首个未通过阶段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 扩展矩阵 | [mTLS: client_credentials](../reports/extended/performance-capacity-curve-extended-mtls-client-credentials.md) | 15/15 | 1,2,4 | 250,500,1000,1500,2000 | 4x / 2000 flow/s | 1999.998 | 1.451 | 2.020 | 0.0000% | 1.876 | 30.352% | 4.851% | 0.014 | 0.127 | 99.9996% | - |
| 扩展矩阵 | [PAR/JAR: signed request object](../reports/extended/performance-capacity-curve-extended-par-signed-request-object.md) | 15/15 | 1,2,4 | 250,500,1000,1500,2000 | 4x / 2000 flow/s | 1999.997 | 0.726 | 1.043 | 0.0000% | 0.700 | 25.385% | 9.122% | 0.013 | 0.093 | 99.9996% | - |
| 扩展矩阵 | [Introspection: opaque refresh token](../reports/extended/performance-capacity-curve-extended-introspect-opaque-refresh-token.md) | 6/15 | 1,2,4 | 16,32,64,128,256 | 4x / 32 flow/s | 191.990 | 173.702 | 207.305 | 0.0000% | 5.506 | 13.536% | 4.144% | 0.041 | 0.153 | 89.4646% | 1x / 64 flow/s / threshold_failed |
| 扩展矩阵 | [Authorize: 已登录会话 + PAR](../reports/extended/performance-capacity-curve-extended-authorize-par-session.md) | 6/15 | 1,2,4 | 16,32,64,128,256 | 4x / 32 flow/s | 95.995 | 189.629 | 219.592 | 0.0000% | 5.413 | 4.169% | 2.448% | 0.034 | 0.233 | 74.9837% | 1x / 64 flow/s / threshold_failed |
| 扩展矩阵 | [Revocation: refresh token](../reports/extended/performance-capacity-curve-extended-revoke-refresh-token.md) | 6/15 | 1,2,4 | 16,32,64,128,256 | 4x / 32 flow/s | 191.990 | 173.966 | 207.317 | 0.0000% | 5.510 | 15.579% | 4.137% | 0.045 | 0.160 | 89.4646% | 1x / 64 flow/s / threshold_failed |
| 扩展矩阵 | [Discovery/JWKS: metadata + keys](../reports/extended/performance-capacity-curve-extended-metadata-jwks.md) | 15/15 | 1,2,4 | 250,500,1000,1500,2000 | 4x / 2000 flow/s | 3999.998 | 0.200 | 0.260 | 0.0000% | 0.298 | 0.543% | 0.492% | 0.008 | 0.124 | - | - |
| 扩展矩阵 | [CIBA: private_key_jwt + DPoP + poll](../reports/extended/performance-capacity-curve-extended-ciba-private-key-jwt-dpop-poll.md) | 15/15 | 1,2,4 | 16,32,64,128,256 | 4x / 256 flow/s | 767.998 | 2.875 | 3.330 | 0.0000% | 0.764 | 17.318% | 5.545% | 0.018 | 0.110 | 99.9984% | - |
| 扩展矩阵 / 同用户压力 | [Same-user: refresh token rotation](../reports/extended/performance-capacity-curve-extended-same-user-refresh-token-rotation.md) | 6/15 | 1,2,4 | 8,16,32,64,128 | 4x / 16 flow/s | 95.995 | 172.595 | 207.392 | 0.0000% | 2.794 | 9.399% | 2.522% | 0.045 | 0.135 | 89.4555% | 1x / 32 flow/s / threshold_failed |
| 扩展矩阵 / 同用户压力 | [Same-user: introspection opaque refresh token](../reports/extended/performance-capacity-curve-extended-same-user-introspect-opaque-refresh-token.md) | 6/15 | 1,2,4 | 8,16,32,64,128 | 4x / 16 flow/s | 95.994 | 173.555 | 207.381 | 0.0000% | 2.790 | 7.052% | 2.584% | 0.040 | 0.132 | 89.4555% | 1x / 32 flow/s / threshold_failed |
| 扩展矩阵 / 同用户压力 | [Same-user: authorize PAR session](../reports/extended/performance-capacity-curve-extended-same-user-authorize-par-session.md) | 6/15 | 1,2,4 | 8,16,32,64,128 | 4x / 16 flow/s | 47.998 | 189.711 | 219.840 | 0.0000% | 2.710 | 2.513% | 1.617% | 0.033 | 0.230 | 74.9674% | 1x / 32 flow/s / threshold_failed |

## 分场景状态

| 场景 | JSON | 详细报告 | 持续时间 | 状态分布 |
| --- | --- | --- | --- | --- |
| mTLS: client_credentials | [`capacity-extended-mtls-client-credentials.json`](../../../perf/results/capacity-extended-mtls-client-credentials.json) | [`performance-capacity-curve-extended-mtls-client-credentials.md`](../reports/extended/performance-capacity-curve-extended-mtls-client-credentials.md) | 30m | passed: 15 |
| PAR/JAR: signed request object | [`capacity-extended-par-signed-request-object.json`](../../../perf/results/capacity-extended-par-signed-request-object.json) | [`performance-capacity-curve-extended-par-signed-request-object.md`](../reports/extended/performance-capacity-curve-extended-par-signed-request-object.md) | 30m | passed: 15 |
| Introspection: opaque refresh token | [`capacity-extended-introspect-opaque-refresh-token.json`](../../../perf/results/capacity-extended-introspect-opaque-refresh-token.json) | [`performance-capacity-curve-extended-introspect-opaque-refresh-token.md`](../reports/extended/performance-capacity-curve-extended-introspect-opaque-refresh-token.md) | 30m | passed: 6, skipped_after_threshold_failure: 6, threshold_failed: 3 |
| Authorize: 已登录会话 + PAR | [`capacity-extended-authorize-par-session.json`](../../../perf/results/capacity-extended-authorize-par-session.json) | [`performance-capacity-curve-extended-authorize-par-session.md`](../reports/extended/performance-capacity-curve-extended-authorize-par-session.md) | 30m | passed: 6, skipped_after_threshold_failure: 6, threshold_failed: 3 |
| Revocation: refresh token | [`capacity-extended-revoke-refresh-token.json`](../../../perf/results/capacity-extended-revoke-refresh-token.json) | [`performance-capacity-curve-extended-revoke-refresh-token.md`](../reports/extended/performance-capacity-curve-extended-revoke-refresh-token.md) | 30m | passed: 6, skipped_after_threshold_failure: 6, threshold_failed: 3 |
| Discovery/JWKS: metadata + keys | [`capacity-extended-metadata-jwks.json`](../../../perf/results/capacity-extended-metadata-jwks.json) | [`performance-capacity-curve-extended-metadata-jwks.md`](../reports/extended/performance-capacity-curve-extended-metadata-jwks.md) | 30m | passed: 15 |
| CIBA: private_key_jwt + DPoP + poll | [`capacity-extended-ciba-private-key-jwt-dpop-poll.json`](../../../perf/results/capacity-extended-ciba-private-key-jwt-dpop-poll.json) | [`performance-capacity-curve-extended-ciba-private-key-jwt-dpop-poll.md`](../reports/extended/performance-capacity-curve-extended-ciba-private-key-jwt-dpop-poll.md) | 30m | passed: 15 |
| Same-user: refresh token rotation | [`capacity-extended-same-user-refresh-token-rotation.json`](../../../perf/results/capacity-extended-same-user-refresh-token-rotation.json) | [`performance-capacity-curve-extended-same-user-refresh-token-rotation.md`](../reports/extended/performance-capacity-curve-extended-same-user-refresh-token-rotation.md) | 30m | passed: 6, skipped_after_threshold_failure: 6, threshold_failed: 3 |
| Same-user: introspection opaque refresh token | [`capacity-extended-same-user-introspect-opaque-refresh-token.json`](../../../perf/results/capacity-extended-same-user-introspect-opaque-refresh-token.json) | [`performance-capacity-curve-extended-same-user-introspect-opaque-refresh-token.md`](../reports/extended/performance-capacity-curve-extended-same-user-introspect-opaque-refresh-token.md) | 30m | passed: 6, skipped_after_threshold_failure: 6, threshold_failed: 3 |
| Same-user: authorize PAR session | [`capacity-extended-same-user-authorize-par-session.json`](../../../perf/results/capacity-extended-same-user-authorize-par-session.json) | [`performance-capacity-curve-extended-same-user-authorize-par-session.md`](../reports/extended/performance-capacity-curve-extended-same-user-authorize-par-session.md) | 30m | passed: 6, skipped_after_threshold_failure: 6, threshold_failed: 3 |

## 测试环境索引

| 场景 | Source commit | Runner | CPU 型号 | 逻辑 CPU | 进程可见 CPU | CPU set | CPU set size | Docker | Compose | 环境文件 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mTLS: client_credentials | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 161-166 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-mtls-client-credentials.md`](../../../perf/results/cnb-environment-extended-mtls-client-credentials.md) |
| PAR/JAR: signed request object | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 167-172 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-par-signed-request-object.md`](../../../perf/results/cnb-environment-extended-par-signed-request-object.md) |
| Introspection: opaque refresh token | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 173-178 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-introspect-opaque-refresh-token.md`](../../../perf/results/cnb-environment-extended-introspect-opaque-refresh-token.md) |
| Authorize: 已登录会话 + PAR | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 179-184 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-authorize-par-session.md`](../../../perf/results/cnb-environment-extended-authorize-par-session.md) |
| Revocation: refresh token | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 185-190 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-revoke-refresh-token.md`](../../../perf/results/cnb-environment-extended-revoke-refresh-token.md) |
| Discovery/JWKS: metadata + keys | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 191-196 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-metadata-jwks.md`](../../../perf/results/cnb-environment-extended-metadata-jwks.md) |
| CIBA: private_key_jwt + DPoP + poll | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 197-202 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-ciba-private-key-jwt-dpop-poll.md`](../../../perf/results/cnb-environment-extended-ciba-private-key-jwt-dpop-poll.md) |
| Same-user: refresh token rotation | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 203-208 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-same-user-refresh-token-rotation.md`](../../../perf/results/cnb-environment-extended-same-user-refresh-token-rotation.md) |
| Same-user: introspection opaque refresh token | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 209-214 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-same-user-introspect-opaque-refresh-token.md`](../../../perf/results/cnb-environment-extended-same-user-introspect-opaque-refresh-token.md) |
| Same-user: authorize PAR session | fa2a0e770c3d6482a90f5b7c9d92891a440bcde6 | cnb:arch:amd64 | AMD EPYC 9K65 192-Core Processor | 384 | 161-224 | 215-220 | 6 | 27.5.1 | 2.33.0 | [`cnb-environment-extended-same-user-authorize-par-session.md`](../../../perf/results/cnb-environment-extended-same-user-authorize-par-session.md) |

## 解释口径

- `目标速率` 是 k6 constant-arrival-rate 的 flow/s 目标；部分场景一个 flow 会产生多次 HTTP 请求，因此 `HTTP RPS` 可能高于目标速率。
- `最高通过阶段` 仅表示该矩阵中已执行并满足阈值的最高目标点，不等同于系统极限容量。
- `首个未通过阶段` 为空时，表示该场景在本次矩阵覆盖的所有目标点均通过；不表示更高压力一定通过。
- CPU 指标来自 Docker stats 聚合；PostgreSQL、DB pool、Valkey 指标来自 benchmark 采集器。
