# NazoAuth 容量基准测试总览

Generated at: `2026-07-06 13:03:57 UTC`

本文是主容量矩阵与扩展容量矩阵的统一入口。详细阶段数据、步骤拆分、数据库指标、Valkey 指标和环境记录保留在各场景报告与 `perf/results/` JSON 中。

## 文档结构

- [主容量矩阵测试总结](summaries/performance-capacity-main-summary.md)
- [扩展容量矩阵测试总结](summaries/performance-capacity-extended-summary.md)
- 各场景详细报告：`docs/performance/reports/**/*.md`
- 原始结构化结果：`perf/results/capacity-*.json`
- 测试环境记录：`perf/results/cnb-environment-*.md`

## 总览表

| 来源 | 场景 | 通过阶段 | 最高通过阶段 | HTTP RPS | p95 ms | p99 ms | 错误率 | 首个未通过阶段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 主矩阵 / 短测 | [Token-only: client_credentials 短测](reports/main/performance-capacity-curve-token-only-short.md) | 9/9 | 4x / 5000 flow/s | 4999.963 | 2.768 | 5.893 | 0.0000% | - |
| 主矩阵 / 短测 | [OIDC: 冷登录 + 刷新短测](reports/main/performance-capacity-curve-oidc-cold-login-short.md) | 8/9 | 4x / 64 flow/s | 383.814 | 152.931 | 171.195 | 0.0000% | 1x / 64 flow/s / threshold_failed |
| 主矩阵 / 短测 | [OIDC: 已登录授权码短测](reports/main/performance-capacity-curve-oidc-logged-in-short.md) | 9/9 | 4x / 64 flow/s | 256.429 | 5.433 | 7.338 | 0.0000% | - |
| 主矩阵 / 短测 | [OIDC: 仅刷新令牌轮换短测](reports/main/performance-capacity-curve-oidc-refresh-only-short.md) | 9/9 | 4x / 1000 flow/s | 999.986 | 8.825 | 15.197 | 0.0000% | - |
| 主矩阵 / 短测 | [FAPI2: 已登录高安全短测](reports/main/performance-capacity-curve-fapi2-logged-in-high-security-short.md) | 9/9 | 4x / 64 flow/s | 320.415 | 7.274 | 9.604 | 0.0000% | - |
| 主矩阵 / 长测 | [Token-only: client_credentials](reports/main/performance-capacity-curve-token-only.md) | 15/15 | 4x / 10000 flow/s | 9972.883 | 4.439 | 32.441 | 0.0000% | - |
| 主矩阵 / 长测 | [OIDC: 已登录授权码](reports/main/performance-capacity-curve-oidc-logged-in.md) | 15/15 | 4x / 256 flow/s | 1023.732 | 6.805 | 12.307 | 0.0269% | - |
| 主矩阵 / 长测 | [OIDC: 仅刷新令牌轮换](reports/main/performance-capacity-curve-oidc-refresh-only.md) | 15/15 | 4x / 2000 flow/s | 1996.388 | 13.778 | 56.414 | 0.0000% | - |
| 主矩阵 / 长测 | [FAPI2: 已登录高安全](reports/main/performance-capacity-curve-fapi2-logged-in-high-security.md) | 15/15 | 4x / 256 flow/s | 1279.754 | 8.981 | 19.428 | 0.0133% | - |
| 扩展矩阵 | [mTLS: client_credentials](reports/extended/performance-capacity-curve-extended-mtls-client-credentials.md) | 15/15 | 4x / 2000 flow/s | 1999.998 | 1.451 | 2.020 | 0.0000% | - |
| 扩展矩阵 | [PAR/JAR: signed request object](reports/extended/performance-capacity-curve-extended-par-signed-request-object.md) | 15/15 | 4x / 2000 flow/s | 1999.997 | 0.726 | 1.043 | 0.0000% | - |
| 扩展矩阵 | [Introspection: opaque refresh token](reports/extended/performance-capacity-curve-extended-introspect-opaque-refresh-token.md) | 6/15 | 4x / 32 flow/s | 191.990 | 173.702 | 207.305 | 0.0000% | 1x / 64 flow/s / threshold_failed |
| 扩展矩阵 | [Authorize: 已登录会话 + PAR](reports/extended/performance-capacity-curve-extended-authorize-par-session.md) | 6/15 | 4x / 32 flow/s | 95.995 | 189.629 | 219.592 | 0.0000% | 1x / 64 flow/s / threshold_failed |
| 扩展矩阵 | [Revocation: refresh token](reports/extended/performance-capacity-curve-extended-revoke-refresh-token.md) | 6/15 | 4x / 32 flow/s | 191.990 | 173.966 | 207.317 | 0.0000% | 1x / 64 flow/s / threshold_failed |
| 扩展矩阵 | [Discovery/JWKS: metadata + keys](reports/extended/performance-capacity-curve-extended-metadata-jwks.md) | 15/15 | 4x / 2000 flow/s | 3999.998 | 0.200 | 0.260 | 0.0000% | - |
| 扩展矩阵 | [CIBA: private_key_jwt + DPoP + poll](reports/extended/performance-capacity-curve-extended-ciba-private-key-jwt-dpop-poll.md) | 15/15 | 4x / 256 flow/s | 767.998 | 2.875 | 3.330 | 0.0000% | - |
| 扩展矩阵 / 同用户压力 | [Same-user: refresh token rotation](reports/extended/performance-capacity-curve-extended-same-user-refresh-token-rotation.md) | 6/15 | 4x / 16 flow/s | 95.995 | 172.595 | 207.392 | 0.0000% | 1x / 32 flow/s / threshold_failed |
| 扩展矩阵 / 同用户压力 | [Same-user: introspection opaque refresh token](reports/extended/performance-capacity-curve-extended-same-user-introspect-opaque-refresh-token.md) | 6/15 | 4x / 16 flow/s | 95.994 | 173.555 | 207.381 | 0.0000% | 1x / 32 flow/s / threshold_failed |
| 扩展矩阵 / 同用户压力 | [Same-user: authorize PAR session](reports/extended/performance-capacity-curve-extended-same-user-authorize-par-session.md) | 6/15 | 4x / 16 flow/s | 47.998 | 189.711 | 219.840 | 0.0000% | 1x / 32 flow/s / threshold_failed |

## 覆盖判断

- 主矩阵覆盖默认可对外开放的 OAuth/OIDC/FAPI2 热路径，包括 client_credentials、已登录 authorization code、refresh rotation、FAPI2 高安全已登录路径，以及短测形式的冷登录路径。
- 扩展矩阵覆盖 mTLS、DPoP、JAR/PAR、CIBA、introspection、revocation、Discovery/JWKS 和同用户压力路径。
- 本轮是容量基准测试，不替代协议一致性测试；协议正确性仍应由 conformance/security matrix 单独证明。
- 对包含密码验证或其它刻意安全限流的路径，应把拒绝/限流视为安全容量边界的一部分，不应简单与无密码哈希的热路径吞吐比较。

## 主要观察

- Token-only 与 refresh-only 热路径达到较高吞吐，延迟主要随目标速率和 PostgreSQL/Valkey 资源占用上升。
- 已登录 OIDC/FAPI2 路径更能代表实际登录后授权链路；冷登录容量受密码哈希并发门禁约束，适合短测和独立保护策略评估。
- 扩展矩阵中的 CIBA、mTLS、PAR/JAR 等场景已经纳入 30 分钟 sustained 测试，可作为后续优化和回归比较基线。
