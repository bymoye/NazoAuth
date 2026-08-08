# 私有服务器本地 OpenID4VC 黑盒矩阵

此流程在运行 NazoAuth 和本地 OIDF Conformance Suite 的同一台私有服务器上执行。它只使用公开 NazoAuth 控制面、公开发行方端点和 Suite HTTP API；不读取 PostgreSQL、Valkey、运行时文件或内部管理入口。

## 能力与信任边界

`run_host_local_openid4vc_conformance.py` 只负责 `materialize_openid4vc_oidf_config.matrix_cases()` 中固定的 **17 个** OpenID4VC Final/HAIP plans：创建一个专用非管理员 subject，写入有界 credential dataset，并通过普通申请、审批和一次性凭据交付创建恰好四个 namespaced wallet client。

这 17 个计划使用 `private_key_jwt` 或 client attestation 加 DPoP，不覆盖 RFC 8705 mTLS。因此 runner 强制四个 onboarding record 的 `mtls_trust_anchor_pem` 都是 `null`，绝不修改 ingress proxy client-CA。真实 mTLS client trust 和 proxy 的事务性安装/恢复属于独立的 27-plan OIDC/FAPI/CIBA runner。最终报告可以汇总两份独立、无凭据 evidence 为 **44 plans**，但两条路径不得混用信任边界。

VP request-object trust anchor 是 NazoAuth 验证 verifier request-object 签名链使用的公开证书，通过 `--request-object-trust-anchor-pem` 传入。该文件必须是常规、非 symlink、最多 1 MiB 的 ASCII PEM 证书文件，且不得含私钥。它不是 ingress client-CA，不得安装到反向代理。

对 standards-full 的受管安装，矩阵开始前只能通过正式控制面生成此公开文件。该命令从活动的
原子 OpenID4VC bundle 导出 `CA:TRUE` certificate。runner 同时将它用作 VCI 计划中
部署 issuer 的 credential/status-list trust anchor，以及 VP request-object trust anchor；
它绝不导出 leaf 或任何私钥：

```bash
install -d -m 0755 /etc/nazoauth/public
nazoauthctl keys export-openid4vc-trust \
  --output /etc/nazoauth/public/vp-request-object-anchor.pem
```

## 秘密输入

runner 只从非交互 stdin 或已继承 FD 接受一个严格 UTF-8 JSON 对象；拒绝秘密文件、argv 和环境变量：

```json
{
  "applicant_email": "...",
  "applicant_password": "...",
  "admin_email": "...",
  "admin_password": "...",
  "admin_mfa_totp_secret": "...",
  "suite_token": "...",
  "issuer_management_token": "...",
  "verifier_management_token": "..."
}
```

刻意不提供 OpenID4VC base 或 driver configuration 字段。全新安装前必须由
`prepare_host_local_oidf_install.py` 在本次连续验收中生成新的 `0700` 目录：公开
不含测试信任密钥的 `standards-full-profile.json`、公开 conformance trust、对应的私有
run material，以及绑定精确源码 commit、Suite origin、文件 SHA-256 的 manifest。安装
只读取 baseline profile；runner 通过 `--prepared-install-dir` 重新验证整个绑定，然后按固定 Suite 配置形状构建四类配置，
绑定新建 subject ID、management token 与公开 request-object trust anchor，并验证四个
public onboarding JWKS 与同一批私钥逐一对应。不接受仓库、历史、共享或任意另一批私钥。

准备目录为 `0700`，四个文件为 `0600`。runner 成功物化私有 Suite 配置后立即校验哈希并
删除 `openid4vc-run-material.json`；随后以 `openid4vc-conformance-trust.json` 创建 8 小时
租约，成功写入后再次校验并删除该文件。公开 profile 与 manifest 保留作安装来源证据。
服务只为绑定该租约的 client 解析 attestation 公钥，并把 run-local credential CA 绑定到
同一 Suite origin 创建的 verifier transaction；撤销或到期后全部立即失效，周期清理器
删除 client、绑定的 verifier transaction 并清空租约公开材料。work directory 内的全部私有配置在 `finally` 删除。每次官方 runner 只通过新的继承
FD 接收 Suite token，绝不使用 token file。run-local CA 仅用于 client-attestation、
key-attestation 和 credential 测试材料；它不是 ingress client CA，绝不安装进反向代理。

本轮 `credential.signing_jwk` 包含由本轮 CA 签发、带 ISO/IEC 18013-5 mDL Document
Signer EKU `1.0.18013.5.1.2` 的证书。固定的 `release-v5.2.2` 已通过上游 !2123
重新生成源码内固定的 mdoc Document Signer 证书，修复了 `release-v5.2.1` 的过期
fixture。私有 Suite 保持官方源码不修改，NazoAuth 继续完整验证证书有效期、用途、
签发链和 mdoc 签名；先前受阻的 mdoc plans 必须真实重跑，不能改成 expected skip
或沿用旧结果。

## 私有服务器命令

使用与部署 release identity 一致的干净 checkout，以及精确 revision 的干净本地 Suite checkout。不得添加 filter、临时 expected skip、`--disable-ssl-verify` 或未固定 revision。

```bash
umask 077
run_id="oid4vc-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
work_dir="/var/lib/nazoauth/conformance/${run_id}/private"
export_dir="/var/lib/nazoauth/conformance/${run_id}/evidence"

secret_provider_for_this_host | python3 /opt/nazoauth/source/scripts/run_host_local_openid4vc_conformance.py \
  --secrets-stdin \
  --deployed-sha "$DEPLOYED_SOURCE_SHA" \
  --runner-sha "$DEPLOYED_SOURCE_SHA" \
  --target-issuer https://auth.nazo.run \
  --conformance-server https://oauth-test.nazo.run \
  --suite-dir /opt/nazo-oauth/conformance/operator-suite \
  --suite-revision 321bc5bc53601b9690b54c023c0cbfac0f0230f2 \
  --work-dir "$work_dir" \
  --export-dir "$export_dir" \
  --run-namespace "$run_id" \
  --prepared-install-dir /run/nazoauth-host-local-oidf-install \
  --nazoauthctl /usr/local/bin/nazoauthctl \
  --nazoauthctl-config /etc/nazoauth/update.json \
  --lease-ttl-seconds 28800 \
  --request-object-trust-anchor-pem /etc/nazoauth/public/vp-request-object-anchor.pem \
  --plan-group-size 4 \
  --timeout-seconds 4800 \
  --monitor-interval-seconds 10
```

`secret_provider_for_this_host` 由运营者维护，只能把这一份文档写到 stdout，不得记录内容、导出到环境变量或写入 shell history。FD 方式等价：传入 `--secret-fd N` 并确保 `N >= 3` 被 Python 继承。

私有预发布门禁应同时传入 `oidf-public-black-box-runbook.zh-CN.md` 所述四个
candidate target 参数。runner 会把同一组 release、revision、build ID 和 OCI
manifest digest 绑定到租约创建、撤销与清理；已发布部署不传这些参数，继续
严格绑定已签名 active Release。

## 完成与失败

开始前会验证 runner/deployed commit 都干净且精确、本地 Suite revision 干净且精确、Suite API 的认证边界、17 个唯一 alias 及固定 registry/expected-record。官方 runner 完成后还会再次完整检查 Suite state。

`finally` 删除生成的 Suite config 和专用 dataset，再经同一公开控制面停用四个 client，
随后调用 `nazoauthctl conformance lease revoke` 与 `cleanup`；此 runner 不创建 mTLS trust
request。随后将 Suite archive 归约为 `evidence-manifest.json`，并写入无凭据的
`host-local-openid4vc-receipt.json`。清理、租约撤销、Suite 洁净性或终态检查有错误即整个
操作失败；不得通过数据库或内部入口修复状态。
