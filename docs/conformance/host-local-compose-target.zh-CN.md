# 宿主机本地 OIDF 的 Compose 被测端

本手册为源码 Docker Compose 沙箱启用 OIDC/FAPI/CIBA/logout/session 一致性测试所需的
运行配置。它不把套件代码加入 NazoAuth 二进制，也不是签名 Release 的正式生产安装。
OIDF Suite 仍按[独立部署手册](host-local-oidf-suite-deployment.zh-CN.md)运行。

## 零状态重建

只允许对明确的新建 `nazo-oauth` Compose project 执行以下清理；先确认清单中没有其他
应用容器或 volume。该命令会删除 PostgreSQL、Valkey、应用密钥、bootstrap、UI 和
operator state，不能用于包含需要保留数据的实例。

```sh
cd /opt/nazoauth-docker
docker compose -f compose.yml -f compose.oidf.yml down -v
export NAZOAUTH_PORT=443
export NAZOAUTH_BIND_ADDRESS=0.0.0.0
export NAZOAUTH_PUBLIC_BASE_URL=https://567t0yglur-443.cnb.run
export NAZOAUTH_OIDF_SUITE_ORIGIN=https://567t0yglur-8443.cnb.run
export NAZOAUTH_BUILD_REVISION="$(git rev-parse HEAD)"
export NAZOAUTH_BUILD_ID="cnb-source:$(git rev-parse HEAD)"
docker compose -f compose.yml -f compose.oidf.yml up -d --build
docker compose -f compose.yml -f compose.oidf.yml ps
```

`compose.oidf.yml` 只负责测试部署配置：在私有 named volume 中生成并持久化动态注册、
CIBA 自动决策和 OpenID4VC 管理 Token；为全新数据库启用 OIDC/FAPI/CIBA/logout/session
所需模块；把 Suite origin 加入受限回调 origin。Token 只通过 `_FILE` 设置由 server
读取，不进入 argv 或普通环境变量。基础 `compose.yml` 的默认最小沙箱不受影响。

OIDF Suite 必须先按其手册启动，因为 overlay 要求已经存在私有网络
`nazoauth-oidf-bridge` 和 PKI volume `nazoauth-oidf-proxy-pki`。`mtls-proxy` 不发布
宿主机端口；它只在该 `/24` 私有网络监听 TLS 443，使用 Suite 信任的短期 server
certificate，并以 `ssl_verify_client optional` 对实际发送的客户端证书建链。代理覆盖
全部外来证书 header；NazoAuth 只信任 `172.30.250.0/24` 中的
`legacy-verified-headers`。CNB 公网流量不会被误当成 mTLS。

## 首任管理员和 runner 秘密

服务健康后执行：

```sh
python3 /opt/nazoauth-docker/scripts/bootstrap_compose_conformance.py \
  --target-origin https://567t0yglur-443.cnb.run \
  --server-container nazo-oauth-server-1 \
  --suite-token-file /opt/oidf-conformance-suite/secrets/api-token \
  --output-dir /opt/nazoauth-conformance/secrets
```

工具在内存中读取 server 容器私有 mount 的一次性 bootstrap Token 与本轮 profile
Token，生成不同的管理员/申请人凭据，通过公开 HTTPS `POST /auth/bootstrap-admin`
创建首任管理员，并删除已消费的 runtime token 文件。它不会打印任何秘密；输出目录为
`0700`，三个 JSON 文件为 `0600`，分别严格匹配 OIDC runner、OpenID4VC runner 和公开
onboarding 的输入 schema。输出目录必须事先不存在。

## 边界

此时只能证明 OIDC/FAPI/CIBA/logout/session 被测端已配置。OpenID4VC 还要求生成受管
ES256 credential/presentation-request key、原子 leaf+CA bundle、数据加密密钥、两个管理
Token、credential metadata 与公开 onboarding trust；在这些边界全部完成前不得启动或
宣称 17-plan OpenID4VC 矩阵。

## mTLS trust reload 入口

被测端启动后，在 WebIDE 私有目录准备 runner 的可回滚 trust target：

```sh
install -d -m 0700 /opt/nazoauth-conformance/proxy
docker cp \
  nazo-oauth-mtls-proxy-1:/etc/nginx/pki/client-ca.pem \
  /opt/nazoauth-conformance/proxy/oidf-mtls-ca.crt
chmod 0644 /opt/nazoauth-conformance/proxy/oidf-mtls-ca.crt
export NAZOAUTH_OIDF_PROXY_CONTAINER=nazo-oauth-mtls-proxy-1
export NAZOAUTH_OIDF_PROXY_TRUST_FILE=/opt/nazoauth-conformance/proxy/oidf-mtls-ca.crt
/opt/nazoauth-docker/deploy/oidf-proxy/docker-nginx-controller.sh -t
/opt/nazoauth-docker/deploy/oidf-proxy/docker-nginx-controller.sh -s reload
```

统一 runner 把经公网审批的 CA bundle 原子写入上述 host 文件，然后调用这个 controller
完成 `docker cp`、容器内 `nginx -t` 和 reload；结束时用同一路径恢复原 bundle。
controller 不接受 trust 内容参数，也不打印证书或秘密。

验证 split-horizon 时使用临时 curl 容器加入私有网络并显式信任 server CA：

```sh
docker run --rm \
  --network nazoauth-oidf-bridge \
  -v nazoauth-oidf-proxy-pki:/pki:ro \
  docker.io/curlimages/curl:8.14.1 \
  --cacert /pki/server-ca.crt \
  https://567t0yglur-443.cnb.run/.well-known/openid-configuration
```
