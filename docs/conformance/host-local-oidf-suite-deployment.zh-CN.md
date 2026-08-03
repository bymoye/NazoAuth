# 宿主机本地 OIDF Conformance Suite 部署

本手册在私有服务器上部署固定 revision 的官方 OIDF Conformance Suite，以及下述有
哈希约束的运行时 fixture overlay。它独立于 NazoAuth 产品镜像，也不通过 GitHub
Actions。公网入口负责终止 TLS；套件只把 Spring Boot 的明文 HTTP 端口 `8080`
映射到宿主机 `0.0.0.0:8443`。本部署只使用 Podman。

固定套件 revision：
`946451d1ce29965c9ab7aee05f5003552233160e`。

## 1. 获取并核验官方源码

```sh
install -d -m 0755 /opt/nazo-oauth/conformance
git clone https://gitlab.com/openid/conformance-suite.git \
  /opt/nazo-oauth/conformance/operator-suite
git -C /opt/nazo-oauth/conformance/operator-suite checkout --detach \
  946451d1ce29965c9ab7aee05f5003552233160e
test "$(git -C /opt/nazo-oauth/conformance/operator-suite rev-parse HEAD)" = \
  946451d1ce29965c9ab7aee05f5003552233160e
test -z "$(git -C /opt/nazo-oauth/conformance/operator-suite status --porcelain)"
```

已存在目录时不得重新 clone 或覆盖；先分别核验远端 URL、HEAD 和 clean 状态。

## 2. 核验 Podman 构建边界

```sh
podman version
podman compose version
podman build --help | grep -F -- --build-context
test -f /opt/nazo-oauth/conformance/operator-suite/pom.xml
```

不得直接运行上游 `builder-compose.yml`，也不得在宿主机安装 Maven 来绕过容器构建。
仓库内的 `deploy/oidf-suite/Containerfile` 通过具名 build context 读取固定 suite 源码，
在 Maven build stage 中应用 overlay、运行聚焦单测并生成 JAR；运行时入口保持上游
容器入口参数契约。实际构建由下一步脚本调用 `podman compose ... up --build`
完成。整个过程只在私有服务器的 Podman builder 中编译；不使用开发机 Cargo 或容器构建，
也不使用 GitHub 生成材料。

上游 OpenID4VP mdoc fixture 未读取计划中的 `credential.signing_jwk`，而是使用源码内的
固定 Document Signer 证书。该固定证书不属于被测端信任材料，也不能通过放宽服务端的
证书时效/链验证来接受。因此 Containerfile 在保持上游 checkout clean 的前提下，验证并
应用 `deploy/oidf-suite/patches/0001-vp-mdoc-use-configured-issuer.patch`，只让 fixture 使用
计划已提供的签名 JWK，并保留其完整 `x5c` 链。构建时会执行对应的 Suite 聚焦单测。
补丁哈希和上游 revision 同时写入镜像 label；任何哈希、revision、clean、apply 或单测
校验失败都会停止构建。GitHub 的官方 Suite workflows 不引用此 overlay。

## 3. 生成短期 API Token 并切换到严格鉴权模式

将同一 NazoAuth 精确源码提交放在 `/opt/nazoauth/source`。脚本先只在
`127.0.0.1:18443` 启动官方套件的开发身份，且明确把该身份设为非管理员；它生成一个
24 小时 API Token 后立即删除临时容器，再以 `devmode=false` 在
`0.0.0.0:8443` 启动正式测试进程。Token 不进入 argv、普通环境变量或日志。

```sh
export OIDF_SUITE_SOURCE_DIR=/opt/nazo-oauth/conformance/operator-suite
export OIDF_SUITE_BASE_URL=https://oauth-test.nazo.run
export OIDF_SUITE_TOKEN_FILE=/opt/nazo-oauth/conformance/secrets/api-token
export OIDF_OPERATOR_ISSUER=https://auth.nazo.run
export OIDF_TARGET_HOSTNAME=auth.nazo.run
export OIDF_CONTAINER_RUNTIME=podman
sh /opt/nazoauth/source/deploy/oidf-suite/bootstrap-api-token.sh
```

脚本的成功条件是公网 `/api/server` 未认证返回 `401`，使用新 Token 返回 `200`。
官方套件在非开发模式启动时必须解析其操作员登录 OIDC issuer；
`OIDF_OPERATOR_ISSUER` 必须指向容器可达且 Discovery issuer 自洽的 HTTPS OIDC
服务。本测试环境使用正在验收的 NazoAuth issuer，只为满足套件操作员登录注册的启动
依赖；矩阵仍通过 Suite API Token 驱动，不执行该登录流程。
若 Token 已生成而后续正式启动或公网核验失败，重新运行脚本只会复用权限为 `0600` 的
现有文件并重新验证，不会覆盖或打印 Token。
MongoDB 状态保存在 Compose 命名卷中；源码和 Token 位于上述独立目录，Maven 缓存由
Podman builder 管理；它们均不进入 NazoAuth 产品容器或数据卷。

部署同时创建私有容器网络 `nazoauth-oidf-bridge` 和独立 PKI volume
`nazoauth-oidf-proxy-pki`。Suite server 启动时只把该 volume 中的短期 server CA 导入
自己的 Java trust store；宿主机和公网客户端的信任库不受影响。被测端的 mTLS proxy
随后在同一网络上以目标公网主机名作为 network alias，使 Suite 内的协议请求走真实
客户端证书校验，而 onboarding 与公网浏览器仍走公开 TLS 入口。这是
split-horizon 测试网络，不修改 issuer 字符串或 Suite plan 配置。

## 4. 部署核验

```sh
export NAZOAUTH_SOURCE_DIR=/opt/nazoauth/source
podman compose \
  -f /opt/nazoauth/source/deploy/oidf-suite/compose.yml ps
podman compose \
  -f /opt/nazoauth/source/deploy/oidf-suite/compose.yml port server 8080
curl -fsS https://oauth-test.nazo.run/login.html >/dev/null
```

端口命令必须返回 `0.0.0.0:8443`。还必须分别核验 Podman published-port、宿主机
回环访问和公网 HTTPS；其中任何一层都不能替代另外两层。

不得把开发身份注入模式留在公开端口，不得把 API Token 打印到终端。若 JAR 构建、
临时 Token 启动、公网转发、401/200 边界或固定 revision 核验中任一步失败，本次部署
不通过；应记录失败并先修复部署代码或文档，不能用未记录的手工操作补齐。

## 5. 矩阵执行顺序

先按公开黑盒 runner 运行 27 个 OIDC/FAPI/CIBA/logout/session plans：safe group
workers 为 `2`，browser group workers 为 `2`，CIBA 组保持串行。完成并清理 suite
worktree 后，再运行 17 个 OpenID4VC plans，`--plan-group-size 4`。具体参数和秘密输入
契约分别见[公开黑盒手册](oidf-public-black-box-runbook.zh-CN.md)、
[OpenID4VC 宿主机手册](host-local-openid4vc-runbook.zh-CN.md)和
[并发调优记录](../operations/2026-07-24-oidf-concurrency-tuning.zh-CN.md)。
