# 宿主机本地 OIDF Conformance Suite 部署

本手册在私有服务器上部署固定 revision、未修改的官方 OIDF Conformance Suite。它
独立于 NazoAuth 产品镜像，也不通过 GitHub Actions。套件自带的 Nginx 在容器内终止
TLS，并把 `8443` 映射到宿主机 `0.0.0.0:8443`；Spring Boot 的明文 HTTP 端口不向
宿主机公开。本部署只使用 Podman。

固定套件 revision：
`321bc5bc53601b9690b54c023c0cbfac0f0230f2`（`release-v5.2.2`）。

## 1. 获取并核验官方源码

```sh
install -d -m 0755 /opt/nazo-oauth/conformance
git clone https://gitlab.com/openid/conformance-suite.git \
  /opt/nazo-oauth/conformance/operator-suite
git -C /opt/nazo-oauth/conformance/operator-suite checkout --detach \
  321bc5bc53601b9690b54c023c0cbfac0f0230f2
test "$(git -C /opt/nazo-oauth/conformance/operator-suite rev-parse HEAD)" = \
  321bc5bc53601b9690b54c023c0cbfac0f0230f2
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
先验证 revision 与 clean 状态，再在 Maven build stage 中生成 JAR；运行时入口保持
上游容器入口参数契约。下一步脚本用 `podman build --build-context` 构建 Suite 镜像，
并从同一固定、未修改的官方 checkout 构建其 Nginx 镜像；PKI 初始化镜像单独构建。
三个镜像均只构建一次，再用 `podman compose ... up --no-build` 启动，Compose 不得再次
触发构建。镜像标签同时绑定 Suite revision 与 NazoAuth 源码 revision，精确标签一致时
才允许复用。整个过程只在私有服务器的 Podman builder 中编译；不使用开发机 Cargo 或
容器构建，也不使用 GitHub 生成材料。

`release-v5.2.2` 已通过上游 !2123 重新生成源码内固定的 mdoc Document Signer
证书，修复了 `release-v5.2.1` 的过期 fixture。私有 Suite 仍保持官方源码不修改，
服务端证书时效、用途、签发链和签名验证也不放宽；受影响的计划必须在该固定 revision
上真实重跑，不能沿用旧阻塞结论或记为 expected skip。

## 3. 生成短期 API Token 并切换到严格鉴权模式

将同一 NazoAuth 精确源码提交放在 `/opt/nazoauth/source`。脚本先只在
`127.0.0.1:18443` 启动官方套件的开发身份，且明确把该身份设为非管理员；它生成一个
24 小时 API Token 后立即删除临时容器，再以 `devmode=false` 在
内部 HTTP 网络启动正式测试进程，并通过套件 Nginx 把 TLS `8443` 发布到宿主机。
脚本要求 NazoAuth 与 Suite 两个 checkout 都 clean，并在启动前完成上述单次镜像构建或
精确镜像复用。Token 不进入 argv、普通环境变量或日志。

Compose 只管理 MongoDB、正式 Suite server 和 Nginx 三个长期服务。临时 Token 进程
由脚本直接接入固定私有网络 `nazoauth-oidf-suite-default`，生成 Token 后立即删除；它不
作为 Compose profile 或依赖服务存在，避免一次性容器与长期服务发生生命周期冲突。

```sh
export OIDF_SUITE_SOURCE_DIR=/opt/nazo-oauth/conformance/operator-suite
export OIDF_SUITE_BASE_URL=https://oauth-test.nazo.run
export OIDF_SUITE_TOKEN_FILE=/opt/nazo-oauth/conformance/secrets/api-token
export OIDF_SUITE_TOKEN_METADATA_FILE=/opt/nazo-oauth/conformance/secrets/api-token.metadata
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
脚本每次运行都会先吊销上一轮仍可识别的 Token，再签发新的 24 小时临时 Token；Token
本体与包含 id/expiry 的 metadata 均为 `0600`，不会输出到日志。正常测试结束后应使用相同
三个变量调用 `deploy/oidf-suite/revoke-api-token.sh` 显式吊销；异常强杀时，未吊销 Token
仍会在上游 TTL 到期后失效。旧版只有 Token、没有 metadata 的文件在 24 小时 TTL 内会
失败关闭，超过 TTL 后才允许清除并换新。
MongoDB 状态保存在 Compose 命名卷中；源码和 Token 位于上述独立目录，Maven 缓存由
Podman builder 管理；它们均不进入 NazoAuth 产品容器或数据卷。

部署同时创建私有容器网络 `nazoauth-oidf-bridge` 和独立 PKI volume
`nazoauth-oidf-proxy-pki`。脚本在 Compose 启动前通过一次性、自动删除的 Podman 容器
初始化或核验该 volume，避免把一次性任务交给 Compose 的服务生命周期。Suite server
启动时只把该 volume 中的短期 server CA 导入自己的 Java trust store；宿主机和公网
客户端的信任库不受影响。被测端的 mTLS proxy
随后在同一网络上以目标公网主机名作为 network alias，使 Suite 内的协议请求走真实
客户端证书校验，而 onboarding 与公网浏览器仍走公开 TLS 入口。这是
split-horizon 测试网络，不修改 issuer 字符串或 Suite plan 配置。

## 4. 部署核验

```sh
export NAZOAUTH_SOURCE_DIR=/opt/nazoauth/source
podman compose \
  -f /opt/nazoauth/source/deploy/oidf-suite/compose.yml ps
podman compose \
  -f /opt/nazoauth/source/deploy/oidf-suite/compose.yml port nginx 8443
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
