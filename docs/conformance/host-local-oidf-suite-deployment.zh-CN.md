# 宿主机本地 OIDF Conformance Suite 部署

本手册只部署官方 OIDF Conformance Suite。它独立于 NazoAuth 产品镜像，也不通过
GitHub Actions。CNB WebIDE 在公网侧终止 TLS，因此套件只需把 Spring Boot 的明文
HTTP 端口 `8080` 映射到宿主机 `0.0.0.0:8443`。

固定套件 revision：
`946451d1ce29965c9ab7aee05f5003552233160e`。

## 1. 获取并核验官方源码

```sh
install -d -m 0755 /opt/oidf-conformance-suite
chown "$(id -u):$(id -g)" /opt/oidf-conformance-suite
git clone https://gitlab.com/openid/conformance-suite.git /opt/oidf-conformance-suite/source
git -C /opt/oidf-conformance-suite/source checkout --detach \
  946451d1ce29965c9ab7aee05f5003552233160e
test "$(git -C /opt/oidf-conformance-suite/source rev-parse HEAD)" = \
  946451d1ce29965c9ab7aee05f5003552233160e
test -z "$(git -C /opt/oidf-conformance-suite/source status --porcelain)"
```

已存在目录时不得重新 clone 或覆盖；先分别核验远端 URL、HEAD 和 clean 状态。

## 2. 核验远端 Docker context 构建边界

```sh
docker context show
docker context inspect "$(docker context show)"
test -f /opt/oidf-conformance-suite/source/pom.xml
```

CNB 的 Docker daemon 不一定与 SSH shell 共享宿主机文件系统，因此不得直接执行上游
`builder-compose.yml`：其中的 `.:/usr/src/mymaven` 是 daemon-side bind mount，在远端
context 下可能得到空目录。仓库内的 `deploy/oidf-suite/Containerfile` 通过 Docker build
context 发送固定 suite 源码，并在 Maven build stage 中生成 JAR；其运行时入口保持上游
Dockerfile 的参数契约。实际构建由下一步脚本调用 `docker compose ... up --build` 完成。
整个过程只在目标服务器的 Docker builder 中编译；不使用本地 Cargo/Docker，也不使用
GitHub 生成材料。

## 3. 生成短期 API Token 并切换到严格鉴权模式

将同一 NazoAuth 精确源码提交放在 `/opt/nazoauth-docker`。脚本先只在
`127.0.0.1:18443` 启动官方套件的开发身份，且明确把该身份设为非管理员；它生成一个
24 小时 API Token 后立即删除临时容器，再以 `devmode=false` 在
`0.0.0.0:8443` 启动正式测试进程。Token 不进入 argv、普通环境变量或日志。

```sh
export OIDF_SUITE_SOURCE_DIR=/opt/oidf-conformance-suite/source
export OIDF_SUITE_BASE_URL=https://567t0yglur-8443.cnb.run
export OIDF_SUITE_TOKEN_FILE=/opt/oidf-conformance-suite/secrets/api-token
export OIDF_OPERATOR_ISSUER=https://567t0yglur-443.cnb.run
sh /opt/nazoauth-docker/deploy/oidf-suite/bootstrap-api-token.sh
```

脚本的成功条件是公网 `/api/server` 未认证返回 `401`，使用新 Token 返回 `200`。
官方套件在非开发模式启动时必须解析其操作员登录 OIDC issuer；CNB 容器网络无法访问
Google/GitLab 时，`OIDF_OPERATOR_ISSUER` 必须指向容器可达且 Discovery issuer 自洽的
HTTPS OIDC 服务。本机测试环境使用正在验收的 NazoAuth issuer，只为满足套件操作员
登录注册的启动依赖；矩阵仍通过 Suite API Token 驱动，不执行该登录流程。
若 Token 已生成而后续正式启动或公网核验失败，重新运行脚本只会复用权限为 `0600` 的
现有文件并重新验证，不会覆盖或打印 Token。
MongoDB 状态保存在 Compose 命名卷中；源码和 Token 位于上述独立目录，Maven 缓存由
Docker builder 管理；它们均不进入 NazoAuth 产品容器或数据卷。

## 4. 部署核验

```sh
export NAZOAUTH_SOURCE_DIR=/opt/nazoauth-docker
docker compose \
  --project-directory /opt/nazoauth-docker/deploy/oidf-suite \
  -f /opt/nazoauth-docker/deploy/oidf-suite/compose.yml ps
ss -ltnp '( sport = :8443 )'
curl -fsS https://567t0yglur-8443.cnb.run/login.html >/dev/null
```

不得把开发身份注入模式留在公开端口，不得把 API Token 打印到终端。若 JAR 构建、
临时 Token 启动、CNB 转发、401/200 边界或固定 revision 核验中任一步失败，本次部署
不通过；应记录失败并先修复部署代码或文档，不能用未记录的手工操作补齐。

## 5. 矩阵执行顺序

先按公开黑盒 runner 运行 27 个 OIDC/FAPI/CIBA/logout/session plans：safe group
workers 为 `2`，browser group workers 为 `2`，CIBA 组保持串行。完成并清理 suite
worktree 后，再运行 17 个 OpenID4VC plans，`--plan-group-size 17`。具体参数和秘密输入
契约分别见[公开黑盒手册](oidf-public-black-box-runbook.zh-CN.md)、
[OpenID4VC 宿主机手册](host-local-openid4vc-runbook.zh-CN.md)和
[并发调优记录](../operations/2026-07-24-oidf-concurrency-tuning.zh-CN.md)。
