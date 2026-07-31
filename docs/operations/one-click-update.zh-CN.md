# 一键升级

`nazoauthctl` 是独立 Podman 部署的正式升级入口。它只消费不可变的标签发布
制品，不会在生产主机克隆源码，也不要求 Rust、Node.js 或 Docker 构建环境。

首次安装将 root 所有的配置写入 `/etc/nazoauth/update.json` 后，日常升级只有
一个命令：

```sh
sudo nazoauthctl update
```

`nazoauthctl check` 只验证最新发布而不修改运行状态；
`nazoauthctl update --to v1.2.3` 固定到指定版本；
`nazoauthctl status` 查看当前镜像 revision。

## 信任与事务边界

每个正式标签由 `release-security` 持久发布：

- 后端不可变镜像归档；
- 由 `release/frontend.lock` 固定提交的前端制品；
- 统一的 `nazoauth` 二进制和 CycloneDX SBOM；
- `nazoauthctl`；
- 包含所有制品大小和 SHA-256 的更新清单；
- 绑定标签和 GitHub Actions 工作流身份的无密钥 Sigstore bundle。

更新器先用 Cosign 校验清单，证书身份必须精确匹配
`release-security.yml@refs/tags/<version>`，然后才解析制品名称和摘要。浮动
镜像标签、未签名清单、错误工作流身份、摘要不一致、镜像 revision 不一致，
以及没有声明数据库回滚兼容性的发布都会失败关闭。

如果主机没有安装 `cosign`，更新器会运行按 OCI digest 固定的官方多架构 Cosign
发布镜像。更新验证器 digest 必须经过源码评审，不会从网络选择 `latest`。

一次升级事务依次完成：

1. 获取主机排他锁；
2. 下载并验证签名清单和制品；
3. 创建并校验 PostgreSQL custom-format 备份；
4. 等待 Valkey `BGSAVE` 完成并复制 RDB；
5. 快照配置中声明的应用持久目录；
6. 加载精确镜像并校验 revision；
7. 执行迁移、替换应用容器并等待 readiness；
8. 原子切换签名前端制品；
9. 验证公网 Discovery 并写入部署记录；
10. 从同一签名发布中原子更新更新器自身。

如果迁移、启动、readiness 或公网验证失败，更新器会删除候选容器、恢复应用
目录快照、重启旧镜像并记录回滚。它不会悄悄回滚 PostgreSQL；数据库恢复必须
从已验证备份单独执行。因此，一键升级只接受经评审的
`release/update-policy.json` 明确声明可重启上一应用版本的迁移集合。

## 配置

以 `deploy/update/update.example.json` 为起点。该文件只包含拓扑和路径，不是
可执行 Shell 配置：

```sh
sudo install -d -m 0755 /etc/nazoauth
sudo install -m 0600 deploy/update/update.example.json /etc/nazoauth/update.json
sudo install -m 0755 deploy/update/nazoauthctl /usr/local/sbin/nazoauthctl
```

首次升级前应核对容器名、数据库和用户、issuer、网络/IP、挂载、快照目录、
Valkey 密码文件及 UI 路径。先运行 `nazoauthctl check` 做非修改验收。

默认不启用定时自动升级。认证基础设施应由运维人员显式执行，或另行评审维护
窗口自动化。
