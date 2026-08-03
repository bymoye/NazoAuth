# Release 平台支持

## 正式制品矩阵

每个 tagged Release 都为以下 Rust target 生成并在同操作系统、同 CPU 架构的
原生 runner 上执行 `nazoauth`：

- Linux GNU：`x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`
- Linux musl：`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`
- Windows MSVC：`x86_64-pc-windows-msvc`、`aarch64-pc-windows-msvc`
- macOS：`x86_64-apple-darwin`、`aarch64-apple-darwin`

GitHub Release 仅保留上述 8 个 target 的 server 可执行文件，以及匹配版本且带
provenance 的 `nazo-operator-protocol` crate。NazoAuthCtl 在独立仓库构建、签名和
发布，不由 server Release 重复构建。
OCI Release 是一个只包含 `linux/amd64` 与 `linux/arm64` 的 index；签名 Release
同时绑定 index digest 和两个 platform manifest digest。

## 安装与升级边界

正式的 `install`、`update`、`rollback`、`recover` 和 migration 生命周期只支持
Linux `x86_64` 与 Linux `aarch64`。其他操作系统或 CPU 架构会在创建配置、密钥、
数据库或容器之前被明确拒绝。Windows 与 macOS 二进制通过原生 smoke/test 只证明
对应可执行文件及只读诊断界面，不代表它们能够执行 Linux 的 systemd、所有权、挂载
标签或数据库恢复流程。

宿主机模式要求 root 与 systemd，并根据当前架构选择对应 GNU 或 musl Release
二进制；systemd unit 和部署目录本身不包含架构假设。Podman/Docker 模式在 x86-64
主机绑定 `linux/amd64` platform manifest digest，在 Arm64 主机绑定
`linux/arm64` platform manifest digest。最终状态、operator task 和审计收据绑定的
是实际平台 manifest 或宿主机二进制 digest，而不是笼统的 OCI index。

浏览器 UI 不嵌入后端二进制。schema-5 Release 绑定独立签名的 NazoAuthWeb
descriptor，应用启动时下载并校验对应 UI 制品。
