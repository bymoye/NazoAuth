# 发布物与一致性测试边界

生产发布物只包含协议实现、数据库迁移，以及分别签名的 `nazoauth` 与
`nazoauthctl`，不包含 OIDF plan、runner
源码、浏览器自动化、预期结果清单、接入夹具、测试凭据或一致性测试脚本。

长期运行的容器只包含 `nazoauth`。公开的 `server` 入口不能修改 schema；特权操作
只接受封闭、签名的 `operator-task` 协议。宿主机 `nazoauthctl` 验证实际 OCI/宿主机
digest，先完成最小权限一次性沙箱准备，再签发 60 秒任务；宿主机部署以服务用户
执行同一已验证二进制。OIDF 工具只存在于源码仓库，并且只能通过公网
HTTPS 协议端点和正常的公开管理流程访问已部署服务。产品代码不得根据 suite
alias、plan 名称、callback path、测试 header 或 conformance 编译开关改变行为。

官方 OpenID Foundation Conformance Suite 必须检出到精确 commit，且其受版本控制的
源码必须保持未修改。仓库可以在套件外部生成 runner 配置、监控公开 API，但不得给
官方 runner 或协议断言打补丁。

`tests/unit/test_release_governance.py` 和容器构建会检查这些边界。如果某项改动需要
OIDF 特异化的产品分支，该实现不应合入；正确做法是实现对应规范，再验证公网行为。
