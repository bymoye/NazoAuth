# 发布物与黑盒验证边界

NazoAuth 生产发布物只包含协议实现、数据库迁移和独立签名的 `nazoauth`。
`nazoauthctl` 由 `nazozero/NazoAuthCtl` 独立构建、签名和发布。

服务仓库与发布物不包含第三方测试 runner、plan 清单、浏览器自动化、测试凭据、
测试专用接入模型或预期结果目录。外部验证器只是普通客户端：它通过公开 HTTPS
协议和所有集成都可使用的租户/客户端管理能力访问服务。产品代码不得根据验证器
身份、plan 名称、callback path、测试 header 或编译开关改变行为。

长期运行容器只包含 `nazoauth`。`server` 入口不能修改 schema；宿主机特权工作通过
签名控制协议执行。外部验证工具在仓库之外独立版本化和运行。OIDF 的 Markdown
证据保留在 `docs/conformance/`，作为 NazoAuth 验证记录的一部分，包含实际发布物
身份、原始结果、人工复核、清理及签名证据摘要。文档与服务端运行行为分离；私有
原始日志和测试 secret 不打包进生产可执行文件，也不随报告提交。

`crates/operator-protocol` 是控制协议与密码规则的唯一事实源。发布兼容性由协议版本
和支持的控制器版本声明，不支持的组合失败关闭。
