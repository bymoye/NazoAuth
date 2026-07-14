//! 登录、注册与 CSRF 相关 HTTP handler 聚合模块。
// 子模块按端点拆分，路由层通过显式模块路径调用 handler。
pub(crate) mod csrf;
pub(crate) mod federation;
