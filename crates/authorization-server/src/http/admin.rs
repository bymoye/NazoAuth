//! 管理端 HTTP handler 聚合模块。
// 每个子模块按一个管理资源拆分，路由层通过显式模块路径调用。
pub(crate) mod access_requests;
pub(crate) mod clients;
pub(crate) mod federation;
pub(crate) mod grants;
pub(crate) mod users;
