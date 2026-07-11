//! 管理端 HTTP handler 聚合模块。
// 每个子模块按一个管理资源拆分，路由层继续通过本模块 re-export 调用。
mod access_requests;
mod clients;
mod federation;
mod grants;
mod users;

pub(crate) use access_requests::*;
pub(crate) use clients::*;
pub(crate) use federation::*;
pub(crate) use grants::*;
pub(crate) use users::*;
