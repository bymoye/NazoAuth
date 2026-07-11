//! 当前用户 HTTP handler 聚合模块。
// 子模块按 /auth/me 下的资源职责拆分，路由层通过本模块 re-export。
mod access_requests;
mod account;
mod applications;
mod avatar;
mod delivery;
mod federation_links;
mod mfa;
mod oidc_logout;
mod passkeys;
mod session;
mod session_management;

pub(crate) use access_requests::*;
pub(crate) use account::*;
pub(crate) use applications::*;
pub(crate) use avatar::*;
pub(crate) use delivery::*;
pub(crate) use federation_links::*;
pub(crate) use mfa::*;
pub(crate) use oidc_logout::*;
pub(crate) use passkeys::*;
pub(crate) use session::*;
pub(crate) use session_management::*;
