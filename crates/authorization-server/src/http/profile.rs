//! 当前用户 HTTP handler 聚合模块。
// 子模块按 /auth/me 下的资源职责拆分，路由层通过显式模块路径调用。
pub(crate) mod access_requests;
pub(crate) mod avatar;
pub(crate) mod delivery;
pub(crate) mod federation_links;

#[cfg(test)]
mod tests {
    #[test]
    fn profile_transports_keep_focused_dependencies() {
        let server_transports = [
            include_str!("profile/access_requests.rs"),
            include_str!("profile/avatar.rs"),
            include_str!("profile/delivery.rs"),
            include_str!("profile/federation_links.rs"),
        ]
        .join("\n");
        let account_transport = include_str!("../../../http-actix/src/profile_account.rs");

        for source in [&server_transports, account_transport] {
            for forbidden in [
                "Data<TestAppState>",
                "nazo_postgres::",
                "nazo_valkey::",
                "diesel::",
                "fred::",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "profile transport crossed a focused boundary: {forbidden}"
                );
            }
        }
        assert!(
            !server_transports.contains("tokio::fs"),
            "profile transport performs filesystem IO directly"
        );
    }
}
