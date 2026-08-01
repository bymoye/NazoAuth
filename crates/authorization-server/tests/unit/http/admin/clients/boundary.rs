#[test]
fn admin_client_handlers_use_focused_service() {
    for (name, source) in [
        (
            "create",
            include_str!("../../../../../src/http/admin/clients/create.rs"),
        ),
        (
            "list",
            include_str!("../../../../../src/http/admin/clients/list.rs"),
        ),
        (
            "detail",
            include_str!("../../../../../src/http/admin/clients/detail.rs"),
        ),
        (
            "update",
            include_str!("../../../../../src/http/admin/clients/update.rs"),
        ),
    ] {
        for forbidden in [
            "OAuthClientRepository",
            "nazo_postgres",
            "ClientRow",
            "KeyManager",
            "Data<TestInfrastructure>",
            "test_dependencies",
        ] {
            assert!(!source.contains(forbidden), "{name} contains {forbidden}");
        }
    }
}
