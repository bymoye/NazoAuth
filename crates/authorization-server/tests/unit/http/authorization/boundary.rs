#[test]
fn authorization_entrypoints_use_focused_dependencies() {
    for (name, source) in [
        (
            "request",
            include_str!("../../../../src/http/authorization/request.rs"),
        ),
        (
            "par",
            include_str!("../../../../src/http/authorization/par.rs"),
        ),
        (
            "jar",
            include_str!("../../../../src/http/authorization/jar.rs"),
        ),
        (
            "consent",
            include_str!("../../../../src/http/authorization/consent.rs"),
        ),
        (
            "decision",
            include_str!("../../../../../http-actix/src/authorization_decision.rs"),
        ),
        (
            "prompt_none",
            include_str!("../../../../src/http/authorization/request/prompt_none.rs"),
        ),
    ] {
        assert!(
            !source.contains("Data<TestInfrastructure>"),
            "{name} reintroduced the giant TestInfrastructure extractor"
        );
        assert!(
            !source.contains("AuthorizationHandles"),
            "{name} reintroduced the authorization forwarding facade"
        );
    }
    for (name, source) in [
        (
            "request",
            include_str!("../../../../src/http/authorization/request.rs"),
        ),
        (
            "par",
            include_str!("../../../../src/http/authorization/par.rs"),
        ),
        (
            "consent",
            include_str!("../../../../src/http/authorization/consent.rs"),
        ),
    ] {
        assert!(
            source.contains("Data<AuthorizationEndpoint>"),
            "{name} must extract only the focused authorization endpoint"
        );
        for dependency in [
            "Data<ServerAuthorizationService>",
            "Data<AuthorizationHttpConfig>",
            "Data<AdminSessionHandles>",
            "Data<ServerRuntimeModuleRegistry>",
        ] {
            assert!(
                !source.contains(dependency),
                "{name} directly extracts {dependency}"
            );
        }
    }
    let decision = include_str!("../../../../../http-actix/src/authorization_decision.rs");
    assert!(decision.contains("Data<AuthorizationDecisionEndpoint>"));
    for (name, source) in [
        (
            "par",
            include_str!("../../../../src/http/authorization/par.rs"),
        ),
        (
            "jar",
            include_str!("../../../../src/http/authorization/jar.rs"),
        ),
    ] {
        assert!(
            !source.contains("TestInfrastructure")
                && !source.contains("TestAuthorizationDependencies"),
            "{name} reintroduced the monolithic authorization test fixture"
        );
    }
}
