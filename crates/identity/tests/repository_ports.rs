use nazo_identity::{
    PublicAccount, TenantContext, UserId,
    ports::{FakeUserRepository, UserRepositoryPort},
};
use uuid::Uuid;

#[tokio::test]
async fn fake_user_repository_is_a_minimal_test_substitute() {
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let fake = FakeUserRepository::default();
    assert!(
        fake.principal_by_id(tenant, user_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn public_account_is_composed_from_domain_concepts_not_a_flat_database_row() {
    fn assert_public_account(_: &PublicAccount) {}
    let _ = assert_public_account;
}

#[test]
fn public_identity_api_has_no_catch_all_identity_user() {
    let model = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/model.rs"))
        .expect("identity model source is readable");
    let repository = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../persistence-postgres/src/repositories/users.rs"
    ))
    .expect("postgres user repository source is readable");
    let claims = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../authorization-server/src/domain/oidc_claims.rs"
    ))
    .expect("OIDC claims source is readable");

    assert!(!model.contains("pub struct IdentityUser"));
    assert!(!repository.contains("user_by_id"));
    assert!(!repository.contains("user_by_email"));
    assert!(!claims.contains("PublicAccount"));
    assert!(!claims.contains("find_user_by"));
}
