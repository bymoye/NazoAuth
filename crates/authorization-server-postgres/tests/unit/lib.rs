use super::*;

#[test]
fn provider_constructs_a_runtime_module_store_for_the_requested_tenant() {
    let pool =
        nazo_postgres::create_pool("not a postgres url", 1).expect("a lazy test pool should build");
    let provider = PostgresProvider::new(pool);

    let store = provider.runtime_modules(uuid::Uuid::now_v7());

    assert_eq!(Arc::strong_count(&store), 1);
}
