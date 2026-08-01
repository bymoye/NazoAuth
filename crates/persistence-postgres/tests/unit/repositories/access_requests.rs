use super::search_pattern;

#[test]
fn search_pattern_trims_and_ignores_blank_queries() {
    assert_eq!(search_pattern(None), None);
    assert_eq!(search_pattern(Some("")), None);
    assert_eq!(search_pattern(Some("   \t")), None);
    assert_eq!(
        search_pattern(Some("  alice@example.com  ")).as_deref(),
        Some("%alice@example.com%")
    );
}
