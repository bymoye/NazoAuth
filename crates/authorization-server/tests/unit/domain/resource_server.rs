use std::sync::Arc;

use super::production::same_key_generation;

#[test]
fn verifier_cache_hits_only_the_same_live_snapshot_generation() {
    let original_manager = crate::test_support::test_key_manager();
    let original = original_manager.snapshot();
    let same_generation = original_manager.snapshot();
    assert!(same_key_generation(&original, &same_generation));

    // Test managers intentionally reuse the same public kid. Distinct
    // key material must still be treated as a rotation and miss.
    let rotated = crate::test_support::test_key_manager().snapshot();
    assert_eq!(original.active_kid, rotated.active_kid);
    assert!(!Arc::ptr_eq(&original, &rotated));
    assert_ne!(original.jwks(), rotated.jwks());
    assert!(!same_key_generation(&original, &rotated));
}
