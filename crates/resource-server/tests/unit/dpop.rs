use super::*;
use jsonwebtoken::Algorithm;

#[test]
fn supported_dpop_algorithm_rejects_unsupported_algs() {
    assert!(supported_dpop_algorithm(Algorithm::HS256).is_none());
    assert!(supported_dpop_algorithm(Algorithm::ES384).is_none());
    assert!(supported_dpop_algorithm(Algorithm::RS384).is_none());
}
