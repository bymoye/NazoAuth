use actix_web::body::to_bytes;

use super::*;

#[actix_web::test]
async fn unauthenticated_challenge_hides_root_presence() {
    let missing = challenge_error_response(crate::recovery_root::RecoveryRootServiceError::Root(
        nazo_postgres::RecoveryRootError::RootMissing,
    ));
    let invalid = challenge_error_response(crate::recovery_root::RecoveryRootServiceError::Root(
        nazo_postgres::RecoveryRootError::InvalidAllocationProof,
    ));
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        to_bytes(missing.into_body()).await.unwrap(),
        to_bytes(invalid.into_body()).await.unwrap()
    );
}
