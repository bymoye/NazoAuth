use super::*;

#[test]
fn machine_management_never_exposes_loopback_http_on_a_non_loopback_bind() {
    let exposed: SocketAddr = "0.0.0.0:8000".parse().unwrap();
    let loopback: SocketAddr = "127.0.0.1:8000".parse().unwrap();

    assert!(validate_management_transport(TransportMode::LoopbackHttp, exposed).is_err());
    assert!(validate_management_transport(TransportMode::LoopbackHttp, loopback).is_ok());
    assert!(validate_management_transport(TransportMode::DirectTls, exposed).is_ok());
    assert!(validate_management_transport(TransportMode::TrustedProxy, exposed).is_ok());
}

#[test]
fn admin_client_failures_preserve_rejected_vs_unavailable_boundary() {
    for error in [
        AdminClientError::InvalidRequest("invalid".to_owned()),
        AdminClientError::NotFound,
    ] {
        assert!(matches!(
            map_admin_client_error(error),
            TenantResourcePreparationError::Rejected
        ));
    }
    for error in [
        AdminClientError::Repository(nazo_auth::AdminClientPortError::Unavailable),
        AdminClientError::Lookup(nazo_auth::AdminClientPortError::CorruptData),
        AdminClientError::Write(nazo_auth::AdminClientPortError::Conflict),
        AdminClientError::Consistency("drift".to_owned()),
    ] {
        assert!(matches!(
            map_admin_client_error(error),
            TenantResourcePreparationError::Unavailable
        ));
    }
}
