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
