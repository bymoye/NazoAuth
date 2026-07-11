use super::*;
use actix_web::test::TestRequest;

use crate::config::ConfigSource;

fn settings(mode: ClientIpHeaderMode, trusted: &str) -> Settings {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.client_ip_header_mode = mode;
    settings.trusted_proxy_cidrs =
        parse_trusted_proxy_cidrs(Some(trusted.to_owned())).expect("trusted CIDRs should parse");
    settings
}

#[test]
fn cidr_matches_ipv4_and_ipv6() {
    let cidr = IpCidr::parse("192.0.2.0/24").unwrap();
    assert!(cidr.contains("192.0.2.10".parse().unwrap()));
    assert!(!cidr.contains("198.51.100.10".parse().unwrap()));

    let cidr = IpCidr::parse("2001:db8::/32").unwrap();
    assert!(cidr.contains("2001:db8::1".parse().unwrap()));
    assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
}

#[test]
fn client_ip_header_mode_accepts_only_explicit_modes() {
    assert_eq!(
        ClientIpHeaderMode::parse(" none ").unwrap(),
        ClientIpHeaderMode::None
    );
    assert_eq!(
        ClientIpHeaderMode::parse("FORWARDED").unwrap(),
        ClientIpHeaderMode::Forwarded
    );
    assert_eq!(
        ClientIpHeaderMode::parse("x-forwarded-for").unwrap(),
        ClientIpHeaderMode::XForwardedFor
    );
    assert!(ClientIpHeaderMode::parse("x-real-ip").is_err());
}

#[test]
fn trusted_proxy_cidrs_reject_malformed_and_out_of_range_values() {
    assert!(IpCidr::parse("192.0.2.0").is_err());
    assert!(IpCidr::parse("not-an-ip/24").is_err());
    assert!(IpCidr::parse("192.0.2.0/not-a-prefix").is_err());
    assert!(IpCidr::parse("192.0.2.0/33").is_err());
    assert!(IpCidr::parse("2001:db8::/129").is_err());

    let cidrs =
        parse_trusted_proxy_cidrs(Some(" 192.0.2.0/24, ,2001:db8::/32 ".to_owned())).unwrap();
    assert_eq!(cidrs.len(), 2);
}

#[test]
fn forwarded_header_parses_basic_rfc7239_values() {
    assert_eq!(
        parse_forwarded_for_value(r#""[2001:db8::1]:443""#),
        Some("2001:db8::1".parse().unwrap())
    );
    assert_eq!(
        parse_forwarded_for_value("203.0.113.7:1234"),
        Some("203.0.113.7".parse().unwrap())
    );
}

#[test]
fn client_ip_ignores_forwarded_headers_until_peer_is_trusted() {
    let settings = settings(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("198.51.100.10:49152".parse().unwrap())
        .insert_header(("forwarded", r#"for=203.0.113.7"#))
        .to_http_request();

    assert_eq!(client_ip(&request, &settings), "198.51.100.10");
    assert!(!request_from_trusted_proxy(&request, &settings));
}

#[test]
fn client_ip_uses_forwarded_header_only_from_trusted_proxy() {
    let settings = settings(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("forwarded", r#"by=192.0.2.10; for="[2001:db8::1]:443""#))
        .to_http_request();

    assert_eq!(client_ip(&request, &settings), "2001:db8::1");
    assert!(request_from_trusted_proxy(&request, &settings));
}

#[test]
fn client_ip_uses_nearest_untrusted_x_forwarded_for_hop() {
    let settings = settings(
        ClientIpHeaderMode::XForwardedFor,
        "192.0.2.0/24,2001:db8::/32",
    );
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("x-forwarded-for", "192.0.2.11, 203.0.113.8, 2001:db8::1"))
        .to_http_request();

    assert_eq!(client_ip(&request, &settings), "203.0.113.8");
}

#[test]
fn xff_discards_attacker_supplied_prefix_before_the_real_client() {
    let settings = settings(ClientIpHeaderMode::XForwardedFor, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("x-forwarded-for", "198.51.100.77, 203.0.113.8, 192.0.2.11"))
        .to_http_request();

    assert_eq!(client_ip(&request, &settings), "203.0.113.8");
}

#[test]
fn forwarded_discards_attacker_supplied_prefix_before_the_real_client() {
    let settings = settings(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header((
            "forwarded",
            "for=198.51.100.77, for=203.0.113.8;proto=https, for=192.0.2.11",
        ))
        .to_http_request();

    assert_eq!(client_ip(&request, &settings), "203.0.113.8");
}

#[test]
fn malformed_proxy_chains_fall_back_to_the_socket_peer() {
    let xff = settings(ClientIpHeaderMode::XForwardedFor, "192.0.2.0/24");
    let malformed_xff = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("x-forwarded-for", "203.0.113.8, not-an-ip, 192.0.2.11"))
        .to_http_request();
    assert_eq!(client_ip(&malformed_xff, &xff), "192.0.2.10");

    let forwarded = settings(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let obfuscated_forwarded = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("forwarded", "for=203.0.113.8, for=_hidden, for=192.0.2.11"))
        .to_http_request();
    assert_eq!(client_ip(&obfuscated_forwarded, &forwarded), "192.0.2.10");
}

#[test]
fn client_ip_falls_back_to_peer_when_forwarded_headers_are_unusable() {
    let forwarded = settings(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let malformed_forwarded = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("forwarded", "proto=https"))
        .to_http_request();
    assert_eq!(client_ip(&malformed_forwarded, &forwarded), "192.0.2.10");

    let xff = settings(ClientIpHeaderMode::XForwardedFor, "192.0.2.0/24");
    let only_trusted = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("x-forwarded-for", "not-an-ip, 192.0.2.11"))
        .to_http_request();
    assert_eq!(client_ip(&only_trusted, &xff), "192.0.2.10");

    let missing_peer = TestRequest::default().to_http_request();
    assert_eq!(client_ip(&missing_peer, &xff), "unknown");
    assert!(!request_from_trusted_proxy(&missing_peer, &xff));
}

#[test]
fn prefix_zero_cidrs_match_same_ip_family_only() {
    let ipv4 = IpCidr::parse("0.0.0.0/0").unwrap();
    assert!(ipv4.contains("203.0.113.8".parse().unwrap()));
    assert!(!ipv4.contains("2001:db8::1".parse().unwrap()));

    let ipv6 = IpCidr::parse("::/0").unwrap();
    assert!(ipv6.contains("2001:db8::1".parse().unwrap()));
    assert!(!ipv6.contains("203.0.113.8".parse().unwrap()));
}
