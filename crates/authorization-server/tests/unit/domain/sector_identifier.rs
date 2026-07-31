use super::{
    MAX_RESPONSE_BYTES, SectorIdentifierError, append_response_chunk, fetch_sector_identifier_uris,
    is_blocked_host, is_blocked_ip, parse_sector_identifier_document,
};
use std::net::IpAddr;

#[test]
fn block_private_ipv4() {
    assert!(is_blocked_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("169.254.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_loopback_ipv4() {
    assert!(is_blocked_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("127.0.0.2".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_metadata_ip() {
    assert!(is_blocked_ip("169.254.169.254".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_unspecified() {
    assert!(is_blocked_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::".parse::<IpAddr>().unwrap()));
}

#[test]
fn allow_public_ipv4() {
    assert!(!is_blocked_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(!is_blocked_ip("93.184.216.34".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_non_global_ipv4_destinations() {
    for address in [
        "100.64.0.1",
        "100.127.255.254",
        "198.18.0.1",
        "198.19.255.254",
        "192.0.2.1",
        "255.255.255.255",
    ] {
        assert!(
            is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} must not be an outbound destination"
        );
    }
}

#[test]
fn allow_globally_reachable_special_purpose_ipv4_destinations() {
    for address in ["192.0.0.9", "192.0.0.10"] {
        assert!(
            !is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} is designated globally reachable"
        );
    }
}

#[test]
fn block_loopback_ipv6() {
    assert!(is_blocked_ip("::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_link_local_ipv6() {
    assert!(is_blocked_ip("fe80::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_unique_local_ipv6() {
    assert!(is_blocked_ip("fc00::1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("fd00::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_non_global_ipv6_destinations() {
    for address in ["100::1", "2001:db8::1"] {
        assert!(
            is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} must not be an outbound destination"
        );
    }
}

#[test]
fn allow_globally_reachable_special_purpose_ipv6_destinations() {
    for address in [
        "64:ff9b::808:808",
        "2001:1::1",
        "2001:1::2",
        "2001:1::3",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:30::1",
    ] {
        assert!(
            !is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} is designated globally reachable"
        );
    }
}

#[test]
fn response_limit_is_enforced_before_appending_an_oversized_chunk() {
    let mut body = vec![0; MAX_RESPONSE_BYTES as usize];

    let err = append_response_chunk(&mut body, &[1])
        .expect_err("a chunk beyond the response limit must be rejected");

    assert!(matches!(err, SectorIdentifierError::ResponseTooLarge));
    assert_eq!(body.len(), MAX_RESPONSE_BYTES as usize);
}

#[test]
fn response_chunks_are_appended_in_order_below_the_closed_limit() {
    let mut body = b"first".to_vec();

    append_response_chunk(&mut body, b"-second").unwrap();
    append_response_chunk(&mut body, b"-third").unwrap();

    assert_eq!(body, b"first-second-third");
}

#[test]
fn block_localhost_domain() {
    assert!(is_blocked_host("localhost"));
}

#[test]
fn block_127_domain() {
    assert!(is_blocked_host("127.0.0.1"));
}

#[test]
fn allow_public_domain() {
    assert!(!is_blocked_host("example.com"));
    assert!(!is_blocked_host("2001:4860:4860::8888"));
}

#[test]
fn block_ipv6_multicast_and_mapped_unspecified() {
    assert!(is_blocked_ip("ff02::1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::ffff:0.0.0.0".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_ipv6_mapped_unspecified_without_ipv4_text() {
    assert!(is_blocked_ip("::ffff:0:0".parse::<IpAddr>().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_uses_the_ipv4_network_policy() {
    assert!(is_blocked_ip("::ffff:127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::ffff:10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip(
        "::ffff:169.254.169.254".parse::<IpAddr>().unwrap()
    ));
    assert!(!is_blocked_ip(
        "::ffff:93.184.216.34".parse::<IpAddr>().unwrap()
    ));
}

#[test]
fn block_literal_private_hosts() {
    assert!(is_blocked_host("0.0.0.0"));
    assert!(is_blocked_host("::1"));
    assert!(is_blocked_host("::"));
}

#[actix_web::test]
async fn fetch_rejects_invalid_sector_identifier_uri_before_network() {
    let err = fetch_sector_identifier_uris("not-a-uri")
        .await
        .expect_err("invalid URI must fail before DNS or HTTP");

    assert!(matches!(err, SectorIdentifierError::InvalidUri));
}

#[actix_web::test]
async fn fetch_rejects_non_https_sector_identifier_uri() {
    let err = fetch_sector_identifier_uris("http://example.com/sector.json")
        .await
        .expect_err("sector_identifier_uri must be HTTPS");

    assert!(matches!(err, SectorIdentifierError::SchemeNotHttps));
}

#[actix_web::test]
async fn fetch_rejects_loopback_sector_identifier_uri_before_dns() {
    let err = fetch_sector_identifier_uris("https://127.0.0.1/sector.json")
        .await
        .expect_err("loopback sector_identifier_uri must be blocked before DNS");

    assert!(matches!(err, SectorIdentifierError::BlockedHost));
}

#[actix_web::test]
async fn fetch_reports_dns_resolution_failure_for_unresolvable_public_host() {
    let err = fetch_sector_identifier_uris("https://sector.invalid/sector.json")
        .await
        .expect_err("unresolvable public host must fail at DNS resolution");

    assert!(matches!(err, SectorIdentifierError::DnsResolutionFailed));
}

#[actix_web::test]
async fn fetch_pins_a_resolved_public_destination_and_fails_closed_on_transport_error() {
    let err = fetch_sector_identifier_uris("https://192.0.0.9:1/sector.json")
        .await
        .expect_err("a closed public endpoint must not produce a document");

    assert!(matches!(
        err,
        SectorIdentifierError::HttpError | SectorIdentifierError::Timeout
    ));
}

#[test]
fn parse_sector_identifier_document_accepts_json_content_type_with_parameters() {
    let uris = parse_sector_identifier_document(
        "application/json; charset=utf-8",
        br#"["https://client.example/callback","https://client.example/alt"]"#,
    )
    .expect("valid sector identifier document should parse");

    assert_eq!(
        uris,
        vec![
            "https://client.example/callback".to_owned(),
            "https://client.example/alt".to_owned()
        ]
    );
}

#[test]
fn parse_sector_identifier_document_rejects_non_json_content_type() {
    let err = parse_sector_identifier_document("text/plain", br#"[]"#)
        .expect_err("sector identifier document must be JSON");

    assert!(matches!(err, SectorIdentifierError::InvalidContentType));
}

#[test]
fn parse_sector_identifier_document_rejects_oversized_body_before_json_parse() {
    let body = vec![b' '; 128 * 1024 + 1];
    let err = parse_sector_identifier_document("application/json", &body)
        .expect_err("oversized sector identifier document must be rejected");

    assert!(matches!(err, SectorIdentifierError::ResponseTooLarge));
}

#[test]
fn parse_sector_identifier_document_rejects_invalid_json() {
    let err = parse_sector_identifier_document("application/json", br#"{"redirect_uris":[]}"#)
        .expect_err("sector identifier document must be a JSON array");

    assert!(matches!(err, SectorIdentifierError::InvalidJson));
}

#[test]
fn parse_sector_identifier_document_rejects_invalid_uri_entry() {
    let err = parse_sector_identifier_document("application/json", br#"["not a uri"]"#)
        .expect_err("sector identifier entries must be absolute URIs");

    assert!(matches!(err, SectorIdentifierError::InvalidEntry(entry) if entry == "not a uri"));
}
