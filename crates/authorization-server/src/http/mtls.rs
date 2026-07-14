//! mTLS client certificate binding helpers.
//!
//! The application only trusts certificate data from configured trusted proxy
//! peers after the proxy has verified the client certificate and forwarded
//! `X-SSL-Client-Verify: SUCCESS`.

use super::client_ip::IpCidr;
#[cfg(test)]
use super::client_ip::request_from_trusted_proxy;
use super::client_ip::request_from_trusted_proxy_cidrs;
use crate::adapters::security::constant_time_eq;
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
#[cfg(test)]
use crate::settings::Settings;
use actix_web::HttpRequest;
#[cfg(test)]
use actix_web::http::header;
use actix_web::http::header::HeaderMap;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_auth::normalize_sha256_thumbprint;
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::x509::{X509, X509NameRef};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(test)]
use uuid::Uuid;

const VERIFY_HEADER: &str = "x-ssl-client-verify";
const DIRECT_THUMBPRINT_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-sha256",
    "x-ssl-client-cert-sha256",
    "x-ssl-client-fingerprint-sha256",
];
const CERTIFICATE_HEADERS: &[&str] = &["x-ssl-client-cert", "x-forwarded-tls-client-cert"];
const SUBJECT_DN_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-subject-dn",
    "x-ssl-client-subject-dn",
    "ssl-client-subject-dn",
];
const SAN_DNS_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-san-dns",
    "x-ssl-client-san-dns",
];
const SAN_URI_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-san-uri",
    "x-ssl-client-san-uri",
];
const SAN_IP_HEADERS: &[&str] = &["x-forwarded-tls-client-cert-san-ip", "x-ssl-client-san-ip"];
const SAN_EMAIL_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-san-email",
    "x-ssl-client-san-email",
];

pub(crate) use nazo_http_actix::ClientCertificateFacts as MtlsClientCertificate;

#[cfg(test)]
pub(crate) fn request_mtls_thumbprint(req: &HttpRequest, settings: &Settings) -> Option<String> {
    request_mtls_client_certificate(req, settings)?.thumbprint
}

#[cfg(test)]
pub(crate) fn request_mtls_client_certificate(
    req: &HttpRequest,
    settings: &Settings,
) -> Option<MtlsClientCertificate> {
    if !request_from_trusted_proxy(req, settings) {
        return None;
    }
    request_mtls_client_certificate_from_headers(req.headers())
}

pub(crate) fn request_mtls_thumbprint_from_trusted_proxy(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<String> {
    if !request_from_trusted_proxy_cidrs(req, trusted_proxy_cidrs) {
        return None;
    }
    request_mtls_client_certificate_from_headers(req.headers())?.thumbprint
}

pub(crate) fn request_mtls_client_certificate_from_trusted_proxy(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<MtlsClientCertificate> {
    if !request_from_trusted_proxy_cidrs(req, trusted_proxy_cidrs) {
        return None;
    }
    request_mtls_client_certificate_from_headers(req.headers())
}

pub(crate) fn request_mtls_client_certificate_from_headers(
    headers: &HeaderMap,
) -> Option<MtlsClientCertificate> {
    if !headers
        .get(VERIFY_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("SUCCESS"))
    {
        return None;
    }

    let mut certificate = MtlsClientCertificate {
        thumbprint: matching_forwarded_value(
            forwarded_values(headers, DIRECT_THUMBPRINT_HEADERS)
                .into_iter()
                .map(|value| normalize_sha256_thumbprint(&value))
                .collect::<Option<Vec<_>>>()?,
        )?,
        subject_dn: matching_forwarded_value(forwarded_values(headers, SUBJECT_DN_HEADERS))?,
        san_dns: matching_forwarded_list_values(headers, SAN_DNS_HEADERS)?,
        san_uri: matching_forwarded_list_values(headers, SAN_URI_HEADERS)?,
        san_ip: matching_forwarded_list_values(headers, SAN_IP_HEADERS)?,
        san_email: matching_forwarded_list_values(headers, SAN_EMAIL_HEADERS)?,
        verified_certificate_expiry: false,
    };

    for pem in forwarded_values(headers, CERTIFICATE_HEADERS) {
        let parsed = certificate_pem_identity(&pem)?;
        merge_matching(&mut certificate.thumbprint, parsed.thumbprint)?;
        merge_matching(&mut certificate.subject_dn, parsed.subject_dn)?;
        merge_matching_values(&mut certificate.san_dns, parsed.san_dns)?;
        merge_matching_values(&mut certificate.san_uri, parsed.san_uri)?;
        merge_matching_values(&mut certificate.san_ip, parsed.san_ip)?;
        merge_matching_values(&mut certificate.san_email, parsed.san_email)?;
        certificate.verified_certificate_expiry |= parsed.verified_certificate_expiry;
    }

    certificate_has_binding_material(&certificate).then_some(certificate)
}

pub(crate) fn certificate_pem_identity(value: &str) -> Option<MtlsClientCertificate> {
    let decoded = decode_forwarded_pem(value);
    let start = decoded.find("-----BEGIN CERTIFICATE-----")?;
    let end = decoded.find("-----END CERTIFICATE-----")?;
    if end <= start {
        return None;
    }
    let body_start = start + "-----BEGIN CERTIFICATE-----".len();
    let body = decoded[body_start..end]
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    let der = STANDARD.decode(body).ok()?;
    let x509 = X509::from_der(&der).ok()?;
    x509_is_current(&x509)?;
    let mut certificate = MtlsClientCertificate {
        thumbprint: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(&der))),
        subject_dn: Some(subject_name_to_dn(x509.subject_name())?),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };
    if let Some(names) = x509.subject_alt_names() {
        for name in names {
            if let Some(value) = name.dnsname() {
                certificate.san_dns.push(value.to_owned());
            }
            if let Some(value) = name.uri() {
                certificate.san_uri.push(value.to_owned());
            }
            if let Some(value) = name.email() {
                certificate.san_email.push(value.to_owned());
            }
            if let Some(value) = name.ipaddress().and_then(ipaddress_to_string) {
                certificate.san_ip.push(value);
            }
        }
    }
    certificate.san_dns = sorted_unique(certificate.san_dns);
    certificate.san_uri = sorted_unique(certificate.san_uri);
    certificate.san_ip = sorted_unique(certificate.san_ip);
    certificate.san_email = sorted_unique(certificate.san_email);
    Some(certificate)
}

pub(crate) fn certificate_x5c_thumbprint(value: &str) -> Option<String> {
    let der = STANDARD
        .decode(
            value
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace())
                .collect::<String>(),
        )
        .ok()?;
    let x509 = X509::from_der(&der).ok()?;
    x509_is_current(&x509)?;
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(&der)))
}

pub(crate) fn client_mtls_thumbprint_matches(client: &ClientRow, thumbprint: &str) -> bool {
    client
        .tls_client_auth_cert_sha256
        .as_deref()
        .and_then(normalize_sha256_thumbprint)
        .is_some_and(|registered| constant_time_eq(registered.as_bytes(), thumbprint.as_bytes()))
}

pub(crate) fn client_mtls_certificate_matches(
    client: &ClientRow,
    certificate: &MtlsClientCertificate,
) -> bool {
    if client.token_endpoint_auth_method == "self_signed_tls_client_auth" {
        return client_self_signed_mtls_certificate_matches(client, certificate);
    }
    if certificate
        .thumbprint
        .as_deref()
        .is_some_and(|thumbprint| client_mtls_thumbprint_matches(client, thumbprint))
    {
        return true;
    }
    if let (Some(registered), Some(actual)) = (
        client.tls_client_auth_subject_dn.as_deref(),
        certificate.subject_dn.as_deref(),
    ) && constant_time_eq(registered.trim().as_bytes(), actual.trim().as_bytes())
    {
        return true;
    }
    registered_values_match(&client.tls_client_auth_san_dns, &certificate.san_dns)
        || registered_values_match(&client.tls_client_auth_san_uri, &certificate.san_uri)
        || registered_values_match(&client.tls_client_auth_san_ip, &certificate.san_ip)
        || registered_values_match(&client.tls_client_auth_san_email, &certificate.san_email)
}

pub(crate) fn client_self_signed_mtls_certificate_matches(
    client: &ClientRow,
    certificate: &MtlsClientCertificate,
) -> bool {
    let Some(thumbprint) = certificate.thumbprint.as_deref() else {
        return false;
    };
    if client
        .jwks
        .as_ref()
        .is_some_and(|jwks| jwks_contains_current_x5c_thumbprint(jwks, thumbprint))
    {
        return true;
    }
    false
}

pub(crate) fn jwks_contains_current_x5c_thumbprint(jwks: &Value, thumbprint: &str) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .filter_map(|key| key.get("x5c").and_then(Value::as_array))
                .filter_map(|x5c| x5c.as_slice().first().and_then(Value::as_str))
                .filter_map(certificate_x5c_thumbprint)
                .any(|registered| constant_time_eq(registered.as_bytes(), thumbprint.as_bytes()))
        })
}

fn certificate_has_binding_material(certificate: &MtlsClientCertificate) -> bool {
    certificate.thumbprint.is_some()
        || certificate.subject_dn.is_some()
        || !certificate.san_dns.is_empty()
        || !certificate.san_uri.is_empty()
        || !certificate.san_ip.is_empty()
        || !certificate.san_email.is_empty()
}

fn forwarded_values(headers: &HeaderMap, names: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for name in names {
        for value in headers.get_all(*name) {
            if let Ok(text) = value.to_str() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    values.push(trimmed.to_owned());
                }
            }
        }
    }
    values
}

fn matching_forwarded_list_values(headers: &HeaderMap, names: &[&str]) -> Option<Vec<String>> {
    let values = forwarded_values(headers, names)
        .into_iter()
        .map(|value| sorted_unique(split_forwarded_list_value(&value)))
        .collect::<Vec<_>>();
    let Some(first) = values.as_slice().first() else {
        return Some(Vec::new());
    };
    values
        .iter()
        .all(|value| string_slices_match(first, value))
        .then(|| first.clone())
}

fn split_forwarded_list_value(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn matching_forwarded_value(values: Vec<String>) -> Option<Option<String>> {
    let Some(first) = values.as_slice().first() else {
        return Some(None);
    };
    values
        .iter()
        .all(|value| constant_time_eq(first.as_bytes(), value.as_bytes()))
        .then_some(Some(first.clone()))
}

fn merge_matching(target: &mut Option<String>, incoming: Option<String>) -> Option<()> {
    match (target.as_ref(), incoming) {
        (_, None) => Some(()),
        (None, Some(value)) => {
            *target = Some(value);
            Some(())
        }
        (Some(current), Some(value)) if constant_time_eq(current.as_bytes(), value.as_bytes()) => {
            Some(())
        }
        _ => None,
    }
}

fn merge_matching_values(target: &mut Vec<String>, incoming: Vec<String>) -> Option<()> {
    if target.is_empty() {
        *target = incoming;
        return Some(());
    }
    string_slices_match(target, &incoming).then_some(())
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn string_slices_match(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| constant_time_eq(left.as_bytes(), right.as_bytes()))
}

#[cfg(test)]
fn merge_sorted_unique(target: &mut Vec<String>, incoming: Vec<String>) {
    target.extend(incoming);
    target.sort();
    target.dedup();
}

fn decode_forwarded_pem(value: &str) -> String {
    let decoded = if value.contains('%') {
        urlencoding::decode(value)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_else(|_| value.to_owned())
    } else {
        value.to_owned()
    };
    decoded.replace("\\n", "\n")
}

fn x509_is_current(x509: &X509) -> Option<()> {
    let now = Asn1Time::from_unix(Utc::now().timestamp()).ok()?;
    let not_before = x509.not_before().compare(&now).ok()?;
    let not_after = x509.not_after().compare(&now).ok()?;
    (not_before != Ordering::Greater && not_after != Ordering::Less).then_some(())
}

fn subject_name_to_dn(name: &X509NameRef) -> Option<String> {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let short_name = nid_short_name(entry.object().nid())?;
        let value = entry.data().to_string().ok()?;
        parts.push(format!("{short_name}={}", escape_dn_value(&value)));
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

fn nid_short_name(nid: Nid) -> Option<&'static str> {
    match nid {
        Nid::COMMONNAME => Some("CN"),
        Nid::COUNTRYNAME => Some("C"),
        Nid::STATEORPROVINCENAME => Some("ST"),
        Nid::LOCALITYNAME => Some("L"),
        Nid::ORGANIZATIONNAME => Some("O"),
        Nid::ORGANIZATIONALUNITNAME => Some("OU"),
        Nid::PKCS9_EMAILADDRESS => Some("emailAddress"),
        _ => nid.short_name().ok(),
    }
}

fn escape_dn_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => vec!['\\', ch],
            _ => vec![ch],
        })
        .collect()
}

fn ipaddress_to_string(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut segments = [0u8; 16];
            segments.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(segments)))
        }
        _ => None,
    }
    .map(|ip| ip.to_string())
}

fn registered_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        actual
            .iter()
            .any(|actual| constant_time_eq(registered.as_bytes(), actual.as_bytes()))
    })
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/mtls.rs"]
mod tests;
