//! mTLS client certificate binding helpers.
//!
//! The application only trusts certificate data from configured trusted proxy
//! peers. Deployments can use the standardized RFC 9440 `Client-Cert` field or
//! the compatibility header contract that includes
//! `X-SSL-Client-Verify: SUCCESS`.

use crate::adapters::security::constant_time_eq;
use crate::domain::ClientRow;

use actix_web::{HttpRequest, web::Data};

use actix_web::http::header::HeaderMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use nazo_auth::normalize_sha256_thumbprint;
use nazo_http_actix::IpCidr;
use nazo_http_actix::request_from_trusted_proxy_cidrs;
use serde_json::Value;

use sha2::Digest;
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use x509_parser::{
    certificate::X509Certificate,
    extensions::GeneralName,
    objects::{oid_registry, oid2sn},
    oid_registry::{
        OID_PKCS9_EMAIL_ADDRESS, OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME,
        OID_X509_LOCALITY_NAME, OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT,
        OID_X509_STATE_OR_PROVINCE_NAME,
    },
    parse_x509_certificate,
    x509::X509Name,
};

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
const RFC9440_CLIENT_CERT_HEADER: &str = "client-cert";

pub(crate) use nazo_http_actix::ClientCertificateFacts as MtlsClientCertificate;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MtlsCertificateSourceMode {
    Disabled,
    DirectTls,
    Rfc9440,
    LegacyVerifiedHeaders,
}

impl MtlsCertificateSourceMode {
    pub(crate) fn from_config(value: Option<&str>, proxy_configured: bool) -> anyhow::Result<Self> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None if proxy_configured => Ok(Self::LegacyVerifiedHeaders),
            None => Ok(Self::Disabled),
            Some("disabled") => Ok(Self::Disabled),
            Some("direct-tls") => Ok(Self::DirectTls),
            Some("rfc9440") => Ok(Self::Rfc9440),
            Some("legacy-verified-headers") => Ok(Self::LegacyVerifiedHeaders),
            Some(value) => anyhow::bail!(
                "MTLS_CERTIFICATE_SOURCE must be disabled, direct-tls, rfc9440, or legacy-verified-headers; got {value}"
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MtlsCertificateSource {
    mode: MtlsCertificateSourceMode,
}

impl MtlsCertificateSource {
    pub(crate) fn new(mode: MtlsCertificateSourceMode) -> Self {
        Self { mode }
    }
}

pub(crate) fn request_mtls_thumbprint_from_trusted_proxy(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<String> {
    request_mtls_client_certificate_from_configured_source(req, trusted_proxy_cidrs)?.thumbprint
}

pub(crate) fn request_mtls_client_certificate_from_trusted_proxy(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<MtlsClientCertificate> {
    request_mtls_client_certificate_from_configured_source(req, trusted_proxy_cidrs)
}

fn request_mtls_client_certificate_from_configured_source(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<MtlsClientCertificate> {
    let mode = req
        .app_data::<Data<MtlsCertificateSource>>()
        .map(|source| source.mode)
        // Focused unit tests without production app data retain the historical
        // compatibility contract.
        .unwrap_or(MtlsCertificateSourceMode::LegacyVerifiedHeaders);
    match mode {
        MtlsCertificateSourceMode::Disabled => None,
        MtlsCertificateSourceMode::DirectTls => req.conn_data::<MtlsClientCertificate>().cloned(),
        MtlsCertificateSourceMode::Rfc9440
            if request_from_trusted_proxy_cidrs(req, trusted_proxy_cidrs) =>
        {
            request_mtls_client_certificate_from_rfc9440(req.headers())
        }
        MtlsCertificateSourceMode::LegacyVerifiedHeaders
            if request_from_trusted_proxy_cidrs(req, trusted_proxy_cidrs) =>
        {
            request_mtls_client_certificate_from_headers(req.headers())
        }
        MtlsCertificateSourceMode::Rfc9440 | MtlsCertificateSourceMode::LegacyVerifiedHeaders => {
            None
        }
    }
}

pub(crate) fn request_mtls_client_certificate_from_rfc9440(
    headers: &HeaderMap,
) -> Option<MtlsClientCertificate> {
    let mut values = headers.get_all(RFC9440_CLIENT_CERT_HEADER);
    let value = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() || value.len() < 3 {
        return None;
    }
    let encoded = value.strip_prefix(':')?.strip_suffix(':')?;
    if encoded.is_empty() || encoded.chars().any(char::is_whitespace) {
        return None;
    }
    let der = STANDARD.decode(encoded).ok()?;
    certificate_der_identity(&der)
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
    certificate_der_identity(&der)
}

pub(crate) fn certificate_der_identity(der: &[u8]) -> Option<MtlsClientCertificate> {
    let x509 = parse_current_x509(der)?;
    let mut certificate = MtlsClientCertificate {
        thumbprint: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(der))),
        subject_dn: Some(subject_name_to_dn(x509.subject())?),
        verified_certificate_expiry: true,
        ..MtlsClientCertificate::default()
    };
    if let Some(names) = x509.subject_alternative_name().ok().flatten() {
        for name in &names.value.general_names {
            match name {
                GeneralName::DNSName(value) => certificate.san_dns.push((*value).to_owned()),
                GeneralName::URI(value) => certificate.san_uri.push((*value).to_owned()),
                GeneralName::RFC822Name(value) => certificate.san_email.push((*value).to_owned()),
                GeneralName::IPAddress(value) => {
                    if let Some(value) = ipaddress_to_string(value) {
                        certificate.san_ip.push(value);
                    }
                }
                _ => {}
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
    parse_current_x509(&der)?;
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
    let selector_count = usize::from(client.tls_client_auth_subject_dn.is_some())
        + client.tls_client_auth_san_dns.len()
        + client.tls_client_auth_san_uri.len()
        + client.tls_client_auth_san_ip.len()
        + client.tls_client_auth_san_email.len();
    if selector_count != 1 {
        // RFC 8705 requires one and only one PKI subject selector. Fail closed
        // for rows missing configured identity constraints instead of widening the match.
        return false;
    }
    let standard_subject_matches = if let (Some(registered), Some(actual)) = (
        client.tls_client_auth_subject_dn.as_deref(),
        certificate.subject_dn.as_deref(),
    ) {
        nazo_key_management::rfc4514_dn_matches(registered, actual)
    } else if !client.tls_client_auth_san_dns.is_empty() {
        registered_dns_values_match(&client.tls_client_auth_san_dns, &certificate.san_dns)
    } else if !client.tls_client_auth_san_uri.is_empty() {
        registered_values_match(&client.tls_client_auth_san_uri, &certificate.san_uri)
    } else if !client.tls_client_auth_san_ip.is_empty() {
        registered_ip_values_match(&client.tls_client_auth_san_ip, &certificate.san_ip)
    } else if !client.tls_client_auth_san_email.is_empty() {
        registered_email_values_match(&client.tls_client_auth_san_email, &certificate.san_email)
    } else {
        false
    };
    if !standard_subject_matches {
        return false;
    }
    // The SHA-256 field is an administrator-only extra pin, not RFC 8705
    // registration metadata. When present it narrows the standard subject
    // match and never acts as an alternative identity selector.
    match (
        client.tls_client_auth_cert_sha256.as_deref(),
        certificate.thumbprint.as_deref(),
    ) {
        (None, _) => true,
        (Some(_), Some(thumbprint)) => client_mtls_thumbprint_matches(client, thumbprint),
        (Some(_), None) => false,
    }
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

fn x509_is_current(x509: &X509Certificate<'_>) -> Option<()> {
    x509.validity().is_valid().then_some(())
}

fn parse_current_x509(der: &[u8]) -> Option<X509Certificate<'_>> {
    let (remaining, certificate) = parse_x509_certificate(der).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    x509_is_current(&certificate)?;
    Some(certificate)
}

fn subject_name_to_dn(name: &X509Name<'_>) -> Option<String> {
    let mut parts = Vec::new();
    for entry in name.iter_attributes() {
        let oid = entry.attr_type();
        let short_name = if oid == &OID_X509_COMMON_NAME {
            "CN"
        } else if oid == &OID_X509_COUNTRY_NAME {
            "C"
        } else if oid == &OID_X509_STATE_OR_PROVINCE_NAME {
            "ST"
        } else if oid == &OID_X509_LOCALITY_NAME {
            "L"
        } else if oid == &OID_X509_ORGANIZATION_NAME {
            "O"
        } else if oid == &OID_X509_ORGANIZATIONAL_UNIT {
            "OU"
        } else if oid == &OID_PKCS9_EMAIL_ADDRESS {
            "emailAddress"
        } else {
            oid2sn(oid, oid_registry()).ok()?
        };
        let value = entry.as_str().ok()?;
        parts.push(format!("{short_name}={}", escape_dn_value(value)));
    }
    (!parts.is_empty()).then(|| parts.join(","))
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

fn registered_dns_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        actual
            .iter()
            .any(|actual| registered.eq_ignore_ascii_case(actual))
    })
}

fn registered_ip_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        let Ok(registered) = registered.parse::<IpAddr>() else {
            return false;
        };
        actual
            .iter()
            .filter_map(|actual| actual.parse::<IpAddr>().ok())
            .any(|actual| actual == registered)
    })
}

fn registered_email_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        let Some((registered_local, registered_domain)) = registered.rsplit_once('@') else {
            return false;
        };
        actual.iter().any(|actual| {
            let Some((actual_local, actual_domain)) = actual.rsplit_once('@') else {
                return false;
            };
            constant_time_eq(registered_local.as_bytes(), actual_local.as_bytes())
                && registered_domain.eq_ignore_ascii_case(actual_domain)
        })
    })
}

#[cfg(test)]
#[path = "../../tests/unit/http/mtls.rs"]
mod tests;
