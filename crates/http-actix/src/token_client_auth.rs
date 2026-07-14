use actix_web::{HttpRequest, http::header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_auth::{PresentedClientCredentials, TokenClientAuthPresentation};

#[derive(Clone, Eq, PartialEq)]
enum BasicAuthorizationCredentials {
    Absent,
    Malformed,
    Present {
        client_id: String,
        client_secret: String,
    },
}

impl BasicAuthorizationCredentials {
    #[must_use]
    pub const fn scheme_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokenClientAuthForm<'a> {
    pub client_id: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

/// Verified client-certificate identity extracted by the deployment-specific HTTP adapter.
///
/// The token-management core receives these facts after the adapter has established that the
/// forwarding peer is trusted. Keeping the value framework-neutral prevents `HttpRequest` and
/// `HeaderMap` from crossing into authentication policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientCertificateFacts {
    pub thumbprint: Option<String>,
    pub subject_dn: Option<String>,
    pub san_dns: Vec<String>,
    pub san_uri: Vec<String>,
    pub san_ip: Vec<String>,
    pub san_email: Vec<String>,
    pub verified_certificate_expiry: bool,
}

#[derive(Clone)]
pub struct TokenClientAuthTransportFacts {
    basic: BasicAuthorizationCredentials,
    form_client_id: Option<String>,
    form_client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

impl std::fmt::Debug for TokenClientAuthTransportFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let basic_credentials = match &self.basic {
            BasicAuthorizationCredentials::Absent => "absent",
            BasicAuthorizationCredentials::Malformed => "malformed",
            BasicAuthorizationCredentials::Present { .. } => "[REDACTED]",
        };
        formatter
            .debug_struct("TokenClientAuthTransportFacts")
            .field("basic_scheme_present", &self.basic.scheme_present())
            .field("basic_credentials", &basic_credentials)
            .field("form_client_id", &self.form_client_id)
            .field(
                "form_client_secret",
                &self.form_client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_assertion_type", &self.client_assertion_type)
            .field(
                "client_assertion",
                &self.client_assertion.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl TokenClientAuthTransportFacts {
    #[must_use]
    pub fn presentation(&self) -> TokenClientAuthPresentation {
        TokenClientAuthPresentation {
            http_basic: self.basic.scheme_present(),
            form_client_id: self.form_client_id.is_some(),
            form_client_secret: self.form_client_secret.is_some(),
            client_assertion_type: self.client_assertion_type.is_some(),
            client_assertion: self.client_assertion.is_some(),
        }
    }

    #[must_use]
    pub fn basic_challenge(&self) -> bool {
        self.basic.scheme_present()
    }

    #[must_use]
    pub fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
    }

    #[must_use]
    pub fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }

    /// Applies the fixed credential-source precedence after the caller has resolved lookup-only
    /// hints. Registered client policy still decides whether the selected method is permitted.
    #[must_use]
    pub fn presented_credentials(
        &self,
        assertion_client_id: Option<String>,
        mtls_client_id: Option<String>,
    ) -> PresentedClientCredentials {
        if matches!(self.basic, BasicAuthorizationCredentials::Malformed) {
            return PresentedClientCredentials {
                method: "client_secret_basic".to_owned(),
                ..PresentedClientCredentials::default()
            };
        }
        if self.client_assertion_type.is_some() || self.client_assertion.is_some() {
            return PresentedClientCredentials {
                client_id: assertion_client_id,
                client_secret: None,
                client_assertion: self.client_assertion.clone(),
                method: "private_key_jwt".to_owned(),
            };
        }
        if let BasicAuthorizationCredentials::Present {
            client_id,
            client_secret,
        } = &self.basic
        {
            return PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: Some(client_secret.clone()),
                client_assertion: None,
                method: "client_secret_basic".to_owned(),
            };
        }
        match self.form_client_id.as_ref() {
            Some(client_id) if self.form_client_secret.is_some() => PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: self.form_client_secret.clone(),
                client_assertion: None,
                method: "client_secret_post".to_owned(),
            },
            Some(client_id) if mtls_client_id.as_deref() == Some(client_id) => {
                PresentedClientCredentials {
                    client_id: Some(client_id.clone()),
                    client_secret: None,
                    client_assertion: None,
                    method: "tls_client_auth".to_owned(),
                }
            }
            Some(client_id) => PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: None,
                client_assertion: None,
                method: "none".to_owned(),
            },
            None if mtls_client_id.is_some() => PresentedClientCredentials {
                client_id: mtls_client_id,
                client_secret: None,
                client_assertion: None,
                method: "tls_client_auth".to_owned(),
            },
            None => PresentedClientCredentials::default(),
        }
    }
}

#[must_use]
pub fn token_client_auth_transport_facts(
    request: &HttpRequest,
    form: TokenClientAuthForm<'_>,
) -> TokenClientAuthTransportFacts {
    TokenClientAuthTransportFacts {
        basic: basic_authorization_credentials(request),
        form_client_id: form.client_id.map(str::to_owned),
        form_client_secret: form.client_secret.map(str::to_owned),
        client_assertion_type: form.client_assertion_type.map(str::to_owned),
        client_assertion: form.client_assertion.map(str::to_owned),
    }
}

fn basic_authorization_credentials(request: &HttpRequest) -> BasicAuthorizationCredentials {
    let Some(raw) = request.headers().get(header::AUTHORIZATION) else {
        return BasicAuthorizationCredentials::Absent;
    };
    let bytes = raw.as_bytes();
    let start = bytes
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(bytes.len());
    if !bytes[start..end].eq_ignore_ascii_case(b"Basic") {
        return BasicAuthorizationCredentials::Absent;
    }
    let Some(encoded) = raw.to_str().ok().and_then(|value| {
        let mut parts = value.trim_start().splitn(2, char::is_whitespace);
        parts.next()?;
        let credentials = parts.next()?.trim();
        (!credentials.is_empty() && credentials.split_whitespace().count() == 1)
            .then_some(credentials)
    }) else {
        return BasicAuthorizationCredentials::Malformed;
    };
    let Some((client_id, client_secret)) = STANDARD.decode(encoded).ok().and_then(|decoded| {
        let separator = decoded.iter().position(|byte| *byte == b':')?;
        let client_id = form_urlencoded_component(&decoded[..separator])?;
        let client_secret = form_urlencoded_component(&decoded[separator + 1..])?;
        Some((client_id, client_secret))
    }) else {
        return BasicAuthorizationCredentials::Malformed;
    };
    BasicAuthorizationCredentials::Present {
        client_id,
        client_secret,
    }
}

fn form_urlencoded_component(input: &[u8]) -> Option<String> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        match input[cursor] {
            b'+' => {
                decoded.push(b' ');
                cursor += 1;
            }
            b'%' => {
                let high = input.get(cursor + 1).and_then(|byte| hex_value(*byte))?;
                let low = input.get(cursor + 2).and_then(|byte| hex_value(*byte))?;
                decoded.push((high << 4) | low);
                cursor += 3;
            }
            byte => {
                decoded.push(byte);
                cursor += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
