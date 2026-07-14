use std::{future::Future, pin::Pin};

use serde::Deserialize;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::{CreateClientRequest, OAuthClient, PreparedClientRegistration, parse_scope};

pub type DynamicRegistrationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DynamicRegistrationDependencyError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationDependencyError {
    Unavailable,
}

/// Persistence boundary for RFC 7591 registration and RFC 7592 client management.
pub trait DynamicRegistrationClientStore: Send + Sync {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>>;

    fn has_client_secret(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool>;

    fn client_secret_salt(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, Option<String>>;

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool>;

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn deactivate(&self, tenant_id: Uuid, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool>;
}

/// Secret-material operations kept outside protocol and transport code.
pub trait DynamicRegistrationSecretPort: Send + Sync {
    fn random_token(&self) -> String;
    fn token_hash(&self, token: &str) -> String;
    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool;
}

pub trait ClientSecretDigesterPort: Send + Sync {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String;
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub tls_client_auth_cert_sha256: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_dns: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_uri: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_ip: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_email: Vec<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<Value>,
    #[serde(default)]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub authorization_signed_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub request_uris: Vec<String>,
    #[serde(default)]
    pub software_statement: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct DynamicRegistrationPolicy<'a> {
    pub default_audience: &'a str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedDynamicClientRegistration {
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub require_dpop_bound_tokens: bool,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_cert_sha256: Option<String>,
    pub tls_client_auth_san_dns: Vec<String>,
    pub tls_client_auth_san_uri: Vec<String>,
    pub tls_client_auth_san_ip: Vec<String>,
    pub tls_client_auth_san_email: Vec<String>,
    pub jwks: Option<Value>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub authorization_signed_response_alg: Option<String>,
    pub authorization_encrypted_response_alg: Option<String>,
    pub authorization_encrypted_response_enc: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicRegistrationError {
    pub error: &'static str,
    pub description: String,
}

impl DynamicRegistrationError {
    #[must_use]
    pub fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    #[must_use]
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new("invalid_client_metadata", description)
    }
}

pub fn prepare_dynamic_client_registration(
    request: DynamicClientRegistrationRequest,
    policy: DynamicRegistrationPolicy<'_>,
) -> Result<PreparedDynamicClientRegistration, DynamicRegistrationError> {
    if request.software_statement.is_some() {
        return Err(DynamicRegistrationError::new(
            "invalid_software_statement",
            "software_statement is not supported by this registration endpoint.",
        ));
    }
    if request.jwks_uri.is_some() && request.jwks.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri and jwks must not both be present.",
        ));
    }
    if request.jwks_uri.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri is not supported; register jwks by value.",
        ));
    }
    validate_request_uris(&request.request_uris)?;
    if request
        .application_type
        .as_deref()
        .is_some_and(|value| !matches!(value, "web" | "native"))
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "application_type must be web or native.",
        ));
    }

    let grant_types = request
        .grant_types
        .unwrap_or_else(default_dynamic_client_grant_types);
    let response_types = match request.response_types {
        Some(values) if values.is_empty() => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "response_types must not be empty.",
            ));
        }
        Some(values) => values,
        None if grant_types
            .iter()
            .any(|grant| grant == "authorization_code") =>
        {
            vec!["code".to_owned()]
        }
        None => Vec::new(),
    };
    validate_response_type_relationship(&grant_types, &response_types)?;

    let token_endpoint_auth_method = request
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_owned());
    let client_type = if token_endpoint_auth_method == "none" {
        "public".to_owned()
    } else {
        "confidential".to_owned()
    };
    let scopes = request
        .scope
        .as_deref()
        .map(parse_scope)
        .unwrap_or_else(|| default_dynamic_client_scopes(&grant_types));
    let client_name = request
        .client_name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Dynamic OAuth Client".to_owned());

    Ok(PreparedDynamicClientRegistration {
        client_name,
        client_type,
        redirect_uris: request.redirect_uris.unwrap_or_default(),
        post_logout_redirect_uris: request.post_logout_redirect_uris,
        scopes,
        allowed_audiences: vec![policy.default_audience.to_owned()],
        grant_types,
        response_types,
        token_endpoint_auth_method,
        subject_type: request.subject_type,
        sector_identifier_uri: request.sector_identifier_uri,
        require_dpop_bound_tokens: request.dpop_bound_access_tokens,
        backchannel_logout_uri: request.backchannel_logout_uri,
        backchannel_logout_session_required: request
            .backchannel_logout_session_required
            .unwrap_or(true),
        frontchannel_logout_uri: request.frontchannel_logout_uri,
        frontchannel_logout_session_required: request
            .frontchannel_logout_session_required
            .unwrap_or(true),
        tls_client_auth_subject_dn: request.tls_client_auth_subject_dn,
        tls_client_auth_cert_sha256: request.tls_client_auth_cert_sha256,
        tls_client_auth_san_dns: request.tls_client_auth_san_dns,
        tls_client_auth_san_uri: request.tls_client_auth_san_uri,
        tls_client_auth_san_ip: request.tls_client_auth_san_ip,
        tls_client_auth_san_email: request.tls_client_auth_san_email,
        jwks: request.jwks,
        userinfo_signed_response_alg: request.userinfo_signed_response_alg,
        userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc,
        authorization_signed_response_alg: request.authorization_signed_response_alg,
        authorization_encrypted_response_alg: request.authorization_encrypted_response_alg,
        authorization_encrypted_response_enc: request.authorization_encrypted_response_enc,
    })
}

pub fn parse_client_configuration_update(
    mut payload: Value,
    current: &OAuthClient,
    current_has_secret: bool,
    submitted_secret_matches: bool,
) -> Result<DynamicClientRegistrationRequest, DynamicRegistrationError> {
    let Some(object) = payload.as_object_mut() else {
        return Err(DynamicRegistrationError::new(
            "invalid_request",
            "Client configuration update body must be a JSON object.",
        ));
    };
    for field in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        if object.contains_key(field) {
            return Err(DynamicRegistrationError::new(
                "invalid_request",
                format!("{field} is managed by the authorization server."),
            ));
        }
    }
    let client_id = object
        .remove("client_id")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            DynamicRegistrationError::invalid_client_metadata(
                "client_id must be present in a client configuration update.",
            )
        })?;
    if client_id != current.client_id {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "client_id must match the client configuration endpoint.",
        ));
    }
    let client_secret = object.remove("client_secret");
    match (current_has_secret, client_secret) {
        (true, Some(Value::String(_))) if submitted_secret_matches => {}
        (true, _) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "client_secret must match the current client secret.",
            ));
        }
        (false, Some(_)) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "public or assertion-based clients must not submit client_secret.",
            ));
        }
        (false, None) => {}
    }
    serde_json::from_value(payload).map_err(|error| {
        DynamicRegistrationError::invalid_client_metadata(format!(
            "Invalid client metadata: {error}"
        ))
    })
}

#[must_use]
pub fn response_types_from_client(client: &OAuthClient) -> Vec<String> {
    if client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        vec!["code".to_owned()]
    } else {
        Vec::new()
    }
}

impl PreparedDynamicClientRegistration {
    #[must_use]
    pub fn into_create_client_request(self) -> CreateClientRequest {
        let allow_authorization_code_without_pkce =
            self.client_type == "confidential" && !self.require_dpop_bound_tokens;
        // OIDC Core section 9 defines the token endpoint URL as the audience for
        // private_key_jwt client assertions. FAPI clients are provisioned through the
        // profile-aware admin/seed paths, which keep this compatibility policy disabled.
        let allow_client_assertion_endpoint_audience =
            self.token_endpoint_auth_method == "private_key_jwt";
        CreateClientRequest {
            client_name: self.client_name,
            client_type: self.client_type,
            redirect_uris: self.redirect_uris,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            scopes: self.scopes,
            allowed_audiences: self.allowed_audiences,
            grant_types: self.grant_types,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            subject_type: self.subject_type,
            sector_identifier_uri: self.sector_identifier_uri,
            require_dpop_bound_tokens: self.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience,
            require_par_request_object: false,
            allow_authorization_code_without_pkce,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
            tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256,
            tls_client_auth_san_dns: self.tls_client_auth_san_dns,
            tls_client_auth_san_uri: self.tls_client_auth_san_uri,
            tls_client_auth_san_ip: self.tls_client_auth_san_ip,
            tls_client_auth_san_email: self.tls_client_auth_san_email,
            jwks: self.jwks,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: self.userinfo_signed_response_alg,
            userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc,
            authorization_signed_response_alg: self.authorization_signed_response_alg,
            authorization_encrypted_response_alg: self.authorization_encrypted_response_alg,
            authorization_encrypted_response_enc: self.authorization_encrypted_response_enc,
            allow_jwks_without_kid: true,
        }
    }
}

fn validate_response_type_relationship(
    grant_types: &[String],
    response_types: &[String],
) -> Result<(), DynamicRegistrationError> {
    if response_types
        .iter()
        .any(|response_type| response_type != "code")
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "only code response type is supported.",
        ));
    }
    let has_code_grant = grant_types
        .iter()
        .any(|grant| grant == "authorization_code");
    let has_code_response = response_types.iter().any(|response| response == "code");
    if has_code_grant != has_code_response {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "authorization_code grant requires code response type.",
        ));
    }
    Ok(())
}

fn default_dynamic_client_scopes(grant_types: &[String]) -> Vec<String> {
    if !grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return Vec::new();
    }
    let mut scopes = ["openid", "profile", "email", "address", "phone"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if grant_types.iter().any(|grant| grant == "refresh_token") {
        scopes.push("offline_access".to_owned());
    }
    scopes
}

fn default_dynamic_client_grant_types() -> Vec<String> {
    ["authorization_code", "refresh_token"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_request_uris(request_uris: &[String]) -> Result<(), DynamicRegistrationError> {
    for request_uri in request_uris {
        let parsed = Url::parse(request_uri).map_err(|_| {
            DynamicRegistrationError::invalid_client_metadata(
                "request_uris values must be absolute HTTPS URLs.",
            )
        })?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "request_uris values must be absolute HTTPS URLs.",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidatedClientRegistration;
    use serde_json::json;
    use uuid::Uuid;

    const POLICY: DynamicRegistrationPolicy<'static> = DynamicRegistrationPolicy {
        default_audience: "https://api.example",
    };

    #[test]
    fn default_registration_contract_matches_oidc_code_client_behavior() {
        let prepared = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest::default(),
            POLICY,
        )
        .expect("default registration");
        assert_eq!(prepared.client_type, "confidential");
        assert_eq!(
            prepared.grant_types,
            ["authorization_code", "refresh_token"]
        );
        assert_eq!(prepared.response_types, ["code"]);
        assert_eq!(
            prepared.scopes,
            [
                "openid",
                "profile",
                "email",
                "address",
                "phone",
                "offline_access"
            ]
        );
        assert!(prepared.backchannel_logout_session_required);
        assert!(prepared.frontchannel_logout_session_required);
    }

    #[test]
    fn software_statement_jwks_uri_and_response_type_errors_keep_rfc_codes() {
        for (request, expected) in [
            (
                DynamicClientRegistrationRequest {
                    software_statement: Some("statement".to_owned()),
                    ..Default::default()
                },
                "invalid_software_statement",
            ),
            (
                DynamicClientRegistrationRequest {
                    jwks_uri: Some("https://client.example/jwks".to_owned()),
                    ..Default::default()
                },
                "invalid_client_metadata",
            ),
            (
                DynamicClientRegistrationRequest {
                    response_types: Some(vec!["token".to_owned()]),
                    ..Default::default()
                },
                "invalid_client_metadata",
            ),
        ] {
            assert_eq!(
                prepare_dynamic_client_registration(request, POLICY)
                    .expect_err("invalid metadata")
                    .error,
                expected
            );
        }
    }

    #[test]
    fn request_uri_and_client_name_normalization_are_transport_independent() {
        let prepared = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                request_uris: vec!["https://client.example/request.jwt".to_owned()],
                client_name: Some("  Example Client  ".to_owned()),
                ..Default::default()
            },
            POLICY,
        )
        .expect("valid request URI");
        assert_eq!(prepared.client_name, "Example Client");
        let error = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                request_uris: vec!["http://client.example/request.jwt".to_owned()],
                ..Default::default()
            },
            POLICY,
        )
        .expect_err("HTTPS is required");
        assert_eq!(error.error, "invalid_client_metadata");
    }

    #[test]
    fn configuration_update_rejects_server_fields_and_requires_matching_credentials() {
        let client = client();
        let managed = parse_client_configuration_update(
            json!({
                "client_id": "client",
                "registration_access_token": "replacement"
            }),
            &client,
            false,
            false,
        )
        .expect_err("server-managed fields must be rejected");
        assert_eq!(managed.error, "invalid_request");

        let wrong_secret = parse_client_configuration_update(
            json!({"client_id": "client", "client_secret": "wrong"}),
            &client,
            true,
            false,
        )
        .expect_err("secret must match");
        assert_eq!(wrong_secret.error, "invalid_client_metadata");

        let update = parse_client_configuration_update(
            json!({
                "client_id": "client",
                "client_secret": "verified-by-adapter",
                "client_name": "Updated"
            }),
            &client,
            true,
            true,
        )
        .expect("authenticated update");
        assert_eq!(update.client_name.as_deref(), Some("Updated"));
    }

    #[test]
    fn prepared_registration_conversion_keeps_pkce_security_policy() {
        let public = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                token_endpoint_auth_method: Some("none".to_owned()),
                redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
                ..Default::default()
            },
            POLICY,
        )
        .expect("public registration")
        .into_create_client_request();
        assert!(!public.allow_authorization_code_without_pkce);

        let confidential = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
                ..Default::default()
            },
            POLICY,
        )
        .expect("confidential registration")
        .into_create_client_request();
        assert!(confidential.allow_authorization_code_without_pkce);
    }

    #[test]
    fn private_key_jwt_registration_enables_standard_oidc_token_endpoint_audience() {
        let private_key_jwt = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
                redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
                ..Default::default()
            },
            POLICY,
        )
        .expect("private_key_jwt registration")
        .into_create_client_request();
        assert!(private_key_jwt.allow_client_assertion_endpoint_audience);

        let client_secret_basic = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
                redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
                ..Default::default()
            },
            POLICY,
        )
        .expect("client_secret_basic registration")
        .into_create_client_request();
        assert!(!client_secret_basic.allow_client_assertion_endpoint_audience);
    }

    fn client() -> OAuthClient {
        OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            realm_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            registration: ValidatedClientRegistration {
                client_id: "client".to_owned(),
                client_name: "Client".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec!["https://client.example/cb".to_owned()],
                post_logout_redirect_uris: Vec::new(),
                scopes: vec!["openid".to_owned()],
                allowed_audiences: vec!["https://api.example".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                token_endpoint_auth_method: "client_secret_basic".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier_uri: None,
                sector_identifier_host: None,
                require_dpop_bound_tokens: false,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                allow_authorization_code_without_pkce: true,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: None,
                tls_client_auth_san_dns: Vec::new(),
                tls_client_auth_san_uri: Vec::new(),
                tls_client_auth_san_ip: Vec::new(),
                tls_client_auth_san_email: Vec::new(),
                jwks: None,
                introspection_encrypted_response_alg: None,
                introspection_encrypted_response_enc: None,
                userinfo_signed_response_alg: None,
                userinfo_encrypted_response_alg: None,
                userinfo_encrypted_response_enc: None,
                authorization_signed_response_alg: None,
                authorization_encrypted_response_alg: None,
                authorization_encrypted_response_enc: None,
            },
            require_mtls_bound_tokens: false,
            is_active: true,
        }
    }
}
