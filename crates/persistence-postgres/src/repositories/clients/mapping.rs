use nazo_auth::{
    ClientSecurityPolicy, OAuthClient, RegisteredLogoutClient, ValidatedClientRegistration,
};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_clients)]
pub(super) struct OAuthClientRecord {
    id: Uuid,
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    client_id: String,
    client_name: String,
    client_type: String,
    redirect_uris: Value,
    scopes: Value,
    allowed_audiences: Value,
    grant_types: Value,
    token_endpoint_auth_method: String,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Value,
    tls_client_auth_san_uri: Value,
    tls_client_auth_san_ip: Value,
    tls_client_auth_san_email: Value,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    is_active: bool,
    jwks_uri: Option<String>,
    jwks: Option<Value>,
    request_uris: Value,
    initiate_login_uri: Option<String>,
    logo_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    id_token_signed_response_alg: Option<String>,
    id_token_encrypted_response_alg: Option<String>,
    id_token_encrypted_response_enc: Option<String>,
    request_object_signing_alg: Option<String>,
    request_object_encryption_alg: Option<String>,
    request_object_encryption_enc: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
    introspection_signed_response_alg: Option<String>,
    introspection_encrypted_response_alg: Option<String>,
    introspection_encrypted_response_enc: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    authorization_signed_response_alg: Option<String>,
    authorization_encrypted_response_alg: Option<String>,
    authorization_encrypted_response_enc: Option<String>,
    post_logout_redirect_uris: Value,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    backchannel_token_delivery_mode: String,
    backchannel_client_notification_endpoint: Option<String>,
    backchannel_authentication_request_signing_alg: Option<String>,
    backchannel_user_code_parameter: bool,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    subject_type: String,
    sector_identifier_uri: Option<String>,
    sector_identifier_host: Option<String>,
    security_policy: Option<Value>,
}

pub(super) fn registered_logout_client(client: OAuthClient) -> RegisteredLogoutClient {
    let OAuthClient {
        id,
        tenant_id,
        registration,
        is_active,
        ..
    } = client;
    RegisteredLogoutClient {
        id,
        tenant_id,
        client_id: registration.client_id,
        active: is_active,
        redirect_uris: registration.redirect_uris,
        post_logout_redirect_uris: registration.post_logout_redirect_uris,
        backchannel_logout_uri: registration.backchannel_logout_uri,
        frontchannel_logout_uri: registration.frontchannel_logout_uri,
        frontchannel_logout_session_required: registration.frontchannel_logout_session_required,
        subject_type: registration.subject_type,
        sector_identifier_host: registration.sector_identifier_host,
    }
}

impl OAuthClientRecord {
    pub(super) fn into_domain(self) -> Result<OAuthClient, RepositoryError> {
        Ok(OAuthClient {
            id: self.id,
            tenant_id: self.tenant_id,
            realm_id: self.realm_id,
            organization_id: self.organization_id,
            registration: ValidatedClientRegistration {
                client_id: self.client_id,
                client_name: self.client_name,
                client_type: self.client_type,
                redirect_uris: string_array(self.redirect_uris, "redirect_uris")?,
                post_logout_redirect_uris: string_array(
                    self.post_logout_redirect_uris,
                    "post_logout_redirect_uris",
                )?,
                scopes: string_array(self.scopes, "scopes")?,
                allowed_audiences: string_array(self.allowed_audiences, "allowed_audiences")?,
                grant_types: string_array(self.grant_types, "grant_types")?,
                token_endpoint_auth_method: self.token_endpoint_auth_method,
                subject_type: self.subject_type,
                sector_identifier_uri: self.sector_identifier_uri,
                sector_identifier_host: self.sector_identifier_host,
                require_dpop_bound_tokens: self.require_dpop_bound_tokens,
                allow_client_assertion_audience_array: self.allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: self
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: self.require_par_request_object,
                backchannel_logout_uri: self.backchannel_logout_uri,
                backchannel_logout_session_required: self.backchannel_logout_session_required,
                backchannel_token_delivery_mode: self.backchannel_token_delivery_mode,
                backchannel_client_notification_endpoint: self
                    .backchannel_client_notification_endpoint,
                backchannel_authentication_request_signing_alg: self
                    .backchannel_authentication_request_signing_alg,
                backchannel_user_code_parameter: self.backchannel_user_code_parameter,
                frontchannel_logout_uri: self.frontchannel_logout_uri,
                frontchannel_logout_session_required: self.frontchannel_logout_session_required,
                tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
                tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256,
                tls_client_auth_san_dns: string_array(
                    self.tls_client_auth_san_dns,
                    "tls_client_auth_san_dns",
                )?,
                tls_client_auth_san_uri: string_array(
                    self.tls_client_auth_san_uri,
                    "tls_client_auth_san_uri",
                )?,
                tls_client_auth_san_ip: string_array(
                    self.tls_client_auth_san_ip,
                    "tls_client_auth_san_ip",
                )?,
                tls_client_auth_san_email: string_array(
                    self.tls_client_auth_san_email,
                    "tls_client_auth_san_email",
                )?,
                jwks_uri: self.jwks_uri,
                jwks: self.jwks,
                request_uris: string_array(self.request_uris, "request_uris")?,
                initiate_login_uri: self.initiate_login_uri,
                presentation: nazo_auth::ClientPresentationMetadata {
                    logo_uri: self.logo_uri,
                    policy_uri: self.policy_uri,
                    tos_uri: self.tos_uri,
                },
                id_token_signed_response_alg: self.id_token_signed_response_alg,
                id_token_encrypted_response_alg: self.id_token_encrypted_response_alg,
                id_token_encrypted_response_enc: self.id_token_encrypted_response_enc,
                request_object_signing_alg: self.request_object_signing_alg,
                request_object_encryption_alg: self.request_object_encryption_alg,
                request_object_encryption_enc: self.request_object_encryption_enc,
                token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg,
                introspection_signed_response_alg: self.introspection_signed_response_alg,
                introspection_encrypted_response_alg: self.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: self.introspection_encrypted_response_enc,
                userinfo_signed_response_alg: self.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc,
                authorization_signed_response_alg: self.authorization_signed_response_alg,
                authorization_encrypted_response_alg: self.authorization_encrypted_response_alg,
                authorization_encrypted_response_enc: self.authorization_encrypted_response_enc,
                security_policy: client_security_policy(self.security_policy)?,
            },
            require_mtls_bound_tokens: self.require_mtls_bound_tokens,
            is_active: self.is_active,
        })
    }
}

fn client_security_policy(
    value: Option<Value>,
) -> Result<Option<ClientSecurityPolicy>, RepositoryError> {
    value
        .map(|value| {
            serde_json::from_value::<ClientSecurityPolicy>(value)
                .map_err(|error| {
                    RepositoryError::Unexpected(format!(
                        "invalid OAuth client security_policy: {error}"
                    ))
                })
                .and_then(|policy| {
                    policy.validate().map_err(|error| {
                        RepositoryError::Unexpected(format!(
                            "invalid OAuth client security_policy: {error}"
                        ))
                    })?;
                    Ok(policy)
                })
        })
        .transpose()
}

pub(super) fn string_array(value: Value, field: &str) -> Result<Vec<String>, RepositoryError> {
    serde_json::from_value(value).map_err(|error| {
        RepositoryError::Unexpected(format!("invalid OAuth client {field}: {error}"))
    })
}

pub(super) fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::NotFound => RepositoryError::NotFound,
        error => RepositoryError::Unexpected(error.to_string()),
    }
}
