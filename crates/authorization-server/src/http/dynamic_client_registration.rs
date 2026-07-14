//! RFC 7591 dynamic client registration endpoint.
use nazo_http_actix::{
    empty_response, empty_response_no_store, json_response_no_store, json_response_status_no_store,
    oauth_bearer_error, oauth_error,
};

use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::client_secret_digest;
use crate::adapters::security::constant_time_eq;
use crate::adapters::security::hash_client_secret;
use crate::adapters::security::random_urlsafe_token;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, DynamicRegistrationHandles};
use crate::http::admin::clients::ServerSectorIdentifierResolver;
use crate::http::client_ip::client_ip_with_context;
use crate::http::rate_limit::RateLimitPolicy;
use crate::http::rate_limit::enforce_rate_limit_with_store;
use actix_web::http::StatusCode;
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use actix_web::web::{Data, Json, Payload};
use actix_web::{FromRequest, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
#[cfg(test)]
use nazo_auth::CreateClientRequest;
use nazo_auth::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, DynamicClientRegistrationRequest,
    DynamicRegistrationError, DynamicRegistrationPolicy as DynamicRegistrationDefaults,
    PreparedClientRegistration, PreparedDynamicClientRegistration,
    parse_client_configuration_update, prepare_dynamic_client_registration,
    response_types_from_client,
};
use serde_json::{Value, json};

pub(crate) async fn dynamic_client_registration(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    body: Payload,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) =
        match Json::<DynamicClientRegistrationRequest>::from_request(&req, &mut body).await {
            Ok(payload) => payload,
            Err(error) => return error.error_response(),
        };
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }
    if !initial_access_token_authorized(
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        handles.config.initial_access_token.as_deref(),
    ) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Initial access token is missing or invalid.",
        );
    }

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationDefaults {
            default_audience: &handles.config.default_audience,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = random_urlsafe_token();
    let response_signing_algorithms = handles
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    match prepare_dynamic_client_insert_with_secret_pepper(
        prepared,
        handles.config.pairwise_subject_secret.as_deref(),
        &handles.config.client_secret_pepper,
        &handles.config.issuer,
        &registration_access_token,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared_insert) => {
            let issued_secret = prepared_insert.issued_secret.clone();
            match nazo_auth::insert_prepared_client(&handles.clients, &prepared_insert).await {
                Ok(client) => {
                    audit_dynamic_client_event(
                        "dynamic_client_registered",
                        &client,
                        &req,
                        &handles,
                    );
                    dynamic_registration_created_response(
                        &client,
                        &response_types,
                        issued_secret,
                        &handles.config.issuer,
                        &registration_access_token,
                        Utc::now(),
                    )
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to dynamically register oauth client");
                    oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "Dynamic client registration failed.",
                    )
                }
            }
        }
        Err(AdminClientError::InvalidRequest(message)) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        Err(error) => {
            tracing::warn!(%error, "failed to dynamically register oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Dynamic client registration failed.",
            )
        }
    }
}

pub(crate) async fn client_configuration_get(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }

    let current = match authenticate_registration_client(&handles, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let response_types = response_types_from_client(&current);
    let registration_access_token = random_urlsafe_token();
    let (issued_secret, secret_hash) = issue_client_secret(
        &current.client_type,
        &current.token_endpoint_auth_method,
        &handles.config.client_secret_pepper,
    );
    let client = match rotate_client_management_credentials(
        &handles,
        &current,
        blake3_hex(&registration_access_token),
        secret_hash,
    )
    .await
    {
        Ok(client) => client,
        Err(response) => return response,
    };
    audit_dynamic_client_event("dynamic_client_configuration_read", &client, &req, &handles);

    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &handles.config.issuer,
        &registration_access_token,
    ))
}

pub(crate) async fn client_configuration_put(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    body: Payload,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) = match Json::<Value>::from_request(&req, &mut body).await {
        Ok(payload) => payload,
        Err(error) => return error.error_response(),
    };
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }

    let current = match authenticate_registration_client(&handles, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let repository = &handles.clients;
    let submitted_secret = payload.get("client_secret").and_then(Value::as_str);
    let has_secret = match repository.has_client_secret(current.id).await {
        Ok(has_secret) => has_secret,
        Err(error) => {
            tracing::warn!(%error, "failed to inspect dynamic client secret state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration lookup failed.",
            );
        }
    };
    let secret_matches = if let Some(secret) = submitted_secret {
        let candidate_match = match repository.client_secret_salt(current.id).await {
            Ok(Some(salt)) => {
                let candidate_digest =
                    client_secret_digest(secret, &handles.config.client_secret_pepper, &salt);
                repository
                    .client_secret_digest_matches(current.id, &candidate_digest)
                    .await
            }
            Ok(None) => Ok(false),
            Err(error) => Err(error),
        };
        match candidate_match {
            Ok(matches) => matches,
            Err(error) => {
                tracing::warn!(%error, "failed to verify dynamic client secret");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Client configuration lookup failed.",
                );
            }
        }
    } else {
        false
    };
    let payload =
        match parse_client_configuration_update(payload, &current, has_secret, secret_matches) {
            Ok(payload) => payload,
            Err(error) => return dynamic_registration_error_response(error),
        };
    let registration = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationDefaults {
            default_audience: &handles.config.default_audience,
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = random_urlsafe_token();
    let response_signing_algorithms = handles
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    let prepared = match prepare_dynamic_client_insert_with_secret_pepper(
        registration,
        handles.config.pairwise_subject_secret.as_deref(),
        &handles.config.client_secret_pepper,
        &handles.config.issuer,
        &registration_access_token,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return insert_error_to_management_response(error),
    };
    let issued_secret = prepared.issued_secret.clone();
    let client = match replace_client_configuration(&handles, &current, &prepared).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    audit_dynamic_client_event(
        "dynamic_client_configuration_updated",
        &client,
        &req,
        &handles,
    );

    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &handles.config.issuer,
        &registration_access_token,
    ))
}

pub(crate) async fn client_configuration_delete(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }

    let current = match authenticate_registration_client(&handles, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if let Err(response) = deactivate_dynamic_client(&handles, &current).await {
        return response;
    }
    audit_dynamic_client_event("dynamic_client_deleted", &current, &req, &handles);

    empty_response_no_store(StatusCode::NO_CONTENT)
}

pub(crate) async fn prepare_dynamic_client_insert_with_secret_pepper(
    registration: PreparedDynamicClientRegistration,
    pairwise_subject_secret: Option<&str>,
    client_secret_pepper: &str,
    issuer: &str,
    registration_access_token: &str,
    response_signing_algorithms: &[&'static str],
) -> Result<PreparedClientRegistration, AdminClientError> {
    let _ = issuer;
    let crypto = DynamicRegistrationCrypto {
        response_signing_algorithms,
    };
    let policy = AdminClientPolicy {
        tenant: nazo_identity::TenantContext::default_system(),
        pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
        client_secret_pepper: client_secret_pepper.to_owned(),
    };
    let mut prepared = nazo_auth::prepare_client_registration(
        registration.into_create_client_request(),
        &policy,
        &ServerSectorIdentifierResolver,
        &crypto,
    )
    .await?;
    prepared.registration_access_token_blake3 = Some(blake3_hex(registration_access_token));
    Ok(prepared)
}

fn issue_client_secret(
    client_type: &str,
    token_endpoint_auth_method: &str,
    pepper: &str,
) -> (Option<String>, Option<String>) {
    if client_type != "confidential"
        || !matches!(
            token_endpoint_auth_method,
            "client_secret_basic" | "client_secret_post"
        )
    {
        return (None, None);
    }
    let secret = random_urlsafe_token();
    let digest = hash_client_secret(&secret, pepper);
    (Some(secret), Some(digest))
}

struct DynamicRegistrationCrypto<'a> {
    response_signing_algorithms: &'a [&'static str],
}

impl AdminClientCryptoPort for DynamicRegistrationCrypto<'_> {
    fn response_signing_algorithms(&self) -> Vec<String> {
        self.response_signing_algorithms
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String> {
        crate::domain::client_policy::validate_client_jwks_with_missing_kid_policy(
            jwks,
            allow_missing_kid,
        )
        .map_err(|error| error.to_string())
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        crate::domain::client_policy::client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        crate::domain::client_policy::client_jwks_contains_signing_key(jwks)
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        crate::domain::client_policy::validate_self_signed_mtls_jwks(jwks)
    }
}

async fn authenticate_registration_client(
    handles: &DynamicRegistrationHandles,
    req: &HttpRequest,
    client_id: &str,
) -> Result<ClientRow, HttpResponse> {
    let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(registration_access_denied());
    };
    let found = handles
        .clients
        .by_registration_access_token(DEFAULT_TENANT_ID, client_id, &blake3_hex(token))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query dynamic client configuration credentials");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration lookup failed.",
            )
        })?;
    let Some(client) = found else {
        return Err(registration_access_denied());
    };
    Ok(client)
}

fn registration_access_denied() -> HttpResponse {
    oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Registration access token is missing or invalid.",
    )
}

async fn rotate_client_management_credentials(
    handles: &DynamicRegistrationHandles,
    current: &ClientRow,
    registration_access_token_hash: String,
    client_secret_hash: Option<String>,
) -> Result<ClientRow, HttpResponse> {
    handles.clients.rotate_credentials(
        current.tenant_id,
        current.id,
        client_secret_hash.as_deref(),
        &registration_access_token_hash,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, client_id = %current.client_id, "failed to rotate dynamic client management credentials");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration update failed.",
        )
    })
}

async fn replace_client_configuration(
    handles: &DynamicRegistrationHandles,
    current: &ClientRow,
    prepared: &PreparedClientRegistration,
) -> Result<ClientRow, HttpResponse> {
    let updated = ClientRow {
        id: current.id,
        tenant_id: current.tenant_id,
        realm_id: current.realm_id,
        organization_id: current.organization_id,
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: current.require_mtls_bound_tokens,
        is_active: current.is_active,
    };
    handles.clients.replace_registration(
        &updated,
        prepared.client_secret_hash.as_deref(),
        prepared.registration_access_token_blake3.as_deref(),
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, client_id = %current.client_id, "failed to replace dynamic client configuration");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration update failed.",
        )
    })
}

async fn deactivate_dynamic_client(
    handles: &DynamicRegistrationHandles,
    current: &ClientRow,
) -> Result<(), HttpResponse> {
    handles.clients.deactivate(current.tenant_id, current.id)
    .await
    .and_then(|changed| changed.then_some(()).ok_or(nazo_identity::ports::RepositoryError::NotFound))
    .map_err(|error| {
        tracing::warn!(%error, client_id = %current.client_id, "failed to delete dynamic client");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client deletion failed.",
        )
    })?;
    Ok(())
}

fn insert_error_to_management_response(error: AdminClientError) -> HttpResponse {
    match error {
        AdminClientError::InvalidRequest(message) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        error => {
            tracing::warn!(%error, "failed to prepare dynamic client management response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            )
        }
    }
}

fn audit_dynamic_client_event(
    event: &str,
    client: &ClientRow,
    req: &HttpRequest,
    handles: &DynamicRegistrationHandles,
) {
    audit_event(
        event,
        dynamic_client_audit_fields(
            client,
            blake3_hex(&client_ip_with_context(
                req,
                handles.config.client_ip_header_mode,
                &handles.config.trusted_proxy_cidrs,
            )),
        ),
    );
}

async fn enforce_dynamic_registration_rate_limit(
    handles: &DynamicRegistrationHandles,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    enforce_rate_limit_with_store(
        &handles.rate_limits,
        req,
        RateLimitPolicy::TokenManagement,
        handles.config.rate_limit_window_seconds,
        handles.config.rate_limit_max_requests,
        handles.config.client_ip_header_mode,
        &handles.config.trusted_proxy_cidrs,
    )
    .await
}

fn dynamic_client_audit_fields(
    client: &ClientRow,
    source_ip_hash: String,
) -> serde_json::Map<String, Value> {
    audit_fields(&[
        ("client_id", json!(client.client_id)),
        ("client_type", json!(client.client_type)),
        ("grant_types", json!(client.grant_types)),
        (
            "token_endpoint_auth_method",
            json!(client.token_endpoint_auth_method),
        ),
        ("source_ip_hash", json!(source_ip_hash)),
    ])
}

pub(crate) fn initial_access_token_authorized(
    authorization_header: Option<&str>,
    expected_token: Option<&str>,
) -> bool {
    let Some(expected_token) = expected_token else {
        return false;
    };
    let Some(actual) = authorization_header
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    constant_time_eq(actual.as_bytes(), expected_token.as_bytes())
}

#[cfg(test)]
pub(crate) fn registration_access_token_authorized(
    authorization_header: Option<&str>,
    stored_token_hash: Option<&str>,
) -> bool {
    let Some(stored_token_hash) = stored_token_hash else {
        return false;
    };
    let Some(actual) = authorization_header
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let actual_hash = blake3_hex(actual);
    constant_time_eq(actual_hash.as_bytes(), stored_token_hash.as_bytes())
}

fn map_insert_error(message: String) -> DynamicRegistrationError {
    let error = if message.contains("redirect_uri") {
        "invalid_redirect_uri"
    } else {
        "invalid_client_metadata"
    };
    DynamicRegistrationError::new(error, message)
}

fn dynamic_registration_error_response(error: DynamicRegistrationError) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, error.error, &error.description)
}

fn dynamic_registration_created_response(
    client: &ClientRow,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
    issued_at: DateTime<Utc>,
) -> HttpResponse {
    let mut body = dynamic_registration_response(
        client,
        response_types,
        issued_secret,
        issuer,
        registration_access_token,
    );
    body["client_id_issued_at"] = json!(issued_at.timestamp());
    json_response_status_no_store(StatusCode::CREATED, body)
}

fn dynamic_registration_response(
    client: &ClientRow,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "registration_access_token": registration_access_token,
        "registration_client_uri": registration_client_uri(issuer, &client.client_id),
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": response_types,
        "scope": client.scopes.join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
    });
    if let Some(uri) = &client.backchannel_logout_uri {
        body["backchannel_logout_uri"] = json!(uri);
    }
    if let Some(uri) = &client.frontchannel_logout_uri {
        body["frontchannel_logout_uri"] = json!(uri);
    }
    if let Some(jwks) = &client.jwks {
        body["jwks"] = jwks.clone();
    }
    for (field, value) in [
        (
            "userinfo_signed_response_alg",
            client.userinfo_signed_response_alg.as_ref(),
        ),
        (
            "userinfo_encrypted_response_alg",
            client.userinfo_encrypted_response_alg.as_ref(),
        ),
        (
            "userinfo_encrypted_response_enc",
            client.userinfo_encrypted_response_enc.as_ref(),
        ),
        (
            "authorization_signed_response_alg",
            client.authorization_signed_response_alg.as_ref(),
        ),
        (
            "authorization_encrypted_response_alg",
            client.authorization_encrypted_response_alg.as_ref(),
        ),
        (
            "authorization_encrypted_response_enc",
            client.authorization_encrypted_response_enc.as_ref(),
        ),
    ] {
        if let Some(value) = value {
            body[field] = json!(value);
        }
    }
    if let Some(secret) = issued_secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    body
}

fn registration_client_uri(issuer: &str, client_id: &str) -> String {
    format!("{issuer}/register/{}", urlencoding::encode(client_id))
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/dynamic_client_registration.rs"]
mod tests;
