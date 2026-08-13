use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path, Payload},
};
use nazo_auth::{
    AdminClientError, AdminClientPolicy, DynamicClientRegistrationRequest,
    DynamicRegistrationPolicy, OAuthClient, PreparedClientRegistration,
    parse_client_configuration_update, prepare_dynamic_client_registration,
    response_types_from_client,
};
use nazo_identity::TenantContext;
use serde_json::Value;
use uuid::Uuid;

use super::{
    auth::{
        authenticate_registration_client, authorize_initial_access, enforce_rate_limit,
        submitted_secret_matches,
    },
    response::{
        dynamic_registration_created_response, dynamic_registration_error_response,
        dynamic_registration_response, lookup_failed, map_insert_error, registration_access_denied,
    },
    types::DynamicRegistrationEndpoint,
};
use crate::{empty_response, empty_response_no_store, json_response_no_store, oauth_error};

pub async fn dynamic_client_registration(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    body: Payload,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) =
        match Json::<DynamicClientRegistrationRequest>::from_request(&request, &mut body).await {
            Ok(payload) => payload,
            Err(error) => return error.error_response(),
        };
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let initial_access = match authorize_initial_access(&endpoint, &request).await {
        Ok(grant) => grant,
        Err(response) => return response,
    };

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
            pairwise_subject_supported: endpoint.config.pairwise_subject_secret.is_some(),
            id_token_signing_algs: &endpoint.config.id_token_signing_algs,
            response_signing_algs: &endpoint.config.response_signing_algs,
            request_object_encryption_algs: &endpoint.config.request_object_encryption_algs,
            request_object_encryption_encs: &endpoint.config.request_object_encryption_encs,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = endpoint.security.registration_tokens.random_token();
    let prepared_insert = match prepare_insert(
        &endpoint,
        prepared,
        &registration_access_token,
        initial_access.conformance_lease_id(),
        None,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(AdminClientError::InvalidRequest(message)) => {
            return dynamic_registration_error_response(map_insert_error(message));
        }
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Dynamic client registration failed.",
            );
        }
    };
    let issued_secret = prepared_insert.issued_secret.clone();
    match endpoint.clients.insert(&prepared_insert).await {
        Ok(client) => {
            endpoint
                .request_guard
                .audit("dynamic_client_registered", &client, &source_ip);
            dynamic_registration_created_response(
                &client,
                &response_types,
                issued_secret,
                &endpoint.config.issuer,
                &registration_access_token,
            )
        }
        Err(_error) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Dynamic client registration failed.",
        ),
    }
}

pub async fn client_configuration_get(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let (current, _authenticated_token_hash, registration_access_token) =
        match authenticate_registration_client(&endpoint, &request, &path).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
    let response_types = response_types_from_client(&current);
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_read", &current, &source_ip);
    json_response_no_store(dynamic_registration_response(
        &current,
        &response_types,
        None,
        &endpoint.config.issuer,
        &registration_access_token,
    ))
}

pub async fn client_configuration_put(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
    body: Payload,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) = match Json::<Value>::from_request(&request, &mut body).await {
        Ok(payload) => payload,
        Err(error) => return error.error_response(),
    };
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let (current, authenticated_token_hash, _) =
        match authenticate_registration_client(&endpoint, &request, &path).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
    let has_secret = match endpoint.clients.has_client_secret(current.id).await {
        Ok(has_secret) => has_secret,
        Err(_error) => {
            return lookup_failed();
        }
    };
    let secret_matches = match submitted_secret_matches(&endpoint, &current, &payload).await {
        Ok(matches) => matches,
        Err(_error) => {
            return lookup_failed();
        }
    };
    let payload =
        match parse_client_configuration_update(payload, &current, has_secret, secret_matches) {
            Ok(payload) => payload,
            Err(error) => return dynamic_registration_error_response(error),
        };
    let registration = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
            pairwise_subject_supported: endpoint.config.pairwise_subject_secret.is_some(),
            id_token_signing_algs: &endpoint.config.id_token_signing_algs,
            response_signing_algs: &endpoint.config.response_signing_algs,
            request_object_encryption_algs: &endpoint.config.request_object_encryption_algs,
            request_object_encryption_encs: &endpoint.config.request_object_encryption_encs,
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = endpoint.security.registration_tokens.random_token();
    let prepared = match prepare_insert(
        &endpoint,
        registration,
        &registration_access_token,
        None,
        current.security_policy.as_ref(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(AdminClientError::InvalidRequest(message)) => {
            return dynamic_registration_error_response(map_insert_error(message));
        }
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    let issued_secret = prepared.issued_secret.clone();
    let mut registration = prepared.registration.clone();
    registration.security_policy = current.security_policy.clone();
    let updated = OAuthClient {
        id: current.id,
        tenant_id: current.tenant_id,
        realm_id: current.realm_id,
        organization_id: current.organization_id,
        registration,
        require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
        is_active: current.is_active,
    };
    let client = match endpoint
        .clients
        .replace_registration(
            &updated,
            prepared.client_secret_hash.as_deref(),
            &authenticated_token_hash,
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await
    {
        Ok(client) => client,
        Err(nazo_auth::DynamicRegistrationDependencyError::StaleCredentials) => {
            return registration_access_denied();
        }
        Err(nazo_auth::DynamicRegistrationDependencyError::Unavailable) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_updated", &client, &source_ip);
    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &endpoint.config.issuer,
        &registration_access_token,
    ))
}

pub async fn client_configuration_delete(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let (current, authenticated_token_hash, _) =
        match authenticate_registration_client(&endpoint, &request, &path).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
    match endpoint
        .clients
        .deactivate(current.tenant_id, current.id, &authenticated_token_hash)
        .await
    {
        Ok(true) => {}
        Err(nazo_auth::DynamicRegistrationDependencyError::StaleCredentials) => {
            return registration_access_denied();
        }
        Ok(false) | Err(nazo_auth::DynamicRegistrationDependencyError::Unavailable) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client deletion failed.",
            );
        }
    }
    endpoint
        .request_guard
        .audit("dynamic_client_deleted", &current, &source_ip);
    empty_response_no_store(StatusCode::NO_CONTENT)
}

pub(super) async fn prepare_insert(
    endpoint: &DynamicRegistrationEndpoint,
    mut registration: nazo_auth::PreparedDynamicClientRegistration,
    registration_access_token: &str,
    conformance_lease_id: Option<Uuid>,
    security_policy_override: Option<&nazo_auth::ClientSecurityPolicy>,
) -> Result<PreparedClientRegistration, AdminClientError> {
    if let Some(uri) = registration.jwks_uri.as_deref() {
        registration.jwks = Some(endpoint.security.remote_jwks.resolve(uri).await.map_err(
            |error| {
                AdminClientError::InvalidRequest(format!("jwks_uri could not be resolved: {error}"))
            },
        )?);
    }
    let mut request = registration.into_create_client_request();
    request.conformance_lease_id = conformance_lease_id;
    if let Some(security_policy) = security_policy_override {
        request.security_policy = security_policy.clone();
    }
    if conformance_lease_id.is_some() && request.client_type == "confidential" {
        request.security_policy.allow_confidential_oidc_without_pkce = true;
    }
    let policy = AdminClientPolicy {
        tenant: TenantContext::default_system(),
        pairwise_subject_secret: endpoint.config.pairwise_subject_secret.clone(),
        client_secret_pepper: endpoint.config.client_secret_pepper.clone(),
    };
    let mut prepared = nazo_auth::prepare_client_registration(
        request,
        &policy,
        endpoint.sector_identifiers.as_ref(),
        endpoint.security.crypto.as_ref(),
    )
    .await?;
    prepared.registration_access_token_blake3 = Some(
        endpoint
            .security
            .registration_tokens
            .token_hash(registration_access_token),
    );
    Ok(prepared)
}
