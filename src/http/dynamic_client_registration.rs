//! RFC 7591 dynamic client registration endpoint.

use crate::http::{
    admin::{CreateClientRequest, InsertClientError, PreparedClientInsert},
    prelude::*,
};
use diesel_async::AsyncConnection;
use url::Url;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub(crate) redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) response_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) application_type: Option<String>,
    #[serde(default)]
    pub(crate) client_name: Option<String>,
    #[serde(default)]
    pub(crate) scope: Option<String>,
    #[serde(default)]
    pub(crate) token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub(crate) subject_type: Option<String>,
    #[serde(default)]
    pub(crate) sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub(crate) post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub(crate) backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub(crate) backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub(crate) frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub(crate) frontchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub(crate) dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_email: Vec<String>,
    #[serde(default)]
    pub(crate) jwks_uri: Option<String>,
    #[serde(default)]
    pub(crate) jwks: Option<Value>,
    #[serde(default)]
    pub(crate) request_uris: Vec<String>,
    #[serde(default)]
    pub(crate) software_statement: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct DynamicRegistrationDefaults<'a> {
    pub(crate) default_audience: &'a str,
}

#[derive(Debug)]
pub(crate) struct PreparedDynamicClientRegistration {
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) post_logout_redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) response_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    pub(crate) subject_type: Option<String>,
    pub(crate) sector_identifier_uri: Option<String>,
    pub(crate) require_dpop_bound_tokens: bool,
    pub(crate) backchannel_logout_uri: Option<String>,
    pub(crate) backchannel_logout_session_required: bool,
    pub(crate) frontchannel_logout_uri: Option<String>,
    pub(crate) frontchannel_logout_session_required: bool,
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    pub(crate) tls_client_auth_san_email: Vec<String>,
    pub(crate) jwks: Option<Value>,
}

#[derive(Debug)]
pub(crate) struct DynamicRegistrationError {
    error: &'static str,
    description: String,
}

pub(crate) async fn dynamic_client_registration(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<DynamicClientRegistrationRequest>,
) -> HttpResponse {
    if !state.settings.enable_dynamic_client_registration {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    if !initial_access_token_authorized(
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        state
            .settings
            .dynamic_client_registration_initial_access_token
            .as_deref(),
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
            default_audience: &state.settings.default_audience,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = random_urlsafe_token();
    match prepare_dynamic_client_insert_with_secret_pepper(
        prepared,
        state.settings.pairwise_subject_secret.as_deref(),
        &state.settings.client_secret_pepper,
        &state.settings.issuer,
        &registration_access_token,
    )
    .await
    {
        Ok(prepared_insert) => {
            let issued_secret = prepared_insert.issued_secret.clone();
            match crate::http::admin::insert_prepared_client_row(&state, &prepared_insert).await {
                Ok(client) => {
                    audit_dynamic_client_event("dynamic_client_registered", &client, &req, &state);
                    dynamic_registration_created_response(
                        &client,
                        &response_types,
                        issued_secret,
                        &state.settings.issuer,
                        &registration_access_token,
                        Utc::now(),
                    )
                }
                Err(crate::http::admin::InsertClientError::InvalidRequest(message)) => {
                    dynamic_registration_error_response(map_insert_error(message))
                }
                Err(crate::http::admin::InsertClientError::Server(message)) => {
                    tracing::warn!(%message, "failed to dynamically register oauth client");
                    oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "Dynamic client registration failed.",
                    )
                }
            }
        }
        Err(crate::http::admin::InsertClientError::InvalidRequest(message)) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        Err(crate::http::admin::InsertClientError::Server(message)) => {
            tracing::warn!(%message, "failed to dynamically register oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Dynamic client registration failed.",
            )
        }
    }
}

pub(crate) async fn client_configuration_get(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !state.settings.enable_dynamic_client_registration {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }

    let current = match authenticate_registration_client(&state, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let response_types = response_types_from_client(&current);
    let registration_access_token = random_urlsafe_token();
    let (issued_secret, secret_hash) = crate::http::admin::issue_client_secret(
        &current.client_type,
        &current.token_endpoint_auth_method,
        &state.settings.client_secret_pepper,
    );
    let client = match rotate_client_management_credentials(
        &state,
        &current,
        blake3_hex(&registration_access_token),
        secret_hash,
    )
    .await
    {
        Ok(client) => client,
        Err(response) => return response,
    };
    audit_dynamic_client_event("dynamic_client_configuration_read", &client, &req, &state);

    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &state.settings.issuer,
        &registration_access_token,
    ))
}

pub(crate) async fn client_configuration_put(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<Value>,
) -> HttpResponse {
    if !state.settings.enable_dynamic_client_registration {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }

    let current = match authenticate_registration_client(&state, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let payload = match parse_client_configuration_update_with_secret_pepper(
        payload,
        &current,
        &state.settings.client_secret_pepper,
    ) {
        Ok(payload) => payload,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let registration = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationDefaults {
            default_audience: &state.settings.default_audience,
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = random_urlsafe_token();
    let prepared = match prepare_dynamic_client_insert_with_secret_pepper(
        registration,
        state.settings.pairwise_subject_secret.as_deref(),
        &state.settings.client_secret_pepper,
        &state.settings.issuer,
        &registration_access_token,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return insert_error_to_management_response(error),
    };
    let issued_secret = prepared.issued_secret.clone();
    let client = match replace_client_configuration(&state, &current, &prepared).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    audit_dynamic_client_event(
        "dynamic_client_configuration_updated",
        &client,
        &req,
        &state,
    );

    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &state.settings.issuer,
        &registration_access_token,
    ))
}

pub(crate) async fn client_configuration_delete(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !state.settings.enable_dynamic_client_registration {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }

    let current = match authenticate_registration_client(&state, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if let Err(response) = deactivate_dynamic_client(&state, &current).await {
        return response;
    }
    audit_dynamic_client_event("dynamic_client_deleted", &current, &req, &state);

    empty_response_no_store(StatusCode::NO_CONTENT)
}

pub(crate) async fn prepare_dynamic_client_insert_with_secret_pepper(
    registration: PreparedDynamicClientRegistration,
    pairwise_subject_secret: Option<&str>,
    client_secret_pepper: &str,
    issuer: &str,
    registration_access_token: &str,
) -> Result<PreparedClientInsert, InsertClientError> {
    let mut prepared = crate::http::admin::prepare_client_insert_with_secret_pepper(
        registration.into_create_client_request(),
        pairwise_subject_secret,
        client_secret_pepper,
        issuer,
    )
    .await?;
    prepared.registration_access_token_blake3 = Some(blake3_hex(registration_access_token));
    Ok(prepared)
}

async fn authenticate_registration_client(
    state: &AppState,
    req: &HttpRequest,
    client_id: &str,
) -> Result<ClientRow, HttpResponse> {
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for client configuration auth");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration lookup failed.",
        )
    })?;
    let found = oauth_clients::table
        .filter(oauth_clients::tenant_id.eq(DEFAULT_TENANT_ID))
        .filter(oauth_clients::client_id.eq(client_id))
        .select((
            ClientRow::as_select(),
            oauth_clients::registration_access_token_blake3,
        ))
        .first::<(ClientRow, Option<String>)>(&mut conn)
        .await
        .optional()
        .map_err(|error| {
            tracing::warn!(%error, "failed to query dynamic client configuration credentials");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration lookup failed.",
            )
        })?;
    let Some((client, registration_token_hash)) = found else {
        return Err(registration_access_denied());
    };
    if !client.is_active
        || !registration_access_token_authorized(
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            registration_token_hash.as_deref(),
        )
    {
        return Err(registration_access_denied());
    }
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
    state: &AppState,
    current: &ClientRow,
    registration_access_token_hash: String,
    client_secret_hash: Option<String>,
) -> Result<ClientRow, HttpResponse> {
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for credential rotation");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration update failed.",
        )
    })?;
    diesel::update(
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(current.tenant_id))
            .filter(oauth_clients::id.eq(current.id))
            .filter(oauth_clients::is_active.eq(true)),
    )
    .set((
        oauth_clients::registration_access_token_blake3.eq(Some(registration_access_token_hash)),
        oauth_clients::client_secret_hash.eq(client_secret_hash),
        oauth_clients::updated_at.eq(diesel_now),
    ))
    .returning(ClientRow::as_returning())
    .get_result::<ClientRow>(&mut conn)
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
    state: &AppState,
    current: &ClientRow,
    prepared: &PreparedClientInsert,
) -> Result<ClientRow, HttpResponse> {
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for client configuration update");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration update failed.",
        )
    })?;
    diesel::update(
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(current.tenant_id))
            .filter(oauth_clients::id.eq(current.id))
            .filter(oauth_clients::is_active.eq(true)),
    )
    .set((
        oauth_clients::client_name.eq(&prepared.client_name),
        oauth_clients::client_type.eq(&prepared.client_type),
        oauth_clients::client_secret_hash.eq(&prepared.client_secret_hash),
        oauth_clients::registration_access_token_blake3
            .eq(&prepared.registration_access_token_blake3),
        oauth_clients::redirect_uris.eq(json!(&prepared.redirect_uris)),
        oauth_clients::post_logout_redirect_uris.eq(json!(&prepared.post_logout_redirect_uris)),
        oauth_clients::scopes.eq(json!(&prepared.scopes)),
        oauth_clients::allowed_audiences.eq(json!(&prepared.allowed_audiences)),
        oauth_clients::grant_types.eq(json!(&prepared.grant_types)),
        oauth_clients::token_endpoint_auth_method.eq(&prepared.token_endpoint_auth_method),
        oauth_clients::subject_type.eq(&prepared.subject_type),
        oauth_clients::sector_identifier_uri.eq(&prepared.sector_identifier_uri),
        oauth_clients::sector_identifier_host.eq(&prepared.sector_identifier_host),
        oauth_clients::require_dpop_bound_tokens.eq(prepared.require_dpop_bound_tokens),
        oauth_clients::allow_client_assertion_audience_array
            .eq(prepared.allow_client_assertion_audience_array),
        oauth_clients::allow_client_assertion_endpoint_audience
            .eq(prepared.allow_client_assertion_endpoint_audience),
        oauth_clients::require_par_request_object.eq(prepared.require_par_request_object),
        oauth_clients::allow_authorization_code_without_pkce
            .eq(prepared.allow_authorization_code_without_pkce),
        oauth_clients::backchannel_logout_uri.eq(&prepared.backchannel_logout_uri),
        oauth_clients::backchannel_logout_session_required
            .eq(prepared.backchannel_logout_session_required),
        oauth_clients::frontchannel_logout_uri.eq(&prepared.frontchannel_logout_uri),
        oauth_clients::frontchannel_logout_session_required
            .eq(prepared.frontchannel_logout_session_required),
        oauth_clients::tls_client_auth_subject_dn.eq(&prepared.tls_client_auth_subject_dn),
        oauth_clients::tls_client_auth_cert_sha256.eq(&prepared.tls_client_auth_cert_sha256),
        oauth_clients::tls_client_auth_san_dns.eq(json!(&prepared.tls_client_auth_san_dns)),
        oauth_clients::tls_client_auth_san_uri.eq(json!(&prepared.tls_client_auth_san_uri)),
        oauth_clients::tls_client_auth_san_ip.eq(json!(&prepared.tls_client_auth_san_ip)),
        oauth_clients::tls_client_auth_san_email.eq(json!(&prepared.tls_client_auth_san_email)),
        oauth_clients::jwks.eq(&prepared.jwks),
        oauth_clients::introspection_encrypted_response_alg
            .eq(&prepared.introspection_encrypted_response_alg),
        oauth_clients::introspection_encrypted_response_enc
            .eq(&prepared.introspection_encrypted_response_enc),
        oauth_clients::updated_at.eq(diesel_now),
    ))
    .returning(ClientRow::as_returning())
    .get_result::<ClientRow>(&mut conn)
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
    state: &AppState,
    current: &ClientRow,
) -> Result<(), HttpResponse> {
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for client deletion");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client deletion failed.",
        )
    })?;
    conn.transaction::<(), diesel::result::Error, _>(async |conn| {
        diesel::update(
            oauth_clients::table
                .filter(oauth_clients::tenant_id.eq(current.tenant_id))
                .filter(oauth_clients::id.eq(current.id)),
        )
        .set((
            oauth_clients::is_active.eq(false),
            oauth_clients::registration_access_token_blake3.eq::<Option<String>>(None),
            oauth_clients::updated_at.eq(diesel_now),
        ))
        .execute(conn)
        .await?;
        diesel::update(
            oauth_tokens::table
                .filter(oauth_tokens::tenant_id.eq(current.tenant_id))
                .filter(oauth_tokens::client_id.eq(current.id))
                .filter(oauth_tokens::revoked_at.is_null()),
        )
        .set(oauth_tokens::revoked_at.eq(diesel_now))
        .execute(conn)
        .await?;
        diesel::delete(
            user_client_grants::table
                .filter(user_client_grants::tenant_id.eq(current.tenant_id))
                .filter(user_client_grants::client_id.eq(current.id)),
        )
        .execute(conn)
        .await?;
        Ok(())
    })
    .await
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

fn insert_error_to_management_response(error: InsertClientError) -> HttpResponse {
    match error {
        InsertClientError::InvalidRequest(message) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        InsertClientError::Server(message) => {
            tracing::warn!(%message, "failed to prepare dynamic client management response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            )
        }
    }
}

fn response_types_from_client(client: &ClientRow) -> Vec<String> {
    let grant_types = json_array_to_strings(&client.grant_types);
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        vec!["code".to_owned()]
    } else {
        Vec::new()
    }
}

fn audit_dynamic_client_event(
    event: &str,
    client: &ClientRow,
    req: &HttpRequest,
    state: &AppState,
) {
    audit_event(
        event,
        dynamic_client_audit_fields(client, blake3_hex(&client_ip(req, &state.settings))),
    );
}

fn dynamic_client_audit_fields(
    client: &ClientRow,
    source_ip_hash: String,
) -> serde_json::Map<String, Value> {
    audit_fields(&[
        ("client_id", json!(client.client_id)),
        ("client_type", json!(client.client_type)),
        (
            "grant_types",
            json!(json_array_to_strings(&client.grant_types)),
        ),
        (
            "token_endpoint_auth_method",
            json!(client.token_endpoint_auth_method),
        ),
        ("source_ip_hash", json!(source_ip_hash)),
    ])
}

pub(crate) fn prepare_dynamic_client_registration(
    request: DynamicClientRegistrationRequest,
    defaults: DynamicRegistrationDefaults<'_>,
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
    if let Some(application_type) = request.application_type.as_deref()
        && !matches!(application_type, "web" | "native")
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
        allowed_audiences: vec![defaults.default_audience.to_owned()],
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
    })
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

pub(crate) fn parse_client_configuration_update_with_secret_pepper(
    mut payload: Value,
    current: &ClientRow,
    client_secret_pepper: &str,
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
    match (&current.client_secret_hash, client_secret) {
        (Some(stored_hash), Some(Value::String(secret)))
            if verify_client_secret(&secret, stored_hash, client_secret_pepper) => {}
        (Some(_), _) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "client_secret must match the current client secret.",
            ));
        }
        (None, Some(_)) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "public or assertion-based clients must not submit client_secret.",
            ));
        }
        (None, None) => {}
    }

    serde_json::from_value(payload).map_err(|error| {
        DynamicRegistrationError::invalid_client_metadata(format!(
            "Invalid client metadata: {error}"
        ))
    })
}

impl PreparedDynamicClientRegistration {
    fn to_create_client_request(&self) -> CreateClientRequest {
        let secret_auth_method = matches!(
            self.token_endpoint_auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        );
        let allow_authorization_code_without_pkce =
            self.client_type == "confidential" && !self.require_dpop_bound_tokens;
        CreateClientRequest {
            client_name: self.client_name.clone(),
            client_type: self.client_type.clone(),
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            scopes: self.scopes.clone(),
            allowed_audiences: self.allowed_audiences.clone(),
            grant_types: self.grant_types.clone(),
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            subject_type: self.subject_type.clone(),
            sector_identifier_uri: self.sector_identifier_uri.clone(),
            require_dpop_bound_tokens: self.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce,
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            frontchannel_logout_uri: self.frontchannel_logout_uri.clone(),
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn.clone(),
            tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256.clone(),
            tls_client_auth_san_dns: self.tls_client_auth_san_dns.clone(),
            tls_client_auth_san_uri: self.tls_client_auth_san_uri.clone(),
            tls_client_auth_san_ip: self.tls_client_auth_san_ip.clone(),
            tls_client_auth_san_email: self.tls_client_auth_san_email.clone(),
            jwks: self.jwks.clone(),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            allow_jwks_without_kid: secret_auth_method,
        }
    }

    fn into_create_client_request(self) -> CreateClientRequest {
        self.to_create_client_request()
    }
}

impl DynamicRegistrationError {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new("invalid_client_metadata", description)
    }
}

fn validate_response_type_relationship(
    grant_types: &[String],
    response_types: &[String],
) -> Result<(), DynamicRegistrationError> {
    for response_type in response_types {
        if response_type != "code" {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "only code response type is supported.",
            ));
        }
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
        "redirect_uris": json_array_to_strings(&client.redirect_uris),
        "grant_types": json_array_to_strings(&client.grant_types),
        "response_types": response_types,
        "scope": json_array_to_strings(&client.scopes).join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": json_array_to_strings(&client.post_logout_redirect_uris),
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
