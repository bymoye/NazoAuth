//! Administrative control plane for issuer-authoritative credential data.
//!
//! OpenID4VCI defines credential issuance, not the operator API used to
//! maintain the data from which credentials are issued. Keep this surface in
//! the authenticated admin boundary instead of presenting it as an
//! OpenID4VCI protocol endpoint.

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path},
};
use nazo_http_actix::{
    csrf_error, empty_response_no_store, has_valid_csrf_token_for_cookies, json_response_no_store,
    json_response_status_no_store,
};
use nazo_openid4vc_http_actix::CredentialHttpError;
use uuid::Uuid;

use crate::{
    adapters::audit::audit_fields,
    domain::{CredentialDatasetAdminService, PutCredentialDatasetRequest},
    http::{
        admin::{persist_required_audit_or_unavailable, require_durable_audit_or_unavailable},
        sessions::{
            AdminSessionHandles, require_admin_or_forbidden_with_handles,
            require_admin_with_recent_mfa_or_forbidden_with_handles,
        },
    },
};

pub(crate) async fn admin_put_credential_dataset(
    sessions: Data<AdminSessionHandles>,
    endpoint: Data<CredentialDatasetAdminService>,
    request: HttpRequest,
    path: Path<(Uuid, String)>,
    Json(payload): Json<PutCredentialDatasetRequest>,
) -> HttpResponse {
    if !valid_csrf(&sessions, &request) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(&sessions, &request).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let (subject_id, configuration_id) = path.into_inner();
    if let Err(response) = require_durable_audit_or_unavailable().await {
        return response;
    }
    match endpoint
        .put_dataset(
            admin.principal.tenant.tenant_id.as_uuid(),
            admin.user_id().as_uuid(),
            subject_id,
            configuration_id.clone(),
            payload,
        )
        .await
    {
        Ok(dataset) => {
            if let Err(response) = persist_required_audit_or_unavailable(
                "openid4vci_credential_dataset_updated",
                audit_fields(&[
                    ("admin_user_id", serde_json::json!(admin.id())),
                    ("subject_id", serde_json::json!(subject_id)),
                    (
                        "credential_configuration_id",
                        serde_json::json!(configuration_id),
                    ),
                ]),
            )
            .await
            {
                return response;
            }
            json_response_no_store(dataset)
        }
        Err(error) => dataset_error(error),
    }
}

pub(crate) async fn admin_get_credential_dataset(
    sessions: Data<AdminSessionHandles>,
    endpoint: Data<CredentialDatasetAdminService>,
    request: HttpRequest,
    path: Path<(Uuid, String)>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(&sessions, &request).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (subject_id, configuration_id) = path.into_inner();
    match endpoint
        .get_dataset(
            admin.principal.tenant.tenant_id.as_uuid(),
            subject_id,
            configuration_id,
        )
        .await
    {
        Ok(dataset) => json_response_no_store(dataset),
        Err(error) => dataset_error(error),
    }
}

pub(crate) async fn admin_delete_credential_dataset(
    sessions: Data<AdminSessionHandles>,
    endpoint: Data<CredentialDatasetAdminService>,
    request: HttpRequest,
    path: Path<(Uuid, String)>,
) -> HttpResponse {
    if !valid_csrf(&sessions, &request) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(&sessions, &request).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let (subject_id, configuration_id) = path.into_inner();
    if let Err(response) = require_durable_audit_or_unavailable().await {
        return response;
    }
    match endpoint
        .delete_dataset(
            admin.principal.tenant.tenant_id.as_uuid(),
            admin.user_id().as_uuid(),
            subject_id,
            configuration_id.clone(),
        )
        .await
    {
        Ok(()) => {
            if let Err(response) = persist_required_audit_or_unavailable(
                "openid4vci_credential_dataset_deleted",
                audit_fields(&[
                    ("admin_user_id", serde_json::json!(admin.id())),
                    ("subject_id", serde_json::json!(subject_id)),
                    (
                        "credential_configuration_id",
                        serde_json::json!(configuration_id),
                    ),
                ]),
            )
            .await
            {
                return response;
            }
            empty_response_no_store(StatusCode::NO_CONTENT)
        }
        Err(error) => dataset_error(error),
    }
}

fn dataset_error(error: CredentialHttpError) -> HttpResponse {
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response_status_no_store(
        status,
        serde_json::json!({
            "error": error.error,
            "error_description": error.description,
        }),
    )
}

fn valid_csrf(sessions: &AdminSessionHandles, request: &HttpRequest) -> bool {
    let config = sessions.http_config();
    has_valid_csrf_token_for_cookies(
        request,
        None,
        config.session_cookie_name(),
        config.csrf_cookie_name(),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/http/admin/openid4vc.rs"]
mod tests;
