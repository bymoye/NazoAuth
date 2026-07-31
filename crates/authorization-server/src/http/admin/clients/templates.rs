//! Reviewed client-creation presets for the administration UI and API clients.

use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use actix_web::{HttpRequest, HttpResponse, web::Data};
use nazo_http_actix::json_response;
use serde_json::json;

pub(crate) async fn admin_client_templates(
    admin_sessions: Data<AdminSessionHandles>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }
    json_response(json!({
        "templates": [
            {
                "id": "web",
                "label": "Web application",
                "required_fields": ["client_name", "redirect_uris"],
                "defaults": {
                    "client_type": "confidential",
                    "scopes": ["openid", "profile", "email"],
                    "allowed_audiences": ["resource://default"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "subject_type": "public"
                }
            },
            {
                "id": "native",
                "label": "Native application",
                "required_fields": ["client_name", "redirect_uris"],
                "defaults": {
                    "client_type": "public",
                    "scopes": ["openid", "profile", "email"],
                    "allowed_audiences": ["resource://default"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "none",
                    "subject_type": "public",
                    "require_dpop_bound_tokens": true
                }
            },
            {
                "id": "service",
                "label": "Machine-to-machine service",
                "required_fields": ["client_name"],
                "defaults": {
                    "client_type": "confidential",
                    "redirect_uris": [],
                    "scopes": [],
                    "allowed_audiences": ["resource://default"],
                    "grant_types": ["client_credentials"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "subject_type": "public"
                }
            },
            {
                "id": "fapi2",
                "label": "FAPI 2.0 application",
                "required_fields": ["client_name", "redirect_uris", "jwks"],
                "defaults": {
                    "client_type": "confidential",
                    "scopes": ["openid"],
                    "allowed_audiences": ["resource://default"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "subject_type": "public",
                    "require_dpop_bound_tokens": true,
                    "require_par_request_object": true,
                    "security_policy": {
                        "version": 1,
                        "assurance": "fapi2"
                    }
                }
            }
        ]
    }))
}
