//! JWT-Secured Authorization Request coordination.

use std::collections::HashMap;

use actix_web::HttpResponse;
use chrono::Utc;
use nazo_auth::{
    AuthorizationRequestError, RequestObjectJtiPolicy, RequestObjectMode, RequestObjectPolicy,
    RequestObjectVerificationInput, verify_request_object,
};

use super::AuthorizationRequestContext;
use crate::{domain::ClientRow, settings::RequestObjectJtiPolicy as ServerRequestObjectJtiPolicy};

pub(crate) use nazo_auth::{
    request_object_uses_unsigned_algorithm, unverified_signed_request_object_client_id,
};
use nazo_http_actix::{request_object_policy_error, request_object_verification_error};

pub(crate) async fn apply_request_object_with_context(
    context: &AuthorizationRequestContext<'_>,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
) -> Result<(), HttpResponse> {
    let Some(request_object) = outer.get("request") else {
        return Ok(());
    };
    let verified = verify_request_object(RequestObjectVerificationInput {
        request_object,
        client,
        profile_disallows_unsigned_request_object: context.config.profile.requires_fapi2_security(),
    })
    .map_err(request_object_verification_error)?;
    let mode = verified.mode;
    let normalized = context
        .service
        .admit_request_object(
            outer,
            &verified.claims,
            RequestObjectPolicy {
                issuer: &context.config.issuer,
                client_id: &client.client_id,
                mode,
                jti_policy: match context.config.request_object_jti_policy {
                    ServerRequestObjectJtiPolicy::Optional => RequestObjectJtiPolicy::Optional,
                    ServerRequestObjectJtiPolicy::RequiredForSignedJar => {
                        RequestObjectJtiPolicy::RequiredForSignedJar
                    }
                },
                unsigned_request_object_allowed: unsigned_request_object_allowed(context, client),
                require_integrity_protected_parameters:
                    signed_request_object_requires_integrity_protected_parameters(
                        context, client, mode,
                    ),
                now: Utc::now().timestamp(),
            },
        )
        .await
        .map_err(|error| {
            if let AuthorizationRequestError::Dependency(dependency) = error {
                tracing::warn!(?dependency, "failed to store request object jti");
            }
            request_object_policy_error(error)
        })?;
    *outer = normalized.parameters;
    Ok(())
}

fn unsigned_request_object_allowed(
    context: &AuthorizationRequestContext<'_>,
    client: &ClientRow,
) -> bool {
    !(client.require_dpop_bound_tokens
        || client.require_par_request_object
        || context
            .config
            .profile
            .requires_signed_authorization_request())
}

fn signed_request_object_requires_integrity_protected_parameters(
    context: &AuthorizationRequestContext<'_>,
    client: &ClientRow,
    mode: RequestObjectMode,
) -> bool {
    mode == RequestObjectMode::SignedJar
        && (client.require_dpop_bound_tokens
            || client.require_par_request_object
            || context
                .config
                .profile
                .requires_signed_authorization_request())
}
