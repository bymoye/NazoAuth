//! JWT-Secured Authorization Request coordination.

use std::collections::HashMap;

use actix_web::HttpResponse;
use chrono::Utc;
use nazo_auth::{
    AuthorizationRequestError, RequestObjectJtiPolicy, RequestObjectPolicy,
    RequestObjectVerificationInput, verify_request_object,
};

use super::AuthorizationRequestContext;
use crate::{domain::ClientRow, settings::RequestObjectJtiPolicy as ServerRequestObjectJtiPolicy};

pub(crate) use nazo_auth::unverified_signed_request_object_client_id;
use nazo_http_actix::{request_object_policy_error, request_object_verification_error};

pub(crate) fn unverified_request_object_client_id(
    keys: &nazo_key_management::KeyManager,
    request_object: &str,
) -> Option<String> {
    if request_object.split('.').count() == 5 {
        let nested = keys.decrypt_request_object(request_object).ok()?;
        return unverified_signed_request_object_client_id(&nested);
    }
    unverified_signed_request_object_client_id(request_object)
}

pub(crate) async fn apply_request_object_with_context(
    context: &AuthorizationRequestContext<'_>,
    outer: &mut HashMap<String, String>,
    client: &ClientRow,
) -> Result<(), HttpResponse> {
    let Some(request_object) = outer.get("request") else {
        return Ok(());
    };
    let decrypted;
    let request_object = if request_object.split('.').count() == 5 {
        if client.request_object_encryption_alg.as_deref() != Some("RSA-OAEP-256")
            || client.request_object_encryption_enc.as_deref() != Some("A256GCM")
        {
            return Err(request_object_verification_error(
                nazo_auth::RequestObjectVerificationError::InvalidAlgorithm,
            ));
        }
        decrypted = context
            .request_object_keys
            .decrypt_request_object(request_object)
            .map_err(|error| {
                tracing::warn!(%error, "encrypted request object rejected");
                request_object_verification_error(
                    nazo_auth::RequestObjectVerificationError::InvalidSignature,
                )
            })?;
        decrypted.as_str()
    } else {
        request_object.as_str()
    };
    let verified = verify_request_object(RequestObjectVerificationInput {
        request_object,
        client,
        expected_signing_algorithm: client.request_object_signing_alg.as_deref(),
    })
    .map_err(request_object_verification_error)?;
    let normalized = context
        .service
        .admit_request_object_owned(
            outer,
            &verified.claims,
            RequestObjectPolicy {
                issuer: &context.config.issuer,
                client_id: &client.client_id,
                jti_policy: match context.config.request_object_jti_policy {
                    ServerRequestObjectJtiPolicy::Optional => RequestObjectJtiPolicy::Optional,
                    ServerRequestObjectJtiPolicy::RequiredForSignedJar => {
                        RequestObjectJtiPolicy::RequiredForSignedJar
                    }
                },
                require_integrity_protected_parameters:
                    signed_request_object_requires_integrity_protected_parameters(context, client),
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

fn signed_request_object_requires_integrity_protected_parameters(
    context: &AuthorizationRequestContext<'_>,
    client: &ClientRow,
) -> bool {
    client.require_dpop_bound_tokens
        || client.require_par_request_object
        || context
            .config
            .profile
            .effective_client_policy(client)
            .require_signed_authorization_request
}
