//! Public, display-only metadata for the hosted authorization login page.

use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use nazo_http_actix::{json_response_no_store, json_response_status_no_store};
use serde::Serialize;

use crate::domain::ClientRow;
use crate::http::authorization::AuthorizationEndpoint;

const MAX_CLIENT_ID_BYTES: usize = 255;

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ClientPresentationResponse<'a> {
    client_name: &'a str,
    logo_uri: Option<&'a str>,
    policy_uri: Option<&'a str>,
    tos_uri: Option<&'a str>,
}

pub(crate) async fn authorize_client_presentation(
    endpoint: Data<AuthorizationEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let Some(client_id) = presentation_client_id(request.query_string()) else {
        return client_presentation_error(StatusCode::BAD_REQUEST, "invalid_request");
    };

    let client = match endpoint.context().service.client_by_id(&client_id).await {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "failed to load client presentation metadata");
            return client_presentation_error(StatusCode::SERVICE_UNAVAILABLE, "server_error");
        }
    };
    client_presentation_response(client.as_ref())
}

fn presentation_client_id(query: &str) -> Option<String> {
    let mut pairs = url::form_urlencoded::parse(query.as_bytes());
    let (name, client_id) = pairs.next()?;
    if name != "client_id" || pairs.next().is_some() {
        return None;
    }
    // RFC 6749 Appendix A.1 defines client-id as VSCHAR; keep this public
    // lookup bounded and aligned with that protocol grammar.
    (!client_id.is_empty()
        && client_id.len() <= MAX_CLIENT_ID_BYTES
        && client_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))
    .then(|| client_id.into_owned())
}

fn client_presentation_response(client: Option<&ClientRow>) -> HttpResponse {
    let Some(client) = client.filter(|client| client.is_active) else {
        return client_presentation_error(StatusCode::NOT_FOUND, "not_found");
    };

    json_response_no_store(ClientPresentationResponse {
        client_name: &client.client_name,
        logo_uri: client.presentation.logo_uri.as_deref(),
        policy_uri: client.presentation.policy_uri.as_deref(),
        tos_uri: client.presentation.tos_uri.as_deref(),
    })
}

fn client_presentation_error(status: StatusCode, error: &'static str) -> HttpResponse {
    json_response_status_no_store(status, serde_json::json!({ "error": error }))
}

#[cfg(test)]
#[path = "../../../tests/unit/http/authorization/presentation.rs"]
mod tests;
