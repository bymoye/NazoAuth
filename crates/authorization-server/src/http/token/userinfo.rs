use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use chrono::{Duration, Utc};
use nazo_auth::Claims;
use nazo_http_actix::{OAuthJsonErrorFields, UserinfoEndpoint};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{ServerTokenService, access_token_subject_key};
use crate::adapters::security::{
    AccessTokenJwtInput, IssuedAccessToken, blake3_hex, jwt_decoding_key_from_jwk, make_jwt,
};
use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use crate::domain::{DatabaseUserFixture, ServerUserinfoOperations, UserinfoHandles};

pub(crate) async fn userinfo(
    handles: Data<UserinfoHandles>,
    token_service: Data<ServerTokenService>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    nazo_http_actix::userinfo(
        Data::new(UserinfoEndpoint::new(Arc::new(
            ServerUserinfoOperations::new(token_service.into_inner(), handles.get_ref().clone()),
        ))),
        request,
        body,
    )
    .await
}

async fn access_token_user_id(
    token_service: &ServerTokenService,
    tenant_id: Uuid,
    claims: &Claims,
) -> anyhow::Result<Option<Uuid>> {
    if let Some(user_id) = claims
        .user_id
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        return Ok(Some(user_id));
    }
    token_service
        .load_access_token_subject(tenant_id, &claims.jti)
        .await
        .map_err(anyhow::Error::from)
}

#[path = "../../../tests/in_source/src/http/token/tests/userinfo.rs"]
mod tests;
