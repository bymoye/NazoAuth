//! client_credentials grant 处理。
use crate::adapters::security::ValidatedClientAssertion;
#[cfg(test)]
use crate::domain::TestAppState;
use crate::domain::client_policy::audiences_allowed;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::parse_scope;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::validate_dpop_proof_with_authorization_service;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
#[cfg(test)]
use crate::settings::Settings;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::oauth_token_error;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
// 只为机密客户端签发无用户主体的访问令牌。
use super::issue::{TokenIssuanceContext, issue_token_response_with_service};
use super::{
    ServerTokenService, TokenForm, consume_token_client_assertion_with_authorization_service,
};

#[derive(Debug)]
pub(super) struct ClientCredentialsIssue {
    pub(super) scopes: Vec<String>,
    pub(super) audiences: Vec<String>,
}

fn reject_non_confidential_client_credentials_client(client: &ClientRow) -> Option<HttpResponse> {
    if client.client_type == "confidential" {
        return None;
    }
    Some(oauth_token_error(
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
        "client_credentials 只允许机密客户端使用.",
        false,
    ))
}

pub(super) fn client_credentials_issue_request_with_default_audience(
    default_audience: &str,
    client: &ClientRow,
    form: &TokenForm,
) -> Result<ClientCredentialsIssue, HttpResponse> {
    let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
    if !requested.is_empty() && !is_subset(&requested, &client.scopes) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
            false,
        ));
    }
    let scopes = if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    };
    if scopes.iter().any(|scope| scope == "openid") {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "client_credentials 不支持 openid scope.",
            false,
        ));
    }
    let audiences = if form.audiences.is_empty() {
        vec![default_audience.to_owned()]
    } else {
        form.audiences.clone()
    };
    if !audiences_allowed(client, &audiences) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ));
    }
    Ok(ClientCredentialsIssue { scopes, audiences })
}

#[cfg(test)]
pub(super) fn client_credentials_issue_request(
    settings: &Settings,
    client: &ClientRow,
    form: &TokenForm,
) -> Result<ClientCredentialsIssue, HttpResponse> {
    client_credentials_issue_request_with_default_audience(
        &settings.protocol.default_audience,
        client,
        form,
    )
}

pub(crate) async fn token_client_credentials_with_service(
    token_service: &ServerTokenService,
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if let Some(response) = reject_non_confidential_client_credentials_client(client) {
        return response;
    }
    let dpop_jkt = match validate_dpop_proof_with_authorization_service(
        authorization_service,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        req,
        None,
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);
    }
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        {
            Some(value) => Some(value),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client_credentials requires mTLS sender constraint.",
                    false,
                );
            }
        }
    } else {
        None
    };
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        authorization_service,
        client,
        client_assertion,
    )
    .await
    {
        return super::token_client_assertion_error(error);
    }
    let issue_request = match client_credentials_issue_request_with_default_audience(
        issuance.config.default_audience(),
        client,
        form,
    ) {
        Ok(issue_request) => issue_request,
        Err(response) => return response,
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id: None,
            subject: client.client_id.clone(),
            scopes: issue_request.scopes,
            authorization_details: json!([]),
            audiences: issue_request.audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
pub(crate) async fn token_client_credentials(
    state: &TestAppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let connection = state.valkey_connection();
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let config = super::issue::TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization_service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    token_client_credentials_with_service(
        &service,
        &authorization_service,
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization_service,
        },
        req,
        client,
        form,
        client_assertion,
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/client_credentials.rs"]
mod tests;
