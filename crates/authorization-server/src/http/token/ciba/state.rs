use super::*;

pub(crate) const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";
pub(crate) const CIBA_AUTOMATED_DECISION_PROFILE: &str = "oidc-fapi-ciba";
pub(crate) const CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
pub(crate) const CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;
pub(crate) const CIBA_BINDING_MESSAGE_MAX_CHARS: usize = 64;

pub(crate) fn ciba_grant_key(
    auth_req_id: &str,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> String {
    let binding = json!({
        "auth_req_id": auth_req_id,
        "dpop_jkt": dpop_jkt,
        "mtls_x5t_s256": mtls_x5t_s256,
    });
    format!("ciba:{}", blake3_hex(&binding.to_string()))
}

pub(crate) type ServerCibaService = CibaService<CibaStore>;

#[derive(Clone)]
pub(crate) struct CibaHttpConfig {
    pub(crate) issuer: Box<str>,
    pub(crate) frontend_base_url: Box<str>,
    pub(crate) client_secret_pepper: Box<str>,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) default_audience: Box<str>,
    // CIBA currently composes a single default-tenant authorization flow.
    // Keep this tenant explicit when checking conformance ownership so an
    // active lease in another tenant can never open automated decisions.
    pub(crate) tenant_id: Uuid,
    pub(crate) auth_req_id_ttl_seconds: u64,
    pub(crate) poll_interval_seconds: u64,
    pub(crate) csrf_cookie_name: Box<str>,
    pub(crate) automated_decision_token: Option<Box<str>>,
    pub(crate) automated_decision_mode: CibaAutomatedDecisionMode,
    pub(crate) ciba_fapi_profile: bool,
    pub(crate) ciba_fapi2_hardening: bool,
    pub(crate) authorization_server_profile: AuthorizationServerProfile,
}

impl From<&Settings> for CibaHttpConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            frontend_base_url: settings.endpoint.frontend_base_url.as_str().into(),
            client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
            trusted_proxy_cidrs: settings.endpoint.trusted_proxy_cidrs.clone(),
            client_ip_header_mode: settings.endpoint.client_ip_header_mode,
            default_audience: settings.protocol.default_audience.as_str().into(),
            tenant_id: DEFAULT_TENANT_ID,
            auth_req_id_ttl_seconds: settings.ciba.ciba_auth_req_id_ttl_seconds,
            poll_interval_seconds: settings.ciba.ciba_poll_interval_seconds,
            csrf_cookie_name: settings.session.csrf_cookie_name.as_str().into(),
            automated_decision_token: settings
                .ciba
                .ciba_automated_decision_token
                .as_deref()
                .map(Into::into),
            automated_decision_mode: settings.ciba.ciba_automated_decision_mode,
            ciba_fapi_profile: settings.protocol.ciba_security_profile.requires_fapi_ciba(),
            ciba_fapi2_hardening: settings
                .protocol
                .ciba_security_profile
                .requires_fapi2_hardening(),
            authorization_server_profile: settings.protocol.authorization_server_profile,
        }
    }
}

pub(crate) struct CibaTokenHandles {
    pub(crate) service: Data<ServerCibaService>,
    pub(crate) users: Data<nazo_postgres::UserRepository>,
    pub(crate) conformance_leases: Data<nazo_postgres::ConformanceLeaseRepository>,
    pub(crate) config: Data<CibaHttpConfig>,
}

impl CibaTokenHandles {
    pub(crate) fn new(
        service: Data<ServerCibaService>,
        users: Data<nazo_postgres::UserRepository>,
        conformance_leases: Data<nazo_postgres::ConformanceLeaseRepository>,
        config: Data<CibaHttpConfig>,
    ) -> Self {
        Self {
            service,
            users,
            conformance_leases,
            config,
        }
    }
}

pub(crate) struct CibaTokenContext<'request, 'issuance> {
    pub(crate) token_service: &'request ServerTokenService,
    pub(crate) issuance: &'request TokenIssuanceContext<'issuance>,
    pub(crate) handles: &'request CibaTokenHandles,
    pub(crate) request: &'request HttpRequest,
}

pub(crate) fn ciba_module_admissible(
    runtime: &ServerRuntimeModuleRegistry,
    admission: nazo_auth::CapabilityAdmission,
) -> bool {
    nazo_auth::module_admissible(
        runtime.snapshot().as_ref(),
        nazo_runtime_modules::ModuleId::Ciba,
        admission,
    )
}

#[derive(Default)]
pub(crate) struct BackchannelAuthenticationForm {
    pub(crate) request: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) login_hint: Option<String>,
    pub(crate) id_token_hint: Option<String>,
    pub(crate) login_hint_token: Option<String>,
    pub(crate) binding_message: Option<String>,
    pub(crate) acr_values: Option<String>,
    pub(crate) requested_expiry_seconds: Option<u64>,
    pub(crate) client_notification_token: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion_type: Option<String>,
    pub(crate) client_assertion: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CibaAuthenticationRequestClaims {
    pub(crate) iss: Option<String>,
    pub(crate) aud: Option<Value>,
    pub(crate) exp: Option<i64>,
    pub(crate) nbf: Option<i64>,
    pub(crate) iat: Option<i64>,
    pub(crate) jti: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) login_hint: Option<String>,
    pub(crate) id_token_hint: Option<String>,
    pub(crate) login_hint_token: Option<String>,
    pub(crate) binding_message: Option<String>,
    pub(crate) acr_values: Option<String>,
    pub(crate) requested_expiry: Option<Value>,
    pub(crate) client_notification_token: Option<String>,
}

#[derive(Debug)]
pub(crate) struct CibaRequestObjectReplay {
    pub(crate) jti: String,
    pub(crate) ttl_seconds: u64,
}

#[derive(Deserialize)]
pub(crate) struct UnverifiedCibaAuthenticationRequestClaims {
    pub(crate) iss: Option<String>,
    pub(crate) sub: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CibaDecisionRequest {
    pub(crate) decision: String,
    pub(crate) csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CibaAutomatedDecisionQuery {
    pub(crate) token: Option<String>,
    pub(crate) auth_req_id: Option<String>,
    pub(crate) r#type: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) decision_token: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct CibaVerificationView {
    pub(crate) auth_req_id: String,
    pub(crate) csrf_token: Option<String>,
    pub(crate) request: Option<CibaAuthorizationRequestView>,
}

#[derive(serde::Serialize)]
pub(crate) struct CibaAuthorizationRequestView {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) audiences: Vec<String>,
    pub(crate) binding_message: Option<String>,
    pub(crate) interval_seconds: u64,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CibaDecisionSource {
    User,
    Automation,
}

impl CibaDecisionSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Automation => "automation",
        }
    }
}

pub(crate) fn ciba_start_audit_fields(
    state: &CibaRequestState,
    auth_req_id: &str,
    source_ip_hash: Option<String>,
) -> serde_json::Map<String, Value> {
    let mut fields = audit_fields(&[
        ("client_id", json!(state.client_id)),
        ("user_id", json!(state.user_id)),
        ("auth_req_id_hash", json!(blake3_hex(auth_req_id))),
        ("scopes", json!(state.scopes)),
        ("audiences", json!(state.audiences)),
    ]);
    if let Some(source_ip_hash) = source_ip_hash {
        fields.insert("source_ip_hash".to_owned(), json!(source_ip_hash));
    }
    fields
}
