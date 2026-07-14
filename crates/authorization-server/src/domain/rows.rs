//! Diesel query rows for auth/runtime tables pending Domain Task 5 extraction.
pub(crate) type ClientRow = nazo_auth::OAuthClient;

#[cfg(test)]
#[macro_export]
macro_rules! client_row {
    (
        id: $id:expr, tenant_id: $tenant_id:expr, realm_id: $realm_id:expr,
        organization_id: $organization_id:expr, client_id: $client_id:expr,
        client_name: $client_name:expr, client_type: $client_type:expr,
        client_secret_hash: $client_secret_hash:expr, redirect_uris: $redirect_uris:expr,
        scopes: $scopes:expr, allowed_audiences: $allowed_audiences:expr,
        grant_types: $grant_types:expr, token_endpoint_auth_method: $auth_method:expr,
        require_dpop_bound_tokens: $require_dpop:expr,
        require_mtls_bound_tokens: $require_mtls:expr,
        tls_client_auth_subject_dn: $subject_dn:expr,
        tls_client_auth_cert_sha256: $cert_sha256:expr,
        tls_client_auth_san_dns: $san_dns:expr, tls_client_auth_san_uri: $san_uri:expr,
        tls_client_auth_san_ip: $san_ip:expr, tls_client_auth_san_email: $san_email:expr,
        allow_client_assertion_audience_array: $allow_aud_array:expr,
        allow_client_assertion_endpoint_audience: $allow_endpoint_aud:expr,
        require_par_request_object: $require_par:expr,
        allow_authorization_code_without_pkce: $allow_no_pkce:expr,
        is_active: $is_active:expr, jwks: $jwks:expr,
        introspection_encrypted_response_alg: $introspection_alg:expr,
        introspection_encrypted_response_enc: $introspection_enc:expr,
        userinfo_signed_response_alg: $userinfo_signed:expr,
        userinfo_encrypted_response_alg: $userinfo_alg:expr,
        userinfo_encrypted_response_enc: $userinfo_enc:expr,
        authorization_signed_response_alg: $authorization_signed:expr,
        authorization_encrypted_response_alg: $authorization_alg:expr,
        authorization_encrypted_response_enc: $authorization_enc:expr,
        post_logout_redirect_uris: $post_logout:expr,
        backchannel_logout_uri: $backchannel_uri:expr,
        backchannel_logout_session_required: $backchannel_session:expr,
        frontchannel_logout_uri: $frontchannel_uri:expr,
        frontchannel_logout_session_required: $frontchannel_session:expr,
        subject_type: $subject_type:expr, sector_identifier_uri: $sector_uri:expr,
        sector_identifier_host: $sector_host:expr $(,)?
    ) => {{
        let _: Option<String> = $client_secret_hash;
        $crate::domain::ClientRow {
            id: $id,
            tenant_id: $tenant_id,
            realm_id: $realm_id,
            organization_id: $organization_id,
            registration: nazo_auth::ValidatedClientRegistration {
                client_id: $client_id,
                client_name: $client_name,
                client_type: $client_type,
                redirect_uris: serde_json::from_value($redirect_uris)
                    .expect("redirect_uris fixture"),
                scopes: serde_json::from_value($scopes).expect("scopes fixture"),
                allowed_audiences: serde_json::from_value($allowed_audiences)
                    .expect("audiences fixture"),
                grant_types: serde_json::from_value($grant_types).expect("grants fixture"),
                token_endpoint_auth_method: $auth_method,
                require_dpop_bound_tokens: $require_dpop,
                tls_client_auth_subject_dn: $subject_dn,
                tls_client_auth_cert_sha256: $cert_sha256,
                tls_client_auth_san_dns: serde_json::from_value($san_dns).expect("dns fixture"),
                tls_client_auth_san_uri: serde_json::from_value($san_uri).expect("uri fixture"),
                tls_client_auth_san_ip: serde_json::from_value($san_ip).expect("ip fixture"),
                tls_client_auth_san_email: serde_json::from_value($san_email)
                    .expect("email fixture"),
                allow_client_assertion_audience_array: $allow_aud_array,
                allow_client_assertion_endpoint_audience: $allow_endpoint_aud,
                require_par_request_object: $require_par,
                allow_authorization_code_without_pkce: $allow_no_pkce,
                jwks: $jwks,
                introspection_encrypted_response_alg: $introspection_alg,
                introspection_encrypted_response_enc: $introspection_enc,
                userinfo_signed_response_alg: $userinfo_signed,
                userinfo_encrypted_response_alg: $userinfo_alg,
                userinfo_encrypted_response_enc: $userinfo_enc,
                authorization_signed_response_alg: $authorization_signed,
                authorization_encrypted_response_alg: $authorization_alg,
                authorization_encrypted_response_enc: $authorization_enc,
                post_logout_redirect_uris: serde_json::from_value($post_logout)
                    .expect("post logout fixture"),
                backchannel_logout_uri: $backchannel_uri,
                backchannel_logout_session_required: $backchannel_session,
                frontchannel_logout_uri: $frontchannel_uri,
                frontchannel_logout_session_required: $frontchannel_session,
                subject_type: $subject_type,
                sector_identifier_uri: $sector_uri,
                sector_identifier_host: $sector_host,
            },
            require_mtls_bound_tokens: $require_mtls,
            is_active: $is_active,
        }
    }};
}

pub(crate) type TokenRow = nazo_auth::RefreshToken;
