diesel::table! {
    backchannel_logout_deliveries (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        client_id -> Uuid,
        client_public_id -> Varchar,
        logout_uri -> Text,
        logout_token -> Text,
        attempts -> Int4,
        next_attempt_at -> Timestamptz,
        locked_at -> Nullable<Timestamptz>,
        delivered_at -> Nullable<Timestamptz>,
        failed_at -> Nullable<Timestamptz>,
        last_error -> Nullable<Text>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    scim_tokens (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        token_hash -> Varchar,
        label -> Varchar,
        scopes -> Jsonb,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        last_used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    scim_audit_events (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        scim_token_id -> Nullable<Uuid>,
        event_type -> Varchar,
        scopes -> Jsonb,
        ip_hash -> Nullable<Varchar>,
        user_agent_hash -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    external_identity_links (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        provider_type -> Varchar,
        provider_id -> Varchar,
        subject -> Varchar,
        email -> Varchar,
        claims -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        last_login_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_passkey_credentials (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        credential_id -> Varchar,
        credential -> Jsonb,
        label -> Varchar,
        sign_count -> Int8,
        last_used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_totp_credentials (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        secret_base32 -> Varchar,
        label -> Varchar,
        confirmed_at -> Nullable<Timestamptz>,
        last_used_step -> Nullable<Int8>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_backup_codes (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        code_hash -> Varchar,
        used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_remembered_devices (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        user_agent_hash -> Nullable<Varchar>,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    access_token_revocations (id) {
        id -> Uuid,
        access_token_jti_blake3 -> Varchar,
        client_id -> Uuid,
        tenant_id -> Uuid,
        revoked_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    client_access_requests (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        site_name -> Varchar,
        site_url -> Varchar,
        request_description -> Varchar,
        status -> SmallInt,
        admin_note -> Nullable<Varchar>,
        resolved_by_user_id -> Nullable<Uuid>,
        approved_client_id -> Nullable<Uuid>,
        resolved_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_clients (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        realm_id -> Uuid,
        organization_id -> Uuid,
        client_id -> Varchar,
        client_name -> Varchar,
        client_type -> Text,
        client_secret_hash -> Nullable<Varchar>,
        registration_access_token_blake3 -> Nullable<Varchar>,
        redirect_uris -> Jsonb,
        scopes -> Jsonb,
        grant_types -> Jsonb,
        token_endpoint_auth_method -> Varchar,
        require_dpop_bound_tokens -> Bool,
        require_mtls_bound_tokens -> Bool,
        tls_client_auth_subject_dn -> Nullable<Varchar>,
        tls_client_auth_cert_sha256 -> Nullable<Varchar>,
        tls_client_auth_san_dns -> Jsonb,
        tls_client_auth_san_uri -> Jsonb,
        tls_client_auth_san_ip -> Jsonb,
        tls_client_auth_san_email -> Jsonb,
        allow_client_assertion_audience_array -> Bool,
        allow_client_assertion_endpoint_audience -> Bool,
        require_par_request_object -> Bool,
        allow_authorization_code_without_pkce -> Bool,
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        allowed_audiences -> Jsonb,
        jwks -> Nullable<Jsonb>,
        introspection_encrypted_response_alg -> Nullable<Varchar>,
        introspection_encrypted_response_enc -> Nullable<Varchar>,
        userinfo_signed_response_alg -> Nullable<Varchar>,
        userinfo_encrypted_response_alg -> Nullable<Varchar>,
        userinfo_encrypted_response_enc -> Nullable<Varchar>,
        authorization_signed_response_alg -> Nullable<Varchar>,
        authorization_encrypted_response_alg -> Nullable<Varchar>,
        authorization_encrypted_response_enc -> Nullable<Varchar>,
        post_logout_redirect_uris -> Jsonb,
        backchannel_logout_uri -> Nullable<Varchar>,
        backchannel_logout_session_required -> Bool,
        frontchannel_logout_uri -> Nullable<Varchar>,
        frontchannel_logout_session_required -> Bool,
        subject_type -> Text,
        sector_identifier_uri -> Nullable<Text>,
        sector_identifier_host -> Nullable<Text>,
    }
}

diesel::table! {
    oauth_tokens (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        refresh_token_blake3 -> Varchar,
        token_family_id -> Uuid,
        rotated_from_id -> Nullable<Uuid>,
        client_id -> Uuid,
        user_id -> Nullable<Uuid>,
        scopes -> Jsonb,
        audience -> Jsonb,
        authorization_details -> Jsonb,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        reuse_detected_at -> Nullable<Timestamptz>,
        subject -> Varchar,
        dpop_jkt -> Nullable<Varchar>,
        mtls_x5t_s256 -> Nullable<Varchar>,
    }
}

diesel::table! {
    user_client_grants (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        client_id -> Uuid,
        first_authorized_at -> Timestamptz,
        last_authorized_at -> Timestamptz,
        last_scopes -> Jsonb,
        last_resource_indicators -> Jsonb,
        last_authorization_details -> Jsonb,
        authorization_count -> Int4,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        realm_id -> Uuid,
        organization_id -> Uuid,
        username -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        is_active -> Bool,
        mfa_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        email_verified -> Bool,
        display_name -> Nullable<Varchar>,
        avatar_url -> Nullable<Varchar>,
        given_name -> Nullable<Varchar>,
        family_name -> Nullable<Varchar>,
        middle_name -> Nullable<Varchar>,
        nickname -> Nullable<Varchar>,
        profile_url -> Nullable<Varchar>,
        website_url -> Nullable<Varchar>,
        gender -> Nullable<Varchar>,
        birthdate -> Nullable<Varchar>,
        zoneinfo -> Nullable<Varchar>,
        locale -> Nullable<Varchar>,
        role -> Text,
        admin_level -> Int4,
        address_formatted -> Nullable<Varchar>,
        address_street_address -> Nullable<Varchar>,
        address_locality -> Nullable<Varchar>,
        address_region -> Nullable<Varchar>,
        address_postal_code -> Nullable<Varchar>,
        address_country -> Nullable<Varchar>,
        phone_number -> Nullable<Varchar>,
        phone_number_verified -> Bool,
    }
}

diesel::table! {
    tenants (id) {
        id -> Uuid,
        slug -> Varchar,
        display_name -> Varchar,
        status -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    realms (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        slug -> Varchar,
        display_name -> Varchar,
        status -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    organizations (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        slug -> Varchar,
        display_name -> Varchar,
        status -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(access_token_revocations -> oauth_clients (client_id));
diesel::joinable!(backchannel_logout_deliveries -> oauth_clients (client_id));
diesel::joinable!(client_access_requests -> oauth_clients (approved_client_id));
diesel::joinable!(client_access_requests -> tenants (tenant_id));
diesel::joinable!(external_identity_links -> tenants (tenant_id));
diesel::joinable!(external_identity_links -> users (user_id));
diesel::joinable!(oauth_clients -> organizations (organization_id));
diesel::joinable!(oauth_clients -> realms (realm_id));
diesel::joinable!(oauth_clients -> tenants (tenant_id));
diesel::joinable!(oauth_tokens -> oauth_clients (client_id));
diesel::joinable!(oauth_tokens -> tenants (tenant_id));
diesel::joinable!(oauth_tokens -> users (user_id));
diesel::joinable!(organizations -> tenants (tenant_id));
diesel::joinable!(realms -> tenants (tenant_id));
diesel::joinable!(scim_audit_events -> scim_tokens (scim_token_id));
diesel::joinable!(scim_audit_events -> tenants (tenant_id));
diesel::joinable!(scim_tokens -> tenants (tenant_id));
diesel::joinable!(user_client_grants -> oauth_clients (client_id));
diesel::joinable!(user_client_grants -> tenants (tenant_id));
diesel::joinable!(user_client_grants -> users (user_id));
diesel::joinable!(user_mfa_backup_codes -> tenants (tenant_id));
diesel::joinable!(user_mfa_backup_codes -> users (user_id));
diesel::joinable!(user_mfa_remembered_devices -> tenants (tenant_id));
diesel::joinable!(user_mfa_remembered_devices -> users (user_id));
diesel::joinable!(user_passkey_credentials -> tenants (tenant_id));
diesel::joinable!(user_passkey_credentials -> users (user_id));
diesel::joinable!(user_totp_credentials -> tenants (tenant_id));
diesel::joinable!(user_totp_credentials -> users (user_id));
diesel::joinable!(users -> organizations (organization_id));
diesel::joinable!(users -> realms (realm_id));
diesel::joinable!(users -> tenants (tenant_id));

diesel::allow_tables_to_appear_in_same_query!(
    access_token_revocations,
    backchannel_logout_deliveries,
    client_access_requests,
    external_identity_links,
    oauth_clients,
    oauth_tokens,
    organizations,
    realms,
    scim_audit_events,
    scim_tokens,
    tenants,
    user_client_grants,
    user_mfa_backup_codes,
    user_mfa_remembered_devices,
    user_passkey_credentials,
    user_totp_credentials,
    users,
);
