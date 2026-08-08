diesel::table! {
    users (id) {
        id -> Uuid, tenant_id -> Uuid, realm_id -> Uuid, organization_id -> Uuid,
        username -> Varchar, email -> Varchar, password_hash -> Varchar, is_active -> Bool,
        mfa_enabled -> Bool, created_at -> Timestamptz, updated_at -> Timestamptz,
        email_verified -> Bool, display_name -> Nullable<Varchar>, avatar_url -> Nullable<Varchar>,
        given_name -> Nullable<Varchar>, family_name -> Nullable<Varchar>, middle_name -> Nullable<Varchar>,
        nickname -> Nullable<Varchar>, profile_url -> Nullable<Varchar>, website_url -> Nullable<Varchar>,
        gender -> Nullable<Varchar>, birthdate -> Nullable<Varchar>, zoneinfo -> Nullable<Varchar>,
        locale -> Nullable<Varchar>, role -> Text, admin_level -> Int4,
        address_formatted -> Nullable<Varchar>, address_street_address -> Nullable<Varchar>,
        address_locality -> Nullable<Varchar>, address_region -> Nullable<Varchar>,
        address_postal_code -> Nullable<Varchar>, address_country -> Nullable<Varchar>,
        phone_number -> Nullable<Varchar>, phone_number_verified -> Bool,
    }
}

diesel::table! {
    initial_admin_bootstrap (singleton) {
        singleton -> Bool,
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
        request_id -> Nullable<Varchar>,
        request_email_hash -> Nullable<Varchar>,
        claimed_user_id -> Nullable<Uuid>,
        claim_result -> Nullable<Varchar>,
        receipt_version -> Nullable<Int2>,
        claimed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_totp_credentials (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, secret_base32 -> Nullable<Varchar>,
        secret_ciphertext -> Nullable<Binary>, secret_key_id -> Nullable<Varchar>,
        label -> Varchar, confirmed_at -> Nullable<Timestamptz>, last_used_step -> Nullable<Int8>,
        created_at -> Timestamptz, updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_backup_codes (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, code_hash -> Varchar,
        used_at -> Nullable<Timestamptz>, created_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_remembered_devices (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, token_hash -> Varchar,
        user_agent_hash -> Nullable<Varchar>, created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>, expires_at -> Timestamptz,
    }
}

diesel::table! {
    identity_security_events (id) {
        id -> Uuid, tenant_id -> Uuid, category -> Varchar, event_type -> Varchar,
        outcome -> Varchar, actor_id -> Nullable<Uuid>, target_user_id -> Nullable<Uuid>,
        reason_code -> Varchar, occurred_at -> Timestamptz,
        request_id -> Nullable<Varchar>,
    }
}

diesel::table! {
    user_passkey_credentials (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, credential_id -> Varchar,
        credential -> Jsonb, label -> Varchar, sign_count -> Int8,
        last_used_at -> Nullable<Timestamptz>, created_at -> Timestamptz, updated_at -> Timestamptz,
    }
}

diesel::table! {
    external_identity_links (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, provider_type -> Varchar,
        provider_id -> Varchar, subject -> Varchar, email -> Varchar, claims -> Jsonb,
        created_at -> Timestamptz, updated_at -> Timestamptz, last_login_at -> Nullable<Timestamptz>,
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
        client_attestation_jkt -> Nullable<Varchar>,
        oidc_auth_context -> Nullable<Jsonb>,
    }
}

diesel::table! {
    oauth_token_issuances (issuance_id) {
        issuance_id -> Uuid,
        tenant_id -> Uuid,
        client_id -> Uuid,
        grant_key_blake3 -> Varchar,
        request_digest -> Varchar,
        phase -> Varchar,
        claim_owner_id -> Nullable<Uuid>,
        claim_started_at -> Nullable<Timestamptz>,
        access_token_jti -> Nullable<Varchar>,
        access_token_expires_at -> Nullable<Timestamptz>,
        response_ciphertext -> Nullable<Binary>,
        response_digest -> Nullable<Varchar>,
        response_envelope_version -> Nullable<Varchar>,
        response_key_id -> Nullable<Varchar>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
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
    scim_tokens (id) {
        id -> Uuid, tenant_id -> Uuid, token_hash -> Varchar, label -> Varchar,
        scopes -> Jsonb, expires_at -> Nullable<Timestamptz>, revoked_at -> Nullable<Timestamptz>,
        last_used_at -> Nullable<Timestamptz>, created_at -> Timestamptz, updated_at -> Timestamptz,
        event_audience -> Nullable<Varchar>,
    }
}

diesel::table! {
    scim_security_events (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        transaction_id -> Uuid,
        subject_uri -> Text,
        events -> Jsonb,
        occurred_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    scim_security_event_receipts (event_id, scim_token_id) {
        event_id -> Uuid,
        scim_token_id -> Uuid,
        disposition -> Varchar,
        error_code -> Nullable<Varchar>,
        error_description -> Nullable<Text>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    scim_audit_events (id) {
        id -> Uuid, tenant_id -> Uuid, scim_token_id -> Nullable<Uuid>, event_type -> Varchar,
        scopes -> Jsonb, ip_hash -> Nullable<Varchar>, user_agent_hash -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    backchannel_logout_deliveries (id) {
        id -> Uuid, tenant_id -> Uuid, client_id -> Uuid, client_public_id -> Varchar,
        logout_uri -> Text, logout_token -> Text, operation_key -> Nullable<Varchar>, attempts -> Int4, next_attempt_at -> Timestamptz,
        locked_at -> Nullable<Timestamptz>, delivered_at -> Nullable<Timestamptz>,
        failed_at -> Nullable<Timestamptz>, last_error -> Nullable<Text>, expires_at -> Timestamptz,
        created_at -> Timestamptz, updated_at -> Timestamptz,
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
    conformance_leases (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        profile -> Varchar,
        material_sha256 -> Varchar,
        dynamic_registration_initial_access_token_sha256 -> Nullable<Varchar>,
        ciba_automated_decision_token_sha256 -> Nullable<Varchar>,
        public_material -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        cleaned_at -> Nullable<Timestamptz>,
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
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        allowed_audiences -> Jsonb,
        jwks_uri -> Nullable<Text>,
        jwks -> Nullable<Jsonb>,
        request_uris -> Jsonb,
        initiate_login_uri -> Nullable<Text>,
        logo_uri -> Nullable<Text>,
        policy_uri -> Nullable<Text>,
        tos_uri -> Nullable<Text>,
        id_token_signed_response_alg -> Nullable<Varchar>,
        id_token_encrypted_response_alg -> Nullable<Varchar>,
        id_token_encrypted_response_enc -> Nullable<Varchar>,
        request_object_signing_alg -> Nullable<Varchar>,
        request_object_encryption_alg -> Nullable<Varchar>,
        request_object_encryption_enc -> Nullable<Varchar>,
        token_endpoint_auth_signing_alg -> Nullable<Varchar>,
        introspection_signed_response_alg -> Nullable<Varchar>,
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
        backchannel_token_delivery_mode -> Varchar,
        backchannel_client_notification_endpoint -> Nullable<Text>,
        backchannel_authentication_request_signing_alg -> Nullable<Varchar>,
        backchannel_user_code_parameter -> Bool,
        frontchannel_logout_uri -> Nullable<Varchar>,
        frontchannel_logout_session_required -> Bool,
        subject_type -> Text,
        sector_identifier_uri -> Nullable<Text>,
        sector_identifier_host -> Nullable<Text>,
        security_policy -> Nullable<Jsonb>,
    }
}

// Keep lease metadata as a narrow Diesel mapping. `oauth_clients` already has
// 64 mapped columns; widening its primary mapping would require Diesel's much
// heavier `128-column-tables` feature in every build.
diesel::table! {
    #[sql_name = "oauth_clients"]
    oauth_client_conformance_bindings (id) {
        id -> Uuid,
        conformance_lease_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    runtime_module_desired_states (module_id) {
        module_id -> Varchar,
        desired_mode -> Varchar,
        revision -> Int8,
        actor_id -> Nullable<Uuid>,
        reason -> Nullable<Varchar>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    runtime_module_instance_states (instance_id, module_id) {
        instance_id -> Varchar,
        module_id -> Varchar,
        actual_state -> Varchar,
        transition_revision -> Int8,
        applied_revision -> Nullable<Int8>,
        drain_deadline -> Nullable<Timestamptz>,
        error_code -> Nullable<Varchar>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    runtime_module_state_events (event_id) {
        event_id -> Uuid,
        module_id -> Varchar,
        event_type -> Varchar,
        revision -> Int8,
        instance_id -> Nullable<Varchar>,
        actor_id -> Nullable<Uuid>,
        reason -> Nullable<Varchar>,
        before_state -> Nullable<Varchar>,
        after_state -> Nullable<Varchar>,
        outcome_code -> Nullable<Varchar>,
        occurred_at -> Timestamptz,
    }
}

diesel::table! {
    security_audit_chain_state (singleton) {
        singleton -> Bool,
        last_sequence -> Int8,
        last_hash -> Binary,
    }
}

diesel::table! {
    security_audit_events (event_id) {
        event_id -> Uuid,
        sequence -> Int8,
        event_type -> Varchar,
        event_category -> Varchar,
        payload -> Jsonb,
        occurred_at -> Timestamptz,
        previous_hash -> Binary,
        event_hash -> Binary,
    }
}

diesel::table! {
    security_audit_event_outbox (event_id) {
        event_id -> Uuid,
        attempts -> Int4,
        available_at -> Timestamptz,
        locked_at -> Nullable<Timestamptz>,
        exported_at -> Nullable<Timestamptz>,
        last_error -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(client_access_requests -> users (user_id));
diesel::joinable!(scim_audit_events -> scim_tokens (scim_token_id));
diesel::joinable!(scim_security_event_receipts -> scim_security_events (event_id));
diesel::joinable!(scim_security_event_receipts -> scim_tokens (scim_token_id));
diesel::joinable!(user_client_grants -> oauth_clients (client_id));
diesel::joinable!(user_client_grants -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    initial_admin_bootstrap,
    user_totp_credentials,
    user_mfa_backup_codes,
    user_mfa_remembered_devices,
    identity_security_events,
    user_passkey_credentials,
    external_identity_links,
    oauth_tokens,
    oauth_token_issuances,
    user_client_grants,
    client_access_requests,
    conformance_leases,
    oauth_clients,
    access_token_revocations,
    scim_tokens,
    scim_audit_events,
    scim_security_events,
    scim_security_event_receipts,
    backchannel_logout_deliveries,
    runtime_module_desired_states,
    runtime_module_instance_states,
    runtime_module_state_events,
    security_audit_chain_state,
    security_audit_events,
    security_audit_event_outbox
);
