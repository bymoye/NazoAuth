DROP FUNCTION IF EXISTS nazo_openid4vp_cleanup_expired_transactions();
DROP TABLE IF EXISTS openid4vp_transactions;
DROP TABLE IF EXISTS openid4vci_notifications;
DROP TABLE IF EXISTS openid4vci_deferred_transactions;
DROP TABLE IF EXISTS openid4vci_nonces;
DROP TABLE IF EXISTS openid4vci_access_grants;
DROP TABLE IF EXISTS openid4vci_offers;
DROP TABLE IF EXISTS openid4vci_credential_configurations;

ALTER TABLE runtime_module_desired_states
    DROP CONSTRAINT ck_runtime_module_desired_module_id,
    ADD CONSTRAINT ck_runtime_module_desired_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management'
        )
    );

ALTER TABLE runtime_module_instance_states
    DROP CONSTRAINT ck_runtime_module_instance_module_id,
    ADD CONSTRAINT ck_runtime_module_instance_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management'
        )
    );

ALTER TABLE runtime_module_state_events
    DROP CONSTRAINT ck_runtime_module_event_module_id,
    ADD CONSTRAINT ck_runtime_module_event_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management'
        )
    );
ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_token_endpoint_auth_method_value,
    ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (
        token_endpoint_auth_method IN (
            'none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt',
            'tls_client_auth', 'self_signed_tls_client_auth'
        )
    );
